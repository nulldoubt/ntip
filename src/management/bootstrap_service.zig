//! Short-lived enrollment bootstrap invitations.
//!
//! The public locator is durable, while the short code and the internal
//! credential secret exist only in caller-owned memory. A keyed derivation
//! rooted outside SQLite lets a valid code reconstruct the exact existing
//! `ntip-enroll-v1` credential until its verifier is consumed or revoked.

const std = @import("std");
const model = @import("../domain/model.zig");
const credential_mod = @import("../protocol/credential.zig");
const management_repository = @import("../state/management_repository.zig");
const sqlite = @import("../state/sqlite.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Kdf = std.crypto.kdf.hkdf.HkdfSha256;

pub const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
pub const locator_len: usize = management_repository.bootstrap_locator_len;
pub const code_symbol_len: usize = 9;
pub const code_text_len: usize = 11;
pub const derivation_version: u8 = management_repository.bootstrap_derivation_version;
pub const maximum_lifetime_seconds: u64 = @intCast(management_repository.bootstrap_maximum_lifetime_seconds);
pub const minimum_lifetime_seconds: u64 = 60;
pub const unknown_throttle_capacity: usize = 64;

const root_domain = "NTIP enrollment bootstrap root v1";
const credential_domain = "NTIP enrollment bootstrap credential v1\x00";

pub const BootstrapId = management_repository.BootstrapLocator;

pub const IssuedBootstrap = struct {
    node_id: model.NodeId,
    bootstrap_id: BootstrapId,
    secret_code: [code_text_len]u8,
    expires_at: i64,

    pub fn clear(self: *IssuedBootstrap) void {
        std.crypto.secureZero(u8, &self.node_id.bytes);
        std.crypto.secureZero(u8, &self.bootstrap_id);
        std.crypto.secureZero(u8, &self.secret_code);
        self.expires_at = 0;
    }
};

pub const RedeemedCredential = struct {
    node_id: model.NodeId,
    node_name: model.Name,
    bootstrap_id: BootstrapId,
    expires_at: i64,
    credential: [credential_mod.text_len]u8,

    pub fn clear(self: *RedeemedCredential) void {
        std.crypto.secureZero(u8, &self.node_id.bytes);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.node_name));
        std.crypto.secureZero(u8, &self.bootstrap_id);
        std.crypto.secureZero(u8, &self.credential);
        self.expires_at = 0;
    }
};

comptime {
    std.debug.assert(alphabet.len == 32);
    std.debug.assert(!@hasField(IssuedBootstrap, "credential"));
    std.debug.assert(!@hasField(IssuedBootstrap, "credential_secret"));
    std.debug.assert(!@hasField(IssuedBootstrap, "derived_psk"));
}

const PreparedBootstrap = struct {
    pending: management_repository.PendingBootstrap,
    secret_code: [code_text_len]u8,

    fn clear(self: *PreparedBootstrap) void {
        std.crypto.secureZero(u8, &self.pending.locator);
        std.crypto.secureZero(u8, &self.pending.node_id.bytes);
        std.crypto.secureZero(u8, &self.pending.handle);
        std.crypto.secureZero(u8, &self.pending.derived_psk);
        self.pending.derivation_version = 0;
        self.pending.expires_at = 0;
        std.crypto.secureZero(u8, &self.secret_code);
    }
};

const UnknownThrottle = struct {
    used: bool = false,
    tag: [16]u8 = [_]u8{0} ** 16,
    failure_count: u8 = 0,
    window_started_at: i64 = 0,
    locked_until: i64 = 0,
    last_seen_at: i64 = 0,
};

pub const Service = struct {
    repository: *management_repository.Repository,
    io: std.Io,
    master_public: [32]u8,
    root_key: [32]u8,
    unknown_throttles: [unknown_throttle_capacity]UnknownThrottle =
        [_]UnknownThrottle{.{}} ** unknown_throttle_capacity,

    pub fn init(
        repository: *management_repository.Repository,
        io: std.Io,
        identity_secret: *const [32]u8,
        master_public: [32]u8,
    ) !Service {
        if (allZero(identity_secret) or allZero(&master_public)) return error.InvalidMasterIdentity;
        return .{
            .repository = repository,
            .io = io,
            .master_public = master_public,
            .root_key = deriveRootKey(identity_secret, &master_public),
        };
    }

    pub fn deinit(self: *Service) void {
        std.crypto.secureZero(u8, &self.root_key);
        std.crypto.secureZero(u8, &self.master_public);
        std.crypto.secureZero(u8, std.mem.asBytes(&self.unknown_throttles));
    }

    pub fn createWithInventory(
        self: *Service,
        candidate: *const model.Store,
        node_id: model.NodeId,
        configured_lifetime_seconds: u64,
        created_at: i64,
        expected_generation: u64,
        audit: management_repository.AuditEntry,
    ) !IssuedBootstrap {
        var prepared = try self.prepare(node_id, configured_lifetime_seconds, created_at);
        defer prepared.clear();
        _ = try self.repository.persistInventoryWithBootstrap(
            candidate,
            prepared.pending,
            expected_generation,
            created_at,
            audit,
        );
        return issuedFromPrepared(&prepared);
    }

    pub fn issueForNode(
        self: *Service,
        node_id: model.NodeId,
        configured_lifetime_seconds: u64,
        created_at: i64,
        expected_generation: u64,
        reset_active_association: bool,
        audit: management_repository.AuditEntry,
    ) !IssuedBootstrap {
        var prepared = try self.prepare(node_id, configured_lifetime_seconds, created_at);
        defer prepared.clear();
        _ = try self.repository.replaceBootstrap(
            prepared.pending,
            reset_active_association,
            created_at,
            expected_generation,
            audit,
        );
        return issuedFromPrepared(&prepared);
    }

    pub fn revokeForNode(
        self: *Service,
        node_id: model.NodeId,
        revoked_at: i64,
        expected_generation: u64,
        audit: management_repository.AuditEntry,
    ) !u64 {
        return self.repository.revokeBootstrap(node_id, revoked_at, expected_generation, audit);
    }

    /// Reconstructs the existing internal credential. The same correct pair
    /// deliberately returns the same bytes on repeat redemptions until the
    /// protocol consumes or another operation invalidates the invitation.
    pub fn redeem(
        self: *Service,
        locator_text: []const u8,
        code_text: []const u8,
        attempted_at: i64,
        request_id: ?[16]u8,
    ) !RedeemedCredential {
        const locator = parseLocator(locator_text) catch return error.InvalidBootstrapInvitation;
        var code = parseCode(code_text) catch return error.InvalidBootstrapInvitation;
        defer std.crypto.secureZero(u8, &code);

        // Once an unknown public locator reaches its bounded cooldown, avoid
        // even the SQLite lookup until that cooldown expires. The caller sees
        // the same generic result for unknown, locked, expired, and revoked
        // invitations, so this does not add an enumeration oracle.
        if (self.unknownLocatorLocked(locator, attempted_at)) {
            return error.InvalidBootstrapInvitation;
        }

        const record = self.repository.readBootstrap(locator) catch |err| switch (err) {
            error.BootstrapNotFound => {
                _ = self.recordUnknownFailure(locator, attempted_at);
                return error.InvalidBootstrapInvitation;
            },
            error.BootstrapUnavailable => return error.InvalidBootstrapInvitation,
            else => return err,
        };
        if (record.derivation_version != derivation_version) {
            return error.UnsupportedBootstrapDerivation;
        }

        var credential = credential_mod.Credential{
            .handle = record.handle,
            .secret = deriveCredentialSecret(&self.root_key, locator, record.handle, &code),
            .master_public = self.master_public,
        };
        defer credential.deinit();
        var derived_psk = credential.derivePsk();
        defer std.crypto.secureZero(u8, &derived_psk);

        var resource_id_buffer: [32]u8 = undefined;
        const resource_id = record.node_id.write(&resource_id_buffer);
        const redemption = self.repository.attemptBootstrapRedemption(
            locator,
            derived_psk,
            attempted_at,
            self.redemptionAudit(resource_id, attempted_at, request_id, "enrollment.bootstrap.redeem"),
            self.redemptionAudit(resource_id, attempted_at, request_id, "enrollment.bootstrap.lockout"),
        ) catch |err| return switch (err) {
            error.InvalidBootstrapCode,
            error.BootstrapNotFound,
            error.BootstrapUnavailable,
            error.BootstrapExpired,
            error.BootstrapLocked,
            => error.InvalidBootstrapInvitation,
            else => err,
        };
        if (!redemption.node_id.eql(record.node_id) or
            !std.crypto.timing_safe.eql([16]u8, redemption.handle, record.handle))
        {
            return error.BootstrapStateChanged;
        }

        var result: RedeemedCredential = .{
            .node_id = redemption.node_id,
            .node_name = redemption.node_name,
            .bootstrap_id = locator,
            .expires_at = redemption.expires_at,
            .credential = undefined,
        };
        _ = credential.encode(&result.credential);
        return result;
    }

    fn prepare(
        self: *Service,
        node_id: model.NodeId,
        configured_lifetime_seconds: u64,
        created_at: i64,
    ) !PreparedBootstrap {
        if (created_at < 0 or configured_lifetime_seconds < minimum_lifetime_seconds) {
            return error.InvalidCredentialLifetime;
        }
        const lifetime = @min(configured_lifetime_seconds, maximum_lifetime_seconds);
        const expires_at = std.math.add(i64, created_at, @as(i64, @intCast(lifetime))) catch
            return error.InvalidCredentialLifetime;

        var locator: BootstrapId = undefined;
        while (true) {
            var random: [locator_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &random);
            self.io.random(&random);
            encodeRandomSymbols(&random, &locator);
            if (!try self.repository.bootstrapLocatorExists(locator)) break;
        }

        var handle: [16]u8 = undefined;
        while (true) {
            self.io.random(&handle);
            if (!allZero(&handle) and !try self.repository.enrollmentHandleExists(handle)) break;
        }
        errdefer std.crypto.secureZero(u8, &handle);

        var random_code: [code_symbol_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &random_code);
        self.io.random(&random_code);
        var code_symbols: [code_symbol_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &code_symbols);
        encodeRandomSymbols(&random_code, &code_symbols);
        var secret_code = renderCode(&code_symbols);
        defer std.crypto.secureZero(u8, &secret_code);

        var credential = credential_mod.Credential{
            .handle = handle,
            .secret = deriveCredentialSecret(&self.root_key, locator, handle, &code_symbols),
            .master_public = self.master_public,
        };
        defer credential.deinit();
        var derived_psk = credential.derivePsk();
        defer std.crypto.secureZero(u8, &derived_psk);
        return .{
            .pending = .{
                .locator = locator,
                .node_id = node_id,
                .handle = handle,
                .derived_psk = derived_psk,
                .derivation_version = derivation_version,
                .expires_at = expires_at,
            },
            .secret_code = secret_code,
        };
    }

    fn redemptionAudit(
        self: *Service,
        resource_id: []const u8,
        occurred_at: i64,
        request_id: ?[16]u8,
        action: []const u8,
    ) management_repository.AuditEntry {
        return .{
            .id = model.NodeId.generate(self.io).bytes,
            .occurred_at = occurred_at,
            .actor_kind = .system,
            .action = action,
            .resource_type = "node",
            .resource_id = resource_id,
            .request_id = request_id,
            .details_json = "{}",
        };
    }

    /// A bounded, keyed in-memory throttle equalizes repeated unknown-locator
    /// work without letting arbitrary public input create durable rows.
    fn unknownLocatorLocked(self: *Service, locator: BootstrapId, now: i64) bool {
        if (now < 0) return true;
        const tag = self.unknownThrottleTag(locator);
        for (&self.unknown_throttles) |*entry| {
            if (!entry.used or !std.crypto.timing_safe.eql([16]u8, entry.tag, tag)) continue;
            entry.last_seen_at = now;
            return entry.locked_until > now;
        }
        return false;
    }

    fn recordUnknownFailure(self: *Service, locator: BootstrapId, now: i64) bool {
        if (now < 0) return true;
        const tag = self.unknownThrottleTag(locator);

        var selected: usize = 0;
        var oldest: i64 = std.math.maxInt(i64);
        for (&self.unknown_throttles, 0..) |*entry, index| {
            if (entry.used and std.crypto.timing_safe.eql([16]u8, entry.tag, tag)) {
                selected = index;
                oldest = std.math.minInt(i64);
                break;
            }
            if (!entry.used) {
                selected = index;
                oldest = std.math.minInt(i64);
                break;
            }
            if (entry.last_seen_at < oldest) {
                oldest = entry.last_seen_at;
                selected = index;
            }
        }
        var entry = &self.unknown_throttles[selected];
        if (!entry.used or !std.crypto.timing_safe.eql([16]u8, entry.tag, tag)) {
            entry.* = .{
                .used = true,
                .tag = tag,
                .failure_count = 1,
                .window_started_at = now,
                .last_seen_at = now,
            };
            return false;
        }
        entry.last_seen_at = now;
        if (entry.locked_until > now) return true;
        if (now < entry.window_started_at or
            now - entry.window_started_at >= management_repository.bootstrap_failure_window_seconds or
            entry.locked_until != 0)
        {
            entry.failure_count = 1;
            entry.window_started_at = now;
            entry.locked_until = 0;
            return false;
        }
        if (entry.failure_count < management_repository.bootstrap_failure_limit) {
            entry.failure_count += 1;
        }
        if (entry.failure_count >= management_repository.bootstrap_failure_limit) {
            entry.locked_until = std.math.add(
                i64,
                now,
                management_repository.bootstrap_cooldown_seconds,
            ) catch std.math.maxInt(i64);
            return true;
        }
        return false;
    }

    fn unknownThrottleTag(self: *const Service, locator: BootstrapId) [16]u8 {
        var full_tag: [HmacSha256.mac_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &full_tag);
        HmacSha256.create(&full_tag, &locator, &self.root_key);
        return full_tag[0..16].*;
    }
};

fn issuedFromPrepared(prepared: *const PreparedBootstrap) IssuedBootstrap {
    return .{
        .node_id = prepared.pending.node_id,
        .bootstrap_id = prepared.pending.locator,
        .secret_code = prepared.secret_code,
        .expires_at = prepared.pending.expires_at,
    };
}

pub fn parseLocator(text: []const u8) !BootstrapId {
    if (text.len != locator_len) return error.InvalidBootstrapLocator;
    var result: BootstrapId = undefined;
    for (text, 0..) |byte, index| {
        if (std.mem.indexOfScalar(u8, alphabet, byte) == null) {
            return error.InvalidBootstrapLocator;
        }
        result[index] = byte;
    }
    return result;
}

pub fn parseCode(text: []const u8) ![code_symbol_len]u8 {
    if (text.len != code_text_len or text[3] != '-' or text[7] != '-') {
        return error.InvalidBootstrapCode;
    }
    var result: [code_symbol_len]u8 = undefined;
    var output_index: usize = 0;
    for (text, 0..) |byte, index| {
        if (index == 3 or index == 7) continue;
        if (std.mem.indexOfScalar(u8, alphabet, byte) == null) return error.InvalidBootstrapCode;
        result[output_index] = byte;
        output_index += 1;
    }
    return result;
}

pub fn renderCode(symbols: *const [code_symbol_len]u8) [code_text_len]u8 {
    var result: [code_text_len]u8 = undefined;
    @memcpy(result[0..3], symbols[0..3]);
    result[3] = '-';
    @memcpy(result[4..7], symbols[3..6]);
    result[7] = '-';
    @memcpy(result[8..11], symbols[6..9]);
    return result;
}

fn encodeRandomSymbols(random: []const u8, output: []u8) void {
    std.debug.assert(random.len == output.len);
    for (random, output) |byte, *symbol| symbol.* = alphabet[byte & 31];
}

pub fn deriveRootKey(
    identity_secret: *const [32]u8,
    master_public: *const [32]u8,
) [32]u8 {
    var prk = Kdf.extract(master_public, identity_secret);
    defer std.crypto.secureZero(u8, &prk);
    var root: [32]u8 = undefined;
    Kdf.expand(&root, root_domain, prk);
    return root;
}

pub fn deriveCredentialSecret(
    root_key: *const [32]u8,
    locator: BootstrapId,
    handle: [16]u8,
    code_symbols: *const [code_symbol_len]u8,
) [32]u8 {
    var mac = HmacSha256.init(root_key);
    mac.update(credential_domain);
    mac.update(&locator);
    mac.update(&handle);
    mac.update(code_symbols);
    var secret: [HmacSha256.mac_length]u8 = undefined;
    mac.final(&secret);
    return secret;
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

test "bootstrap alphabet mapping is unbiased and parsers require canonical text" {
    var counts = [_]u16{0} ** alphabet.len;
    var raw: [256]u8 = undefined;
    var symbols: [256]u8 = undefined;
    for (&raw, 0..) |*byte, index| byte.* = @intCast(index);
    encodeRandomSymbols(&raw, &symbols);
    for (symbols) |symbol| {
        const index = std.mem.indexOfScalar(u8, alphabet, symbol).?;
        counts[index] += 1;
    }
    for (counts) |count| try std.testing.expectEqual(@as(u16, 8), count);

    try std.testing.expectEqualStrings("ABCDEFGH", &(try parseLocator("ABCDEFGH")));
    try std.testing.expectError(error.InvalidBootstrapLocator, parseLocator("abcdefgH"));
    try std.testing.expectError(error.InvalidBootstrapLocator, parseLocator("ABCDEFIH"));
    const code = try parseCode("ABC-DEF-GHJ");
    try std.testing.expectEqualStrings("ABCDEFGHJ", &code);
    try std.testing.expectEqualStrings("ABC-DEF-GHJ", &renderCode(&code));
    try std.testing.expectError(error.InvalidBootstrapCode, parseCode("ABCDEFGHI"));
    try std.testing.expectError(error.InvalidBootstrapCode, parseCode("ABC-DEF-GHI"));
}

test "bootstrap derivation is deterministic and domain-separated" {
    const identity = [_]u8{0x11} ** 32;
    const public = [_]u8{0x22} ** 32;
    var root = deriveRootKey(&identity, &public);
    defer std.crypto.secureZero(u8, &root);
    const locator: BootstrapId = "ABCDEFGH".*;
    const handle = [_]u8{0x33} ** 16;
    const code = "ABCDEFGHJ".*;
    var first = deriveCredentialSecret(&root, locator, handle, &code);
    defer std.crypto.secureZero(u8, &first);
    var second = deriveCredentialSecret(&root, locator, handle, &code);
    defer std.crypto.secureZero(u8, &second);
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, first, second));
    var other_code = code;
    other_code[8] = 'K';
    var changed_code = deriveCredentialSecret(&root, locator, handle, &other_code);
    defer std.crypto.secureZero(u8, &changed_code);
    try std.testing.expect(!std.crypto.timing_safe.eql([32]u8, first, changed_code));
    var other_public = public;
    other_public[0] ^= 1;
    var other_root = deriveRootKey(&identity, &other_public);
    defer std.crypto.secureZero(u8, &other_root);
    try std.testing.expect(!std.crypto.timing_safe.eql([32]u8, root, other_root));
}

test "unknown-locator throttle enforces a bounded keyed cooldown" {
    var service: Service = undefined;
    service.root_key = [_]u8{0x44} ** 32;
    service.unknown_throttles = [_]UnknownThrottle{.{}} ** unknown_throttle_capacity;
    defer {
        std.crypto.secureZero(u8, &service.root_key);
        std.crypto.secureZero(u8, std.mem.asBytes(&service.unknown_throttles));
    }
    const locator: BootstrapId = "ABCDEFGH".*;
    const now: i64 = 100;
    try std.testing.expect(!service.unknownLocatorLocked(locator, now));
    for (0..management_repository.bootstrap_failure_limit - 1) |_| {
        try std.testing.expect(!service.recordUnknownFailure(locator, now));
    }
    try std.testing.expect(service.recordUnknownFailure(locator, now));
    try std.testing.expect(service.unknownLocatorLocked(locator, now + 1));
    try std.testing.expect(!service.unknownLocatorLocked(
        locator,
        now + management_repository.bootstrap_cooldown_seconds,
    ));
}

test "service issues a capped invitation and reconstructs one repeatable protocol credential" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrintZ(
        &path_buffer,
        ".zig-cache/tmp/{s}/ntip.sqlite3",
        .{&tmp.sub_path},
    );
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);

    var candidate = model.Store.init(std.testing.allocator);
    defer candidate.deinit();
    _ = try candidate.createVnr("core", try model.Cidr.parse("10.24.0.0/24"));
    const node_id: model.NodeId = .{ .bytes = [_]u8{0x41} ** 16 };
    try candidate.createNode(
        node_id,
        "edge-a",
        "core",
        try model.Ipv4.parse("10.24.0.2"),
    );
    candidate.generation = 1;

    const identity_secret = [_]u8{0x51} ** 32;
    const master_public = [_]u8{0x61} ** 32;
    var service = try Service.init(
        &repository,
        std.testing.io,
        &identity_secret,
        master_public,
    );
    defer service.deinit();
    var issued = try service.createWithInventory(
        &candidate,
        node_id,
        30 * 24 * 60 * 60,
        100,
        0,
        .{
            .id = [_]u8{0x71} ** 16,
            .occurred_at = 100,
            .actor_kind = .system,
            .action = "enrollment.bootstrap.issue",
            .resource_type = "node",
        },
    );
    defer issued.clear();
    try std.testing.expectEqual(@as(i64, 100 + 86_400), issued.expires_at);
    _ = try parseLocator(&issued.bootstrap_id);
    _ = try parseCode(&issued.secret_code);

    var first = try service.redeem(&issued.bootstrap_id, &issued.secret_code, 101, null);
    defer first.clear();
    var second = try service.redeem(&issued.bootstrap_id, &issued.secret_code, 102, null);
    defer second.clear();
    try std.testing.expectEqualStrings(&first.credential, &second.credential);
    try std.testing.expectEqualStrings("edge-a", first.node_name.slice());
    var decoded = try credential_mod.Credential.decode(&first.credential);
    defer decoded.deinit();
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, decoded.master_public, master_public));

    var wrong_code = issued.secret_code;
    wrong_code[0] = if (wrong_code[0] == 'A') 'B' else 'A';
    try std.testing.expectError(
        error.InvalidBootstrapInvitation,
        service.redeem(&issued.bootstrap_id, &wrong_code, 103, null),
    );
    try std.testing.expectError(
        error.InvalidBootstrapInvitation,
        service.redeem("ZZZZZZZZ", "ABC-DEF-GHJ", 103, null),
    );

    var psk = decoded.derivePsk();
    defer std.crypto.secureZero(u8, &psk);
    _ = try repository.consumeEnrollment(
        decoded.handle,
        psk,
        [_]u8{0x81} ** 32,
        104,
        1,
        .{
            .id = [_]u8{0x72} ** 16,
            .occurred_at = 104,
            .actor_kind = .system,
            .action = "enrollment.consume",
            .resource_type = "node",
        },
    );
    try std.testing.expectError(
        error.InvalidBootstrapInvitation,
        service.redeem(&issued.bootstrap_id, &issued.secret_code, 105, null),
    );

    var replacement = try service.issueForNode(
        node_id,
        3_600,
        106,
        2,
        true,
        .{
            .id = [_]u8{0x73} ** 16,
            .occurred_at = 106,
            .actor_kind = .system,
            .action = "enrollment.bootstrap.reset",
            .resource_type = "node",
        },
    );
    defer replacement.clear();
    try std.testing.expect(!std.mem.eql(u8, &replacement.bootstrap_id, &issued.bootstrap_id));
    var reset_redeemed = try service.redeem(
        &replacement.bootstrap_id,
        &replacement.secret_code,
        107,
        null,
    );
    defer reset_redeemed.clear();
    try std.testing.expectEqualStrings("edge-a", reset_redeemed.node_name.slice());
}
