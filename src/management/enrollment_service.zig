//! Transport-independent enrollment administration for the v0.2 web API.
//!
//! The serialized operator worker is the sole production caller. This layer
//! revalidates authorization and dangerous-operation preconditions, generates
//! one-time browser credentials, commits through `management_repository`, and
//! publishes the live Store only after SQLite is durable. HTTP response
//! framing and idempotency replay storage remain responsibilities of the
//! central API dispatcher.

const std = @import("std");
const model = @import("../domain/model.zig");
const credential_mod = @import("../protocol/credential.zig");
const management_repository = @import("../state/management_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const auth = @import("auth.zig");
const settings = @import("settings.zig");
const inventory_service = @import("inventory_service.zig");
const security_policy = @import("security_policy.zig");
const service_ipc = @import("service_ipc.zig");

pub const minimum_lifetime_seconds: u64 = settings.minimum_enrollment_lifetime_seconds;
pub const maximum_lifetime_seconds: u64 = settings.maximum_enrollment_lifetime_seconds;
pub const maximum_proxy_peer_bytes: usize = 255;

const enrollment_projection_sql =
    "CASE WHEN nodes.enrollment_state = 'enrolled' THEN 'enrolled' " ++
    "WHEN EXISTS (SELECT 1 FROM enrollment_credentials AS credential " ++
    "WHERE credential.node_id = nodes.id AND credential.status = 'unused' " ++
    "AND credential.expires_at > ?1) THEN 'credential_issued' " ++
    "ELSE 'unenrolled' END";

pub const NodeRecord = inventory_service.NodeRecord;
pub const ResourceEtag = inventory_service.ResourceEtag;
pub const Callbacks = inventory_service.Callbacks;

pub const Principal = struct {
    user_id: [16]u8,
    session_id: [16]u8,
    role: auth.Role,
    /// This value comes from the authenticated server-side session, never a
    /// client-supplied header or body field.
    reauthenticated_at: ?i64,
    user_agent: ?[]const u8 = null,
    proxy_peer: ?[]const u8 = null,
};

pub const RequestContext = struct {
    request_id: [16]u8,
    occurred_at: i64,
    preconditions: service_ipc.Preconditions,

    /// Validation is repeated here for direct callers. The central dispatcher
    /// reserves the key and stores/replays the final encoded response.
    pub fn requireIdempotency(self: RequestContext) ![32]u8 {
        const key = self.preconditions.idempotency_key orelse return error.IdempotencyRequired;
        if (key.len == 0 or key.len > service_ipc.maximum_idempotency_key_bytes) {
            return error.InvalidIdempotencyKey;
        }
        for (key) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidIdempotencyKey;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
        return digest;
    }
};

/// Owns the only recoverable credential representation returned by this
/// service. The caller must copy it into the no-store download response and
/// immediately call `clear`, including on transport failure.
pub const IssuedCredential = struct {
    node_id: model.NodeId,
    expires_at: i64,
    bytes: [credential_mod.text_len]u8,

    pub fn slice(self: *const IssuedCredential) []const u8 {
        return &self.bytes;
    }

    pub fn clear(self: *IssuedCredential) void {
        std.crypto.secureZero(u8, &self.bytes);
        std.crypto.secureZero(u8, &self.node_id.bytes);
        self.expires_at = 0;
    }
};

comptime {
    std.debug.assert(!@hasField(IssuedCredential, "secret"));
    std.debug.assert(!@hasField(IssuedCredential, "derived_psk"));
    std.debug.assert(credential_mod.text_len == 122);
}

pub const Service = struct {
    repository: *management_repository.Repository,
    live: *model.Store,
    allocator: std.mem.Allocator,
    io: std.Io,
    master_public: [32]u8,
    callbacks: Callbacks = .{},

    pub fn init(
        repository: *management_repository.Repository,
        live: *model.Store,
        allocator: std.mem.Allocator,
        io: std.Io,
        master_public: [32]u8,
        callbacks: Callbacks,
    ) !Service {
        if (allZero(&master_public)) return error.InvalidMasterPublicKey;
        if (try repository.durableGeneration() != live.generation) {
            return error.PreconditionFailed;
        }
        return .{
            .repository = repository,
            .live = live,
            .allocator = allocator,
            .io = io,
            .master_public = master_public,
            .callbacks = callbacks,
        };
    }

    /// Issues or replaces the unused credential for an unenrolled Node. Only
    /// the HKDF-derived PSK reaches SQLite; the raw text remains caller-owned
    /// memory and is returned exactly once.
    pub fn issueCredential(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        node_id: model.NodeId,
        lifetime_seconds: u64,
    ) !IssuedCredential {
        try validateMutation(principal, context);
        _ = try context.requireIdempotency();
        if (lifetime_seconds < minimum_lifetime_seconds or
            lifetime_seconds > maximum_lifetime_seconds)
        {
            return error.InvalidCredentialLifetime;
        }

        const current = try self.readNode(node_id, context.occurred_at);
        try validateDangerous(principal, context, current);
        if (current.enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;
        const lifetime: i64 = @intCast(lifetime_seconds);
        const expires_at = std.math.add(i64, context.occurred_at, lifetime) catch
            return error.InvalidCredentialLifetime;

        // All allocations and output construction precede the transaction so
        // no fallible work remains between commit and projection publication.
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try advanceGeneration(&candidate);
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);

        var credential = try self.generateUnusedCredential();
        defer credential.deinit();
        var derived_psk = credential.derivePsk();
        defer std.crypto.secureZero(u8, &derived_psk);
        var issued: IssuedCredential = .{
            .node_id = node_id,
            .expires_at = expires_at,
            .bytes = undefined,
        };
        _ = credential.encode(&issued.bytes);
        errdefer issued.clear();

        var resource_id: [32]u8 = undefined;
        const committed_generation = try self.repository.replaceEnrollment(
            node_id,
            credential.handle,
            derived_psk,
            false,
            context.occurred_at,
            expires_at,
            self.live.generation,
            .{
                .id = model.NodeId.generate(self.io).bytes,
                .occurred_at = context.occurred_at,
                .actor_kind = .web,
                .actor_id = principal.user_id,
                .action = "enrollment.credential.issue",
                .resource_type = "node",
                .resource_id = node_id.write(&resource_id),
                .request_id = context.request_id,
                .details_json = audit_details,
            },
        );
        std.debug.assert(committed_generation == candidate.generation);
        self.installCommitted(&candidate, &.{});
        return issued;
    }

    /// Revokes any unused credential and clears an active enrollment without
    /// issuing replacement material. An active data-plane association is
    /// retired after commit and before the committed generation is published.
    pub fn resetEnrollment(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        node_id: model.NodeId,
    ) !NodeRecord {
        try validateMutation(principal, context);
        _ = try context.requireIdempotency();
        const current = try self.readNode(node_id, context.occurred_at);
        try validateDangerous(principal, context, current);
        const was_enrolled = current.enrollment_state == .enrolled;

        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        if (was_enrolled) {
            try candidate.resetNodeEnrollment(current.name.slice());
        } else {
            try advanceGeneration(&candidate);
        }

        var result = current;
        result.enrollment_state = .unenrolled;
        if (was_enrolled) {
            result.revision = try nextRevision(current.revision);
            result.updated_at = context.occurred_at;
        }
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        var resource_id: [32]u8 = undefined;
        const committed_generation = try self.repository.resetEnrollment(
            node_id,
            context.occurred_at,
            self.live.generation,
            .{
                .id = model.NodeId.generate(self.io).bytes,
                .occurred_at = context.occurred_at,
                .actor_kind = .web,
                .actor_id = principal.user_id,
                .action = "enrollment.reset",
                .resource_type = "node",
                .resource_id = node_id.write(&resource_id),
                .request_id = context.request_id,
                .details_json = audit_details,
            },
        );
        std.debug.assert(committed_generation == candidate.generation);
        const retire_ids = [_]model.NodeId{node_id};
        self.installCommitted(&candidate, if (was_enrolled) &retire_ids else &.{});
        return result;
    }

    fn readNode(self: *Service, id: model.NodeId, observed_at: i64) !NodeRecord {
        if (observed_at < 0) return error.InvalidTimestamp;
        var statement = try self.repository.db.prepare(
            "SELECT nodes.id,nodes.name,nodes.vnr_name,nodes.address," ++
                enrollment_projection_sql ++
                ",nodes.revision,nodes.created_at,nodes.updated_at FROM nodes WHERE nodes.id = ?2;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, observed_at);
        try statement.bindBlob(2, &id.bytes);
        if (try statement.step() != .row) return error.NodeNotFound;
        const record: NodeRecord = .{
            .id = try columnId(&statement, 0),
            .name = model.Name.parse(statement.columnText(1) orelse return error.CorruptInventory) catch
                return error.CorruptInventory,
            .vnr = model.Name.parse(statement.columnText(2) orelse return error.CorruptInventory) catch
                return error.CorruptInventory,
            .address = .{ .value = try columnU32(&statement, 3) },
            .enrollment_state = try columnEnrollmentState(&statement, 4),
            .revision = try columnRevision(&statement, 5),
            .created_at = try columnTimestamp(&statement, 6),
            .updated_at = try columnTimestamp(&statement, 7),
        };
        if (try statement.step() != .done) return error.CorruptInventory;
        const live_node = self.live.findNodeById(id) orelse return error.ProjectionMismatch;
        const live_state_matches = switch (record.enrollment_state) {
            .enrolled => live_node.enrollment_state == .enrolled,
            .unenrolled, .credential_issued => live_node.enrollment_state == .unenrolled,
        };
        if (!live_node.name.eql(record.name) or !live_node.vnr.eql(record.vnr) or
            live_node.address.value != record.address.value or !live_state_matches)
        {
            return error.ProjectionMismatch;
        }
        return record;
    }

    fn generateUnusedCredential(self: *Service) !credential_mod.Credential {
        while (true) {
            var credential: credential_mod.Credential = .{
                .handle = undefined,
                .secret = undefined,
                .master_public = self.master_public,
            };
            self.io.random(&credential.handle);
            self.io.random(&credential.secret);
            if (allZero(&credential.handle) or allZero(&credential.secret) or
                try self.enrollmentHandleExists(credential.handle))
            {
                credential.deinit();
                continue;
            }
            return credential;
        }
    }

    fn enrollmentHandleExists(self: *Service, handle: [16]u8) !bool {
        var statement = try self.repository.db.prepare(
            "SELECT 1 FROM enrollment_credentials WHERE handle = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &handle);
        return switch (try statement.step()) {
            .done => false,
            .row => blk: {
                if (try statement.step() != .done) return error.CorruptEnrollmentCredential;
                break :blk true;
            },
        };
    }

    fn installCommitted(
        self: *Service,
        candidate: *model.Store,
        retire_ids: []const model.NodeId,
    ) void {
        std.mem.swap(model.Store, self.live, candidate);
        if (retire_ids.len != 0) if (self.callbacks.retire_associations) |retire| {
            retire(self.callbacks.context, retire_ids);
        };
        if (self.callbacks.publish_generation) |publish| {
            publish(self.callbacks.context, self.live.generation, self.live);
        }
    }
};

fn validateMutation(principal: Principal, context: RequestContext) !void {
    if (allZero(&principal.user_id) or allZero(&principal.session_id)) return error.InvalidPrincipal;
    if (!auth.allows(principal.role, .manage_enrollment)) return error.Forbidden;
    if (allZero(&context.request_id)) return error.InvalidRequestId;
    if (context.occurred_at < 0) return error.InvalidTimestamp;
    try validateAuditText(principal.user_agent, service_ipc.maximum_user_agent_bytes);
    try validateAuditText(principal.proxy_peer, maximum_proxy_peer_bytes);
}

fn validateDangerous(principal: Principal, context: RequestContext, current: NodeRecord) !void {
    const reauthenticated_at: ?u64 = if (principal.reauthenticated_at) |value| blk: {
        if (value < 0) return error.InvalidTimestamp;
        break :blk @intCast(value);
    } else null;
    var current_etag = current.etag();
    try security_policy.validateDangerous(.{
        .role = principal.role,
        .reauthenticated_at = reauthenticated_at,
        .now = @intCast(context.occurred_at),
        .supplied_etag = context.preconditions.etag,
        .current_etag = current_etag.slice(),
        .supplied_confirmation = context.preconditions.confirmation,
        .required_confirmation = current.name.slice(),
    });
}

fn validateAuditText(value: ?[]const u8, maximum: usize) !void {
    const text = value orelse return;
    if (text.len > maximum or !std.unicode.utf8ValidateSlice(text)) return error.InvalidAuditMetadata;
    for (text) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidAuditMetadata;
}

fn encodeAuditDetails(allocator: std.mem.Allocator, principal: Principal) ![]u8 {
    const Details = struct {
        userAgent: ?[]const u8 = null,
        proxyPeer: ?[]const u8 = null,
    };
    return std.json.Stringify.valueAlloc(allocator, Details{
        .userAgent = principal.user_agent,
        .proxyPeer = principal.proxy_peer,
    }, .{ .emit_null_optional_fields = false });
}

fn cloneStore(allocator: std.mem.Allocator, source: *const model.Store) !model.Store {
    var result = model.Store.init(allocator);
    errdefer result.deinit();
    result.generation = source.generation;
    try result.vnrs.appendSlice(allocator, source.vnrs.items);
    try result.nodes.appendSlice(allocator, source.nodes.items);
    try result.routes.appendSlice(allocator, source.routes.items);
    return result;
}

fn advanceGeneration(store: *model.Store) !void {
    store.generation = std.math.add(u64, store.generation, 1) catch
        return error.GenerationOverflow;
    if (store.generation > std.math.maxInt(i64)) return error.GenerationOverflow;
}

fn nextRevision(current: u64) !u64 {
    const next = std.math.add(u64, current, 1) catch return error.RevisionOverflow;
    if (next > std.math.maxInt(i64)) return error.RevisionOverflow;
    return next;
}

fn columnId(statement: *const sqlite.Statement, index: c_int) !model.NodeId {
    const blob = statement.columnBlob(index) orelse return error.CorruptInventory;
    if (blob.len != 16) return error.CorruptInventory;
    var id: model.NodeId = undefined;
    @memcpy(&id.bytes, blob);
    return id;
}

fn columnU32(statement: *const sqlite.Statement, index: c_int) !u32 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u32)) return error.CorruptInventory;
    return @intCast(value);
}

fn columnRevision(statement: *const sqlite.Statement, index: c_int) !u64 {
    const value = statement.columnInt64(index);
    if (value <= 0) return error.CorruptInventory;
    return @intCast(value);
}

fn columnTimestamp(statement: *const sqlite.Statement, index: c_int) !i64 {
    const value = statement.columnInt64(index);
    if (value < 0) return error.CorruptInventory;
    return value;
}

fn columnEnrollmentState(statement: *const sqlite.Statement, index: c_int) !inventory_service.EnrollmentState {
    const text = statement.columnText(index) orelse return error.CorruptInventory;
    if (std.mem.eql(u8, text, "unenrolled")) return .unenrolled;
    if (std.mem.eql(u8, text, "credential_issued")) return .credential_issued;
    if (std.mem.eql(u8, text, "enrolled")) return .enrolled;
    return error.CorruptInventory;
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

const CallbackRecorder = struct {
    repository: *management_repository.Repository,
    events: [8]enum { retire, publish } = undefined,
    event_count: usize = 0,
    retire_count: usize = 0,
    retired_id: ?model.NodeId = null,
    publish_count: usize = 0,
    last_generation: u64 = 0,
    durable_at_callback: u64 = 0,

    fn onRetire(context: ?*anyopaque, ids: []const model.NodeId) void {
        const self: *CallbackRecorder = @ptrCast(@alignCast(context.?));
        self.events[self.event_count] = .retire;
        self.event_count += 1;
        self.retire_count += ids.len;
        if (ids.len == 1) self.retired_id = ids[0];
        self.durable_at_callback = self.repository.durableGeneration() catch 0;
    }

    fn onPublish(context: ?*anyopaque, generation: u64, store: *const model.Store) void {
        const self: *CallbackRecorder = @ptrCast(@alignCast(context.?));
        self.events[self.event_count] = .publish;
        self.event_count += 1;
        self.publish_count += 1;
        self.last_generation = generation;
        self.durable_at_callback = self.repository.durableGeneration() catch 0;
        std.debug.assert(store.generation == generation);
    }

    fn callbacks(self: *CallbackRecorder) Callbacks {
        return .{
            .context = self,
            .retire_associations = onRetire,
            .publish_generation = onPublish,
        };
    }

    fn reset(self: *CallbackRecorder) void {
        self.event_count = 0;
        self.retire_count = 0;
        self.retired_id = null;
        self.publish_count = 0;
        self.last_generation = 0;
        self.durable_at_callback = 0;
    }
};

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testPrincipal(role: auth.Role, reauthenticated_at: ?i64) Principal {
    return .{
        .user_id = [_]u8{0xa1} ** 16,
        .session_id = [_]u8{0xb2} ** 16,
        .role = role,
        .reauthenticated_at = reauthenticated_at,
        .user_agent = "ntip-test/1",
        .proxy_peer = "loopback",
    };
}

fn testContext(
    now: i64,
    request_byte: u8,
    etag: ?[]const u8,
    confirmation: ?[]const u8,
    idempotency_key: ?[]const u8,
) RequestContext {
    return .{
        .request_id = [_]u8{request_byte} ** 16,
        .occurred_at = now,
        .preconditions = .{
            .etag = etag,
            .confirmation = confirmation,
            .idempotency_key = idempotency_key,
        },
    };
}

fn seedNode(
    repository: *management_repository.Repository,
    live: *model.Store,
    io: std.Io,
) !NodeRecord {
    var inventory = inventory_service.Service.init(
        repository,
        live,
        std.testing.allocator,
        io,
        .{},
    );
    const operator: inventory_service.Principal = .{
        .id = [_]u8{0x31} ** 16,
        .role = .operator,
    };
    _ = try inventory.createVnr(operator, .{
        .request_id = [_]u8{0x32} ** 16,
        .occurred_at = 10,
    }, .{
        .name = "core",
        .range = try model.Cidr.parse("10.24.0.0/24"),
    });
    return inventory.createNode(operator, .{
        .request_id = [_]u8{0x33} ** 16,
        .occurred_at = 11,
    }, .{
        .name = "edge-a",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.24.0.2"),
    });
}

fn scalarInt(db: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try db.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const value = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return value;
}

fn credentialStatus(db: *sqlite.Database, handle: [16]u8) !struct {
    status: []const u8,
    derived_psk: ?[32]u8,
} {
    var statement = try db.prepare(
        "SELECT status,derived_psk FROM enrollment_credentials WHERE handle = ?1;",
    );
    defer statement.deinit();
    try statement.bindBlob(1, &handle);
    if (try statement.step() != .row) return error.EnrollmentCredentialNotFound;
    const status_text = statement.columnText(0) orelse return error.CorruptEnrollmentCredential;
    const status = if (std.mem.eql(u8, status_text, "unused"))
        "unused"
    else if (std.mem.eql(u8, status_text, "consumed"))
        "consumed"
    else if (std.mem.eql(u8, status_text, "revoked"))
        "revoked"
    else
        return error.CorruptEnrollmentCredential;
    const derived_psk: ?[32]u8 = if (statement.columnBlob(1)) |blob| blk: {
        if (blob.len != 32) return error.CorruptEnrollmentCredential;
        break :blk blob[0..32].*;
    } else null;
    if (try statement.step() != .done) return error.CorruptEnrollmentCredential;
    return .{ .status = status, .derived_psk = derived_psk };
}

test "enrollment mutations require superuser reauthentication ETag confirmation and idempotency" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    const node = try seedNode(&repository, &live, std.testing.io);
    var service = try Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        [_]u8{0x71} ** 32,
        .{},
    );
    var etag = node.etag();

    try std.testing.expectError(error.Forbidden, service.issueCredential(
        testPrincipal(.viewer, 100),
        testContext(100, 1, etag.slice(), "edge-a", "issue-1"),
        node.id,
        minimum_lifetime_seconds,
    ));
    try std.testing.expectError(error.ReauthenticationRequired, service.issueCredential(
        testPrincipal(.superuser, null),
        testContext(100, 2, etag.slice(), "edge-a", "issue-2"),
        node.id,
        minimum_lifetime_seconds,
    ));
    try std.testing.expectError(error.IdempotencyRequired, service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 3, etag.slice(), "edge-a", null),
        node.id,
        minimum_lifetime_seconds,
    ));
    try std.testing.expectError(error.InvalidIdempotencyKey, service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 4, etag.slice(), "edge-a", "not visible"),
        node.id,
        minimum_lifetime_seconds,
    ));
    try std.testing.expectError(error.PreconditionRequired, service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 5, null, "edge-a", "issue-5"),
        node.id,
        minimum_lifetime_seconds,
    ));
    var stale = ResourceEtag.forNode(node.id, node.revision + 1);
    try std.testing.expectError(error.PreconditionFailed, service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 6, stale.slice(), "edge-a", "issue-6"),
        node.id,
        minimum_lifetime_seconds,
    ));
    try std.testing.expectError(error.ConfirmationFailed, service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 7, etag.slice(), "EDGE-A", "issue-7"),
        node.id,
        minimum_lifetime_seconds,
    ));
    try std.testing.expectError(error.InvalidCredentialLifetime, service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 8, etag.slice(), "edge-a", "issue-8"),
        node.id,
        minimum_lifetime_seconds - 1,
    ));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials;"));
    try std.testing.expectEqual(@as(u64, 2), live.generation);
}

test "credential replacement persists only the verifier and raw output is explicitly wiped" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    const node = try seedNode(&repository, &live, std.testing.io);
    var recorder: CallbackRecorder = .{ .repository = &repository };
    var service = try Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        [_]u8{0x72} ** 32,
        recorder.callbacks(),
    );
    var etag = node.etag();

    var first = try service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 10, etag.slice(), "edge-a", "issue-first"),
        node.id,
        3600,
    );
    var first_decoded = try credential_mod.Credential.decode(first.slice());
    defer first_decoded.deinit();
    var first_psk = first_decoded.derivePsk();
    defer std.crypto.secureZero(u8, &first_psk);
    const first_row = try credentialStatus(&db, first_decoded.handle);
    try std.testing.expectEqualStrings("unused", first_row.status);
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, first_psk, first_row.derived_psk.?));
    try std.testing.expect(!std.crypto.timing_safe.eql([32]u8, first_decoded.secret, first_row.derived_psk.?));
    try std.testing.expectEqual(
        inventory_service.EnrollmentState.credential_issued,
        (try service.readNode(node.id, 100)).enrollment_state,
    );

    var second = try service.issueCredential(
        testPrincipal(.superuser, 101),
        testContext(101, 11, etag.slice(), "edge-a", "issue-second"),
        node.id,
        7200,
    );
    defer second.clear();
    var second_decoded = try credential_mod.Credential.decode(second.slice());
    defer second_decoded.deinit();
    const revoked = try credentialStatus(&db, first_decoded.handle);
    const current = try credentialStatus(&db, second_decoded.handle);
    try std.testing.expectEqualStrings("revoked", revoked.status);
    try std.testing.expect(revoked.derived_psk == null);
    try std.testing.expectEqualStrings("unused", current.status);
    try std.testing.expect(current.derived_psk != null);
    try std.testing.expectEqual(
        inventory_service.EnrollmentState.credential_issued,
        (try service.readNode(node.id, 101)).enrollment_state,
    );
    try std.testing.expectEqual(
        inventory_service.EnrollmentState.unenrolled,
        (try service.readNode(node.id, second.expires_at)).enrollment_state,
    );
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused';"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE details_json LIKE '%ntip-enroll-v1%';"));
    try std.testing.expectEqual(@as(usize, 2), recorder.publish_count);
    try std.testing.expectEqual(@as(usize, 0), recorder.retire_count);
    try std.testing.expectEqual(live.generation, recorder.durable_at_callback);

    first.clear();
    try std.testing.expect(allZero(&first.bytes));
    try std.testing.expect(allZero(&first.node_id.bytes));
    try std.testing.expectEqual(@as(i64, 0), first.expires_at);
}

test "reset revokes an unused credential without issuing a replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    const node = try seedNode(&repository, &live, std.testing.io);
    var recorder: CallbackRecorder = .{ .repository = &repository };
    var service = try Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        [_]u8{0x73} ** 32,
        recorder.callbacks(),
    );
    var etag = node.etag();
    var issued = try service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 20, etag.slice(), "edge-a", "issue-before-reset"),
        node.id,
        3600,
    );
    var decoded = try credential_mod.Credential.decode(issued.slice());
    defer decoded.deinit();
    issued.clear();
    recorder.reset();

    const reset = try service.resetEnrollment(
        testPrincipal(.superuser, 101),
        testContext(101, 21, etag.slice(), "edge-a", "reset-unused"),
        node.id,
    );
    try std.testing.expectEqual(inventory_service.EnrollmentState.unenrolled, reset.enrollment_state);
    try std.testing.expectEqual(node.revision, reset.revision);
    const row = try credentialStatus(&db, decoded.handle);
    try std.testing.expectEqualStrings("revoked", row.status);
    try std.testing.expect(row.derived_psk == null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials;"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused';"));
    try std.testing.expectEqual(@as(usize, 0), recorder.retire_count);
    try std.testing.expectEqual(@as(usize, 1), recorder.publish_count);
    try std.testing.expectEqual(live.generation, recorder.durable_at_callback);
}

test "active reset commits before association retirement and one projection publication" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    const node = try seedNode(&repository, &live, std.testing.io);
    var recorder: CallbackRecorder = .{ .repository = &repository };
    var service = try Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        [_]u8{0x74} ** 32,
        recorder.callbacks(),
    );
    var initial_etag = node.etag();
    var issued = try service.issueCredential(
        testPrincipal(.superuser, 100),
        testContext(100, 30, initial_etag.slice(), "edge-a", "issue-active"),
        node.id,
        3600,
    );
    var decoded = try credential_mod.Credential.decode(issued.slice());
    defer decoded.deinit();
    var psk = decoded.derivePsk();
    defer std.crypto.secureZero(u8, &psk);
    issued.clear();

    const public_key = [_]u8{0x55} ** 32;
    const consumed = try repository.consumeEnrollment(
        decoded.handle,
        psk,
        public_key,
        101,
        live.generation,
        .{
            .id = [_]u8{0xd1} ** 16,
            .occurred_at = 101,
            .actor_kind = .system,
            .action = "enrollment.consume",
            .resource_type = "node",
        },
    );
    try live.bindNodePublicKey("edge-a", public_key);
    try std.testing.expectEqual(consumed.generation, live.generation);
    const enrolled = try service.readNode(node.id, 101);
    var enrolled_etag = enrolled.etag();
    recorder.reset();

    try std.testing.expectError(error.NodeAlreadyEnrolled, service.issueCredential(
        testPrincipal(.superuser, 102),
        testContext(102, 31, enrolled_etag.slice(), "edge-a", "issue-enrolled"),
        node.id,
        3600,
    ));
    try std.testing.expectEqual(@as(usize, 0), recorder.event_count);

    const reset = try service.resetEnrollment(
        testPrincipal(.superuser, 103),
        testContext(103, 32, enrolled_etag.slice(), "edge-a", "reset-active"),
        node.id,
    );
    try std.testing.expectEqual(inventory_service.EnrollmentState.unenrolled, reset.enrollment_state);
    try std.testing.expectEqual(enrolled.revision + 1, reset.revision);
    try std.testing.expectEqual(@as(usize, 2), recorder.event_count);
    try std.testing.expectEqual(.retire, recorder.events[0]);
    try std.testing.expectEqual(.publish, recorder.events[1]);
    try std.testing.expectEqual(@as(usize, 1), recorder.retire_count);
    try std.testing.expect(recorder.retired_id.?.eql(node.id));
    try std.testing.expectEqual(@as(usize, 1), recorder.publish_count);
    try std.testing.expectEqual(live.generation, recorder.last_generation);
    try std.testing.expectEqual(live.generation, recorder.durable_at_callback);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials;"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused';"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM nodes WHERE enrollment_state = 'unenrolled' AND public_key IS NULL;"));

    try std.testing.expectError(error.PreconditionFailed, service.resetEnrollment(
        testPrincipal(.superuser, 104),
        testContext(104, 33, enrolled_etag.slice(), "edge-a", "reset-stale"),
        node.id,
    ));
    try std.testing.expectEqual(@as(usize, 2), recorder.event_count);
}
