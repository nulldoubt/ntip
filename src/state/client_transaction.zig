//! Crash-recoverable Node reconfiguration.
//!
//! `ntcl config` replaces both public configuration and private enrollment
//! state, and it must also revoke any prior local static identity. A private,
//! checksummed write-ahead intent makes those independent filesystem changes
//! one recoverable operation. Recovery always rolls a fully validated intent
//! forward and is safe to repeat after a crash at any boundary.

const std = @import("std");
const atomic = @import("atomic_file.zig");
const client = @import("client.zig");
const config = @import("config.zig");
const secret_store = @import("secret_store.zig");
const credential = @import("../protocol/credential.zig");

const magic = "NTIPCTXN";
const format_version: u8 = 1;
const header_len: usize = 16;
const digest_len: usize = 32;
pub const intent_file = "reconfigure.pending";
pub const maximum_intent_bytes = header_len + config.max_config_bytes + credential.text_len + digest_len;

pub const FaultPoint = enum {
    none,
    after_intent,
    after_token,
    after_config,
    after_identity_delete,
    after_state,
};

pub fn commit(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    config_path: []const u8,
    config_bytes: []const u8,
    credential_text: []const u8,
) !void {
    return commitFaultInjected(allocator, io, dir, config_path, config_bytes, credential_text, .none);
}

pub fn commitFaultInjected(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    config_path: []const u8,
    config_bytes: []const u8,
    credential_text: []const u8,
    fault: FaultPoint,
) !void {
    try validatePayload(allocator, config_bytes, credential_text);
    const intent = try encodeIntent(allocator, config_bytes, credential_text);
    defer {
        std.crypto.secureZero(u8, intent);
        allocator.free(intent);
    }
    try atomic.replace(dir, io, intent_file, intent, atomic.private_file_permissions);
    if (fault == .after_intent) return error.InjectedFailure;
    _ = try recoverFaultInjected(allocator, io, dir, config_path, fault);
}

/// Must run while holding `state.lock`, before configuration, client state, or
/// identity is loaded. A malformed or newer intent fails closed and remains in
/// place for operator inspection.
pub fn recover(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    config_path: []const u8,
) !bool {
    return recoverFaultInjected(allocator, io, dir, config_path, .none);
}

pub fn recoverFaultInjected(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    config_path: []const u8,
    fault: FaultPoint,
) !bool {
    const stat = dir.statFile(io, intent_file, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidClientTransactionFileType;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;

    const bytes = try atomic.readAlloc(dir, io, intent_file, allocator, maximum_intent_bytes);
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    const decoded = try decodeIntent(bytes);
    try validatePayload(allocator, decoded.config, decoded.credential);
    if (fault == .after_intent) return error.InjectedFailure;

    const secrets: secret_store.FileSecretStore = .{ .dir = dir };
    try secrets.write(allocator, io, "enrollment.token", .enrollment_token, decoded.credential);
    if (fault == .after_token) return error.InjectedFailure;

    try replaceConfigPath(io, config_path, decoded.config);
    if (fault == .after_config) return error.InjectedFailure;

    deleteIfPresentDurable(dir, io, "identity.key") catch |err| return err;
    if (fault == .after_identity_delete) return error.InjectedFailure;

    try (client.File{ .dir = dir }).save(allocator, io, .{});
    if (fault == .after_state) return error.InjectedFailure;

    try atomic.deleteDurable(dir, io, intent_file);
    return true;
}

const Intent = struct {
    config: []const u8,
    credential: []const u8,
};

fn encodeIntent(allocator: std.mem.Allocator, config_bytes: []const u8, credential_text: []const u8) ![]u8 {
    if (config_bytes.len == 0 or config_bytes.len > config.max_config_bytes or
        credential_text.len != credential.text_len)
    {
        return error.ClientTransactionPayloadTooLarge;
    }
    const payload_end = std.math.add(usize, header_len, config_bytes.len) catch return error.ClientTransactionPayloadTooLarge;
    const credential_end = std.math.add(usize, payload_end, credential_text.len) catch return error.ClientTransactionPayloadTooLarge;
    const total = std.math.add(usize, credential_end, digest_len) catch return error.ClientTransactionPayloadTooLarge;
    if (total > maximum_intent_bytes) return error.ClientTransactionPayloadTooLarge;

    const bytes = try allocator.alloc(u8, total);
    @memcpy(bytes[0..8], magic);
    bytes[8] = format_version;
    @memset(bytes[9..12], 0);
    std.mem.writeInt(u32, bytes[12..16], @intCast(config_bytes.len), .big);
    @memcpy(bytes[header_len..payload_end], config_bytes);
    @memcpy(bytes[payload_end..credential_end], credential_text);
    std.crypto.hash.blake2.Blake2s256.hash(bytes[0..credential_end], bytes[credential_end..][0..digest_len], .{});
    return bytes;
}

fn decodeIntent(bytes: []const u8) !Intent {
    if (bytes.len < header_len + credential.text_len + digest_len or bytes.len > maximum_intent_bytes) {
        return error.InvalidClientTransaction;
    }
    if (!std.mem.eql(u8, bytes[0..8], magic)) return error.InvalidClientTransaction;
    if (bytes[8] != format_version) return error.UnsupportedClientTransactionVersion;
    if (!std.mem.eql(u8, bytes[9..12], &([_]u8{0} ** 3))) return error.InvalidClientTransaction;
    const config_len: usize = std.mem.readInt(u32, bytes[12..16], .big);
    if (config_len == 0 or config_len > config.max_config_bytes) return error.InvalidClientTransaction;
    const config_end = std.math.add(usize, header_len, config_len) catch return error.InvalidClientTransaction;
    const credential_end = std.math.add(usize, config_end, credential.text_len) catch return error.InvalidClientTransaction;
    if (credential_end + digest_len != bytes.len) return error.InvalidClientTransaction;

    var expected: [digest_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &expected);
    std.crypto.hash.blake2.Blake2s256.hash(bytes[0..credential_end], &expected, .{});
    if (!std.crypto.timing_safe.eql([digest_len]u8, expected, bytes[credential_end..][0..digest_len].*)) {
        return error.InvalidClientTransactionDigest;
    }
    return .{
        .config = bytes[header_len..config_end],
        .credential = bytes[config_end..credential_end],
    };
}

fn validatePayload(allocator: std.mem.Allocator, config_bytes: []const u8, credential_text: []const u8) !void {
    if (config_bytes.len == 0 or config_bytes.len > config.max_config_bytes) return error.InvalidClientTransaction;
    const parsed = try config.decodeClient(allocator, config_bytes);
    defer parsed.deinit();
    var enrollment = try credential.Credential.decode(credential_text);
    defer enrollment.deinit();
    const configured_master = try config.decodePublicKey(parsed.value.master_public_key);
    if (!std.crypto.timing_safe.eql([32]u8, configured_master, enrollment.master_public)) {
        return error.ClientTransactionIdentityMismatch;
    }
}

fn replaceConfigPath(io: std.Io, path: []const u8, bytes: []const u8) !void {
    if (path.len == 0) return error.InvalidPath;
    const dirname = std.fs.path.dirname(path) orelse ".";
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidPath;
    const permissions = std.Io.File.Permissions.fromMode(0o755);
    const cwd = std.Io.Dir.cwd();
    const dir = openDirectory(io, dirname) catch |err| switch (err) {
        error.FileNotFound => blk: {
            _ = try cwd.createDirPathStatus(io, dirname, permissions);
            break :blk try openDirectory(io, dirname);
        },
        else => return err,
    };
    defer dir.close(io);
    try atomic.replace(dir, io, basename, bytes, atomic.public_config_permissions);
}

fn openDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    return if (std.fs.path.isAbsolute(path))
        std.Io.Dir.openDirAbsolute(io, path, .{})
    else
        std.Io.Dir.cwd().openDir(io, path, .{});
}

fn deleteIfPresentDurable(dir: std.Io.Dir, io: std.Io, sub_path: []const u8) !void {
    atomic.deleteDurable(dir, io, sub_path) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
}

test "crashes at every Node reconfiguration boundary recover one complete replacement" {
    inline for (.{
        FaultPoint.after_intent,
        .after_token,
        .after_config,
        .after_identity_delete,
        .after_state,
    }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
        defer std.testing.allocator.free(root);
        const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
        defer std.testing.allocator.free(config_path);

        const old_key = [_]u8{0x77} ** 32;
        const secrets: secret_store.FileSecretStore = .{ .dir = tmp.dir };
        try secrets.write(std.testing.allocator, std.testing.io, "identity.key", .identity_key, &old_key);
        try (client.File{ .dir = tmp.dir }).save(std.testing.allocator, std.testing.io, .{
            .generation = 9,
            .enrollment_state = .enrolled,
            .node_id = .{ .bytes = .{0x22} ** 16 },
            .assigned_address = try @import("../domain/model.zig").Ipv4.parse("10.1.0.2"),
            .vnr_range = try @import("../domain/model.zig").Cidr.parse("10.1.0.0/24"),
        });

        const master_public = [_]u8{0x33} ** 32;
        const new_config = try config.encodeClient(std.testing.allocator, "master.example:49152", "node01", master_public);
        defer std.testing.allocator.free(new_config);
        var enrollment = credential.Credential{
            .handle = .{0x11} ** 16,
            .secret = .{0x22} ** 32,
            .master_public = master_public,
        };
        defer enrollment.deinit();
        var credential_buffer: [credential.text_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &credential_buffer);
        const credential_text = enrollment.encode(&credential_buffer);

        try std.testing.expectError(error.InjectedFailure, commitFaultInjected(
            std.testing.allocator,
            std.testing.io,
            tmp.dir,
            config_path,
            new_config,
            credential_text,
            fault,
        ));
        const marker = try tmp.dir.statFile(std.testing.io, intent_file, .{ .follow_symlinks = false });
        try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), marker.permissions.toMode() & 0o777);

        try std.testing.expect(try recover(std.testing.allocator, std.testing.io, tmp.dir, config_path));
        try std.testing.expect(!(try recover(std.testing.allocator, std.testing.io, tmp.dir, config_path)));

        const stored = try secrets.load(std.testing.allocator, std.testing.io, "enrollment.token", .enrollment_token);
        defer {
            std.crypto.secureZero(u8, stored);
            std.testing.allocator.free(stored);
        }
        try std.testing.expectEqualStrings(credential_text, stored);
        const persisted_config = try std.Io.Dir.cwd().readFileAlloc(
            std.testing.io,
            config_path,
            std.testing.allocator,
            .limited(config.max_config_bytes),
        );
        defer std.testing.allocator.free(persisted_config);
        try std.testing.expectEqualStrings(new_config, persisted_config);
        const persisted_state = try (client.File{ .dir = tmp.dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
        try std.testing.expectEqual(@as(u64, 0), persisted_state.generation);
        try std.testing.expect(persisted_state.node_id == null);
        try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(std.testing.io, "identity.key", .{ .follow_symlinks = false }));
    }
}

test "malformed or newer Node reconfiguration intent fails closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);

    const old_key = [_]u8{0x44} ** 32;
    const secrets: secret_store.FileSecretStore = .{ .dir = tmp.dir };
    try secrets.write(std.testing.allocator, std.testing.io, "identity.key", .identity_key, &old_key);
    const master_public = [_]u8{0x55} ** 32;
    const config_bytes = try config.encodeClient(std.testing.allocator, "master.example:49152", "node01", master_public);
    defer std.testing.allocator.free(config_bytes);
    var enrollment = credential.Credential{
        .handle = .{0x11} ** 16,
        .secret = .{0x22} ** 32,
        .master_public = master_public,
    };
    defer enrollment.deinit();
    var credential_buffer: [credential.text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &credential_buffer);
    const credential_text = enrollment.encode(&credential_buffer);
    try std.testing.expectError(error.InjectedFailure, commitFaultInjected(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        config_path,
        config_bytes,
        credential_text,
        .after_intent,
    ));

    const intent = try atomic.readAlloc(tmp.dir, std.testing.io, intent_file, std.testing.allocator, maximum_intent_bytes);
    defer {
        std.crypto.secureZero(u8, intent);
        std.testing.allocator.free(intent);
    }
    intent[8] = format_version + 1;
    try atomic.replace(tmp.dir, std.testing.io, intent_file, intent, atomic.private_file_permissions);
    try std.testing.expectError(
        error.UnsupportedClientTransactionVersion,
        recover(std.testing.allocator, std.testing.io, tmp.dir, config_path),
    );
    const identity = try secrets.load(std.testing.allocator, std.testing.io, "identity.key", .identity_key);
    defer {
        std.crypto.secureZero(u8, identity);
        std.testing.allocator.free(identity);
    }
    try std.testing.expectEqualSlices(u8, &old_key, identity);
}
