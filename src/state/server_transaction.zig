//! Recoverable two-file transactions for authoritative Master state.
//!
//! A private, checksummed intent is synced first. Recovery always rolls that
//! fully validated intent forward, making `state.json` and `enrollments.json`
//! one logical commit even if power is lost between their atomic renames.

const std = @import("std");
const model = @import("../domain/model.zig");
const state_json = @import("json.zig");
const enrollment = @import("enrollments.zig");
const atomic = @import("atomic_file.zig");

const magic = "NTIPTXN1";
const header_len: usize = 16;
const digest_len: usize = 32;
pub const intent_file = "transaction.pending";
pub const maximum_intent_bytes = header_len + state_json.max_state_bytes + enrollment.max_enrollment_bytes + digest_len;

pub const FaultPoint = enum {
    none,
    after_intent,
    after_enrollments,
    after_state,
};

pub fn commit(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    store: *const model.Store,
    registry: *const enrollment.Registry,
) !void {
    return commitFaultInjected(allocator, io, dir, store, registry, .none);
}

pub fn commitFaultInjected(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    store: *const model.Store,
    registry: *const enrollment.Registry,
    fault: FaultPoint,
) !void {
    try store.validate();
    const state_bytes = try state_json.encode(allocator, store);
    defer allocator.free(state_bytes);
    const enrollment_bytes = try enrollment.encode(allocator, registry);
    defer {
        std.crypto.secureZero(u8, enrollment_bytes);
        allocator.free(enrollment_bytes);
    }
    const intent = try encodeIntent(allocator, state_bytes, enrollment_bytes);
    defer {
        std.crypto.secureZero(u8, intent);
        allocator.free(intent);
    }
    try atomic.replace(dir, io, intent_file, intent, atomic.private_file_permissions);
    if (fault == .after_intent) return error.InjectedFailure;
    try atomic.replace(dir, io, "enrollments.json", enrollment_bytes, atomic.private_file_permissions);
    if (fault == .after_enrollments) return error.InjectedFailure;
    try atomic.replace(dir, io, "state.json", state_bytes, atomic.private_file_permissions);
    if (fault == .after_state) return error.InjectedFailure;
    try atomic.deleteDurable(dir, io, intent_file);
}

/// Must run while holding `state.lock`, before either authoritative file is
/// loaded. A malformed intent fails closed and is never discarded.
pub fn recover(allocator: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !bool {
    const stat = dir.statFile(io, intent_file, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidTransactionFileType;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
    const bytes = try atomic.readAlloc(dir, io, intent_file, allocator, maximum_intent_bytes);
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    const decoded = try decodeIntent(bytes);

    // Validate both payloads completely before altering either destination.
    var candidate_store = try state_json.decode(allocator, decoded.state);
    defer candidate_store.deinit();
    var candidate_registry = try enrollment.decode(allocator, decoded.enrollments);
    defer candidate_registry.deinit();

    try atomic.replace(dir, io, "enrollments.json", decoded.enrollments, atomic.private_file_permissions);
    try atomic.replace(dir, io, "state.json", decoded.state, atomic.private_file_permissions);
    try atomic.deleteDurable(dir, io, intent_file);
    return true;
}

const Intent = struct {
    state: []const u8,
    enrollments: []const u8,
};

fn encodeIntent(allocator: std.mem.Allocator, state_bytes: []const u8, enrollment_bytes: []const u8) ![]u8 {
    if (state_bytes.len == 0 or state_bytes.len > state_json.max_state_bytes or
        enrollment_bytes.len == 0 or enrollment_bytes.len > enrollment.max_enrollment_bytes)
    {
        return error.TransactionPayloadTooLarge;
    }
    const total = std.math.add(usize, header_len + digest_len, state_bytes.len) catch return error.TransactionPayloadTooLarge;
    const final_len = std.math.add(usize, total, enrollment_bytes.len) catch return error.TransactionPayloadTooLarge;
    if (final_len > maximum_intent_bytes) return error.TransactionPayloadTooLarge;
    const bytes = try allocator.alloc(u8, final_len);
    @memcpy(bytes[0..8], magic);
    std.mem.writeInt(u32, bytes[8..12], @intCast(state_bytes.len), .big);
    std.mem.writeInt(u32, bytes[12..16], @intCast(enrollment_bytes.len), .big);
    @memcpy(bytes[header_len .. header_len + state_bytes.len], state_bytes);
    @memcpy(bytes[header_len + state_bytes.len .. final_len - digest_len], enrollment_bytes);
    std.crypto.hash.blake2.Blake2s256.hash(bytes[0 .. final_len - digest_len], bytes[final_len - digest_len ..][0..digest_len], .{});
    return bytes;
}

fn decodeIntent(bytes: []const u8) !Intent {
    if (bytes.len < header_len + digest_len or bytes.len > maximum_intent_bytes) return error.InvalidTransaction;
    if (!std.mem.eql(u8, bytes[0..8], magic)) return error.InvalidTransaction;
    const state_len: usize = std.mem.readInt(u32, bytes[8..12], .big);
    const enrollment_len: usize = std.mem.readInt(u32, bytes[12..16], .big);
    if (state_len == 0 or state_len > state_json.max_state_bytes or
        enrollment_len == 0 or enrollment_len > enrollment.max_enrollment_bytes)
    {
        return error.InvalidTransaction;
    }
    const payload_end = std.math.add(usize, header_len, state_len) catch return error.InvalidTransaction;
    const expected_end = std.math.add(usize, payload_end, enrollment_len) catch return error.InvalidTransaction;
    if (expected_end + digest_len != bytes.len) return error.InvalidTransaction;
    var expected: [digest_len]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(bytes[0..expected_end], &expected, .{});
    if (!std.crypto.timing_safe.eql([digest_len]u8, expected, bytes[expected_end..][0..digest_len].*)) {
        return error.InvalidTransactionDigest;
    }
    return .{
        .state = bytes[header_len..payload_end],
        .enrollments = bytes[payload_end..expected_end],
    };
}

test "crashes at every two-file boundary recover one complete generation" {
    inline for (.{ FaultPoint.after_intent, .after_enrollments, .after_state }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var old_store = model.Store.init(std.testing.allocator);
        defer old_store.deinit();
        var old_registry = enrollment.Registry.init(std.testing.allocator);
        defer old_registry.deinit();
        try commit(std.testing.allocator, std.testing.io, tmp.dir, &old_store, &old_registry);

        var next_store = model.Store.init(std.testing.allocator);
        defer next_store.deinit();
        _ = try next_store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
        var next_registry = enrollment.Registry.init(std.testing.allocator);
        defer next_registry.deinit();
        _ = try next_registry.issue(
            std.testing.io,
            "node01",
            .{ .bytes = .{7} ** 16 },
            .{7} ** 32,
            1,
            1000,
        );
        try std.testing.expectError(error.InjectedFailure, commitFaultInjected(
            std.testing.allocator,
            std.testing.io,
            tmp.dir,
            &next_store,
            &next_registry,
            fault,
        ));
        try std.testing.expect(try recover(std.testing.allocator, std.testing.io, tmp.dir));
        const recovered_state_bytes = try tmp.dir.readFileAlloc(
            std.testing.io,
            "state.json",
            std.testing.allocator,
            .limited(state_json.max_state_bytes),
        );
        defer std.testing.allocator.free(recovered_state_bytes);
        var recovered_store = try state_json.decode(std.testing.allocator, recovered_state_bytes);
        defer recovered_store.deinit();
        try std.testing.expectEqual(next_store.generation, recovered_store.generation);
        const enrollment_bytes = try tmp.dir.readFileAlloc(
            std.testing.io,
            "enrollments.json",
            std.testing.allocator,
            .limited(enrollment.max_enrollment_bytes),
        );
        defer std.testing.allocator.free(enrollment_bytes);
        var recovered_registry = try enrollment.decode(std.testing.allocator, enrollment_bytes);
        defer recovered_registry.deinit();
        try std.testing.expectEqual(next_registry.generation, recovered_registry.generation);
        try std.testing.expect(!(try recover(std.testing.allocator, std.testing.io, tmp.dir)));
    }
}
