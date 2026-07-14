const std = @import("std");
const model = @import("../domain/model.zig");
const atomic = @import("atomic_file.zig");

pub const schema_version: u32 = 1;
pub const max_enrollment_bytes: usize = 16 * 1024 * 1024;

pub const Status = enum {
    unused,
    consumed,
    revoked,
};

pub const Record = struct {
    handle: [16]u8,
    node: model.Name,
    node_id: model.NodeId,
    derived_psk: [32]u8,
    created_at: u64,
    expires_at: u64,
    status: Status = .unused,

    pub fn usable(self: Record, now: u64) bool {
        return self.status == .unused and now < self.expires_at;
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    generation: u64 = 0,
    records: std.ArrayList(Record) = .empty,

    pub fn init(allocator: std.mem.Allocator) Registry {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Registry) void {
        // PSKs remain bearer-equivalent, so erase before releasing storage.
        for (self.records.items) |*record| std.crypto.secureZero(u8, &record.derived_psk);
        self.records.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn issue(
        self: *Registry,
        io: std.Io,
        node_text: []const u8,
        node_id: model.NodeId,
        derived_psk: [32]u8,
        created_at: u64,
        expires_at: u64,
    ) ![16]u8 {
        var handle: [16]u8 = undefined;
        while (true) {
            io.random(&handle);
            var collision = false;
            for (self.records.items) |record| collision = collision or constantTimeEqual(&handle, &record.handle);
            if (!collision) break;
        }
        try self.issueWithHandle(node_text, node_id, handle, derived_psk, created_at, expires_at);
        return handle;
    }

    /// Installs a credential whose handle was generated before PSK derivation.
    /// This is the normal protocol path because the handle is the HKDF salt.
    pub fn issueWithHandle(
        self: *Registry,
        node_text: []const u8,
        node_id: model.NodeId,
        handle: [16]u8,
        derived_psk: [32]u8,
        created_at: u64,
        expires_at: u64,
    ) !void {
        const node = model.Name.parse(node_text) catch return error.InvalidName;
        if (expires_at == 0 or created_at >= expires_at) return error.InvalidExpiry;
        if (allZero(&node_id.bytes)) return error.InvalidNodeId;
        if (allZero(&derived_psk)) return error.InvalidPsk;
        for (self.records.items) |record| {
            if (constantTimeEqual(&handle, &record.handle)) return error.EnrollmentHandleInUse;
        }
        const next_generation = try self.nextGeneration();
        try self.records.ensureUnusedCapacity(self.allocator, 1);
        for (self.records.items) |*record| {
            if (record.node.eql(node) and record.status == .unused) {
                record.status = .revoked;
                std.crypto.secureZero(u8, &record.derived_psk);
            }
        }
        self.records.appendAssumeCapacity(.{
            .handle = handle,
            .node = node,
            .node_id = node_id,
            .derived_psk = derived_psk,
            .created_at = created_at,
            .expires_at = expires_at,
        });
        self.generation = next_generation;
    }

    pub fn consume(self: *Registry, handle: [16]u8, now: u64) !Record {
        for (self.records.items) |*record| {
            if (!constantTimeEqual(&handle, &record.handle)) continue;
            switch (record.status) {
                .consumed => return error.EnrollmentConsumed,
                .revoked => return error.EnrollmentRevoked,
                .unused => {},
            }
            if (now >= record.expires_at) return error.EnrollmentExpired;
            const next_generation = try self.nextGeneration();
            const consumed = record.*;
            record.status = .consumed;
            std.crypto.secureZero(u8, &record.derived_psk);
            self.generation = next_generation;
            return consumed;
        }
        return error.EnrollmentNotFound;
    }

    pub fn revokeNode(self: *Registry, node: []const u8) !void {
        var found = false;
        for (self.records.items) |record| {
            if (record.node.eqlSlice(node) and record.status == .unused) found = true;
        }
        if (!found) return error.EnrollmentNotFound;
        const next_generation = try self.nextGeneration();
        for (self.records.items) |*record| {
            if (record.node.eqlSlice(node) and record.status == .unused) {
                record.status = .revoked;
                std.crypto.secureZero(u8, &record.derived_psk);
            }
        }
        self.generation = next_generation;
    }

    fn nextGeneration(self: *const Registry) !u64 {
        return std.math.add(u64, self.generation, 1) catch return error.GenerationOverflow;
    }
};

const DiskRecord = struct {
    handle: []const u8,
    node: []const u8,
    node_id: []const u8,
    derived_psk: []const u8,
    created_at: u64,
    expires_at: u64,
    status: []const u8,
};

const DiskRegistry = struct {
    schema_version: u32,
    generation: u64,
    records: []const DiskRecord,
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !Registry {
    if (bytes.len == 0 or bytes.len > max_enrollment_bytes) return error.InvalidEnrollmentState;
    const parsed = std.json.parseFromSlice(DiskRegistry, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_if_needed,
    }) catch return error.InvalidEnrollmentJson;
    defer parsed.deinit();
    if (parsed.value.schema_version != schema_version) return error.UnsupportedSchemaVersion;

    var registry = Registry.init(allocator);
    errdefer registry.deinit();
    registry.generation = parsed.value.generation;
    for (parsed.value.records) |disk| {
        var handle: [16]u8 = undefined;
        var psk: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &psk);
        decodeHex(disk.handle, &handle) catch return error.InvalidEnrollmentState;
        decodeHex(disk.derived_psk, &psk) catch return error.InvalidEnrollmentState;
        const node = model.Name.parse(disk.node) catch return error.InvalidEnrollmentState;
        const node_id = model.NodeId.parse(disk.node_id) catch return error.InvalidEnrollmentState;
        const status: Status = if (std.mem.eql(u8, disk.status, "unused"))
            .unused
        else if (std.mem.eql(u8, disk.status, "consumed"))
            .consumed
        else if (std.mem.eql(u8, disk.status, "revoked"))
            .revoked
        else
            return error.InvalidEnrollmentState;
        if (disk.expires_at == 0 or disk.created_at >= disk.expires_at) return error.InvalidEnrollmentState;
        if (status == .unused and allZero(&psk)) return error.InvalidEnrollmentState;
        for (registry.records.items) |existing| {
            if (constantTimeEqual(&handle, &existing.handle)) return error.InvalidEnrollmentState;
            if (status == .unused and existing.status == .unused and existing.node.eql(node)) return error.InvalidEnrollmentState;
        }
        registry.records.append(allocator, .{
            .handle = handle,
            .node = node,
            .node_id = node_id,
            .derived_psk = psk,
            .created_at = disk.created_at,
            .expires_at = disk.expires_at,
            .status = status,
        }) catch return error.OutOfMemory;
    }
    return registry;
}

pub fn encode(allocator: std.mem.Allocator, registry: *const Registry) error{OutOfMemory}![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{ .whitespace = .indent_2 } };
    json.beginObject() catch return error.OutOfMemory;
    json.objectField("schema_version") catch return error.OutOfMemory;
    json.write(schema_version) catch return error.OutOfMemory;
    json.objectField("generation") catch return error.OutOfMemory;
    json.write(registry.generation) catch return error.OutOfMemory;
    json.objectField("records") catch return error.OutOfMemory;
    json.beginArray() catch return error.OutOfMemory;
    for (registry.records.items) |record| {
        var handle_text: [32]u8 = undefined;
        var node_id_text: [32]u8 = undefined;
        var psk_text: [64]u8 = undefined;
        json.beginObject() catch return error.OutOfMemory;
        json.objectField("handle") catch return error.OutOfMemory;
        json.write(encodeHex(&record.handle, &handle_text)) catch return error.OutOfMemory;
        json.objectField("node") catch return error.OutOfMemory;
        json.write(record.node.slice()) catch return error.OutOfMemory;
        json.objectField("node_id") catch return error.OutOfMemory;
        json.write(record.node_id.write(&node_id_text)) catch return error.OutOfMemory;
        json.objectField("derived_psk") catch return error.OutOfMemory;
        json.write(encodeHex(&record.derived_psk, &psk_text)) catch return error.OutOfMemory;
        json.objectField("created_at") catch return error.OutOfMemory;
        json.write(record.created_at) catch return error.OutOfMemory;
        json.objectField("expires_at") catch return error.OutOfMemory;
        json.write(record.expires_at) catch return error.OutOfMemory;
        json.objectField("status") catch return error.OutOfMemory;
        json.write(@tagName(record.status)) catch return error.OutOfMemory;
        json.endObject() catch return error.OutOfMemory;
    }
    json.endArray() catch return error.OutOfMemory;
    json.endObject() catch return error.OutOfMemory;
    output.writer.writeByte('\n') catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

pub const File = struct {
    dir: std.Io.Dir,
    sub_path: []const u8 = "enrollments.json",

    pub fn loadOrEmpty(self: File, allocator: std.mem.Allocator, io: std.Io) !Registry {
        const stat = self.dir.statFile(io, self.sub_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return Registry.init(allocator),
            else => return err,
        };
        if (stat.kind != .file) return error.InvalidEnrollmentFileType;
        if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
        const bytes = try atomic.readAlloc(self.dir, io, self.sub_path, allocator, max_enrollment_bytes);
        defer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        return decode(allocator, bytes);
    }

    pub fn save(self: File, allocator: std.mem.Allocator, io: std.Io, registry: *const Registry) !void {
        const bytes = try encode(allocator, registry);
        defer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        try atomic.replace(self.dir, io, self.sub_path, bytes, atomic.private_file_permissions);
    }
};

fn encodeHex(input: []const u8, output: []u8) []const u8 {
    const alphabet = "0123456789abcdef";
    for (input, 0..) |byte, i| {
        output[i * 2] = alphabet[byte >> 4];
        output[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output[0 .. input.len * 2];
}

fn decodeHex(input: []const u8, output: []u8) !void {
    if (input.len != output.len * 2) return error.InvalidHex;
    for (output, 0..) |*byte, i| {
        const hi = decodeNibble(input[i * 2]) orelse return error.InvalidHex;
        const lo = decodeNibble(input[i * 2 + 1]) orelse return error.InvalidHex;
        byte.* = hi << 4 | lo;
    }
}

fn decodeNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    for (left, right) |a, b| difference |= a ^ b;
    return difference == 0;
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

test "renewal revokes the unused credential and consumption is single-use" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();
    const node_id: model.NodeId = .{ .bytes = .{9} ** 16 };
    const first = try registry.issue(std.testing.io, "node01", node_id, .{1} ** 32, 1, 100);
    const second = try registry.issue(std.testing.io, "node01", node_id, .{2} ** 32, 2, 100);
    try std.testing.expectError(error.EnrollmentRevoked, registry.consume(first, 10));
    _ = try registry.consume(second, 10);
    try std.testing.expectError(error.EnrollmentConsumed, registry.consume(second, 10));
    try std.testing.expect(allZero(&registry.records.items[1].derived_psk));
}

test "enrollment JSON stores a derived PSK and survives round trip" {
    var registry = Registry.init(std.testing.allocator);
    defer registry.deinit();
    const node_id: model.NodeId = .{ .bytes = .{8} ** 16 };
    _ = try registry.issue(std.testing.io, "node01", node_id, .{3} ** 32, 10, 1000);
    const bytes = try encode(std.testing.allocator, &registry);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "derived_psk") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"node_id\": \"08080808080808080808080808080808\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"created_at\": 10") != null);
    var decoded = try decode(std.testing.allocator, bytes);
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 1), decoded.records.items.len);
    try std.testing.expect(decoded.records.items[0].node_id.eql(node_id));
    try std.testing.expectEqual(@as(u64, 10), decoded.records.items[0].created_at);
    try std.testing.expectEqualSlices(u8, &registry.records.items[0].derived_psk, &decoded.records.items[0].derived_psk);
}
