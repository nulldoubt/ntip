const std = @import("std");
const model = @import("../domain/model.zig");
const atomic = @import("atomic_file.zig");

pub const schema_version: u32 = 1;
pub const max_state_bytes: usize = 1024 * 1024;

pub const PersistentState = struct {
    generation: u64 = 0,
    enrollment_state: model.EnrollmentState = .unenrolled,
    /// Persisted as soon as an authenticated XK response assigns the Node.
    /// Keeping it while enrollment is still pending lets a restart try IK
    /// first when ENROLLMENT_COMPLETE was lost.
    node_id: ?model.NodeId = null,
    assigned_address: ?model.Ipv4 = null,
    vnr_range: ?model.Cidr = null,

    pub fn validate(self: PersistentState) !void {
        const has_assignment = self.node_id != null or self.assigned_address != null or self.vnr_range != null;
        if (has_assignment and (self.node_id == null or self.assigned_address == null or self.vnr_range == null)) {
            return error.InvalidClientState;
        }
        if (self.enrollment_state == .enrolled and !has_assignment) return error.InvalidClientState;
        if (self.node_id) |id| {
            var combined: u8 = 0;
            for (id.bytes) |byte| combined |= byte;
            if (combined == 0) return error.InvalidClientState;
        }
        if (self.assigned_address) |address| {
            const range = self.vnr_range.?;
            range.validateVnr() catch return error.InvalidClientState;
            if (!range.isUsableHost(address) or address.value == range.firstUsable().?.value) return error.InvalidClientState;
        }
    }
};

const DiskState = struct {
    schema_version: u32,
    generation: u64,
    enrollment_state: []const u8,
    node_id: ?[]const u8,
    assigned_address: ?[]const u8,
    vnr_range: ?[]const u8,
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !PersistentState {
    if (bytes.len == 0 or bytes.len > max_state_bytes) return error.InvalidClientState;
    const parsed = std.json.parseFromSlice(DiskState, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidClientStateJson;
    defer parsed.deinit();
    if (parsed.value.schema_version != schema_version) return error.UnsupportedSchemaVersion;

    const enrollment_state: model.EnrollmentState = if (std.mem.eql(u8, parsed.value.enrollment_state, "unenrolled"))
        .unenrolled
    else if (std.mem.eql(u8, parsed.value.enrollment_state, "enrolled"))
        .enrolled
    else
        return error.InvalidClientState;
    const address = if (parsed.value.assigned_address) |text|
        model.Ipv4.parse(text) catch return error.InvalidClientState
    else
        null;
    const range = if (parsed.value.vnr_range) |text|
        model.Cidr.parse(text) catch return error.InvalidClientState
    else
        null;
    const node_id = if (parsed.value.node_id) |text|
        model.NodeId.parse(text) catch return error.InvalidClientState
    else
        null;
    const result: PersistentState = .{
        .generation = parsed.value.generation,
        .enrollment_state = enrollment_state,
        .node_id = node_id,
        .assigned_address = address,
        .vnr_range = range,
    };
    try result.validate();
    return result;
}

pub fn encode(allocator: std.mem.Allocator, state: PersistentState) ![]u8 {
    try state.validate();
    var address_buffer: [15]u8 = undefined;
    var range_buffer: [18]u8 = undefined;
    var node_id_buffer: [32]u8 = undefined;
    const disk = DiskState{
        .schema_version = schema_version,
        .generation = state.generation,
        .enrollment_state = @tagName(state.enrollment_state),
        .node_id = if (state.node_id) |id| id.write(&node_id_buffer) else null,
        .assigned_address = if (state.assigned_address) |address| try address.write(&address_buffer) else null,
        .vnr_range = if (state.vnr_range) |range| try range.write(&range_buffer) else null,
    };
    var bytes = try std.json.Stringify.valueAlloc(allocator, disk, .{ .whitespace = .indent_2 });
    errdefer allocator.free(bytes);
    bytes = try allocator.realloc(bytes, bytes.len + 1);
    bytes[bytes.len - 1] = '\n';
    return bytes;
}

pub const File = struct {
    dir: std.Io.Dir,
    sub_path: []const u8 = "state.json",

    pub fn loadOrEmpty(self: File, allocator: std.mem.Allocator, io: std.Io) !PersistentState {
        const stat = self.dir.statFile(io, self.sub_path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return .{},
            else => return err,
        };
        if (stat.kind != .file) return error.InvalidStateFileType;
        if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
        const bytes = try atomic.readAlloc(self.dir, io, self.sub_path, allocator, max_state_bytes);
        defer allocator.free(bytes);
        return decode(allocator, bytes);
    }

    pub fn save(self: File, allocator: std.mem.Allocator, io: std.Io, state: PersistentState) !void {
        const bytes = try encode(allocator, state);
        defer allocator.free(bytes);
        try atomic.replace(self.dir, io, self.sub_path, bytes, atomic.private_file_permissions);
    }
};

test "client persistent state excludes sessions and validates assignment" {
    const state: PersistentState = .{
        .generation = 4,
        .enrollment_state = .enrolled,
        .node_id = .{ .bytes = .{1} ** 16 },
        .assigned_address = try model.Ipv4.parse("10.1.0.2"),
        .vnr_range = try model.Cidr.parse("10.1.0.0/24"),
    };
    const bytes = try encode(std.testing.allocator, state);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "session") == null);
    const decoded = try decode(std.testing.allocator, bytes);
    try std.testing.expectEqual(state.assigned_address.?.value, decoded.assigned_address.?.value);
}

test "partial or impossible assignments fail closed" {
    const partial: PersistentState = .{
        .node_id = .{ .bytes = .{1} ** 16 },
        .assigned_address = try model.Ipv4.parse("10.1.0.2"),
    };
    try std.testing.expectError(error.InvalidClientState, partial.validate());
    const master: PersistentState = .{
        .enrollment_state = .enrolled,
        .node_id = .{ .bytes = .{1} ** 16 },
        .assigned_address = try model.Ipv4.parse("10.1.0.1"),
        .vnr_range = try model.Cidr.parse("10.1.0.0/24"),
    };
    try std.testing.expectError(error.InvalidClientState, master.validate());
}

test "pending authenticated assignment is recoverable before enrollment completion" {
    const pending: PersistentState = .{
        .generation = 1,
        .enrollment_state = .unenrolled,
        .node_id = .{ .bytes = .{2} ** 16 },
        .assigned_address = try model.Ipv4.parse("10.1.0.2"),
        .vnr_range = try model.Cidr.parse("10.1.0.0/24"),
    };
    try pending.validate();
    const bytes = try encode(std.testing.allocator, pending);
    defer std.testing.allocator.free(bytes);
    const decoded = try decode(std.testing.allocator, bytes);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, decoded.enrollment_state);
    try std.testing.expectEqualSlices(u8, &pending.node_id.?.bytes, &decoded.node_id.?.bytes);
}
