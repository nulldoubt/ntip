const std = @import("std");
const model = @import("../domain/model.zig");

pub const schema_version: u32 = 1;
pub const max_state_bytes: usize = 16 * 1024 * 1024;

const DiskVnr = struct {
    name: []const u8,
    range: []const u8,
};

const DiskNode = struct {
    id: []const u8,
    name: []const u8,
    vnr: []const u8,
    address: []const u8,
    enrollment_state: []const u8,
    public_key: ?[]const u8,
};

const DiskRoute = struct {
    prefix: []const u8,
    node: []const u8,
};

const DiskState = struct {
    schema_version: u32,
    generation: u64,
    vnrs: []const DiskVnr,
    nodes: []const DiskNode,
    routes: []const DiskRoute,
};

pub const DecodeError = error{
    InvalidJson,
    InvalidState,
    UnsupportedSchemaVersion,
    OutOfMemory,
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) DecodeError!model.Store {
    if (bytes.len == 0 or bytes.len > max_state_bytes) return error.InvalidState;
    const parsed = std.json.parseFromSlice(DiskState, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidJson;
    defer parsed.deinit();

    if (parsed.value.schema_version != schema_version) return error.UnsupportedSchemaVersion;

    var store = model.Store.init(allocator);
    errdefer store.deinit();
    store.generation = parsed.value.generation;

    for (parsed.value.vnrs) |disk| {
        const name = model.Name.parse(disk.name) catch return error.InvalidState;
        const range = model.Cidr.parse(disk.range) catch return error.InvalidState;
        store.vnrs.append(allocator, .{ .name = name, .range = range }) catch return error.OutOfMemory;
    }
    for (parsed.value.nodes) |disk| {
        const id = model.NodeId.parse(disk.id) catch return error.InvalidState;
        const name = model.Name.parse(disk.name) catch return error.InvalidState;
        const vnr = model.Name.parse(disk.vnr) catch return error.InvalidState;
        const address = model.Ipv4.parse(disk.address) catch return error.InvalidState;
        const enrollment_state: model.EnrollmentState = if (std.mem.eql(u8, disk.enrollment_state, "unenrolled"))
            .unenrolled
        else if (std.mem.eql(u8, disk.enrollment_state, "enrolled"))
            .enrolled
        else
            return error.InvalidState;
        var public_key: ?[32]u8 = null;
        if (disk.public_key) |encoded| {
            var key: [32]u8 = undefined;
            decodeHex(encoded, &key) catch return error.InvalidState;
            public_key = key;
        }
        store.nodes.append(allocator, .{
            .id = id,
            .name = name,
            .vnr = vnr,
            .address = address,
            .enrollment_state = enrollment_state,
            .public_key = public_key,
        }) catch return error.OutOfMemory;
    }
    for (parsed.value.routes) |disk| {
        const prefix = model.Cidr.parse(disk.prefix) catch return error.InvalidState;
        const node = model.Name.parse(disk.node) catch return error.InvalidState;
        const owner = store.findNode(node.slice()) orelse return error.InvalidState;
        store.routes.append(allocator, .{
            .id = model.deriveLegacyRouteId(prefix, owner.id),
            .prefix = prefix,
            .node = node,
        }) catch return error.OutOfMemory;
    }

    store.validate() catch return error.InvalidState;
    return store;
}

pub fn encode(allocator: std.mem.Allocator, store: *const model.Store) error{OutOfMemory}![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var json: std.json.Stringify = .{
        .writer = &output.writer,
        .options = .{ .whitespace = .indent_2 },
    };

    json.beginObject() catch return error.OutOfMemory;
    json.objectField("schema_version") catch return error.OutOfMemory;
    json.write(schema_version) catch return error.OutOfMemory;
    json.objectField("generation") catch return error.OutOfMemory;
    json.write(store.generation) catch return error.OutOfMemory;

    json.objectField("vnrs") catch return error.OutOfMemory;
    json.beginArray() catch return error.OutOfMemory;
    for (store.vnrs.items) |vnr| {
        var cidr_buffer: [18]u8 = undefined;
        const cidr = vnr.range.write(&cidr_buffer) catch unreachable;
        json.beginObject() catch return error.OutOfMemory;
        json.objectField("name") catch return error.OutOfMemory;
        json.write(vnr.name.slice()) catch return error.OutOfMemory;
        json.objectField("range") catch return error.OutOfMemory;
        json.write(cidr) catch return error.OutOfMemory;
        json.endObject() catch return error.OutOfMemory;
    }
    json.endArray() catch return error.OutOfMemory;

    json.objectField("nodes") catch return error.OutOfMemory;
    json.beginArray() catch return error.OutOfMemory;
    for (store.nodes.items) |node| {
        var id_buffer: [32]u8 = undefined;
        var address_buffer: [15]u8 = undefined;
        const id = node.id.write(&id_buffer);
        const address = node.address.write(&address_buffer) catch unreachable;
        json.beginObject() catch return error.OutOfMemory;
        json.objectField("id") catch return error.OutOfMemory;
        json.write(id) catch return error.OutOfMemory;
        json.objectField("name") catch return error.OutOfMemory;
        json.write(node.name.slice()) catch return error.OutOfMemory;
        json.objectField("vnr") catch return error.OutOfMemory;
        json.write(node.vnr.slice()) catch return error.OutOfMemory;
        json.objectField("address") catch return error.OutOfMemory;
        json.write(address) catch return error.OutOfMemory;
        json.objectField("enrollment_state") catch return error.OutOfMemory;
        json.write(@tagName(node.enrollment_state)) catch return error.OutOfMemory;
        json.objectField("public_key") catch return error.OutOfMemory;
        if (node.public_key) |key| {
            var key_buffer: [64]u8 = undefined;
            json.write(encodeHex(&key, &key_buffer)) catch return error.OutOfMemory;
        } else {
            json.write(null) catch return error.OutOfMemory;
        }
        json.endObject() catch return error.OutOfMemory;
    }
    json.endArray() catch return error.OutOfMemory;

    json.objectField("routes") catch return error.OutOfMemory;
    json.beginArray() catch return error.OutOfMemory;
    for (store.routes.items) |route| {
        var prefix_buffer: [18]u8 = undefined;
        const prefix = route.prefix.write(&prefix_buffer) catch unreachable;
        json.beginObject() catch return error.OutOfMemory;
        json.objectField("prefix") catch return error.OutOfMemory;
        json.write(prefix) catch return error.OutOfMemory;
        json.objectField("node") catch return error.OutOfMemory;
        json.write(route.node.slice()) catch return error.OutOfMemory;
        json.endObject() catch return error.OutOfMemory;
    }
    json.endArray() catch return error.OutOfMemory;
    json.endObject() catch return error.OutOfMemory;
    output.writer.writeByte('\n') catch return error.OutOfMemory;
    return output.toOwnedSlice();
}

fn encodeHex(input: []const u8, output: []u8) []const u8 {
    std.debug.assert(output.len >= input.len * 2);
    const alphabet = "0123456789abcdef";
    for (input, 0..) |byte, i| {
        output[i * 2] = alphabet[byte >> 4];
        output[i * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output[0 .. input.len * 2];
}

fn decodeHex(input: []const u8, output: []u8) error{InvalidHex}!void {
    if (input.len != output.len * 2) return error.InvalidHex;
    for (output, 0..) |*byte, i| {
        const hi = decodeNibble(input[i * 2]) orelse return error.InvalidHex;
        const lo = decodeNibble(input[i * 2 + 1]) orelse return error.InvalidHex;
        byte.* = (hi << 4) | lo;
    }
}

fn decodeNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        else => null,
    };
}

test "state JSON round trip is stable and strict" {
    var original = model.Store.init(std.testing.allocator);
    defer original.deinit();
    _ = try original.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    try original.createNode(.{ .bytes = .{1} ** 16 }, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    try original.addRoute(try model.Cidr.parse("192.168.178.0/24"), "node01");

    const encoded = try encode(std.testing.allocator, &original);
    defer std.testing.allocator.free(encoded);
    var decoded = try decode(std.testing.allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqual(original.generation, decoded.generation);
    try std.testing.expectEqual(@as(usize, 1), decoded.vnrs.items.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.nodes.items.len);
    try std.testing.expectEqual(@as(usize, 1), decoded.routes.items.len);

    const encoded_again = try encode(std.testing.allocator, &decoded);
    defer std.testing.allocator.free(encoded_again);
    try std.testing.expectEqualStrings(encoded, encoded_again);
}

test "unknown fields and newer schemas fail closed" {
    const unknown =
        \\{"schema_version":1,"generation":0,"vnrs":[],"nodes":[],"routes":[],"surprise":true}
    ;
    try std.testing.expectError(error.InvalidJson, decode(std.testing.allocator, unknown));
    const newer =
        \\{"schema_version":2,"generation":0,"vnrs":[],"nodes":[],"routes":[]}
    ;
    try std.testing.expectError(error.UnsupportedSchemaVersion, decode(std.testing.allocator, newer));
}
