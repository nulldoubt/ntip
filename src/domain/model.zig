const std = @import("std");
const net = @import("ipv4.zig");

pub const Ipv4 = net.Ipv4;
pub const Cidr = net.Cidr;

pub const max_name_len = 63;

pub const Name = struct {
    len: u8,
    bytes: [max_name_len]u8,

    pub fn parse(text: []const u8) error{InvalidName}!Name {
        if (text.len == 0 or text.len > max_name_len) return error.InvalidName;
        for (text, 0..) |c, i| {
            const valid = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
            if (!valid) return error.InvalidName;
            if (i == 0 and (c == '-' or c == '.')) return error.InvalidName;
        }
        var result: Name = .{ .len = @intCast(text.len), .bytes = undefined };
        @memcpy(result.bytes[0..text.len], text);
        @memset(result.bytes[text.len..], 0);
        return result;
    }

    pub fn slice(self: *const Name) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn eql(self: Name, other: Name) bool {
        return std.mem.eql(u8, self.slice(), other.slice());
    }

    pub fn eqlSlice(self: Name, other: []const u8) bool {
        return std.mem.eql(u8, self.slice(), other);
    }
};

pub const NodeId = struct {
    bytes: [16]u8,

    pub fn generate(io: std.Io) NodeId {
        var result: NodeId = undefined;
        io.random(&result.bytes);
        // UUIDv4-compatible variant/version bits make IDs easier to recognize
        // while preserving 122 bits of cryptographic randomness.
        result.bytes[6] = (result.bytes[6] & 0x0f) | 0x40;
        result.bytes[8] = (result.bytes[8] & 0x3f) | 0x80;
        return result;
    }

    pub fn parse(text: []const u8) error{InvalidNodeId}!NodeId {
        if (text.len != 32) return error.InvalidNodeId;
        var result: NodeId = undefined;
        for (0..16) |i| {
            const hi = decodeHex(text[i * 2]) orelse return error.InvalidNodeId;
            const lo = decodeHex(text[i * 2 + 1]) orelse return error.InvalidNodeId;
            result.bytes[i] = (hi << 4) | lo;
        }
        return result;
    }

    pub fn write(self: NodeId, buffer: *[32]u8) []const u8 {
        const alphabet = "0123456789abcdef";
        for (self.bytes, 0..) |byte, i| {
            buffer[i * 2] = alphabet[byte >> 4];
            buffer[i * 2 + 1] = alphabet[byte & 0x0f];
        }
        return buffer;
    }

    pub fn eql(self: NodeId, other: NodeId) bool {
        return std.mem.eql(u8, &self.bytes, &other.bytes);
    }

    fn decodeHex(c: u8) ?u8 {
        return switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            else => null,
        };
    }
};

pub const EnrollmentState = enum {
    unenrolled,
    enrolled,
};

pub const Vnr = struct {
    name: Name,
    range: Cidr,

    pub fn masterAddress(self: Vnr) Ipv4 {
        return self.range.firstUsable().?;
    }
};

pub const Node = struct {
    id: NodeId,
    name: Name,
    vnr: Name,
    address: Ipv4,
    enrollment_state: EnrollmentState = .unenrolled,
    public_key: ?[32]u8 = null,
};

pub const Route = struct {
    prefix: Cidr,
    node: Name,
};

pub const CreateVnrResult = struct {
    public_range_warning: bool,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    generation: u64 = 0,
    vnrs: std.ArrayList(Vnr) = .empty,
    nodes: std.ArrayList(Node) = .empty,
    routes: std.ArrayList(Route) = .empty,

    pub const MutationError = error{
        InvalidName,
        InvalidVnrPrefix,
        InvalidVnrRange,
        InvalidRoutePrefix,
        InvalidRouteRange,
        VnrExists,
        VnrNotFound,
        VnrOverlap,
        VnrInUse,
        NodeExists,
        NodeIdInUse,
        NodeAlreadyEnrolled,
        InvalidEnrollmentState,
        PublicKeyInUse,
        InvalidPublicKey,
        NodeNotFound,
        NodeAddressOutsideVnr,
        NodeAddressReserved,
        AddressInUse,
        NodeHasRoutes,
        RouteExists,
        RouteNotFound,
        RouteOverlap,
        RouteOverlapsVnr,
        GenerationOverflow,
        OutOfMemory,
    };

    pub fn init(allocator: std.mem.Allocator) Store {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Store) void {
        self.vnrs.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.routes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn findVnr(self: *const Store, name: []const u8) ?*const Vnr {
        for (self.vnrs.items) |*vnr| if (vnr.name.eqlSlice(name)) return vnr;
        return null;
    }

    pub fn findNode(self: *const Store, name: []const u8) ?*const Node {
        for (self.nodes.items) |*node| if (node.name.eqlSlice(name)) return node;
        return null;
    }

    pub fn findRoute(self: *const Store, prefix: Cidr) ?*const Route {
        for (self.routes.items) |*route| {
            if (route.prefix.prefix == prefix.prefix and route.prefix.network.value == prefix.network.value) return route;
        }
        return null;
    }

    pub fn createVnr(self: *Store, name_text: []const u8, range: Cidr) MutationError!CreateVnrResult {
        const name = Name.parse(name_text) catch return error.InvalidName;
        range.validateVnr() catch |err| return switch (err) {
            error.InvalidVnrPrefix => error.InvalidVnrPrefix,
            error.InvalidVnrRange => error.InvalidVnrRange,
        };
        if (self.findVnr(name_text) != null) return error.VnrExists;
        for (self.vnrs.items) |existing| if (existing.range.overlaps(range)) return error.VnrOverlap;

        const next_generation = try self.nextGeneration();
        try self.vnrs.append(self.allocator, .{ .name = name, .range = range });
        self.generation = next_generation;
        return .{ .public_range_warning = !range.isPrivateRange() };
    }

    pub fn deleteVnr(self: *Store, name: []const u8) MutationError!void {
        const index = self.vnrIndex(name) orelse return error.VnrNotFound;
        for (self.nodes.items) |node| if (node.vnr.eqlSlice(name)) return error.VnrInUse;
        const next_generation = try self.nextGeneration();
        _ = self.vnrs.orderedRemove(index);
        self.generation = next_generation;
    }

    pub fn createNode(self: *Store, id: NodeId, name_text: []const u8, vnr_name: []const u8, address: Ipv4) MutationError!void {
        const name = Name.parse(name_text) catch return error.InvalidName;
        const vnr = self.findVnr(vnr_name) orelse return error.VnrNotFound;
        if (self.findNode(name_text) != null) return error.NodeExists;
        for (self.nodes.items) |existing| if (existing.id.eql(id)) return error.NodeIdInUse;
        if (!vnr.range.contains(address)) return error.NodeAddressOutsideVnr;
        if (!vnr.range.isUsableHost(address) or address.value == vnr.masterAddress().value) return error.NodeAddressReserved;
        for (self.nodes.items) |existing| if (existing.address.value == address.value) return error.AddressInUse;

        const next_generation = try self.nextGeneration();
        try self.nodes.append(self.allocator, .{
            .id = id,
            .name = name,
            .vnr = vnr.name,
            .address = address,
        });
        self.generation = next_generation;
    }

    pub fn createNodeRandom(self: *Store, io: std.Io, name: []const u8, vnr: []const u8, address: Ipv4) MutationError!NodeId {
        const id = NodeId.generate(io);
        try self.createNode(id, name, vnr, address);
        return id;
    }

    pub fn deleteNode(self: *Store, name: []const u8) MutationError!void {
        const index = self.nodeIndex(name) orelse return error.NodeNotFound;
        for (self.routes.items) |route| if (route.node.eqlSlice(name)) return error.NodeHasRoutes;
        const next_generation = try self.nextGeneration();
        _ = self.nodes.orderedRemove(index);
        self.generation = next_generation;
    }

    pub fn bindNodePublicKey(self: *Store, name: []const u8, public_key: [32]u8) MutationError!void {
        const index = self.nodeIndex(name) orelse return error.NodeNotFound;
        var any_nonzero = false;
        for (public_key) |byte| any_nonzero = any_nonzero or byte != 0;
        if (!any_nonzero) return error.InvalidPublicKey;
        if (self.nodes.items[index].enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;
        for (self.nodes.items, 0..) |node, other_index| {
            if (other_index == index) continue;
            if (node.public_key) |existing| {
                if (std.mem.eql(u8, &existing, &public_key)) return error.PublicKeyInUse;
            }
        }
        const next_generation = try self.nextGeneration();
        self.nodes.items[index].public_key = public_key;
        self.nodes.items[index].enrollment_state = .enrolled;
        self.generation = next_generation;
    }

    pub fn resetNodeEnrollment(self: *Store, name: []const u8) MutationError!void {
        const index = self.nodeIndex(name) orelse return error.NodeNotFound;
        const next_generation = try self.nextGeneration();
        if (self.nodes.items[index].public_key) |*key| @memset(key, 0);
        self.nodes.items[index].public_key = null;
        self.nodes.items[index].enrollment_state = .unenrolled;
        self.generation = next_generation;
    }

    pub fn addRoute(self: *Store, prefix: Cidr, node_name: []const u8) MutationError!void {
        prefix.validateRouted() catch |err| return switch (err) {
            error.InvalidRoutePrefix => error.InvalidRoutePrefix,
            error.InvalidRouteRange => error.InvalidRouteRange,
        };
        const node = self.findNode(node_name) orelse return error.NodeNotFound;
        for (self.vnrs.items) |vnr| if (vnr.range.overlaps(prefix)) return error.RouteOverlapsVnr;
        for (self.routes.items) |route| {
            if (route.prefix.prefix == prefix.prefix and route.prefix.network.value == prefix.network.value) return error.RouteExists;
            if (route.prefix.overlaps(prefix)) return error.RouteOverlap;
        }

        const next_generation = try self.nextGeneration();
        try self.routes.append(self.allocator, .{ .prefix = prefix, .node = node.name });
        self.generation = next_generation;
    }

    pub fn deleteRoute(self: *Store, prefix: Cidr) MutationError!void {
        const index = self.routeIndex(prefix) orelse return error.RouteNotFound;
        const next_generation = try self.nextGeneration();
        _ = self.routes.orderedRemove(index);
        self.generation = next_generation;
    }

    /// Master ingress anti-spoofing: a Node may source only its assigned /32
    /// or a routed prefix explicitly owned by that Node.
    pub fn sourceAuthorized(self: *const Store, node_name: []const u8, source: Ipv4) bool {
        const node = self.findNode(node_name) orelse return false;
        if (node.address.value == source.value) return true;
        for (self.routes.items) |route| {
            if (route.node.eql(node.name) and route.prefix.contains(source)) return true;
        }
        return false;
    }

    pub fn validate(self: *const Store) MutationError!void {
        for (self.vnrs.items, 0..) |vnr, i| {
            vnr.range.validateVnr() catch return error.InvalidVnrRange;
            for (self.vnrs.items[i + 1 ..]) |other| {
                if (vnr.name.eql(other.name)) return error.VnrExists;
                if (vnr.range.overlaps(other.range)) return error.VnrOverlap;
            }
        }
        for (self.nodes.items, 0..) |node, i| {
            const vnr = self.findVnr(node.vnr.slice()) orelse return error.VnrNotFound;
            if (!vnr.range.isUsableHost(node.address) or node.address.value == vnr.masterAddress().value) return error.NodeAddressReserved;
            if ((node.enrollment_state == .enrolled) != (node.public_key != null)) return error.InvalidEnrollmentState;
            if (node.public_key) |key| {
                var any_nonzero = false;
                for (key) |byte| any_nonzero = any_nonzero or byte != 0;
                if (!any_nonzero) return error.InvalidPublicKey;
            }
            for (self.nodes.items[i + 1 ..]) |other| {
                if (node.name.eql(other.name)) return error.NodeExists;
                if (node.id.eql(other.id)) return error.NodeIdInUse;
                if (node.address.value == other.address.value) return error.AddressInUse;
                if (node.public_key) |key| if (other.public_key) |other_key| {
                    if (std.mem.eql(u8, &key, &other_key)) return error.PublicKeyInUse;
                };
            }
        }
        for (self.routes.items, 0..) |route, i| {
            if (self.findNode(route.node.slice()) == null) return error.NodeNotFound;
            for (self.vnrs.items) |vnr| if (vnr.range.overlaps(route.prefix)) return error.RouteOverlapsVnr;
            for (self.routes.items[i + 1 ..]) |other| if (route.prefix.overlaps(other.prefix)) return error.RouteOverlap;
        }
    }

    fn nextGeneration(self: *const Store) MutationError!u64 {
        return std.math.add(u64, self.generation, 1) catch return error.GenerationOverflow;
    }

    fn vnrIndex(self: *const Store, name: []const u8) ?usize {
        for (self.vnrs.items, 0..) |vnr, i| if (vnr.name.eqlSlice(name)) return i;
        return null;
    }

    fn nodeIndex(self: *const Store, name: []const u8) ?usize {
        for (self.nodes.items, 0..) |node, i| if (node.name.eqlSlice(name)) return i;
        return null;
    }

    fn routeIndex(self: *const Store, prefix: Cidr) ?usize {
        for (self.routes.items, 0..) |route, i| {
            if (route.prefix.prefix == prefix.prefix and route.prefix.network.value == prefix.network.value) return i;
        }
        return null;
    }
};

test "domain invariants reject overlap and deletion dependencies" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.createVnr("vnr0", try Cidr.parse("10.1.0.0/24"));
    try std.testing.expectError(error.VnrOverlap, store.createVnr("vnr1", try Cidr.parse("10.1.0.0/25")));
    const id = NodeId{ .bytes = .{0} ** 16 };
    try store.createNode(id, "node01", "vnr0", try Ipv4.parse("10.1.0.2"));
    try std.testing.expectError(error.VnrInUse, store.deleteVnr("vnr0"));

    try store.addRoute(try Cidr.parse("192.168.178.0/24"), "node01");
    try std.testing.expectError(error.NodeHasRoutes, store.deleteNode("node01"));
    try std.testing.expect(store.sourceAuthorized("node01", try Ipv4.parse("192.168.178.20")));
    try std.testing.expect(!store.sourceAuthorized("node01", try Ipv4.parse("192.168.179.20")));
}

test "public VNR returns an explicit warning" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    const result = try store.createVnr("public", try Cidr.parse("8.8.8.0/24"));
    try std.testing.expect(result.public_range_warning);
}

test "Node IDs use UUIDv4 version and variant bits" {
    const id = NodeId.generate(std.testing.io);
    try std.testing.expectEqual(@as(u8, 0x40), id.bytes[6] & 0xf0);
    try std.testing.expectEqual(@as(u8, 0x80), id.bytes[8] & 0xc0);
    var text: [32]u8 = undefined;
    const parsed = try NodeId.parse(id.write(&text));
    try std.testing.expectEqualSlices(u8, &id.bytes, &parsed.bytes);
}

test "permanent Node public keys bind once and reset explicitly" {
    var store = Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try Cidr.parse("10.1.0.0/24"));
    try store.createNode(.{ .bytes = .{1} ** 16 }, "node01", "vnr0", try Ipv4.parse("10.1.0.2"));
    try store.bindNodePublicKey("node01", .{7} ** 32);
    try std.testing.expectEqual(EnrollmentState.enrolled, store.findNode("node01").?.enrollment_state);
    try std.testing.expectError(error.NodeAlreadyEnrolled, store.bindNodePublicKey("node01", .{8} ** 32));
    try store.resetNodeEnrollment("node01");
    try std.testing.expectEqual(EnrollmentState.unenrolled, store.findNode("node01").?.enrollment_state);
    try std.testing.expect(store.findNode("node01").?.public_key == null);
}
