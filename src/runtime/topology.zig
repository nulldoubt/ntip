const std = @import("std");
const model = @import("../domain/model.zig");
const configuration = @import("../protocol/configuration.zig");
const forwarding = @import("forwarding.zig");
const authorization = @import("authorization.zig");

pub const SessionBinding = struct {
    node_id: model.NodeId,
    receiver_session_id: u64,
};

pub const MasterSnapshots = struct {
    forwarding: forwarding.Snapshot,
    sources: authorization.Snapshot,
    destinations: authorization.Snapshot,

    pub fn deinit(self: *MasterSnapshots) void {
        self.forwarding.deinit();
        self.sources.deinit();
        self.destinations.deinit();
        self.* = undefined;
    }

    pub fn destroy(self: *MasterSnapshots) void {
        const allocator = self.forwarding.allocator;
        self.deinit();
        allocator.destroy(self);
    }
};

pub const ClientSnapshots = struct {
    forwarding: forwarding.Snapshot,
    sources: authorization.Snapshot,
    destinations: authorization.Snapshot,

    pub fn deinit(self: *ClientSnapshots) void {
        self.forwarding.deinit();
        self.sources.deinit();
        self.destinations.deinit();
        self.* = undefined;
    }

    pub fn destroy(self: *ClientSnapshots) void {
        const allocator = self.forwarding.allocator;
        self.deinit();
        allocator.destroy(self);
    }
};

pub fn createMaster(
    allocator: std.mem.Allocator,
    store: *const model.Store,
    sessions: []const SessionBinding,
) !*MasterSnapshots {
    const snapshots = try allocator.create(MasterSnapshots);
    errdefer allocator.destroy(snapshots);
    snapshots.* = try buildMaster(allocator, store, sessions);
    return snapshots;
}

/// Builds the Node's complete immutable policy from one authenticated
/// configuration generation. The authenticated Master may carry packets from
/// any IPv4 source (including an Internet client preserved by DNAT), while the
/// destination policy still confines delivery to this Node's assigned address
/// and prefixes routed locally behind it. Master-side policy separately
/// enforces strict per-Node source ownership on the untrusted direction.
pub fn createClient(
    allocator: std.mem.Allocator,
    view: configuration.View,
    session_owner: u128,
    destination_owner: u128,
) !*ClientSnapshots {
    const snapshots = try allocator.create(ClientSnapshots);
    errdefer allocator.destroy(snapshots);

    var forwarding_entries: std.ArrayList(forwarding.Entry) = .empty;
    defer forwarding_entries.deinit(allocator);
    var source_entries: std.ArrayList(authorization.Entry) = .empty;
    defer source_entries.deinit(allocator);
    var destination_entries: std.ArrayList(authorization.Entry) = .empty;
    defer destination_entries.deinit(allocator);

    // This is source authorization for packets received from the authoritative
    // Master, not a default route. Restricting this set to VNRs would break an
    // ordinary DNAT flow that preserves the public client's source address.
    try source_entries.append(allocator, .{
        .owner = session_owner,
        .network = 0,
        .prefix_len = 0,
    });
    try destination_entries.append(allocator, .{
        .owner = destination_owner,
        .network = std.mem.readInt(u32, &view.own_address, .big),
        .prefix_len = 32,
    });
    var index: usize = 0;
    while (index < view.route_count) : (index += 1) {
        const route = try view.route(index);
        const network = std.mem.readInt(u32, &route.network, .big);
        if (route.kind == .local_routed_prefix) {
            try destination_entries.append(allocator, .{
                .owner = destination_owner,
                .network = network,
                .prefix_len = route.prefix_len,
            });
        } else {
            try forwarding_entries.append(allocator, .{
                .network = network,
                .prefix_len = route.prefix_len,
                .owner = session_owner,
            });
        }
    }

    var forwarding_snapshot = try forwarding.Snapshot.init(allocator, forwarding_entries.items);
    errdefer forwarding_snapshot.deinit();
    var source_snapshot = try authorization.Snapshot.init(allocator, source_entries.items);
    errdefer source_snapshot.deinit();
    const destination_snapshot = try authorization.Snapshot.init(allocator, destination_entries.items);
    snapshots.* = .{
        .forwarding = forwarding_snapshot,
        .sources = source_snapshot,
        .destinations = destination_snapshot,
    };
    return snapshots;
}

pub fn createEmptyClient(allocator: std.mem.Allocator) !*ClientSnapshots {
    const snapshots = try allocator.create(ClientSnapshots);
    errdefer allocator.destroy(snapshots);
    var forwarding_snapshot = try forwarding.Snapshot.init(allocator, &.{});
    errdefer forwarding_snapshot.deinit();
    var source_snapshot = try authorization.Snapshot.init(allocator, &.{});
    errdefer source_snapshot.deinit();
    snapshots.* = .{
        .forwarding = forwarding_snapshot,
        .sources = source_snapshot,
        .destinations = try authorization.Snapshot.init(allocator, &.{}),
    };
    return snapshots;
}

/// Materializes all policy decisions outside the packet hot path. Offline
/// Nodes retain route entries with receiver id zero, which the data plane drops
/// and counts without buffering.
pub fn buildMaster(
    allocator: std.mem.Allocator,
    store: *const model.Store,
    sessions: []const SessionBinding,
) !MasterSnapshots {
    const route_count = try std.math.add(usize, store.nodes.items.len, store.routes.items.len);
    var routes = try allocator.alloc(forwarding.Entry, route_count);
    defer allocator.free(routes);
    var sources = try allocator.alloc(authorization.Entry, route_count);
    defer allocator.free(sources);
    const destination_count = try std.math.add(usize, store.vnrs.items.len, route_count);
    var destinations = try allocator.alloc(authorization.Entry, destination_count);
    defer allocator.free(destinations);

    var route_index: usize = 0;
    var source_index: usize = 0;
    var destination_index: usize = 0;
    for (store.vnrs.items) |vnr| {
        destinations[destination_index] = .{
            .owner = masterDestinationOwner(),
            .network = vnr.masterAddress().value,
            .prefix_len = 32,
        };
        destination_index += 1;
    }
    for (store.nodes.items) |node| {
        const owner = ownerForNode(node.id);
        const receiver_id = receiverFor(node.id, sessions);
        routes[route_index] = .{
            .network = node.address.value,
            .prefix_len = 32,
            .owner = owner,
            .receiver_session_id = receiver_id,
        };
        route_index += 1;
        sources[source_index] = .{ .owner = owner, .network = node.address.value, .prefix_len = 32 };
        source_index += 1;
        destinations[destination_index] = .{
            .owner = masterDestinationOwner(),
            .network = node.address.value,
            .prefix_len = 32,
        };
        destination_index += 1;
    }
    for (store.routes.items) |route| {
        const node = store.findNode(route.node.slice()).?;
        const owner = ownerForNode(node.id);
        const receiver_id = receiverFor(node.id, sessions);
        routes[route_index] = .{
            .network = route.prefix.network.value,
            .prefix_len = route.prefix.prefix,
            .owner = owner,
            .receiver_session_id = receiver_id,
        };
        route_index += 1;
        sources[source_index] = .{
            .owner = owner,
            .network = route.prefix.network.value,
            .prefix_len = route.prefix.prefix,
        };
        source_index += 1;
        destinations[destination_index] = .{
            .owner = masterDestinationOwner(),
            .network = route.prefix.network.value,
            .prefix_len = route.prefix.prefix,
        };
        destination_index += 1;
    }
    var forwarding_snapshot = try forwarding.Snapshot.init(allocator, routes);
    errdefer forwarding_snapshot.deinit();
    var source_snapshot = try authorization.Snapshot.init(allocator, sources);
    errdefer source_snapshot.deinit();
    return .{
        .forwarding = forwarding_snapshot,
        .sources = source_snapshot,
        .destinations = try authorization.Snapshot.init(allocator, destinations),
    };
}

pub fn masterDestinationOwner() u128 {
    return 0;
}

pub fn ownerForNode(id: model.NodeId) u128 {
    return std.mem.readInt(u128, &id.bytes, .big);
}

fn receiverFor(id: model.NodeId, sessions: []const SessionBinding) u64 {
    for (sessions) |binding| if (binding.node_id.eql(id)) return binding.receiver_session_id;
    return 0;
}

test "Master snapshots bind node and routed prefixes to one owner" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    const id: model.NodeId = .{ .bytes = .{7} ** 16 };
    try store.createNode(id, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    try store.addRoute(try model.Cidr.parse("192.168.178.0/24"), "node01");
    var snapshots = try buildMaster(std.testing.allocator, &store, &.{.{
        .node_id = id,
        .receiver_session_id = 99,
    }});
    defer snapshots.deinit();
    try std.testing.expectEqual(@as(u64, 99), snapshots.forwarding.lookup(0x0a010002).?.receiver_session_id);
    try std.testing.expectEqual(@as(u64, 99), snapshots.forwarding.lookup(0xc0a8b22a).?.receiver_session_id);
    try std.testing.expect(snapshots.sources.permits(ownerForNode(id), 0xc0a8b22a));
    try std.testing.expect(snapshots.destinations.permits(masterDestinationOwner(), 0x0a010001));
    try std.testing.expect(snapshots.destinations.permits(masterDestinationOwner(), 0x0a010002));
    try std.testing.expect(snapshots.destinations.permits(masterDestinationOwner(), 0xc0a8b22a));
    try std.testing.expect(!snapshots.destinations.permits(masterDestinationOwner(), 0x0a010063));
    try std.testing.expect(!snapshots.destinations.permits(masterDestinationOwner(), 0xac100001));
}

test "heap-owned Master snapshots have one explicit destroy path" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    const id: model.NodeId = .{ .bytes = .{8} ** 16 };
    try store.createNode(id, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    const snapshots = try createMaster(std.testing.allocator, &store, &.{});
    try std.testing.expectEqual(@as(u128, ownerForNode(id)), snapshots.forwarding.lookup(0x0a010002).?.owner);
    snapshots.destroy();
}

test "Node policy accepts public DNAT sources but confines destinations" {
    const configured_routes = [_]configuration.Route{
        .{ .network = .{ 10, 1, 0, 0 }, .prefix_len = 24, .kind = .vnr },
        .{ .network = .{ 192, 168, 178, 0 }, .prefix_len = 24, .kind = .local_routed_prefix },
    };
    var storage: [configuration.maximum_snapshot_len]u8 = undefined;
    const bytes = try (configuration.Snapshot{
        .node_uuid = [_]u8{0x44} ** 16,
        .own_address = .{ 10, 1, 0, 2 },
        .own_vnr_network = .{ 10, 1, 0, 0 },
        .own_vnr_prefix_len = 24,
        .master_address = .{ 10, 1, 0, 1 },
        .inner_mtu = 1380,
        .heartbeat_seconds = 15,
        .suspect_seconds = 30,
        .offline_seconds = 45,
        .cold_seconds = 30,
        .hysteresis_seconds = 5,
        .hot_packets_per_second = 100_000,
        .hot_bits_per_second = 1_000_000_000,
        .saturated_queue_percent = 80,
        .routes = &configured_routes,
    }).encode(&storage);
    const session_owner: u128 = 91;
    const destination_owner: u128 = 92;
    const snapshots = try createClient(
        std.testing.allocator,
        try configuration.View.decode(bytes),
        session_owner,
        destination_owner,
    );
    defer snapshots.destroy();

    try std.testing.expect(snapshots.sources.permits(session_owner, 0xcb00_7109)); // 203.0.113.9
    try std.testing.expect(snapshots.sources.permits(session_owner, 0x0a01_0001));
    try std.testing.expect(snapshots.destinations.permits(destination_owner, 0x0a01_0002));
    try std.testing.expect(snapshots.destinations.permits(destination_owner, 0xc0a8_b214));
    try std.testing.expect(!snapshots.destinations.permits(destination_owner, 0x0a01_0003));
}
