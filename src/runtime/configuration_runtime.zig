//! Authenticated configuration publication and atomic Node-side application.
//!
//! This module is deliberately control-plane only. It may allocate while
//! materializing a new generation, but the installed forwarding and policy
//! snapshots are immutable and allocation-free in the packet path.

const std = @import("std");
const model = @import("../domain/model.zig");
const protocol_control = @import("../protocol/control.zig");
const configuration = @import("../protocol/configuration.zig");
const state_config = @import("../state/config.zig");
const client_state = @import("../state/client.zig");
const control_plane = @import("control_plane.zig");
const config_sync = @import("config_sync.zig");
const data_worker = @import("data_worker.zig");
const topology = @import("topology.zig");
const routes_mod = @import("../platform/linux/routes.zig");

const resend_interval_ns: u64 = std.time.ns_per_s;

const PublishedPeer = struct {
    active: bool = false,
    node_uuid: [16]u8 = [_]u8{0} ** 16,
    receiver_session_id: u64 = 0,
    acknowledged_generation: u64 = 0,
    pending_generation: u64 = 0,
    pending_request_id: u32 = 0,
    pending_bytes: []u8 = &.{},
    pending_hash: [protocol_control.snapshot_hash_len]u8 = [_]u8{0} ** protocol_control.snapshot_hash_len,
    next_send_ns: u64 = 0,

    fn clearPending(self: *PublishedPeer, allocator: std.mem.Allocator) void {
        if (self.pending_bytes.len != 0) allocator.free(self.pending_bytes);
        self.pending_bytes = &.{};
        self.pending_generation = 0;
        self.pending_request_id = 0;
        @memset(&self.pending_hash, 0);
        self.next_send_ns = 0;
    }
};

pub const AssociationRetirer = struct {
    context: *anyopaque,
    retire_fn: *const fn (*anyopaque, [16]u8) void,

    pub fn retire(self: AssociationRetirer, node_uuid: [16]u8) void {
        self.retire_fn(self.context, node_uuid);
    }
};

/// Bounded per-Node publisher. A generation is retained until the Node
/// acknowledges the exact snapshot hash. Retransmission re-encapsulates the
/// same snapshot with fresh transport sequences.
pub const MasterPublisher = struct {
    allocator: std.mem.Allocator,
    control: *control_plane.ControlPlane,
    store: *const model.Store,
    config: *const state_config.ServerConfig,
    peers: []PublishedPeer,
    effective_generation: u64 = 0,
    association_retirer: ?AssociationRetirer = null,

    pub fn init(
        allocator: std.mem.Allocator,
        control: *control_plane.ControlPlane,
        store: *const model.Store,
        config: *const state_config.ServerConfig,
        capacity: usize,
    ) !MasterPublisher {
        if (capacity == 0) return error.InvalidPublisherCapacity;
        const peers = try allocator.alloc(PublishedPeer, capacity);
        for (peers) |*peer| peer.* = .{};
        return .{
            .allocator = allocator,
            .control = control,
            .store = store,
            .config = config,
            .peers = peers,
            .effective_generation = store.generation,
        };
    }

    pub fn deinit(self: *MasterPublisher) void {
        for (self.peers) |*peer| peer.clearPending(self.allocator);
        self.allocator.free(self.peers);
        self.* = undefined;
    }

    pub fn readyCallback(self: *MasterPublisher) @import("handshake_coordinator.zig").MasterSessionReady {
        return .{ .context = self, .ready_fn = sessionReadyOpaque };
    }

    pub fn observer(self: *MasterPublisher) control_plane.ConfigurationObserver {
        return .{ .context = self, .receive_fn = receiveOpaque };
    }

    pub fn generationChanged(self: *MasterPublisher, generation: u64) void {
        if (generation > self.effective_generation) self.effective_generation = generation;
    }

    pub fn setAssociationRetirer(self: *MasterPublisher, retirer: AssociationRetirer) void {
        self.association_retirer = retirer;
    }

    pub fn tick(self: *MasterPublisher, now_ns: u64) !void {
        // Inventory and effective settings acknowledgements advance the same
        // committed generation. Reading the in-memory projection here also
        // covers inventory publishers that coalesced their explicit notice.
        if (self.store.generation > self.effective_generation) {
            self.effective_generation = self.store.generation;
        }
        for (self.peers) |*peer| {
            if (!peer.active) continue;
            const node = self.findNode(peer.node_uuid);
            if (node == null or node.?.enrollment_state != .enrolled) {
                if (self.association_retirer) |retirer| {
                    retirer.retire(peer.node_uuid);
                } else {
                    self.control.abortSession(peer.receiver_session_id) catch {};
                }
                peer.clearPending(self.allocator);
                peer.* = .{};
                continue;
            }
            if (peer.pending_generation == 0 and peer.acknowledged_generation < self.effective_generation) {
                try self.prepare(peer, self.effective_generation, now_ns);
            }
            if (peer.pending_generation == 0 or now_ns < peer.next_send_ns) continue;
            self.transmit(peer, now_ns) catch |err| switch (err) {
                error.CommandQueueFull => {
                    peer.next_send_ns = now_ns +| 100 * std.time.ns_per_ms;
                    continue;
                },
                error.UnknownSession => {
                    peer.clearPending(self.allocator);
                    peer.* = .{};
                    continue;
                },
                else => return err,
            };
        }
    }

    fn prepare(self: *MasterPublisher, peer: *PublishedPeer, generation: u64, now_ns: u64) !void {
        const bytes = try buildSnapshot(self.allocator, self.store, self.config, peer.node_uuid);
        errdefer self.allocator.free(bytes);
        const sender = try config_sync.Sender.init(bytes);
        const request_base = try self.control.reserveRequestIds(
            peer.receiver_session_id,
            @as(u32, sender.chunk_count) + 1,
        );
        peer.clearPending(self.allocator);
        peer.pending_bytes = bytes;
        peer.pending_hash = sender.hash;
        peer.pending_generation = generation;
        peer.pending_request_id = request_base;
        peer.next_send_ns = now_ns;
    }

    fn transmit(self: *MasterPublisher, peer: *PublishedPeer, now_ns: u64) !void {
        const sender = try config_sync.Sender.init(peer.pending_bytes);
        const begin = sender.begin().encode();
        try self.control.sendConfigurationFrameWithRequestId(
            peer.receiver_session_id,
            .configuration_begin,
            peer.pending_request_id,
            &begin,
            peer.pending_generation,
            now_ns,
        );
        var index: u16 = 0;
        while (index < sender.chunk_count) : (index += 1) {
            const chunk = try sender.chunk(index);
            var storage: [protocol_control.max_payload_len]u8 = undefined;
            const encoded = try chunk.encode(&storage);
            try self.control.sendConfigurationFrameWithRequestId(
                peer.receiver_session_id,
                .configuration_chunk,
                control_plane.requestIdAt(peer.pending_request_id, @as(u32, index) + 1),
                encoded,
                peer.pending_generation,
                now_ns,
            );
        }
        peer.next_send_ns = now_ns +| resend_interval_ns;
    }

    fn sessionReadyOpaque(
        raw: *anyopaque,
        node_uuid: [16]u8,
        receiver_session_id: u64,
        _: u64,
        _: @import("handshake_coordinator.zig").EstablishedKind,
        now_ns: u64,
    ) anyerror!void {
        const self: *MasterPublisher = @ptrCast(@alignCast(raw));
        const peer = self.findPeer(node_uuid) orelse self.acquirePeer() orelse return error.PublisherCapacityExhausted;
        peer.clearPending(self.allocator);
        peer.* = .{
            .active = true,
            .node_uuid = node_uuid,
            .receiver_session_id = receiver_session_id,
        };
        try self.prepare(peer, self.effective_generation, now_ns);
        // Queue the first generation before the coordinator emits the
        // enrollment completion/heartbeat signal.
        try self.transmit(peer, now_ns);
    }

    fn receiveOpaque(
        raw: *anyopaque,
        receiver_session_id: u64,
        frame_type: protocol_control.Type,
        request_id: u32,
        generation: u64,
        payload: []const u8,
        _: u64,
    ) void {
        if (frame_type != .configuration_ack or payload.len != protocol_control.snapshot_hash_len) return;
        const self: *MasterPublisher = @ptrCast(@alignCast(raw));
        for (self.peers) |*peer| {
            if (!peer.active or peer.receiver_session_id != receiver_session_id) continue;
            if (peer.pending_generation != generation) return;
            if (peer.pending_request_id != request_id) return;
            if (!std.crypto.timing_safe.eql(
                [protocol_control.snapshot_hash_len]u8,
                peer.pending_hash,
                payload[0..protocol_control.snapshot_hash_len].*,
            )) return;
            peer.acknowledged_generation = generation;
            peer.clearPending(self.allocator);
            return;
        }
    }

    fn findPeer(self: *MasterPublisher, node_uuid: [16]u8) ?*PublishedPeer {
        for (self.peers) |*peer| {
            if (peer.active and std.mem.eql(u8, &peer.node_uuid, &node_uuid)) return peer;
        }
        return null;
    }

    fn acquirePeer(self: *MasterPublisher) ?*PublishedPeer {
        for (self.peers) |*peer| if (!peer.active) return peer;
        return null;
    }

    fn findNode(self: *const MasterPublisher, node_uuid: [16]u8) ?*const model.Node {
        for (self.store.nodes.items) |*node| {
            if (std.mem.eql(u8, &node.id.bytes, &node_uuid)) return node;
        }
        return null;
    }
};

/// Reassembles one authenticated generation, reconciles only NTIP-owned TUN
/// state, and acknowledges it after the data worker has installed the exact
/// immutable policy snapshots.
pub const NodeApplier = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    control: *control_plane.ControlPlane,
    worker: *data_worker.DataWorker,
    routes: routes_mod.Controller,
    interface_name: []const u8,
    persistent: *client_state.PersistentState,
    generation_store: ?GenerationStore = null,
    receiver: config_sync.Receiver,
    installed_routes: std.ArrayList(model.Cidr) = .empty,
    pending_install: bool = false,
    pending_receiver_id: u64 = 0,
    pending_generation: u64 = 0,
    pending_request_id: u32 = 0,
    pending_hash: [protocol_control.snapshot_hash_len]u8 = [_]u8{0} ** protocol_control.snapshot_hash_len,
    pending_allows_rollback: bool = false,
    active_receiver_id: u64 = 0,
    applied_generation: u64 = 0,
    applied_hash: [protocol_control.snapshot_hash_len]u8 = [_]u8{0} ** protocol_control.snapshot_hash_len,
    ack_due: bool = false,
    forwarding_warning_checked: bool = false,
    fatal_error: ?anyerror = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        control: *control_plane.ControlPlane,
        worker: *data_worker.DataWorker,
        routes: routes_mod.Controller,
        interface_name: []const u8,
        persistent: *client_state.PersistentState,
    ) NodeApplier {
        return .{
            .allocator = allocator,
            .io = io,
            .control = control,
            .worker = worker,
            .routes = routes,
            .interface_name = interface_name,
            .persistent = persistent,
            .receiver = config_sync.Receiver.init(allocator),
        };
    }

    pub fn setGenerationStore(self: *NodeApplier, store: GenerationStore) void {
        self.generation_store = store;
    }

    pub fn deinit(self: *NodeApplier) void {
        self.receiver.deinit();
        self.installed_routes.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn observer(self: *NodeApplier) control_plane.ConfigurationObserver {
        return .{ .context = self, .receive_fn = receiveOpaque };
    }

    pub fn snapshotObserver(self: *NodeApplier) control_plane.ClientSnapshotObserver {
        return .{ .context = self, .installed_fn = installedOpaque };
    }

    pub fn tick(self: *NodeApplier, now_ns: u64) !void {
        if (self.fatal_error) |err| return err;
        if (!self.ack_due) return;
        self.control.sendConfigurationResponse(
            self.pending_receiver_id,
            .configuration_ack,
            self.pending_request_id,
            &self.applied_hash,
            self.applied_generation,
            now_ns,
        ) catch |err| switch (err) {
            error.CommandQueueFull => return,
            else => return err,
        };
        self.ack_due = false;
    }

    fn receiveOpaque(
        raw: *anyopaque,
        receiver_session_id: u64,
        frame_type: protocol_control.Type,
        request_id: u32,
        generation: u64,
        payload: []const u8,
        now_ns: u64,
    ) void {
        const self: *NodeApplier = @ptrCast(@alignCast(raw));
        self.receive(receiver_session_id, frame_type, request_id, generation, payload, now_ns) catch |err| {
            self.fatal_error = err;
        };
    }

    fn receive(
        self: *NodeApplier,
        receiver_session_id: u64,
        frame_type: protocol_control.Type,
        request_id: u32,
        generation: u64,
        payload: []const u8,
        now_ns: u64,
    ) !void {
        if (frame_type == .configuration_begin) {
            if (!self.selectAuthenticatedSession(receiver_session_id)) return;
        } else if (receiver_session_id != self.active_receiver_id) {
            return;
        }
        switch (frame_type) {
            .configuration_begin => {
                const begin = try protocol_control.ConfigurationBegin.decode(payload);
                if (generation < self.applied_generation) return;
                self.pending_request_id = request_id;
                if (generation == self.applied_generation and std.crypto.timing_safe.eql(
                    [protocol_control.snapshot_hash_len]u8,
                    self.applied_hash,
                    begin.hash,
                )) {
                    self.pending_receiver_id = receiver_session_id;
                    self.ack_due = true;
                    try self.tick(now_ns);
                    return;
                }
                if (self.pending_install) {
                    if (generation == self.pending_generation and std.crypto.timing_safe.eql(
                        [protocol_control.snapshot_hash_len]u8,
                        self.pending_hash,
                        begin.hash,
                    )) return;
                    if (generation <= self.pending_generation) return;
                    return error.ConfigurationInstallAlreadyPending;
                }
                try self.receiver.start(generation, begin);
            },
            .configuration_chunk => {
                if (self.pending_install or generation != self.receiver.generation) return;
                _ = try self.receiver.accept(try protocol_control.ConfigurationChunk.decode(payload));
                if (!self.receiver.complete()) return;
                try self.apply(receiver_session_id, generation);
            },
            .configuration_ack => {},
            else => return error.InvalidConfigurationFrameType,
        }
    }

    fn apply(self: *NodeApplier, receiver_session_id: u64, generation: u64) !void {
        const view = try self.receiver.finish();
        const expected_id = self.persistent.node_id orelse return error.MissingPersistentAssignment;
        if (!std.mem.eql(u8, &view.node_uuid, &expected_id.bytes)) return error.ConfigurationIdentityMismatch;
        const expected_address = self.persistent.assigned_address orelse return error.MissingPersistentAssignment;
        const expected_range = self.persistent.vnr_range orelse return error.MissingPersistentAssignment;
        if (std.mem.readInt(u32, &view.own_address, .big) != expected_address.value or
            std.mem.readInt(u32, &view.own_vnr_network, .big) != expected_range.network.value or
            view.own_vnr_prefix_len != expected_range.prefix)
        {
            return error.ConfigurationAssignmentMismatch;
        }

        const session_owner = topology.ownerForNode(expected_id);
        const snapshots = try topology.createClient(self.allocator, view, session_owner, destination_owner);
        errdefer snapshots.destroy();
        try self.control.configureLiveness(view.heartbeat_seconds, view.suspect_seconds, view.offline_seconds);
        try self.reconcileKernel(view);
        const traffic_config: @import("traffic.zig").Config = .{
            .cold_after_ns = @as(u64, view.cold_seconds) * std.time.ns_per_s,
            .hot_pps = view.hot_packets_per_second,
            .hot_bits_per_second = view.hot_bits_per_second,
            .saturated_queue_percent = view.saturated_queue_percent,
            .hysteresis_ns = @as(u64, view.hysteresis_seconds) * std.time.ns_per_s,
        };
        if (!self.worker.submit(data_worker.DataCommand.installClientSnapshot(
            snapshots,
            generation,
            traffic_config,
            view.inner_mtu,
        ))) {
            return error.CommandQueueFull;
        }
        self.pending_install = true;
        self.pending_receiver_id = receiver_session_id;
        self.pending_generation = generation;
        self.pending_hash = self.receiver.expected_hash;
        self.pending_allows_rollback = self.applied_generation == 0;
        self.receiver.reset();
    }

    /// Configuration generations are monotonic within one authenticated
    /// transport session. A fresh Noise session is also the recovery boundary:
    /// it must reinstall a complete snapshot even when a coherent Master
    /// backup has a numerically lower generation than the Node last recorded.
    fn selectAuthenticatedSession(self: *NodeApplier, receiver_session_id: u64) bool {
        if (self.control.peerTransmitEnabled(receiver_session_id) != true) return false;
        if (receiver_session_id == self.active_receiver_id) return true;
        if (self.pending_install) return false;

        self.receiver.reset();
        self.active_receiver_id = receiver_session_id;
        self.applied_generation = 0;
        @memset(&self.applied_hash, 0);
        self.ack_due = false;
        return true;
    }

    fn reconcileKernel(self: *NodeApplier, view: configuration.View) !void {
        try self.routes.configureLink(self.interface_name, view.inner_mtu);
        var address_buffer: [15]u8 = undefined;
        var address_cidr_buffer: [18]u8 = undefined;
        const address = model.Ipv4{ .value = std.mem.readInt(u32, &view.own_address, .big) };
        const address_cidr = try std.fmt.bufPrint(&address_cidr_buffer, "{s}/32", .{try address.write(&address_buffer)});
        try self.routes.replaceAddress(self.interface_name, address_cidr);

        var desired: std.ArrayList(model.Cidr) = .empty;
        defer desired.deinit(self.allocator);
        var has_local_routed_prefix = false;
        var index: usize = 0;
        while (index < view.route_count) : (index += 1) {
            const route = try view.route(index);
            if (route.kind == .local_routed_prefix) {
                has_local_routed_prefix = true;
                continue;
            }
            const cidr = model.Cidr.fromAddress(.{
                .value = std.mem.readInt(u32, &route.network, .big),
            }, route.prefix_len);
            try desired.append(self.allocator, cidr);
            var cidr_buffer: [18]u8 = undefined;
            try self.routes.replaceRoute(self.interface_name, try cidr.write(&cidr_buffer), view.inner_mtu);
        }
        for (self.installed_routes.items) |old| {
            if (containsCidr(desired.items, old)) continue;
            var cidr_buffer: [18]u8 = undefined;
            try self.routes.deleteRoute(self.interface_name, try old.write(&cidr_buffer));
        }
        self.installed_routes.clearRetainingCapacity();
        try self.installed_routes.appendSlice(self.allocator, desired.items);
        if (has_local_routed_prefix and !self.forwarding_warning_checked) {
            self.forwarding_warning_checked = true;
            const enabled = self.routes.forwardingEnabled() catch |err| {
                std.log.warn("could not inspect net.ipv4.ip_forward for routed-prefix Node ({s})", .{@errorName(err)});
                return;
            };
            if (!enabled) {
                std.log.warn("IPv4 forwarding is disabled; prefixes routed behind this Node will not work", .{});
            }
        }
    }

    fn installedOpaque(raw: *anyopaque, generation: u64, retired: ?*topology.ClientSnapshots) void {
        const self: *NodeApplier = @ptrCast(@alignCast(raw));
        if (retired) |snapshot| snapshot.destroy();
        if (!self.pending_install or generation != self.pending_generation) {
            self.fatal_error = error.ClientSnapshotAcknowledgementMismatch;
            return;
        }
        if (self.generation_store) |store| store.persist(generation, self.pending_allows_rollback) catch |err| {
            self.fatal_error = err;
            return;
        };
        self.pending_install = false;
        self.pending_allows_rollback = false;
        self.applied_generation = generation;
        self.applied_hash = self.pending_hash;
        self.ack_due = true;
    }
};

pub const GenerationStore = struct {
    context: *anyopaque,
    persist_fn: *const fn (*anyopaque, u64, bool) anyerror!void,

    pub fn persist(self: GenerationStore, generation: u64, allow_rollback: bool) !void {
        return self.persist_fn(self.context, generation, allow_rollback);
    }
};

pub fn buildSnapshot(
    allocator: std.mem.Allocator,
    store: *const model.Store,
    config: *const state_config.ServerConfig,
    node_uuid: [16]u8,
) ![]u8 {
    const node = findNode(store, node_uuid) orelse return error.NodeNotFound;
    const own_vnr = store.findVnr(node.vnr.slice()) orelse return error.VnrNotFound;
    var entries = try allocator.alloc(configuration.Route, store.vnrs.items.len + store.routes.items.len);
    defer allocator.free(entries);
    var index: usize = 0;
    for (store.vnrs.items) |vnr| {
        entries[index] = .{
            .network = vnr.range.network.octets(),
            .prefix_len = vnr.range.prefix,
            .kind = .vnr,
        };
        index += 1;
    }
    for (store.routes.items) |route| {
        entries[index] = .{
            .network = route.prefix.network.octets(),
            .prefix_len = route.prefix.prefix,
            .kind = if (route.node.eql(node.name)) .local_routed_prefix else .routed_prefix,
        };
        index += 1;
    }
    std.mem.sort(configuration.Route, entries, {}, routeLessThan);

    const storage = try allocator.alloc(u8, configuration.header_len + entries.len * configuration.entry_len);
    errdefer allocator.free(storage);
    const encoded = try (configuration.Snapshot{
        .node_uuid = node.id.bytes,
        .own_address = node.address.octets(),
        .own_vnr_network = own_vnr.range.network.octets(),
        .own_vnr_prefix_len = own_vnr.range.prefix,
        .master_address = own_vnr.masterAddress().octets(),
        .inner_mtu = config.inner_mtu,
        .heartbeat_seconds = config.heartbeat_idle_seconds,
        .suspect_seconds = config.suspect_after_seconds,
        .offline_seconds = config.offline_after_seconds,
        .cold_seconds = @intCast(config.traffic.cold_after_seconds),
        .hysteresis_seconds = @intCast(config.traffic.hysteresis_seconds),
        .hot_packets_per_second = @intCast(config.traffic.hot_packets_per_second),
        .hot_bits_per_second = config.traffic.hot_bits_per_second,
        .saturated_queue_percent = config.traffic.saturated_queue_percent,
        .routes = entries,
    }).encode(storage);
    std.debug.assert(encoded.len == storage.len);
    return storage;
}

fn routeLessThan(_: void, left: configuration.Route, right: configuration.Route) bool {
    const left_network = std.mem.readInt(u32, &left.network, .big);
    const right_network = std.mem.readInt(u32, &right.network, .big);
    if (left_network != right_network) return left_network < right_network;
    if (left.prefix_len != right.prefix_len) return left.prefix_len < right.prefix_len;
    return @intFromEnum(left.kind) < @intFromEnum(right.kind);
}

fn findNode(store: *const model.Store, node_uuid: [16]u8) ?*const model.Node {
    for (store.nodes.items) |*node| if (std.mem.eql(u8, &node.id.bytes, &node_uuid)) return node;
    return null;
}

fn containsCidr(items: []const model.Cidr, expected: model.Cidr) bool {
    for (items) |item| {
        if (item.network.value == expected.network.value and item.prefix == expected.prefix) return true;
    }
    return false;
}

pub const destination_owner: u128 = 2;

test "Master snapshot marks prefixes routed behind the receiving Node as local" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    _ = try store.createVnr("vnr1", try model.Cidr.parse("10.2.0.0/24"));
    const id: model.NodeId = .{ .bytes = .{7} ** 16 };
    try store.createNode(id, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    try store.addRoute(try model.Cidr.parse("192.168.178.0/24"), "node01");
    const config: state_config.ServerConfig = .{ .schema_version = 1 };
    const bytes = try buildSnapshot(std.testing.allocator, &store, &config, id.bytes);
    defer std.testing.allocator.free(bytes);
    const view = try configuration.View.decode(bytes);
    try std.testing.expectEqual(@as(u16, 3), view.route_count);
    var found_local = false;
    for (0..view.route_count) |route_index| {
        if ((try view.route(route_index)).kind == .local_routed_prefix) found_local = true;
    }
    try std.testing.expect(found_local);
}

test "settings-only effective generation is published and acknowledged" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    const id: model.NodeId = .{ .bytes = .{7} ** 16 };
    try store.createNode(id, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    try store.bindNodePublicKey("node01", [_]u8{9} ** 32);

    var events = try data_worker.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink_context: u8 = 0;
    var control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink_context,
        .submit_fn = AcceptingCommandSink.submit,
    });
    defer control.deinit();
    try control.registerPendingSession(.{
        .receiver_id = 71,
        .peer_receiver_id = 72,
        .owner = 7,
        .tx_key = [_]u8{0x11} ** 32,
        .rx_key = [_]u8{0x22} ** 32,
        .created_ns = 1,
        .endpoint = .{ .ip4 = .loopback(49171) },
    }, [_]u8{0x33} ** 32, 1);
    try control.confirmAsInitiator(71, 1);

    var config: state_config.ServerConfig = .{ .schema_version = 1 };
    var publisher = try MasterPublisher.init(
        std.testing.allocator,
        &control,
        &store,
        &config,
        1,
    );
    defer publisher.deinit();
    try publisher.readyCallback().ready(id.bytes, 71, 0, .reconnect_or_rekey, 1);

    var peer = &publisher.peers[0];
    const initial_generation = peer.pending_generation;
    const initial_request = peer.pending_request_id;
    const initial_hash = peer.pending_hash;
    publisher.observer().receive(
        71,
        .configuration_ack,
        initial_request,
        initial_generation,
        &initial_hash,
        2,
    );
    try std.testing.expectEqual(initial_generation, peer.acknowledged_generation);
    try std.testing.expectEqual(@as(u64, 0), peer.pending_generation);

    // This models the post-commit effective callback: no inventory object
    // changes, but the shared durable configuration generation advances and
    // the immutable runtime config is replaced before publication.
    config.inner_mtu = 1420;
    store.generation = try std.math.add(u64, store.generation, 1);
    publisher.generationChanged(store.generation);
    try publisher.tick(3);

    peer = &publisher.peers[0];
    try std.testing.expectEqual(store.generation, peer.pending_generation);
    try std.testing.expect(peer.pending_generation > initial_generation);
    const view = try configuration.View.decode(peer.pending_bytes);
    try std.testing.expectEqual(@as(u16, 1420), view.inner_mtu);

    const applied_generation = peer.pending_generation;
    const applied_request = peer.pending_request_id;
    const applied_hash = peer.pending_hash;
    publisher.observer().receive(
        71,
        .configuration_ack,
        applied_request,
        applied_generation,
        &applied_hash,
        4,
    );
    try std.testing.expectEqual(applied_generation, peer.acknowledged_generation);
    try std.testing.expectEqual(@as(u64, 0), peer.pending_generation);
}

const AcceptingCommandSink = struct {
    fn submit(_: *anyopaque, _: data_worker.DataCommand) bool {
        return true;
    }
};

test "fresh authenticated session resets the configuration generation floor" {
    var events = try data_worker.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink_context: u8 = 0;
    var control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink_context,
        .submit_fn = AcceptingCommandSink.submit,
    });
    defer control.deinit();

    var fake_worker: data_worker.DataWorker = undefined;
    var persistent: client_state.PersistentState = .{ .generation = 41 };
    var applier = NodeApplier.init(
        std.testing.allocator,
        std.testing.io,
        &control,
        &fake_worker,
        .{ .allocator = std.testing.allocator, .io = std.testing.io },
        "ntip0",
        &persistent,
    );
    defer applier.deinit();

    inline for (.{ @as(u64, 10), @as(u64, 11) }) |receiver_id| {
        try control.registerPendingSession(.{
            .receiver_id = receiver_id,
            .peer_receiver_id = receiver_id + 100,
            .owner = 7,
            .tx_key = [_]u8{@intCast(receiver_id)} ** 32,
            .rx_key = [_]u8{@intCast(receiver_id + 1)} ** 32,
            .created_ns = receiver_id,
            .endpoint = .{ .ip4 = .loopback(@intCast(49152 + receiver_id)) },
        }, [_]u8{@intCast(receiver_id + 2)} ** 32, receiver_id);
        try control.confirmAsInitiator(receiver_id, receiver_id);
    }

    try std.testing.expect(applier.selectAuthenticatedSession(10));
    applier.applied_generation = 99;
    applier.applied_hash = [_]u8{0xaa} ** protocol_control.snapshot_hash_len;
    control.makeReceiveOnly(10);
    try std.testing.expect(!applier.selectAuthenticatedSession(10));
    try std.testing.expect(applier.selectAuthenticatedSession(11));
    try std.testing.expectEqual(@as(u64, 0), applier.applied_generation);
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** protocol_control.snapshot_hash_len),
        &applier.applied_hash,
    );
}
