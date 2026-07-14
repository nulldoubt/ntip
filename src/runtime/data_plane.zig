const std = @import("std");
const wire = @import("../protocol/header.zig");
const transport = @import("../protocol/transport.zig");
const replay = @import("../protocol/replay.zig");
const ipv4 = @import("../protocol/ipv4.zig");
const forwarding = @import("forwarding.zig");
const authorization = @import("authorization.zig");
const tables = @import("session_table.zig");
const traffic = @import("traffic.zig");

pub const default_inner_mtu: u16 = 1380;
pub const control_plaintext_limit: usize = 1200;
pub const soft_rekey_packets: u64 = @as(u64, 1) << 32;
pub const hard_expiry_packets: u64 = @as(u64, 1) << 40;
pub const soft_rekey_ns: u64 = 60 * std.time.ns_per_min;
pub const hard_expiry_ns: u64 = 24 * std.time.ns_per_hour;

pub const Session = struct {
    /// Session identifier chosen locally and used for inbound table lookup.
    receiver_id: u64,
    /// Receiver identifier chosen by the peer and emitted on outbound packets.
    peer_receiver_id: u64 = 0,
    owner: u128,
    tx_key: [transport.key_len]u8,
    rx_key: [transport.key_len]u8,
    tx_sequence: u64 = 0,
    rx_replay: replay.Window = .{},
    rx_rekey_signaled: bool = false,
    created_ns: u64,
    confirmed: bool = false,
    /// Pending and current sessions may transmit. A superseded session is
    /// switched to receive-only for the bounded rekey drain interval; it must
    /// never be selected for DATA or explicit CONTROL transmission again.
    tx_enabled: bool = true,
    endpoint: ?std.Io.net.IpAddress = null,
    traffic_tracker: traffic.Tracker = .{},
    reported_traffic_state: traffic.State = .cold,

    pub fn rekeyDue(self: *const Session, now_ns: u64) bool {
        return self.tx_sequence >= soft_rekey_packets or now_ns -| self.created_ns >= soft_rekey_ns;
    }

    pub fn expired(self: *const Session, now_ns: u64) bool {
        return self.tx_sequence >= hard_expiry_packets or now_ns -| self.created_ns >= hard_expiry_ns;
    }

    pub fn wipe(self: *Session) void {
        std.crypto.secureZero(u8, &self.tx_key);
        std.crypto.secureZero(u8, &self.rx_key);
    }
};

pub const Counters = struct {
    tx_packets: u64 = 0,
    tx_bytes: u64 = 0,
    rx_packets: u64 = 0,
    rx_bytes: u64 = 0,
    offline_drops: u64 = 0,
    malformed_drops: u64 = 0,
    authentication_drops: u64 = 0,
    replay_drops: u64 = 0,
    source_policy_drops: u64 = 0,
    destination_policy_drops: u64 = 0,
    mtu_drops: u64 = 0,
    unknown_session_drops: u64 = 0,
    session_expiry_drops: u64 = 0,
};

pub const Outbound = struct {
    datagram: []u8,
    receiver_session_id: u64,
    endpoint: ?std.Io.net.IpAddress,
    rekey_due: bool,
};

pub const InboundPayload = union(enum) {
    data: []u8,
    control: []u8,
};

pub const Inbound = struct {
    receiver_session_id: u64,
    payload: InboundPayload,
    rekey_due: bool,
};

pub const TrafficUpdate = struct {
    receiver_session_id: u64,
    state: traffic.State,
};

pub const DataPlane = struct {
    sessions: tables.SessionTable(Session),
    routes: *forwarding.Snapshot,
    source_policy: *const authorization.Snapshot,
    destination_policy: ?*const authorization.Snapshot,
    destination_policy_owner: u128 = 0,
    /// The Master rejects an authenticated Node packet routed back to that
    /// same Node. A Node must disable this check because its single Master
    /// session owns the VNR route that also contains the Node's local /32.
    reject_same_owner_destination: bool = true,
    inner_mtu: u16 = default_inner_mtu,
    traffic_config: traffic.Config = .{},
    counters: Counters = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        session_capacity: usize,
        routes: *forwarding.Snapshot,
        source_policy: *const authorization.Snapshot,
        destination_policy: ?*const authorization.Snapshot,
    ) !DataPlane {
        return .{
            .sessions = try tables.SessionTable(Session).initWithCleanup(allocator, session_capacity, Session.wipe),
            .routes = routes,
            .source_policy = source_policy,
            .destination_policy = destination_policy,
        };
    }

    pub fn deinit(self: *DataPlane) void {
        self.sessions.deinit();
        self.* = undefined;
    }

    pub fn installSession(self: *DataPlane, new_session: Session) !void {
        var session = new_session;
        defer session.wipe();
        if (session.receiver_id == 0) return error.InvalidSessionId;
        if (session.peer_receiver_id == 0) session.peer_receiver_id = session.receiver_id;
        const activate = session.confirmed;
        // Installation cannot restore a caller-supplied receive-only state.
        // Confirmed test/bootstrap sessions pass through confirmSession so the
        // same-owner retirement invariant is applied in exactly one place.
        session.confirmed = false;
        session.tx_enabled = true;
        session.traffic_tracker.config = self.traffic_config;
        try self.sessions.put(session.receiver_id, session);
        if (activate) try self.confirmSession(session.receiver_id);
    }

    pub fn configureTraffic(self: *DataPlane, config: traffic.Config) void {
        self.traffic_config = config;
        var iterator = self.sessions.iterator();
        while (iterator.next()) |session| session.traffic_tracker.config = config;
    }

    pub fn nextTrafficUpdate(
        self: *DataPlane,
        now_ns: u64,
        queue_occupancy: usize,
        queue_capacity: usize,
        backpressure: bool,
    ) ?TrafficUpdate {
        var iterator = self.sessions.iterator();
        while (iterator.next()) |session| {
            session.traffic_tracker.observeQueue(now_ns, queue_occupancy, queue_capacity, backpressure);
            if (session.traffic_tracker.state == session.reported_traffic_state) continue;
            return .{ .receiver_session_id = session.receiver_id, .state = session.traffic_tracker.state };
        }
        return null;
    }

    pub fn markTrafficReported(self: *DataPlane, update: TrafficUpdate) void {
        const session = self.sessions.get(update.receiver_session_id) orelse return;
        if (session.traffic_tracker.state == update.state) session.reported_traffic_state = update.state;
    }

    pub fn observeBackpressure(self: *DataPlane, receiver_id: u64, now_ns: u64) void {
        const session = self.sessions.get(receiver_id) orelse return;
        session.traffic_tracker.observeQueue(now_ns, 1, 1, true);
    }

    pub fn confirmSession(self: *DataPlane, receiver_id: u64) !void {
        const session = self.sessions.get(receiver_id) orelse return error.UnknownSession;
        // A delayed duplicate SESSION_CONFIRM for an already retired key must
        // not roll transmission back to the old sequence space.
        if (session.confirmed) {
            if (!session.tx_enabled) return error.SessionReceiveOnly;
            return;
        }

        var iterator = self.sessions.iterator();
        while (iterator.next()) |candidate| {
            if (candidate.receiver_id == receiver_id or candidate.owner != session.owner) continue;
            candidate.tx_enabled = false;
        }
        session.confirmed = true;
        session.tx_enabled = true;
        self.rebindOwner(session.owner);
    }

    pub fn updateEndpoint(self: *DataPlane, receiver_id: u64, endpoint: std.Io.net.IpAddress) !void {
        const session = self.sessions.get(receiver_id) orelse return error.UnknownSession;
        session.endpoint = endpoint;
    }

    pub fn removeSession(self: *DataPlane, receiver_id: u64) bool {
        const owner = if (self.sessions.get(receiver_id)) |session| session.owner else return false;
        const removed = self.sessions.remove(receiver_id);
        if (removed) self.rebindOwner(owner);
        return removed;
    }

    /// The data worker calls this only when a one-shot receive-side rekey
    /// event could not enter the bounded control queue. A later authenticated
    /// packet at/above the threshold can then signal again.
    pub fn rearmReceiveRekey(self: *DataPlane, receiver_id: u64) void {
        const session = self.sessions.get(receiver_id) orelse return;
        session.rx_rekey_signaled = false;
    }

    /// Installs a control-plane-built routing/source policy at a data-worker
    /// quiescent point, then attaches its owners to currently confirmed
    /// sessions. No allocation occurs here.
    pub fn replacePolicySnapshots(
        self: *DataPlane,
        routes: *forwarding.Snapshot,
        source_policy: *const authorization.Snapshot,
        destination_policy: *const authorization.Snapshot,
    ) void {
        self.routes = routes;
        self.source_policy = source_policy;
        self.destination_policy = destination_policy;
        for (routes.entries) |entry| self.rebindOwner(entry.owner);
    }

    /// Installs one authenticated Node configuration at a data-worker
    /// quiescent point. The snapshots remain owned by the data worker.
    pub fn replaceClientPolicySnapshots(
        self: *DataPlane,
        routes: *forwarding.Snapshot,
        source_policy: *const authorization.Snapshot,
        destination_policy: *const authorization.Snapshot,
    ) void {
        self.routes = routes;
        self.source_policy = source_policy;
        self.destination_policy = destination_policy;
        for (routes.entries) |entry| self.rebindOwner(entry.owner);
    }

    pub fn encryptControl(
        self: *DataPlane,
        receiver_id: u64,
        frame: []const u8,
        now_ns: u64,
        allow_unconfirmed: bool,
        output: []u8,
    ) !Outbound {
        if (frame.len == 0 or frame.len > control_plaintext_limit) return error.ControlFrameTooLarge;
        const session = self.sessions.get(receiver_id) orelse return error.UnknownSession;
        if (!session.tx_enabled) return error.SessionReceiveOnly;
        if (!session.confirmed and !allow_unconfirmed) return error.SessionUnconfirmed;
        if (session.expired(now_ns)) return error.SessionExpired;
        if (session.endpoint == null) return error.EndpointUnavailable;
        const header: wire.Header = .{
            .packet_type = .control,
            .context = session.peer_receiver_id,
            .sequence = session.tx_sequence,
        };
        const datagram = try transport.seal(header, frame, session.tx_key, output);
        session.tx_sequence += 1;
        self.counters.tx_packets +|= 1;
        self.counters.tx_bytes +|= datagram.len;
        return .{
            .datagram = datagram,
            .receiver_session_id = session.receiver_id,
            .endpoint = session.endpoint,
            .rekey_due = session.rekeyDue(now_ns),
        };
    }

    /// TUN -> route lookup -> AEAD -> UDP. No allocation or global lock occurs.
    pub fn encryptData(self: *DataPlane, inner_packet: []const u8, now_ns: u64, output: []u8) !Outbound {
        if (inner_packet.len > self.inner_mtu) {
            self.counters.mtu_drops +|= 1;
            return error.InnerPacketExceedsMtu;
        }
        const packet = ipv4.Packet.parse(inner_packet) catch {
            self.counters.malformed_drops +|= 1;
            return error.MalformedInnerPacket;
        };
        const destination = std.mem.readInt(u32, &packet.destination, .big);
        const route = self.routes.lookup(destination) orelse {
            self.counters.offline_drops +|= 1;
            return error.NoRoute;
        };
        const session = self.sessions.get(route.receiver_session_id) orelse {
            self.counters.offline_drops +|= 1;
            return error.DestinationOffline;
        };
        if (!session.tx_enabled) {
            self.counters.offline_drops +|= 1;
            return error.SessionReceiveOnly;
        }
        if (!session.confirmed) {
            self.counters.offline_drops +|= 1;
            return error.SessionUnconfirmed;
        }
        if (session.endpoint == null) {
            self.counters.offline_drops +|= 1;
            return error.EndpointUnavailable;
        }
        if (session.expired(now_ns)) return error.SessionExpired;

        const header: wire.Header = .{
            .packet_type = .data,
            .context = session.peer_receiver_id,
            .sequence = session.tx_sequence,
        };
        const datagram = try transport.seal(header, inner_packet, session.tx_key, output);
        session.tx_sequence += 1;
        session.traffic_tracker.observeData(now_ns, inner_packet.len);
        self.counters.tx_packets +|= 1;
        self.counters.tx_bytes +|= datagram.len;
        return .{
            .datagram = datagram,
            .receiver_session_id = session.receiver_id,
            .endpoint = session.endpoint,
            .rekey_due = session.rekeyDue(now_ns),
        };
    }

    /// UDP -> session lookup -> AEAD/replay -> policy -> TUN/control queue.
    /// Failed authentication cannot advance the replay window.
    pub fn decryptTransport(self: *DataPlane, datagram: []const u8, now_ns: u64, plaintext: []u8) !Inbound {
        if (datagram.len < transport.overhead) {
            self.counters.malformed_drops +|= 1;
            return error.MalformedDatagram;
        }
        const header = wire.Header.decode(datagram[0..wire.encoded_len]) catch {
            self.counters.malformed_drops +|= 1;
            return error.MalformedDatagram;
        };
        const session = self.sessions.get(header.context) orelse {
            self.counters.unknown_session_drops +|= 1;
            return error.UnknownSession;
        };
        if (header.sequence >= hard_expiry_packets or session.expired(now_ns)) {
            self.counters.session_expiry_drops +|= 1;
            return error.SessionExpired;
        }
        const opened = transport.open(datagram, session.rx_key, &session.rx_replay, plaintext) catch |err| {
            switch (err) {
                error.Duplicate, error.TooOld => self.counters.replay_drops +|= 1,
                error.AuthenticationFailed => self.counters.authentication_drops +|= 1,
                else => self.counters.malformed_drops +|= 1,
            }
            return err;
        };
        switch (opened.header.packet_type) {
            .data => {
                // CONTROL must remain available for SESSION_CONFIRM, but an
                // unconfirmed session is never permitted to inject DATA.
                if (!session.confirmed) {
                    self.counters.offline_drops +|= 1;
                    return error.SessionUnconfirmed;
                }
                if (opened.plaintext.len > self.inner_mtu) {
                    self.counters.mtu_drops +|= 1;
                    return error.InnerPacketExceedsMtu;
                }
                const packet = ipv4.Packet.parse(opened.plaintext) catch {
                    self.counters.malformed_drops +|= 1;
                    return error.MalformedInnerPacket;
                };
                const source = std.mem.readInt(u32, &packet.source, .big);
                if (!self.source_policy.permits(session.owner, source)) {
                    self.counters.source_policy_drops +|= 1;
                    return error.SourceNotAuthorized;
                }
                if (self.destination_policy) |policy| {
                    const destination = std.mem.readInt(u32, &packet.destination, .big);
                    if (!policy.permits(self.destination_policy_owner, destination)) {
                        self.counters.destination_policy_drops +|= 1;
                        return error.DestinationNotAuthorized;
                    }
                    if (self.reject_same_owner_destination) {
                        if (self.routes.lookup(destination)) |route| {
                            if (route.owner == session.owner) {
                                self.counters.destination_policy_drops +|= 1;
                                return error.DestinationReflection;
                            }
                        }
                    }
                }
                self.counters.rx_packets +|= 1;
                self.counters.rx_bytes +|= datagram.len;
                session.traffic_tracker.observeData(now_ns, opened.plaintext.len);
                return .{
                    .receiver_session_id = session.receiver_id,
                    .payload = .{ .data = opened.plaintext },
                    .rekey_due = noteReceiveRekey(session, opened.header.sequence, now_ns),
                };
            },
            .control => {
                if (opened.plaintext.len > control_plaintext_limit) return error.ControlFrameTooLarge;
                self.counters.rx_packets +|= 1;
                self.counters.rx_bytes +|= datagram.len;
                return .{
                    .receiver_session_id = session.receiver_id,
                    .payload = .{ .control = opened.plaintext },
                    .rekey_due = noteReceiveRekey(session, opened.header.sequence, now_ns),
                };
            },
            else => unreachable,
        }
    }

    fn rebindOwner(self: *DataPlane, owner: u128) void {
        var selected_receiver_id: u64 = 0;
        var selected_created_ns: u64 = 0;
        var iterator = self.sessions.iterator();
        while (iterator.next()) |session| {
            if (!session.confirmed or !session.tx_enabled or session.owner != owner) continue;
            if (selected_receiver_id == 0 or session.created_ns > selected_created_ns or
                (session.created_ns == selected_created_ns and session.receiver_id > selected_receiver_id))
            {
                selected_receiver_id = session.receiver_id;
                selected_created_ns = session.created_ns;
            }
        }
        self.routes.bindOwner(owner, selected_receiver_id);
    }
};

fn noteReceiveRekey(session: *Session, sequence: u64, now_ns: u64) bool {
    if (session.rx_rekey_signaled) return false;
    if (sequence < soft_rekey_packets and now_ns -| session.created_ns < soft_rekey_ns) return false;
    session.rx_rekey_signaled = true;
    return true;
}

test "data plane encrypts, authenticates, validates, and rejects replay" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a010002, .prefix_len = 32, .owner = 7, .receiver_session_id = 22 },
    });
    defer routes.deinit();
    var policy = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 7, .network = 0x0a010001, .prefix_len = 32 },
    });
    defer policy.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &policy, null);
    defer plane.deinit();
    const key = [_]u8{0x42} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 22,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 0,
        .confirmed = true,
        .endpoint = .{ .ip4 = .loopback(49152) },
    });

    const packet = [_]u8{
        0x45, 0, 0, 20, 0,  0, 0x40, 0, 64, 17, 0, 0,
        10,   1, 0, 1,  10, 1, 0,    2,
    };
    var datagram_buffer: [2048]u8 = undefined;
    const outbound = try plane.encryptData(&packet, 1, &datagram_buffer);
    var plaintext: [2048]u8 = undefined;
    const inbound = try plane.decryptTransport(outbound.datagram, 1, &plaintext);
    try std.testing.expectEqualSlices(u8, &packet, inbound.payload.data);
    try std.testing.expectError(error.Duplicate, plane.decryptTransport(outbound.datagram, 1, &plaintext));
}

test "data plane rejects spoofed source after authentication" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a010002, .prefix_len = 32, .owner = 7, .receiver_session_id = 22 },
    });
    defer routes.deinit();
    var policy = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 7, .network = 0x0a010001, .prefix_len = 32 },
    });
    defer policy.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &policy, null);
    defer plane.deinit();
    const key = [_]u8{0x24} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 22,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 0,
        .confirmed = true,
        .endpoint = .{ .ip4 = .loopback(49152) },
    });
    const spoofed = [_]u8{
        0x45, 0, 0, 20, 0,  0, 0x40, 0, 64, 17, 0, 0,
        10,   1, 0, 9,  10, 1, 0,    2,
    };
    var datagram: [2048]u8 = undefined;
    const sealed = try transport.seal(.{ .packet_type = .data, .context = 22, .sequence = 99 }, &spoofed, key, &datagram);
    var plaintext: [2048]u8 = undefined;
    try std.testing.expectError(error.SourceNotAuthorized, plane.decryptTransport(sealed, 1, &plaintext));
}

test "Master destination policy prevents authenticated lateral injection and reflection" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a010002, .prefix_len = 32, .owner = 7, .receiver_session_id = 22 },
        .{ .network = 0x0a010003, .prefix_len = 32, .owner = 8, .receiver_session_id = 23 },
    });
    defer routes.deinit();
    var sources = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 7, .network = 0x0a010002, .prefix_len = 32 },
    });
    defer sources.deinit();
    var destinations = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 0, .network = 0x0a010001, .prefix_len = 32 },
        .{ .owner = 0, .network = 0x0a010002, .prefix_len = 32 },
        .{ .owner = 0, .network = 0x0a010003, .prefix_len = 32 },
    });
    defer destinations.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &sources, &destinations);
    defer plane.deinit();
    plane.destination_policy_owner = 0;
    const key = [_]u8{0x29} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 22,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 0,
        .confirmed = true,
    });

    var packet = [_]u8{
        0x45, 0, 0, 20, 0,   0,  0x40, 0, 64, 17, 0, 0,
        10,   1, 0, 2,  172, 16, 0,    1,
    };
    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var sealed = try transport.seal(.{ .packet_type = .data, .context = 22, .sequence = 1 }, &packet, key, &datagram);
    try std.testing.expectError(error.DestinationNotAuthorized, plane.decryptTransport(sealed, 1, &plaintext));

    packet[16..20].* = .{ 10, 1, 0, 2 };
    sealed = try transport.seal(.{ .packet_type = .data, .context = 22, .sequence = 2 }, &packet, key, &datagram);
    try std.testing.expectError(error.DestinationReflection, plane.decryptTransport(sealed, 1, &plaintext));

    packet[16..20].* = .{ 10, 1, 0, 3 };
    sealed = try transport.seal(.{ .packet_type = .data, .context = 22, .sequence = 3 }, &packet, key, &datagram);
    const forwarded = try plane.decryptTransport(sealed, 1, &plaintext);
    try std.testing.expectEqualSlices(u8, &packet, forwarded.payload.data);
}

test "Node accepts its local address inside the Master-owned VNR route" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a010000, .prefix_len = 24, .owner = 7, .receiver_session_id = 22 },
    });
    defer routes.deinit();
    var sources = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 7, .network = 0, .prefix_len = 0 },
    });
    defer sources.deinit();
    var destinations = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 2, .network = 0x0a010002, .prefix_len = 32 },
    });
    defer destinations.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &sources, &destinations);
    defer plane.deinit();
    plane.destination_policy_owner = 2;
    plane.reject_same_owner_destination = false;
    const key = [_]u8{0x2a} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 22,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 0,
        .confirmed = true,
    });

    const packet = [_]u8{
        0x45, 0, 0, 20, 0,  0, 0x40, 0, 64, 17, 0, 0,
        10,   1, 0, 1,  10, 1, 0,    2,
    };
    var datagram: [256]u8 = undefined;
    const sealed = try transport.seal(.{
        .packet_type = .data,
        .context = 22,
        .sequence = 1,
    }, &packet, key, &datagram);
    var plaintext: [256]u8 = undefined;
    const incoming = try plane.decryptTransport(sealed, 1, &plaintext);
    try std.testing.expectEqualSlices(u8, &packet, incoming.payload.data);
}

test "replacement is transmit-current while old session drains receive-only" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a010002, .prefix_len = 32, .owner = 7 },
    });
    defer routes.deinit();
    var policy = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 7, .network = 0x0a010002, .prefix_len = 32 },
    });
    defer policy.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &policy, null);
    defer plane.deinit();
    const key = [_]u8{0x33} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 10,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 1,
        .confirmed = true,
        .endpoint = .{ .ip4 = .loopback(5000) },
    });
    try std.testing.expectEqual(@as(u64, 10), routes.lookup(0x0a010002).?.receiver_session_id);

    const packet = [_]u8{
        0x45, 0, 0, 20, 0,  0, 0x40, 0, 64, 17, 0, 0,
        10,   1, 0, 1,  10, 1, 0,    2,
    };
    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var outbound = try plane.encryptData(&packet, 2, &datagram);
    try std.testing.expectEqual(@as(u64, 10), outbound.receiver_session_id);

    try plane.installSession(.{
        .receiver_id = 11,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 2,
        .endpoint = .{ .ip4 = .loopback(5001) },
    });
    try std.testing.expectEqual(@as(u64, 10), routes.lookup(0x0a010002).?.receiver_session_id);
    try plane.confirmSession(11);
    try std.testing.expectEqual(@as(u64, 11), routes.lookup(0x0a010002).?.receiver_session_id);
    try std.testing.expect(!plane.sessions.get(10).?.tx_enabled);
    try std.testing.expect(plane.sessions.get(10).?.confirmed);
    try std.testing.expect(plane.sessions.get(11).?.tx_enabled);

    outbound = try plane.encryptData(&packet, 3, &datagram);
    try std.testing.expectEqual(@as(u64, 11), outbound.receiver_session_id);
    try std.testing.expectError(error.SessionReceiveOnly, plane.encryptControl(10, "old heartbeat", 3, false, &datagram));
    try std.testing.expectError(error.SessionReceiveOnly, plane.confirmSession(10));

    // The superseded receive key remains usable until the coordinator's
    // 30-second drain deadline removes it.
    const old_control = try transport.seal(.{
        .packet_type = .control,
        .context = 10,
        .sequence = 0,
    }, "draining", key, &datagram);
    const inbound = try plane.decryptTransport(old_control, 3, &plaintext);
    try std.testing.expectEqual(@as(u64, 10), inbound.receiver_session_id);
    try std.testing.expectEqualStrings("draining", inbound.payload.control);

    var delayed_packet = packet;
    delayed_packet[12..16].* = .{ 10, 1, 0, 2 };
    delayed_packet[16..20].* = .{ 10, 1, 0, 1 };
    const old_data = try transport.seal(.{
        .packet_type = .data,
        .context = 10,
        .sequence = 1,
    }, &delayed_packet, key, &datagram);
    const delayed = try plane.decryptTransport(old_data, 3, &plaintext);
    try std.testing.expectEqual(@as(u64, 10), delayed.receiver_session_id);
    try std.testing.expectEqualSlices(u8, &delayed_packet, delayed.payload.data);

    try std.testing.expect(plane.removeSession(11));
    // Removing the replacement cannot reactivate an old sequence space.
    try std.testing.expectEqual(@as(u64, 0), routes.lookup(0x0a010002).?.receiver_session_id);

    var replacement = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0xc0a8b200, .prefix_len = 24, .owner = 7 },
    });
    defer replacement.deinit();
    var destinations = try authorization.Snapshot.init(std.testing.allocator, &.{});
    defer destinations.deinit();
    plane.replacePolicySnapshots(&replacement, &policy, &destinations);
    try std.testing.expectEqual(@as(u64, 0), replacement.lookup(0xc0a8b22a).?.receiver_session_id);
}

test "unconfirmed session may authenticate control but never data" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a010002, .prefix_len = 32, .owner = 7, .receiver_session_id = 22 },
    });
    defer routes.deinit();
    var policy = try authorization.Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 7, .network = 0x0a010001, .prefix_len = 32 },
    });
    defer policy.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &policy, null);
    defer plane.deinit();
    const key = [_]u8{0x55} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 22,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 0,
    });
    const packet = [_]u8{
        0x45, 0, 0, 20, 0,  0, 0x40, 0, 64, 17, 0, 0,
        10,   1, 0, 1,  10, 1, 0,    2,
    };
    var datagram: [2048]u8 = undefined;
    const sealed_data = try transport.seal(.{ .packet_type = .data, .context = 22, .sequence = 1 }, &packet, key, &datagram);
    var plaintext: [2048]u8 = undefined;
    try std.testing.expectError(error.SessionUnconfirmed, plane.decryptTransport(sealed_data, 1, &plaintext));

    const sealed_control = try transport.seal(.{ .packet_type = .control, .context = 22, .sequence = 2 }, "confirm", key, &datagram);
    const incoming = try plane.decryptTransport(sealed_control, 1, &plaintext);
    try std.testing.expectEqualStrings("confirm", incoming.payload.control);
}

test "receive sequence thresholds signal rekey once and hard-expire before authentication" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{});
    defer routes.deinit();
    var policy = try authorization.Snapshot.init(std.testing.allocator, &.{});
    defer policy.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &policy, null);
    defer plane.deinit();
    const key = [_]u8{0x67} ** transport.key_len;
    try plane.installSession(.{
        .receiver_id = 44,
        .owner = 7,
        .tx_key = key,
        .rx_key = key,
        .created_ns = 0,
        .confirmed = true,
        .endpoint = .{ .ip4 = .loopback(49152) },
    });

    var datagram: [256]u8 = undefined;
    var plaintext: [256]u8 = undefined;
    var sealed = try transport.seal(.{
        .packet_type = .control,
        .context = 44,
        .sequence = soft_rekey_packets - 1,
    }, "before-soft", key, &datagram);
    var inbound = try plane.decryptTransport(sealed, 1, &plaintext);
    try std.testing.expect(!inbound.rekey_due);

    sealed = try transport.seal(.{
        .packet_type = .control,
        .context = 44,
        .sequence = soft_rekey_packets,
    }, "forged-soft", key, &datagram);
    datagram[sealed.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, plane.decryptTransport(datagram[0..sealed.len], 1, &plaintext));
    const session = plane.sessions.get(44).?;
    try std.testing.expect(!session.rx_rekey_signaled);
    try std.testing.expectEqual(soft_rekey_packets - 1, session.rx_replay.highest);

    sealed = try transport.seal(.{
        .packet_type = .control,
        .context = 44,
        .sequence = soft_rekey_packets,
    }, "at-soft", key, &datagram);
    inbound = try plane.decryptTransport(sealed, 1, &plaintext);
    try std.testing.expect(inbound.rekey_due);
    try std.testing.expect(session.rx_rekey_signaled);

    sealed = try transport.seal(.{
        .packet_type = .control,
        .context = 44,
        .sequence = soft_rekey_packets + 1,
    }, "after-soft", key, &datagram);
    inbound = try plane.decryptTransport(sealed, 1, &plaintext);
    try std.testing.expect(!inbound.rekey_due);

    plane.rearmReceiveRekey(44);
    sealed = try transport.seal(.{
        .packet_type = .control,
        .context = 44,
        .sequence = soft_rekey_packets + 2,
    }, "rearmed-soft", key, &datagram);
    inbound = try plane.decryptTransport(sealed, 1, &plaintext);
    try std.testing.expect(inbound.rekey_due);

    sealed = try transport.seal(.{
        .packet_type = .control,
        .context = 44,
        .sequence = hard_expiry_packets,
    }, "at-hard", key, &datagram);
    try std.testing.expectError(error.SessionExpired, plane.decryptTransport(sealed, 1, &plaintext));
    try std.testing.expectEqual(soft_rekey_packets + 2, session.rx_replay.highest);
    try std.testing.expectEqual(@as(u64, 1), plane.counters.session_expiry_drops);
}

test "data-plane session removal securely wipes directional keys" {
    var routes = try forwarding.Snapshot.init(std.testing.allocator, &.{});
    defer routes.deinit();
    var policy = try authorization.Snapshot.init(std.testing.allocator, &.{});
    defer policy.deinit();
    var plane = try DataPlane.init(std.testing.allocator, 8, &routes, &policy, null);
    defer plane.deinit();
    try plane.installSession(.{
        .receiver_id = 55,
        .owner = 7,
        .tx_key = [_]u8{0xaa} ** transport.key_len,
        .rx_key = [_]u8{0xbb} ** transport.key_len,
        .created_ns = 0,
    });
    const removed_storage = plane.sessions.get(55).?;
    try std.testing.expect(plane.removeSession(55));
    try std.testing.expectEqual([_]u8{0} ** transport.key_len, removed_storage.tx_key);
    try std.testing.expectEqual([_]u8{0} ** transport.key_len, removed_storage.rx_key);
}
