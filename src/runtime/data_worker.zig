const std = @import("std");
const builtin = @import("builtin");
const tun_mod = @import("../platform/linux/tun.zig");
const udp_mod = @import("../platform/linux/udp.zig");
const lifecycle = @import("../platform/linux/lifecycle.zig");
const queues = @import("bounded_queue.zig");
const buffers = @import("buffer_pool.zig");
const icmp = @import("icmp.zig");
const connectivity = @import("connectivity.zig");
const plane_mod = @import("data_plane.zig");
const topology = @import("topology.zig");
const wire = @import("../protocol/header.zig");
const traffic = @import("traffic.zig");

pub const ControlEventKind = enum {
    handshake_datagram,
    control_frame,
    endpoint_observed,
    outbound_authenticated,
    rekey_due,
    snapshot_installed,
    client_snapshot_installed,
    runtime_settings_applied,
    traffic_state_changed,
    session_command_failed,
};

pub const ControlEvent = struct {
    kind: ControlEventKind,
    receiver_session_id: u64,
    endpoint: ?std.Io.net.IpAddress = null,
    length: u16 = 0,
    bytes: [plane_mod.control_plaintext_limit]u8 = undefined,
    snapshot_generation: u64 = 0,
    retired_snapshot: ?*topology.MasterSnapshots = null,
    retired_client_snapshot: ?*topology.ClientSnapshots = null,
    traffic_state: traffic.State = .cold,

    pub fn control(session_id: u64, endpoint: std.Io.net.IpAddress, frame_bytes: []const u8) ControlEvent {
        std.debug.assert(frame_bytes.len <= plane_mod.control_plaintext_limit);
        var event: ControlEvent = .{
            .kind = .control_frame,
            .receiver_session_id = session_id,
            .endpoint = endpoint,
            .length = @intCast(frame_bytes.len),
        };
        @memcpy(event.bytes[0..frame_bytes.len], frame_bytes);
        return event;
    }

    pub fn handshake(endpoint: std.Io.net.IpAddress, datagram: []const u8) ControlEvent {
        std.debug.assert(datagram.len <= plane_mod.control_plaintext_limit);
        var event: ControlEvent = .{
            .kind = .handshake_datagram,
            .receiver_session_id = 0,
            .endpoint = endpoint,
            .length = @intCast(datagram.len),
        };
        @memcpy(event.bytes[0..datagram.len], datagram);
        return event;
    }

    pub fn frame(self: *const ControlEvent) []const u8 {
        return self.bytes[0..self.length];
    }
};

pub const ControlQueue = queues.SpscQueue(ControlEvent);

/// Master forwarding and live-settings barriers share a dedicated bounded
/// hand-off in their original DATA-command order. Ordinary observations or
/// handshake datagrams can therefore never head-of-line block the barrier that
/// releases the serialized operator worker's next mutation reservation.
pub const RuntimeBarrierAcknowledgement = union(enum) {
    master_snapshot: struct {
        generation: u64,
        retired: ?*topology.MasterSnapshots,
    },
    runtime_settings: u64,
};

pub const RuntimeBarrierAcknowledgementQueue = queues.SpscQueue(RuntimeBarrierAcknowledgement);

pub const DataCommandKind = enum {
    send_datagram,
    send_control,
    install_session,
    confirm_session,
    update_endpoint,
    remove_session,
    install_master_snapshot,
    install_client_snapshot,
    apply_runtime_settings,
};

pub const DataCommand = struct {
    kind: DataCommandKind,
    receiver_session_id: u64 = 0,
    endpoint: ?std.Io.net.IpAddress = null,
    allow_unconfirmed: bool = false,
    length: u16 = 0,
    bytes: [buffers.packet_capacity]u8 = undefined,
    session: plane_mod.Session = undefined,
    snapshot_generation: u64 = 0,
    master_snapshot: ?*topology.MasterSnapshots = null,
    client_snapshot: ?*topology.ClientSnapshots = null,
    traffic_config: traffic.Config = .{},
    inner_mtu: u16 = plane_mod.default_inner_mtu,

    pub fn datagram(endpoint: std.Io.net.IpAddress, bytes: []const u8) DataCommand {
        std.debug.assert(bytes.len <= buffers.packet_capacity);
        var command: DataCommand = .{ .kind = .send_datagram, .endpoint = endpoint, .length = @intCast(bytes.len) };
        @memcpy(command.bytes[0..bytes.len], bytes);
        return command;
    }

    pub fn control(receiver_session_id: u64, endpoint: ?std.Io.net.IpAddress, frame: []const u8, allow_unconfirmed: bool) DataCommand {
        std.debug.assert(frame.len <= plane_mod.control_plaintext_limit);
        var command: DataCommand = .{
            .kind = .send_control,
            .receiver_session_id = receiver_session_id,
            .endpoint = endpoint,
            .allow_unconfirmed = allow_unconfirmed,
            .length = @intCast(frame.len),
        };
        @memcpy(command.bytes[0..frame.len], frame);
        return command;
    }

    pub fn payload(self: *const DataCommand) []const u8 {
        return self.bytes[0..self.length];
    }

    pub fn installMasterSnapshot(snapshot: *topology.MasterSnapshots, generation: u64) DataCommand {
        return .{
            .kind = .install_master_snapshot,
            .snapshot_generation = generation,
            .master_snapshot = snapshot,
        };
    }

    pub fn installClientSnapshot(
        snapshot: *topology.ClientSnapshots,
        generation: u64,
        traffic_config: traffic.Config,
        inner_mtu: u16,
    ) DataCommand {
        return .{
            .kind = .install_client_snapshot,
            .snapshot_generation = generation,
            .client_snapshot = snapshot,
            .traffic_config = traffic_config,
            .inner_mtu = inner_mtu,
        };
    }

    pub fn applyRuntimeSettings(
        sequence: u64,
        traffic_config: traffic.Config,
        inner_mtu: u16,
    ) DataCommand {
        return .{
            .kind = .apply_runtime_settings,
            .snapshot_generation = sequence,
            .traffic_config = traffic_config,
            .inner_mtu = inner_mtu,
        };
    }
};

pub const CommandQueue = queues.SpscQueue(DataCommand);
/// Dedicated high-priority queue for session revocation. Values are only
/// receiver IDs, so the queue can be sized for every preallocated session
/// without reserving hundreds of megabytes of full DataCommand storage.
pub const RetirementQueue = queues.SpscQueue(u64);

/// Receiver tombstones bridge the independent priority and command queues.
/// A retirement may overtake an already-queued install; the tombstone makes
/// that install a no-op until the ordinary queue reaches a quiescent point.
const RetirementFences = struct {
    allocator: std.mem.Allocator,
    receiver_ids: []u64,
    count: usize = 0,
    overflow: bool = false,

    fn init(allocator: std.mem.Allocator, capacity: usize) !RetirementFences {
        return .{ .allocator = allocator, .receiver_ids = try allocator.alloc(u64, capacity) };
    }

    fn deinit(self: *RetirementFences) void {
        self.allocator.free(self.receiver_ids);
        self.* = undefined;
    }

    fn note(self: *RetirementFences, receiver_session_id: u64) void {
        if (self.blocksExact(receiver_session_id)) return;
        if (self.count == self.receiver_ids.len) {
            // Fail closed if the capacity invariant is ever violated: all
            // pending installs are suppressed until the command queue drains.
            self.overflow = true;
            return;
        }
        self.receiver_ids[self.count] = receiver_session_id;
        self.count += 1;
    }

    fn blocks(self: *const RetirementFences, receiver_session_id: u64) bool {
        return self.overflow or self.blocksExact(receiver_session_id);
    }

    fn clear(self: *RetirementFences) void {
        @memset(self.receiver_ids[0..self.count], 0);
        self.count = 0;
        self.overflow = false;
    }

    fn blocksExact(self: *const RetirementFences, receiver_session_id: u64) bool {
        for (self.receiver_ids[0..self.count]) |candidate| {
            if (candidate == receiver_session_id) return true;
        }
        return false;
    }
};

pub const WorkerCounters = struct {
    control_queue_drops: u64 = 0,
    tun_io_errors: u64 = 0,
    udp_io_errors: u64 = 0,
    icmp_synthesized: u64 = 0,
    connectivity_started: u64 = 0,
    connectivity_completed: u64 = 0,
    connectivity_failed: u64 = 0,
};

/// Linux epoll worker that exclusively owns TUN, UDP, sessions, replay state,
/// sequence numbers, forwarding snapshots, and reusable packet buffers.
pub const DataWorker = struct {
    io: std.Io,
    tun: *tun_mod.Device,
    udp: *udp_mod.DualStack,
    plane: *plane_mod.DataPlane,
    control_queue: *ControlQueue,
    command_queue: *CommandQueue,
    retirement_queue: *RetirementQueue,
    connectivity_channel: ?*connectivity.Channel = null,
    runtime_barrier_acknowledgements: ?*RuntimeBarrierAcknowledgementQueue = null,
    retirement_fences: RetirementFences,
    epoll_fd: i32,
    wake_fd: i32,
    counters: WorkerCounters = .{},
    command_queue_drops: std.atomic.Value(u64) = .init(0),
    owned_master_snapshot: ?*topology.MasterSnapshots = null,
    owned_client_snapshot: ?*topology.ClientSnapshots = null,
    pending_snapshot_ack: ?ControlEvent = null,
    last_queue_drops: u64 = 0,
    tun_buffer: [buffers.packet_capacity]u8 = undefined,
    datagram_buffer: [buffers.packet_capacity]u8 = undefined,
    plaintext_buffer: [buffers.packet_capacity]u8 = undefined,
    icmp_buffer: [buffers.packet_capacity]u8 = undefined,

    pub fn init(
        io: std.Io,
        tun: *tun_mod.Device,
        udp: *udp_mod.DualStack,
        plane: *plane_mod.DataPlane,
        control_queue: *ControlQueue,
        command_queue: *CommandQueue,
        retirement_queue: *RetirementQueue,
    ) !DataWorker {
        if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
        const linux = std.os.linux;
        const result = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            else => return error.EpollCreateFailed,
        }
        const epoll_fd: i32 = @intCast(result);
        errdefer _ = std.os.linux.close(epoll_fd);
        const wake_result = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        switch (linux.errno(wake_result)) {
            .SUCCESS => {},
            else => return error.EventFdCreateFailed,
        }
        const wake_fd: i32 = @intCast(wake_result);
        errdefer _ = linux.close(wake_fd);
        var retirement_fences = try RetirementFences.init(retirement_queue.allocator, retirement_queue.capacity());
        errdefer retirement_fences.deinit();
        try addToEpoll(epoll_fd, tun.fd);
        try addToEpoll(epoll_fd, udp.ipv4.handle);
        try addToEpoll(epoll_fd, udp.ipv6.handle);
        try addToEpoll(epoll_fd, wake_fd);
        return .{
            .io = io,
            .tun = tun,
            .udp = udp,
            .plane = plane,
            .control_queue = control_queue,
            .command_queue = command_queue,
            .retirement_queue = retirement_queue,
            .retirement_fences = retirement_fences,
            .epoll_fd = epoll_fd,
            .wake_fd = wake_fd,
        };
    }

    pub fn deinit(self: *DataWorker) void {
        self.reclaimQueuedSnapshots();
        if (self.pending_snapshot_ack) |ack| {
            if (ack.retired_snapshot) |retired| retired.destroy();
            if (ack.retired_client_snapshot) |retired| retired.destroy();
        }
        if (self.owned_master_snapshot) |snapshot| snapshot.destroy();
        if (self.owned_client_snapshot) |snapshot| snapshot.destroy();
        self.retirement_fences.deinit();
        if (comptime builtin.os.tag == .linux) _ = std.os.linux.close(self.epoll_fd);
        if (comptime builtin.os.tag == .linux) _ = std.os.linux.close(self.wake_fd);
        self.* = undefined;
    }

    pub fn submit(self: *DataWorker, command: DataCommand) bool {
        if (!self.command_queue.push(command)) {
            _ = self.command_queue_drops.fetchAdd(1, .monotonic);
            return false;
        }
        if (comptime builtin.os.tag == .linux) {
            const wake: u64 = 1;
            _ = std.os.linux.write(self.wake_fd, @ptrCast(&wake), @sizeOf(u64));
        }
        return true;
    }

    /// Session removal must not compete with configuration and control-frame
    /// traffic. The queue is sized to the session table, and each control peer
    /// submits at most one retirement before relinquishing its peer state.
    pub fn submitRetirement(self: *DataWorker, receiver_session_id: u64) bool {
        if (receiver_session_id == 0) return true;
        if (!self.retirement_queue.push(receiver_session_id)) return false;
        if (comptime builtin.os.tag == .linux) {
            const wake: u64 = 1;
            _ = std.os.linux.write(self.wake_fd, @ptrCast(&wake), @sizeOf(u64));
        }
        return true;
    }

    /// Attaches the Master-only connectivity channel before the DATA thread
    /// starts. Nodes leave this unset and retain their existing packet path.
    pub fn attachConnectivityChannel(self: *DataWorker, channel: *connectivity.Channel) !void {
        if (self.connectivity_channel != null) return error.ConnectivityChannelAlreadyAttached;
        self.connectivity_channel = channel;
    }

    /// Attaches the Master-only acknowledgement queue before the DATA thread
    /// starts. Node runtimes and tests that do not attach it retain the legacy
    /// shared-control-queue path for client/settings acknowledgements.
    pub fn attachRuntimeBarrierAcknowledgements(
        self: *DataWorker,
        acknowledgements: *RuntimeBarrierAcknowledgementQueue,
    ) !void {
        if (self.runtime_barrier_acknowledgements != null) {
            return error.RuntimeBarrierAcknowledgementsAlreadyAttached;
        }
        self.runtime_barrier_acknowledgements = acknowledgements;
    }

    /// Control-side non-blocking admission seam. A successful return reserves
    /// a terminal completion; a false return means the request was not
    /// admitted and no DATA-path work will occur.
    pub fn submitConnectivity(self: *DataWorker, request: connectivity.Request) bool {
        const channel = self.connectivity_channel orelse return false;
        if (!channel.submit(request)) return false;
        if (comptime builtin.os.tag == .linux) {
            const wake: u64 = 1;
            _ = std.os.linux.write(self.wake_fd, @ptrCast(&wake), @sizeOf(u64));
        }
        return true;
    }

    pub fn nextConnectivityCompletion(self: *DataWorker) ?connectivity.Completion {
        const channel = self.connectivity_channel orelse return null;
        return channel.nextCompletion();
    }

    /// Transfers initial snapshot ownership to the data worker before its
    /// thread starts. The DataPlane must already reference this snapshot.
    pub fn adoptMasterSnapshot(self: *DataWorker, snapshot: *topology.MasterSnapshots) !void {
        if (self.owned_master_snapshot != null) return error.SnapshotAlreadyOwned;
        self.owned_master_snapshot = snapshot;
        self.plane.destination_policy_owner = topology.masterDestinationOwner();
        self.plane.replacePolicySnapshots(&snapshot.forwarding, &snapshot.sources, &snapshot.destinations);
    }

    pub fn adoptClientSnapshot(self: *DataWorker, snapshot: *topology.ClientSnapshots) !void {
        if (self.owned_client_snapshot != null) return error.SnapshotAlreadyOwned;
        self.owned_client_snapshot = snapshot;
        self.plane.replaceClientPolicySnapshots(
            &snapshot.forwarding,
            &snapshot.sources,
            &snapshot.destinations,
        );
    }

    pub fn run(self: *DataWorker) !void {
        if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
        defer {
            if (self.connectivity_channel) |channel| {
                _ = channel.interruptAll(monotonicNow(self.io));
            }
        }
        const linux = std.os.linux;
        var events: [16]linux.epoll_event = undefined;
        while (!lifecycle.shouldStop()) {
            self.flushSnapshotAck();
            self.processRetirements();
            self.processCommands();
            self.processConnectivity();
            self.expireConnectivity(monotonicNow(self.io));
            self.reportTraffic();
            const count_result = linux.epoll_wait(self.epoll_fd, &events, events.len, 1000);
            switch (linux.errno(count_result)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.EpollWaitFailed,
            }
            const count: usize = @intCast(count_result);
            for (events[0..count]) |event| {
                const fd = event.data.fd;
                if (fd == self.tun.fd) {
                    self.handleTun();
                } else if (fd == self.udp.ipv4.handle) {
                    self.handleUdp(.ipv4);
                } else if (fd == self.udp.ipv6.handle) {
                    self.handleUdp(.ipv6);
                } else if (fd == self.wake_fd) {
                    self.handleWake();
                }
            }
        }
    }

    fn handleTun(self: *DataWorker) void {
        // Apply accepted liveness/revocation decisions before selecting a
        // session for any newly readable inner packet.
        self.processRetirements();
        const length = self.tun.read(self.io, &self.tun_buffer) catch {
            self.counters.tun_io_errors +|= 1;
            return;
        };
        if (length == 0) return;
        const now_ns = monotonicNow(self.io);
        const outbound = self.plane.encryptData(self.tun_buffer[0..length], now_ns, &self.datagram_buffer) catch |err| {
            if (err == error.InnerPacketExceedsMtu) self.synthesizeFragmentationNeeded(self.tun_buffer[0..length]);
            return;
        };
        const endpoint = outbound.endpoint orelse return;
        self.udp.send(&endpoint, outbound.datagram) catch |err| {
            self.plane.observeBackpressure(outbound.receiver_session_id, monotonicNow(self.io));
            if (err == error.MessageOversize) {
                self.synthesizeFragmentationNeeded(self.tun_buffer[0..length]);
            } else {
                self.counters.udp_io_errors +|= 1;
            }
            return;
        };
        _ = self.pushEvent(.{
            .kind = .outbound_authenticated,
            .receiver_session_id = outbound.receiver_session_id,
        });
        if (outbound.rekey_due) _ = self.pushEvent(.{
            .kind = .rekey_due,
            .receiver_session_id = outbound.receiver_session_id,
        });
    }

    const UnderlayFamily = enum { ipv4, ipv6 };

    fn handleUdp(self: *DataWorker, family: UnderlayFamily) void {
        self.processRetirements();
        const incoming = switch (family) {
            .ipv4 => self.udp.receiveIpv4(&self.datagram_buffer),
            .ipv6 => self.udp.receiveIpv6(&self.datagram_buffer),
        } catch {
            self.counters.udp_io_errors +|= 1;
            return;
        };
        if (incoming.data.len >= wire.encoded_len) {
            if (wire.Header.decode(incoming.data[0..wire.encoded_len])) |header| {
                switch (header.packet_type) {
                    .enrollment_handshake, .session_handshake, .stateless_retry => {
                        if (incoming.data.len <= plane_mod.control_plaintext_limit) {
                            _ = self.pushEvent(ControlEvent.handshake(incoming.from, incoming.data));
                        }
                        return;
                    },
                    else => {},
                }
            } else |_| {}
        }
        const result = self.plane.decryptTransport(incoming.data, monotonicNow(self.io), &self.plaintext_buffer) catch return;
        _ = self.pushEvent(.{
            .kind = .endpoint_observed,
            .receiver_session_id = result.receiver_session_id,
            .endpoint = incoming.from,
        });
        if (result.rekey_due) {
            if (!self.pushEvent(.{
                .kind = .rekey_due,
                .receiver_session_id = result.receiver_session_id,
            })) self.plane.rearmReceiveRekey(result.receiver_session_id);
        }
        switch (result.payload) {
            .data => |packet| {
                if (self.connectivity_channel) |channel| {
                    if (channel.matchReply(packet, monotonicNow(self.io))) {
                        self.counters.connectivity_completed +|= 1;
                        return;
                    }
                }
                self.tun.write(self.io, packet) catch {
                    self.counters.tun_io_errors +|= 1;
                };
            },
            .control => |frame| _ = self.pushEvent(ControlEvent.control(result.receiver_session_id, incoming.from, frame)),
        }
    }

    fn synthesizeFragmentationNeeded(self: *DataWorker, original: []const u8) void {
        const packet = icmp.fragmentationNeeded(&self.icmp_buffer, original, self.plane.inner_mtu) catch return;
        self.tun.write(self.io, packet) catch {
            self.counters.tun_io_errors +|= 1;
            return;
        };
        self.counters.icmp_synthesized +|= 1;
    }

    fn pushEvent(self: *DataWorker, event: ControlEvent) bool {
        if (!self.control_queue.push(event)) {
            self.counters.control_queue_drops +|= 1;
            return false;
        }
        return true;
    }

    fn handleWake(self: *DataWorker) void {
        if (comptime builtin.os.tag != .linux) return;
        var value: u64 = 0;
        _ = std.os.linux.read(self.wake_fd, @ptrCast(&value), @sizeOf(u64));
        self.processRetirements();
        self.processCommands();
        self.processConnectivity();
    }

    fn processConnectivity(self: *DataWorker) void {
        const channel = self.connectivity_channel orelse return;
        while (channel.nextRequest()) |request| {
            const now_ns = monotonicNow(self.io);
            const pending = channel.begin(request, now_ns) catch {
                channel.fail(request, now_ns, .packet_rejected);
                self.counters.connectivity_failed +|= 1;
                continue;
            };
            const packet = pending.buildRequest(&self.icmp_buffer, request.ipv4_id) catch {
                channel.failPending(request.check_id, now_ns, .packet_rejected);
                self.counters.connectivity_failed +|= 1;
                continue;
            };
            const outbound = self.plane.encryptData(packet, now_ns, &self.datagram_buffer) catch |err| {
                channel.failPending(request.check_id, now_ns, connectivityFailure(err));
                self.counters.connectivity_failed +|= 1;
                continue;
            };
            const endpoint = outbound.endpoint orelse {
                channel.failPending(request.check_id, now_ns, .node_offline);
                self.counters.connectivity_failed +|= 1;
                continue;
            };
            self.udp.send(&endpoint, outbound.datagram) catch {
                self.plane.observeBackpressure(outbound.receiver_session_id, monotonicNow(self.io));
                channel.failPending(request.check_id, monotonicNow(self.io), .transport_unavailable);
                self.counters.udp_io_errors +|= 1;
                self.counters.connectivity_failed +|= 1;
                continue;
            };
            self.counters.connectivity_started +|= 1;
            _ = self.pushEvent(.{
                .kind = .outbound_authenticated,
                .receiver_session_id = outbound.receiver_session_id,
            });
            if (outbound.rekey_due) _ = self.pushEvent(.{
                .kind = .rekey_due,
                .receiver_session_id = outbound.receiver_session_id,
            });
        }
    }

    fn expireConnectivity(self: *DataWorker, now_ns: u64) void {
        const channel = self.connectivity_channel orelse return;
        self.counters.connectivity_completed +|= channel.expire(now_ns);
    }

    fn processRetirements(self: *DataWorker) void {
        while (self.retirement_queue.pop()) |receiver_session_id| {
            self.retirement_fences.note(receiver_session_id);
            _ = self.plane.removeSession(receiver_session_id);
        }
    }

    fn processCommands(self: *DataWorker) void {
        defer if (self.command_queue.occupancy() == 0) self.retirement_fences.clear();
        self.flushSnapshotAck();
        if (self.pending_snapshot_ack != null) return;
        while (self.command_queue.popSecure()) |raw_command| {
            if (!self.processCommand(raw_command)) return;
        }
    }

    fn processCommand(self: *DataWorker, raw_command: DataCommand) bool {
        var command = raw_command;
        defer if (command.kind == .install_session) command.session.wipe();

        switch (command.kind) {
            .send_datagram => {
                const endpoint = command.endpoint orelse return true;
                self.udp.send(&endpoint, command.payload()) catch {
                    self.counters.udp_io_errors +|= 1;
                };
            },
            .send_control => {
                const outbound = self.plane.encryptControl(
                    command.receiver_session_id,
                    command.payload(),
                    monotonicNow(self.io),
                    command.allow_unconfirmed,
                    &self.datagram_buffer,
                ) catch return true;
                const endpoint = command.endpoint orelse outbound.endpoint orelse return true;
                self.udp.send(&endpoint, outbound.datagram) catch {
                    self.plane.observeBackpressure(outbound.receiver_session_id, monotonicNow(self.io));
                    self.counters.udp_io_errors +|= 1;
                    return true;
                };
                _ = self.pushEvent(.{
                    .kind = .outbound_authenticated,
                    .receiver_session_id = outbound.receiver_session_id,
                });
            },
            .install_session => {
                if (self.retirement_fences.blocks(command.session.receiver_id)) {
                    _ = self.pushEvent(.{
                        .kind = .session_command_failed,
                        .receiver_session_id = command.session.receiver_id,
                    });
                    return true;
                }
                self.plane.installSession(command.session) catch {
                    _ = self.pushEvent(.{
                        .kind = .session_command_failed,
                        .receiver_session_id = command.session.receiver_id,
                    });
                };
            },
            .confirm_session => self.plane.confirmSession(command.receiver_session_id) catch {
                _ = self.pushEvent(.{
                    .kind = .session_command_failed,
                    .receiver_session_id = command.receiver_session_id,
                });
            },
            .update_endpoint => {
                const endpoint = command.endpoint orelse return true;
                self.plane.updateEndpoint(command.receiver_session_id, endpoint) catch {};
            },
            .remove_session => _ = self.plane.removeSession(command.receiver_session_id),
            .install_master_snapshot => {
                const snapshot = command.master_snapshot orelse return true;
                const retired = self.owned_master_snapshot;
                self.plane.destination_policy_owner = topology.masterDestinationOwner();
                self.plane.replacePolicySnapshots(&snapshot.forwarding, &snapshot.sources, &snapshot.destinations);
                self.owned_master_snapshot = snapshot;
                self.pending_snapshot_ack = .{
                    .kind = .snapshot_installed,
                    .receiver_session_id = 0,
                    .snapshot_generation = command.snapshot_generation,
                    .retired_snapshot = retired,
                };
                self.flushSnapshotAck();
                // Never install a second snapshot until the first retirement
                // acknowledgment has entered the bounded control queue.
                if (self.pending_snapshot_ack != null) return false;
            },
            .install_client_snapshot => {
                const snapshot = command.client_snapshot orelse return true;
                const retired = self.owned_client_snapshot;
                self.plane.replaceClientPolicySnapshots(
                    &snapshot.forwarding,
                    &snapshot.sources,
                    &snapshot.destinations,
                );
                self.plane.configureTraffic(command.traffic_config);
                self.plane.inner_mtu = command.inner_mtu;
                self.owned_client_snapshot = snapshot;
                self.pending_snapshot_ack = .{
                    .kind = .client_snapshot_installed,
                    .receiver_session_id = 0,
                    .snapshot_generation = command.snapshot_generation,
                    .retired_client_snapshot = retired,
                };
                self.flushSnapshotAck();
                if (self.pending_snapshot_ack != null) return false;
            },
            .apply_runtime_settings => {
                // This is the DATA worker's acknowledgement point. The
                // control-side settings applier does not mark the durable
                // revision effective until this event is observed.
                self.plane.configureTraffic(command.traffic_config);
                self.plane.inner_mtu = command.inner_mtu;
                self.pending_snapshot_ack = .{
                    .kind = .runtime_settings_applied,
                    .receiver_session_id = 0,
                    .snapshot_generation = command.snapshot_generation,
                };
                self.flushSnapshotAck();
                if (self.pending_snapshot_ack != null) return false;
            },
        }
        return true;
    }

    fn flushSnapshotAck(self: *DataWorker) void {
        const event = self.pending_snapshot_ack orelse return;
        if (self.runtime_barrier_acknowledgements) |acknowledgements| {
            switch (event.kind) {
                .snapshot_installed => {
                    if (acknowledgements.push(.{ .master_snapshot = .{
                        .generation = event.snapshot_generation,
                        .retired = event.retired_snapshot,
                    } })) self.pending_snapshot_ack = null;
                    return;
                },
                .runtime_settings_applied => {
                    if (acknowledgements.push(.{
                        .runtime_settings = event.snapshot_generation,
                    })) self.pending_snapshot_ack = null;
                    return;
                },
                else => {},
            }
        }
        if (self.control_queue.push(event)) self.pending_snapshot_ack = null;
    }

    fn reportTraffic(self: *DataWorker) void {
        const drops = self.counters.control_queue_drops +|
            self.command_queue_drops.load(.monotonic);
        const backpressure = drops != self.last_queue_drops;
        self.last_queue_drops = drops;
        const occupancy = self.control_queue.occupancy() + self.command_queue.occupancy();
        const capacity = self.control_queue.capacity() + self.command_queue.capacity();
        const now_ns = monotonicNow(self.io);
        while (self.plane.nextTrafficUpdate(now_ns, occupancy, capacity, backpressure)) |update| {
            if (!self.pushEvent(.{
                .kind = .traffic_state_changed,
                .receiver_session_id = update.receiver_session_id,
                .traffic_state = update.state,
            })) break;
            self.plane.markTrafficReported(update);
        }
    }

    /// Called only after the data thread has joined. Snapshot commands that
    /// were accepted just before shutdown still carry ownership and must not
    /// be abandoned in the ring.
    fn reclaimQueuedSnapshots(self: *DataWorker) void {
        while (self.command_queue.popSecure()) |raw_command| {
            var command = raw_command;
            defer if (command.kind == .install_session) command.session.wipe();
            if (command.kind == .install_master_snapshot) {
                if (command.master_snapshot) |snapshot| snapshot.destroy();
            } else if (command.kind == .install_client_snapshot) {
                if (command.client_snapshot) |snapshot| snapshot.destroy();
            }
        }
    }
};

fn connectivityFailure(err: anyerror) connectivity.Failure {
    return switch (err) {
        error.NoRoute => .route_unavailable,
        error.DestinationOffline,
        error.SessionReceiveOnly,
        error.SessionUnconfirmed,
        error.EndpointUnavailable,
        error.SessionExpired,
        => .node_offline,
        else => .packet_rejected,
    };
}

fn addToEpoll(epoll_fd: i32, watched_fd: i32) !void {
    const linux = std.os.linux;
    var event: linux.epoll_event = .{
        .events = linux.EPOLL.IN | linux.EPOLL.ERR | linux.EPOLL.HUP,
        .data = .{ .fd = watched_fd },
    };
    switch (linux.errno(linux.epoll_ctl(epoll_fd, linux.EPOLL.CTL_ADD, watched_fd, &event))) {
        .SUCCESS => {},
        else => return error.EpollAddFailed,
    }
}

fn monotonicNow(io: std.Io) u64 {
    const raw = std.Io.Clock.now(.awake, io).nanoseconds;
    return if (raw <= 0) 0 else @intCast(@min(raw, std.math.maxInt(u64)));
}

test "control events copy bounded frames" {
    const endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(49152) };
    const event = ControlEvent.control(7, endpoint, "heartbeat");
    try std.testing.expectEqualStrings("heartbeat", event.frame());
}

test "retirement fences suppress overtaken installs and fail closed on overflow" {
    var fences = try RetirementFences.init(std.testing.allocator, 2);
    defer fences.deinit();
    fences.note(11);
    fences.note(11);
    try std.testing.expect(fences.blocks(11));
    try std.testing.expect(!fences.blocks(12));
    try std.testing.expectEqual(@as(usize, 1), fences.count);

    fences.note(12);
    fences.note(13);
    try std.testing.expect(fences.overflow);
    try std.testing.expect(fences.blocks(99));
    fences.clear();
    try std.testing.expect(!fences.blocks(11));
    try std.testing.expect(!fences.blocks(99));
}

test "runtime settings acknowledgement is retained under control queue pressure" {
    const forwarding_mod = @import("forwarding.zig");
    const authorization_mod = @import("authorization.zig");
    var routes = try forwarding_mod.Snapshot.init(std.testing.allocator, &.{});
    defer routes.deinit();
    var sources = try authorization_mod.Snapshot.init(std.testing.allocator, &.{});
    defer sources.deinit();
    var plane = try plane_mod.DataPlane.init(std.testing.allocator, 2, &routes, &sources, null);
    defer plane.deinit();
    var events = try ControlQueue.init(std.testing.allocator, 2);
    defer events.deinit();
    try std.testing.expect(events.push(.{ .kind = .traffic_state_changed, .receiver_session_id = 1 }));
    try std.testing.expect(events.push(.{ .kind = .traffic_state_changed, .receiver_session_id = 2 }));

    var worker: DataWorker = undefined;
    worker.plane = &plane;
    worker.control_queue = &events;
    worker.runtime_barrier_acknowledgements = null;
    worker.pending_snapshot_ack = null;
    const desired: traffic.Config = .{
        .cold_after_ns = 7 * std.time.ns_per_s,
        .hot_pps = 1234,
        .hot_bits_per_second = 9_876_543,
        .saturated_queue_percent = 73,
        .hysteresis_ns = 9 * std.time.ns_per_s,
    };
    try std.testing.expect(!worker.processCommand(DataCommand.applyRuntimeSettings(42, desired, 1420)));
    try std.testing.expectEqual(@as(u16, 1420), plane.inner_mtu);
    try std.testing.expectEqual(desired, plane.traffic_config);
    try std.testing.expect(worker.pending_snapshot_ack != null);

    _ = events.pop();
    _ = events.pop();
    worker.flushSnapshotAck();
    const acknowledgement = events.pop().?;
    try std.testing.expectEqual(ControlEventKind.runtime_settings_applied, acknowledgement.kind);
    try std.testing.expectEqual(@as(u64, 42), acknowledgement.snapshot_generation);
    try std.testing.expect(worker.pending_snapshot_ack == null);
}

test "Master runtime barriers bypass a saturated control queue in command order" {
    var events = try ControlQueue.init(std.testing.allocator, 2);
    defer events.deinit();
    try std.testing.expect(events.push(.{ .kind = .traffic_state_changed, .receiver_session_id = 1 }));
    try std.testing.expect(events.push(.{ .kind = .traffic_state_changed, .receiver_session_id = 2 }));

    var acknowledgements = try RuntimeBarrierAcknowledgementQueue.init(std.testing.allocator, 2);
    defer acknowledgements.deinit();
    var worker: DataWorker = undefined;
    worker.control_queue = &events;
    worker.runtime_barrier_acknowledgements = &acknowledgements;
    worker.pending_snapshot_ack = .{
        .kind = .runtime_settings_applied,
        .receiver_session_id = 0,
        .snapshot_generation = 72,
    };
    worker.flushSnapshotAck();
    worker.pending_snapshot_ack = .{
        .kind = .snapshot_installed,
        .receiver_session_id = 0,
        .snapshot_generation = 73,
    };

    worker.flushSnapshotAck();
    try std.testing.expect(worker.pending_snapshot_ack == null);
    try std.testing.expectEqual(@as(usize, 2), events.occupancy());
    try std.testing.expectEqual(
        @as(u64, 72),
        acknowledgements.pop().?.runtime_settings,
    );
    const snapshot = acknowledgements.pop().?.master_snapshot;
    try std.testing.expectEqual(@as(u64, 73), snapshot.generation);
    try std.testing.expect(snapshot.retired == null);
}
