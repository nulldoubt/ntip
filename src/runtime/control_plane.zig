const std = @import("std");
const control = @import("../protocol/control.zig");
const endpoint_protocol = @import("../protocol/endpoint.zig");
const handshake = @import("../protocol/handshake.zig");
const worker_mod = @import("data_worker.zig");
const plane_mod = @import("data_plane.zig");
const topology = @import("topology.zig");
const traffic = @import("traffic.zig");

pub const heartbeat_idle_ns: u64 = 15 * std.time.ns_per_s;
pub const suspect_after_ns: u64 = 30 * std.time.ns_per_s;
pub const offline_after_ns: u64 = 45 * std.time.ns_per_s;

pub const PeerState = enum {
    awaiting_confirmation,
    online,
    suspect,
    rekey_required,
    offline,
};

pub const Peer = struct {
    receiver_session_id: u64,
    expected_handshake_hash: [32]u8,
    validator: endpoint_protocol.Validator,
    state: PeerState = .awaiting_confirmation,
    last_rx_ns: u64,
    last_tx_ns: u64,
    authenticated_rx_ns: ?u64 = null,
    authenticated_tx_ns: ?u64 = null,
    next_request_id: u32 = 1,
    traffic_state: traffic.State = .cold,
    /// Cleared as soon as a same-owner replacement becomes current. The peer
    /// remains installed only so authenticated packets can drain until the
    /// coordinator removes its receive key.
    transmit_enabled: bool = true,
    candidate_endpoint: ?std.Io.net.IpAddress = null,
    next_path_challenge_ns: u64 = 0,
    removal_queued: bool = false,
};

pub const CommandSink = struct {
    context: *anyopaque,
    submit_fn: *const fn (*anyopaque, worker_mod.DataCommand) bool,
    retire_fn: ?*const fn (*anyopaque, u64) bool = null,

    pub fn submit(self: CommandSink, command: worker_mod.DataCommand) bool {
        return self.submit_fn(self.context, command);
    }

    pub fn retire(self: CommandSink, receiver_session_id: u64) bool {
        if (self.retire_fn) |retire_fn| return retire_fn(self.context, receiver_session_id);
        return self.submit(.{ .kind = .remove_session, .receiver_session_id = receiver_session_id });
    }

    pub fn fromWorker(worker: *worker_mod.DataWorker) CommandSink {
        return .{ .context = worker, .submit_fn = submitToWorker, .retire_fn = retireFromWorker };
    }

    fn submitToWorker(context: *anyopaque, command: worker_mod.DataCommand) bool {
        const worker: *worker_mod.DataWorker = @ptrCast(@alignCast(context));
        return worker.submit(command);
    }

    fn retireFromWorker(context: *anyopaque, receiver_session_id: u64) bool {
        const worker: *worker_mod.DataWorker = @ptrCast(@alignCast(context));
        return worker.submitRetirement(receiver_session_id);
    }
};

pub const HandshakeSink = struct {
    context: *anyopaque,
    receive_fn: *const fn (*anyopaque, std.Io.net.IpAddress, []const u8, u64) void,

    pub fn receive(self: HandshakeSink, endpoint: std.Io.net.IpAddress, datagram: []const u8, now_ns: u64) void {
        self.receive_fn(self.context, endpoint, datagram, now_ns);
    }
};

/// Notification hook for bounded handshake coordinators. On the responder it
/// runs after a valid encrypted SESSION_CONFIRM has been queued for activation.
/// On the initiator it runs after the first authenticated completion/heartbeat
/// response, allowing retransmission state to be retired safely.
pub const SessionObserver = struct {
    context: *anyopaque,
    confirmed_fn: *const fn (*anyopaque, u64, u64) void,

    pub fn confirmed(self: SessionObserver, receiver_session_id: u64, now_ns: u64) void {
        self.confirmed_fn(self.context, receiver_session_id, now_ns);
    }
};

/// Fired only for a fully authenticated ENROLLMENT_COMPLETE frame with the
/// exact 16-byte Node UUID payload.
pub const EnrollmentCompleteObserver = struct {
    context: *anyopaque,
    complete_fn: *const fn (*anyopaque, u64, [16]u8, u64) void,

    pub fn complete(self: EnrollmentCompleteObserver, receiver_session_id: u64, node_uuid: [16]u8, now_ns: u64) void {
        self.complete_fn(self.context, receiver_session_id, node_uuid, now_ns);
    }
};

/// Synchronous hook for authenticated configuration frames. Implementations
/// must copy payload bytes if they need to retain them after the callback.
pub const ConfigurationObserver = struct {
    context: *anyopaque,
    receive_fn: *const fn (*anyopaque, u64, control.Type, u32, u64, []const u8, u64) void,

    pub fn receive(
        self: ConfigurationObserver,
        receiver_session_id: u64,
        frame_type: control.Type,
        request_id: u32,
        generation: u64,
        payload: []const u8,
        now_ns: u64,
    ) void {
        self.receive_fn(self.context, receiver_session_id, frame_type, request_id, generation, payload, now_ns);
    }
};

/// Acknowledges that the data worker has installed a policy generation. The
/// retired snapshot is exclusively owned by the callback and must be freed.
pub const SnapshotObserver = struct {
    context: *anyopaque,
    installed_fn: *const fn (*anyopaque, u64, ?*topology.MasterSnapshots) void,

    pub fn installed(self: SnapshotObserver, generation: u64, retired: ?*topology.MasterSnapshots) void {
        self.installed_fn(self.context, generation, retired);
    }
};

pub const ClientSnapshotObserver = struct {
    context: *anyopaque,
    installed_fn: *const fn (*anyopaque, u64, ?*topology.ClientSnapshots) void,

    pub fn installed(self: ClientSnapshotObserver, generation: u64, retired: ?*topology.ClientSnapshots) void {
        self.installed_fn(self.context, generation, retired);
    }
};

/// Acknowledges that the DATA worker has installed one live operational
/// settings revision. The serialized operator worker uses this as the final
/// runtime barrier before advancing the durable effective revision.
pub const RuntimeSettingsObserver = struct {
    context: *anyopaque,
    applied_fn: *const fn (*anyopaque, u64) void,

    pub fn applied(self: RuntimeSettingsObserver, sequence: u64) void {
        self.applied_fn(self.context, sequence);
    }
};

pub const ControlPlane = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    events: *worker_mod.ControlQueue,
    commands: CommandSink,
    handshake_sink: ?HandshakeSink = null,
    session_observer: ?SessionObserver = null,
    enrollment_complete_observer: ?EnrollmentCompleteObserver = null,
    configuration_observer: ?ConfigurationObserver = null,
    snapshot_observer: ?SnapshotObserver = null,
    client_snapshot_observer: ?ClientSnapshotObserver = null,
    runtime_settings_observer: ?RuntimeSettingsObserver = null,
    peers: std.ArrayList(Peer) = .empty,
    heartbeat_interval_ns: u64 = heartbeat_idle_ns,
    suspect_interval_ns: u64 = suspect_after_ns,
    offline_interval_ns: u64 = offline_after_ns,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        events: *worker_mod.ControlQueue,
        commands: CommandSink,
    ) ControlPlane {
        return .{ .allocator = allocator, .io = io, .events = events, .commands = commands };
    }

    pub fn deinit(self: *ControlPlane) void {
        // The data thread has already stopped in the service teardown order.
        // Drain any queued retirement acknowledgements so their heap-owned
        // snapshots cannot be stranded in the SPSC ring.
        while (self.events.pop()) |event| {
            if (event.kind == .snapshot_installed) self.onSnapshotInstalled(event);
            if (event.kind == .client_snapshot_installed) self.onClientSnapshotInstalled(event);
        }
        self.peers.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn setHandshakeSink(self: *ControlPlane, sink: ?HandshakeSink) void {
        self.handshake_sink = sink;
    }

    pub fn setSessionObserver(self: *ControlPlane, observer: ?SessionObserver) void {
        self.session_observer = observer;
    }

    pub fn setEnrollmentCompleteObserver(self: *ControlPlane, observer: ?EnrollmentCompleteObserver) void {
        self.enrollment_complete_observer = observer;
    }

    pub fn setConfigurationObserver(self: *ControlPlane, observer: ?ConfigurationObserver) void {
        self.configuration_observer = observer;
    }

    pub fn setSnapshotObserver(self: *ControlPlane, observer: ?SnapshotObserver) void {
        self.snapshot_observer = observer;
    }

    pub fn setClientSnapshotObserver(self: *ControlPlane, observer: ?ClientSnapshotObserver) void {
        self.client_snapshot_observer = observer;
    }

    pub fn setRuntimeSettingsObserver(self: *ControlPlane, observer: ?RuntimeSettingsObserver) void {
        self.runtime_settings_observer = observer;
    }

    /// Delivers a dedicated DATA barrier acknowledgement without routing it
    /// behind lossy/coalescible runtime observations in the general queue.
    pub fn runtimeSettingsApplied(self: *ControlPlane, sequence: u64) void {
        if (self.runtime_settings_observer) |observer| observer.applied(sequence);
    }

    pub fn registerPendingSession(
        self: *ControlPlane,
        session: plane_mod.Session,
        handshake_hash: [32]u8,
        now_ns: u64,
    ) !void {
        const initial_endpoint = session.endpoint orelse return error.EndpointUnavailable;
        if (self.findPeer(session.receiver_id) != null) return error.SessionAlreadyExists;
        try self.peers.ensureUnusedCapacity(self.allocator, 1);
        var validator: endpoint_protocol.Validator = .{};
        validator.setInitial(toProtocolEndpoint(initial_endpoint));
        var command: worker_mod.DataCommand = .{ .kind = .install_session, .session = session };
        command.session.confirmed = false;
        if (!self.commands.submit(command)) return error.CommandQueueFull;
        self.peers.appendAssumeCapacity(.{
            .receiver_session_id = session.receiver_id,
            .expected_handshake_hash = handshake_hash,
            .validator = validator,
            .last_rx_ns = now_ns,
            .last_tx_ns = now_ns,
        });
    }

    /// Node-side finalization: queue SESSION_CONFIRM using the freshly split
    /// keys, then enable local data transmission. The Master enables its TX
    /// side only after receiving and validating this frame.
    pub fn confirmAsInitiator(self: *ControlPlane, receiver_session_id: u64, now_ns: u64) !void {
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        const payload = (handshake.SessionConfirm{ .handshake_hash = peer.expected_handshake_hash }).encode();
        try self.sendFrame(peer, .session_confirm, &payload, null, true, now_ns);
        if (!self.commands.submit(.{ .kind = .confirm_session, .receiver_session_id = receiver_session_id })) {
            return error.CommandQueueFull;
        }
        peer.state = .online;
    }

    pub fn sendEnrollmentComplete(self: *ControlPlane, receiver_session_id: u64, node_uuid: [16]u8, now_ns: u64) !void {
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        try self.sendFrame(peer, .enrollment_complete, &node_uuid, null, false, now_ns);
    }

    pub fn sendHeartbeatNow(self: *ControlPlane, receiver_session_id: u64, now_ns: u64) !void {
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        var timestamp: [8]u8 = undefined;
        std.mem.writeInt(u64, &timestamp, now_ns, .big);
        try self.sendFrame(peer, .heartbeat, &timestamp, null, false, now_ns);
    }

    pub fn sendConfigurationFrame(
        self: *ControlPlane,
        receiver_session_id: u64,
        frame_type: control.Type,
        payload: []const u8,
        generation: u64,
        now_ns: u64,
    ) !void {
        _ = try self.sendConfigurationRequest(receiver_session_id, frame_type, payload, generation, now_ns);
    }

    /// Sends a configuration request and returns the stable correlation ID
    /// that an acknowledgement must echo.
    pub fn sendConfigurationRequest(
        self: *ControlPlane,
        receiver_session_id: u64,
        frame_type: control.Type,
        payload: []const u8,
        generation: u64,
        now_ns: u64,
    ) !u32 {
        switch (frame_type) {
            .configuration_begin, .configuration_chunk, .configuration_ack => {},
            else => return error.InvalidConfigurationFrameType,
        }
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        return self.sendFrameGenerationRequest(peer, frame_type, payload, generation, null, false, now_ns);
    }

    /// Reserves a consecutive logical request-ID range. Zero is skipped on
    /// wrap, and callers may retransmit the corresponding frames with fresh
    /// transport sequences without changing these IDs.
    pub fn reserveRequestIds(self: *ControlPlane, receiver_session_id: u64, count: u32) !u32 {
        if (count == 0 or count > 65_536) return error.InvalidRequestIdCount;
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        if (!peer.transmit_enabled) return error.SessionReceiveOnly;
        const first = peer.next_request_id;
        peer.next_request_id = requestIdAt(first, count);
        return first;
    }

    pub fn sendConfigurationFrameWithRequestId(
        self: *ControlPlane,
        receiver_session_id: u64,
        frame_type: control.Type,
        request_id: u32,
        payload: []const u8,
        generation: u64,
        now_ns: u64,
    ) !void {
        switch (frame_type) {
            .configuration_begin, .configuration_chunk => {},
            else => return error.InvalidConfigurationFrameType,
        }
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        try self.sendFrameGenerationWithRequestId(peer, frame_type, request_id, payload, generation, null, false, now_ns);
    }

    /// Emits a correlated configuration response without consuming a new
    /// local request ID. Transport encryption still uses a fresh sequence.
    pub fn sendConfigurationResponse(
        self: *ControlPlane,
        receiver_session_id: u64,
        frame_type: control.Type,
        request_id: u32,
        payload: []const u8,
        generation: u64,
        now_ns: u64,
    ) !void {
        if (frame_type != .configuration_ack) return error.InvalidConfigurationFrameType;
        const peer = self.findPeer(receiver_session_id) orelse return error.UnknownSession;
        try self.sendFrameGenerationWithRequestId(peer, frame_type, request_id, payload, generation, null, false, now_ns);
    }

    /// Removes timed-out, unconfirmed handshake state from both workers.
    pub fn abortSession(self: *ControlPlane, receiver_session_id: u64) !void {
        const index = self.findPeerIndex(receiver_session_id) orelse return error.UnknownSession;
        const peer = &self.peers.items[index];
        peer.transmit_enabled = false;
        if (!peer.removal_queued) {
            if (!self.commands.retire(receiver_session_id)) return error.CommandQueueFull;
            peer.removal_queued = true;
        }
        _ = self.peers.orderedRemove(index);
    }

    /// Immediately retires every control-plane transmit path for a superseded
    /// session while preserving its receive state for the bounded key drain.
    /// This is idempotent and deliberately has no inverse: a delayed duplicate
    /// confirmation can never reactivate an old sequence space.
    pub fn makeReceiveOnly(self: *ControlPlane, receiver_session_id: u64) void {
        const peer = self.findPeer(receiver_session_id) orelse return;
        peer.transmit_enabled = false;
        peer.validator.candidate = null;
        peer.candidate_endpoint = null;
        peer.next_path_challenge_ns = 0;
    }

    pub fn poll(self: *ControlPlane, now_ns: u64) void {
        while (self.pollOneEvent(now_ns)) {}
        self.pollTimers(now_ns);
    }

    /// Processes at most one bounded DATA-to-control event. The Master
    /// operator loop uses this seam to stop immediately after an event commits
    /// a new runtime projection; Nodes continue to use `poll`.
    pub fn pollOneEvent(self: *ControlPlane, now_ns: u64) bool {
        const event = self.events.pop() orelse return false;
        self.onEvent(event, now_ns);
        return true;
    }

    pub fn pollTimers(self: *ControlPlane, now_ns: u64) void {
        self.tick(now_ns);
    }

    pub fn peerState(self: *ControlPlane, receiver_session_id: u64) ?PeerState {
        const peer = self.findPeer(receiver_session_id) orelse return null;
        return peer.state;
    }

    pub fn peerEndpoint(self: *ControlPlane, receiver_session_id: u64) ?endpoint_protocol.Endpoint {
        const peer = self.findPeer(receiver_session_id) orelse return null;
        return peer.validator.current;
    }

    pub fn peerTrafficState(self: *ControlPlane, receiver_session_id: u64) ?traffic.State {
        const peer = self.findPeer(receiver_session_id) orelse return null;
        return peer.traffic_state;
    }

    pub const PeerActivity = struct {
        authenticated_rx_ns: ?u64,
        authenticated_tx_ns: ?u64,
    };

    pub fn peerActivity(self: *ControlPlane, receiver_session_id: u64) ?PeerActivity {
        const peer = self.findPeer(receiver_session_id) orelse return null;
        return .{
            .authenticated_rx_ns = peer.authenticated_rx_ns,
            .authenticated_tx_ns = peer.authenticated_tx_ns,
        };
    }

    pub fn peerTransmitEnabled(self: *ControlPlane, receiver_session_id: u64) ?bool {
        const peer = self.findPeer(receiver_session_id) orelse return null;
        return peer.transmit_enabled;
    }

    pub fn configureLiveness(self: *ControlPlane, heartbeat_seconds: u16, suspect_seconds: u16, offline_seconds: u16) !void {
        if (heartbeat_seconds == 0 or heartbeat_seconds >= suspect_seconds or suspect_seconds >= offline_seconds) {
            return error.InvalidLivenessTiming;
        }
        self.heartbeat_interval_ns = @as(u64, heartbeat_seconds) * std.time.ns_per_s;
        self.suspect_interval_ns = @as(u64, suspect_seconds) * std.time.ns_per_s;
        self.offline_interval_ns = @as(u64, offline_seconds) * std.time.ns_per_s;
    }

    pub fn hasPeer(self: *ControlPlane, receiver_session_id: u64) bool {
        return self.findPeer(receiver_session_id) != null;
    }

    fn onEvent(self: *ControlPlane, event: worker_mod.ControlEvent, now_ns: u64) void {
        switch (event.kind) {
            .handshake_datagram => {
                const sink = self.handshake_sink orelse return;
                sink.receive(event.endpoint orelse return, event.frame(), now_ns);
            },
            .endpoint_observed => {
                const peer = self.findPeer(event.receiver_session_id) orelse return;
                if (!peer.transmit_enabled) return;
                peer.last_rx_ns = now_ns;
                peer.authenticated_rx_ns = now_ns;
                if (peer.state == .suspect) peer.state = .online;
                self.observeEndpoint(peer, event.endpoint orelse return, now_ns);
            },
            .outbound_authenticated => {
                const peer = self.findPeer(event.receiver_session_id) orelse return;
                peer.last_tx_ns = now_ns;
                peer.authenticated_tx_ns = now_ns;
            },
            .control_frame => {
                const peer = self.findPeer(event.receiver_session_id) orelse return;
                if (!peer.transmit_enabled) return;
                peer.last_rx_ns = now_ns;
                peer.authenticated_rx_ns = now_ns;
                self.handleControl(peer, event.endpoint orelse return, event.frame(), now_ns);
            },
            .rekey_due => {
                const peer = self.findPeer(event.receiver_session_id) orelse return;
                if (!peer.transmit_enabled) return;
                peer.state = .rekey_required;
                self.sendFrame(peer, .rotate_key, "", null, false, now_ns) catch {};
            },
            .snapshot_installed => self.onSnapshotInstalled(event),
            .client_snapshot_installed => self.onClientSnapshotInstalled(event),
            .runtime_settings_applied => self.runtimeSettingsApplied(event.snapshot_generation),
            .traffic_state_changed => {
                const peer = self.findPeer(event.receiver_session_id) orelse return;
                peer.traffic_state = event.traffic_state;
            },
            .session_command_failed => {
                const index = self.findPeerIndex(event.receiver_session_id) orelse return;
                _ = self.peers.orderedRemove(index);
            },
        }
    }

    fn onSnapshotInstalled(self: *ControlPlane, event: worker_mod.ControlEvent) void {
        if (self.snapshot_observer) |observer| {
            observer.installed(event.snapshot_generation, event.retired_snapshot);
        } else if (event.retired_snapshot) |retired| {
            retired.destroy();
        }
    }

    fn onClientSnapshotInstalled(self: *ControlPlane, event: worker_mod.ControlEvent) void {
        if (self.client_snapshot_observer) |observer| {
            observer.installed(event.snapshot_generation, event.retired_client_snapshot);
        } else if (event.retired_client_snapshot) |retired| {
            retired.destroy();
        }
    }

    fn observeEndpoint(self: *ControlPlane, peer: *Peer, endpoint: std.Io.net.IpAddress, now_ns: u64) void {
        const observed = toProtocolEndpoint(endpoint);
        if (peer.validator.current) |current| if (endpoint_protocol.Endpoint.eql(current, observed)) return;
        if (peer.validator.candidate) |candidate| {
            if (now_ns <= candidate.expires_at and endpoint_protocol.Endpoint.eql(candidate.endpoint, observed)) return;
        }
        var challenge: [endpoint_protocol.challenge_len]u8 = undefined;
        self.io.random(&challenge);
        if (!peer.validator.observeAuthenticated(observed, challenge, now_ns)) return;
        self.sendFrame(peer, .path_challenge, &challenge, endpoint, false, now_ns) catch return;
        peer.candidate_endpoint = endpoint;
        peer.next_path_challenge_ns = now_ns +| std.time.ns_per_s;
    }

    fn handleControl(
        self: *ControlPlane,
        peer: *Peer,
        source_endpoint: std.Io.net.IpAddress,
        bytes: []const u8,
        now_ns: u64,
    ) void {
        const frame = control.Frame.decode(bytes) catch return;
        // A responder-side split key is deliberately receive-capable before it
        // is active for transmission, solely so it can authenticate the exact
        // SESSION_CONFIRM bound to the handshake hash. No other control frame
        // may advance liveness, endpoint, configuration, or association state
        // while confirmation is pending.
        if (peer.state == .awaiting_confirmation and frame.frame_type != .session_confirm) return;
        switch (frame.frame_type) {
            .session_confirm => {
                if (peer.state != .awaiting_confirmation) return;
                const confirmation = handshake.SessionConfirm.decode(frame.payload) catch return;
                if (!std.crypto.timing_safe.eql([32]u8, confirmation.handshake_hash, peer.expected_handshake_hash)) return;
                if (!self.commands.submit(.{ .kind = .confirm_session, .receiver_session_id = peer.receiver_session_id })) return;
                peer.state = .online;
                if (self.session_observer) |observer| observer.confirmed(peer.receiver_session_id, now_ns);
            },
            .heartbeat => {
                if (frame.payload.len != @sizeOf(u64)) return;
                if (peer.state == .awaiting_confirmation) return;
                self.sendFrameWithRequestId(peer, .heartbeat_ack, frame.request_id, frame.payload, null, false, now_ns) catch return;
                if (self.session_observer) |observer| observer.confirmed(peer.receiver_session_id, now_ns);
            },
            .heartbeat_ack => {
                if (frame.payload.len != @sizeOf(u64)) return;
                // A heartbeat acknowledgement is liveness evidence only for
                // an already-confirmed association. In particular, it cannot
                // stand in for the IK/XK SESSION_CONFIRM carrying the expected
                // handshake hash. Node-side pending attempts install their
                // transport as initiator-confirmed before waiting for Master
                // liveness, so this gate preserves that completion path while
                // preventing premature Master association activation.
                if (peer.state == .awaiting_confirmation) return;
                if (peer.state == .suspect) peer.state = .online;
                if (self.session_observer) |observer| observer.confirmed(peer.receiver_session_id, now_ns);
            },
            .path_challenge => {
                if (frame.payload.len != endpoint_protocol.challenge_len) return;
                self.sendFrameWithRequestId(peer, .path_response, frame.request_id, frame.payload, source_endpoint, false, now_ns) catch {};
            },
            .path_response => {
                if (frame.payload.len != endpoint_protocol.challenge_len) return;
                const response = frame.payload[0..endpoint_protocol.challenge_len].*;
                const endpoint = toProtocolEndpoint(source_endpoint);
                if (!peer.validator.responseValid(endpoint, response, now_ns)) return;
                if (!self.commands.submit(.{
                    .kind = .update_endpoint,
                    .receiver_session_id = peer.receiver_session_id,
                    .endpoint = source_endpoint,
                })) return;
                if (!peer.validator.acceptResponse(endpoint, response, now_ns)) return;
                peer.candidate_endpoint = null;
                peer.next_path_challenge_ns = 0;
            },
            .rotate_key => peer.state = .rekey_required,
            .goodbye => {
                peer.state = .offline;
                peer.transmit_enabled = false;
                if (!peer.removal_queued) {
                    peer.removal_queued = self.commands.retire(peer.receiver_session_id);
                }
            },
            .enrollment_complete => {
                if (frame.payload.len != 16) return;
                if (self.enrollment_complete_observer) |observer| {
                    observer.complete(peer.receiver_session_id, frame.payload[0..16].*, now_ns);
                }
            },
            .configuration_begin,
            .configuration_chunk,
            .configuration_ack,
            => if (self.configuration_observer) |observer| observer.receive(
                peer.receiver_session_id,
                frame.frame_type,
                frame.request_id,
                frame.generation,
                frame.payload,
                now_ns,
            ),
            .protocol_error => {},
        }
    }

    fn tick(self: *ControlPlane, now_ns: u64) void {
        for (self.peers.items) |*peer| {
            if (peer.state == .offline) {
                peer.transmit_enabled = false;
                if (!peer.removal_queued) {
                    peer.removal_queued = self.commands.retire(peer.receiver_session_id);
                }
                continue;
            }
            if (!peer.transmit_enabled) continue;
            self.tickPathChallenge(peer, now_ns);
            if (peer.state == .awaiting_confirmation) continue;
            const receive_idle = now_ns -| peer.last_rx_ns;
            if (receive_idle >= self.offline_interval_ns) {
                peer.state = .offline;
                peer.transmit_enabled = false;
                peer.removal_queued = self.commands.retire(peer.receiver_session_id);
                continue;
            }
            if (receive_idle >= self.suspect_interval_ns and peer.state == .online) peer.state = .suspect;
            if (now_ns >= heartbeatDeadline(peer.*, self.heartbeat_interval_ns)) {
                var timestamp: [8]u8 = undefined;
                std.mem.writeInt(u64, &timestamp, now_ns, .big);
                self.sendFrame(peer, .heartbeat, &timestamp, null, false, now_ns) catch {};
            }
        }
    }

    fn tickPathChallenge(self: *ControlPlane, peer: *Peer, now_ns: u64) void {
        const candidate = peer.validator.candidate orelse return;
        if (now_ns > candidate.expires_at) {
            peer.candidate_endpoint = null;
            peer.next_path_challenge_ns = 0;
            return;
        }
        const endpoint = peer.candidate_endpoint orelse return;
        if (now_ns < peer.next_path_challenge_ns) return;
        self.sendFrame(peer, .path_challenge, &candidate.challenge, endpoint, false, now_ns) catch return;
        peer.next_path_challenge_ns = now_ns +| std.time.ns_per_s;
    }

    fn sendFrame(
        self: *ControlPlane,
        peer: *Peer,
        frame_type: control.Type,
        payload: []const u8,
        endpoint_override: ?std.Io.net.IpAddress,
        allow_unconfirmed: bool,
        now_ns: u64,
    ) !void {
        _ = try self.sendFrameGenerationRequest(peer, frame_type, payload, 0, endpoint_override, allow_unconfirmed, now_ns);
    }

    fn sendFrameWithRequestId(
        self: *ControlPlane,
        peer: *Peer,
        frame_type: control.Type,
        request_id: u32,
        payload: []const u8,
        endpoint_override: ?std.Io.net.IpAddress,
        allow_unconfirmed: bool,
        now_ns: u64,
    ) !void {
        return self.sendFrameGenerationWithRequestId(
            peer,
            frame_type,
            request_id,
            payload,
            0,
            endpoint_override,
            allow_unconfirmed,
            now_ns,
        );
    }

    fn sendFrameGenerationRequest(
        self: *ControlPlane,
        peer: *Peer,
        frame_type: control.Type,
        payload: []const u8,
        generation: u64,
        endpoint_override: ?std.Io.net.IpAddress,
        allow_unconfirmed: bool,
        now_ns: u64,
    ) !u32 {
        const request_id = peer.next_request_id;
        try self.sendFrameGenerationWithRequestId(
            peer,
            frame_type,
            request_id,
            payload,
            generation,
            endpoint_override,
            allow_unconfirmed,
            now_ns,
        );
        peer.next_request_id +%= 1;
        if (peer.next_request_id == 0) peer.next_request_id = 1;
        return request_id;
    }

    fn sendFrameGenerationWithRequestId(
        self: *ControlPlane,
        peer: *Peer,
        frame_type: control.Type,
        request_id: u32,
        payload: []const u8,
        generation: u64,
        endpoint_override: ?std.Io.net.IpAddress,
        allow_unconfirmed: bool,
        now_ns: u64,
    ) !void {
        if (!peer.transmit_enabled) return error.SessionReceiveOnly;
        var storage: [control.max_frame_len]u8 = undefined;
        const encoded = try (control.Frame{
            .frame_type = frame_type,
            .request_id = request_id,
            .generation = generation,
            .payload = payload,
        }).encode(&storage);
        const command = worker_mod.DataCommand.control(
            peer.receiver_session_id,
            endpoint_override,
            encoded,
            allow_unconfirmed,
        );
        if (!self.commands.submit(command)) return error.CommandQueueFull;
        peer.last_tx_ns = now_ns;
    }

    fn findPeer(self: *ControlPlane, receiver_session_id: u64) ?*Peer {
        for (self.peers.items) |*peer| if (peer.receiver_session_id == receiver_session_id) return peer;
        return null;
    }

    fn findPeerIndex(self: *const ControlPlane, receiver_session_id: u64) ?usize {
        for (self.peers.items, 0..) |peer, index| if (peer.receiver_session_id == receiver_session_id) return index;
        return null;
    }
};

pub fn requestIdAt(first: u32, offset: u32) u32 {
    var result = first;
    var remaining = offset;
    while (remaining != 0) : (remaining -= 1) {
        result +%= 1;
        if (result == 0) result = 1;
    }
    return result;
}

fn heartbeatDeadline(peer: Peer, idle_ns: u64) u64 {
    const maximum_jitter = @min(1500 * std.time.ns_per_ms, idle_ns / 4);
    var value = peer.receiver_session_id +% 0x9e37_79b9_7f4a_7c15;
    value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
    value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
    value ^= value >> 31;
    const magnitude = if (maximum_jitter == 0) 0 else value % (maximum_jitter + 1);
    const base = peer.last_tx_ns +| idle_ns;
    return if ((peer.receiver_session_id & 1) == 0) base +| magnitude else base -| magnitude;
}

fn toProtocolEndpoint(endpoint: std.Io.net.IpAddress) endpoint_protocol.Endpoint {
    return switch (endpoint) {
        .ip4 => |ip4| .{
            .family = .ipv4,
            .address = ip4.bytes ++ ([_]u8{0} ** 12),
            .port = ip4.port,
        },
        .ip6 => |ip6| .{
            .family = .ipv6,
            .address = ip6.bytes,
            .port = ip6.port,
        },
    };
}

const TestSink = struct {
    commands: std.ArrayList(worker_mod.DataCommand) = .empty,
    allocator: std.mem.Allocator,
    fail_submissions: bool = false,
    retirement_failures_remaining: usize = 0,
    retired: [8]u64 = [_]u64{0} ** 8,
    retired_count: usize = 0,

    fn submit(context: *anyopaque, command: worker_mod.DataCommand) bool {
        const self: *TestSink = @ptrCast(@alignCast(context));
        if (self.fail_submissions) return false;
        self.commands.append(self.allocator, command) catch return false;
        return true;
    }

    fn retire(context: *anyopaque, receiver_session_id: u64) bool {
        const self: *TestSink = @ptrCast(@alignCast(context));
        if (self.retirement_failures_remaining != 0) {
            self.retirement_failures_remaining -= 1;
            return false;
        }
        if (self.retired_count == self.retired.len) return false;
        self.retired[self.retired_count] = receiver_session_id;
        self.retired_count += 1;
        return true;
    }
};

test "session confirmation gates Master transmission" {
    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink,
        .submit_fn = TestSink.submit,
    });
    defer plane.deinit();
    const session: plane_mod.Session = .{
        .receiver_id = 7,
        .owner = 9,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    };
    const hash = [_]u8{3} ** 32;
    try plane.registerPendingSession(session, hash, 0);
    try std.testing.expectEqual(PeerState.awaiting_confirmation, plane.peerState(7).?);
    try std.testing.expect(plane.peerActivity(7).?.authenticated_rx_ns == null);
    try std.testing.expect(plane.peerActivity(7).?.authenticated_tx_ns == null);

    const payload = (handshake.SessionConfirm{ .handshake_hash = hash }).encode();
    var frame_bytes: [control.max_frame_len]u8 = undefined;
    const frame = try (control.Frame{ .frame_type = .session_confirm, .request_id = 1, .generation = 0, .payload = &payload }).encode(&frame_bytes);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(7, .{ .ip4 = .loopback(49152) }, frame)));
    plane.poll(1);
    try std.testing.expectEqual(PeerState.online, plane.peerState(7).?);
    try std.testing.expectEqual(@as(?u64, 1), plane.peerActivity(7).?.authenticated_rx_ns);
    try std.testing.expect(events.push(.{
        .kind = .outbound_authenticated,
        .receiver_session_id = 7,
    }));
    plane.poll(2);
    try std.testing.expectEqual(@as(?u64, 2), plane.peerActivity(7).?.authenticated_tx_ns);
    try std.testing.expectEqual(worker_mod.DataCommandKind.confirm_session, sink.commands.items[sink.commands.items.len - 1].kind);
}

test "heartbeat and acknowledgement cannot confirm a pending session" {
    const ConfirmationObserver = struct {
        calls: usize = 0,
        receiver_session_id: u64 = 0,

        fn confirmed(raw: *anyopaque, receiver_session_id: u64, _: u64) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            self.receiver_session_id = receiver_session_id;
        }
    };

    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink,
        .submit_fn = TestSink.submit,
    });
    defer plane.deinit();
    var observer: ConfirmationObserver = .{};
    plane.setSessionObserver(.{ .context = &observer, .confirmed_fn = ConfirmationObserver.confirmed });

    const receiver_session_id: u64 = 29;
    const expected_hash = [_]u8{0x71} ** 32;
    try plane.registerPendingSession(.{
        .receiver_id = receiver_session_id,
        .owner = 9,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    }, expected_hash, 0);

    var heartbeat_payload: [8]u8 = undefined;
    std.mem.writeInt(u64, &heartbeat_payload, 1, .big);
    var heartbeat_ack_storage: [control.max_frame_len]u8 = undefined;
    const heartbeat_ack = try (control.Frame{
        .frame_type = .heartbeat_ack,
        .request_id = 1,
        .generation = 0,
        .payload = &heartbeat_payload,
    }).encode(&heartbeat_ack_storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(
        receiver_session_id,
        .{ .ip4 = .loopback(49152) },
        heartbeat_ack,
    )));
    plane.poll(1);

    try std.testing.expectEqual(PeerState.awaiting_confirmation, plane.peerState(receiver_session_id).?);
    try std.testing.expectEqual(@as(usize, 0), observer.calls);

    var heartbeat_storage: [control.max_frame_len]u8 = undefined;
    const heartbeat = try (control.Frame{
        .frame_type = .heartbeat,
        .request_id = 2,
        .generation = 0,
        .payload = &heartbeat_payload,
    }).encode(&heartbeat_storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(
        receiver_session_id,
        .{ .ip4 = .loopback(49152) },
        heartbeat,
    )));
    plane.poll(2);

    try std.testing.expectEqual(PeerState.awaiting_confirmation, plane.peerState(receiver_session_id).?);
    try std.testing.expectEqual(@as(usize, 0), observer.calls);

    const confirmation_payload = (handshake.SessionConfirm{ .handshake_hash = expected_hash }).encode();
    var confirmation_storage: [control.max_frame_len]u8 = undefined;
    const session_confirm = try (control.Frame{
        .frame_type = .session_confirm,
        .request_id = 3,
        .generation = 0,
        .payload = &confirmation_payload,
    }).encode(&confirmation_storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(
        receiver_session_id,
        .{ .ip4 = .loopback(49152) },
        session_confirm,
    )));
    plane.poll(3);

    try std.testing.expectEqual(PeerState.online, plane.peerState(receiver_session_id).?);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expectEqual(receiver_session_id, observer.receiver_session_id);

    const command_count = sink.commands.items.len;
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(
        receiver_session_id,
        .{ .ip4 = .loopback(49152) },
        session_confirm,
    )));
    plane.poll(4);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expectEqual(command_count, sink.commands.items.len);
}

test "bounded control replies echo the authenticated request ID" {
    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink,
        .submit_fn = TestSink.submit,
    });
    defer plane.deinit();
    try plane.registerPendingSession(.{
        .receiver_id = 17,
        .owner = 9,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    }, [_]u8{3} ** 32, 0);
    try plane.confirmAsInitiator(17, 1);

    var payload: [8]u8 = undefined;
    std.mem.writeInt(u64, &payload, 123, .big);
    var storage: [control.max_frame_len]u8 = undefined;
    const request = try (control.Frame{
        .frame_type = .heartbeat,
        .request_id = 0xa1b2_c3d4,
        .generation = 0,
        .payload = &payload,
    }).encode(&storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(17, .{ .ip4 = .loopback(49152) }, request)));
    plane.poll(2);
    const response = sink.commands.items[sink.commands.items.len - 1];
    try std.testing.expectEqual(worker_mod.DataCommandKind.send_control, response.kind);
    const frame = try control.Frame.decode(response.payload());
    try std.testing.expectEqual(control.Type.heartbeat_ack, frame.frame_type);
    try std.testing.expectEqual(@as(u32, 0xa1b2_c3d4), frame.request_id);
    try std.testing.expectEqualSlices(u8, &payload, frame.payload);
}

test "liveness becomes suspect then offline without authenticated traffic" {
    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{ .context = &sink, .submit_fn = TestSink.submit });
    defer plane.deinit();
    const session: plane_mod.Session = .{
        .receiver_id = 1,
        .owner = 1,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    };
    try plane.registerPendingSession(session, [_]u8{3} ** 32, 0);
    try plane.confirmAsInitiator(1, 1);
    plane.poll(suspect_after_ns);
    try std.testing.expectEqual(PeerState.suspect, plane.peerState(1).?);
    plane.poll(offline_after_ns);
    try std.testing.expectEqual(PeerState.offline, plane.peerState(1).?);
}

test "offline retirement bypasses command saturation and retries until accepted" {
    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink,
        .submit_fn = TestSink.submit,
        .retire_fn = TestSink.retire,
    });
    defer plane.deinit();
    try plane.registerPendingSession(.{
        .receiver_id = 81,
        .owner = 1,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    }, [_]u8{3} ** 32, 0);
    try plane.confirmAsInitiator(81, 1);

    // Saturate ordinary commands and transiently refuse the dedicated path.
    // The peer becomes non-transmitting immediately and retirement remains
    // pending until the bounded revocation queue accepts the receiver ID.
    sink.fail_submissions = true;
    sink.retirement_failures_remaining = 2;
    plane.poll(offline_after_ns);
    try std.testing.expectEqual(PeerState.offline, plane.peerState(81).?);
    try std.testing.expectEqual(false, plane.peerTransmitEnabled(81).?);
    try std.testing.expect(!plane.findPeer(81).?.removal_queued);
    try std.testing.expectEqual(@as(usize, 0), sink.retired_count);

    plane.poll(offline_after_ns + 1);
    try std.testing.expect(!plane.findPeer(81).?.removal_queued);
    plane.poll(offline_after_ns + 2);
    try std.testing.expect(plane.findPeer(81).?.removal_queued);
    try std.testing.expectEqual(@as(usize, 1), sink.retired_count);
    try std.testing.expectEqual(@as(u64, 81), sink.retired[0]);
    try std.testing.expectError(error.SessionReceiveOnly, plane.sendHeartbeatNow(81, offline_after_ns + 3));
}

test "receive-only peer never emits heartbeat response or scheduled control" {
    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{
        .context = &sink,
        .submit_fn = TestSink.submit,
    });
    defer plane.deinit();

    inline for (.{ @as(u64, 1), @as(u64, 2) }) |receiver_id| {
        try plane.registerPendingSession(.{
            .receiver_id = receiver_id,
            .owner = 9,
            .tx_key = [_]u8{@intCast(receiver_id)} ** 32,
            .rx_key = [_]u8{@intCast(receiver_id + 2)} ** 32,
            .created_ns = receiver_id,
            .endpoint = .{ .ip4 = .loopback(@intCast(49151 + receiver_id)) },
        }, [_]u8{@intCast(receiver_id + 4)} ** 32, receiver_id);
        try plane.confirmAsInitiator(receiver_id, receiver_id);
    }

    plane.makeReceiveOnly(1);
    try std.testing.expectEqual(false, plane.peerTransmitEnabled(1).?);
    try std.testing.expectEqual(true, plane.peerTransmitEnabled(2).?);
    try std.testing.expectError(error.SessionReceiveOnly, plane.sendHeartbeatNow(1, 2));
    try std.testing.expectError(
        error.SessionReceiveOnly,
        plane.sendConfigurationFrame(1, .configuration_ack, &([_]u8{0} ** control.snapshot_hash_len), 7, 2),
    );

    const before = sink.commands.items.len;
    var frame_storage: [control.max_frame_len]u8 = undefined;
    var timestamp: [8]u8 = undefined;
    std.mem.writeInt(u64, &timestamp, 2, .big);
    const heartbeat = try (control.Frame{
        .frame_type = .heartbeat,
        .request_id = 99,
        .generation = 0,
        .payload = &timestamp,
    }).encode(&frame_storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(1, .{ .ip4 = .loopback(49152) }, heartbeat)));
    plane.poll(2);
    try std.testing.expectEqual(before, sink.commands.items.len);

    // At 17 seconds both deterministic heartbeat deadlines have elapsed. The
    // current peer emits one heartbeat; the draining peer emits nothing.
    plane.poll(17 * std.time.ns_per_s);
    try std.testing.expectEqual(before + 1, sink.commands.items.len);
    const scheduled = sink.commands.items[sink.commands.items.len - 1];
    try std.testing.expectEqual(worker_mod.DataCommandKind.send_control, scheduled.kind);
    try std.testing.expectEqual(@as(u64, 2), scheduled.receiver_session_id);
}

test "configuration generation is preserved and timed-out sessions can abort" {
    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{ .context = &sink, .submit_fn = TestSink.submit });
    defer plane.deinit();
    const session: plane_mod.Session = .{
        .receiver_id = 71,
        .owner = 9,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    };
    try plane.registerPendingSession(session, [_]u8{3} ** 32, 0);
    var chunk_storage: [64]u8 = undefined;
    const chunk = try (control.ConfigurationChunk{ .index = 0, .offset = 0, .data = "chunk" }).encode(&chunk_storage);
    try plane.sendConfigurationFrame(71, .configuration_chunk, chunk, 418, 1);
    const command = sink.commands.items[sink.commands.items.len - 1];
    try std.testing.expectEqual(worker_mod.DataCommandKind.send_control, command.kind);
    const frame = try control.Frame.decode(command.payload());
    try std.testing.expectEqual(control.Type.configuration_chunk, frame.frame_type);
    try std.testing.expectEqual(@as(u64, 418), frame.generation);
    try std.testing.expectEqualStrings("chunk", (try control.ConfigurationChunk.decode(frame.payload)).data);

    const retransmit_id = try plane.reserveRequestIds(71, 2);
    try plane.sendConfigurationFrameWithRequestId(71, .configuration_chunk, retransmit_id, chunk, 418, 2);
    try plane.sendConfigurationFrameWithRequestId(71, .configuration_chunk, retransmit_id, chunk, 418, 3);
    const retransmit_a = try control.Frame.decode(sink.commands.items[sink.commands.items.len - 2].payload());
    const retransmit_b = try control.Frame.decode(sink.commands.items[sink.commands.items.len - 1].payload());
    try std.testing.expectEqual(retransmit_a.request_id, retransmit_b.request_id);
    try std.testing.expectEqualSlices(u8, retransmit_a.payload, retransmit_b.payload);
    try std.testing.expectEqual(requestIdAt(retransmit_id, 2), plane.findPeer(71).?.next_request_id);

    try plane.sendConfigurationResponse(
        71,
        .configuration_ack,
        0x4242_4242,
        &([_]u8{0x5a} ** control.snapshot_hash_len),
        418,
        2,
    );
    const acknowledgement = try control.Frame.decode(sink.commands.items[sink.commands.items.len - 1].payload());
    try std.testing.expectEqual(control.Type.configuration_ack, acknowledgement.frame_type);
    try std.testing.expectEqual(@as(u32, 0x4242_4242), acknowledgement.request_id);
    try std.testing.expectEqual(@as(u64, 418), acknowledgement.generation);

    try plane.abortSession(71);
    try std.testing.expect(!plane.hasPeer(71));
    try std.testing.expectEqual(worker_mod.DataCommandKind.remove_session, sink.commands.items[sink.commands.items.len - 1].kind);
}

test "reserved request ID ranges skip zero on wrap" {
    try std.testing.expectEqual(std.math.maxInt(u32) - 1, requestIdAt(std.math.maxInt(u32) - 1, 0));
    try std.testing.expectEqual(std.math.maxInt(u32), requestIdAt(std.math.maxInt(u32) - 1, 1));
    try std.testing.expectEqual(@as(u32, 1), requestIdAt(std.math.maxInt(u32) - 1, 2));
    try std.testing.expectEqual(@as(u32, 2), requestIdAt(std.math.maxInt(u32) - 1, 3));
}

test "authenticated enrollment and configuration frames use dedicated observers" {
    const Observer = struct {
        enrollment_uuid: ?[16]u8 = null,
        config_generation: u64 = 0,

        fn enrollment(raw: *anyopaque, _: u64, node_uuid: [16]u8, _: u64) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.enrollment_uuid = node_uuid;
        }

        fn configuration(
            raw: *anyopaque,
            _: u64,
            _: control.Type,
            _: u32,
            generation: u64,
            _: []const u8,
            _: u64,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.config_generation = generation;
        }
    };

    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{ .context = &sink, .submit_fn = TestSink.submit });
    defer plane.deinit();
    var observer: Observer = .{};
    plane.setEnrollmentCompleteObserver(.{ .context = &observer, .complete_fn = Observer.enrollment });
    plane.setConfigurationObserver(.{ .context = &observer, .receive_fn = Observer.configuration });
    try plane.registerPendingSession(.{
        .receiver_id = 7,
        .owner = 9,
        .tx_key = [_]u8{1} ** 32,
        .rx_key = [_]u8{2} ** 32,
        .created_ns = 0,
        .endpoint = .{ .ip4 = .loopback(49152) },
    }, [_]u8{3} ** 32, 0);
    // This scenario models the Node/initiator side, which becomes locally
    // confirmed immediately after sending SESSION_CONFIRM.
    try plane.confirmAsInitiator(7, 0);

    var frame_storage: [control.max_frame_len]u8 = undefined;
    const uuid = [_]u8{0xa5} ** 16;
    const enrollment = try (control.Frame{
        .frame_type = .enrollment_complete,
        .request_id = 1,
        .generation = 0,
        .payload = &uuid,
    }).encode(&frame_storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(7, .{ .ip4 = .loopback(49152) }, enrollment)));
    plane.poll(1);
    try std.testing.expectEqualSlices(u8, &uuid, &observer.enrollment_uuid.?);

    const configuration = try (control.Frame{
        .frame_type = .configuration_ack,
        .request_id = 2,
        .generation = 99,
        .payload = &([_]u8{0x42} ** control.snapshot_hash_len),
    }).encode(&frame_storage);
    try std.testing.expect(events.push(worker_mod.ControlEvent.control(7, .{ .ip4 = .loopback(49152) }, configuration)));
    plane.poll(2);
    try std.testing.expectEqual(@as(u64, 99), observer.config_generation);
}

test "unobserved snapshot acknowledgement still retires ownership" {
    const model = @import("../domain/model.zig");
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    const retired = try topology.createMaster(std.testing.allocator, &store, &.{});

    var events = try worker_mod.ControlQueue.init(std.testing.allocator, 8);
    defer events.deinit();
    var sink: TestSink = .{ .allocator = std.testing.allocator };
    defer sink.commands.deinit(std.testing.allocator);
    var plane = ControlPlane.init(std.testing.allocator, std.testing.io, &events, .{ .context = &sink, .submit_fn = TestSink.submit });
    defer plane.deinit();
    try std.testing.expect(events.push(.{
        .kind = .snapshot_installed,
        .receiver_session_id = 0,
        .snapshot_generation = 3,
        .retired_snapshot = retired,
    }));
    plane.poll(0);
}
