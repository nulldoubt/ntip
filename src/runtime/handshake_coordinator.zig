const std = @import("std");
const credential_protocol = @import("../protocol/credential.zig");
const cookie_protocol = @import("../protocol/cookie.zig");
const endpoint_protocol = @import("../protocol/endpoint.zig");
const handshake_protocol = @import("../protocol/handshake.zig");
const noise = @import("../protocol/noise.zig");
const timing = @import("../protocol/timing.zig");
const wire = @import("../protocol/header.zig");
const control_plane = @import("control_plane.zig");
const data_plane = @import("data_plane.zig");
const data_worker = @import("data_worker.zig");

pub const maximum_handshake_datagram_len: usize = data_plane.control_plaintext_limit;
pub const handshake_attempt_timeout_ns: u64 = 45 * std.time.ns_per_s;
/// After emitting the fifth and final cached retransmission, retain the
/// attempt for one final eight-second response window before retiring it.
pub const retransmission_final_grace_ns: u64 =
    timing.retransmission_delays[timing.retransmission_delays.len - 1];

pub const Counters = struct {
    initial_requests: u64 = 0,
    malformed_drops: u64 = 0,
    authentication_drops: u64 = 0,
    unknown_identity_drops: u64 = 0,
    capacity_drops: u64 = 0,
    identity_conflict_drops: u64 = 0,
    queue_drops: u64 = 0,
    retransmissions: u64 = 0,
    retry_challenges: u64 = 0,
    completed: u64 = 0,
    persistence_failures: u64 = 0,
};

pub const AdmissionSnapshot = struct {
    initial_requests: u64,
    authentication_failures: u64,
};

/// Registry result for an unused one-time enrollment. Expiry and consumed
/// state are checked by the registry implementation before this value is
/// returned. `psk` is the bearer-equivalent derived PSK, never the raw token.
pub const EnrollmentRecord = struct {
    node_uuid: [16]u8,
    assigned_ipv4: [4]u8,
    vnr_network: [4]u8,
    vnr_prefix_len: u8,
    config_generation: u64,
    owner: u128,
    psk: [32]u8,
};

pub const NodeRecord = struct {
    node_uuid: [16]u8,
    public_key: [32]u8,
    config_generation: u64,
    owner: u128,
};

/// Server-side persistence boundary. `consume_and_bind_fn` must atomically
/// consume the credential and durably bind the supplied Node static public key
/// before returning success. Races are resolved by that callback, not by this
/// in-memory coordinator.
pub const MasterRegistry = struct {
    context: *anyopaque,
    lookup_enrollment_fn: *const fn (*anyopaque, [16]u8) anyerror!EnrollmentRecord,
    consume_and_bind_fn: *const fn (*anyopaque, [16]u8, [16]u8, [32]u8) anyerror!void,
    lookup_node_fn: *const fn (*anyopaque, [16]u8) anyerror!NodeRecord,

    pub fn lookupEnrollment(self: MasterRegistry, handle: [16]u8) !EnrollmentRecord {
        return self.lookup_enrollment_fn(self.context, handle);
    }

    pub fn consumeAndBind(
        self: MasterRegistry,
        handle: [16]u8,
        node_uuid: [16]u8,
        public_key: [32]u8,
    ) !void {
        return self.consume_and_bind_fn(self.context, handle, node_uuid, public_key);
    }

    pub fn lookupNode(self: MasterRegistry, node_uuid: [16]u8) !NodeRecord {
        return self.lookup_node_fn(self.context, node_uuid);
    }
};

pub const EnrollmentAssignment = struct {
    node_uuid: [16]u8,
    assigned_ipv4: [4]u8,
    vnr_network: [4]u8,
    vnr_prefix_len: u8,
    config_generation: u64,
    master_public: [32]u8,
};

/// Node-side durable staging hook. The callback persists the authenticated
/// assignment before the final XK message is sent. It must not delete the
/// enrollment token yet; that is safe only after ENROLLMENT_COMPLETE arrives.
pub const NodePersistence = struct {
    context: *anyopaque,
    stage_assignment_fn: *const fn (*anyopaque, EnrollmentAssignment) anyerror!void,
    complete_enrollment_fn: *const fn (*anyopaque, [16]u8) anyerror!void,

    pub fn stageAssignment(self: NodePersistence, assignment: EnrollmentAssignment) !void {
        return self.stage_assignment_fn(self.context, assignment);
    }

    /// Atomically flips the staged assignment to enrolled and removes the
    /// one-time token. The coordinator invokes this only for an authenticated
    /// ENROLLMENT_COMPLETE, or after authenticated IK recovery of a staged
    /// enrollment.
    pub fn completeEnrollment(self: NodePersistence, node_uuid: [16]u8) !void {
        return self.complete_enrollment_fn(self.context, node_uuid);
    }
};

pub const EstablishedKind = enum { enrollment, reconnect_or_rekey };

/// Trigger for per-Node configuration delivery. It runs only after the Master
/// has authenticated SESSION_CONFIRM and queued data-plane activation. The
/// service uses the stable Node UUID to build and send the correct immutable
/// configuration snapshot.
pub const MasterSessionReady = struct {
    context: *anyopaque,
    ready_fn: *const fn (*anyopaque, [16]u8, u64, u64, EstablishedKind, u64) anyerror!void,

    pub fn ready(
        self: MasterSessionReady,
        node_uuid: [16]u8,
        receiver_session_id: u64,
        config_generation: u64,
        kind: EstablishedKind,
        now_ns: u64,
    ) !void {
        return self.ready_fn(self.context, node_uuid, receiver_session_id, config_generation, kind, now_ns);
    }
};

pub const RetryPolicy = struct {
    verifier: cookie_protocol.RotatingVerifier,
    required: bool = true,
};

const CachedDatagram = struct {
    endpoint: std.Io.net.IpAddress = undefined,
    length: u16 = 0,
    bytes: [maximum_handshake_datagram_len]u8 = undefined,

    fn set(self: *CachedDatagram, endpoint: std.Io.net.IpAddress, datagram: []const u8) !void {
        if (datagram.len == 0 or datagram.len > self.bytes.len) return error.HandshakeDatagramTooLarge;
        self.endpoint = endpoint;
        self.length = @intCast(datagram.len);
        @memcpy(self.bytes[0..datagram.len], datagram);
    }

    fn slice(self: *const CachedDatagram) []const u8 {
        return self.bytes[0..self.length];
    }

    fn clear(self: *CachedDatagram) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.length = 0;
    }
};

const AttemptKind = enum { enrollment, session };
const AttemptPhase = enum { awaiting_response, awaiting_confirmation };

const NodeAttempt = struct {
    kind: AttemptKind,
    phase: AttemptPhase = .awaiting_response,
    packet_type: wire.PacketType,
    context: u64,
    identity_context: [16]u8,
    endpoint: std.Io.net.IpAddress,
    local_receiver_id: u64,
    peer_receiver_id: u64 = 0,
    node_uuid: [16]u8 = [_]u8{0} ** 16,
    owner: u128 = 0,
    finalizes_enrollment: bool = false,
    started_ns: u64,
    first_noise_length: u16 = 0,
    first_noise: [maximum_handshake_datagram_len]u8 = undefined,
    outbound: CachedDatagram = .{},
    retransmission: timing.Retransmission,
    exhaustion_deadline_ns: ?u64 = null,
    xk: ?noise.XkInitiator = null,
    ik: ?noise.IkInitiator = null,

    fn deinit(self: *NodeAttempt) void {
        if (self.xk) |*state| state.deinit();
        if (self.ik) |*state| state.deinit();
        std.crypto.secureZero(u8, &self.first_noise);
        self.outbound.clear();
        self.xk = null;
        self.ik = null;
    }
};

/// Single-peer Node coordinator. It owns one bounded in-flight handshake and
/// emits all network/data-plane work through the existing command queue.
pub const NodeCoordinator = struct {
    io: std.Io,
    control: *control_plane.ControlPlane,
    commands: control_plane.CommandSink,
    persistence: ?NodePersistence,
    attempt: ?NodeAttempt = null,
    active_receiver_id: ?u64 = null,
    draining_receiver_id: ?u64 = null,
    drain_deadline_ns: u64 = 0,
    counters: Counters = .{},

    pub fn init(
        io: std.Io,
        control: *control_plane.ControlPlane,
        commands: control_plane.CommandSink,
        persistence: ?NodePersistence,
    ) NodeCoordinator {
        return .{ .io = io, .control = control, .commands = commands, .persistence = persistence };
    }

    pub fn deinit(self: *NodeCoordinator) void {
        self.clearAttempt();
        self.* = undefined;
    }

    /// Call after the coordinator is placed at its final address.
    pub fn attach(self: *NodeCoordinator) void {
        self.control.setHandshakeSink(self.handshakeSink());
        self.control.setSessionObserver(self.sessionObserver());
        self.control.setEnrollmentCompleteObserver(self.enrollmentCompleteObserver());
    }

    pub fn handshakeSink(self: *NodeCoordinator) control_plane.HandshakeSink {
        return .{ .context = self, .receive_fn = receiveFromControlPlane };
    }

    pub fn sessionObserver(self: *NodeCoordinator) control_plane.SessionObserver {
        return .{ .context = self, .confirmed_fn = sessionConfirmed };
    }

    pub fn enrollmentCompleteObserver(self: *NodeCoordinator) control_plane.EnrollmentCompleteObserver {
        return .{ .context = self, .complete_fn = enrollmentCompleted };
    }

    pub fn beginEnrollment(
        self: *NodeCoordinator,
        endpoint: std.Io.net.IpAddress,
        enrollment_credential: *const credential_protocol.Credential,
        node_static: noise.KeyPair,
        now_ns: u64,
    ) !void {
        if (self.attempt != null) return error.HandshakeInProgress;
        const context = randomNonzero(self.io);
        const receiver_id = freshReceiverId(self.control, self.io);
        var psk = enrollment_credential.derivePsk();
        defer std.crypto.secureZero(u8, &psk);

        self.attempt = NodeAttempt{
            .kind = .enrollment,
            .packet_type = .enrollment_handshake,
            .context = context,
            .identity_context = enrollment_credential.handle,
            .endpoint = endpoint,
            .local_receiver_id = receiver_id,
            .started_ns = now_ns,
            .retransmission = timing.Retransmission.init(now_ns),
            .xk = noise.XkInitiator.init(
                node_static,
                noise.KeyPair.generate(self.io),
                enrollment_credential.master_public,
                psk,
                enrollment_credential.handle,
            ),
        };
        errdefer self.clearAttempt();
        const attempt = &self.attempt.?;
        const payload = (handshake_protocol.EnrollmentMessage0{ .node_receiver_id = receiver_id }).encode();
        const noise_message = try attempt.xk.?.writeMessageOne(&payload, &attempt.first_noise);
        attempt.first_noise_length = @intCast(noise_message.len);
        try self.cacheEnvelope(attempt, null, noise_message, 0);
        try self.sendCached(&attempt.outbound);
    }

    pub fn beginSession(
        self: *NodeCoordinator,
        endpoint: std.Io.net.IpAddress,
        node_uuid: [16]u8,
        node_static: noise.KeyPair,
        master_public: [32]u8,
        now_ns: u64,
    ) !void {
        return self.beginIk(endpoint, node_uuid, node_static, master_public, false, now_ns);
    }

    /// Recovery path used when XK message 1 was durably staged but
    /// ENROLLMENT_COMPLETE was lost. Successful authenticated IK finalizes the
    /// staged enrollment and deletes the stale token through NodePersistence.
    pub fn beginRecovery(
        self: *NodeCoordinator,
        endpoint: std.Io.net.IpAddress,
        node_uuid: [16]u8,
        node_static: noise.KeyPair,
        master_public: [32]u8,
        now_ns: u64,
    ) !void {
        return self.beginIk(endpoint, node_uuid, node_static, master_public, true, now_ns);
    }

    fn beginIk(
        self: *NodeCoordinator,
        endpoint: std.Io.net.IpAddress,
        node_uuid: [16]u8,
        node_static: noise.KeyPair,
        master_public: [32]u8,
        finalizes_enrollment: bool,
        now_ns: u64,
    ) !void {
        if (self.attempt != null) return error.HandshakeInProgress;
        if (allZero(&node_uuid) or allZero(&master_public)) return error.InvalidIdentity;
        const context = randomNonzero(self.io);
        const receiver_id = freshReceiverId(self.control, self.io);
        self.attempt = NodeAttempt{
            .kind = .session,
            .packet_type = .session_handshake,
            .context = context,
            .identity_context = node_uuid,
            .endpoint = endpoint,
            .local_receiver_id = receiver_id,
            .started_ns = now_ns,
            .node_uuid = node_uuid,
            .owner = ownerFromUuid(node_uuid),
            .finalizes_enrollment = finalizes_enrollment,
            .retransmission = timing.Retransmission.init(now_ns),
            .ik = noise.IkInitiator.init(node_static, noise.KeyPair.generate(self.io), master_public, node_uuid),
        };
        errdefer self.clearAttempt();
        const attempt = &self.attempt.?;
        const payload = (handshake_protocol.SessionMessage0{
            .node_uuid = node_uuid,
            .node_receiver_id = receiver_id,
        }).encode();
        const noise_message = try attempt.ik.?.writeMessageOne(&payload, &attempt.first_noise);
        attempt.first_noise_length = @intCast(noise_message.len);
        try self.cacheEnvelope(attempt, null, noise_message, 0);
        try self.sendCached(&attempt.outbound);
    }

    pub fn beginRekey(
        self: *NodeCoordinator,
        endpoint: std.Io.net.IpAddress,
        node_uuid: [16]u8,
        node_static: noise.KeyPair,
        master_public: [32]u8,
        now_ns: u64,
    ) !void {
        return self.beginSession(endpoint, node_uuid, node_static, master_public, now_ns);
    }

    pub fn receive(self: *NodeCoordinator, endpoint: std.Io.net.IpAddress, datagram: []const u8, now_ns: u64) !void {
        const attempt = if (self.attempt) |*value| value else return error.NoHandshakeInProgress;
        if (!endpointEql(endpoint, attempt.endpoint)) return error.UnexpectedHandshakeEndpoint;
        if (datagram.len < wire.encoded_len) return error.TruncatedHandshakeDatagram;
        const header = try wire.Header.decode(datagram[0..wire.encoded_len]);
        if (header.context != attempt.context) return error.UnexpectedHandshakeContext;

        if (header.packet_type == .stateless_retry) {
            if (attempt.phase != .awaiting_response or header.sequence != 0) return error.UnexpectedRetry;
            const retry = try cookie_protocol.RetryPayload.decode(datagram[wire.encoded_len..]);
            try self.cacheEnvelope(attempt, retry, attempt.first_noise[0..attempt.first_noise_length], 0);
            attempt.retransmission = timing.Retransmission.init(now_ns);
            attempt.exhaustion_deadline_ns = null;
            try self.sendCached(&attempt.outbound);
            return;
        }

        if (header.packet_type != attempt.packet_type or header.sequence != 1 or attempt.phase != .awaiting_response) {
            return error.UnexpectedHandshakeMessage;
        }
        const envelope = try handshake_protocol.Envelope.decode(datagram[wire.encoded_len..]);
        if (!std.mem.eql(u8, &envelope.identity_context, &attempt.identity_context) or envelope.retry != null) {
            return error.UnexpectedIdentityContext;
        }
        switch (attempt.kind) {
            .enrollment => try self.finishEnrollment(attempt, envelope.noise_message, now_ns),
            .session => try self.finishSession(attempt, envelope.noise_message, now_ns),
        }
    }

    pub fn tick(self: *NodeCoordinator, now_ns: u64) void {
        if (self.draining_receiver_id) |receiver_id| {
            if (now_ns >= self.drain_deadline_ns) {
                self.control.abortSession(receiver_id) catch {
                    self.counters.queue_drops +|= 1;
                    return;
                };
                self.draining_receiver_id = null;
            }
        }
        const attempt = if (self.attempt) |*value| value else return;
        if (now_ns -| attempt.started_ns >= handshake_attempt_timeout_ns) {
            self.expireAttempt(attempt);
            return;
        }
        if (attempt.exhaustion_deadline_ns) |deadline| {
            if (now_ns >= deadline) self.expireAttempt(attempt);
            return;
        }
        if (!attempt.retransmission.onTimer(now_ns)) return;
        if (attempt.outbound.length != 0) self.sendCached(&attempt.outbound) catch {
            self.counters.queue_drops +|= 1;
        };
        if (attempt.phase == .awaiting_confirmation) {
            self.control.confirmAsInitiator(attempt.local_receiver_id, now_ns) catch {
                self.counters.queue_drops +|= 1;
            };
        }
        self.counters.retransmissions +|= 1;
        if (attempt.retransmission.exhausted()) {
            attempt.exhaustion_deadline_ns = now_ns +| retransmission_final_grace_ns;
        }
    }

    pub fn cancel(self: *NodeCoordinator) void {
        if (self.attempt) |attempt| if (self.control.hasPeer(attempt.local_receiver_id)) {
            self.control.abortSession(attempt.local_receiver_id) catch return;
        };
        self.clearAttempt();
    }

    pub fn retransmissionsExhausted(self: *const NodeCoordinator) bool {
        const attempt = self.attempt orelse return false;
        return attempt.retransmission.exhausted();
    }

    pub fn inProgress(self: *const NodeCoordinator) bool {
        return self.attempt != null;
    }

    pub fn activeReceiver(self: *const NodeCoordinator) ?u64 {
        return self.active_receiver_id;
    }

    fn finishEnrollment(self: *NodeCoordinator, attempt: *NodeAttempt, noise_message: []const u8, now_ns: u64) !void {
        var payload_storage: [128]u8 = undefined;
        const payload = attempt.xk.?.readMessageTwo(noise_message, &payload_storage) catch |err| {
            self.clearAttempt();
            return err;
        };
        const accepted = handshake_protocol.EnrollmentMessage1.decode(payload) catch |err| {
            self.clearAttempt();
            return err;
        };
        if (accepted.master_receiver_id == 0 or allZero(&accepted.node_uuid)) {
            self.clearAttempt();
            return error.InvalidEnrollmentAcceptance;
        }
        const assignment = EnrollmentAssignment{
            .node_uuid = accepted.node_uuid,
            .assigned_ipv4 = accepted.assigned_ipv4,
            .vnr_network = accepted.vnr_network,
            .vnr_prefix_len = accepted.vnr_prefix_len,
            .config_generation = accepted.config_generation,
            .master_public = attempt.xk.?.remote_static,
        };
        if (self.persistence) |persistence| persistence.stageAssignment(assignment) catch |err| {
            self.clearAttempt();
            return err;
        };

        const final_payload = (handshake_protocol.EnrollmentMessage2{ .node_uuid = accepted.node_uuid }).encode();
        var final_noise: [maximum_handshake_datagram_len]u8 = undefined;
        const finish = attempt.xk.?.writeMessageThree(&final_payload, &final_noise) catch |err| {
            self.clearAttempt();
            return err;
        };
        attempt.xk = null;
        attempt.peer_receiver_id = accepted.master_receiver_id;
        attempt.node_uuid = accepted.node_uuid;
        attempt.owner = ownerFromUuid(accepted.node_uuid);
        self.cacheEnvelope(attempt, null, finish.message, 2) catch |err| {
            self.clearAttempt();
            return err;
        };
        attempt.phase = .awaiting_confirmation;
        attempt.started_ns = now_ns;
        attempt.retransmission = timing.Retransmission.init(now_ns);
        attempt.exhaustion_deadline_ns = null;
        self.installInitiatorSession(attempt, finish.keys, now_ns) catch |err| {
            if (err == error.CommandQueueFull) self.counters.queue_drops +|= 1;
            self.clearAttempt();
            return err;
        };
        try self.sendCached(&attempt.outbound);
        try self.control.confirmAsInitiator(attempt.local_receiver_id, now_ns);
    }

    fn finishSession(self: *NodeCoordinator, attempt: *NodeAttempt, noise_message: []const u8, now_ns: u64) !void {
        var payload_storage: [128]u8 = undefined;
        const finish = attempt.ik.?.readMessageTwo(noise_message, &payload_storage) catch |err| {
            self.clearAttempt();
            return err;
        };
        const accepted = handshake_protocol.SessionMessage1.decode(finish.payload) catch |err| {
            self.clearAttempt();
            return err;
        };
        if (accepted.master_receiver_id == 0) {
            self.clearAttempt();
            return error.InvalidSessionAcceptance;
        }
        attempt.ik = null;
        attempt.peer_receiver_id = accepted.master_receiver_id;
        attempt.outbound.clear();
        attempt.phase = .awaiting_confirmation;
        attempt.started_ns = now_ns;
        attempt.retransmission = timing.Retransmission.init(now_ns);
        attempt.exhaustion_deadline_ns = null;
        self.installInitiatorSession(attempt, finish.keys, now_ns) catch |err| {
            if (err == error.CommandQueueFull) self.counters.queue_drops +|= 1;
            self.clearAttempt();
            return err;
        };
        try self.control.confirmAsInitiator(attempt.local_receiver_id, now_ns);
        // The initiator has authenticated the IK response and queued
        // SESSION_CONFIRM. From this point the Master may immediately send
        // configuration on the replacement session, so the previous control
        // peer must already be receive-only before this call returns.
        try self.activateSession(attempt.local_receiver_id, now_ns);
    }

    fn installInitiatorSession(
        self: *NodeCoordinator,
        attempt: *const NodeAttempt,
        keys: noise.DirectionalKeys,
        now_ns: u64,
    ) !void {
        try self.control.registerPendingSession(.{
            .receiver_id = attempt.local_receiver_id,
            .peer_receiver_id = attempt.peer_receiver_id,
            .owner = attempt.owner,
            .tx_key = keys.initiator_to_responder,
            .rx_key = keys.responder_to_initiator,
            .created_ns = now_ns,
            .endpoint = attempt.endpoint,
        }, keys.handshake_hash, now_ns);
    }

    fn cacheEnvelope(
        self: *NodeCoordinator,
        attempt: *NodeAttempt,
        retry: ?cookie_protocol.RetryPayload,
        noise_message: []const u8,
        message_index: u64,
    ) !void {
        _ = self;
        var storage: [maximum_handshake_datagram_len]u8 = undefined;
        const encoded = try encodeHandshakeDatagram(
            attempt.packet_type,
            attempt.context,
            message_index,
            attempt.identity_context,
            retry,
            noise_message,
            &storage,
        );
        try attempt.outbound.set(attempt.endpoint, encoded);
    }

    fn sendCached(self: *NodeCoordinator, cached: *const CachedDatagram) !void {
        if (!self.commands.submit(data_worker.DataCommand.datagram(cached.endpoint, cached.slice()))) {
            self.counters.queue_drops +|= 1;
            return error.CommandQueueFull;
        }
    }

    fn clearAttempt(self: *NodeCoordinator) void {
        if (self.attempt) |*attempt| attempt.deinit();
        self.attempt = null;
    }

    fn expireAttempt(self: *NodeCoordinator, attempt: *const NodeAttempt) void {
        if (self.control.hasPeer(attempt.local_receiver_id)) self.control.abortSession(attempt.local_receiver_id) catch {
            // Keep the coordinator state until the bounded command queue can
            // accept the matching data-plane removal.
            self.counters.queue_drops +|= 1;
            return;
        };
        self.clearAttempt();
    }

    fn receiveFromControlPlane(context: *anyopaque, endpoint: std.Io.net.IpAddress, datagram: []const u8, now_ns: u64) void {
        const self: *NodeCoordinator = @ptrCast(@alignCast(context));
        self.receive(endpoint, datagram, now_ns) catch |err| switch (err) {
            error.AuthenticationFailed, error.UnexpectedRemoteStatic, error.InvalidDhPublicKey => self.counters.authentication_drops +|= 1,
            else => self.counters.malformed_drops +|= 1,
        };
    }

    fn sessionConfirmed(context: *anyopaque, receiver_session_id: u64, now_ns: u64) void {
        const self: *NodeCoordinator = @ptrCast(@alignCast(context));
        const attempt = self.attempt orelse return;
        if (attempt.local_receiver_id != receiver_session_id) return;
        // XK may be finalized only by the dedicated, strictly authenticated
        // ENROLLMENT_COMPLETE callback below.
        if (attempt.kind == .enrollment) return;
        if (attempt.finalizes_enrollment) {
            if (self.persistence) |persistence| persistence.completeEnrollment(attempt.node_uuid) catch {
                self.counters.persistence_failures +|= 1;
                return;
            };
        }
        self.activateSession(receiver_session_id, now_ns) catch return;
        self.counters.completed +|= 1;
        self.clearAttempt();
    }

    fn enrollmentCompleted(
        context: *anyopaque,
        receiver_session_id: u64,
        node_uuid: [16]u8,
        now_ns: u64,
    ) void {
        const self: *NodeCoordinator = @ptrCast(@alignCast(context));
        const attempt = self.attempt orelse return;
        if (attempt.kind != .enrollment or attempt.local_receiver_id != receiver_session_id) return;
        if (!std.crypto.timing_safe.eql([16]u8, attempt.node_uuid, node_uuid)) return;
        if (self.persistence) |persistence| persistence.completeEnrollment(node_uuid) catch {
            self.counters.persistence_failures +|= 1;
            return;
        };
        self.activateSession(receiver_session_id, now_ns) catch return;
        self.counters.completed +|= 1;
        self.clearAttempt();
    }

    fn activateSession(self: *NodeCoordinator, receiver_session_id: u64, now_ns: u64) !void {
        if (self.active_receiver_id == receiver_session_id) return;
        if (self.active_receiver_id) |previous| self.control.makeReceiveOnly(previous);
        if (self.draining_receiver_id) |oldest| {
            try self.control.abortSession(oldest);
            self.draining_receiver_id = null;
        }
        if (self.active_receiver_id) |previous| {
            self.draining_receiver_id = previous;
            self.drain_deadline_ns = now_ns +| timing.RekeyPolicy.old_receive_drain;
        }
        self.active_receiver_id = receiver_session_id;
    }
};

const MasterPhase = enum { awaiting_final, awaiting_confirmation };

const MasterSlot = struct {
    active: bool = false,
    /// Set by an administrative reset/delete. Revoked slots never retransmit
    /// or activate, and remain allocated only while session retirement is
    /// waiting for the bounded high-priority queue.
    revoked: bool = false,
    kind: AttemptKind = .session,
    phase: MasterPhase = .awaiting_confirmation,
    packet_type: wire.PacketType = .session_handshake,
    context: u64 = 0,
    identity_context: [16]u8 = [_]u8{0} ** 16,
    endpoint: std.Io.net.IpAddress = undefined,
    local_receiver_id: u64 = 0,
    peer_receiver_id: u64 = 0,
    node_uuid: [16]u8 = [_]u8{0} ** 16,
    owner: u128 = 0,
    config_generation: u64 = 0,
    started_ns: u64 = 0,
    enrollment: ?EnrollmentRecord = null,
    xk: ?noise.XkResponder = null,
    request: CachedDatagram = .{},
    response: CachedDatagram = .{},
    retransmission: timing.Retransmission = .{ .deadline = 0 },
    exhaustion_deadline_ns: ?u64 = null,

    fn deinit(self: *MasterSlot) void {
        if (self.xk) |*state| state.deinit();
        if (self.enrollment) |*record| std.crypto.secureZero(u8, &record.psk);
        self.request.clear();
        self.response.clear();
        self.xk = null;
        self.enrollment = null;
        self.active = false;
    }
};

const Association = struct {
    active: bool = false,
    /// A durable in-memory revocation marker. While set, no receiver is
    /// discoverable or replaceable for this Node and all removals are retried.
    revoking: bool = false,
    node_uuid: [16]u8 = [_]u8{0} ** 16,
    current_receiver_id: u64 = 0,
    draining_receiver_id: u64 = 0,
    drain_deadline_ns: u64 = 0,
};

/// Bounded multi-Node Master coordinator. The slot array is allocated once at
/// initialization and no per-handshake allocation occurs thereafter.
pub const MasterCoordinator = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    control: *control_plane.ControlPlane,
    commands: control_plane.CommandSink,
    registry: MasterRegistry,
    session_ready: ?MasterSessionReady,
    master_static: noise.KeyPair,
    retry_policy: ?RetryPolicy,
    slots: []MasterSlot,
    associations: []Association,
    counters: Counters = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        control: *control_plane.ControlPlane,
        commands: control_plane.CommandSink,
        registry: MasterRegistry,
        session_ready: ?MasterSessionReady,
        master_static: noise.KeyPair,
        retry_policy: ?RetryPolicy,
        maximum_inflight: usize,
    ) !MasterCoordinator {
        if (maximum_inflight == 0) return error.InvalidHandshakeCapacity;
        const slots = try allocator.alloc(MasterSlot, maximum_inflight);
        errdefer allocator.free(slots);
        for (slots) |*slot| slot.* = .{};
        const associations = try allocator.alloc(Association, maximum_inflight);
        for (associations) |*association| association.* = .{};
        return .{
            .allocator = allocator,
            .io = io,
            .control = control,
            .commands = commands,
            .registry = registry,
            .session_ready = session_ready,
            .master_static = master_static,
            .retry_policy = retry_policy,
            .slots = slots,
            .associations = associations,
        };
    }

    pub fn deinit(self: *MasterCoordinator) void {
        for (self.slots) |*slot| if (slot.active) slot.deinit();
        self.allocator.free(self.slots);
        self.allocator.free(self.associations);
        std.crypto.secureZero(u8, &self.master_static.secret);
        if (self.retry_policy) |*policy| {
            std.crypto.secureZero(u8, &policy.verifier.current_secret);
            std.crypto.secureZero(u8, &policy.verifier.previous_secret);
        }
        self.* = undefined;
    }

    /// Call after the coordinator is placed at its final address.
    pub fn attach(self: *MasterCoordinator) void {
        self.control.setHandshakeSink(self.handshakeSink());
        self.control.setSessionObserver(self.sessionObserver());
    }

    pub fn handshakeSink(self: *MasterCoordinator) control_plane.HandshakeSink {
        return .{ .context = self, .receive_fn = receiveFromControlPlane };
    }

    pub fn sessionObserver(self: *MasterCoordinator) control_plane.SessionObserver {
        return .{ .context = self, .confirmed_fn = sessionConfirmed };
    }

    pub fn updateRetryPolicy(self: *MasterCoordinator, policy: ?RetryPolicy) void {
        if (self.retry_policy) |*existing| {
            std.crypto.secureZero(u8, &existing.verifier.current_secret);
            std.crypto.secureZero(u8, &existing.verifier.previous_secret);
        }
        self.retry_policy = policy;
    }

    pub fn receive(self: *MasterCoordinator, endpoint: std.Io.net.IpAddress, datagram: []const u8, now_ns: u64) !void {
        if (datagram.len < wire.encoded_len or datagram.len > maximum_handshake_datagram_len) {
            return error.InvalidHandshakeDatagramLength;
        }
        const header = try wire.Header.decode(datagram[0..wire.encoded_len]);
        if (header.packet_type != .enrollment_handshake and header.packet_type != .session_handshake) {
            return error.UnexpectedHandshakePacketType;
        }

        if (self.findContext(header.context)) |slot| {
            if (!endpointEql(endpoint, slot.endpoint) or header.packet_type != slot.packet_type) {
                return error.HandshakeContextCollision;
            }
            if (header.sequence == 0) {
                if (!std.mem.eql(u8, datagram, slot.request.slice())) return error.HandshakeContextCollision;
                try self.sendCached(&slot.response);
                self.counters.retransmissions +|= 1;
                return;
            }
            if (slot.kind == .enrollment and slot.phase == .awaiting_final and header.sequence == 2) {
                return self.finishEnrollment(slot, datagram, now_ns);
            }
            return error.UnexpectedHandshakeMessage;
        }

        if (header.sequence != 0) return error.UnknownHandshakeContext;
        self.counters.initial_requests +|= 1;
        const envelope = try handshake_protocol.Envelope.decode(datagram[wire.encoded_len..]);
        try self.requireValidRetry(endpoint, header.context, envelope);
        if (self.findIdentityAttempt(header.packet_type, envelope.identity_context) != null) {
            self.counters.identity_conflict_drops +|= 1;
            return error.HandshakeIdentityBusy;
        }
        const slot = self.acquireSlot() orelse {
            self.counters.capacity_drops +|= 1;
            return error.HandshakeCapacityExhausted;
        };
        slot.* = .{
            .active = true,
            .kind = if (header.packet_type == .enrollment_handshake) .enrollment else .session,
            .packet_type = header.packet_type,
            .context = header.context,
            .identity_context = envelope.identity_context,
            .endpoint = endpoint,
            .started_ns = now_ns,
            .retransmission = timing.Retransmission.init(now_ns),
        };
        errdefer slot.deinit();
        try slot.request.set(endpoint, datagram);
        switch (header.packet_type) {
            .enrollment_handshake => try self.beginEnrollment(slot, envelope, now_ns),
            .session_handshake => try self.beginSession(slot, envelope, now_ns),
            else => unreachable,
        }
    }

    pub fn tick(self: *MasterCoordinator, now_ns: u64) void {
        for (self.associations) |*association| {
            if (!association.active) continue;
            if (association.revoking) {
                self.retryAssociationReceivers(association);
                continue;
            }
            if (association.draining_receiver_id == 0 or now_ns < association.drain_deadline_ns) continue;
            self.control.abortSession(association.draining_receiver_id) catch {
                self.counters.queue_drops +|= 1;
                continue;
            };
            association.draining_receiver_id = 0;
        }
        for (self.slots) |*slot| {
            if (!slot.active) continue;
            if (slot.revoked) {
                self.expireSlot(slot);
                continue;
            }
            if (now_ns -| slot.started_ns >= handshake_attempt_timeout_ns) {
                self.expireSlot(slot);
                continue;
            }
            if (slot.exhaustion_deadline_ns) |deadline| {
                if (now_ns >= deadline) self.expireSlot(slot);
                continue;
            }
            if (slot.response.length == 0) continue;
            if (!slot.retransmission.onTimer(now_ns)) continue;
            self.sendCached(&slot.response) catch {
                self.counters.queue_drops +|= 1;
            };
            self.counters.retransmissions +|= 1;
            if (slot.retransmission.exhausted()) {
                slot.exhaustion_deadline_ns = now_ns +| retransmission_final_grace_ns;
            }
        }
        for (self.associations) |*association| {
            if (association.active and association.revoking) self.finishRevocationIfComplete(association);
        }
    }

    pub fn activeCount(self: *const MasterCoordinator) usize {
        var count: usize = 0;
        for (self.slots) |slot| if (slot.active) {
            count += 1;
        };
        return count;
    }

    pub fn admissionSnapshot(self: *const MasterCoordinator) AdmissionSnapshot {
        return .{
            .initial_requests = self.counters.initial_requests,
            .authentication_failures = self.counters.authentication_drops +| self.counters.unknown_identity_drops,
        };
    }

    pub fn activeReceiverFor(self: *MasterCoordinator, node_uuid: [16]u8) ?u64 {
        const association = self.findAssociation(node_uuid) orelse return null;
        if (association.revoking) return null;
        return if (association.current_receiver_id == 0) null else association.current_receiver_id;
    }

    pub fn retireAssociation(self: *MasterCoordinator, node_uuid: [16]u8) void {
        const association = self.findAssociation(node_uuid) orelse self.acquireAssociation(node_uuid) orelse {
            self.counters.capacity_drops +|= 1;
            // Capacity should be impossible here because a configured Node
            // reserves one association slot. Still fail closed for any
            // already-known handshake slot if that invariant is violated.
            for (self.slots) |*slot| {
                if (!slot.active or !std.mem.eql(u8, &slot.node_uuid, &node_uuid)) continue;
                slot.revoked = true;
                self.control.makeReceiveOnly(slot.local_receiver_id);
            }
            return;
        };
        association.revoking = true;
        if (association.current_receiver_id != 0) self.control.makeReceiveOnly(association.current_receiver_id);
        if (association.draining_receiver_id != 0) self.control.makeReceiveOnly(association.draining_receiver_id);
        for (self.slots) |*slot| {
            if (!slot.active or !std.mem.eql(u8, &slot.node_uuid, &node_uuid)) continue;
            slot.revoked = true;
            self.control.makeReceiveOnly(slot.local_receiver_id);
        }
        self.retryAssociationReceivers(association);
        for (self.slots) |*slot| {
            if (slot.active and slot.revoked and std.mem.eql(u8, &slot.node_uuid, &node_uuid)) self.expireSlot(slot);
        }
        self.finishRevocationIfComplete(association);
    }

    fn requireValidRetry(
        self: *MasterCoordinator,
        endpoint: std.Io.net.IpAddress,
        context: u64,
        envelope: handshake_protocol.Envelope,
    ) !void {
        const policy = self.retry_policy orelse return;
        const source = toProtocolEndpoint(endpoint);
        if (envelope.retry) |retry| {
            if (policy.verifier.verify(source, context, envelope.identity_context, retry.epoch, retry.tag)) return;
        } else if (!policy.required) {
            return;
        }
        const challenge = cookie_protocol.RetryPayload{
            .epoch = policy.verifier.current_epoch,
            .tag = cookie_protocol.create(
                &policy.verifier.current_secret,
                source,
                context,
                envelope.identity_context,
                policy.verifier.current_epoch,
            ),
        };
        try self.sendRetry(endpoint, context, challenge);
        self.counters.retry_challenges +|= 1;
        return error.RetryRequired;
    }

    fn beginEnrollment(
        self: *MasterCoordinator,
        slot: *MasterSlot,
        envelope: handshake_protocol.Envelope,
        _: u64,
    ) !void {
        var record = self.registry.lookupEnrollment(envelope.identity_context) catch |err| {
            self.counters.unknown_identity_drops +|= 1;
            return err;
        };
        defer std.crypto.secureZero(u8, &record.psk);
        slot.enrollment = record;
        slot.node_uuid = record.node_uuid;
        slot.owner = record.owner;
        slot.config_generation = record.config_generation;
        if (allZero(&record.psk) or allZero(&record.node_uuid)) return error.InvalidEnrollmentRecord;
        if (self.revocationPending(record.node_uuid)) return error.AssociationRevoked;
        if (self.hasOtherNodeAttempt(record.node_uuid, slot)) {
            self.counters.identity_conflict_drops +|= 1;
            return error.HandshakeIdentityBusy;
        }
        slot.local_receiver_id = freshReceiverId(self.control, self.io);
        slot.xk = noise.XkResponder.init(
            self.master_static,
            noise.KeyPair.generate(self.io),
            record.psk,
            envelope.identity_context,
        );
        var payload_storage: [128]u8 = undefined;
        const payload = slot.xk.?.readMessageOne(envelope.noise_message, &payload_storage) catch |err| {
            self.counters.authentication_drops +|= 1;
            return err;
        };
        const request = try handshake_protocol.EnrollmentMessage0.decode(payload);
        if (request.node_receiver_id == 0) return error.InvalidReceiverSessionId;
        slot.peer_receiver_id = request.node_receiver_id;
        const response_payload = (handshake_protocol.EnrollmentMessage1{
            .master_receiver_id = slot.local_receiver_id,
            .node_uuid = record.node_uuid,
            .assigned_ipv4 = record.assigned_ipv4,
            .vnr_network = record.vnr_network,
            .vnr_prefix_len = record.vnr_prefix_len,
            .config_generation = record.config_generation,
        }).encode();
        var response_noise: [maximum_handshake_datagram_len]u8 = undefined;
        const message = try slot.xk.?.writeMessageTwo(&response_payload, &response_noise);
        var response_datagram: [maximum_handshake_datagram_len]u8 = undefined;
        const encoded = try encodeHandshakeDatagram(
            .enrollment_handshake,
            slot.context,
            1,
            slot.identity_context,
            null,
            message,
            &response_datagram,
        );
        try slot.response.set(slot.endpoint, encoded);
        slot.phase = .awaiting_final;
        try self.sendCached(&slot.response);
    }

    fn beginSession(
        self: *MasterCoordinator,
        slot: *MasterSlot,
        envelope: handshake_protocol.Envelope,
        now_ns: u64,
    ) !void {
        const record = self.registry.lookupNode(envelope.identity_context) catch |err| {
            self.counters.unknown_identity_drops +|= 1;
            return err;
        };
        if (!std.mem.eql(u8, &record.node_uuid, &envelope.identity_context)) return error.RegistryIdentityMismatch;
        slot.node_uuid = record.node_uuid;
        slot.owner = record.owner;
        slot.config_generation = record.config_generation;
        if (self.revocationPending(record.node_uuid)) return error.AssociationRevoked;
        if (self.hasOtherNodeAttempt(record.node_uuid, slot)) {
            self.counters.identity_conflict_drops +|= 1;
            return error.HandshakeIdentityBusy;
        }
        slot.local_receiver_id = freshReceiverId(self.control, self.io);
        var responder = noise.IkResponder.init(
            self.master_static,
            noise.KeyPair.generate(self.io),
            record.public_key,
            envelope.identity_context,
        );
        defer responder.deinit();
        var payload_storage: [128]u8 = undefined;
        const payload = responder.readMessageOne(envelope.noise_message, &payload_storage) catch |err| {
            self.counters.authentication_drops +|= 1;
            return err;
        };
        const request = try handshake_protocol.SessionMessage0.decode(payload);
        if (!std.mem.eql(u8, &request.node_uuid, &record.node_uuid)) return error.RegistryIdentityMismatch;
        if (request.node_receiver_id == 0) return error.InvalidReceiverSessionId;
        slot.peer_receiver_id = request.node_receiver_id;
        const response_payload = (handshake_protocol.SessionMessage1{
            .master_receiver_id = slot.local_receiver_id,
            .config_generation = record.config_generation,
        }).encode();
        var response_noise: [maximum_handshake_datagram_len]u8 = undefined;
        const finish = try responder.writeMessageTwo(&response_payload, &response_noise);
        var response_datagram: [maximum_handshake_datagram_len]u8 = undefined;
        const encoded = try encodeHandshakeDatagram(
            .session_handshake,
            slot.context,
            1,
            slot.identity_context,
            null,
            finish.message,
            &response_datagram,
        );
        try slot.response.set(slot.endpoint, encoded);
        slot.phase = .awaiting_confirmation;
        try self.installResponderSession(slot, finish.keys, now_ns);
        // Once the pending session command is queued, retain the slot even if
        // the bounded datagram queue is temporarily full; tick() will resend
        // the already serialized, byte-identical response.
        self.sendCached(&slot.response) catch return;
    }

    fn finishEnrollment(self: *MasterCoordinator, slot: *MasterSlot, datagram: []const u8, now_ns: u64) !void {
        const envelope = try handshake_protocol.Envelope.decode(datagram[wire.encoded_len..]);
        if (!std.mem.eql(u8, &envelope.identity_context, &slot.identity_context) or envelope.retry != null) {
            return error.UnexpectedIdentityContext;
        }
        var payload_storage: [128]u8 = undefined;
        const finish = slot.xk.?.readMessageThree(envelope.noise_message, &payload_storage) catch |err| {
            self.counters.authentication_drops +|= 1;
            return err;
        };
        // Noise message 3 is not replayable after this point. Any subsequent
        // validation, durable binding, or session-install error is terminal
        // for this slot; the Node can recover using authenticated IK if the
        // binding committed, or repeat enrollment if it did not.
        errdefer slot.deinit();
        const completion = try handshake_protocol.EnrollmentMessage2.decode(finish.payload);
        if (!std.mem.eql(u8, &completion.node_uuid, &slot.node_uuid)) return error.RegistryIdentityMismatch;
        const node_public = try slot.xk.?.remoteStatic();
        try self.registry.consumeAndBind(slot.identity_context, slot.node_uuid, node_public);
        slot.xk = null;
        self.installResponderSession(slot, finish.keys, now_ns) catch |err| {
            if (err == error.CommandQueueFull) self.counters.queue_drops +|= 1;
            return err;
        };
        slot.phase = .awaiting_confirmation;
        slot.started_ns = now_ns;
        slot.retransmission = timing.Retransmission.init(now_ns);
        slot.exhaustion_deadline_ns = null;
    }

    fn installResponderSession(
        self: *MasterCoordinator,
        slot: *const MasterSlot,
        keys: noise.DirectionalKeys,
        now_ns: u64,
    ) !void {
        try self.control.registerPendingSession(.{
            .receiver_id = slot.local_receiver_id,
            .peer_receiver_id = slot.peer_receiver_id,
            .owner = slot.owner,
            .tx_key = keys.responder_to_initiator,
            .rx_key = keys.initiator_to_responder,
            .created_ns = now_ns,
            .endpoint = slot.endpoint,
        }, keys.handshake_hash, now_ns);
    }

    fn sendRetry(
        self: *MasterCoordinator,
        endpoint: std.Io.net.IpAddress,
        context: u64,
        retry: cookie_protocol.RetryPayload,
    ) !void {
        var storage: [wire.encoded_len + cookie_protocol.RetryPayload.encoded_len]u8 = undefined;
        const header = try (wire.Header{ .packet_type = .stateless_retry, .context = context, .sequence = 0 }).encode();
        @memcpy(storage[0..wire.encoded_len], &header);
        const payload = retry.encode();
        @memcpy(storage[wire.encoded_len..], &payload);
        if (!self.commands.submit(data_worker.DataCommand.datagram(endpoint, &storage))) {
            self.counters.queue_drops +|= 1;
            return error.CommandQueueFull;
        }
    }

    fn sendCached(self: *MasterCoordinator, cached: *const CachedDatagram) !void {
        if (!self.commands.submit(data_worker.DataCommand.datagram(cached.endpoint, cached.slice()))) {
            self.counters.queue_drops +|= 1;
            return error.CommandQueueFull;
        }
    }

    fn acquireSlot(self: *MasterCoordinator) ?*MasterSlot {
        for (self.slots) |*slot| if (!slot.active) return slot;
        return null;
    }

    fn findContext(self: *MasterCoordinator, context: u64) ?*MasterSlot {
        for (self.slots) |*slot| if (slot.active and slot.context == context) return slot;
        return null;
    }

    fn findIdentityAttempt(
        self: *MasterCoordinator,
        packet_type: wire.PacketType,
        identity_context: [16]u8,
    ) ?*MasterSlot {
        const kind: AttemptKind = switch (packet_type) {
            .enrollment_handshake => .enrollment,
            .session_handshake => .session,
            else => return null,
        };
        for (self.slots) |*slot| {
            if (slot.active and slot.kind == kind and
                std.crypto.timing_safe.eql([16]u8, slot.identity_context, identity_context)) return slot;
        }
        return null;
    }

    fn hasOtherNodeAttempt(
        self: *MasterCoordinator,
        node_uuid: [16]u8,
        current: *const MasterSlot,
    ) bool {
        for (self.slots) |*slot| {
            if (slot == current or !slot.active or allZero(&slot.node_uuid)) continue;
            if (std.crypto.timing_safe.eql([16]u8, slot.node_uuid, node_uuid)) return true;
        }
        return false;
    }

    fn expireSlot(self: *MasterCoordinator, slot: *MasterSlot) void {
        if (self.control.hasPeer(slot.local_receiver_id)) self.control.abortSession(slot.local_receiver_id) catch {
            self.counters.queue_drops +|= 1;
            return;
        };
        slot.deinit();
    }

    fn findReceiver(self: *MasterCoordinator, receiver_session_id: u64) ?*MasterSlot {
        for (self.slots) |*slot| {
            if (slot.active and slot.local_receiver_id == receiver_session_id) return slot;
        }
        return null;
    }

    fn findAssociation(self: *MasterCoordinator, node_uuid: [16]u8) ?*Association {
        for (self.associations) |*association| {
            if (association.active and std.mem.eql(u8, &association.node_uuid, &node_uuid)) return association;
        }
        return null;
    }

    fn acquireAssociation(self: *MasterCoordinator, node_uuid: [16]u8) ?*Association {
        for (self.associations) |*candidate| if (!candidate.active) {
            candidate.* = .{ .active = true, .node_uuid = node_uuid };
            return candidate;
        };
        return null;
    }

    fn revocationPending(self: *MasterCoordinator, node_uuid: [16]u8) bool {
        const association = self.findAssociation(node_uuid) orelse return false;
        return association.revoking;
    }

    fn retryAssociationReceivers(self: *MasterCoordinator, association: *Association) void {
        self.retryReceiverRetirement(&association.current_receiver_id);
        self.retryReceiverRetirement(&association.draining_receiver_id);
    }

    fn retryReceiverRetirement(self: *MasterCoordinator, receiver_session_id: *u64) void {
        if (receiver_session_id.* == 0) return;
        self.control.makeReceiveOnly(receiver_session_id.*);
        self.control.abortSession(receiver_session_id.*) catch |err| switch (err) {
            error.UnknownSession => {
                receiver_session_id.* = 0;
                return;
            },
            else => {
                self.counters.queue_drops +|= 1;
                return;
            },
        };
        receiver_session_id.* = 0;
    }

    fn finishRevocationIfComplete(self: *MasterCoordinator, association: *Association) void {
        if (association.current_receiver_id != 0 or association.draining_receiver_id != 0) return;
        for (self.slots) |slot| {
            if (slot.active and slot.revoked and std.mem.eql(u8, &slot.node_uuid, &association.node_uuid)) return;
        }
        association.* = .{};
    }

    fn activateAssociation(
        self: *MasterCoordinator,
        node_uuid: [16]u8,
        receiver_session_id: u64,
        now_ns: u64,
    ) !void {
        const association = self.findAssociation(node_uuid) orelse
            self.acquireAssociation(node_uuid) orelse return error.AssociationCapacityExhausted;
        if (association.revoking) return error.AssociationRevoked;
        if (association.current_receiver_id == receiver_session_id) return;
        if (association.draining_receiver_id != 0) {
            try self.control.abortSession(association.draining_receiver_id);
            association.draining_receiver_id = 0;
        }
        if (association.current_receiver_id != 0) {
            self.control.makeReceiveOnly(association.current_receiver_id);
            association.draining_receiver_id = association.current_receiver_id;
            association.drain_deadline_ns = now_ns +| timing.RekeyPolicy.old_receive_drain;
        }
        association.current_receiver_id = receiver_session_id;
    }

    fn receiveFromControlPlane(context: *anyopaque, endpoint: std.Io.net.IpAddress, datagram: []const u8, now_ns: u64) void {
        const self: *MasterCoordinator = @ptrCast(@alignCast(context));
        self.receive(endpoint, datagram, now_ns) catch |err| switch (err) {
            error.AuthenticationFailed, error.UnexpectedRemoteStatic, error.InvalidDhPublicKey => self.counters.authentication_drops +|= 1,
            error.NodeNotFound, error.EnrollmentNotFound, error.EnrollmentExpired, error.EnrollmentConsumed => self.counters.unknown_identity_drops +|= 1,
            error.HandshakeCapacityExhausted => {},
            error.HandshakeIdentityBusy => {},
            error.AssociationRevoked => {},
            error.RetryRequired => {},
            else => self.counters.malformed_drops +|= 1,
        };
    }

    fn sessionConfirmed(context: *anyopaque, receiver_session_id: u64, now_ns: u64) void {
        const self: *MasterCoordinator = @ptrCast(@alignCast(context));
        const slot = self.findReceiver(receiver_session_id) orelse return;
        if (slot.revoked or self.revocationPending(slot.node_uuid)) {
            self.expireSlot(slot);
            return;
        }
        self.activateAssociation(slot.node_uuid, receiver_session_id, now_ns) catch {
            self.counters.capacity_drops +|= 1;
            self.control.abortSession(receiver_session_id) catch {};
            slot.deinit();
            return;
        };
        if (self.session_ready) |ready| ready.ready(
            slot.node_uuid,
            receiver_session_id,
            slot.config_generation,
            if (slot.kind == .enrollment) .enrollment else .reconnect_or_rekey,
            now_ns,
        ) catch return;
        switch (slot.kind) {
            .enrollment => self.control.sendEnrollmentComplete(receiver_session_id, slot.node_uuid, now_ns) catch return,
            .session => self.control.sendHeartbeatNow(receiver_session_id, now_ns) catch return,
        }
        self.counters.completed +|= 1;
        slot.deinit();
    }
};

fn encodeHandshakeDatagram(
    packet_type: wire.PacketType,
    context: u64,
    message_index: u64,
    identity_context: [16]u8,
    retry: ?cookie_protocol.RetryPayload,
    noise_message: []const u8,
    out: []u8,
) ![]u8 {
    if (out.len < wire.encoded_len) return error.BufferTooSmall;
    const header = try (wire.Header{
        .packet_type = packet_type,
        .context = context,
        .sequence = message_index,
    }).encode();
    @memcpy(out[0..wire.encoded_len], &header);
    const envelope = try (handshake_protocol.Envelope{
        .identity_context = identity_context,
        .retry = retry,
        .noise_message = noise_message,
    }).encode(out[wire.encoded_len..]);
    return out[0 .. wire.encoded_len + envelope.len];
}

fn randomNonzero(io: std.Io) u64 {
    while (true) {
        var bytes: [8]u8 = undefined;
        io.random(&bytes);
        const value = std.mem.readInt(u64, &bytes, .big);
        if (value != 0) return value;
    }
}

fn freshReceiverId(control: *control_plane.ControlPlane, io: std.Io) u64 {
    while (true) {
        const candidate = randomNonzero(io);
        if (!control.hasPeer(candidate)) return candidate;
    }
}

fn ownerFromUuid(uuid: [16]u8) u128 {
    return std.mem.readInt(u128, &uuid, .big);
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

fn endpointEql(a: std.Io.net.IpAddress, b: std.Io.net.IpAddress) bool {
    return endpoint_protocol.Endpoint.eql(toProtocolEndpoint(a), toProtocolEndpoint(b));
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

const TestCommandSink = struct {
    allocator: std.mem.Allocator,
    commands: std.ArrayList(data_worker.DataCommand) = .empty,
    fail_kind: ?data_worker.DataCommandKind = null,
    failures_remaining: usize = 0,

    fn deinit(self: *TestCommandSink) void {
        self.commands.deinit(self.allocator);
    }

    fn submit(context: *anyopaque, command: data_worker.DataCommand) bool {
        const self: *TestCommandSink = @ptrCast(@alignCast(context));
        if (self.failures_remaining != 0 and self.fail_kind == command.kind) {
            self.failures_remaining -= 1;
            return false;
        }
        self.commands.append(self.allocator, command) catch return false;
        return true;
    }

    fn sink(self: *TestCommandSink) control_plane.CommandSink {
        return .{ .context = self, .submit_fn = submit };
    }

    fn last(self: *const TestCommandSink, kind: data_worker.DataCommandKind) !data_worker.DataCommand {
        var index = self.commands.items.len;
        while (index != 0) {
            index -= 1;
            if (self.commands.items[index].kind == kind) return self.commands.items[index];
        }
        return error.CommandNotFound;
    }

    fn failNext(self: *TestCommandSink, kind: data_worker.DataCommandKind) void {
        self.fail_kind = kind;
        self.failures_remaining = 1;
    }
};

const TestRegistry = struct {
    handle: [16]u8,
    enrollment: EnrollmentRecord,
    consumed: bool = false,
    public_key: [32]u8 = [_]u8{0} ** 32,

    fn interface(self: *TestRegistry) MasterRegistry {
        return .{
            .context = self,
            .lookup_enrollment_fn = lookupEnrollment,
            .consume_and_bind_fn = consumeAndBind,
            .lookup_node_fn = lookupNode,
        };
    }

    fn lookupEnrollment(context: *anyopaque, handle: [16]u8) anyerror!EnrollmentRecord {
        const self: *TestRegistry = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, &handle, &self.handle)) return error.EnrollmentNotFound;
        if (self.consumed) return error.EnrollmentConsumed;
        return self.enrollment;
    }

    fn consumeAndBind(
        context: *anyopaque,
        handle: [16]u8,
        node_uuid: [16]u8,
        public_key: [32]u8,
    ) anyerror!void {
        const self: *TestRegistry = @ptrCast(@alignCast(context));
        if (self.consumed) return error.EnrollmentConsumed;
        if (!std.mem.eql(u8, &handle, &self.handle) or !std.mem.eql(u8, &node_uuid, &self.enrollment.node_uuid)) {
            return error.RegistryIdentityMismatch;
        }
        self.public_key = public_key;
        self.consumed = true;
    }

    fn lookupNode(context: *anyopaque, node_uuid: [16]u8) anyerror!NodeRecord {
        const self: *TestRegistry = @ptrCast(@alignCast(context));
        if (!self.consumed or !std.mem.eql(u8, &node_uuid, &self.enrollment.node_uuid)) return error.NodeNotFound;
        return .{
            .node_uuid = self.enrollment.node_uuid,
            .public_key = self.public_key,
            .config_generation = self.enrollment.config_generation + 1,
            .owner = self.enrollment.owner,
        };
    }
};

const TestPersistence = struct {
    staged: ?EnrollmentAssignment = null,
    completed: bool = false,

    fn interface(self: *TestPersistence) NodePersistence {
        return .{
            .context = self,
            .stage_assignment_fn = stage,
            .complete_enrollment_fn = complete,
        };
    }

    fn stage(context: *anyopaque, assignment: EnrollmentAssignment) anyerror!void {
        const self: *TestPersistence = @ptrCast(@alignCast(context));
        self.staged = assignment;
    }

    fn complete(context: *anyopaque, node_uuid: [16]u8) anyerror!void {
        const self: *TestPersistence = @ptrCast(@alignCast(context));
        const staged = self.staged orelse return error.NoStagedEnrollment;
        if (!std.mem.eql(u8, &staged.node_uuid, &node_uuid)) return error.StagedIdentityMismatch;
        self.completed = true;
    }
};

const TestSessionReady = struct {
    calls: u8 = 0,
    last_node_uuid: [16]u8 = [_]u8{0} ** 16,
    last_generation: u64 = 0,

    fn interface(self: *TestSessionReady) MasterSessionReady {
        return .{ .context = self, .ready_fn = ready };
    }

    fn ready(
        context: *anyopaque,
        node_uuid: [16]u8,
        _: u64,
        generation: u64,
        _: EstablishedKind,
        _: u64,
    ) anyerror!void {
        const self: *TestSessionReady = @ptrCast(@alignCast(context));
        self.calls += 1;
        self.last_node_uuid = node_uuid;
        self.last_generation = generation;
    }
};

fn testKey(fill: u8) !noise.KeyPair {
    var secret = [_]u8{fill} ** 32;
    secret[0] +%= 1;
    return noise.KeyPair.fromSecret(secret);
}

fn testEnrollmentInitial(
    credential: *const credential_protocol.Credential,
    node_static: noise.KeyPair,
    ephemeral_fill: u8,
    context: u64,
    receiver_id: u64,
    out: []u8,
) ![]u8 {
    var psk = credential.derivePsk();
    defer std.crypto.secureZero(u8, &psk);
    var initiator = noise.XkInitiator.init(
        node_static,
        try testKey(ephemeral_fill),
        credential.master_public,
        psk,
        credential.handle,
    );
    defer initiator.deinit();
    const payload = (handshake_protocol.EnrollmentMessage0{ .node_receiver_id = receiver_id }).encode();
    var noise_storage: [maximum_handshake_datagram_len]u8 = undefined;
    const message = try initiator.writeMessageOne(&payload, &noise_storage);
    return encodeHandshakeDatagram(
        .enrollment_handshake,
        context,
        0,
        credential.handle,
        null,
        message,
        out,
    );
}

fn testSessionInitial(
    node_uuid: [16]u8,
    node_static: noise.KeyPair,
    master_public: [32]u8,
    ephemeral_fill: u8,
    context: u64,
    receiver_id: u64,
    out: []u8,
) ![]u8 {
    var initiator = noise.IkInitiator.init(
        node_static,
        try testKey(ephemeral_fill),
        master_public,
        node_uuid,
    );
    defer initiator.deinit();
    const payload = (handshake_protocol.SessionMessage0{
        .node_uuid = node_uuid,
        .node_receiver_id = receiver_id,
    }).encode();
    var noise_storage: [maximum_handshake_datagram_len]u8 = undefined;
    const message = try initiator.writeMessageOne(&payload, &noise_storage);
    return encodeHandshakeDatagram(
        .session_handshake,
        context,
        0,
        node_uuid,
        null,
        message,
        out,
    );
}

test "durable enrollment binding retires the slot when session installation is backpressured" {
    const master_static = try testKey(0x11);
    const node_static = try testKey(0x21);
    const master_endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(49152) };
    const node_endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(52000) };
    const node_uuid = [_]u8{0x31} ** 16;
    const handle = [_]u8{0x41} ** 16;
    var credential = credential_protocol.Credential{
        .handle = handle,
        .secret = [_]u8{0x51} ** 32,
        .master_public = master_static.public,
    };
    defer credential.deinit();
    var registry = TestRegistry{
        .handle = handle,
        .enrollment = .{
            .node_uuid = node_uuid,
            .assigned_ipv4 = .{ 10, 1, 0, 2 },
            .vnr_network = .{ 10, 1, 0, 0 },
            .vnr_prefix_len = 24,
            .config_generation = 1,
            .owner = ownerFromUuid(node_uuid),
            .psk = credential.derivePsk(),
        },
    };
    defer std.crypto.secureZero(u8, &registry.enrollment.psk);
    var persistence = TestPersistence{};

    var node_events = try data_worker.ControlQueue.init(std.testing.allocator, 16);
    defer node_events.deinit();
    var master_events = try data_worker.ControlQueue.init(std.testing.allocator, 16);
    defer master_events.deinit();
    var node_commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer node_commands.deinit();
    var master_commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer master_commands.deinit();
    var node_control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &node_events, node_commands.sink());
    defer node_control.deinit();
    var master_control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &master_events, master_commands.sink());
    defer master_control.deinit();
    var node = NodeCoordinator.init(std.testing.io, &node_control, node_commands.sink(), persistence.interface());
    defer node.deinit();
    node.attach();
    var master = try MasterCoordinator.init(
        std.testing.allocator,
        std.testing.io,
        &master_control,
        master_commands.sink(),
        registry.interface(),
        null,
        master_static,
        null,
        4,
    );
    defer master.deinit();
    master.attach();

    try node.beginEnrollment(master_endpoint, &credential, node_static, 0);
    const initial = try node_commands.last(.send_datagram);
    try master.receive(node_endpoint, initial.payload(), 1);
    const master_receiver_id = master.slots[0].local_receiver_id;
    const response = try master_commands.last(.send_datagram);
    try node.receive(master_endpoint, response.payload(), 2);
    const final = try node_commands.last(.send_datagram);

    master_commands.failNext(.install_session);
    try std.testing.expectError(error.CommandQueueFull, master.receive(node_endpoint, final.payload(), 3));
    try std.testing.expect(registry.consumed);
    try std.testing.expectEqual(node_static.public, registry.public_key);
    try std.testing.expectEqual(@as(usize, 0), master.activeCount());
    try std.testing.expect(!master_control.hasPeer(master_receiver_id));

    // The identical final retransmission is now a bounded unknown-context
    // drop, never a second dereference of the completed and retired XK state.
    try std.testing.expectError(error.UnknownHandshakeContext, master.receive(node_endpoint, final.payload(), 4));

    // The durable binding permits the documented IK recovery path immediately.
    node.cancel();
    try node.beginRecovery(master_endpoint, node_uuid, node_static, master_static.public, 5);
    const recovery = try node_commands.last(.send_datagram);
    try master.receive(node_endpoint, recovery.payload(), 6);
    try std.testing.expectEqual(@as(usize, 1), master.activeCount());
}

test "Master bounds concurrent handshakes by enrollment handle and Node UUID" {
    const master_static = try testKey(0x12);
    const node_static = try testKey(0x22);
    const node_endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(52001) };
    const node_uuid = [_]u8{0x32} ** 16;
    const handle = [_]u8{0x42} ** 16;
    var credential = credential_protocol.Credential{
        .handle = handle,
        .secret = [_]u8{0x52} ** 32,
        .master_public = master_static.public,
    };
    defer credential.deinit();
    var registry = TestRegistry{
        .handle = handle,
        .enrollment = .{
            .node_uuid = node_uuid,
            .assigned_ipv4 = .{ 10, 2, 0, 2 },
            .vnr_network = .{ 10, 2, 0, 0 },
            .vnr_prefix_len = 24,
            .config_generation = 2,
            .owner = ownerFromUuid(node_uuid),
            .psk = credential.derivePsk(),
        },
    };
    defer std.crypto.secureZero(u8, &registry.enrollment.psk);

    var events = try data_worker.ControlQueue.init(std.testing.allocator, 16);
    defer events.deinit();
    var commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer commands.deinit();
    var control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &events, commands.sink());
    defer control.deinit();
    var master = try MasterCoordinator.init(
        std.testing.allocator,
        std.testing.io,
        &control,
        commands.sink(),
        registry.interface(),
        null,
        master_static,
        null,
        4,
    );
    defer master.deinit();

    var enrollment_a_storage: [maximum_handshake_datagram_len]u8 = undefined;
    const enrollment_a = try testEnrollmentInitial(&credential, node_static, 0x62, 0x1001, 0x2001, &enrollment_a_storage);
    var enrollment_b_storage: [maximum_handshake_datagram_len]u8 = undefined;
    const enrollment_b = try testEnrollmentInitial(&credential, node_static, 0x63, 0x1002, 0x2002, &enrollment_b_storage);
    try master.receive(node_endpoint, enrollment_a, 0);
    const first_response = try commands.last(.send_datagram);
    try master.receive(node_endpoint, enrollment_a, 1);
    const cached_response = try commands.last(.send_datagram);
    try std.testing.expectEqualSlices(u8, first_response.payload(), cached_response.payload());
    try std.testing.expectError(error.HandshakeIdentityBusy, master.receive(node_endpoint, enrollment_b, 2));
    try std.testing.expectEqual(@as(usize, 1), master.activeCount());

    // Exhaustion emits all five fixed retransmissions and then retains one
    // final response window before terminating the attempt.
    const retry_times = [_]u64{
        500 * std.time.ns_per_ms,
        1500 * std.time.ns_per_ms,
        3500 * std.time.ns_per_ms,
        7500 * std.time.ns_per_ms,
        15_500 * std.time.ns_per_ms,
    };
    for (retry_times) |now_ns| master.tick(now_ns);
    try std.testing.expectEqual(@as(usize, 1), master.activeCount());
    master.tick(23_500 * std.time.ns_per_ms - 1);
    try std.testing.expectEqual(@as(usize, 1), master.activeCount());
    master.tick(23_500 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 0), master.activeCount());

    registry.consumed = true;
    registry.public_key = node_static.public;
    var session_a_storage: [maximum_handshake_datagram_len]u8 = undefined;
    const session_a = try testSessionInitial(node_uuid, node_static, master_static.public, 0x72, 0x3001, 0x4001, &session_a_storage);
    var session_b_storage: [maximum_handshake_datagram_len]u8 = undefined;
    const session_b = try testSessionInitial(node_uuid, node_static, master_static.public, 0x73, 0x3002, 0x4002, &session_b_storage);
    try master.receive(node_endpoint, session_a, 24 * std.time.ns_per_s);
    const first_session_response = try commands.last(.send_datagram);
    try master.receive(node_endpoint, session_a, 24 * std.time.ns_per_s + 1);
    const cached_session_response = try commands.last(.send_datagram);
    try std.testing.expectEqualSlices(u8, first_session_response.payload(), cached_session_response.payload());
    try std.testing.expectError(
        error.HandshakeIdentityBusy,
        master.receive(node_endpoint, session_b, 24 * std.time.ns_per_s + 2),
    );
    try std.testing.expectEqual(@as(usize, 1), master.activeCount());
    try std.testing.expectEqual(@as(u64, 2), master.counters.identity_conflict_drops);
}

test "administrative revocation survives saturated removal queue and blocks rebind" {
    const master_static = try testKey(0x14);
    const node_uuid = [_]u8{0x34} ** 16;
    var registry = TestRegistry{
        .handle = [_]u8{0x44} ** 16,
        .enrollment = .{
            .node_uuid = node_uuid,
            .assigned_ipv4 = .{ 10, 4, 0, 2 },
            .vnr_network = .{ 10, 4, 0, 0 },
            .vnr_prefix_len = 24,
            .config_generation = 4,
            .owner = ownerFromUuid(node_uuid),
            .psk = [_]u8{0x54} ** 32,
        },
    };
    defer std.crypto.secureZero(u8, &registry.enrollment.psk);
    var events = try data_worker.ControlQueue.init(std.testing.allocator, 16);
    defer events.deinit();
    var commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer commands.deinit();
    var control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &events, commands.sink());
    defer control.deinit();

    inline for (.{ @as(u64, 901), @as(u64, 902) }) |receiver_id| {
        try control.registerPendingSession(.{
            .receiver_id = receiver_id,
            .owner = ownerFromUuid(node_uuid),
            .tx_key = [_]u8{@truncate(receiver_id)} ** 32,
            .rx_key = [_]u8{@truncate(receiver_id + 1)} ** 32,
            .created_ns = 0,
            .endpoint = .{ .ip4 = .loopback(@intCast(49152 + receiver_id - 901)) },
        }, [_]u8{0x64} ** 32, 0);
        try control.confirmAsInitiator(receiver_id, 1);
    }

    var master = try MasterCoordinator.init(
        std.testing.allocator,
        std.testing.io,
        &control,
        commands.sink(),
        registry.interface(),
        null,
        master_static,
        null,
        2,
    );
    defer master.deinit();
    master.associations[0] = .{
        .active = true,
        .node_uuid = node_uuid,
        .current_receiver_id = 901,
    };
    master.slots[0] = .{
        .active = true,
        .node_uuid = node_uuid,
        .local_receiver_id = 902,
    };

    // Refuse both immediate remove commands. Association and handshake state
    // must remain as non-transmitting revocation work, never disappear.
    commands.fail_kind = .remove_session;
    commands.failures_remaining = 2;
    master.retireAssociation(node_uuid);
    try std.testing.expect(master.findAssociation(node_uuid).?.revoking);
    try std.testing.expect(master.slots[0].active);
    try std.testing.expect(master.slots[0].revoked);
    try std.testing.expect(master.activeReceiverFor(node_uuid) == null);
    try std.testing.expectEqual(false, control.peerTransmitEnabled(901).?);
    try std.testing.expectEqual(false, control.peerTransmitEnabled(902).?);
    try std.testing.expectError(error.AssociationRevoked, master.activateAssociation(node_uuid, 903, 2));

    // A later tick retries both retained removals. Only after both are
    // accepted may the revocation marker and pending handshake slot disappear.
    master.tick(3);
    try std.testing.expect(master.findAssociation(node_uuid) == null);
    try std.testing.expect(!master.slots[0].active);
    try std.testing.expect(!control.hasPeer(901));
    try std.testing.expect(!control.hasPeer(902));
}

test "Node terminates an exhausted handshake after the final response window" {
    const master_static = try testKey(0x13);
    const node_static = try testKey(0x23);
    const master_endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(49152) };
    var credential = credential_protocol.Credential{
        .handle = [_]u8{0x43} ** 16,
        .secret = [_]u8{0x53} ** 32,
        .master_public = master_static.public,
    };
    defer credential.deinit();
    var events = try data_worker.ControlQueue.init(std.testing.allocator, 16);
    defer events.deinit();
    var commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer commands.deinit();
    var control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &events, commands.sink());
    defer control.deinit();
    var node = NodeCoordinator.init(std.testing.io, &control, commands.sink(), null);
    defer node.deinit();

    try node.beginEnrollment(master_endpoint, &credential, node_static, 0);
    const retry_times = [_]u64{
        500 * std.time.ns_per_ms,
        1500 * std.time.ns_per_ms,
        3500 * std.time.ns_per_ms,
        7500 * std.time.ns_per_ms,
        15_500 * std.time.ns_per_ms,
    };
    for (retry_times) |now_ns| node.tick(now_ns);
    try std.testing.expect(node.retransmissionsExhausted());
    try std.testing.expect(node.inProgress());
    node.tick(23_500 * std.time.ns_per_ms - 1);
    try std.testing.expect(node.inProgress());
    node.tick(23_500 * std.time.ns_per_ms);
    try std.testing.expect(!node.inProgress());
}

test "bounded XK enrollment and IK reconnect install directional sessions only through confirmation" {
    const master_static = try testKey(0x31);
    const node_static = try testKey(0x41);
    const master_endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(49152) };
    const node_endpoint: std.Io.net.IpAddress = .{ .ip4 = .loopback(52000) };
    const node_uuid = [_]u8{0x77} ** 16;
    const handle = [_]u8{0x22} ** 16;
    var enrollment_credential = credential_protocol.Credential{
        .handle = handle,
        .secret = [_]u8{0x33} ** 32,
        .master_public = master_static.public,
    };
    defer enrollment_credential.deinit();

    var registry = TestRegistry{
        .handle = handle,
        .enrollment = .{
            .node_uuid = node_uuid,
            .assigned_ipv4 = .{ 10, 1, 0, 2 },
            .vnr_network = .{ 10, 1, 0, 0 },
            .vnr_prefix_len = 24,
            .config_generation = 7,
            .owner = ownerFromUuid(node_uuid),
            .psk = enrollment_credential.derivePsk(),
        },
    };
    defer std.crypto.secureZero(u8, &registry.enrollment.psk);
    var persistence = TestPersistence{};
    var ready = TestSessionReady{};

    var node_events = try data_worker.ControlQueue.init(std.testing.allocator, 32);
    defer node_events.deinit();
    var master_events = try data_worker.ControlQueue.init(std.testing.allocator, 32);
    defer master_events.deinit();
    var node_commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer node_commands.deinit();
    var master_commands = TestCommandSink{ .allocator = std.testing.allocator };
    defer master_commands.deinit();
    var node_control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &node_events, node_commands.sink());
    defer node_control.deinit();
    var master_control = control_plane.ControlPlane.init(std.testing.allocator, std.testing.io, &master_events, master_commands.sink());
    defer master_control.deinit();
    var node = NodeCoordinator.init(std.testing.io, &node_control, node_commands.sink(), persistence.interface());
    defer node.deinit();
    node.attach();
    const retry_policy = RetryPolicy{
        .verifier = .{
            .current_secret = [_]u8{0x91} ** 32,
            .previous_secret = [_]u8{0x90} ** 32,
            .current_epoch = 11,
        },
    };
    var master = try MasterCoordinator.init(
        std.testing.allocator,
        std.testing.io,
        &master_control,
        master_commands.sink(),
        registry.interface(),
        ready.interface(),
        master_static,
        retry_policy,
        4,
    );
    defer master.deinit();
    master.attach();

    try node.beginEnrollment(master_endpoint, &enrollment_credential, node_static, 0);
    const first_request = try node_commands.last(.send_datagram);
    node.tick(499 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), node_commands.commands.items.len);
    node.tick(500 * std.time.ns_per_ms);
    const retransmitted = try node_commands.last(.send_datagram);
    try std.testing.expectEqualSlices(u8, first_request.payload(), retransmitted.payload());

    try std.testing.expectError(error.RetryRequired, master.receive(node_endpoint, first_request.payload(), 600 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(usize, 0), master.activeCount());
    const retry = try master_commands.last(.send_datagram);
    try node.receive(master_endpoint, retry.payload(), 700 * std.time.ns_per_ms);
    const retried_request = try node_commands.last(.send_datagram);
    const retried_envelope = try handshake_protocol.Envelope.decode(retried_request.payload()[wire.encoded_len..]);
    try std.testing.expect(retried_envelope.retry != null);

    try master.receive(node_endpoint, retried_request.payload(), 800 * std.time.ns_per_ms);
    try std.testing.expectEqual(@as(usize, 1), master.activeCount());
    const enrollment_response = try master_commands.last(.send_datagram);
    try node.receive(master_endpoint, enrollment_response.payload(), 900 * std.time.ns_per_ms);
    try std.testing.expect(persistence.staged != null);
    try std.testing.expectEqual(node_uuid, persistence.staged.?.node_uuid);
    const node_enrollment_session = try node_commands.last(.install_session);
    try std.testing.expect(!node_enrollment_session.session.confirmed);
    const enrollment_final = try node_commands.last(.send_datagram);
    try master.receive(node_endpoint, enrollment_final.payload(), std.time.ns_per_s);
    try std.testing.expect(registry.consumed);
    try std.testing.expectEqual(node_static.public, registry.public_key);
    const master_enrollment_session = try master_commands.last(.install_session);
    try std.testing.expect(!master_enrollment_session.session.confirmed);
    try std.testing.expectEqual(node_enrollment_session.session.tx_key, master_enrollment_session.session.rx_key);
    try std.testing.expectEqual(node_enrollment_session.session.rx_key, master_enrollment_session.session.tx_key);

    const enrollment_confirm = try node_commands.last(.send_control);
    try std.testing.expect(master_events.push(data_worker.ControlEvent.control(
        master_enrollment_session.session.receiver_id,
        node_endpoint,
        enrollment_confirm.payload(),
    )));
    master_control.poll(std.time.ns_per_s + 1);
    try std.testing.expectEqual(@as(usize, 0), master.activeCount());
    try std.testing.expectEqual(control_plane.PeerState.online, master_control.peerState(master_enrollment_session.session.receiver_id).?);
    const enrollment_complete = try master_commands.last(.send_control);
    try std.testing.expect(node_events.push(data_worker.ControlEvent.control(
        node_enrollment_session.session.receiver_id,
        master_endpoint,
        enrollment_complete.payload(),
    )));
    node_control.poll(std.time.ns_per_s + 2);
    try std.testing.expect(!node.inProgress());
    try std.testing.expect(persistence.completed);

    persistence.completed = false;
    try node.beginRecovery(master_endpoint, node_uuid, node_static, master_static.public, 2 * std.time.ns_per_s);
    const ik_request = try node_commands.last(.send_datagram);
    try std.testing.expectError(error.RetryRequired, master.receive(node_endpoint, ik_request.payload(), 2 * std.time.ns_per_s + 1));
    const ik_retry = try master_commands.last(.send_datagram);
    try node.receive(master_endpoint, ik_retry.payload(), 2 * std.time.ns_per_s + 2);
    const ik_retried_request = try node_commands.last(.send_datagram);
    try master.receive(node_endpoint, ik_retried_request.payload(), 2 * std.time.ns_per_s + 3);
    const ik_response = try master_commands.last(.send_datagram);
    try node.receive(master_endpoint, ik_response.payload(), 2 * std.time.ns_per_s + 4);
    const node_ik_session = try node_commands.last(.install_session);
    const master_ik_session = try master_commands.last(.install_session);
    try std.testing.expect(!node_ik_session.session.confirmed);
    try std.testing.expect(!master_ik_session.session.confirmed);
    try std.testing.expectEqual(node_ik_session.session.tx_key, master_ik_session.session.rx_key);
    try std.testing.expectEqual(node_ik_session.session.rx_key, master_ik_session.session.tx_key);
    // IK initiator authentication is sufficient for the Node to switch its
    // control ownership before SESSION_CONFIRM leaves the command queue. The
    // responder must keep its old session current until that confirmation is
    // authenticated.
    try std.testing.expectEqual(false, node_control.peerTransmitEnabled(node_enrollment_session.session.receiver_id).?);
    try std.testing.expectEqual(true, node_control.peerTransmitEnabled(node_ik_session.session.receiver_id).?);
    try std.testing.expectEqual(node_ik_session.session.receiver_id, node.activeReceiver().?);
    try std.testing.expectEqual(true, master_control.peerTransmitEnabled(master_enrollment_session.session.receiver_id).?);

    const ik_confirm = try node_commands.last(.send_control);
    try std.testing.expect(master_events.push(data_worker.ControlEvent.control(
        master_ik_session.session.receiver_id,
        node_endpoint,
        ik_confirm.payload(),
    )));
    master_control.poll(2 * std.time.ns_per_s + 5);
    try std.testing.expectEqual(@as(usize, 0), master.activeCount());
    const authenticated_heartbeat = try master_commands.last(.send_control);
    try std.testing.expect(node_events.push(data_worker.ControlEvent.control(
        node_ik_session.session.receiver_id,
        master_endpoint,
        authenticated_heartbeat.payload(),
    )));
    node_control.poll(2 * std.time.ns_per_s + 6);
    try std.testing.expect(!node.inProgress());
    try std.testing.expect(persistence.completed);
    try std.testing.expectEqual(@as(u64, 2), node.counters.completed);
    try std.testing.expectEqual(@as(u64, 2), master.counters.completed);
    try std.testing.expectEqual(@as(u8, 2), ready.calls);
    try std.testing.expectEqual(node_uuid, ready.last_node_uuid);
    try std.testing.expectEqual(@as(u64, 8), ready.last_generation);

    // Rekey activation immediately retires both old transmit paths, while the
    // peers and their receive keys remain present until the drain deadline.
    try std.testing.expectEqual(false, node_control.peerTransmitEnabled(node_enrollment_session.session.receiver_id).?);
    try std.testing.expectEqual(false, master_control.peerTransmitEnabled(master_enrollment_session.session.receiver_id).?);
    try std.testing.expectEqual(true, node_control.peerTransmitEnabled(node_ik_session.session.receiver_id).?);
    try std.testing.expectEqual(true, master_control.peerTransmitEnabled(master_ik_session.session.receiver_id).?);
    try std.testing.expectError(
        error.SessionReceiveOnly,
        node_control.sendHeartbeatNow(node_enrollment_session.session.receiver_id, 3 * std.time.ns_per_s),
    );
    try std.testing.expectError(
        error.SessionReceiveOnly,
        master_control.sendHeartbeatNow(master_enrollment_session.session.receiver_id, 3 * std.time.ns_per_s),
    );

    const drained_at = 33 * std.time.ns_per_s;
    node.tick(drained_at);
    master.tick(drained_at);
    try std.testing.expect(!node_control.hasPeer(node_enrollment_session.session.receiver_id));
    try std.testing.expect(!master_control.hasPeer(master_enrollment_session.session.receiver_id));
    try std.testing.expect(node_control.hasPeer(node_ik_session.session.receiver_id));
    try std.testing.expect(master_control.hasPeer(master_ik_session.session.receiver_id));
}
