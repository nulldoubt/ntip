const std = @import("std");

pub const second: u64 = std.time.ns_per_s;
pub const minute: u64 = 60 * second;
pub const hour: u64 = 60 * minute;

pub const retransmission_delays = [5]u64{
    500 * std.time.ns_per_ms,
    1 * second,
    2 * second,
    4 * second,
    8 * second,
};

pub const Retransmission = struct {
    attempt: u8 = 0,
    deadline: u64,

    pub fn init(now: u64) Retransmission {
        return .{ .deadline = now +| retransmission_delays[0] };
    }

    /// Advances only when due. The caller reuses the identical cached
    /// serialized handshake bytes for each returned retransmission.
    pub fn onTimer(self: *Retransmission, now: u64) bool {
        if (self.attempt >= retransmission_delays.len or now < self.deadline) return false;
        self.attempt += 1;
        if (self.attempt < retransmission_delays.len) {
            self.deadline = now +| retransmission_delays[self.attempt];
        }
        return true;
    }

    pub fn exhausted(self: Retransmission) bool {
        return self.attempt >= retransmission_delays.len;
    }
};

pub const RekeyPolicy = struct {
    pub const soft_age = 60 * minute;
    pub const hard_age = 24 * hour;
    pub const soft_datagrams: u64 = @as(u64, 1) << 32;
    pub const hard_datagrams: u64 = @as(u64, 1) << 40;
    pub const old_receive_drain = 30 * second;

    pub fn softDue(started_at: u64, now: u64, sent: u64) bool {
        return elapsed(started_at, now) >= soft_age or sent >= soft_datagrams;
    }

    pub fn hardExpired(started_at: u64, now: u64, sent: u64) bool {
        return elapsed(started_at, now) >= hard_age or sent >= hard_datagrams;
    }
};

pub const RekeyAction = enum { none, begin_full_handshake, hard_expire };
pub const RekeyPhase = enum { active, handshaking, expired };

pub const RekeyTracker = struct {
    phase: RekeyPhase = .active,
    started_at: u64,
    sent_datagrams: u64 = 0,
    previous_receive_until: ?u64 = null,

    pub fn noteSent(self: *RekeyTracker) void {
        self.sent_datagrams +|= 1;
    }

    pub fn evaluate(self: *RekeyTracker, now: u64) RekeyAction {
        if (RekeyPolicy.hardExpired(self.started_at, now, self.sent_datagrams)) {
            self.phase = .expired;
            return .hard_expire;
        }
        if (self.phase == .active and RekeyPolicy.softDue(self.started_at, now, self.sent_datagrams)) {
            self.phase = .handshaking;
            return .begin_full_handshake;
        }
        return .none;
    }

    pub fn complete(self: *RekeyTracker, now: u64) !void {
        if (self.phase != .handshaking) return error.InvalidRekeyState;
        self.phase = .active;
        self.started_at = now;
        self.sent_datagrams = 0;
        self.previous_receive_until = now +| RekeyPolicy.old_receive_drain;
    }

    pub fn previousReceiveKeyAccepted(self: RekeyTracker, now: u64) bool {
        const deadline = self.previous_receive_until orelse return false;
        return now <= deadline;
    }
};

/// A responder must not transmit on freshly split keys until an encrypted
/// SESSION_CONFIRM arrives from the Node on those keys.
pub const SessionActivation = enum {
    awaiting_session_confirm,
    active,
    closed,

    pub fn confirm(self: *SessionActivation) !void {
        if (self.* != .awaiting_session_confirm) return error.InvalidActivationState;
        self.* = .active;
    }

    pub fn mayTransmit(self: SessionActivation) bool {
        return self == .active;
    }

    pub fn close(self: *SessionActivation) void {
        self.* = .closed;
    }
};

pub const LivenessState = enum { online, suspect, offline };

pub const Liveness = struct {
    pub const heartbeat_idle = 15 * second;
    pub const suspect_after = 30 * second;
    pub const offline_after = 45 * second;
    pub const maximum_jitter = 1500 * std.time.ns_per_ms;

    last_authenticated: u64,
    last_outbound_authenticated: u64,

    pub fn heartbeatDue(self: Liveness, now: u64, session_id: u64) bool {
        const base = self.last_outbound_authenticated +| heartbeat_idle;
        const magnitude = jitterMagnitude(session_id);
        const deadline = if ((session_id & 1) == 0)
            base +| magnitude
        else
            base -| magnitude;
        return now >= deadline;
    }

    pub fn state(self: Liveness, now: u64) LivenessState {
        const idle = elapsed(self.last_authenticated, now);
        if (idle >= offline_after) return .offline;
        if (idle >= suspect_after) return .suspect;
        return .online;
    }

    pub fn authenticated(self: *Liveness, now: u64, outbound: bool) void {
        self.last_authenticated = now;
        if (outbound) self.last_outbound_authenticated = now;
    }

    fn jitterMagnitude(session_id: u64) u64 {
        var value = session_id +% 0x9e37_79b9_7f4a_7c15;
        value = (value ^ (value >> 30)) *% 0xbf58_476d_1ce4_e5b9;
        value = (value ^ (value >> 27)) *% 0x94d0_49bb_1331_11eb;
        value ^= value >> 31;
        return value % (maximum_jitter + 1);
    }
};

pub const TrafficState = enum(u2) { cold, warm, hot, saturated };

pub const TrafficSample = struct {
    packets_per_second: u64 = 0,
    bits_per_second: u64 = 0,
    queue_occupancy_percent: u8 = 0,
    backpressure: bool = false,
    dropped: bool = false,
};

pub const TrafficMeter = struct {
    pub const cold_after = 30 * second;
    pub const hot_packets_per_second: u64 = 100_000;
    pub const hot_bits_per_second: u64 = 1_000_000_000;
    pub const saturated_queue_percent: u8 = 80;
    pub const hysteresis = 5 * second;

    current: TrafficState = .cold,
    last_data: ?u64 = null,
    downgrade_candidate: ?TrafficState = null,
    downgrade_since: u64 = 0,

    pub fn observeData(self: *TrafficMeter, now: u64, sample: TrafficSample) TrafficState {
        self.last_data = now;
        return self.update(now, sample);
    }

    pub fn update(self: *TrafficMeter, now: u64, sample: TrafficSample) TrafficState {
        const target = self.desired(now, sample);
        if (@intFromEnum(target) >= @intFromEnum(self.current)) {
            self.current = target;
            self.downgrade_candidate = null;
            return self.current;
        }

        if (target == .cold) {
            self.current = .cold;
            self.downgrade_candidate = null;
            return self.current;
        }
        if (self.downgrade_candidate == null or self.downgrade_candidate.? != target) {
            self.downgrade_candidate = target;
            self.downgrade_since = now;
        } else if (elapsed(self.downgrade_since, now) >= hysteresis) {
            self.current = target;
            self.downgrade_candidate = null;
        }
        return self.current;
    }

    fn desired(self: TrafficMeter, now: u64, sample: TrafficSample) TrafficState {
        if (self.last_data == null or elapsed(self.last_data.?, now) >= cold_after) return .cold;
        if (sample.queue_occupancy_percent >= saturated_queue_percent or sample.backpressure or sample.dropped) return .saturated;
        if (sample.packets_per_second >= hot_packets_per_second or sample.bits_per_second >= hot_bits_per_second) return .hot;
        return .warm;
    }
};

fn elapsed(start: u64, now: u64) u64 {
    return now -| start;
}

test "retransmission, rekey, and liveness boundaries are exact" {
    var retry = Retransmission.init(0);
    try std.testing.expect(!retry.onTimer(499 * std.time.ns_per_ms));
    try std.testing.expect(retry.onTimer(500 * std.time.ns_per_ms));
    try std.testing.expectEqual(@as(u8, 1), retry.attempt);

    try std.testing.expect(RekeyPolicy.softDue(0, RekeyPolicy.soft_age, 0));
    try std.testing.expect(RekeyPolicy.hardExpired(0, RekeyPolicy.hard_age, 0));

    const live = Liveness{ .last_authenticated = 0, .last_outbound_authenticated = 0 };
    try std.testing.expectEqual(LivenessState.online, live.state(29 * second));
    try std.testing.expectEqual(LivenessState.suspect, live.state(30 * second));
    try std.testing.expectEqual(LivenessState.offline, live.state(45 * second));
}

test "full rekey and session confirmation gate activation" {
    var tracker = RekeyTracker{ .started_at = 0 };
    try std.testing.expectEqual(RekeyAction.begin_full_handshake, tracker.evaluate(RekeyPolicy.soft_age));
    try tracker.complete(RekeyPolicy.soft_age + 1);
    try std.testing.expect(tracker.previousReceiveKeyAccepted(RekeyPolicy.soft_age + 1 + 30 * second));
    try std.testing.expect(!tracker.previousReceiveKeyAccepted(RekeyPolicy.soft_age + 2 + 30 * second));

    var activation = SessionActivation.awaiting_session_confirm;
    try std.testing.expect(!activation.mayTransmit());
    try activation.confirm();
    try std.testing.expect(activation.mayTransmit());
    try std.testing.expectError(error.InvalidActivationState, activation.confirm());
}

test "DATA activates traffic and downgrades use hysteresis" {
    var meter = TrafficMeter{};
    try std.testing.expectEqual(TrafficState.warm, meter.observeData(1, .{}));
    try std.testing.expectEqual(TrafficState.hot, meter.observeData(2, .{ .packets_per_second = 100_000 }));
    try std.testing.expectEqual(TrafficState.hot, meter.update(3, .{}));
    try std.testing.expectEqual(TrafficState.warm, meter.update(3 + 5 * second, .{}));
    try std.testing.expectEqual(TrafficState.saturated, meter.observeData(10 * second, .{ .queue_occupancy_percent = 80 }));
    try std.testing.expectEqual(TrafficState.cold, meter.update(40 * second, .{}));
}
