const std = @import("std");

pub const State = enum {
    cold,
    warm,
    hot,
    saturated,
};

pub const Config = struct {
    cold_after_ns: u64 = 30 * std.time.ns_per_s,
    hot_pps: u64 = 100_000,
    hot_bits_per_second: u64 = 1_000_000_000,
    saturated_queue_percent: u8 = 80,
    hysteresis_ns: u64 = 5 * std.time.ns_per_s,
};

/// Allocation-free telemetry tracker. State labels never alter wire behavior in
/// v0.1; they are observations for operators and future acceleration tiers.
pub const Tracker = struct {
    config: Config = .{},
    state: State = .cold,
    last_data_ns: u64 = 0,
    last_sample_ns: u64 = 0,
    sample_packets: u64 = 0,
    sample_bytes: u64 = 0,
    packets_per_second: u64 = 0,
    bits_per_second: u64 = 0,
    saturated_until_ns: u64 = 0,

    pub fn observeData(self: *Tracker, now_ns: u64, packet_bytes: usize) void {
        self.last_data_ns = now_ns;
        self.sample_packets +|= 1;
        self.sample_bytes +|= packet_bytes;
        if (self.state == .cold) self.state = .warm;
        self.rollSample(now_ns);
        self.recompute(now_ns, 0, 1, false);
    }

    pub fn observeQueue(self: *Tracker, now_ns: u64, occupied: usize, capacity: usize, backpressure: bool) void {
        self.rollSample(now_ns);
        self.recompute(now_ns, occupied, capacity, backpressure);
    }

    pub fn tick(self: *Tracker, now_ns: u64) void {
        self.rollSample(now_ns);
        self.recompute(now_ns, 0, 1, false);
    }

    fn rollSample(self: *Tracker, now_ns: u64) void {
        if (self.last_sample_ns == 0) {
            self.last_sample_ns = now_ns;
            return;
        }
        const elapsed = now_ns -| self.last_sample_ns;
        if (elapsed < std.time.ns_per_s) return;
        self.packets_per_second = perSecond(self.sample_packets, elapsed);
        const bytes_per_second = perSecond(self.sample_bytes, elapsed);
        self.bits_per_second = bytes_per_second *| 8;
        self.sample_packets = 0;
        self.sample_bytes = 0;
        self.last_sample_ns = now_ns;
    }

    fn recompute(self: *Tracker, now_ns: u64, occupied: usize, capacity: usize, backpressure: bool) void {
        const queue_saturated = capacity != 0 and occupied != 0 and
            occupied * 100 >= capacity * @as(usize, self.config.saturated_queue_percent);
        if (backpressure or queue_saturated) {
            self.state = .saturated;
            self.saturated_until_ns = now_ns +| self.config.hysteresis_ns;
            return;
        }
        if (self.state == .saturated and now_ns < self.saturated_until_ns) return;
        if (self.last_data_ns == 0 or now_ns -| self.last_data_ns >= self.config.cold_after_ns) {
            self.state = .cold;
        } else if (self.packets_per_second >= self.config.hot_pps or self.bits_per_second >= self.config.hot_bits_per_second) {
            self.state = .hot;
        } else {
            self.state = .warm;
        }
    }
};

fn perSecond(value: u64, elapsed_ns: u64) u64 {
    if (elapsed_ns == 0) return 0;
    const scaled: u128 = @as(u128, value) * std.time.ns_per_s;
    return @intCast(@min(scaled / elapsed_ns, std.math.maxInt(u64)));
}

test "data activates cold tracker and inactivity returns it to cold" {
    var tracker: Tracker = .{};
    tracker.observeData(std.time.ns_per_s, 100);
    try std.testing.expectEqual(State.warm, tracker.state);
    tracker.tick(31 * std.time.ns_per_s);
    try std.testing.expectEqual(State.cold, tracker.state);
}

test "saturation has five second hysteresis" {
    var tracker: Tracker = .{};
    tracker.observeData(std.time.ns_per_s, 100);
    tracker.observeQueue(2 * std.time.ns_per_s, 8, 10, false);
    try std.testing.expectEqual(State.saturated, tracker.state);
    tracker.observeQueue(6 * std.time.ns_per_s, 0, 10, false);
    try std.testing.expectEqual(State.saturated, tracker.state);
    tracker.observeQueue(7 * std.time.ns_per_s, 0, 10, false);
    try std.testing.expectEqual(State.warm, tracker.state);
}
