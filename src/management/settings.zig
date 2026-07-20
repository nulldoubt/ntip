const std = @import("std");

pub const minimum_enrollment_lifetime_seconds: u32 = 60;
pub const maximum_enrollment_lifetime_seconds: u32 = 30 * 24 * 60 * 60;
pub const maximum_traffic_hysteresis_seconds: u32 = 60 * 60;

pub const RevisionStatus = enum {
    pending_apply,
    active,
    failed,
    pending_restart,
};

pub const OperationalSettings = struct {
    inner_mtu: u16 = 1380,
    heartbeat_idle_seconds: u16 = 15,
    suspect_after_seconds: u16 = 30,
    offline_after_seconds: u16 = 45,
    default_enrollment_lifetime_seconds: u32 = 24 * 60 * 60,
    maximum_nodes: u32 = 4096,
    traffic_cold_after_seconds: u32 = 30,
    traffic_hot_packets_per_second: u64 = 100_000,
    traffic_hot_bits_per_second: u64 = 1_000_000_000,
    traffic_saturated_queue_percent: u8 = 80,
    traffic_hysteresis_seconds: u32 = 5,
    runtime_event_retention_days: u16 = 90,
    connectivity_result_retention_days: u16 = 30,

    pub fn validate(self: OperationalSettings, current_node_count: usize) error{InvalidSettings}!void {
        if (self.inner_mtu < 576 or self.inner_mtu > 65_535 - 34) return error.InvalidSettings;
        if (self.heartbeat_idle_seconds == 0 or
            !(self.heartbeat_idle_seconds < self.suspect_after_seconds and
                self.suspect_after_seconds < self.offline_after_seconds)) return error.InvalidSettings;
        if (self.default_enrollment_lifetime_seconds < minimum_enrollment_lifetime_seconds or
            self.default_enrollment_lifetime_seconds > maximum_enrollment_lifetime_seconds)
        {
            return error.InvalidSettings;
        }
        if (self.maximum_nodes == 0 or self.maximum_nodes > 65_536) return error.InvalidSettings;
        if (self.maximum_nodes < current_node_count) return error.InvalidSettings;
        if (self.traffic_cold_after_seconds == 0 or
            self.traffic_hot_packets_per_second == 0 or
            self.traffic_hot_packets_per_second > std.math.maxInt(u32) or
            self.traffic_hot_bits_per_second == 0 or
            self.traffic_hot_bits_per_second > std.math.maxInt(i64) or
            self.traffic_saturated_queue_percent == 0 or
            self.traffic_saturated_queue_percent > 100 or
            self.traffic_hysteresis_seconds == 0 or
            self.traffic_cold_after_seconds > std.math.maxInt(u16) or
            self.traffic_hysteresis_seconds > maximum_traffic_hysteresis_seconds) return error.InvalidSettings;
        if (!validRetention(self.runtime_event_retention_days) or
            !validRetention(self.connectivity_result_retention_days)) return error.InvalidSettings;
    }
};

pub const ApplyPlan = struct {
    live_change: bool,
    restart_change: bool,

    pub fn initialStatus(self: ApplyPlan) RevisionStatus {
        if (self.live_change) return .pending_apply;
        if (self.restart_change) return .pending_restart;
        return .active;
    }

    pub fn afterLiveApply(self: ApplyPlan) RevisionStatus {
        return if (self.restart_change) .pending_restart else .active;
    }
};

pub fn classify(previous: OperationalSettings, desired: OperationalSettings) ApplyPlan {
    return .{
        .live_change = previous.inner_mtu != desired.inner_mtu or
            previous.heartbeat_idle_seconds != desired.heartbeat_idle_seconds or
            previous.suspect_after_seconds != desired.suspect_after_seconds or
            previous.offline_after_seconds != desired.offline_after_seconds or
            previous.default_enrollment_lifetime_seconds != desired.default_enrollment_lifetime_seconds or
            previous.traffic_cold_after_seconds != desired.traffic_cold_after_seconds or
            previous.traffic_hot_packets_per_second != desired.traffic_hot_packets_per_second or
            previous.traffic_hot_bits_per_second != desired.traffic_hot_bits_per_second or
            previous.traffic_saturated_queue_percent != desired.traffic_saturated_queue_percent or
            previous.traffic_hysteresis_seconds != desired.traffic_hysteresis_seconds or
            previous.runtime_event_retention_days != desired.runtime_event_retention_days or
            previous.connectivity_result_retention_days != desired.connectivity_result_retention_days,
        .restart_change = previous.maximum_nodes != desired.maximum_nodes,
    };
}

pub fn liveProjection(desired: OperationalSettings, restart_effective: OperationalSettings) OperationalSettings {
    var projected = desired;
    projected.maximum_nodes = restart_effective.maximum_nodes;
    return projected;
}

fn validRetention(days: u16) bool {
    return days >= 1 and days <= 3650;
}

test "operational defaults match the accepted v0.2 policy" {
    const defaults = OperationalSettings{};
    try defaults.validate(0);
    try std.testing.expectEqual(@as(u16, 1380), defaults.inner_mtu);
    try std.testing.expectEqual(@as(u16, 90), defaults.runtime_event_retention_days);
    try std.testing.expectEqual(@as(u16, 30), defaults.connectivity_result_retention_days);
}

test "settings validation cross-checks thresholds and inventory capacity" {
    var settings = OperationalSettings{};
    settings.suspect_after_seconds = settings.heartbeat_idle_seconds;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.maximum_nodes = 2;
    try std.testing.expectError(error.InvalidSettings, settings.validate(3));

    settings = .{};
    settings.runtime_event_retention_days = 0;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.default_enrollment_lifetime_seconds = minimum_enrollment_lifetime_seconds - 1;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.default_enrollment_lifetime_seconds = maximum_enrollment_lifetime_seconds + 1;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.heartbeat_idle_seconds = 0;
    settings.suspect_after_seconds = 1;
    settings.offline_after_seconds = 2;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.traffic_hot_bits_per_second = @as(u64, std.math.maxInt(i64)) + 1;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.traffic_hysteresis_seconds = maximum_traffic_hysteresis_seconds + 1;
    try std.testing.expectError(error.InvalidSettings, settings.validate(0));

    settings = .{};
    settings.heartbeat_idle_seconds = 1;
    settings.suspect_after_seconds = 2;
    settings.offline_after_seconds = 3;
    settings.default_enrollment_lifetime_seconds = minimum_enrollment_lifetime_seconds;
    settings.traffic_hot_bits_per_second = std.math.maxInt(i64);
    settings.traffic_hysteresis_seconds = maximum_traffic_hysteresis_seconds;
    try settings.validate(0);
}

test "live settings apply independently while capacity waits for restart" {
    const previous = OperationalSettings{};
    var desired = previous;
    desired.inner_mtu = 1400;
    desired.maximum_nodes = 8192;
    const plan = classify(previous, desired);
    try std.testing.expect(plan.live_change);
    try std.testing.expect(plan.restart_change);
    try std.testing.expectEqual(RevisionStatus.pending_apply, plan.initialStatus());
    try std.testing.expectEqual(RevisionStatus.pending_restart, plan.afterLiveApply());

    const projected = liveProjection(desired, previous);
    try std.testing.expectEqual(@as(u16, 1400), projected.inner_mtu);
    try std.testing.expectEqual(@as(u32, 4096), projected.maximum_nodes);
}
