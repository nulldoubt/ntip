const std = @import("std");

pub const schema_version: u16 = 1;
pub const header_len: usize = 64;
pub const entry_len: usize = 8;
pub const maximum_entries: usize = 8192;
pub const maximum_snapshot_len: usize = header_len + maximum_entries * entry_len;

pub const RouteKind = enum(u8) {
    vnr = 0,
    routed_prefix = 1,
    /// A routed prefix owned by the receiving Node. It is accepted as a
    /// destination from the Master but is not installed back through ntip0.
    local_routed_prefix = 2,

    fn fromByte(value: u8) !RouteKind {
        return switch (value) {
            0 => .vnr,
            1 => .routed_prefix,
            2 => .local_routed_prefix,
            else => error.UnknownConfigurationRouteKind,
        };
    }
};

pub const Route = struct {
    network: [4]u8,
    prefix_len: u8,
    kind: RouteKind,
};

pub const Snapshot = struct {
    node_uuid: [16]u8,
    own_address: [4]u8,
    own_vnr_network: [4]u8,
    own_vnr_prefix_len: u8,
    master_address: [4]u8,
    inner_mtu: u16,
    heartbeat_seconds: u16,
    suspect_seconds: u16,
    offline_seconds: u16,
    cold_seconds: u16,
    hysteresis_seconds: u16,
    hot_packets_per_second: u32,
    hot_bits_per_second: u64,
    saturated_queue_percent: u8,
    routes: []const Route,

    pub fn encode(self: Snapshot, out: []u8) ![]u8 {
        try validate(self);
        const needed = header_len + self.routes.len * entry_len;
        if (out.len < needed) return error.BufferTooSmall;

        std.mem.writeInt(u16, out[0..2], schema_version, .big);
        @memset(out[2..4], 0);
        @memcpy(out[4..20], &self.node_uuid);
        @memcpy(out[20..24], &self.own_address);
        @memcpy(out[24..28], &self.own_vnr_network);
        out[28] = self.own_vnr_prefix_len;
        @memset(out[29..32], 0);
        @memcpy(out[32..36], &self.master_address);
        std.mem.writeInt(u16, out[36..38], self.inner_mtu, .big);
        std.mem.writeInt(u16, out[38..40], self.heartbeat_seconds, .big);
        std.mem.writeInt(u16, out[40..42], self.suspect_seconds, .big);
        std.mem.writeInt(u16, out[42..44], self.offline_seconds, .big);
        std.mem.writeInt(u16, out[44..46], self.cold_seconds, .big);
        std.mem.writeInt(u16, out[46..48], self.hysteresis_seconds, .big);
        std.mem.writeInt(u32, out[48..52], self.hot_packets_per_second, .big);
        std.mem.writeInt(u64, out[52..60], self.hot_bits_per_second, .big);
        out[60] = self.saturated_queue_percent;
        out[61] = 0;
        std.mem.writeInt(u16, out[62..64], @intCast(self.routes.len), .big);

        for (self.routes, 0..) |route, index| {
            const offset = header_len + index * entry_len;
            @memcpy(out[offset .. offset + 4], &route.network);
            out[offset + 4] = route.prefix_len;
            out[offset + 5] = @intFromEnum(route.kind);
            @memset(out[offset + 6 .. offset + 8], 0);
        }
        return out[0..needed];
    }
};

/// A validated zero-allocation snapshot view. It borrows `bytes`; route entries
/// are decoded on demand and remain bounded by `maximum_entries`.
pub const View = struct {
    bytes: []const u8,
    node_uuid: [16]u8,
    own_address: [4]u8,
    own_vnr_network: [4]u8,
    own_vnr_prefix_len: u8,
    master_address: [4]u8,
    inner_mtu: u16,
    heartbeat_seconds: u16,
    suspect_seconds: u16,
    offline_seconds: u16,
    cold_seconds: u16,
    hysteresis_seconds: u16,
    hot_packets_per_second: u32,
    hot_bits_per_second: u64,
    saturated_queue_percent: u8,
    route_count: u16,

    pub fn decode(bytes: []const u8) !View {
        if (bytes.len < header_len or bytes.len > maximum_snapshot_len) return error.InvalidConfigurationLength;
        if (std.mem.readInt(u16, bytes[0..2], .big) != schema_version) return error.UnsupportedConfigurationSchema;
        if (!allZero(bytes[2..4]) or !allZero(bytes[29..32]) or bytes[61] != 0) return error.NonzeroConfigurationReserved;
        const route_count = std.mem.readInt(u16, bytes[62..64], .big);
        if (route_count > maximum_entries) return error.TooManyConfigurationRoutes;
        if (bytes.len != header_len + @as(usize, route_count) * entry_len) return error.InvalidConfigurationLength;

        const view = View{
            .bytes = bytes,
            .node_uuid = bytes[4..20].*,
            .own_address = bytes[20..24].*,
            .own_vnr_network = bytes[24..28].*,
            .own_vnr_prefix_len = bytes[28],
            .master_address = bytes[32..36].*,
            .inner_mtu = std.mem.readInt(u16, bytes[36..38], .big),
            .heartbeat_seconds = std.mem.readInt(u16, bytes[38..40], .big),
            .suspect_seconds = std.mem.readInt(u16, bytes[40..42], .big),
            .offline_seconds = std.mem.readInt(u16, bytes[42..44], .big),
            .cold_seconds = std.mem.readInt(u16, bytes[44..46], .big),
            .hysteresis_seconds = std.mem.readInt(u16, bytes[46..48], .big),
            .hot_packets_per_second = std.mem.readInt(u32, bytes[48..52], .big),
            .hot_bits_per_second = std.mem.readInt(u64, bytes[52..60], .big),
            .saturated_queue_percent = bytes[60],
            .route_count = route_count,
        };
        try view.validateDecoded();
        return view;
    }

    pub fn route(self: View, index: usize) !Route {
        if (index >= self.route_count) return error.ConfigurationRouteOutOfBounds;
        const offset = header_len + index * entry_len;
        if (!allZero(self.bytes[offset + 6 .. offset + 8])) return error.NonzeroConfigurationReserved;
        return .{
            .network = self.bytes[offset..][0..4].*,
            .prefix_len = self.bytes[offset + 4],
            .kind = try RouteKind.fromByte(self.bytes[offset + 5]),
        };
    }

    fn validateDecoded(self: View) !void {
        if (allZero(&self.node_uuid)) return error.InvalidConfigurationIdentity;
        try validateLocal(self.own_address, self.own_vnr_network, self.own_vnr_prefix_len, self.master_address);
        try validateTiming(self.inner_mtu, self.heartbeat_seconds, self.suspect_seconds, self.offline_seconds, self.cold_seconds, self.hysteresis_seconds, self.hot_packets_per_second, self.hot_bits_per_second, self.saturated_queue_percent);

        var previous_end: ?u64 = null;
        var previous: ?Route = null;
        var contains_own_vnr = false;
        const own_network = self.own_vnr_network;
        var index: usize = 0;
        while (index < self.route_count) : (index += 1) {
            const item = try self.route(index);
            const interval = try validateRoute(item);
            if (previous) |prior| {
                if (!lessThan(prior, item)) return error.UnsortedConfigurationRoutes;
            }
            if (previous_end) |end| {
                if (interval.start <= end) return error.OverlappingConfigurationRoutes;
            }
            if (item.kind == .vnr and item.prefix_len == self.own_vnr_prefix_len and
                std.mem.eql(u8, &item.network, &own_network))
            {
                contains_own_vnr = true;
            }
            previous = item;
            previous_end = interval.end;
        }
        if (!contains_own_vnr) return error.MissingOwnVnrRoute;
    }
};

fn validate(snapshot: Snapshot) !void {
    if (snapshot.routes.len > maximum_entries) return error.TooManyConfigurationRoutes;
    if (allZero(&snapshot.node_uuid)) return error.InvalidConfigurationIdentity;
    try validateLocal(snapshot.own_address, snapshot.own_vnr_network, snapshot.own_vnr_prefix_len, snapshot.master_address);
    try validateTiming(snapshot.inner_mtu, snapshot.heartbeat_seconds, snapshot.suspect_seconds, snapshot.offline_seconds, snapshot.cold_seconds, snapshot.hysteresis_seconds, snapshot.hot_packets_per_second, snapshot.hot_bits_per_second, snapshot.saturated_queue_percent);

    var previous_end: ?u64 = null;
    var previous: ?Route = null;
    var contains_own_vnr = false;
    const own_network = snapshot.own_vnr_network;
    for (snapshot.routes) |item| {
        const interval = try validateRoute(item);
        if (previous) |prior| {
            if (!lessThan(prior, item)) return error.UnsortedConfigurationRoutes;
        }
        if (previous_end) |end| {
            if (interval.start <= end) return error.OverlappingConfigurationRoutes;
        }
        if (item.kind == .vnr and item.prefix_len == snapshot.own_vnr_prefix_len and
            std.mem.eql(u8, &item.network, &own_network))
        {
            contains_own_vnr = true;
        }
        previous = item;
        previous_end = interval.end;
    }
    if (!contains_own_vnr) return error.MissingOwnVnrRoute;
}

fn validateLocal(own_address: [4]u8, own_network_bytes: [4]u8, prefix_len: u8, master_address: [4]u8) !void {
    if (prefix_len < 1 or prefix_len > 30) return error.InvalidOwnVnrPrefix;
    const own = addressInt(own_address);
    const canonical_network = canonicalNetwork(own_address, prefix_len);
    if (!std.mem.eql(u8, &canonical_network, &own_network_bytes)) return error.InvalidOwnVnrNetwork;
    const network = addressInt(own_network_bytes);
    const broadcast = network | ~prefixMask(prefix_len);
    const master = addressInt(master_address);
    if (master != network + 1) return error.InvalidMasterAddress;
    if (own <= master or own >= broadcast) return error.InvalidAssignedAddress;
}

fn validateTiming(mtu: u16, heartbeat: u16, suspect: u16, offline: u16, cold: u16, hysteresis: u16, hot_pps: u32, hot_bps: u64, saturated_percent: u8) !void {
    if (mtu < 576 or mtu > 9000) return error.InvalidInnerMtu;
    if (heartbeat == 0 or heartbeat >= suspect or suspect >= offline) return error.InvalidLivenessTiming;
    if (cold == 0 or hysteresis == 0 or hot_pps == 0 or hot_bps == 0 or saturated_percent == 0 or saturated_percent > 100) {
        return error.InvalidTrafficThresholds;
    }
}

const Interval = struct { start: u64, end: u64 };

fn validateRoute(route: Route) !Interval {
    if (route.prefix_len < 1 or route.prefix_len > 32) return error.InvalidConfigurationPrefix;
    const address = addressInt(route.network);
    const mask = prefixMask(route.prefix_len);
    if ((address & mask) != address) return error.NonCanonicalConfigurationPrefix;
    return .{ .start = address, .end = address | ~@as(u64, mask) & 0xffff_ffff };
}

fn lessThan(a: Route, b: Route) bool {
    const a_network = addressInt(a.network);
    const b_network = addressInt(b.network);
    if (a_network != b_network) return a_network < b_network;
    if (a.prefix_len != b.prefix_len) return a.prefix_len < b.prefix_len;
    return @intFromEnum(a.kind) < @intFromEnum(b.kind);
}

fn canonicalNetwork(address: [4]u8, prefix_len: u8) [4]u8 {
    var out: [4]u8 = undefined;
    std.mem.writeInt(u32, &out, addressInt(address) & prefixMask(prefix_len), .big);
    return out;
}

fn prefixMask(prefix_len: u8) u32 {
    if (prefix_len == 0) return 0;
    return @as(u32, std.math.maxInt(u32)) << @as(u5, @intCast(32 - prefix_len));
}

fn addressInt(address: [4]u8) u32 {
    return std.mem.readInt(u32, &address, .big);
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

test "configuration snapshot round trips without allocation" {
    const routes = [_]Route{
        .{ .network = .{ 10, 1, 0, 0 }, .prefix_len = 24, .kind = .vnr },
        .{ .network = .{ 10, 2, 0, 0 }, .prefix_len = 24, .kind = .vnr },
        .{ .network = .{ 192, 168, 178, 0 }, .prefix_len = 24, .kind = .routed_prefix },
    };
    const snapshot = Snapshot{
        .node_uuid = [_]u8{1} ** 16,
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
        .routes = &routes,
    };
    var bytes: [maximum_snapshot_len]u8 = undefined;
    const encoded = try snapshot.encode(&bytes);
    try std.testing.expectEqual(@as(usize, 64 + 3 * 8), encoded.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x86, 0xa0 }, encoded[48..52]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0x3b, 0x9a, 0xca, 0x00 }, encoded[52..60]);
    try std.testing.expectEqual(@as(u8, 0), encoded[64 + 5]);
    try std.testing.expectEqual(@as(u8, 1), encoded[64 + 2 * 8 + 5]);
    const view = try View.decode(encoded);
    try std.testing.expectEqual(snapshot.node_uuid, view.node_uuid);
    try std.testing.expectEqual(snapshot.routes[2], try view.route(2));
}

test "configuration snapshot rejects reserved, unsorted, overlap, and noncanonical data" {
    const own = Route{ .network = .{ 10, 1, 0, 0 }, .prefix_len = 24, .kind = .vnr };
    var routes = [_]Route{own};
    var snapshot = Snapshot{
        .node_uuid = [_]u8{1} ** 16,
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
        .routes = &routes,
    };
    var bytes: [maximum_snapshot_len]u8 = undefined;
    const encoded = try snapshot.encode(&bytes);
    bytes[2] = 1;
    try std.testing.expectError(error.NonzeroConfigurationReserved, View.decode(encoded));
    bytes[2] = 0;

    routes[0].network = .{ 10, 1, 0, 1 };
    try std.testing.expectError(error.NonCanonicalConfigurationPrefix, snapshot.encode(&bytes));
    routes[0] = own;

    const overlapping = [_]Route{
        own,
        .{ .network = .{ 10, 1, 0, 128 }, .prefix_len = 25, .kind = .routed_prefix },
    };
    snapshot.routes = &overlapping;
    try std.testing.expectError(error.OverlappingConfigurationRoutes, snapshot.encode(&bytes));
}
