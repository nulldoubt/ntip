const std = @import("std");
const model = @import("../domain/model.zig");
const cli_common = @import("../cli/common.zig");

pub const schema_version: u32 = 1;
pub const max_config_bytes: usize = 1024 * 1024;

pub const TrafficConfig = struct {
    cold_after_seconds: u32 = 30,
    hot_packets_per_second: u64 = 100_000,
    hot_bits_per_second: u64 = 1_000_000_000,
    saturated_queue_percent: u8 = 80,
    hysteresis_seconds: u32 = 5,
};

pub const ServerConfig = struct {
    schema_version: u32,
    listen_port: u16 = 49152,
    tun_name: []const u8 = "ntip0",
    inner_mtu: u16 = 1380,
    heartbeat_idle_seconds: u16 = 15,
    suspect_after_seconds: u16 = 30,
    offline_after_seconds: u16 = 45,
    default_enrollment_lifetime_seconds: u32 = 24 * 60 * 60,
    maximum_nodes: u32 = 4096,
    traffic: TrafficConfig = .{},
};

pub const ClientConfig = struct {
    schema_version: u32,
    master: []const u8,
    node: []const u8,
    /// Lowercase hexadecimal X25519 Master static public key. This is the
    /// identity anchor; DNS is only endpoint discovery.
    master_public_key: []const u8,
    tun_name: []const u8 = "ntip0",
    inner_mtu: u16 = 1380,
};

pub fn decodeServer(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(ServerConfig) {
    if (bytes.len == 0 or bytes.len > max_config_bytes) return error.InvalidConfig;
    const parsed = std.json.parseFromSlice(ServerConfig, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidConfigJson;
    errdefer parsed.deinit();
    if (parsed.value.schema_version != schema_version) return error.UnsupportedSchemaVersion;
    try validateTun(parsed.value.tun_name, parsed.value.inner_mtu);
    if (parsed.value.listen_port == 0) return error.InvalidConfig;
    if (!(parsed.value.heartbeat_idle_seconds < parsed.value.suspect_after_seconds and
        parsed.value.suspect_after_seconds < parsed.value.offline_after_seconds)) return error.InvalidConfig;
    if (parsed.value.default_enrollment_lifetime_seconds == 0) return error.InvalidConfig;
    if (parsed.value.maximum_nodes == 0 or parsed.value.maximum_nodes > 65_536) return error.InvalidConfig;
    const traffic = parsed.value.traffic;
    if (traffic.cold_after_seconds == 0 or traffic.hot_packets_per_second == 0 or
        traffic.hot_bits_per_second == 0 or traffic.saturated_queue_percent == 0 or
        traffic.saturated_queue_percent > 100 or traffic.hysteresis_seconds == 0 or
        traffic.cold_after_seconds > std.math.maxInt(u16) or
        traffic.hysteresis_seconds > std.math.maxInt(u16) or
        traffic.hot_packets_per_second > std.math.maxInt(u32))
    {
        return error.InvalidConfig;
    }
    return parsed;
}

pub fn decodeClient(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(ClientConfig) {
    if (bytes.len == 0 or bytes.len > max_config_bytes) return error.InvalidConfig;
    const parsed = std.json.parseFromSlice(ClientConfig, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidConfigJson;
    errdefer parsed.deinit();
    if (parsed.value.schema_version != schema_version) return error.UnsupportedSchemaVersion;
    cli_common.validateEndpoint(parsed.value.master) catch return error.InvalidConfig;
    _ = model.Name.parse(parsed.value.node) catch return error.InvalidConfig;
    try validateLowerHex(parsed.value.master_public_key, 32);
    try validateTun(parsed.value.tun_name, parsed.value.inner_mtu);
    return parsed;
}

pub fn encodeClient(
    allocator: std.mem.Allocator,
    master: []const u8,
    node: []const u8,
    master_public_key: [32]u8,
) ![]u8 {
    try cli_common.validateEndpoint(master);
    _ = try model.Name.parse(node);
    var any_nonzero = false;
    for (master_public_key) |byte| any_nonzero = any_nonzero or byte != 0;
    if (!any_nonzero) return error.InvalidConfig;
    var public_text: [64]u8 = undefined;
    encodeHex(&master_public_key, &public_text);
    const value = ClientConfig{
        .schema_version = schema_version,
        .master = master,
        .node = node,
        .master_public_key = &public_text,
    };
    var bytes = try std.json.Stringify.valueAlloc(allocator, value, .{ .whitespace = .indent_2 });
    errdefer allocator.free(bytes);
    // Stable config files end with a newline.
    bytes = try allocator.realloc(bytes, bytes.len + 1);
    bytes[bytes.len - 1] = '\n';
    return bytes;
}

pub fn decodePublicKey(text: []const u8) ![32]u8 {
    try validateLowerHex(text, 32);
    var output: [32]u8 = undefined;
    for (&output, 0..) |*byte, index| {
        const high = decodeNibble(text[index * 2]) orelse return error.InvalidConfig;
        const low = decodeNibble(text[index * 2 + 1]) orelse return error.InvalidConfig;
        byte.* = high << 4 | low;
    }
    return output;
}

fn validateTun(name: []const u8, mtu: u16) !void {
    if (name.len == 0 or name.len > 15) return error.InvalidConfig;
    for (name) |c| if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-')) return error.InvalidConfig;
    if (mtu < 576 or mtu > 65_535 - 34) return error.InvalidConfig;
}

fn validateLowerHex(text: []const u8, byte_len: usize) !void {
    if (text.len != byte_len * 2) return error.InvalidConfig;
    var any_nonzero = false;
    for (text) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return error.InvalidConfig;
        any_nonzero = any_nonzero or c != '0';
    }
    if (!any_nonzero) return error.InvalidConfig;
}

fn encodeHex(input: []const u8, output: []u8) void {
    const alphabet = "0123456789abcdef";
    for (input, 0..) |byte, i| {
        output[i * 2] = alphabet[byte >> 4];
        output[i * 2 + 1] = alphabet[byte & 0x0f];
    }
}

fn decodeNibble(value: u8) ?u8 {
    return switch (value) {
        '0'...'9' => value - '0',
        'a'...'f' => value - 'a' + 10,
        else => null,
    };
}

test "server config defaults pin v0.1 operational thresholds" {
    const bytes = "{\"schema_version\":1}";
    const parsed = try decodeServer(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(u16, 49152), parsed.value.listen_port);
    try std.testing.expectEqual(@as(u16, 1380), parsed.value.inner_mtu);
    try std.testing.expectEqual(@as(u16, 15), parsed.value.heartbeat_idle_seconds);
    try std.testing.expectEqual(@as(u16, 45), parsed.value.offline_after_seconds);
}

test "client config is strict and pins Master identity independently of DNS" {
    const bytes =
        \\{"schema_version":1,"master":"master.example:49152","node":"node01","master_public_key":"0100000000000000000000000000000000000000000000000000000000000000"}
    ;
    const parsed = try decodeClient(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("master.example:49152", parsed.value.master);

    const unknown =
        \\{"schema_version":1,"master":"master.example:49152","node":"node01","master_public_key":"0100000000000000000000000000000000000000000000000000000000000000","extra":1}
    ;
    try std.testing.expectError(error.InvalidConfigJson, decodeClient(std.testing.allocator, unknown));
}

test "packaged sample configurations satisfy the strict decoders" {
    const server_bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "packaging/config/server.json",
        std.testing.allocator,
        .limited(max_config_bytes),
    );
    defer std.testing.allocator.free(server_bytes);
    const client_bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "packaging/config/client.json",
        std.testing.allocator,
        .limited(max_config_bytes),
    );
    defer std.testing.allocator.free(client_bytes);
    const server = try decodeServer(std.testing.allocator, server_bytes);
    defer server.deinit();
    const client = try decodeClient(std.testing.allocator, client_bytes);
    defer client.deinit();
    try std.testing.expectEqual(@as(u16, 49152), server.value.listen_port);
    try std.testing.expectEqualStrings("node01", client.value.node);
}
