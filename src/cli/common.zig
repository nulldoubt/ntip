const std = @import("std");
const underlay_endpoint = @import("../runtime/endpoint.zig");

pub const ExitCode = enum(u8) {
    success = 0,
    internal_failure = 1,
    usage_or_config = 2,
    conflict_or_not_found = 3,
    daemon_unavailable = 4,
    authentication_or_protocol = 5,
};

pub const OutputFormat = enum {
    text,
    json,
};

pub const Paths = struct {
    config: []const u8,
    state_dir: []const u8,
    runtime_dir: []const u8,

    pub const server_defaults: Paths = .{
        .config = "/etc/ntip/server.json",
        .state_dir = "/var/lib/ntip/server",
        .runtime_dir = "/run/ntip",
    };

    pub const client_defaults: Paths = .{
        .config = "/etc/ntip/client.json",
        .state_dir = "/var/lib/ntip/client",
        .runtime_dir = "/run/ntip",
    };
};

pub fn consumeGlobal(args: []const []const u8, index: *usize, paths: *Paths) !bool {
    if (index.* >= args.len) return false;
    const arg = args[index.*];
    const destination: ?*[]const u8 = if (std.mem.eql(u8, arg, "--config"))
        &paths.config
    else if (std.mem.eql(u8, arg, "--state-dir"))
        &paths.state_dir
    else if (std.mem.eql(u8, arg, "--runtime-dir"))
        &paths.runtime_dir
    else
        null;
    const target = destination orelse return false;
    index.* += 1;
    if (index.* >= args.len or args[index.*].len == 0) return error.MissingOptionValue;
    target.* = args[index.*];
    index.* += 1;
    return true;
}

pub fn parseDuration(text: []const u8) !u64 {
    if (text.len < 2) return error.InvalidDuration;
    const multiplier: u64 = switch (text[text.len - 1]) {
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        else => return error.InvalidDuration,
    };
    const digits = text[0 .. text.len - 1];
    if (digits.len > 1 and digits[0] == '0') return error.InvalidDuration;
    const value = std.fmt.parseInt(u64, digits, 10) catch return error.InvalidDuration;
    if (value == 0) return error.InvalidDuration;
    return std.math.mul(u64, value, multiplier) catch return error.InvalidDuration;
}

pub fn validateEndpoint(endpoint: []const u8) !void {
    _ = underlay_endpoint.parse(endpoint) catch return error.InvalidEndpoint;
}

pub fn parseOutputFlag(args: []const []const u8) !OutputFormat {
    if (args.len == 0) return .text;
    if (args.len == 1 and std.mem.eql(u8, args[0], "--json")) return .json;
    return error.InvalidArguments;
}

test "durations use explicit suffixes and reject overflow" {
    try std.testing.expectEqual(@as(u64, 86_400), try parseDuration("24h"));
    try std.testing.expectError(error.InvalidDuration, parseDuration("24"));
    try std.testing.expectError(error.InvalidDuration, parseDuration("0s"));
    try std.testing.expectError(error.InvalidDuration, parseDuration("18446744073709551615d"));
}

test "endpoint syntax accepts IPv4, DNS and bracketed IPv6" {
    try validateEndpoint("203.0.113.10:49152");
    try validateEndpoint("master.example.test:49152");
    try validateEndpoint("[2001:db8::1]:49152");
    try std.testing.expectError(error.InvalidEndpoint, validateEndpoint("2001:db8::1:49152"));
    try std.testing.expectError(error.InvalidEndpoint, validateEndpoint("example.test:0"));
    try std.testing.expectError(error.InvalidEndpoint, validateEndpoint("bad_host:49152"));
    try std.testing.expectError(error.InvalidEndpoint, validateEndpoint("[not:ipv6]:49152"));
}
