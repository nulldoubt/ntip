const std = @import("std");

pub const Kind = enum { ipv4, ipv6, dns };

pub const Spec = struct {
    host: []const u8,
    port: u16,
    kind: Kind,

    pub fn resolve(self: Spec, io: std.Io) !std.Io.net.IpAddress {
        return std.Io.net.IpAddress.resolve(io, self.host, self.port);
    }
};

pub fn parse(text: []const u8) !Spec {
    if (text.len == 0) return error.InvalidEndpoint;
    if (text[0] == '[') return parseBracketedIpv6(text);

    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse return error.MissingPort;
    if (std.mem.indexOfScalar(u8, text[0..colon], ':') != null) return error.Ipv6RequiresBrackets;
    const host = text[0..colon];
    if (host.len == 0) return error.InvalidHost;
    const port = try parsePort(text[colon + 1 ..]);

    if (std.Io.net.IpAddress.parseIp4(host, port)) |_| {
        return .{ .host = host, .port = port, .kind = .ipv4 };
    } else |_| {}
    if (!validDnsName(host)) return error.InvalidHost;
    return .{ .host = host, .port = port, .kind = .dns };
}

fn parseBracketedIpv6(text: []const u8) !Spec {
    const closing = std.mem.indexOfScalar(u8, text, ']') orelse return error.InvalidEndpoint;
    if (closing <= 1 or closing + 2 > text.len or text[closing + 1] != ':') return error.InvalidEndpoint;
    const host = text[1..closing];
    const port = try parsePort(text[closing + 2 ..]);
    _ = std.Io.net.IpAddress.parseIp6(host, port) catch return error.InvalidHost;
    return .{ .host = host, .port = port, .kind = .ipv6 };
}

fn parsePort(text: []const u8) !u16 {
    if (text.len == 0) return error.MissingPort;
    const port = std.fmt.parseInt(u16, text, 10) catch return error.InvalidPort;
    if (port == 0) return error.InvalidPort;
    return port;
}

fn validDnsName(host: []const u8) bool {
    if (host.len == 0 or host.len > 253 or host[0] == '.' or host[host.len - 1] == '.') return false;
    var label_len: usize = 0;
    var label_start = true;
    var previous: u8 = 0;
    for (host) |byte| {
        if (byte == '.') {
            if (label_len == 0 or label_len > 63 or previous == '-') return false;
            label_len = 0;
            label_start = true;
            previous = byte;
            continue;
        }
        if (label_start and byte == '-') return false;
        label_start = false;
        label_len += 1;
        previous = byte;
        switch (byte) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return false,
        }
    }
    return label_len != 0 and label_len <= 63 and host[host.len - 1] != '-';
}

test "endpoint parser accepts IPv4 DNS and bracketed IPv6" {
    try std.testing.expectEqual(Kind.ipv4, (try parse("203.0.113.10:49152")).kind);
    try std.testing.expectEqual(Kind.dns, (try parse("master.example:49152")).kind);
    const ip6 = try parse("[2001:db8::1]:49152");
    try std.testing.expectEqual(Kind.ipv6, ip6.kind);
    try std.testing.expectEqual(@as(u16, 49152), ip6.port);
}

test "endpoint parser rejects ambiguous or unsafe text" {
    try std.testing.expectError(error.Ipv6RequiresBrackets, parse("2001:db8::1:49152"));
    try std.testing.expectError(error.InvalidPort, parse("master.example:0"));
    try std.testing.expectError(error.InvalidHost, parse("bad host:49152"));
}
