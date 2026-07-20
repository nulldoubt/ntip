const std = @import("std");

pub const ipv4_header_bytes = 20;
pub const icmp_header_bytes = 8;

pub const EchoReply = struct {
    source: [4]u8,
    destination: [4]u8,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
};

/// Builds a complete inner IPv4 ICMP echo request. The caller chooses the
/// identifier, sequence, and opaque payload used by the management plane to
/// correlate a bounded connectivity check. No allocation or wire extension is
/// required; the packet follows the ordinary authenticated DATA path.
pub fn echoRequest(
    destination: []u8,
    source: [4]u8,
    target: [4]u8,
    ipv4_id: u16,
    identifier: u16,
    sequence: u16,
    payload: []const u8,
) ![]u8 {
    const total_len = std.math.add(usize, ipv4_header_bytes + icmp_header_bytes, payload.len) catch
        return error.PacketTooLarge;
    if (total_len > std.math.maxInt(u16)) return error.PacketTooLarge;
    if (destination.len < total_len) return error.DestinationTooSmall;
    const output = destination[0..total_len];
    @memset(output, 0);

    output[0] = 0x45;
    std.mem.writeInt(u16, output[2..4], @intCast(total_len), .big);
    std.mem.writeInt(u16, output[4..6], ipv4_id, .big);
    std.mem.writeInt(u16, output[6..8], 0x4000, .big);
    output[8] = 64;
    output[9] = 1;
    output[12..16].* = source;
    output[16..20].* = target;

    const icmp = output[ipv4_header_bytes..];
    icmp[0] = 8;
    icmp[1] = 0;
    std.mem.writeInt(u16, icmp[4..6], identifier, .big);
    std.mem.writeInt(u16, icmp[6..8], sequence, .big);
    @memcpy(icmp[icmp_header_bytes..], payload);
    std.mem.writeInt(u16, icmp[2..4], checksum(icmp), .big);
    std.mem.writeInt(u16, output[10..12], checksum(output[0..ipv4_header_bytes]), .big);
    return output;
}

/// Recognizes and validates an unfragmented ICMP echo reply. Returning a view
/// into the authenticated plaintext lets the data worker correlate a pending
/// management probe before deciding whether the packet should reach the TUN.
pub fn parseEchoReply(packet: []const u8) !EchoReply {
    if (packet.len < ipv4_header_bytes + icmp_header_bytes) return error.MalformedIpv4;
    if (packet[0] >> 4 != 4) return error.NotIpv4;
    const header_len = @as(usize, packet[0] & 0x0f) * 4;
    if (header_len < ipv4_header_bytes or header_len + icmp_header_bytes > packet.len) return error.MalformedIpv4;
    const total_len = std.mem.readInt(u16, packet[2..4], .big);
    if (total_len < header_len + icmp_header_bytes or total_len > packet.len) return error.MalformedIpv4;
    if (packet[9] != 1) return error.NotIcmp;
    if (std.mem.readInt(u16, packet[6..8], .big) & 0x3fff != 0) return error.FragmentedIpv4;
    if (checksum(packet[0..header_len]) != 0) return error.InvalidIpv4Checksum;

    const icmp = packet[header_len..total_len];
    if (icmp[0] != 0 or icmp[1] != 0) return error.NotEchoReply;
    if (checksum(icmp) != 0) return error.InvalidIcmpChecksum;
    return .{
        .source = packet[12..16].*,
        .destination = packet[16..20].*,
        .identifier = std.mem.readInt(u16, icmp[4..6], .big),
        .sequence = std.mem.readInt(u16, icmp[6..8], .big),
        .payload = icmp[icmp_header_bytes..],
    };
}

/// Synthesizes ICMPv4 Destination Unreachable / Fragmentation Needed in the
/// caller-provided buffer. Returns the exact packet slice without allocation.
pub fn fragmentationNeeded(destination: []u8, original: []const u8, next_hop_mtu: u16) ![]u8 {
    if (original.len < ipv4_header_bytes) return error.MalformedIpv4;
    if (original[0] >> 4 != 4) return error.NotIpv4;
    const ihl = @as(usize, original[0] & 0x0f) * 4;
    if (ihl < ipv4_header_bytes or ihl > original.len) return error.MalformedIpv4;
    const original_total = std.mem.readInt(u16, original[2..4], .big);
    if (original_total < ihl or original_total > original.len) return error.MalformedIpv4;

    const quoted_len = @min(@as(usize, original_total), ihl + 8);
    const total_len = ipv4_header_bytes + icmp_header_bytes + quoted_len;
    if (destination.len < total_len) return error.DestinationTooSmall;
    const output = destination[0..total_len];
    @memset(output, 0);

    output[0] = 0x45;
    std.mem.writeInt(u16, output[2..4], @intCast(total_len), .big);
    std.mem.writeInt(u16, output[6..8], 0, .big);
    output[8] = 64;
    output[9] = 1;
    @memcpy(output[12..16], original[16..20]);
    @memcpy(output[16..20], original[12..16]);

    const icmp = output[ipv4_header_bytes..];
    icmp[0] = 3;
    icmp[1] = 4;
    std.mem.writeInt(u16, icmp[6..8], next_hop_mtu, .big);
    @memcpy(icmp[icmp_header_bytes..][0..quoted_len], original[0..quoted_len]);
    std.mem.writeInt(u16, icmp[2..4], checksum(icmp), .big);
    std.mem.writeInt(u16, output[10..12], checksum(output[0..ipv4_header_bytes]), .big);
    return output;
}

pub fn checksum(bytes: []const u8) u16 {
    var sum: u32 = 0;
    var index: usize = 0;
    while (index + 1 < bytes.len) : (index += 2) {
        sum += (@as(u32, bytes[index]) << 8) | bytes[index + 1];
    }
    if (index < bytes.len) sum += @as(u32, bytes[index]) << 8;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

test "fragmentation-needed quotes the IPv4 header and eight bytes" {
    var original: [28]u8 = [_]u8{0} ** 28;
    original[0] = 0x45;
    std.mem.writeInt(u16, original[2..4], original.len, .big);
    original[8] = 64;
    original[9] = 17;
    original[12..16].* = .{ 10, 1, 0, 1 };
    original[16..20].* = .{ 10, 1, 0, 2 };
    std.mem.writeInt(u16, original[10..12], checksum(&original), .big);
    var destination: [128]u8 = undefined;
    const packet = try fragmentationNeeded(&destination, &original, 1380);
    try std.testing.expectEqual(@as(usize, 56), packet.len);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 2 }, packet[12..16]);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 1 }, packet[16..20]);
    try std.testing.expectEqual(@as(u8, 3), packet[20]);
    try std.testing.expectEqual(@as(u8, 4), packet[21]);
    try std.testing.expectEqual(@as(u16, 1380), std.mem.readInt(u16, packet[26..28], .big));
    try std.testing.expectEqual(@as(u16, 0), checksum(packet[0..20]));
    try std.testing.expectEqual(@as(u16, 0), checksum(packet[20..]));
}

test "echo request is valid and reply correlation parses authenticated plaintext" {
    var buffer: [128]u8 = undefined;
    const nonce = [_]u8{0xa5} ** 16;
    const request = try echoRequest(
        &buffer,
        .{ 10, 1, 0, 1 },
        .{ 10, 1, 0, 2 },
        7,
        42,
        9,
        &nonce,
    );
    try std.testing.expectEqual(@as(u8, 8), request[20]);
    try std.testing.expectEqual(@as(u16, 0), checksum(request[0..20]));
    try std.testing.expectEqual(@as(u16, 0), checksum(request[20..]));

    // Turn the request into the reply a Node kernel would produce.
    request[12..16].* = .{ 10, 1, 0, 2 };
    request[16..20].* = .{ 10, 1, 0, 1 };
    request[10..12].* = .{ 0, 0 };
    std.mem.writeInt(u16, request[10..12], checksum(request[0..20]), .big);
    request[20] = 0;
    request[22..24].* = .{ 0, 0 };
    std.mem.writeInt(u16, request[22..24], checksum(request[20..]), .big);

    const reply = try parseEchoReply(request);
    try std.testing.expectEqual(@as(u16, 42), reply.identifier);
    try std.testing.expectEqual(@as(u16, 9), reply.sequence);
    try std.testing.expectEqualSlices(u8, &nonce, reply.payload);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 2 }, &reply.source);
}

test "echo reply parser rejects corruption and unrelated ICMP" {
    var buffer: [64]u8 = undefined;
    const packet = try echoRequest(&buffer, .{ 10, 1, 0, 1 }, .{ 10, 1, 0, 2 }, 1, 2, 3, "check");
    try std.testing.expectError(error.NotEchoReply, parseEchoReply(packet));
    packet[20] = 0;
    packet[22..24].* = .{ 0, 0 };
    std.mem.writeInt(u16, packet[22..24], checksum(packet[20..]), .big);
    packet[packet.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidIcmpChecksum, parseEchoReply(packet));
}
