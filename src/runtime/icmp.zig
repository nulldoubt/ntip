const std = @import("std");

pub const ipv4_header_bytes = 20;
pub const icmp_header_bytes = 8;

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
