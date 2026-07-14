const std = @import("std");

pub const minimum_header_len: usize = 20;
pub const maximum_packet_len: usize = 65_535;

pub const Address = [4]u8;

/// Validated view of exactly one complete IPv4 packet. This parser performs no
/// allocation and rejects padding or concatenated packets by requiring the IP
/// total-length field to exactly equal the supplied DATA plaintext length.
pub const Packet = struct {
    bytes: []const u8,
    header_len: u8,
    source: Address,
    destination: Address,
    protocol: u8,
    fragmented: bool,

    pub fn parse(bytes: []const u8) !Packet {
        if (bytes.len < minimum_header_len) return error.TruncatedIpv4Packet;
        if (bytes.len > maximum_packet_len) return error.Ipv4PacketTooLarge;
        if (bytes[0] >> 4 != 4) return error.NotIpv4;
        const ihl_words = bytes[0] & 0x0f;
        if (ihl_words < 5) return error.InvalidIpv4HeaderLength;
        const header_len: usize = @as(usize, ihl_words) * 4;
        if (header_len > bytes.len) return error.TruncatedIpv4Header;
        const total_len = std.mem.readInt(u16, bytes[2..4], .big);
        if (total_len < header_len) return error.InvalidIpv4TotalLength;
        if (total_len != bytes.len) return error.InvalidIpv4TotalLength;

        const fragment = std.mem.readInt(u16, bytes[6..8], .big);
        return .{
            .bytes = bytes,
            .header_len = @intCast(header_len),
            .source = bytes[12..16].*,
            .destination = bytes[16..20].*,
            .protocol = bytes[9],
            .fragmented = (fragment & 0x3fff) != 0,
        };
    }
};

test "IPv4 parser accepts exactly one complete packet" {
    const bytes = [_]u8{
        0x45, 0x00, 0x00, 0x18, 0,  0, 0x40, 0,
        64,   17,   0,    0,    10, 1, 0,    1,
        10,   1,    0,    2,    1,  2, 3,    4,
    };
    const packet = try Packet.parse(&bytes);
    try std.testing.expectEqual(Address{ 10, 1, 0, 1 }, packet.source);
    try std.testing.expectEqual(Address{ 10, 1, 0, 2 }, packet.destination);
    try std.testing.expectEqual(@as(u8, 17), packet.protocol);
    try std.testing.expect(!packet.fragmented);
}

test "IPv4 parser rejects truncation, padding, and non-IPv4" {
    var bytes = [_]u8{0} ** 20;
    bytes[0] = 0x45;
    bytes[2] = 0;
    bytes[3] = 20;
    _ = try Packet.parse(&bytes);
    bytes[0] = 0x65;
    try std.testing.expectError(error.NotIpv4, Packet.parse(&bytes));
    bytes[0] = 0x44;
    try std.testing.expectError(error.InvalidIpv4HeaderLength, Packet.parse(&bytes));
    try std.testing.expectError(error.TruncatedIpv4Packet, Packet.parse(bytes[0..19]));

    bytes[0] = 0x45;
    bytes[3] = 19;
    try std.testing.expectError(error.InvalidIpv4TotalLength, Packet.parse(&bytes));
}
