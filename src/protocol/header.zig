const std = @import("std");

pub const wire_version: u8 = 1;
pub const encoded_len: usize = 18;
pub const authentication_tag_len: usize = 16;
pub const data_overhead: usize = encoded_len + authentication_tag_len;
pub const reserved_batched_data_type: u8 = 0x12;

pub const PacketType = enum(u8) {
    enrollment_handshake = 0x01,
    session_handshake = 0x02,
    stateless_retry = 0x03,
    control = 0x10,
    data = 0x11,
    pub fn fromByte(value: u8) !PacketType {
        return switch (value) {
            0x01 => .enrollment_handshake,
            0x02 => .session_handshake,
            0x03 => .stateless_retry,
            0x10 => .control,
            0x11 => .data,
            reserved_batched_data_type => error.ReservedPacketType,
            else => error.UnknownPacketType,
        };
    }

    pub fn isEncrypted(self: PacketType) bool {
        return switch (self) {
            .control, .data => true,
            .enrollment_handshake, .session_handshake, .stateless_retry => false,
        };
    }
};

/// The fixed cleartext prefix present on every NTIP datagram. Integer fields
/// are encoded in network byte order. For transport packets `context` is the
/// receiver session identifier and `sequence` is the shared CONTROL/DATA
/// sequence number for that direction.
pub const Header = struct {
    packet_type: PacketType,
    context: u64,
    sequence: u64,

    pub fn encode(self: Header) ![encoded_len]u8 {
        try self.validate();
        var out: [encoded_len]u8 = undefined;
        out[0] = wire_version;
        out[1] = @intFromEnum(self.packet_type);
        std.mem.writeInt(u64, out[2..10], self.context, .big);
        std.mem.writeInt(u64, out[10..18], self.sequence, .big);
        return out;
    }

    pub fn validate(self: Header) !void {
        if (self.context == 0) return error.ZeroPacketContext;
        switch (self.packet_type) {
            .enrollment_handshake => if (self.sequence > 2) return error.InvalidHandshakeMessageIndex,
            .session_handshake => if (self.sequence > 1) return error.InvalidHandshakeMessageIndex,
            .stateless_retry => if (self.sequence != 0) return error.InvalidHandshakeMessageIndex,
            .control, .data => {},
        }
    }

    pub fn decode(bytes: []const u8) !Header {
        if (bytes.len != encoded_len) return error.InvalidHeaderLength;
        if (bytes[0] != wire_version) return error.UnsupportedWireVersion;
        const header = Header{
            .packet_type = try PacketType.fromByte(bytes[1]),
            .context = std.mem.readInt(u64, bytes[2..10], .big),
            .sequence = std.mem.readInt(u64, bytes[10..18], .big),
        };
        try header.validate();
        return header;
    }
};

test "header is exactly 18 bytes in network byte order" {
    const header = Header{
        .packet_type = .data,
        .context = 0x0102_0304_0506_0708,
        .sequence = 0x1112_1314_1516_1718,
    };
    const encoded = try header.encode();
    try std.testing.expectEqualSlices(u8, &.{
        0x01, 0x11,
        0x01, 0x02,
        0x03, 0x04,
        0x05, 0x06,
        0x07, 0x08,
        0x11, 0x12,
        0x13, 0x14,
        0x15, 0x16,
        0x17, 0x18,
    }, &encoded);
    try std.testing.expectEqual(header, try Header.decode(&encoded));
    try std.testing.expectEqual(@as(usize, 34), data_overhead);
}

test "header parser rejects unknown, reserved, and malformed inputs" {
    try std.testing.expectError(error.InvalidHeaderLength, Header.decode(&[_]u8{0} ** 17));

    var bytes = [_]u8{0} ** encoded_len;
    bytes[0] = 2;
    bytes[1] = @intFromEnum(PacketType.data);
    try std.testing.expectError(error.UnsupportedWireVersion, Header.decode(&bytes));

    bytes[0] = wire_version;
    bytes[1] = 0xff;
    try std.testing.expectError(error.UnknownPacketType, Header.decode(&bytes));
    bytes[1] = reserved_batched_data_type;
    try std.testing.expectError(error.ReservedPacketType, Header.decode(&bytes));

    bytes[1] = @intFromEnum(PacketType.enrollment_handshake);
    bytes[17] = 3;
    try std.testing.expectError(error.ZeroPacketContext, Header.decode(&bytes));
    bytes[9] = 1;
    try std.testing.expectError(error.InvalidHandshakeMessageIndex, Header.decode(&bytes));
}
