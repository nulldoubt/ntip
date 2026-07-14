const std = @import("std");
const configuration = @import("configuration.zig");

pub const version: u8 = 1;
pub const header_len: usize = 16;
pub const max_frame_len: usize = 1200;
pub const max_payload_len: usize = max_frame_len - header_len;

pub const Type = enum(u8) {
    enrollment_complete = 0x01,
    session_confirm = 0x02,
    heartbeat = 0x03,
    heartbeat_ack = 0x04,

    configuration_begin = 0x10,
    configuration_chunk = 0x11,
    configuration_ack = 0x12,

    path_challenge = 0x20,
    path_response = 0x21,

    rotate_key = 0x30,
    goodbye = 0x31,
    protocol_error = 0x7f,

    pub fn fromByte(value: u8) !Type {
        return switch (value) {
            0x01 => .enrollment_complete,
            0x02 => .session_confirm,
            0x03 => .heartbeat,
            0x04 => .heartbeat_ack,
            0x10 => .configuration_begin,
            0x11 => .configuration_chunk,
            0x12 => .configuration_ack,
            0x20 => .path_challenge,
            0x21 => .path_response,
            0x30 => .rotate_key,
            0x31 => .goodbye,
            0x7f => .protocol_error,
            else => error.UnknownControlType,
        };
    }
};

/// A single bounded binary control message. `generation` makes configuration
/// messages idempotent while `request_id` correlates bounded replies.
pub const Frame = struct {
    frame_type: Type,
    request_id: u32,
    generation: u64,
    payload: []const u8,

    pub fn encode(self: Frame, out: []u8) ![]u8 {
        if (self.payload.len > max_payload_len) return error.PayloadTooLarge;
        try validatePayload(self.frame_type, self.payload);
        try validateGeneration(self.frame_type, self.generation);
        const needed = header_len + self.payload.len;
        if (out.len < needed) return error.BufferTooSmall;

        out[0] = version;
        out[1] = @intFromEnum(self.frame_type);
        std.mem.writeInt(u16, out[2..4], @intCast(self.payload.len), .big);
        std.mem.writeInt(u32, out[4..8], self.request_id, .big);
        std.mem.writeInt(u64, out[8..16], self.generation, .big);
        @memcpy(out[header_len..needed], self.payload);
        return out[0..needed];
    }

    pub fn decode(bytes: []const u8) !Frame {
        if (bytes.len < header_len) return error.TruncatedControlFrame;
        if (bytes.len > max_frame_len) return error.ControlFrameTooLarge;
        if (bytes[0] != version) return error.UnsupportedControlVersion;
        const payload_len = std.mem.readInt(u16, bytes[2..4], .big);
        if (payload_len > max_payload_len) return error.PayloadTooLarge;
        if (bytes.len != header_len + payload_len) return error.InvalidControlLength;
        const frame_type = try Type.fromByte(bytes[1]);
        const payload = bytes[header_len..];
        try validatePayload(frame_type, payload);
        const generation = std.mem.readInt(u64, bytes[8..16], .big);
        try validateGeneration(frame_type, generation);
        return .{
            .frame_type = frame_type,
            .request_id = std.mem.readInt(u32, bytes[4..8], .big),
            .generation = generation,
            .payload = payload,
        };
    }
};

fn validateGeneration(frame_type: Type, generation: u64) !void {
    const configuration_related = switch (frame_type) {
        .configuration_begin, .configuration_chunk, .configuration_ack => true,
        else => false,
    };
    if (!configuration_related and generation != 0) return error.UnexpectedControlGeneration;
}

fn validatePayload(frame_type: Type, payload: []const u8) !void {
    const valid = switch (frame_type) {
        .enrollment_complete => payload.len == 16,
        .session_confirm => payload.len == 32,
        .heartbeat, .heartbeat_ack => payload.len == 8,
        .configuration_begin => begin: {
            _ = ConfigurationBegin.decode(payload) catch break :begin false;
            break :begin true;
        },
        .configuration_chunk => chunk: {
            _ = ConfigurationChunk.decode(payload) catch break :chunk false;
            break :chunk true;
        },
        .configuration_ack => payload.len == 32,
        .path_challenge, .path_response => payload.len == 16,
        .rotate_key => payload.len == 0,
        .goodbye => payload.len == 2,
        .protocol_error => payload.len >= 2 and payload.len <= 258 and std.unicode.utf8ValidateSlice(payload[2..]),
    };
    if (!valid) return error.InvalidControlPayload;
}

pub const snapshot_hash_len = 32;

pub fn hashConfiguration(snapshot: []const u8) [snapshot_hash_len]u8 {
    var hash: [snapshot_hash_len]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(snapshot, &hash, .{});
    return hash;
}

/// Payload for CONFIGURATION_BEGIN. Chunk sizes are selected by the sender;
/// every CONFIGURATION_CHUNK is still independently bounded by Frame.
pub const ConfigurationBegin = struct {
    hash: [snapshot_hash_len]u8,
    total_len: u32,
    chunk_count: u16,

    pub const encoded_len: usize = snapshot_hash_len + 4 + 2;

    pub fn encode(self: ConfigurationBegin) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        @memcpy(out[0..snapshot_hash_len], &self.hash);
        std.mem.writeInt(u32, out[32..36], self.total_len, .big);
        std.mem.writeInt(u16, out[36..38], self.chunk_count, .big);
        return out;
    }

    pub fn decode(bytes: []const u8) !ConfigurationBegin {
        if (bytes.len != encoded_len) return error.InvalidConfigurationBegin;
        const total_len = std.mem.readInt(u32, bytes[32..36], .big);
        const chunk_count = std.mem.readInt(u16, bytes[36..38], .big);
        if (total_len < configuration.header_len or total_len > configuration.maximum_snapshot_len or chunk_count == 0) {
            return error.InvalidConfigurationBegin;
        }
        const minimum_chunks = (total_len + ConfigurationChunk.max_data_len - 1) / ConfigurationChunk.max_data_len;
        if (chunk_count < minimum_chunks or chunk_count > total_len) return error.InvalidConfigurationBegin;
        return .{
            .hash = bytes[0..32].*,
            .total_len = total_len,
            .chunk_count = chunk_count,
        };
    }
};

/// Prefix inside a CONFIGURATION_CHUNK payload, followed by `data`.
pub const ConfigurationChunk = struct {
    index: u16,
    offset: u32,
    data: []const u8,

    pub const prefix_len: usize = 6;
    pub const max_data_len: usize = max_payload_len - prefix_len;

    pub fn encode(self: ConfigurationChunk, out: []u8) ![]u8 {
        if (self.data.len == 0 or self.data.len > max_data_len) return error.InvalidConfigurationChunk;
        const needed = prefix_len + self.data.len;
        if (out.len < needed) return error.BufferTooSmall;
        std.mem.writeInt(u16, out[0..2], self.index, .big);
        std.mem.writeInt(u32, out[2..6], self.offset, .big);
        @memcpy(out[prefix_len..needed], self.data);
        return out[0..needed];
    }

    pub fn decode(bytes: []const u8) !ConfigurationChunk {
        if (bytes.len <= prefix_len or bytes.len > max_payload_len) return error.InvalidConfigurationChunk;
        return .{
            .index = std.mem.readInt(u16, bytes[0..2], .big),
            .offset = std.mem.readInt(u32, bytes[2..6], .big),
            .data = bytes[prefix_len..],
        };
    }
};

test "control frame has strict, bounded network-order encoding" {
    const frame = Frame{
        .frame_type = .goodbye,
        .request_id = 0x0102_0304,
        .generation = 0,
        .payload = "ok",
    };
    var bytes: [max_frame_len]u8 = undefined;
    const encoded = try frame.encode(&bytes);
    try std.testing.expectEqualSlices(u8, &.{
        1,   0x31, 0, 2, 1, 2, 3, 4,
        0,   0,    0, 0, 0, 0, 0, 0,
        'o', 'k',
    }, encoded);
    const decoded = try Frame.decode(encoded);
    try std.testing.expectEqual(frame.frame_type, decoded.frame_type);
    try std.testing.expectEqual(frame.request_id, decoded.request_id);
    try std.testing.expectEqual(frame.generation, decoded.generation);
    try std.testing.expectEqualStrings("ok", decoded.payload);

    try std.testing.expectError(error.TruncatedControlFrame, Frame.decode(encoded[0..15]));
    bytes[2] = 0;
    bytes[3] = 1;
    try std.testing.expectError(error.InvalidControlLength, Frame.decode(encoded));

    const invalid = Frame{ .frame_type = .session_confirm, .request_id = 0, .generation = 0, .payload = "short" };
    try std.testing.expectError(error.InvalidControlPayload, invalid.encode(&bytes));

    const config_ack = Frame{
        .frame_type = .configuration_ack,
        .request_id = 0,
        .generation = 0x1112_1314_1516_1718,
        .payload = &([_]u8{0} ** 32),
    };
    const config_encoded = try config_ack.encode(&bytes);
    try std.testing.expectEqualSlices(u8, &.{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 }, config_encoded[8..16]);
}

test "configuration metadata and chunks are strict" {
    const begin = ConfigurationBegin{
        .hash = hashConfiguration("snapshot"),
        .total_len = 64,
        .chunk_count = 1,
    };
    const begin_bytes = begin.encode();
    try std.testing.expectEqual(begin, try ConfigurationBegin.decode(&begin_bytes));

    var chunk_bytes: [64]u8 = undefined;
    const encoded = try (ConfigurationChunk{ .index = 0, .offset = 0, .data = "snapshot" }).encode(&chunk_bytes);
    const chunk = try ConfigurationChunk.decode(encoded);
    try std.testing.expectEqual(@as(u16, 0), chunk.index);
    try std.testing.expectEqualStrings("snapshot", chunk.data);
}
