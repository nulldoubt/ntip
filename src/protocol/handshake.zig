const std = @import("std");
const cookie = @import("cookie.zig");

pub const identity_context_len: usize = 16;
pub const cookie_present_flag: u8 = 0x01;
pub const envelope_prefix_len: usize = 1 + identity_context_len;
pub const maximum_envelope_len: usize = 65_535;

/// Application envelope around each standard Noise handshake message. The
/// identity context is the enrollment handle for XKpsk1 and the Node UUID for
/// IK. A retry cookie is echoed only when requested by a stateless retry.
pub const Envelope = struct {
    identity_context: [identity_context_len]u8,
    retry: ?cookie.RetryPayload,
    noise_message: []const u8,

    pub fn encode(self: Envelope, out: []u8) ![]u8 {
        if (self.noise_message.len == 0) return error.EmptyNoiseMessage;
        const optional_len: usize = if (self.retry != null) cookie.RetryPayload.encoded_len else 0;
        if (self.noise_message.len > maximum_envelope_len - envelope_prefix_len - optional_len) {
            return error.HandshakeEnvelopeTooLarge;
        }
        const needed = envelope_prefix_len + optional_len + self.noise_message.len;
        if (out.len < needed) return error.BufferTooSmall;

        out[0] = if (self.retry != null) cookie_present_flag else 0;
        @memcpy(out[1..17], &self.identity_context);
        var offset: usize = envelope_prefix_len;
        if (self.retry) |retry| {
            const encoded = retry.encode();
            @memcpy(out[offset .. offset + encoded.len], &encoded);
            offset += encoded.len;
        }
        @memcpy(out[offset..needed], self.noise_message);
        return out[0..needed];
    }

    pub fn decode(bytes: []const u8) !Envelope {
        if (bytes.len <= envelope_prefix_len) return error.TruncatedHandshakeEnvelope;
        if (bytes.len > maximum_envelope_len) return error.HandshakeEnvelopeTooLarge;
        const flags = bytes[0];
        if ((flags & ~cookie_present_flag) != 0) return error.ReservedHandshakeFlags;
        var offset: usize = envelope_prefix_len;
        const retry = if ((flags & cookie_present_flag) != 0) retry: {
            if (bytes.len <= offset + cookie.RetryPayload.encoded_len) return error.TruncatedHandshakeEnvelope;
            const value = try cookie.RetryPayload.decode(bytes[offset .. offset + cookie.RetryPayload.encoded_len]);
            offset += cookie.RetryPayload.encoded_len;
            break :retry value;
        } else null;
        if (offset >= bytes.len) return error.EmptyNoiseMessage;
        return .{
            .identity_context = bytes[1..17].*,
            .retry = retry,
            .noise_message = bytes[offset..],
        };
    }
};

/// XKpsk1 message index 0, Node to Master.
pub const EnrollmentMessage0 = struct {
    node_receiver_id: u64,
    pub const encoded_len: usize = 8;

    pub fn encode(self: EnrollmentMessage0) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        std.mem.writeInt(u64, &out, self.node_receiver_id, .big);
        return out;
    }

    pub fn decode(bytes: []const u8) !EnrollmentMessage0 {
        if (bytes.len != encoded_len) return error.InvalidEnrollmentMessage0;
        return .{ .node_receiver_id = std.mem.readInt(u64, bytes[0..8], .big) };
    }
};

/// XKpsk1 message index 1, Master to Node.
pub const EnrollmentMessage1 = struct {
    master_receiver_id: u64,
    node_uuid: [16]u8,
    assigned_ipv4: [4]u8,
    vnr_network: [4]u8,
    vnr_prefix_len: u8,
    config_generation: u64,
    pub const encoded_len: usize = 8 + 16 + 4 + 4 + 1 + 8;

    pub fn encode(self: EnrollmentMessage1) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.master_receiver_id, .big);
        @memcpy(out[8..24], &self.node_uuid);
        @memcpy(out[24..28], &self.assigned_ipv4);
        @memcpy(out[28..32], &self.vnr_network);
        out[32] = self.vnr_prefix_len;
        std.mem.writeInt(u64, out[33..41], self.config_generation, .big);
        return out;
    }

    pub fn decode(bytes: []const u8) !EnrollmentMessage1 {
        if (bytes.len != encoded_len) return error.InvalidEnrollmentMessage1;
        const result: EnrollmentMessage1 = .{
            .master_receiver_id = std.mem.readInt(u64, bytes[0..8], .big),
            .node_uuid = bytes[8..24].*,
            .assigned_ipv4 = bytes[24..28].*,
            .vnr_network = bytes[28..32].*,
            .vnr_prefix_len = bytes[32],
            .config_generation = std.mem.readInt(u64, bytes[33..41], .big),
        };
        try validateVnrAssignment(result.assigned_ipv4, result.vnr_network, result.vnr_prefix_len);
        return result;
    }
};

fn validateVnrAssignment(address_bytes: [4]u8, network_bytes: [4]u8, prefix_len: u8) !void {
    if (prefix_len < 1 or prefix_len > 30) return error.InvalidEnrollmentVnr;
    const address = std.mem.readInt(u32, &address_bytes, .big);
    const network = std.mem.readInt(u32, &network_bytes, .big);
    const host_bits: u5 = @intCast(32 - prefix_len);
    const mask: u32 = ~@as(u32, 0) << host_bits;
    if ((network & mask) != network or (address & mask) != network) return error.InvalidEnrollmentVnr;
    const host = address & ~mask;
    const broadcast_host = ~mask;
    if (host == 0 or host == 1 or host == broadcast_host) return error.InvalidEnrollmentVnr;
}

/// XKpsk1 message index 2, Node to Master.
pub const EnrollmentMessage2 = struct {
    node_uuid: [16]u8,
    pub const encoded_len: usize = 16;

    pub fn encode(self: EnrollmentMessage2) [encoded_len]u8 {
        return self.node_uuid;
    }

    pub fn decode(bytes: []const u8) !EnrollmentMessage2 {
        if (bytes.len != encoded_len) return error.InvalidEnrollmentMessage2;
        return .{ .node_uuid = bytes[0..16].* };
    }
};

/// IK message index 0, Node to Master.
pub const SessionMessage0 = struct {
    node_uuid: [16]u8,
    node_receiver_id: u64,
    pub const encoded_len: usize = 16 + 8;

    pub fn encode(self: SessionMessage0) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        @memcpy(out[0..16], &self.node_uuid);
        std.mem.writeInt(u64, out[16..24], self.node_receiver_id, .big);
        return out;
    }

    pub fn decode(bytes: []const u8) !SessionMessage0 {
        if (bytes.len != encoded_len) return error.InvalidSessionMessage0;
        return .{
            .node_uuid = bytes[0..16].*,
            .node_receiver_id = std.mem.readInt(u64, bytes[16..24], .big),
        };
    }
};

/// IK message index 1, Master to Node.
pub const SessionMessage1 = struct {
    master_receiver_id: u64,
    config_generation: u64,
    pub const encoded_len: usize = 16;

    pub fn encode(self: SessionMessage1) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.master_receiver_id, .big);
        std.mem.writeInt(u64, out[8..16], self.config_generation, .big);
        return out;
    }

    pub fn decode(bytes: []const u8) !SessionMessage1 {
        if (bytes.len != encoded_len) return error.InvalidSessionMessage1;
        return .{
            .master_receiver_id = std.mem.readInt(u64, bytes[0..8], .big),
            .config_generation = std.mem.readInt(u64, bytes[8..16], .big),
        };
    }
};

/// Exact payload of the first encrypted SESSION_CONFIRM control frame.
pub const SessionConfirm = struct {
    handshake_hash: [32]u8,
    pub const encoded_len: usize = 32;

    pub fn encode(self: SessionConfirm) [encoded_len]u8 {
        return self.handshake_hash;
    }

    pub fn decode(bytes: []const u8) !SessionConfirm {
        if (bytes.len != encoded_len) return error.InvalidSessionConfirm;
        return .{ .handshake_hash = bytes[0..32].* };
    }
};

test "handshake envelope is strict and retry is unambiguous" {
    const retry = cookie.RetryPayload{ .epoch = 7, .tag = [_]u8{8} ** cookie.tag_len };
    const envelope = Envelope{
        .identity_context = [_]u8{9} ** identity_context_len,
        .retry = retry,
        .noise_message = "noise",
    };
    var bytes: [128]u8 = undefined;
    const encoded = try envelope.encode(&bytes);
    const decoded = try Envelope.decode(encoded);
    try std.testing.expectEqual(envelope.identity_context, decoded.identity_context);
    try std.testing.expectEqual(retry, decoded.retry.?);
    try std.testing.expectEqualStrings("noise", decoded.noise_message);

    bytes[0] = 0x80;
    try std.testing.expectError(error.ReservedHandshakeFlags, Envelope.decode(encoded));
    try std.testing.expectError(error.TruncatedHandshakeEnvelope, Envelope.decode(encoded[0..17]));
}

test "handshake payloads use fixed network-order encodings" {
    const enrollment = EnrollmentMessage1{
        .master_receiver_id = 0x0102_0304_0506_0708,
        .node_uuid = [_]u8{0xaa} ** 16,
        .assigned_ipv4 = .{ 10, 1, 0, 2 },
        .vnr_network = .{ 10, 1, 0, 0 },
        .vnr_prefix_len = 24,
        .config_generation = 0x1112_1314_1516_1718,
    };
    const encoded_enrollment = enrollment.encode();
    try std.testing.expectEqual(enrollment, try EnrollmentMessage1.decode(&encoded_enrollment));
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, encoded_enrollment[0..8]);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 2 }, encoded_enrollment[24..28]);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 0 }, encoded_enrollment[28..32]);
    try std.testing.expectEqual(@as(u8, 24), encoded_enrollment[32]);

    var invalid_enrollment = encoded_enrollment;
    invalid_enrollment[32] = 31;
    try std.testing.expectError(error.InvalidEnrollmentVnr, EnrollmentMessage1.decode(&invalid_enrollment));

    const session = SessionMessage0{ .node_uuid = [_]u8{0xbb} ** 16, .node_receiver_id = 42 };
    const encoded_session = session.encode();
    try std.testing.expectEqual(session, try SessionMessage0.decode(&encoded_session));
    try std.testing.expectError(error.InvalidSessionMessage0, SessionMessage0.decode(encoded_session[0..23]));

    const confirm = SessionConfirm{ .handshake_hash = [_]u8{0xcc} ** 32 };
    const encoded_confirm = confirm.encode();
    try std.testing.expectEqual(confirm, try SessionConfirm.decode(&encoded_confirm));
}
