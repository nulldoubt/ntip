const std = @import("std");
const wire = @import("header.zig");
const replay = @import("replay.zig");

const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

pub const key_len = Aead.key_length;
pub const tag_len = Aead.tag_length;
pub const overhead = wire.encoded_len + tag_len;

pub fn noiseNonce(sequence: u64) [Aead.nonce_length]u8 {
    var nonce = [_]u8{0} ** Aead.nonce_length;
    std.mem.writeInt(u64, nonce[4..12], sequence, .little);
    return nonce;
}

/// Encrypts one CONTROL or DATA plaintext into `out`, returning the exact
/// datagram slice. The 18-byte clear header is authenticated as associated
/// data, and is therefore not malleable despite remaining visible.
pub fn seal(header: wire.Header, plaintext: []const u8, key: [key_len]u8, out: []u8) ![]u8 {
    if (!header.packet_type.isEncrypted()) return error.UnencryptedPacketType;
    if (plaintext.len > std.math.maxInt(usize) - overhead) return error.PayloadTooLarge;
    const needed = overhead + plaintext.len;
    if (out.len < needed) return error.BufferTooSmall;

    const encoded = try header.encode();
    @memcpy(out[0..wire.encoded_len], &encoded);
    const ciphertext = out[wire.encoded_len .. wire.encoded_len + plaintext.len];
    var tag: [tag_len]u8 = undefined;
    Aead.encrypt(ciphertext, &tag, plaintext, &encoded, noiseNonce(header.sequence), key);
    @memcpy(out[wire.encoded_len + plaintext.len .. needed], &tag);
    return out[0..needed];
}

pub const OpenResult = struct {
    header: wire.Header,
    plaintext: []u8,
};

/// One instance is owned by a session's data worker and is used for both
/// CONTROL and DATA, guaranteeing a single sequence space per direction.
pub const SendState = struct {
    receiver_session_id: u64,
    key: [key_len]u8,
    next_sequence: u64 = 0,

    pub fn seal(self: *SendState, packet_type: wire.PacketType, plaintext: []const u8, out: []u8) ![]u8 {
        if (self.next_sequence == std.math.maxInt(u64)) return error.SequenceExhausted;
        const datagram = try @import("transport.zig").seal(.{
            .packet_type = packet_type,
            .context = self.receiver_session_id,
            .sequence = self.next_sequence,
        }, plaintext, self.key, out);
        self.next_sequence += 1;
        return datagram;
    }
};

pub const ReceiveState = struct {
    key: [key_len]u8,
    replay_window: replay.Window = .{},

    pub fn open(self: *ReceiveState, datagram: []const u8, out: []u8) !OpenResult {
        return @import("transport.zig").open(datagram, self.key, &self.replay_window, out);
    }
};

/// Authenticates and decrypts a transport datagram. The replay window is only
/// committed after successful AEAD authentication.
pub fn open(datagram: []const u8, key: [key_len]u8, window: *replay.Window, out: []u8) !OpenResult {
    if (datagram.len < overhead) return error.TruncatedDatagram;
    const header = try wire.Header.decode(datagram[0..wire.encoded_len]);
    if (!header.packet_type.isEncrypted()) return error.UnencryptedPacketType;
    try window.check(header.sequence);

    const ciphertext_len = datagram.len - overhead;
    if (out.len < ciphertext_len) return error.BufferTooSmall;
    const ciphertext = datagram[wire.encoded_len .. wire.encoded_len + ciphertext_len];
    const tag = datagram[datagram.len - tag_len ..][0..tag_len].*;
    Aead.decrypt(out[0..ciphertext_len], ciphertext, tag, datagram[0..wire.encoded_len], noiseNonce(header.sequence), key) catch {
        return error.AuthenticationFailed;
    };
    try window.commit(header.sequence);
    return .{ .header = header, .plaintext = out[0..ciphertext_len] };
}

test "Noise transport nonce is zero32 followed by little-endian sequence" {
    try std.testing.expectEqualSlices(u8, &.{
        0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1,
    }, &noiseNonce(0x0102_0304_0506_0708));
}

test "transport authenticates header, payload, and replay state" {
    const header = wire.Header{ .packet_type = .data, .context = 42, .sequence = 9 };
    const key = [_]u8{0x5a} ** key_len;
    var datagram: [256]u8 = undefined;
    const sealed = try seal(header, "complete IPv4 packet", key, &datagram);
    try std.testing.expectEqual(@as(usize, "complete IPv4 packet".len + 34), sealed.len);

    var window = replay.Window{};
    var plaintext: [256]u8 = undefined;
    const result = try open(sealed, key, &window, &plaintext);
    try std.testing.expectEqual(header, result.header);
    try std.testing.expectEqualStrings("complete IPv4 packet", result.plaintext);
    try std.testing.expectError(error.Duplicate, open(sealed, key, &window, &plaintext));

    var tampered = datagram;
    tampered[10] ^= 0x80;
    try std.testing.expectError(error.AuthenticationFailed, open(tampered[0..sealed.len], key, &window, &plaintext));
    try std.testing.expectEqual(@as(u64, 9), window.highest);
}

test "CONTROL and DATA consume one sender sequence space" {
    var sender = SendState{ .receiver_session_id = 7, .key = [_]u8{3} ** key_len };
    var first: [128]u8 = undefined;
    var second: [128]u8 = undefined;
    const control = try sender.seal(.control, "control", &first);
    const data = try sender.seal(.data, "data", &second);
    try std.testing.expectEqual(@as(u64, 0), (try wire.Header.decode(control[0..wire.encoded_len])).sequence);
    try std.testing.expectEqual(@as(u64, 1), (try wire.Header.decode(data[0..wire.encoded_len])).sequence);

    var receiver = ReceiveState{ .key = sender.key };
    var plaintext: [128]u8 = undefined;
    try std.testing.expectEqualStrings("data", (try receiver.open(data, &plaintext)).plaintext);
    try std.testing.expectEqualStrings("control", (try receiver.open(control, &plaintext)).plaintext);
}
