const std = @import("std");
const endpoint = @import("endpoint.zig");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
const domain = "NTIP retry cookie v1";

pub const tag_len = 16;
pub const rotation_epoch_seconds: u64 = 120;

pub fn epochFromUnixSeconds(seconds: u64) u64 {
    return seconds / rotation_epoch_seconds;
}

pub const RetryPayload = struct {
    epoch: u64,
    tag: [tag_len]u8,

    pub const encoded_len: usize = 8 + tag_len;

    pub fn encode(self: RetryPayload) [encoded_len]u8 {
        var out: [encoded_len]u8 = undefined;
        std.mem.writeInt(u64, out[0..8], self.epoch, .big);
        @memcpy(out[8..], &self.tag);
        return out;
    }

    pub fn decode(bytes: []const u8) !RetryPayload {
        if (bytes.len != encoded_len) return error.InvalidRetryPayload;
        return .{ .epoch = std.mem.readInt(u64, bytes[0..8], .big), .tag = bytes[8..24].* };
    }
};

/// Produces a truncated HMAC-SHA256 cookie bound to the serialized source
/// endpoint, outer handshake context, and rotation epoch. Callers retain both
/// current and immediately previous secrets during rotation.
pub fn create(secret: *const [32]u8, source: endpoint.Endpoint, context: u64, identity_context: [16]u8, epoch: u64) [tag_len]u8 {
    var context_bytes: [8]u8 = undefined;
    var epoch_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &context_bytes, context, .big);
    std.mem.writeInt(u64, &epoch_bytes, epoch, .big);
    const source_binding = source.cookieBinding();

    var mac = Hmac.init(secret);
    mac.update(domain);
    mac.update(&source_binding);
    mac.update(&context_bytes);
    mac.update(&identity_context);
    mac.update(&epoch_bytes);
    var full: [Hmac.mac_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &full);
    mac.final(&full);
    return full[0..tag_len].*;
}

pub fn verify(secret: *const [32]u8, source: endpoint.Endpoint, context: u64, identity_context: [16]u8, epoch: u64, candidate: [tag_len]u8) bool {
    return std.crypto.timing_safe.eql([tag_len]u8, create(secret, source, context, identity_context, epoch), candidate);
}

pub const RotatingVerifier = struct {
    current_secret: [32]u8,
    previous_secret: [32]u8,
    current_epoch: u64,

    pub fn verify(self: *const RotatingVerifier, source: endpoint.Endpoint, context: u64, identity_context: [16]u8, epoch: u64, candidate: [tag_len]u8) bool {
        if (epoch == self.current_epoch) {
            return @import("cookie.zig").verify(&self.current_secret, source, context, identity_context, epoch, candidate);
        }
        if (self.current_epoch != 0 and epoch == self.current_epoch - 1) {
            return @import("cookie.zig").verify(&self.previous_secret, source, context, identity_context, epoch, candidate);
        }
        return false;
    }
};

test "retry cookies bind source, context, epoch, and rotation secret" {
    const secret = [_]u8{0x11} ** 32;
    const source = endpoint.Endpoint{
        .family = .ipv4,
        .address = .{ 203, 0, 113, 1 } ++ ([_]u8{0} ** 12),
        .port = 50_000,
    };
    var other_source = source;
    other_source.address[3] = 2;
    const identity_context = [_]u8{9} ** 16;
    const tag = create(&secret, source, 7, identity_context, 10);
    try std.testing.expect(verify(&secret, source, 7, identity_context, 10, tag));
    try std.testing.expect(!verify(&secret, other_source, 7, identity_context, 10, tag));
    try std.testing.expect(!verify(&secret, source, 8, identity_context, 10, tag));
    try std.testing.expect(!verify(&secret, source, 7, identity_context, 11, tag));
    var other_identity = identity_context;
    other_identity[0] ^= 1;
    try std.testing.expect(!verify(&secret, source, 7, other_identity, 10, tag));

    const verifier = RotatingVerifier{
        .current_secret = [_]u8{0x22} ** 32,
        .previous_secret = secret,
        .current_epoch = 11,
    };
    try std.testing.expect(verifier.verify(source, 7, identity_context, 10, tag));
    try std.testing.expectEqual(@as(u64, 10), epochFromUnixSeconds(1_200));

    const payload = RetryPayload{ .epoch = 10, .tag = tag };
    const bytes = payload.encode();
    try std.testing.expectEqual(payload, try RetryPayload.decode(&bytes));
    try std.testing.expectError(error.InvalidRetryPayload, RetryPayload.decode(bytes[0..23]));
}
