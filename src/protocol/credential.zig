const std = @import("std");

pub const prefix = "ntip-enroll-v1.";
pub const handle_len = 16;
pub const secret_len = 32;
pub const master_public_len = 32;
pub const binary_len = handle_len + secret_len + master_public_len;
pub const encoded_payload_len = std.base64.url_safe_no_pad.Encoder.calcSize(binary_len);
pub const text_len = prefix.len + encoded_payload_len;

const psk_context_label = "NTIP enrollment PSK v1";

pub const Credential = struct {
    handle: [handle_len]u8,
    secret: [secret_len]u8,
    master_public: [master_public_len]u8,

    pub fn encode(self: *const Credential, out: *[text_len]u8) []const u8 {
        var binary: [binary_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &binary);
        @memcpy(binary[0..handle_len], &self.handle);
        @memcpy(binary[handle_len .. handle_len + secret_len], &self.secret);
        @memcpy(binary[handle_len + secret_len ..], &self.master_public);

        @memcpy(out[0..prefix.len], prefix);
        _ = std.base64.url_safe_no_pad.Encoder.encode(out[prefix.len..], &binary);
        return out;
    }

    pub fn decode(text: []const u8) !Credential {
        if (text.len != text_len) return error.InvalidCredentialLength;
        if (!std.mem.eql(u8, text[0..prefix.len], prefix)) return error.InvalidCredentialPrefix;

        var binary: [binary_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &binary);
        std.base64.url_safe_no_pad.Decoder.decode(&binary, text[prefix.len..]) catch {
            return error.InvalidCredentialEncoding;
        };
        var canonical: [encoded_payload_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &canonical);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&canonical, &binary);
        if (!std.mem.eql(u8, &canonical, text[prefix.len..])) return error.NonCanonicalCredential;
        const credential = Credential{
            .handle = binary[0..handle_len].*,
            .secret = binary[handle_len .. handle_len + secret_len].*,
            .master_public = binary[handle_len + secret_len ..].*,
        };
        if (allZero(&credential.handle) or allZero(&credential.secret) or allZero(&credential.master_public)) {
            return error.InvalidCredentialComponent;
        }
        return credential;
    }

    /// Derives the bearer-equivalent PSK stored by the Master. The credential
    /// handle is the HKDF salt; the fixed domain label and embedded Master
    /// static public key form the expansion context.
    pub fn derivePsk(self: *const Credential) [32]u8 {
        const Kdf = std.crypto.kdf.hkdf.HkdfSha256;
        var prk = Kdf.extract(&self.handle, &self.secret);
        defer std.crypto.secureZero(u8, &prk);
        var context: [psk_context_label.len + master_public_len]u8 = undefined;
        @memcpy(context[0..psk_context_label.len], psk_context_label);
        @memcpy(context[psk_context_label.len..], &self.master_public);
        var psk: [32]u8 = undefined;
        Kdf.expand(&psk, &context, prk);
        return psk;
    }

    pub fn deinit(self: *Credential) void {
        std.crypto.secureZero(u8, &self.handle);
        std.crypto.secureZero(u8, &self.secret);
        std.crypto.secureZero(u8, &self.master_public);
    }
};

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

test "credential has fixed base64url wire representation and round trips" {
    var credential = Credential{
        .handle = undefined,
        .secret = undefined,
        .master_public = undefined,
    };
    for (&credential.handle, 0..) |*byte, i| byte.* = @intCast(i);
    for (&credential.secret, 0..) |*byte, i| byte.* = @intCast(0x10 + i);
    for (&credential.master_public, 0..) |*byte, i| byte.* = @intCast(0x30 + i);

    var text: [text_len]u8 = undefined;
    const encoded = credential.encode(&text);
    try std.testing.expectEqual(@as(usize, 122), encoded.len);
    try std.testing.expectEqualStrings(
        "ntip-enroll-v1.AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-P0BBQkNERUZHSElKS0xNTk8",
        encoded,
    );
    try std.testing.expectEqual(credential, try Credential.decode(encoded));
}

test "credential parser fails closed and PSK binds handle and Master" {
    const zero = Credential{
        .handle = [_]u8{0} ** handle_len,
        .secret = [_]u8{1} ** secret_len,
        .master_public = [_]u8{2} ** master_public_len,
    };
    var text: [text_len]u8 = undefined;
    const encoded = zero.encode(&text);
    try std.testing.expectError(error.InvalidCredentialLength, Credential.decode(encoded[0 .. encoded.len - 1]));
    try std.testing.expectError(error.InvalidCredentialComponent, Credential.decode(encoded));
    text[0] = 'x';
    try std.testing.expectError(error.InvalidCredentialPrefix, Credential.decode(&text));

    var changed_handle = zero;
    changed_handle.handle[0] = 9;
    var changed_master = zero;
    changed_master.master_public[31] = 9;
    try std.testing.expect(!std.mem.eql(u8, &zero.derivePsk(), &changed_handle.derivePsk()));
    try std.testing.expect(!std.mem.eql(u8, &zero.derivePsk(), &changed_master.derivePsk()));
}
