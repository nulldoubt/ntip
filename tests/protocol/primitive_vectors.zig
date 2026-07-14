const std = @import("std");

fn decodeHex(comptime encoded: []const u8) [encoded.len / 2]u8 {
    if (encoded.len % 2 != 0) @compileError("hex input must contain whole bytes");
    var decoded: [encoded.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&decoded, encoded) catch unreachable;
    return decoded;
}

test "RFC 8439 section 2.8.2 ChaCha20-Poly1305 AEAD" {
    // Official vector: https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    const aad = decodeHex("50515253c0c1c2c3c4c5c6c7");
    const key = decodeHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
    const nonce = decodeHex("070000004041424344454647");
    const expected_ciphertext = decodeHex(
        "d31a8d34648e60db7b86afbc53ef7ec2" ++
            "a4aded51296e08fea9e2b5a736ee62d6" ++
            "3dbea45e8ca9671282fafb69da92728b" ++
            "1a71de0a9e060b2905d6a5b67ecd3b36" ++
            "92ddbd7f2d778b8c9803aee328091b58" ++
            "fab324e4fad675945585808b4831d7bc" ++
            "3ff4def08e4b7a9de576d26586cec64b" ++
            "6116",
    );
    const expected_tag = decodeHex("1ae10b594f09e26a7e902ecbd0600691");

    var ciphertext: [plaintext.len]u8 = undefined;
    var tag: [Aead.tag_length]u8 = undefined;
    Aead.encrypt(&ciphertext, &tag, plaintext, &aad, nonce, key);
    try std.testing.expectEqualSlices(u8, &expected_ciphertext, &ciphertext);
    try std.testing.expectEqual(expected_tag, tag);

    var decrypted: [plaintext.len]u8 = undefined;
    try Aead.decrypt(&decrypted, &ciphertext, tag, &aad, nonce, key);
    try std.testing.expectEqualStrings(plaintext, &decrypted);
}

test "RFC 5869 appendix A.1 HKDF-SHA256" {
    // Official vector: https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const ikm = [_]u8{0x0b} ** 22;
    const salt = decodeHex("000102030405060708090a0b0c");
    const info = decodeHex("f0f1f2f3f4f5f6f7f8f9");
    const expected_prk = decodeHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
    const expected_okm = decodeHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    const prk = Hkdf.extract(&salt, &ikm);
    try std.testing.expectEqual(expected_prk, prk);

    var okm: [expected_okm.len]u8 = undefined;
    Hkdf.expand(&okm, &info, prk);
    try std.testing.expectEqualSlices(u8, &expected_okm, &okm);
}

test "RFC 7748 section 5.2 X25519" {
    // Official vectors: https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2
    const X25519 = std.crypto.dh.X25519;
    const vectors = .{
        .{
            .scalar = decodeHex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
            .u_coordinate = decodeHex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"),
            .expected = decodeHex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
        },
        .{
            .scalar = decodeHex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
            .u_coordinate = decodeHex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"),
            .expected = decodeHex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
        },
    };

    inline for (vectors) |vector| {
        const shared = try X25519.scalarmult(vector.scalar, vector.u_coordinate);
        try std.testing.expectEqual(vector.expected, shared);
    }
}
