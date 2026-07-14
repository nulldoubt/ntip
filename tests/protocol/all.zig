const std = @import("std");
const protocol = @import("ntip_protocol");

test "bounded parsers reject arbitrary short prefixes without trapping" {
    var bytes = [_]u8{0xa5} ** 128;
    var length: usize = 0;
    while (length <= bytes.len) : (length += 1) {
        _ = protocol.header.Header.decode(bytes[0..length]) catch {};
        _ = protocol.control.Frame.decode(bytes[0..length]) catch {};
        _ = protocol.ipv4.Packet.parse(bytes[0..length]) catch {};
    }
}

test "every single-byte transport mutation fails or changes no replay state" {
    const key = [_]u8{0x42} ** protocol.transport.key_len;
    const header = protocol.header.Header{ .packet_type = .data, .context = 8, .sequence = 1 };
    var storage: [256]u8 = undefined;
    const sealed = try protocol.transport.seal(header, "authenticated packet", key, &storage);
    const sealed_len = sealed.len;

    var index: usize = 0;
    while (index < sealed_len) : (index += 1) {
        var mutated = storage;
        mutated[index] ^= 0x80;
        var window = protocol.replay.Window{};
        var plaintext: [256]u8 = undefined;
        _ = protocol.transport.open(mutated[0..sealed_len], key, &window, &plaintext) catch {};
        try std.testing.expect(!window.initialized);
    }
}

test "replay bitmap handles a deterministic reorder and future jump" {
    var window = protocol.replay.Window{};
    const order = [_]u64{ 5000, 4998, 4999, 3001, 7000, 6999, 9050, 9049 };
    for (order) |sequence| try window.commit(sequence);
    try std.testing.expectError(error.Duplicate, window.check(9050));
    try std.testing.expectError(error.Duplicate, window.check(9049));
    try std.testing.expectError(error.TooOld, window.check(7000));
    try std.testing.expectError(error.TooOld, window.check(5000));
    try window.check(9051);
    try std.testing.expectEqual(@as(u64, 9050), window.highest);
}

test "credential alphabet rejects padding and non-url-safe text" {
    const credential = protocol.credential.Credential{
        .handle = [_]u8{1} ** 16,
        .secret = [_]u8{2} ** 32,
        .master_public = [_]u8{3} ** 32,
    };
    var text: [protocol.credential.text_len]u8 = undefined;
    _ = credential.encode(&text);
    text[text.len - 1] = '=';
    try std.testing.expectError(error.InvalidCredentialEncoding, protocol.credential.Credential.decode(&text));
    text[text.len - 1] = '+';
    try std.testing.expectError(error.InvalidCredentialEncoding, protocol.credential.Credential.decode(&text));
}
