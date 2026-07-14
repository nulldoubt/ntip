const std = @import("std");

const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Blake2s = std.crypto.hash.blake2.Blake2s256;
const HmacBlake2s = std.crypto.auth.hmac.Hmac(Blake2s);
const X25519 = std.crypto.dh.X25519;

pub const xk_protocol_name = "Noise_XKpsk1_25519_ChaChaPoly_BLAKE2s";
pub const ik_protocol_name = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
pub const prologue_prefix = [_]u8{ 'N', 'T', 'I', 'P', 0, 1, 0 };
pub const context_len = 16;
pub const maximum_message_len: usize = 65_535;

pub const KeyPair = struct {
    secret: [32]u8,
    public: [32]u8,

    pub fn fromSecret(secret: [32]u8) !KeyPair {
        return .{
            .secret = secret,
            .public = X25519.recoverPublicKey(secret) catch return error.InvalidPrivateKey,
        };
    }

    pub fn generate(io: std.Io) KeyPair {
        const generated = X25519.KeyPair.generate(io);
        return .{ .secret = generated.secret_key, .public = generated.public_key };
    }
};

pub const DirectionalKeys = struct {
    initiator_to_responder: [32]u8,
    responder_to_initiator: [32]u8,
    handshake_hash: [32]u8,
};

pub const FinishRead = struct {
    payload: []u8,
    keys: DirectionalKeys,
};

pub const FinishWrite = struct {
    message: []u8,
    keys: DirectionalKeys,
};

const CipherState = struct {
    key: ?[32]u8 = null,
    nonce: u64 = 0,

    fn initializeKey(self: *CipherState, key: ?[32]u8) void {
        if (self.key) |*old_key| std.crypto.secureZero(u8, old_key);
        self.key = key;
        self.nonce = 0;
    }

    fn wipe(self: *CipherState) void {
        if (self.key) |*key| std.crypto.secureZero(u8, key);
        self.key = null;
        self.nonce = 0;
    }

    fn encryptWithAd(self: *CipherState, ad: []const u8, plaintext: []const u8, out: []u8) ![]u8 {
        if (self.key) |key| {
            if (self.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
            const needed = plaintext.len + Aead.tag_length;
            if (out.len < needed) return error.BufferTooSmall;
            const ciphertext = out[0..plaintext.len];
            var tag: [Aead.tag_length]u8 = undefined;
            Aead.encrypt(ciphertext, &tag, plaintext, ad, nonceBytes(self.nonce), key);
            @memcpy(out[plaintext.len..needed], &tag);
            self.nonce += 1;
            return out[0..needed];
        }
        if (out.len < plaintext.len) return error.BufferTooSmall;
        @memcpy(out[0..plaintext.len], plaintext);
        return out[0..plaintext.len];
    }

    fn decryptWithAd(self: *CipherState, ad: []const u8, ciphertext_and_tag: []const u8, out: []u8) ![]u8 {
        if (self.key) |key| {
            if (self.nonce == std.math.maxInt(u64)) return error.NonceExhausted;
            if (ciphertext_and_tag.len < Aead.tag_length) return error.TruncatedCiphertext;
            const plaintext_len = ciphertext_and_tag.len - Aead.tag_length;
            if (out.len < plaintext_len) return error.BufferTooSmall;
            const ciphertext = ciphertext_and_tag[0..plaintext_len];
            const tag = ciphertext_and_tag[plaintext_len..][0..Aead.tag_length].*;
            Aead.decrypt(out[0..plaintext_len], ciphertext, tag, ad, nonceBytes(self.nonce), key) catch {
                return error.AuthenticationFailed;
            };
            self.nonce += 1;
            return out[0..plaintext_len];
        }
        if (out.len < ciphertext_and_tag.len) return error.BufferTooSmall;
        @memcpy(out[0..ciphertext_and_tag.len], ciphertext_and_tag);
        return out[0..ciphertext_and_tag.len];
    }
};

const SymmetricState = struct {
    chaining_key: [32]u8,
    handshake_hash: [32]u8,
    cipher: CipherState,

    fn initialize(protocol_name: []const u8, context: [context_len]u8) SymmetricState {
        var initial_hash = [_]u8{0} ** 32;
        if (protocol_name.len <= initial_hash.len) {
            @memcpy(initial_hash[0..protocol_name.len], protocol_name);
        } else {
            Blake2s.hash(protocol_name, &initial_hash, .{});
        }
        var self = SymmetricState{
            .chaining_key = initial_hash,
            .handshake_hash = initial_hash,
            .cipher = .{},
        };
        var prologue: [prologue_prefix.len + context_len]u8 = undefined;
        @memcpy(prologue[0..prologue_prefix.len], &prologue_prefix);
        @memcpy(prologue[prologue_prefix.len..], &context);
        self.mixHash(&prologue);
        return self;
    }

    fn mixHash(self: *SymmetricState, data: []const u8) void {
        var hash = Blake2s.init(.{});
        hash.update(&self.handshake_hash);
        hash.update(data);
        hash.final(&self.handshake_hash);
    }

    fn mixKey(self: *SymmetricState, input_key_material: []const u8) void {
        var output = hkdf2(self.chaining_key, input_key_material);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&output));
        self.chaining_key = output[0];
        self.cipher.initializeKey(output[1]);
    }

    fn mixKeyAndHash(self: *SymmetricState, input_key_material: []const u8) void {
        var output = hkdf3(self.chaining_key, input_key_material);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&output));
        self.chaining_key = output[0];
        self.mixHash(&output[1]);
        self.cipher.initializeKey(output[2]);
    }

    fn encryptAndHash(self: *SymmetricState, plaintext: []const u8, out: []u8) ![]u8 {
        const ciphertext = try self.cipher.encryptWithAd(&self.handshake_hash, plaintext, out);
        self.mixHash(ciphertext);
        return ciphertext;
    }

    fn decryptAndHash(self: *SymmetricState, ciphertext: []const u8, out: []u8) ![]u8 {
        const plaintext = try self.cipher.decryptWithAd(&self.handshake_hash, ciphertext, out);
        self.mixHash(ciphertext);
        return plaintext;
    }

    fn split(self: *const SymmetricState) DirectionalKeys {
        var output = hkdf2(self.chaining_key, "");
        defer std.crypto.secureZero(u8, std.mem.asBytes(&output));
        const keys = DirectionalKeys{
            .initiator_to_responder = output[0],
            .responder_to_initiator = output[1],
            .handshake_hash = self.handshake_hash,
        };
        return keys;
    }

    fn wipe(self: *SymmetricState) void {
        std.crypto.secureZero(u8, &self.chaining_key);
        std.crypto.secureZero(u8, &self.handshake_hash);
        self.cipher.wipe();
    }
};

fn hkdf2(chaining_key: [32]u8, input: []const u8) [2][32]u8 {
    var temp_key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &temp_key);
    HmacBlake2s.create(&temp_key, input, &chaining_key);

    var output: [2][32]u8 = undefined;
    HmacBlake2s.create(&output[0], &.{1}, &temp_key);
    var second = HmacBlake2s.init(&temp_key);
    second.update(&output[0]);
    second.update(&.{2});
    second.final(&output[1]);
    return output;
}

fn hkdf3(chaining_key: [32]u8, input: []const u8) [3][32]u8 {
    var temp_key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &temp_key);
    HmacBlake2s.create(&temp_key, input, &chaining_key);

    var output: [3][32]u8 = undefined;
    HmacBlake2s.create(&output[0], &.{1}, &temp_key);
    var second = HmacBlake2s.init(&temp_key);
    second.update(&output[0]);
    second.update(&.{2});
    second.final(&output[1]);
    var third = HmacBlake2s.init(&temp_key);
    third.update(&output[1]);
    third.update(&.{3});
    third.final(&output[2]);
    return output;
}

fn nonceBytes(nonce: u64) [Aead.nonce_length]u8 {
    var bytes = [_]u8{0} ** Aead.nonce_length;
    std.mem.writeInt(u64, bytes[4..12], nonce, .little);
    return bytes;
}

fn dh(secret: [32]u8, public: [32]u8) ![32]u8 {
    const shared = X25519.scalarmult(secret, public) catch return error.InvalidDhPublicKey;
    if (std.crypto.timing_safe.eql([32]u8, shared, [_]u8{0} ** 32)) return error.InvalidDhPublicKey;
    return shared;
}

fn mixDh(symmetric: *SymmetricState, secret: [32]u8, public: [32]u8) !void {
    var shared = try dh(secret, public);
    defer std.crypto.secureZero(u8, &shared);
    symmetric.mixKey(&shared);
}

fn wipeKeyPair(key_pair: *KeyPair) void {
    std.crypto.secureZero(u8, &key_pair.secret);
}

fn appendClear(out: []u8, offset: *usize, bytes: []const u8) !void {
    if (offset.* + bytes.len > maximum_message_len or offset.* + bytes.len > out.len) return error.BufferTooSmall;
    @memcpy(out[offset.* .. offset.* + bytes.len], bytes);
    offset.* += bytes.len;
}

fn appendEncrypted(symmetric: *SymmetricState, out: []u8, offset: *usize, plaintext: []const u8) !void {
    if (offset.* > maximum_message_len or plaintext.len > maximum_message_len - offset.*) return error.MessageTooLarge;
    const ciphertext = try symmetric.encryptAndHash(plaintext, out[offset.*..]);
    if (offset.* + ciphertext.len > maximum_message_len) return error.MessageTooLarge;
    offset.* += ciphertext.len;
}

fn remainingEncryptedPayload(symmetric: *SymmetricState, message: []const u8, offset: usize, out: []u8) ![]u8 {
    if (message.len > maximum_message_len or offset > message.len) return error.InvalidHandshakeLength;
    return symmetric.decryptAndHash(message[offset..], out);
}

pub const XkInitiator = struct {
    symmetric: SymmetricState,
    static: KeyPair,
    ephemeral: KeyPair,
    remote_static: [32]u8,
    remote_ephemeral: [32]u8 = [_]u8{0} ** 32,
    psk: [32]u8,
    step: enum { write_one, read_two, write_three, complete } = .write_one,
    failed: bool = false,

    /// `ephemeral` must be freshly generated for this handshake. The caller
    /// caches serialized output for retransmission instead of reusing a key in
    /// a second handshake.
    pub fn init(static: KeyPair, ephemeral: KeyPair, remote_static: [32]u8, psk: [32]u8, context: [context_len]u8) XkInitiator {
        var symmetric = SymmetricState.initialize(xk_protocol_name, context);
        symmetric.mixHash(&remote_static);
        return .{ .symmetric = symmetric, .static = static, .ephemeral = ephemeral, .remote_static = remote_static, .psk = psk };
    }

    pub fn deinit(self: *XkInitiator) void {
        self.wipeSecrets();
        self.failed = true;
    }

    fn wipeSecrets(self: *XkInitiator) void {
        self.symmetric.wipe();
        wipeKeyPair(&self.static);
        wipeKeyPair(&self.ephemeral);
        std.crypto.secureZero(u8, &self.psk);
    }

    pub fn writeMessageOne(self: *XkInitiator, payload: []const u8, out: []u8) ![]u8 {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .write_one) return error.InvalidHandshakeState;
        errdefer self.deinit();
        var offset: usize = 0;
        try appendClear(out, &offset, &self.ephemeral.public);
        self.symmetric.mixHash(&self.ephemeral.public);
        self.symmetric.mixKey(&self.ephemeral.public);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_static);
        self.symmetric.mixKeyAndHash(&self.psk);
        try appendEncrypted(&self.symmetric, out, &offset, payload);
        self.step = .read_two;
        return out[0..offset];
    }

    pub fn readMessageTwo(self: *XkInitiator, message: []const u8, payload_out: []u8) ![]u8 {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .read_two) return error.InvalidHandshakeState;
        errdefer self.deinit();
        if (message.len < 32 + Aead.tag_length or message.len > maximum_message_len) return error.InvalidHandshakeLength;
        self.remote_ephemeral = message[0..32].*;
        self.symmetric.mixHash(&self.remote_ephemeral);
        self.symmetric.mixKey(&self.remote_ephemeral);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_ephemeral);
        const payload = try remainingEncryptedPayload(&self.symmetric, message, 32, payload_out);
        self.step = .write_three;
        return payload;
    }

    pub fn writeMessageThree(self: *XkInitiator, payload: []const u8, out: []u8) !FinishWrite {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .write_three) return error.InvalidHandshakeState;
        errdefer self.deinit();
        var offset: usize = 0;
        try appendEncrypted(&self.symmetric, out, &offset, &self.static.public);
        try mixDh(&self.symmetric, self.static.secret, self.remote_ephemeral);
        try appendEncrypted(&self.symmetric, out, &offset, payload);
        const keys = self.symmetric.split();
        self.step = .complete;
        self.wipeSecrets();
        return .{ .message = out[0..offset], .keys = keys };
    }
};

pub const XkResponder = struct {
    symmetric: SymmetricState,
    static: KeyPair,
    ephemeral: KeyPair,
    remote_static: [32]u8 = [_]u8{0} ** 32,
    remote_ephemeral: [32]u8 = [_]u8{0} ** 32,
    psk: [32]u8,
    step: enum { read_one, write_two, read_three, complete } = .read_one,
    failed: bool = false,

    /// `ephemeral` must be freshly generated for this handshake.
    pub fn init(static: KeyPair, ephemeral: KeyPair, psk: [32]u8, context: [context_len]u8) XkResponder {
        var symmetric = SymmetricState.initialize(xk_protocol_name, context);
        symmetric.mixHash(&static.public);
        return .{ .symmetric = symmetric, .static = static, .ephemeral = ephemeral, .psk = psk };
    }

    pub fn deinit(self: *XkResponder) void {
        self.wipeSecrets();
        self.failed = true;
    }

    fn wipeSecrets(self: *XkResponder) void {
        self.symmetric.wipe();
        wipeKeyPair(&self.static);
        wipeKeyPair(&self.ephemeral);
        std.crypto.secureZero(u8, &self.psk);
    }

    pub fn readMessageOne(self: *XkResponder, message: []const u8, payload_out: []u8) ![]u8 {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .read_one) return error.InvalidHandshakeState;
        errdefer self.deinit();
        if (message.len < 32 + Aead.tag_length or message.len > maximum_message_len) return error.InvalidHandshakeLength;
        self.remote_ephemeral = message[0..32].*;
        self.symmetric.mixHash(&self.remote_ephemeral);
        self.symmetric.mixKey(&self.remote_ephemeral);
        try mixDh(&self.symmetric, self.static.secret, self.remote_ephemeral);
        self.symmetric.mixKeyAndHash(&self.psk);
        const payload = try remainingEncryptedPayload(&self.symmetric, message, 32, payload_out);
        self.step = .write_two;
        return payload;
    }

    pub fn writeMessageTwo(self: *XkResponder, payload: []const u8, out: []u8) ![]u8 {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .write_two) return error.InvalidHandshakeState;
        errdefer self.deinit();
        var offset: usize = 0;
        try appendClear(out, &offset, &self.ephemeral.public);
        self.symmetric.mixHash(&self.ephemeral.public);
        self.symmetric.mixKey(&self.ephemeral.public);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_ephemeral);
        try appendEncrypted(&self.symmetric, out, &offset, payload);
        self.step = .read_three;
        return out[0..offset];
    }

    pub fn readMessageThree(self: *XkResponder, message: []const u8, payload_out: []u8) !FinishRead {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .read_three) return error.InvalidHandshakeState;
        errdefer self.deinit();
        if (message.len < 48 + Aead.tag_length or message.len > maximum_message_len) return error.InvalidHandshakeLength;
        const static_plaintext = try self.symmetric.decryptAndHash(message[0..48], &self.remote_static);
        if (static_plaintext.len != 32) return error.InvalidStaticKey;
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_static);
        const payload = try remainingEncryptedPayload(&self.symmetric, message, 48, payload_out);
        const keys = self.symmetric.split();
        self.step = .complete;
        self.wipeSecrets();
        return .{ .payload = payload, .keys = keys };
    }

    pub fn remoteStatic(self: *const XkResponder) ![32]u8 {
        if (self.step != .complete) return error.InvalidHandshakeState;
        return self.remote_static;
    }
};

pub const IkInitiator = struct {
    symmetric: SymmetricState,
    static: KeyPair,
    ephemeral: KeyPair,
    remote_static: [32]u8,
    remote_ephemeral: [32]u8 = [_]u8{0} ** 32,
    step: enum { write_one, read_two, complete } = .write_one,
    failed: bool = false,

    /// `ephemeral` must be freshly generated for this full reconnect/rekey.
    pub fn init(static: KeyPair, ephemeral: KeyPair, remote_static: [32]u8, context: [context_len]u8) IkInitiator {
        var symmetric = SymmetricState.initialize(ik_protocol_name, context);
        symmetric.mixHash(&remote_static);
        return .{ .symmetric = symmetric, .static = static, .ephemeral = ephemeral, .remote_static = remote_static };
    }

    pub fn deinit(self: *IkInitiator) void {
        self.wipeSecrets();
        self.failed = true;
    }

    fn wipeSecrets(self: *IkInitiator) void {
        self.symmetric.wipe();
        wipeKeyPair(&self.static);
        wipeKeyPair(&self.ephemeral);
    }

    pub fn writeMessageOne(self: *IkInitiator, payload: []const u8, out: []u8) ![]u8 {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .write_one) return error.InvalidHandshakeState;
        errdefer self.deinit();
        var offset: usize = 0;
        try appendClear(out, &offset, &self.ephemeral.public);
        self.symmetric.mixHash(&self.ephemeral.public);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_static);
        try appendEncrypted(&self.symmetric, out, &offset, &self.static.public);
        try mixDh(&self.symmetric, self.static.secret, self.remote_static);
        try appendEncrypted(&self.symmetric, out, &offset, payload);
        self.step = .read_two;
        return out[0..offset];
    }

    pub fn readMessageTwo(self: *IkInitiator, message: []const u8, payload_out: []u8) !FinishRead {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .read_two) return error.InvalidHandshakeState;
        errdefer self.deinit();
        if (message.len < 32 + Aead.tag_length or message.len > maximum_message_len) return error.InvalidHandshakeLength;
        self.remote_ephemeral = message[0..32].*;
        self.symmetric.mixHash(&self.remote_ephemeral);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_ephemeral);
        try mixDh(&self.symmetric, self.static.secret, self.remote_ephemeral);
        const payload = try remainingEncryptedPayload(&self.symmetric, message, 32, payload_out);
        const keys = self.symmetric.split();
        self.step = .complete;
        self.wipeSecrets();
        return .{ .payload = payload, .keys = keys };
    }
};

pub const IkResponder = struct {
    symmetric: SymmetricState,
    static: KeyPair,
    ephemeral: KeyPair,
    remote_static: [32]u8 = [_]u8{0} ** 32,
    expected_remote_static: [32]u8,
    remote_ephemeral: [32]u8 = [_]u8{0} ** 32,
    step: enum { read_one, write_two, complete } = .read_one,
    failed: bool = false,

    /// `ephemeral` must be freshly generated for this full reconnect/rekey.
    pub fn init(static: KeyPair, ephemeral: KeyPair, expected_remote_static: [32]u8, context: [context_len]u8) IkResponder {
        var symmetric = SymmetricState.initialize(ik_protocol_name, context);
        symmetric.mixHash(&static.public);
        return .{ .symmetric = symmetric, .static = static, .ephemeral = ephemeral, .expected_remote_static = expected_remote_static };
    }

    pub fn deinit(self: *IkResponder) void {
        self.wipeSecrets();
        self.failed = true;
    }

    fn wipeSecrets(self: *IkResponder) void {
        self.symmetric.wipe();
        wipeKeyPair(&self.static);
        wipeKeyPair(&self.ephemeral);
    }

    pub fn readMessageOne(self: *IkResponder, message: []const u8, payload_out: []u8) ![]u8 {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .read_one) return error.InvalidHandshakeState;
        errdefer self.deinit();
        if (message.len < 32 + 48 + Aead.tag_length or message.len > maximum_message_len) return error.InvalidHandshakeLength;
        self.remote_ephemeral = message[0..32].*;
        self.symmetric.mixHash(&self.remote_ephemeral);
        try mixDh(&self.symmetric, self.static.secret, self.remote_ephemeral);
        const static_plaintext = try self.symmetric.decryptAndHash(message[32..80], &self.remote_static);
        if (static_plaintext.len != 32) return error.InvalidStaticKey;
        if (!std.crypto.timing_safe.eql([32]u8, self.remote_static, self.expected_remote_static)) {
            return error.UnexpectedRemoteStatic;
        }
        try mixDh(&self.symmetric, self.static.secret, self.remote_static);
        const payload = try remainingEncryptedPayload(&self.symmetric, message, 80, payload_out);
        self.step = .write_two;
        return payload;
    }

    pub fn writeMessageTwo(self: *IkResponder, payload: []const u8, out: []u8) !FinishWrite {
        if (self.failed) return error.HandshakeFailed;
        if (self.step != .write_two) return error.InvalidHandshakeState;
        errdefer self.deinit();
        var offset: usize = 0;
        try appendClear(out, &offset, &self.ephemeral.public);
        self.symmetric.mixHash(&self.ephemeral.public);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_ephemeral);
        try mixDh(&self.symmetric, self.ephemeral.secret, self.remote_static);
        try appendEncrypted(&self.symmetric, out, &offset, payload);
        const keys = self.symmetric.split();
        self.step = .complete;
        self.wipeSecrets();
        return .{ .message = out[0..offset], .keys = keys };
    }

    pub fn remoteStatic(self: *const IkResponder) ![32]u8 {
        if (self.step != .complete) return error.InvalidHandshakeState;
        return self.remote_static;
    }
};

fn testKey(fill: u8) !KeyPair {
    var secret = [_]u8{fill} ** 32;
    secret[0] +%= 1;
    return KeyPair.fromSecret(secret);
}

fn expectHex(expected_hex: []const u8, actual: []const u8) !void {
    if (expected_hex.len != actual.len * 2) return error.InvalidGoldenVector;
    var expected: [maximum_message_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected[0..actual.len], expected_hex);
    try std.testing.expectEqualSlices(u8, expected[0..actual.len], actual);
}

const initiator_transport_payload = "node-to-master";
const responder_transport_payload = "master-to-node";

fn expectFirstTransportCiphertext(expected_hex: []const u8, key: [32]u8, plaintext: []const u8) !void {
    var encryptor = CipherState{};
    encryptor.initializeKey(key);
    defer encryptor.wipe();
    var ciphertext_storage: [128]u8 = undefined;
    const ciphertext = try encryptor.encryptWithAd("", plaintext, &ciphertext_storage);
    try expectHex(expected_hex, ciphertext);

    var decryptor = CipherState{};
    decryptor.initializeKey(key);
    defer decryptor.wipe();
    var plaintext_storage: [128]u8 = undefined;
    const decrypted = try decryptor.decryptWithAd("", ciphertext, &plaintext_storage);
    try std.testing.expectEqualStrings(plaintext, decrypted);
}

test "XKpsk1 deterministic transcript agrees and derives directional keys" {
    // Golden handshake and transport values are produced independently by the
    // pinned Python and Go oracles under tests/protocol/.
    const node_static = try testKey(1);
    const master_static = try testKey(2);
    const node_ephemeral = try testKey(3);
    const master_ephemeral = try testKey(4);
    const psk = [_]u8{5} ** 32;
    const context = [_]u8{6} ** context_len;

    var initiator = XkInitiator.init(node_static, node_ephemeral, master_static.public, psk, context);
    var responder = XkResponder.init(master_static, master_ephemeral, psk, context);
    var message_one: [256]u8 = undefined;
    var message_two: [256]u8 = undefined;
    var message_three: [256]u8 = undefined;
    var payload: [128]u8 = undefined;

    const m1 = try initiator.writeMessageOne("enroll", &message_one);
    try std.testing.expectEqual(@as(usize, 32 + 6 + 16), m1.len);
    try expectHex("5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22488e3f6e979e6c0d255b27e07091d5556770d9575edf", m1);
    try std.testing.expectEqualStrings("enroll", try responder.readMessageOne(m1, &payload));
    const m2 = try responder.writeMessageTwo("accept", &message_two);
    try expectHex("ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b50cf3d489135073dc41b52a892a92c4ed4ae4e6d6ba4", m2);
    try std.testing.expectEqualStrings("accept", try initiator.readMessageTwo(m2, &payload));
    const initiator_finish = try initiator.writeMessageThree("confirm", &message_three);
    try expectHex("d58fdac4e38f4c30be25fc8347deffdc74ab84b435bbaa378da5510415ac1f724e5c378016ca8d37e63a7e6486f5c603877d2a27475d9cc6c024422a74ea7d397c761a4d4ceb82", initiator_finish.message);
    const responder_finish = try responder.readMessageThree(initiator_finish.message, &payload);
    try std.testing.expectEqualStrings("confirm", responder_finish.payload);
    try std.testing.expectEqual(initiator_finish.keys, responder_finish.keys);
    try expectHex("80620c7269251e42db8135f93a7d22ded094d4335afd0376f922b08f062b8445", &initiator_finish.keys.handshake_hash);
    try expectFirstTransportCiphertext("3f52b62a847b155ceb79b189ed94061d100104b2d03fcb69c2d08e7142fb", initiator_finish.keys.initiator_to_responder, initiator_transport_payload);
    try expectFirstTransportCiphertext("4c3111e8e0e2870d87f9f6364542a1fd2b4db915b6db2b87c9b7041a49b4", initiator_finish.keys.responder_to_initiator, responder_transport_payload);
    try std.testing.expectEqual(node_static.public, try responder.remoteStatic());
}

test "IK deterministic transcript agrees and authenticates both static keys" {
    const node_static = try testKey(11);
    const master_static = try testKey(12);
    const node_ephemeral = try testKey(13);
    const master_ephemeral = try testKey(14);
    const context = [_]u8{15} ** context_len;

    var initiator = IkInitiator.init(node_static, node_ephemeral, master_static.public, context);
    var responder = IkResponder.init(master_static, master_ephemeral, node_static.public, context);
    var message_one: [256]u8 = undefined;
    var message_two: [256]u8 = undefined;
    var payload: [128]u8 = undefined;

    const m1 = try initiator.writeMessageOne("reconnect", &message_one);
    try std.testing.expectEqual(@as(usize, 32 + 48 + 9 + 16), m1.len);
    try expectHex("b307ae8660efaed4d6a65f6640896892ea4a1f0075555c489d1312a2e1677c284f7b35cc256824a63302bfd173ece0200cb500cf8ac1d70b5c9af56918813e2ce035f2da81de55a0a48b85f91d36eac2bc52db39e052f9a2c71ff0e29d7ce0d634471fec9ce04439a9", m1);
    try std.testing.expectEqualStrings("reconnect", try responder.readMessageOne(m1, &payload));
    const responder_finish = try responder.writeMessageTwo("session", &message_two);
    try expectHex("5855784cb3c8c796d84ac93e8f4a53dab0bb31e80960042cfa87f03a4293b30832dfd3c7c6693f3b523ec50a8836fb1e0b63f5c9f003d8", responder_finish.message);
    const initiator_finish = try initiator.readMessageTwo(responder_finish.message, &payload);
    try std.testing.expectEqualStrings("session", initiator_finish.payload);
    try std.testing.expectEqual(responder_finish.keys, initiator_finish.keys);
    try expectHex("2e3b030c89bf7c82b59bdcd4cb93c19f9433b0db491ec305b41991283f644048", &responder_finish.keys.handshake_hash);
    try expectFirstTransportCiphertext("d439ae16587490b7f2c747a95e8eea17caa278af0a09fc9aa66608e462ab", responder_finish.keys.initiator_to_responder, initiator_transport_payload);
    try expectFirstTransportCiphertext("f340ed6fc1ea9c14c90b6cefc6137412dd6246d9720ef7d667984911c8c3", responder_finish.keys.responder_to_initiator, responder_transport_payload);
    try std.testing.expectEqual(node_static.public, try responder.remoteStatic());
}

test "wrong PSK, altered context, tamper, and all-zero DH fail closed" {
    const node_static = try testKey(21);
    const master_static = try testKey(22);
    const node_ephemeral = try testKey(23);
    const master_ephemeral = try testKey(24);
    const context = [_]u8{25} ** context_len;
    var initiator = XkInitiator.init(node_static, node_ephemeral, master_static.public, [_]u8{1} ** 32, context);
    var responder = XkResponder.init(master_static, master_ephemeral, [_]u8{2} ** 32, context);
    var message: [256]u8 = undefined;
    var payload: [128]u8 = undefined;
    const m1 = try initiator.writeMessageOne("x", &message);
    try std.testing.expectError(error.AuthenticationFailed, responder.readMessageOne(m1, &payload));
    try std.testing.expectError(error.HandshakeFailed, responder.readMessageOne(m1, &payload));

    var ik_initiator = IkInitiator.init(node_static, node_ephemeral, master_static.public, context);
    var altered_context = context;
    altered_context[0] ^= 1;
    var ik_responder = IkResponder.init(master_static, master_ephemeral, node_static.public, altered_context);
    const ik_m1 = try ik_initiator.writeMessageOne("x", &message);
    try std.testing.expectError(error.AuthenticationFailed, ik_responder.readMessageOne(ik_m1, &payload));

    const wrong_node = try testKey(26);
    var keyed_initiator = IkInitiator.init(node_static, node_ephemeral, master_static.public, context);
    var wrong_key_responder = IkResponder.init(master_static, master_ephemeral, wrong_node.public, context);
    const keyed_m1 = try keyed_initiator.writeMessageOne("x", &message);
    try std.testing.expectError(error.UnexpectedRemoteStatic, wrong_key_responder.readMessageOne(keyed_m1, &payload));

    var good_initiator = XkInitiator.init(node_static, node_ephemeral, master_static.public, [_]u8{3} ** 32, context);
    var good_responder = XkResponder.init(master_static, master_ephemeral, [_]u8{3} ** 32, context);
    const good_m1 = try good_initiator.writeMessageOne("tamper", &message);
    message[good_m1.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, good_responder.readMessageOne(message[0..good_m1.len], &payload));
    try std.testing.expectError(error.HandshakeFailed, good_responder.readMessageOne(message[0..good_m1.len], &payload));

    try std.testing.expectError(error.InvalidDhPublicKey, dh(node_static.secret, [_]u8{0} ** 32));
}
