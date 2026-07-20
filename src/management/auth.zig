const std = @import("std");

pub const username_max_len: usize = 63;
pub const password_min_codepoints: usize = 14;
pub const password_max_codepoints: usize = 256;
pub const password_max_bytes: usize = 1024;
pub const session_token_len: usize = 32;
pub const session_token_text_len: usize = session_token_len * 2;
pub const idle_timeout_seconds: u64 = 30 * 60;
pub const absolute_timeout_seconds: u64 = 12 * 60 * 60;
pub const reauthentication_window_seconds: u64 = 5 * 60;

pub const password_params = std.crypto.pwhash.argon2.Params{
    .t = 3,
    .m = 64 * 1024,
    .p = 1,
};

pub const Role = enum {
    viewer,
    operator,
    superuser,
};

pub const Permission = enum {
    read,
    update_inventory,
    run_connectivity_check,
    delete_inventory,
    manage_enrollment,
    manage_users,
    manage_all_sessions,
    manage_settings,
    manage_audit,
    control_service,
};

pub fn allows(role: Role, permission: Permission) bool {
    return switch (permission) {
        .read => true,
        .update_inventory, .run_connectivity_check => role == .operator or role == .superuser,
        .delete_inventory,
        .manage_enrollment,
        .manage_users,
        .manage_all_sessions,
        .manage_settings,
        .manage_audit,
        .control_service,
        => role == .superuser,
    };
}

pub const Username = struct {
    len: u8,
    bytes: [username_max_len]u8,

    pub fn parse(text: []const u8) error{InvalidUsername}!Username {
        if (text.len == 0 or text.len > username_max_len) return error.InvalidUsername;
        var result = Username{ .len = @intCast(text.len), .bytes = [_]u8{0} ** username_max_len };
        for (text, 0..) |byte, index| {
            if (!std.ascii.isAscii(byte)) return error.InvalidUsername;
            const canonical = std.ascii.toLower(byte);
            const valid = std.ascii.isAlphanumeric(canonical) or canonical == '-' or canonical == '_' or canonical == '.';
            if (!valid) return error.InvalidUsername;
            if (index == 0 and !std.ascii.isAlphanumeric(canonical)) return error.InvalidUsername;
            result.bytes[index] = canonical;
        }
        return result;
    }

    pub fn slice(self: *const Username) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn validatePassword(password: []const u8) error{InvalidPassword}!void {
    if (password.len == 0 or password.len > password_max_bytes) return error.InvalidPassword;
    if (std.mem.indexOfScalar(u8, password, 0) != null) return error.InvalidPassword;
    const codepoints = std.unicode.utf8CountCodepoints(password) catch return error.InvalidPassword;
    if (codepoints < password_min_codepoints or codepoints > password_max_codepoints) {
        return error.InvalidPassword;
    }
}

pub const PasswordHash = struct {
    len: u8,
    bytes: [128]u8,

    pub fn create(allocator: std.mem.Allocator, io: std.Io, password: []const u8) !PasswordHash {
        try validatePassword(password);
        var result = PasswordHash{ .len = 0, .bytes = [_]u8{0} ** 128 };
        const encoded = try std.crypto.pwhash.argon2.strHash(
            password,
            .{ .allocator = allocator, .params = password_params, .mode = .argon2id },
            &result.bytes,
            io,
        );
        result.len = @intCast(encoded.len);
        return result;
    }

    pub fn parse(encoded: []const u8) error{InvalidPasswordHash}!PasswordHash {
        if (encoded.len == 0 or encoded.len > 128) return error.InvalidPasswordHash;
        var result = PasswordHash{ .len = @intCast(encoded.len), .bytes = [_]u8{0} ** 128 };
        @memcpy(result.bytes[0..encoded.len], encoded);
        return result;
    }

    pub fn slice(self: *const PasswordHash) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn verify(self: *const PasswordHash, allocator: std.mem.Allocator, io: std.Io, password: []const u8) bool {
        validatePassword(password) catch return false;
        std.crypto.pwhash.argon2.strVerify(
            self.slice(),
            password,
            .{ .allocator = allocator },
            io,
        ) catch return false;
        return true;
    }

    /// A successful login rewrites any otherwise valid PHC string that does
    /// not carry the exact fixed v0.2 Argon2id cost tuple.
    pub fn needsRehash(self: *const PasswordHash) bool {
        return !std.mem.startsWith(u8, self.slice(), "$argon2id$v=19$m=65536,t=3,p=1$");
    }
};

pub const SecretToken = struct {
    bytes: [session_token_len]u8,

    pub fn generate(io: std.Io) SecretToken {
        var token: SecretToken = undefined;
        io.random(&token.bytes);
        return token;
    }

    pub fn encode(self: SecretToken, output: *[session_token_text_len]u8) []const u8 {
        const alphabet = "0123456789abcdef";
        for (self.bytes, 0..) |byte, index| {
            output[index * 2] = alphabet[byte >> 4];
            output[index * 2 + 1] = alphabet[byte & 0x0f];
        }
        return output;
    }

    pub fn parse(text: []const u8) error{InvalidToken}!SecretToken {
        if (text.len != session_token_text_len) return error.InvalidToken;
        var token: SecretToken = undefined;
        for (&token.bytes, 0..) |*byte, index| {
            const high = decodeNibble(text[index * 2]) orelse return error.InvalidToken;
            const low = decodeNibble(text[index * 2 + 1]) orelse return error.InvalidToken;
            byte.* = high << 4 | low;
        }
        return token;
    }

    pub fn hash(self: SecretToken) [32]u8 {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&self.bytes, &digest, .{});
        return digest;
    }
};

pub const SessionTimes = struct {
    created_at: u64,
    last_seen_at: u64,

    pub fn idleExpiresAt(self: SessionTimes) u64 {
        return std.math.add(u64, self.last_seen_at, idle_timeout_seconds) catch std.math.maxInt(u64);
    }

    pub fn absoluteExpiresAt(self: SessionTimes) u64 {
        return std.math.add(u64, self.created_at, absolute_timeout_seconds) catch std.math.maxInt(u64);
    }

    pub fn isExpired(self: SessionTimes, now: u64) bool {
        return now >= self.idleExpiresAt() or now >= self.absoluteExpiresAt();
    }
};

pub fn recentlyReauthenticated(reauthenticated_at: ?u64, now: u64) bool {
    const at = reauthenticated_at orelse return false;
    if (at > now) return false;
    return now - at <= reauthentication_window_seconds;
}

fn decodeNibble(value: u8) ?u8 {
    return switch (value) {
        '0'...'9' => value - '0',
        'a'...'f' => value - 'a' + 10,
        else => null,
    };
}

test "usernames canonicalize to lowercase strict ASCII" {
    const username = try Username.parse("Operator_01");
    try std.testing.expectEqualStrings("operator_01", username.slice());
    try std.testing.expectError(error.InvalidUsername, Username.parse("-operator"));
    try std.testing.expectError(error.InvalidUsername, Username.parse("oper ator"));
    try std.testing.expectError(error.InvalidUsername, Username.parse("opérator"));
}

test "password policy permits long Unicode passphrases without composition rules" {
    try validatePassword("correct horse battery staple");
    try validatePassword("شبكة آمنة طويلة جدا");
    try std.testing.expectError(error.InvalidPassword, validatePassword("too short"));
    try std.testing.expectError(error.InvalidPassword, validatePassword("valid length but\x00bad"));
    try std.testing.expectError(error.InvalidPassword, validatePassword("invalid utf8 \xff repeated"));
}

test "password hashes use the fixed production Argon2id policy" {
    var hash = try PasswordHash.create(std.testing.allocator, std.testing.io, "correct horse battery staple");
    defer std.crypto.secureZero(u8, &hash.bytes);
    try std.testing.expect(std.mem.startsWith(u8, hash.slice(), "$argon2id$v=19$m=65536,t=3,p=1$"));
    try std.testing.expect(hash.verify(std.testing.allocator, std.testing.io, "correct horse battery staple"));
    try std.testing.expect(!hash.verify(std.testing.allocator, std.testing.io, "incorrect horse battery staple"));
    try std.testing.expect(!hash.needsRehash());
    const legacy = try PasswordHash.parse("$argon2id$v=19$m=32768,t=2,p=1$salt$hash");
    try std.testing.expect(legacy.needsRehash());
}

test "opaque tokens round trip and hash deterministically" {
    const token = SecretToken.generate(std.testing.io);
    var text: [session_token_text_len]u8 = undefined;
    const parsed = try SecretToken.parse(token.encode(&text));
    try std.testing.expectEqualSlices(u8, &token.bytes, &parsed.bytes);
    try std.testing.expect(std.crypto.timing_safe.eql([32]u8, token.hash(), parsed.hash()));
    try std.testing.expectError(error.InvalidToken, SecretToken.parse("ABC"));
}

test "session and authorization policy is explicit" {
    try std.testing.expect(allows(.viewer, .read));
    try std.testing.expect(!allows(.viewer, .run_connectivity_check));
    try std.testing.expect(allows(.operator, .update_inventory));
    try std.testing.expect(!allows(.operator, .delete_inventory));
    try std.testing.expect(allows(.superuser, .control_service));

    const session = SessionTimes{ .created_at = 100, .last_seen_at = 200 };
    try std.testing.expect(!session.isExpired(300));
    try std.testing.expect(session.isExpired(200 + idle_timeout_seconds));
    try std.testing.expect(recentlyReauthenticated(1000, 1000 + reauthentication_window_seconds));
    try std.testing.expect(!recentlyReauthenticated(1000, 1001 + reauthentication_window_seconds));
}
