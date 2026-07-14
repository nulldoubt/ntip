const std = @import("std");
const atomic = @import("atomic_file.zig");

const magic = "NTIPSECR";
const format_version: u8 = 1;
const header_len = 12;
const digest_len = 32;
const max_secret_len = 4096;

pub const SecretKind = enum(u8) {
    identity_key = 1,
    enrollment_token = 2,
};

pub const FileSecretStore = struct {
    dir: std.Io.Dir,

    pub fn write(self: FileSecretStore, allocator: std.mem.Allocator, io: std.Io, name: []const u8, kind: SecretKind, secret: []const u8) !void {
        try validateLength(kind, secret.len);
        const total = header_len + secret.len + digest_len;
        const encoded = try allocator.alloc(u8, total);
        defer {
            std.crypto.secureZero(u8, encoded);
            allocator.free(encoded);
        }

        @memcpy(encoded[0..8], magic);
        encoded[8] = format_version;
        encoded[9] = @intFromEnum(kind);
        std.mem.writeInt(u16, encoded[10..12], @intCast(secret.len), .big);
        @memcpy(encoded[header_len .. header_len + secret.len], secret);
        std.crypto.hash.blake2.Blake2s256.hash(encoded[0 .. header_len + secret.len], encoded[header_len + secret.len ..][0..digest_len], .{});
        try atomic.replace(self.dir, io, name, encoded, atomic.private_file_permissions);
    }

    pub fn load(self: FileSecretStore, allocator: std.mem.Allocator, io: std.Io, name: []const u8, expected_kind: SecretKind) ![]u8 {
        const stat = try self.dir.statFile(io, name, .{ .follow_symlinks = false });
        if (stat.kind != .file) return error.InvalidSecretFileType;
        if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
        const encoded = try atomic.readAlloc(self.dir, io, name, allocator, header_len + max_secret_len + digest_len + 1);
        defer {
            std.crypto.secureZero(u8, encoded);
            allocator.free(encoded);
        }

        if (encoded.len < header_len + digest_len) return error.CorruptSecret;
        if (!std.mem.eql(u8, encoded[0..8], magic)) return error.CorruptSecret;
        if (encoded[8] != format_version) return error.UnsupportedSecretVersion;
        const kind: SecretKind = switch (encoded[9]) {
            1 => .identity_key,
            2 => .enrollment_token,
            else => return error.CorruptSecret,
        };
        if (kind != expected_kind) return error.UnexpectedSecretKind;
        const payload_len = std.mem.readInt(u16, encoded[10..12], .big);
        if (encoded.len != header_len + payload_len + digest_len) return error.CorruptSecret;
        try validateLength(kind, payload_len);

        var expected_digest: [digest_len]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(encoded[0 .. header_len + payload_len], &expected_digest, .{});
        if (!constantTimeEqual(&expected_digest, encoded[header_len + payload_len ..])) return error.CorruptSecret;
        return allocator.dupe(u8, encoded[header_len .. header_len + payload_len]);
    }

    pub fn delete(self: FileSecretStore, io: std.Io, name: []const u8) !void {
        try self.dir.deleteFile(io, name);
    }
};

fn validateLength(kind: SecretKind, len: usize) !void {
    switch (kind) {
        .identity_key => if (len != 32) return error.InvalidSecretLength,
        .enrollment_token => if (len == 0 or len > max_secret_len) return error.InvalidSecretLength,
    }
}

fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |left, right| difference |= left ^ right;
    return difference == 0;
}

test "FileSecretStore round trips a versioned private identity" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const secrets: FileSecretStore = .{ .dir = tmp.dir };
    const key = [_]u8{0x42} ** 32;
    try secrets.write(std.testing.allocator, io, "identity.key", .identity_key, &key);
    const loaded = try secrets.load(std.testing.allocator, io, "identity.key", .identity_key);
    defer std.testing.allocator.free(loaded);
    try std.testing.expectEqualSlices(u8, &key, loaded);
}

test "FileSecretStore rejects corruption and kind confusion" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const secrets: FileSecretStore = .{ .dir = tmp.dir };
    const key = [_]u8{0x24} ** 32;
    try secrets.write(std.testing.allocator, io, "identity.key", .identity_key, &key);
    try std.testing.expectError(error.UnexpectedSecretKind, secrets.load(std.testing.allocator, io, "identity.key", .enrollment_token));

    var bytes = try atomic.readAlloc(tmp.dir, io, "identity.key", std.testing.allocator, 128);
    defer std.testing.allocator.free(bytes);
    bytes[header_len] ^= 1;
    try atomic.replace(tmp.dir, io, "identity.key", bytes, atomic.private_file_permissions);
    try std.testing.expectError(error.CorruptSecret, secrets.load(std.testing.allocator, io, "identity.key", .identity_key));
}
