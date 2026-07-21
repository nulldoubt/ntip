//! Strict Node bootstrap bundle and durable non-secret ticket marker.

const std = @import("std");
const atomic = @import("atomic_file.zig");
const config = @import("config.zig");
const model = @import("../domain/model.zig");
const credential_mod = @import("../protocol/credential.zig");

pub const schema_version: u32 = 1;
pub const maximum_bundle_bytes: usize = 4096;
pub const bootstrap_id_len: usize = 8;
pub const marker_file = "bootstrap.id";
const accepted_id_alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub const Bundle = struct {
    schemaVersion: u32,
    bootstrapId: []const u8,
    nodeName: []const u8,
    masterEndpoint: []const u8,
    expiresAt: []const u8,
    enrollmentCredential: []const u8,
    archives: [2]Archive,
};

pub const Archive = struct {
    version: []const u8,
    target: []const u8,
    path: []const u8,
    sha256: []const u8,
    sizeBytes: u64,
};

pub const Validated = struct {
    bootstrap_id: [bootstrap_id_len]u8,
    expires_at: i64,
    credential: credential_mod.Credential,
    config_json: []u8,

    pub fn deinit(self: *Validated, allocator: std.mem.Allocator) void {
        self.credential.deinit();
        std.crypto.secureZero(u8, self.config_json);
        allocator.free(self.config_json);
        std.crypto.secureZero(u8, &self.bootstrap_id);
        self.* = undefined;
    }
};

pub fn parseAndValidate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    now_seconds: i64,
) !Validated {
    if (bytes.len == 0 or bytes.len > maximum_bundle_bytes) return error.InvalidBootstrapBundle;
    // Every contract string is plain bounded ASCII. Rejecting escapes keeps
    // all parsed string slices in the caller-owned buffer, which the CLI can
    // securely erase after import instead of leaving decoded secret copies in
    // a JSON arena.
    if (std.mem.indexOfScalar(u8, bytes, '\\') != null) return error.InvalidBootstrapBundle;
    const parsed = std.json.parseFromSlice(Bundle, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_if_needed,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidBootstrapBundle,
    };
    defer parsed.deinit();
    if (parsed.value.schemaVersion != schema_version) return error.UnsupportedBootstrapSchema;
    try validateArchives(parsed.value.archives);

    const bootstrap_id = try parseId(parsed.value.bootstrapId);
    _ = model.Name.parse(parsed.value.nodeName) catch return error.InvalidBootstrapBundle;
    const expires_at = parseRfc3339Utc(parsed.value.expiresAt) catch return error.InvalidBootstrapExpiry;
    if (expires_at <= now_seconds) return error.ExpiredBootstrapBundle;

    var enrollment = credential_mod.Credential.decode(parsed.value.enrollmentCredential) catch
        return error.InvalidBootstrapCredential;
    errdefer enrollment.deinit();
    const config_json = config.encodeClient(
        allocator,
        parsed.value.masterEndpoint,
        parsed.value.nodeName,
        enrollment.master_public,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidBootstrapBundle,
    };
    errdefer {
        std.crypto.secureZero(u8, config_json);
        allocator.free(config_json);
    }
    return .{
        .bootstrap_id = bootstrap_id,
        .expires_at = expires_at,
        .credential = enrollment,
        .config_json = config_json,
    };
}

fn validateArchives(archives: [2]Archive) !void {
    var found_x86_64 = false;
    var found_aarch64 = false;
    for (archives) |archive| {
        if (archive.version.len == 0 or archive.version.len > 64 or
            !isVersionText(archive.version) or
            archive.path.len < 24 or archive.path.len > 192 or
            !std.mem.startsWith(u8, archive.path, "/enrollment/assets/") or
            !isAssetBasename(archive.path["/enrollment/assets/".len..]) or
            archive.sha256.len != 64 or !isLowerHex(archive.sha256) or
            archive.sizeBytes == 0 or archive.sizeBytes > 268_435_456)
        {
            return error.InvalidBootstrapArchive;
        }
        if (std.mem.eql(u8, archive.target, "x86_64-linux-musl")) {
            if (found_x86_64) return error.InvalidBootstrapArchive;
            found_x86_64 = true;
        } else if (std.mem.eql(u8, archive.target, "aarch64-linux-musl")) {
            if (found_aarch64) return error.InvalidBootstrapArchive;
            found_aarch64 = true;
        } else {
            return error.InvalidBootstrapArchive;
        }
    }
    if (!found_x86_64 or !found_aarch64) return error.InvalidBootstrapArchive;
}

fn isVersionText(text: []const u8) bool {
    if (!std.ascii.isAlphanumeric(text[0])) return false;
    for (text[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '+' or byte == '-')) return false;
    }
    return true;
}

fn isAssetBasename(text: []const u8) bool {
    if (text.len == 0 or !std.ascii.isAlphanumeric(text[0])) return false;
    for (text[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '_' or byte == '+' or byte == '-')) return false;
    }
    return true;
}

fn isLowerHex(text: []const u8) bool {
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

pub fn parseId(text: []const u8) ![bootstrap_id_len]u8 {
    if (text.len != bootstrap_id_len) return error.InvalidBootstrapId;
    var result: [bootstrap_id_len]u8 = undefined;
    for (text, 0..) |byte, index| {
        if (std.mem.indexOfScalar(u8, accepted_id_alphabet, byte) == null) {
            return error.InvalidBootstrapId;
        }
        result[index] = byte;
    }
    return result;
}

pub fn loadMarker(
    allocator: std.mem.Allocator,
    dir: std.Io.Dir,
    io: std.Io,
) !?[bootstrap_id_len]u8 {
    const stat = dir.statFile(io, marker_file, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidBootstrapMarkerType;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
    const bytes = try atomic.readAlloc(dir, io, marker_file, allocator, bootstrap_id_len + 1);
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return parseId(bytes) catch return error.InvalidBootstrapMarker;
}

pub fn saveMarker(dir: std.Io.Dir, io: std.Io, bootstrap_id: [bootstrap_id_len]u8) !void {
    _ = try parseId(&bootstrap_id);
    try atomic.replace(dir, io, marker_file, &bootstrap_id, atomic.private_file_permissions);
}

pub fn deleteMarker(dir: std.Io.Dir, io: std.Io) !void {
    atomic.deleteDurable(dir, io, marker_file) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

fn parseRfc3339Utc(text: []const u8) !i64 {
    if (text.len != 20 or text[4] != '-' or text[7] != '-' or text[10] != 'T' or
        text[13] != ':' or text[16] != ':' or text[19] != 'Z')
    {
        return error.InvalidTimestamp;
    }
    const year = try decimal(text[0..4]);
    const month = try decimal(text[5..7]);
    const day = try decimal(text[8..10]);
    const hour = try decimal(text[11..13]);
    const minute = try decimal(text[14..16]);
    const second = try decimal(text[17..19]);
    if (year < 1970 or year > 9999 or month < 1 or month > 12 or hour > 23 or
        minute > 59 or second > 59)
    {
        return error.InvalidTimestamp;
    }
    const month_days = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var maximum_day: u16 = month_days[@as(usize, month - 1)];
    if (month == 2 and isLeapYear(year)) maximum_day = 29;
    if (day < 1 or day > maximum_day) return error.InvalidTimestamp;

    var days: i64 = 0;
    var current_year: u16 = 1970;
    while (current_year < year) : (current_year += 1) {
        days += if (isLeapYear(current_year)) 366 else 365;
    }
    var current_month: u16 = 1;
    while (current_month < month) : (current_month += 1) {
        days += month_days[@as(usize, current_month - 1)];
        if (current_month == 2 and isLeapYear(year)) days += 1;
    }
    days += @as(i64, day - 1);
    return days * 86_400 + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + @as(i64, second);
}

fn decimal(bytes: []const u8) !u16 {
    var value: u16 = 0;
    for (bytes) |byte| {
        if (byte < '0' or byte > '9') return error.InvalidTimestamp;
        value = value * 10 + byte - '0';
    }
    return value;
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

test "strict bootstrap bundle validates identity expiry and credential" {
    var credential = credential_mod.Credential{
        .handle = .{0x11} ** 16,
        .secret = .{0x22} ** 32,
        .master_public = .{0x33} ** 32,
    };
    defer credential.deinit();
    var credential_text: [credential_mod.text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &credential_text);
    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"schemaVersion\":1,\"bootstrapId\":\"ABC23456\",\"nodeName\":\"node01\",\"masterEndpoint\":\"203.0.113.10:49152\",\"expiresAt\":\"2030-01-02T03:04:05Z\",\"enrollmentCredential\":\"{s}\",\"archives\":[{{\"version\":\"0.2.0\",\"target\":\"x86_64-linux-musl\",\"path\":\"/enrollment/assets/ntip-node-v0.2.0-x86_64-linux-musl.tar.gz\",\"sha256\":\"{s}\",\"sizeBytes\":1234}},{{\"version\":\"0.2.0\",\"target\":\"aarch64-linux-musl\",\"path\":\"/enrollment/assets/ntip-node-v0.2.0-aarch64-linux-musl.tar.gz\",\"sha256\":\"{s}\",\"sizeBytes\":1234}}]}}",
        .{ credential.encode(&credential_text), "ab" ** 32, "cd" ** 32 },
    );
    defer std.testing.allocator.free(json);
    var validated = try parseAndValidate(std.testing.allocator, json, 0);
    defer validated.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("ABC23456", &validated.bootstrap_id);
    try std.testing.expect(std.mem.indexOf(u8, validated.config_json, "203.0.113.10:49152") != null);
}

test "bootstrap bundle rejects unknown fields bad IDs expiry and noncanonical timestamps" {
    try std.testing.expectError(error.InvalidBootstrapId, parseId("ABC10IOZ"));
    try std.testing.expectError(error.InvalidTimestamp, parseRfc3339Utc("2100-02-29T00:00:00Z"));
    try std.testing.expectError(error.InvalidTimestamp, parseRfc3339Utc("2030-01-02T03:04:05+00:00"));
    try std.testing.expectEqual(@as(i64, 0), try parseRfc3339Utc("1970-01-01T00:00:00Z"));
}

test "bootstrap archive projection requires one canonical record per target" {
    const x86_64 = Archive{
        .version = "0.2.0",
        .target = "x86_64-linux-musl",
        .path = "/enrollment/assets/ntip-node-v0.2.0-x86_64-linux-musl.tar.gz",
        .sha256 = "abababababababababababababababababababababababababababababababab",
        .sizeBytes = 1234,
    };
    const aarch64 = Archive{
        .version = "0.2.0",
        .target = "aarch64-linux-musl",
        .path = "/enrollment/assets/ntip-node-v0.2.0-aarch64-linux-musl.tar.gz",
        .sha256 = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        .sizeBytes = 1234,
    };
    try validateArchives(.{ x86_64, aarch64 });
    try std.testing.expectError(error.InvalidBootstrapArchive, validateArchives(.{ x86_64, x86_64 }));
    var uppercase_digest = aarch64;
    uppercase_digest.sha256 = "CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD";
    try std.testing.expectError(error.InvalidBootstrapArchive, validateArchives(.{ x86_64, uppercase_digest }));
}
