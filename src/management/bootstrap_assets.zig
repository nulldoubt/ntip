//! Strict, root-owned manifest consumed by the DB-free bootstrap HTTP edge.

const std = @import("std");

pub const schema_version: u16 = 1;
pub const maximum_manifest_bytes: usize = 64 * 1024;
pub const maximum_archive_size: u64 = 256 * 1024 * 1024;

pub const Target = enum {
    x86_64_linux_musl,
    aarch64_linux_musl,

    pub fn text(self: Target) []const u8 {
        return switch (self) {
            .x86_64_linux_musl => "x86_64-linux-musl",
            .aarch64_linux_musl => "aarch64-linux-musl",
        };
    }
};

pub const Archive = struct {
    target: []const u8,
    file: []const u8,
    sha256: []const u8,
    size_bytes: u64,
};

pub const Manifest = struct {
    schema_version: u16,
    version: []const u8,
    archives: []const Archive,
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Manifest) {
    if (bytes.len == 0 or bytes.len > maximum_manifest_bytes) {
        return error.InvalidBootstrapManifest;
    }
    const parsed = std.json.parseFromSlice(Manifest, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidBootstrapManifest;
    errdefer parsed.deinit();
    try validate(parsed.value);
    return parsed;
}

pub fn validate(manifest: Manifest) !void {
    if (manifest.schema_version != schema_version) return error.UnsupportedBootstrapManifest;
    try validateVersion(manifest.version);
    if (manifest.archives.len != 2) return error.InvalidBootstrapManifest;
    var seen_x86 = false;
    var seen_arm = false;
    for (manifest.archives) |archive| {
        const target = parseTarget(archive.target) orelse return error.InvalidBootstrapManifest;
        switch (target) {
            .x86_64_linux_musl => {
                if (seen_x86) return error.InvalidBootstrapManifest;
                seen_x86 = true;
            },
            .aarch64_linux_musl => {
                if (seen_arm) return error.InvalidBootstrapManifest;
                seen_arm = true;
            },
        }
        try validateAssetBasename(archive.file);
        if (!isLowerHex(archive.sha256, 64)) return error.InvalidBootstrapManifest;
        if (archive.size_bytes == 0 or archive.size_bytes > maximum_archive_size) {
            return error.InvalidBootstrapManifest;
        }
    }
    if (!seen_x86 or !seen_arm) return error.InvalidBootstrapManifest;
}

pub fn archiveFor(manifest: Manifest, target: Target) Archive {
    for (manifest.archives) |archive| {
        if (parseTarget(archive.target) == target) return archive;
    }
    unreachable;
}

fn parseTarget(text: []const u8) ?Target {
    inline for (std.meta.fields(Target)) |field| {
        const target: Target = @enumFromInt(field.value);
        if (std.mem.eql(u8, text, target.text())) return target;
    }
    return null;
}

fn validateVersion(version: []const u8) !void {
    if (version.len == 0 or version.len > 64) return error.InvalidBootstrapManifest;
    for (version, 0..) |byte, index| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => {},
        '.', '+', '-' => if (index == 0) return error.InvalidBootstrapManifest,
        else => return error.InvalidBootstrapManifest,
    };
}

fn validateAssetBasename(file: []const u8) !void {
    if (file.len == 0 or file.len > 160) return error.InvalidBootstrapManifest;
    for (file, 0..) |byte, index| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9' => {},
        '.', '_', '+', '-' => if (index == 0) return error.InvalidBootstrapManifest,
        else => return error.InvalidBootstrapManifest,
    };
}

fn isLowerHex(value: []const u8, exact_length: usize) bool {
    if (value.len != exact_length) return false;
    for (value) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

test "bootstrap asset manifest is strict complete and architecture unique" {
    const bytes =
        \\{"schema_version":1,"version":"0.2.0","archives":[{"target":"x86_64-linux-musl","file":"ntip-node-v0.2.0-x86_64-linux-musl.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1024},{"target":"aarch64-linux-musl","file":"ntip-node-v0.2.0-aarch64-linux-musl.tar.gz","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size_bytes":2048}]}
    ;
    const parsed = try decode(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "ntip-node-v0.2.0-aarch64-linux-musl.tar.gz",
        archiveFor(parsed.value, .aarch64_linux_musl).file,
    );

    const duplicate =
        \\{"schema_version":1,"version":"0.2.0","archives":[{"target":"x86_64-linux-musl","file":"one.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1},{"target":"x86_64-linux-musl","file":"two.tar.gz","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size_bytes":1}]}
    ;
    try std.testing.expectError(error.InvalidBootstrapManifest, decode(std.testing.allocator, duplicate));
}

test "bootstrap asset manifest rejects traversal secrets and unknown fields" {
    const traversal =
        \\{"schema_version":1,"version":"0.2.0","archives":[{"target":"x86_64-linux-musl","file":"../node.tar.gz","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":1},{"target":"aarch64-linux-musl","file":"node.tar.gz","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size_bytes":1}]}
    ;
    try std.testing.expectError(error.InvalidBootstrapManifest, decode(std.testing.allocator, traversal));
    const unknown =
        \\{"schema_version":1,"version":"0.2.0","archives":[],"secret":"no"}
    ;
    try std.testing.expectError(error.InvalidBootstrapManifest, decode(std.testing.allocator, unknown));
}
