//! Ordered, checksummed SQLite schema migrations.
//!
//! Migration SQL is append-only after release. The declared checksum makes an
//! accidental edit fail before a database transaction starts; the same value
//! is recorded in `schema_migrations` and verified on every open.

const std = @import("std");

pub const current_schema_version: u32 = 2;

pub const Migration = struct {
    version: u32,
    name: []const u8,
    sql: [:0]const u8,
    sha256: [32]u8,
};

const management_plane_sql = @embedFile("migrations/0001_management_plane.sql");
const enrollment_bootstraps_sql = @embedFile("migrations/0002_enrollment_bootstraps.sql");

pub const all = [_]Migration{
    .{
        .version = 1,
        .name = "management_plane",
        .sql = management_plane_sql,
        // Updated only when the unreleased migration source intentionally
        // changes. Once shipped, add a migration instead of changing this one.
        .sha256 = .{
            0xd7, 0xaa, 0xb9, 0x68, 0x03, 0x79, 0xde, 0xc5,
            0x66, 0x98, 0x9e, 0x29, 0x98, 0x82, 0x8e, 0x06,
            0x3e, 0x67, 0xc9, 0xd4, 0x41, 0xae, 0x86, 0x0a,
            0x38, 0x71, 0xd7, 0x39, 0x3f, 0x3d, 0x46, 0x78,
        },
    },
    .{
        .version = 2,
        .name = "enrollment_bootstraps",
        .sql = enrollment_bootstraps_sql,
        .sha256 = .{
            0xda, 0xd2, 0xd0, 0x79, 0x3e, 0xfb, 0xf1, 0xca,
            0x7e, 0x71, 0xa5, 0x66, 0xe8, 0x21, 0xab, 0x28,
            0x2a, 0xb3, 0xa8, 0xca, 0xfb, 0xdf, 0x4c, 0x60,
            0x8f, 0xf3, 0x6f, 0xe0, 0xdd, 0xa8, 0xe7, 0x55,
        },
    },
};

pub fn sourceChecksum(migration: Migration) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(migration.sql, &digest, .{});
    return digest;
}

pub fn validateSources() error{MigrationSourceChecksumMismatch}!void {
    for (all) |migration| {
        if (!std.mem.eql(u8, &sourceChecksum(migration), &migration.sha256)) {
            return error.MigrationSourceChecksumMismatch;
        }
    }
}

pub fn find(version: u32) ?Migration {
    for (all) |migration| {
        if (migration.version == version) return migration;
    }
    return null;
}

test "migration registry is contiguous and source checksums are pinned" {
    for (all, 0..) |migration, index| {
        try std.testing.expectEqual(@as(u32, @intCast(index + 1)), migration.version);
        try std.testing.expect(migration.name.len != 0);
    }
    try std.testing.expectEqual(current_schema_version, all[all.len - 1].version);
    try validateSources();
}
