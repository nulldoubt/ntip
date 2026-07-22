//! Authoritative Master database bootstrap and ownership boundary.
//!
//! Callers must already hold `state.lock` for the lifetime of this repository.
//! This module does not import or remove v0.1 JSON. A fresh v0.2 database is
//! created only when no legacy authoritative file is present.

const std = @import("std");
const sqlite = @import("sqlite.zig");

pub const database_file = "ntip.sqlite3";
pub const private_directory_mode: u32 = 0o700;
pub const private_file_mode: u32 = 0o600;

pub const LegacyFile = enum {
    state_json,
    enrollments_json,
    transaction_intent,

    pub fn fileName(self: LegacyFile) []const u8 {
        return switch (self) {
            .state_json => "state.json",
            .enrollments_json => "enrollments.json",
            .transaction_intent => "transaction.pending",
        };
    }
};

const legacy_files = [_]LegacyFile{
    .state_json,
    .enrollments_json,
    .transaction_intent,
};

pub const DatabaseFileState = enum {
    existing,
    created,
};

pub const Repository = struct {
    db: sqlite.Database,

    /// Opens the sole writable Master database. `state_dir` and its canonical
    /// path are used together so SQLite never creates the file before legacy
    /// detection and permission checks have completed.
    pub fn open(
        allocator: std.mem.Allocator,
        io: std.Io,
        state_dir: std.Io.Dir,
    ) !Repository {
        try validateStateDirectory(state_dir, io);
        const file_state = try ensureDatabaseFile(state_dir, io);

        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path_length = try state_dir.realPath(io, &path_buffer);
        const database_path = try std.fs.path.joinZ(
            allocator,
            &.{ path_buffer[0..path_length], database_file },
        );
        defer allocator.free(database_path);

        // A mere regular file named `ntip.sqlite3` is not proof that v0.2 was
        // initialized. In particular, a crash can leave the exclusive
        // placeholder created above at zero bytes. When legacy authoritative
        // files coexist with an existing path, prove that the path is already
        // a complete v0.2 database before allowing it to take precedence. This
        // check is read-only: malformed state is never initialized, imported,
        // deleted, or reinterpreted behind the operator's back.
        if (file_state == .existing and try detectLegacy(state_dir, io) != null) {
            var existing = sqlite.Database.openReadOnly(database_path) catch
                return error.LegacyMasterStateUnsupported;
            defer existing.close();
            existing.exec("PRAGMA trusted_schema = OFF;") catch
                return error.LegacyMasterStateUnsupported;
            existing.validateCurrentSchema() catch
                return error.LegacyMasterStateUnsupported;
        }

        var db = try sqlite.Database.openInitialized(database_path);
        errdefer db.close();
        return .{ .db = db };
    }

    pub fn deinit(self: *Repository) void {
        self.db.close();
        self.* = undefined;
    }

    pub fn begin(self: *Repository, mode: sqlite.TransactionMode) !sqlite.Transaction {
        return self.db.begin(mode);
    }
};

/// Returns the first legacy authoritative file without following symlinks.
/// Any object at one of these names is treated as legacy state, including a
/// directory or symlink, so a malformed path cannot turn into a fresh DB.
pub fn detectLegacy(state_dir: std.Io.Dir, io: std.Io) !?LegacyFile {
    for (legacy_files) |legacy| {
        _ = state_dir.statFile(io, legacy.fileName(), .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return legacy;
    }
    return null;
}

/// Creates an empty private database file only after proving that this is not
/// a v0.1 Master state directory. The caller must hold `state.lock`, which is
/// what makes the check across multiple filenames race-free.
pub fn ensureDatabaseFile(state_dir: std.Io.Dir, io: std.Io) !DatabaseFileState {
    if (try databaseStat(state_dir, io)) |_| return .existing;
    if (try detectLegacy(state_dir, io) != null) return error.LegacyMasterStateUnsupported;

    var file = state_dir.createFile(io, database_file, .{
        .read = true,
        .truncate = false,
        .exclusive = true,
        .permissions = .fromMode(private_file_mode),
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        // With `state.lock` held this can only be a defensive race check.
        error.PathAlreadyExists => {
            _ = (try databaseStat(state_dir, io)) orelse return error.InvalidDatabaseFileType;
            return .existing;
        },
        else => return err,
    };
    defer file.close(io);
    try file.setPermissions(io, .fromMode(private_file_mode));
    try file.sync(io);
    _ = (try databaseStat(state_dir, io)) orelse return error.InvalidDatabaseFileType;
    return .created;
}

pub fn validateStateDirectory(state_dir: std.Io.Dir, io: std.Io) !void {
    const stat = try state_dir.stat(io);
    if (stat.kind != .directory) return error.InvalidStateDirectoryType;
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        if (stat.permissions.toMode() & 0o777 != private_directory_mode) {
            return error.InsecureStateDirectoryPermissions;
        }
    }
}

fn databaseStat(state_dir: std.Io.Dir, io: std.Io) !?std.Io.File.Stat {
    const stat = state_dir.statFile(io, database_file, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    if (stat.kind != .file) return error.InvalidDatabaseFileType;
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        if (stat.permissions.toMode() & 0o777 != private_file_mode) {
            return error.InsecureDatabasePermissions;
        }
    }
    return stat;
}

fn makePrivate(tmp: *std.testing.TmpDir) !void {
    try setTestDirectoryPermissions(tmp.dir, private_directory_mode);
}

fn setTestDirectoryPermissions(dir: std.Io.Dir, mode: std.posix.mode_t) !void {
    var permission_dir = try dir.openDir(std.testing.io, ".", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer permission_dir.close(std.testing.io);
    try permission_dir.setPermissions(std.testing.io, .fromMode(mode));
}

test "legacy Master files fail closed and are never modified" {
    inline for (legacy_files) |legacy| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        try makePrivate(&tmp);
        var legacy_file = try tmp.dir.createFile(std.testing.io, legacy.fileName(), .{
            .permissions = .fromMode(private_file_mode),
        });
        legacy_file.close(std.testing.io);

        try std.testing.expectEqual(legacy, (try detectLegacy(tmp.dir, std.testing.io)).?);
        try std.testing.expectError(
            error.LegacyMasterStateUnsupported,
            ensureDatabaseFile(tmp.dir, std.testing.io),
        );
        try std.testing.expectError(
            error.FileNotFound,
            tmp.dir.statFile(std.testing.io, database_file, .{}),
        );
        _ = try tmp.dir.statFile(std.testing.io, legacy.fileName(), .{ .follow_symlinks = false });
    }
}

test "an initialized v0.2 database takes precedence over inert legacy files" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makePrivate(&tmp);

    var initialized = try Repository.open(std.testing.allocator, std.testing.io, tmp.dir);
    initialized.deinit();
    var legacy = try tmp.dir.createFile(std.testing.io, "state.json", .{
        .permissions = .fromMode(private_file_mode),
    });
    legacy.close(std.testing.io);

    var reopened = try Repository.open(std.testing.allocator, std.testing.io, tmp.dir);
    defer reopened.deinit();
    try std.testing.expectEqual(sqlite.current_schema_version, try reopened.db.schemaVersion());
    _ = try tmp.dir.statFile(std.testing.io, "state.json", .{ .follow_symlinks = false });
}

test "an empty database placeholder cannot mask legacy Master state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makePrivate(&tmp);

    var placeholder = try tmp.dir.createFile(std.testing.io, database_file, .{
        .permissions = .fromMode(private_file_mode),
    });
    try placeholder.setPermissions(std.testing.io, .fromMode(private_file_mode));
    placeholder.close(std.testing.io);
    var legacy = try tmp.dir.createFile(std.testing.io, "enrollments.json", .{
        .permissions = .fromMode(private_file_mode),
    });
    legacy.close(std.testing.io);

    try std.testing.expectError(
        error.LegacyMasterStateUnsupported,
        Repository.open(std.testing.allocator, std.testing.io, tmp.dir),
    );
    const database_stat = try tmp.dir.statFile(std.testing.io, database_file, .{ .follow_symlinks = false });
    try std.testing.expectEqual(@as(u64, 0), database_stat.size);
    _ = try tmp.dir.statFile(std.testing.io, "enrollments.json", .{ .follow_symlinks = false });
}

test "repository creates a private migrated database" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makePrivate(&tmp);

    var repository = try Repository.open(std.testing.allocator, std.testing.io, tmp.dir);
    defer repository.deinit();
    try std.testing.expectEqual(sqlite.current_schema_version, try repository.db.schemaVersion());
    try repository.db.quickCheck();

    const stat = try tmp.dir.statFile(std.testing.io, database_file, .{ .follow_symlinks = false });
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        try std.testing.expectEqual(@as(u32, private_file_mode), stat.permissions.toMode() & 0o777);
        inline for (.{ database_file ++ "-wal", database_file ++ "-shm" }) |sidecar| {
            const sidecar_stat = try tmp.dir.statFile(std.testing.io, sidecar, .{
                .follow_symlinks = false,
            });
            try std.testing.expectEqual(
                @as(u32, private_file_mode),
                sidecar_stat.permissions.toMode() & 0o777,
            );
        }
    }
}

test "insecure database and state directory permissions are rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try setTestDirectoryPermissions(tmp.dir, 0o755);
    try std.testing.expectError(
        error.InsecureStateDirectoryPermissions,
        validateStateDirectory(tmp.dir, std.testing.io),
    );

    try makePrivate(&tmp);
    var database = try tmp.dir.createFile(std.testing.io, database_file, .{
        .permissions = .fromMode(0o644),
    });
    database.close(std.testing.io);
    try std.testing.expectError(
        error.InsecureDatabasePermissions,
        ensureDatabaseFile(tmp.dir, std.testing.io),
    );
}
