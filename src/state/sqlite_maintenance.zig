//! Explicit, operator-driven SQLite backup and stopped-service restore.
//!
//! `onlineBackup` may run against the serialized worker's live connection.
//! `restoreStopped` must only be called after the service is stopped and while
//! the caller holds the state directory lifetime lock. The lock assumption is
//! deliberately part of the API contract: this module cannot prove ownership
//! of an advisory lock represented by another object.

const std = @import("std");
const builtin = @import("builtin");
const model = @import("../domain/model.zig");
const management_repository = @import("management_repository.zig");
const operations_repository = @import("operations_repository.zig");
const settings_repository = @import("settings_repository.zig");
const sqlite = @import("sqlite.zig");

pub const database_file = "ntip.sqlite3";
pub const private_directory_mode: u32 = 0o700;
pub const private_file_mode: u32 = 0o600;
pub const maximum_artifact_name_bytes: usize = 200;

const sqlite_header_bytes: u64 = 100;
const copy_buffer_bytes: usize = 64 * 1024;
const sidecar_suffixes = [_][]const u8{ "-wal", "-shm", "-journal" };

pub const MaintenanceError = error{
    InvalidArtifactName,
    InvalidDirectoryType,
    InsecureDirectoryPermissions,
    BackupAlreadyExists,
    InvalidDatabaseFileType,
    InsecureDatabasePermissions,
    HardLinkedDatabaseUnsupported,
    DatabaseArtifactTooSmall,
    SourceHasSidecars,
    SourceBusy,
    SourceChangedDuringRead,
    InvalidSidecarFileType,
    InsecureSidecarPermissions,
    HardLinkedSidecarUnsupported,
};

pub const RestoreResult = struct {
    /// Number of sessions removed from the restored snapshot. The source
    /// artifact and recoverable pre-restore copy are never modified.
    revoked_sessions: u64,
    /// Unused setup invitations invalidated in the staged restored image.
    revoked_bootstraps: u64,
};

/// Caller-supplied identity for the fixed local restore audit entry. This
/// module owns the operation/action/resource fields so a successful install
/// cannot omit or mislabel its immutable restore record.
pub const RestoreAudit = struct {
    id: [16]u8,
    bootstrap_revoke_id: [16]u8,
    occurred_at: i64,
};

pub const OnlineBackupOptions = struct {
    pages_per_step: u16 = sqlite.default_backup_pages_per_step,
    busy_retry_limit: u8 = sqlite.default_backup_busy_retry_limit,
    checkpoint: ?sqlite.BackupCheckpoint = null,
};

/// Writes a consistent snapshot to a new, explicitly named file. Existing
/// paths are never overwritten, including symbolic links and directories.
/// The destination directory must be private (0700); the materialized backup
/// is a single, private (0600), link-count-one SQLite file without sidecars.
pub fn onlineBackup(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *sqlite.Database,
    destination_dir: std.Io.Dir,
    destination_name: []const u8,
) !void {
    return onlineBackupWithOptions(
        allocator,
        io,
        source,
        destination_dir,
        destination_name,
        .{},
    );
}

/// Variant used by the live serialized owner. The checkpoint runs only after
/// each bounded SQLite backup step has returned; it may advance higher-priority
/// protocol/runtime work but must not accept a recursive management request.
pub fn onlineBackupWithOptions(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *sqlite.Database,
    destination_dir: std.Io.Dir,
    destination_name: []const u8,
    options: OnlineBackupOptions,
) !void {
    try validatePrivateDirectory(destination_dir, io);
    try validateArtifactName(destination_name);
    try ensureAbsent(destination_dir, io, destination_name);
    try rejectSidecars(destination_dir, io, destination_name);

    var atomic = try destination_dir.createFileAtomic(io, destination_name, .{
        .permissions = .fromMode(private_file_mode),
        // A named temporary file is required because SQLite accepts a path,
        // not an already-open file descriptor. Final materialization still
        // uses `link`, which refuses to replace the requested destination.
        .replace = true,
    });
    defer atomic.deinit(io);
    try inheritDirectoryOwner(destination_dir, atomic.file);
    try atomic.file.setPermissions(io, .fromMode(private_file_mode));

    const temporary_name = std.fmt.hex(atomic.file_basename_hex);
    atomic.file.close(io);
    atomic.file_open = false;
    defer cleanupSidecarsBestEffort(destination_dir, io, &temporary_name);

    const temporary_path = try databasePath(allocator, io, destination_dir, &temporary_name);
    defer allocator.free(temporary_path);

    var destination = try sqlite.Database.open(temporary_path);
    var destination_open = true;
    defer if (destination_open) destination.close();
    try source.backupTo(&destination, .{
        .pages_per_step = options.pages_per_step,
        .busy_retry_limit = options.busy_retry_limit,
        .checkpoint = options.checkpoint,
    });
    try destination.exec("PRAGMA trusted_schema = OFF;");
    try destination.exec("PRAGMA synchronous = FULL;");
    try destination.exec("PRAGMA journal_mode = DELETE;");
    try destination.integrityCheck();
    try destination.validateCurrentSchema();
    try validateApplicationState(allocator, &destination);
    destination.close();
    destination_open = false;

    try cleanupSidecars(destination_dir, io, &temporary_name);
    try syncAndValidateDatabaseFile(destination_dir, io, &temporary_name);
    // `link` performs an atomic non-replacing rename for this named temp.
    try atomic.link(io);
    try syncDirectory(destination_dir, io);
    _ = try validateDatabaseFile(destination_dir, io, destination_name);
    try rejectSidecars(destination_dir, io, destination_name);
}

/// Installs a validated backup into the authoritative state directory.
///
/// The caller must have stopped every SQLite owner and must hold `state.lock`
/// for the entire call. `source_name` and `recovery_name` are explicit
/// basenames. The source is copied through a no-follow file handle, checked,
/// changed only in a private staging file to revoke web sessions and append
/// the restore audit in one transaction, checked again, and atomically
/// installed. Before installation, the current database is checkpointed and
/// copied through SQLite's backup API to `recovery_name`.
pub fn restoreStopped(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_dir: std.Io.Dir,
    source_dir: std.Io.Dir,
    source_name: []const u8,
    recovery_name: []const u8,
    audit: RestoreAudit,
) !RestoreResult {
    try validatePrivateDirectory(state_dir, io);
    try validatePrivateDirectory(source_dir, io);
    try validateArtifactName(source_name);
    try validateArtifactName(recovery_name);
    if (std.mem.eql(u8, recovery_name, database_file)) {
        return error.InvalidArtifactName;
    }
    try ensureAbsent(state_dir, io, recovery_name);
    try rejectSidecars(state_dir, io, recovery_name);
    _ = try validateDatabaseFile(state_dir, io, database_file);
    try validateSidecarsForCleanup(state_dir, io, database_file);
    try rejectSidecars(source_dir, io, source_name);

    // Stage relative to the target directory so final replacement cannot cross
    // a filesystem boundary and is guaranteed to be atomic.
    var staged = try state_dir.createFileAtomic(io, database_file, .{
        .permissions = .fromMode(private_file_mode),
        .replace = true,
    });
    defer staged.deinit(io);
    try inheritDirectoryOwner(state_dir, staged.file);
    try staged.file.setPermissions(io, .fromMode(private_file_mode));
    const staged_name = std.fmt.hex(staged.file_basename_hex);
    defer cleanupSidecarsBestEffort(state_dir, io, &staged_name);

    try copySourceSnapshot(io, source_dir, source_name, staged.file);
    try staged.file.sync(io);
    staged.file.close(io);
    staged.file_open = false;
    try syncAndValidateDatabaseFile(state_dir, io, &staged_name);

    const staged_path = try databasePath(allocator, io, state_dir, &staged_name);
    defer allocator.free(staged_path);

    // First pass validates the exact source snapshot copied through the secure
    // file handle. No current state has been touched at this point.
    try validateDatabasePath(allocator, staged_path);
    try cleanupSidecars(state_dir, io, &staged_name);

    var staged_db = try sqlite.Database.open(staged_path);
    var staged_db_open = true;
    defer if (staged_db_open) staged_db.close();
    try staged_db.exec("PRAGMA trusted_schema = OFF;");
    try staged_db.exec("PRAGMA synchronous = FULL;");
    try staged_db.exec("PRAGMA secure_delete = ON;");
    try staged_db.exec("PRAGMA journal_mode = DELETE;");
    var transaction = try staged_db.begin(.immediate);
    errdefer transaction.rollback() catch {};
    try staged_db.exec("DELETE FROM web_sessions;");
    const revoked_sessions = staged_db.changes();
    _ = try operations_repository.Repository.init(&staged_db).appendAudit(.{
        .id = audit.id,
        .occurred_at = audit.occurred_at,
        .actor_kind = .local_cli,
        .action = "database.restore",
        .resource_type = "database",
        .details_json = "{\"sessionsRevoked\":true}",
    });
    try transaction.commit();

    const revoked_bootstraps = try management_repository.Repository.init(&staged_db)
        .revokeRestoredBootstrapCredentials(audit.occurred_at, .{
        .id = audit.bootstrap_revoke_id,
        .occurred_at = audit.occurred_at,
        .actor_kind = .local_cli,
        .action = "enrollment.bootstrap.restore_revoke",
        .resource_type = "database",
        .details_json = "{}",
    });
    try staged_db.integrityCheck();
    try staged_db.validateCurrentSchema();
    staged_db.close();
    staged_db_open = false;

    try cleanupSidecars(state_dir, io, &staged_name);
    try syncAndValidateDatabaseFile(state_dir, io, &staged_name);
    // Second pass proves the session-revoked staged image remains complete and
    // internally consistent before it can replace the live database.
    try validateDatabasePath(allocator, staged_path);
    try cleanupSidecars(state_dir, io, &staged_name);

    const current_path = try databasePath(allocator, io, state_dir, database_file);
    defer allocator.free(current_path);
    var current = try sqlite.Database.open(current_path);
    var current_open = true;
    defer if (current_open) current.close();
    try current.checkpointTruncate();
    try onlineBackup(allocator, io, &current, state_dir, recovery_name);
    current.close();
    current_open = false;

    // No committed frame can be lost now: checkpoint succeeded, the sole
    // connection is closed, and a validated standalone recovery exists.
    try cleanupSidecars(state_dir, io, database_file);
    try staged.replace(io);
    try syncDirectory(state_dir, io);
    _ = try validateDatabaseFile(state_dir, io, database_file);
    try rejectSidecars(state_dir, io, database_file);

    return .{
        .revoked_sessions = revoked_sessions,
        .revoked_bootstraps = revoked_bootstraps,
    };
}

fn validateDatabasePath(allocator: std.mem.Allocator, path: [:0]const u8) !void {
    var db = try sqlite.Database.openReadOnly(path);
    defer db.close();
    try db.exec("PRAGMA trusted_schema = OFF;");
    try db.integrityCheck();
    try db.validateCurrentSchema();
    try validateApplicationState(allocator, &db);
}

fn validateApplicationState(allocator: std.mem.Allocator, db: *sqlite.Database) !void {
    var inventory = management_repository.Repository.init(db).loadInventory(allocator) catch |err|
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.IntegrityCheckFailed,
        };
    defer inventory.deinit();
    const settings_state = settings_repository.Repository.init(db).loadState() catch
        return error.IntegrityCheckFailed;
    settings_state.validate(inventory.nodes.items.len) catch
        return error.IntegrityCheckFailed;
}

fn copySourceSnapshot(
    io: std.Io,
    source_dir: std.Io.Dir,
    source_name: []const u8,
    destination: std.Io.File,
) !void {
    var source = source_dir.openFile(io, source_name, .{
        .mode = .read_only,
        .allow_directory = false,
        .lock = .shared,
        .lock_nonblocking = true,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.WouldBlock => return error.SourceBusy,
        else => return err,
    };
    defer source.close(io);
    const before = try source.stat(io);
    try validateDatabaseStat(before);

    var buffer: [copy_buffer_bytes]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        const requested: usize = @intCast(@min(buffer.len, before.size - offset));
        const read = try source.readPositionalAll(io, buffer[0..requested], offset);
        if (read == 0) return error.SourceChangedDuringRead;
        try destination.writePositionalAll(io, buffer[0..read], offset);
        offset += read;
    }

    const after = try source.stat(io);
    if (before.inode != after.inode or before.size != after.size or
        before.mtime.nanoseconds != after.mtime.nanoseconds or
        before.ctime.nanoseconds != after.ctime.nanoseconds)
    {
        return error.SourceChangedDuringRead;
    }
}

fn databasePath(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
) ![:0]u8 {
    var directory_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const directory_length = try dir.realPath(io, &directory_buffer);
    return std.fs.path.joinZ(allocator, &.{ directory_buffer[0..directory_length], name });
}

fn validateArtifactName(name: []const u8) MaintenanceError!void {
    if (name.len == 0 or name.len > maximum_artifact_name_bytes or
        std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, ".."))
    {
        return error.InvalidArtifactName;
    }
    for (name) |byte| {
        if (byte == 0 or byte == '/' or byte == '\\') return error.InvalidArtifactName;
    }
}

fn validatePrivateDirectory(dir: std.Io.Dir, io: std.Io) !void {
    const stat = try dir.stat(io);
    if (stat.kind != .directory) return error.InvalidDirectoryType;
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        if (stat.permissions.toMode() & 0o777 != private_directory_mode) {
            return error.InsecureDirectoryPermissions;
        }
    }
}

fn ensureAbsent(dir: std.Io.Dir, io: std.Io, name: []const u8) !void {
    _ = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.BackupAlreadyExists;
}

fn validateDatabaseFile(dir: std.Io.Dir, io: std.Io, name: []const u8) !std.Io.File.Stat {
    const stat = try dir.statFile(io, name, .{ .follow_symlinks = false });
    try validateDatabaseStat(stat);
    return stat;
}

fn validateDatabaseStat(stat: std.Io.File.Stat) MaintenanceError!void {
    if (stat.kind != .file) return error.InvalidDatabaseFileType;
    if (stat.nlink != 1) return error.HardLinkedDatabaseUnsupported;
    if (stat.size < sqlite_header_bytes) return error.DatabaseArtifactTooSmall;
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        if (stat.permissions.toMode() & 0o777 != private_file_mode) {
            return error.InsecureDatabasePermissions;
        }
    }
}

fn syncAndValidateDatabaseFile(dir: std.Io.Dir, io: std.Io, name: []const u8) !void {
    var file = try dir.openFile(io, name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
    defer file.close(io);
    try validateDatabaseStat(try file.stat(io));
    try file.sync(io);
}

fn sidecarName(buffer: []u8, database_name: []const u8, suffix: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ database_name, suffix });
}

fn rejectSidecars(dir: std.Io.Dir, io: std.Io, database_name: []const u8) !void {
    for (sidecar_suffixes) |suffix| {
        var buffer: [maximum_artifact_name_bytes + 16]u8 = undefined;
        const name = try sidecarName(&buffer, database_name, suffix);
        _ = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return error.SourceHasSidecars;
    }
}

fn validateSidecarsForCleanup(dir: std.Io.Dir, io: std.Io, database_name: []const u8) !void {
    for (sidecar_suffixes) |suffix| {
        var buffer: [maximum_artifact_name_bytes + 16]u8 = undefined;
        const name = try sidecarName(&buffer, database_name, suffix);
        const stat = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        try validateSidecarStat(stat);
    }
}

fn validateSidecarStat(stat: std.Io.File.Stat) MaintenanceError!void {
    if (stat.kind != .file) return error.InvalidSidecarFileType;
    if (stat.nlink != 1) return error.HardLinkedSidecarUnsupported;
    if (comptime std.Io.File.Permissions.has_executable_bit) {
        if (stat.permissions.toMode() & 0o777 != private_file_mode) {
            return error.InsecureSidecarPermissions;
        }
    }
}

fn cleanupSidecars(dir: std.Io.Dir, io: std.Io, database_name: []const u8) !void {
    var removed = false;
    for (sidecar_suffixes) |suffix| {
        var buffer: [maximum_artifact_name_bytes + 16]u8 = undefined;
        const name = try sidecarName(&buffer, database_name, suffix);
        const stat = dir.statFile(io, name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        try validateSidecarStat(stat);
        try dir.deleteFile(io, name);
        removed = true;
    }
    if (removed) try syncDirectory(dir, io);
}

fn cleanupSidecarsBestEffort(dir: std.Io.Dir, io: std.Io, database_name: []const u8) void {
    cleanupSidecars(dir, io, database_name) catch {};
}

fn syncDirectory(dir: std.Io.Dir, io: std.Io) !void {
    if (comptime builtin.os.tag == .linux) {
        const sync_handle = try std.posix.openat(dir.handle, ".", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0);
        const directory_file: std.Io.File = .{
            .handle = sync_handle,
            .flags = .{ .nonblocking = false },
        };
        defer directory_file.close(io);
        try directory_file.sync(io);
        return;
    }

    const directory_file: std.Io.File = .{
        .handle = dir.handle,
        .flags = .{ .nonblocking = false },
    };
    try directory_file.sync(io);
}

fn inheritDirectoryOwner(dir: std.Io.Dir, file: std.Io.File) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const request: linux.STATX = .{ .UID = true, .GID = true };
    var directory_stat = std.mem.zeroes(linux.Statx);
    var file_stat = std.mem.zeroes(linux.Statx);
    switch (linux.errno(linux.statx(dir.handle, "", linux.AT.EMPTY_PATH, request, &directory_stat))) {
        .SUCCESS => {},
        else => return error.OwnerLookupFailed,
    }
    switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, request, &file_stat))) {
        .SUCCESS => {},
        else => return error.OwnerLookupFailed,
    }
    if (directory_stat.uid == file_stat.uid and directory_stat.gid == file_stat.gid) return;
    switch (linux.errno(linux.fchown(file.handle, directory_stat.uid, directory_stat.gid))) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.OwnerPreservationDenied,
        else => return error.OwnerPreservationFailed,
    }
}

fn makePrivate(dir: std.Io.Dir) !void {
    try dir.setPermissions(std.testing.io, .fromMode(private_directory_mode));
}

fn testRestoreAudit(seed: u8) RestoreAudit {
    return .{
        .id = [_]u8{seed} ** 16,
        .bootstrap_revoke_id = [_]u8{seed +% 1} ** 16,
        .occurred_at = 42,
    };
}

fn createInitializedDatabase(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
) !sqlite.Database {
    var file = try dir.createFile(io, name, .{
        .read = true,
        .exclusive = true,
        .permissions = .fromMode(private_file_mode),
    });
    try file.setPermissions(io, .fromMode(private_file_mode));
    file.close(io);
    const path = try databasePath(allocator, io, dir, name);
    defer allocator.free(path);
    return sqlite.Database.openInitialized(path);
}

fn insertMarkerAndSession(db: *sqlite.Database, marker: []const u8) !void {
    var marker_statement = try db.prepare(
        "INSERT INTO vnrs " ++
            "(name, network, prefix, revision, created_at, updated_at) " ++
            "VALUES (?1, 167772160, 24, 1, 1, 1);",
    );
    defer marker_statement.deinit();
    try marker_statement.bindText(1, marker);
    if (try marker_statement.step() != .done) return error.UnexpectedRow;
    try db.exec(
        "INSERT INTO users " ++
            "(id,username,role,password_phc,enabled,password_change_required," ++
            "revision,created_at,updated_at,password_changed_at) VALUES " ++
            "(X'01010101010101010101010101010101','admin','superuser','x',1,0,1,1,1,1);" ++
            "INSERT INTO web_sessions " ++
            "(id,user_id,token_hash,csrf_token_hash,created_at,last_seen_at," ++
            "idle_expires_at,absolute_expires_at,user_agent) VALUES " ++
            "(X'02020202020202020202020202020202'," ++
            "X'01010101010101010101010101010101',zeroblob(32)," ++
            "X'0303030303030303030303030303030303030303030303030303030303030303'," ++
            "1,1,1801,43201,'test');",
    );
}

fn expectCounts(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    marker: []const u8,
    sessions: i64,
) !void {
    const path = try databasePath(allocator, io, dir, name);
    defer allocator.free(path);
    var db = try sqlite.Database.openReadOnly(path);
    defer db.close();
    try db.integrityCheck();
    var statement = try db.prepare(
        "SELECT " ++
            "(SELECT count(*) FROM vnrs WHERE name = ?1), " ++
            "(SELECT count(*) FROM web_sessions);",
    );
    defer statement.deinit();
    try statement.bindText(1, marker);
    try std.testing.expectEqual(sqlite.Step.row, try statement.step());
    try std.testing.expectEqual(@as(i64, 1), statement.columnInt64(0));
    try std.testing.expectEqual(sessions, statement.columnInt64(1));
}

fn expectRestoreAudit(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    expected: RestoreAudit,
) !void {
    const path = try databasePath(allocator, io, dir, name);
    defer allocator.free(path);
    var db = try sqlite.Database.openReadOnly(path);
    defer db.close();
    var statement = try db.prepare(
        "SELECT id,occurred_at,actor_kind,action,resource_type,details_json " ++
            "FROM audit_entries WHERE action = 'database.restore';",
    );
    defer statement.deinit();
    try std.testing.expectEqual(sqlite.Step.row, try statement.step());
    try std.testing.expectEqualSlices(u8, &expected.id, statement.columnBlob(0).?);
    try std.testing.expectEqual(expected.occurred_at, statement.columnInt64(1));
    try std.testing.expectEqualStrings("local_cli", statement.columnText(2).?);
    try std.testing.expectEqualStrings("database.restore", statement.columnText(3).?);
    try std.testing.expectEqualStrings("database", statement.columnText(4).?);
    try std.testing.expectEqualStrings("{\"sessionsRevoked\":true}", statement.columnText(5).?);
    try std.testing.expectEqual(sqlite.Step.done, try statement.step());
}

fn expectAuditCount(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    expected: i64,
) !void {
    const path = try databasePath(allocator, io, dir, name);
    defer allocator.free(path);
    var db = try sqlite.Database.openReadOnly(path);
    defer db.close();
    var statement = try db.prepare("SELECT count(*) FROM audit_entries;");
    defer statement.deinit();
    try std.testing.expectEqual(sqlite.Step.row, try statement.step());
    try std.testing.expectEqual(expected, statement.columnInt64(0));
}

fn expectBootstrapState(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    expected_status: []const u8,
    expected_reason: ?[]const u8,
    verifier_present: bool,
) !void {
    const path = try databasePath(allocator, io, dir, name);
    defer allocator.free(path);
    var db = try sqlite.Database.openReadOnly(path);
    defer db.close();
    var statement = try db.prepare(
        "SELECT b.status,b.invalidation_reason,c.status,c.derived_psk " ++
            "FROM enrollment_bootstraps AS b JOIN enrollment_credentials AS c " ++
            "ON c.handle=b.enrollment_handle WHERE b.locator='ABC23456';",
    );
    defer statement.deinit();
    try std.testing.expectEqual(sqlite.Step.row, try statement.step());
    try std.testing.expectEqualStrings(expected_status, statement.columnText(0).?);
    if (expected_reason) |reason| {
        try std.testing.expectEqualStrings(reason, statement.columnText(1).?);
    } else {
        try std.testing.expect(statement.columnIsNull(1));
    }
    try std.testing.expectEqualStrings(if (verifier_present) "unused" else "revoked", statement.columnText(2).?);
    try std.testing.expectEqual(verifier_present, !statement.columnIsNull(3));
    try std.testing.expectEqual(sqlite.Step.done, try statement.step());
}

const LiveBackupCheckpoint = struct {
    source: *sqlite.Database,
    calls: u32 = 0,
    maximum_total_pages: u32 = 0,
    inserted_during_backup: bool = false,

    fn checkpoint(self: *LiveBackupCheckpoint) sqlite.BackupCheckpoint {
        return .{ .context = self, .checkpoint_fn = runOpaque };
    }

    fn runOpaque(raw: ?*anyopaque, progress: sqlite.BackupProgress) anyerror!void {
        const self: *LiveBackupCheckpoint = @ptrCast(@alignCast(raw orelse
            return error.InvalidTestCheckpoint));
        self.calls += 1;
        self.maximum_total_pages = @max(self.maximum_total_pages, progress.total_pages);
        if (self.inserted_during_backup) return;
        self.inserted_during_backup = true;
        try self.source.exec(
            "INSERT INTO backup_payload (id, payload) VALUES (2, zeroblob(8192));",
        );
    }
};

const CountingBackupCheckpoint = struct {
    calls: u32 = 0,

    fn checkpoint(self: *CountingBackupCheckpoint) sqlite.BackupCheckpoint {
        return .{ .context = self, .checkpoint_fn = runOpaque };
    }

    fn runOpaque(raw: ?*anyopaque, _: sqlite.BackupProgress) anyerror!void {
        const self: *CountingBackupCheckpoint = @ptrCast(@alignCast(raw orelse
            return error.InvalidTestCheckpoint));
        self.calls += 1;
    }
};

test "online backup yields between multi-page steps and includes same-owner writes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    var backup_tmp = std.testing.tmpDir(.{});
    defer backup_tmp.cleanup();
    try makePrivate(source_tmp.dir);
    try makePrivate(backup_tmp.dir);

    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, database_file);
    defer source.close();
    try source.exec(
        "CREATE TABLE backup_payload (id INTEGER PRIMARY KEY, payload BLOB NOT NULL) STRICT;" ++
            "INSERT INTO backup_payload (id, payload) VALUES (1, zeroblob(1048576));",
    );

    var checkpoint: LiveBackupCheckpoint = .{ .source = &source };
    try onlineBackupWithOptions(
        allocator,
        io,
        &source,
        backup_tmp.dir,
        "bounded.sqlite3",
        .{
            .pages_per_step = 8,
            .checkpoint = checkpoint.checkpoint(),
        },
    );

    try std.testing.expect(checkpoint.calls > 1);
    try std.testing.expect(checkpoint.maximum_total_pages > 8);
    try std.testing.expect(checkpoint.inserted_during_backup);

    const backup_path = try databasePath(allocator, io, backup_tmp.dir, "bounded.sqlite3");
    defer allocator.free(backup_path);
    var backup = try sqlite.Database.openReadOnly(backup_path);
    defer backup.close();
    var count = try backup.prepare("SELECT count(*) FROM backup_payload;");
    defer count.deinit();
    try std.testing.expectEqual(sqlite.Step.row, try count.step());
    // SQLite guarantees that a source write made through the backup's own
    // connection between steps is reflected in the destination snapshot.
    try std.testing.expectEqual(@as(i64, 2), count.columnInt64(0));
}

test "online backup bounds SQLITE_BUSY or SQLITE_LOCKED retries" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try makePrivate(tmp.dir);

    var source = try createInitializedDatabase(allocator, io, tmp.dir, "locked-source.sqlite3");
    defer source.close();
    var destination = try createInitializedDatabase(allocator, io, tmp.dir, "locked-destination.sqlite3");
    defer destination.close();

    var transaction = try source.begin(.immediate);
    defer transaction.rollback() catch {};
    var checkpoint: CountingBackupCheckpoint = .{};
    if (source.backupTo(&destination, .{
        .pages_per_step = 1,
        .busy_retry_limit = 2,
        .checkpoint = checkpoint.checkpoint(),
    })) |_| {
        return error.LockedBackupUnexpectedlySucceeded;
    } else |err| {
        try std.testing.expect(err == error.DatabaseBusy or err == error.DatabaseLocked);
    }
    // The initial contention result is followed by exactly two admitted
    // retries; the terminal result is surfaced instead of spinning forever.
    try std.testing.expectEqual(@as(u32, 2), checkpoint.calls);
}

test "online backup is private, standalone, consistent, and non-replacing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    var backup_tmp = std.testing.tmpDir(.{});
    defer backup_tmp.cleanup();
    try makePrivate(source_tmp.dir);
    try makePrivate(backup_tmp.dir);

    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, database_file);
    defer source.close();
    try insertMarkerAndSession(&source, "snapshot");
    try onlineBackup(allocator, io, &source, backup_tmp.dir, "backup.sqlite3");

    const stat = try validateDatabaseFile(backup_tmp.dir, io, "backup.sqlite3");
    try std.testing.expectEqual(@as(u32, private_file_mode), stat.permissions.toMode() & 0o777);
    try rejectSidecars(backup_tmp.dir, io, "backup.sqlite3");
    try expectCounts(allocator, io, backup_tmp.dir, "backup.sqlite3", "snapshot", 1);
    try std.testing.expectError(
        error.BackupAlreadyExists,
        onlineBackup(allocator, io, &source, backup_tmp.dir, "backup.sqlite3"),
    );

    try backup_tmp.dir.symLink(io, "backup.sqlite3", "blocked.sqlite3", .{});
    try std.testing.expectError(
        error.BackupAlreadyExists,
        onlineBackup(allocator, io, &source, backup_tmp.dir, "blocked.sqlite3"),
    );
}

test "stopped restore retains current database and revokes restored sessions and invitations" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var state_tmp = std.testing.tmpDir(.{});
    defer state_tmp.cleanup();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    try makePrivate(state_tmp.dir);
    try makePrivate(source_tmp.dir);

    var current = try createInitializedDatabase(allocator, io, state_tmp.dir, database_file);
    try insertMarkerAndSession(&current, "current");
    current.close();

    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, "source-live.sqlite3");
    try insertMarkerAndSession(&source, "restored");
    var source_repository = management_repository.Repository.init(&source);
    var source_store = try source_repository.loadInventory(allocator);
    defer source_store.deinit();
    const node_id: model.NodeId = .{ .bytes = [_]u8{0x31} ** 16 };
    try source_store.createNode(node_id, "node01", "restored", try model.Ipv4.parse("10.0.0.2"));
    _ = try source_repository.persistInventoryWithBootstrap(
        &source_store,
        .{
            .locator = "ABC23456".*,
            .node_id = node_id,
            .handle = [_]u8{0x41} ** 16,
            .derived_psk = [_]u8{0x42} ** 32,
            .expires_at = 100,
        },
        0,
        10,
        .{
            .id = [_]u8{0x70} ** 16,
            .occurred_at = 10,
            .actor_kind = .system,
            .action = "test.bootstrap.issue",
            .resource_type = "node",
        },
    );
    try onlineBackup(allocator, io, &source, source_tmp.dir, "source.sqlite3");
    source.close();

    const result = try restoreStopped(
        allocator,
        io,
        state_tmp.dir,
        source_tmp.dir,
        "source.sqlite3",
        "before-restore.sqlite3",
        testRestoreAudit(0x40),
    );
    try std.testing.expectEqual(@as(u64, 1), result.revoked_sessions);
    try std.testing.expectEqual(@as(u64, 1), result.revoked_bootstraps);
    try expectCounts(allocator, io, state_tmp.dir, database_file, "restored", 0);
    try expectRestoreAudit(allocator, io, state_tmp.dir, database_file, testRestoreAudit(0x40));
    try expectBootstrapState(allocator, io, state_tmp.dir, database_file, "revoked", "restore", false);
    try expectCounts(allocator, io, state_tmp.dir, "before-restore.sqlite3", "current", 1);
    try expectAuditCount(allocator, io, state_tmp.dir, "before-restore.sqlite3", 0);
    try expectCounts(allocator, io, source_tmp.dir, "source.sqlite3", "restored", 1);
    try expectAuditCount(allocator, io, source_tmp.dir, "source.sqlite3", 1);
    try expectBootstrapState(allocator, io, source_tmp.dir, "source.sqlite3", "active", null, true);
    try rejectSidecars(state_tmp.dir, io, database_file);
    try rejectSidecars(state_tmp.dir, io, "before-restore.sqlite3");
}

test "restore audit failure cannot replace current state or retain recovery" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var state_tmp = std.testing.tmpDir(.{});
    defer state_tmp.cleanup();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    try makePrivate(state_tmp.dir);
    try makePrivate(source_tmp.dir);

    var current = try createInitializedDatabase(allocator, io, state_tmp.dir, database_file);
    try insertMarkerAndSession(&current, "current");
    current.close();

    const duplicate = testRestoreAudit(0x55);
    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, "source-live.sqlite3");
    try insertMarkerAndSession(&source, "restored");
    _ = try operations_repository.Repository.init(&source).appendAudit(.{
        .id = duplicate.id,
        .occurred_at = 1,
        .actor_kind = .system,
        .action = "seed",
        .resource_type = "test",
    });
    try onlineBackup(allocator, io, &source, source_tmp.dir, "source.sqlite3");
    source.close();

    try std.testing.expectError(
        error.ConstraintViolation,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "source.sqlite3",
            "before-restore.sqlite3",
            duplicate,
        ),
    );
    try expectCounts(allocator, io, state_tmp.dir, database_file, "current", 1);
    try expectAuditCount(allocator, io, state_tmp.dir, database_file, 0);
    try expectCounts(allocator, io, source_tmp.dir, "source.sqlite3", "restored", 1);
    try expectAuditCount(allocator, io, source_tmp.dir, "source.sqlite3", 1);
    try std.testing.expectError(
        error.FileNotFound,
        state_tmp.dir.statFile(io, "before-restore.sqlite3", .{ .follow_symlinks = false }),
    );
}

test "restore rejects corrupt, sidecar-backed, and symlink sources before replacement" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var state_tmp = std.testing.tmpDir(.{});
    defer state_tmp.cleanup();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    try makePrivate(state_tmp.dir);
    try makePrivate(source_tmp.dir);

    var current = try createInitializedDatabase(allocator, io, state_tmp.dir, database_file);
    try insertMarkerAndSession(&current, "current");
    current.close();

    var corrupt = try source_tmp.dir.createFile(io, "corrupt.sqlite3", .{
        .permissions = .fromMode(private_file_mode),
    });
    try corrupt.setPermissions(io, .fromMode(private_file_mode));
    try corrupt.writeStreamingAll(io, "not a sqlite database");
    try corrupt.sync(io);
    corrupt.close(io);
    if (restoreStopped(
        allocator,
        io,
        state_tmp.dir,
        source_tmp.dir,
        "corrupt.sqlite3",
        "recovery.sqlite3",
        testRestoreAudit(0x41),
    )) |_| {
        return error.CorruptRestoreSucceeded;
    } else |_| {}
    try expectCounts(allocator, io, state_tmp.dir, database_file, "current", 1);
    try std.testing.expectError(
        error.FileNotFound,
        state_tmp.dir.statFile(io, "recovery.sqlite3", .{ .follow_symlinks = false }),
    );

    try source_tmp.dir.symLink(io, "corrupt.sqlite3", "linked.sqlite3", .{});
    if (restoreStopped(
        allocator,
        io,
        state_tmp.dir,
        source_tmp.dir,
        "linked.sqlite3",
        "recovery.sqlite3",
        testRestoreAudit(0x42),
    )) |_| {
        return error.SymbolicLinkRestoreSucceeded;
    } else |_| {}

    var sidecar = try source_tmp.dir.createFile(io, "corrupt.sqlite3-wal", .{
        .permissions = .fromMode(private_file_mode),
    });
    try sidecar.setPermissions(io, .fromMode(private_file_mode));
    sidecar.close(io);
    try std.testing.expectError(
        error.SourceHasSidecars,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "corrupt.sqlite3",
            "recovery.sqlite3",
            testRestoreAudit(0x43),
        ),
    );
}

test "restore rejects relational corruption before retaining or replacing current state" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var state_tmp = std.testing.tmpDir(.{});
    defer state_tmp.cleanup();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    try makePrivate(state_tmp.dir);
    try makePrivate(source_tmp.dir);

    var current = try createInitializedDatabase(allocator, io, state_tmp.dir, database_file);
    try insertMarkerAndSession(&current, "current");
    current.close();

    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, "orphan.sqlite3");
    // integrity_check alone considers this structurally valid. A stopped
    // restore must additionally reject the orphaned Node before creating a
    // recovery artifact or touching the authoritative database.
    try source.exec("PRAGMA journal_mode = DELETE;");
    try source.exec("PRAGMA foreign_keys = OFF;");
    try source.exec(
        "INSERT INTO nodes (id,name,vnr_name,address,created_at,updated_at) VALUES " ++
            "(X'09090909090909090909090909090909','orphan','missing',167772162,1,1);",
    );
    source.close();

    try std.testing.expectError(
        error.IntegrityCheckFailed,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "orphan.sqlite3",
            "before-restore.sqlite3",
            testRestoreAudit(0x44),
        ),
    );
    try expectCounts(allocator, io, state_tmp.dir, database_file, "current", 1);
    try std.testing.expectError(
        error.FileNotFound,
        state_tmp.dir.statFile(io, "before-restore.sqlite3", .{ .follow_symlinks = false }),
    );

    var overlap = try createInitializedDatabase(allocator, io, source_tmp.dir, "overlap.sqlite3");
    try overlap.exec("PRAGMA journal_mode = DELETE;");
    try overlap.exec(
        "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) VALUES " ++
            "('one',167772160,24,1,1,1),('two',167772288,25,1,1,1);",
    );
    // Foreign keys and SQLite integrity are both clean here; only NTIP's CIDR
    // non-overlap invariant distinguishes this from a restorable snapshot.
    overlap.close();
    try std.testing.expectError(
        error.IntegrityCheckFailed,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "overlap.sqlite3",
            "before-restore.sqlite3",
            testRestoreAudit(0x45),
        ),
    );
    try expectCounts(allocator, io, state_tmp.dir, database_file, "current", 1);
}

test "restore rejects an unsafe target sidecar without touching it" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var state_tmp = std.testing.tmpDir(.{});
    defer state_tmp.cleanup();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    try makePrivate(state_tmp.dir);
    try makePrivate(source_tmp.dir);

    var current = try createInitializedDatabase(allocator, io, state_tmp.dir, database_file);
    try insertMarkerAndSession(&current, "current");
    current.close();
    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, "source-live.sqlite3");
    try insertMarkerAndSession(&source, "restored");
    try onlineBackup(allocator, io, &source, source_tmp.dir, "source.sqlite3");
    source.close();

    try state_tmp.dir.symLink(io, database_file, database_file ++ "-wal", .{});
    try std.testing.expectError(
        error.InvalidSidecarFileType,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "source.sqlite3",
            "before-restore.sqlite3",
            testRestoreAudit(0x46),
        ),
    );
    const sidecar = try state_tmp.dir.statFile(io, database_file ++ "-wal", .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.sym_link, sidecar.kind);
    // Remove the deliberately hostile object before asking SQLite to open the
    // unchanged current database; SQLite itself correctly refuses that path.
    try state_tmp.dir.deleteFile(io, database_file ++ "-wal");
    try expectCounts(allocator, io, state_tmp.dir, database_file, "current", 1);
}

test "maintenance rejects insecure directories and source permissions" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var state_tmp = std.testing.tmpDir(.{});
    defer state_tmp.cleanup();
    var source_tmp = std.testing.tmpDir(.{});
    defer source_tmp.cleanup();
    try makePrivate(state_tmp.dir);
    try makePrivate(source_tmp.dir);

    var current = try createInitializedDatabase(allocator, io, state_tmp.dir, database_file);
    try insertMarkerAndSession(&current, "current");
    current.close();
    var source = try createInitializedDatabase(allocator, io, source_tmp.dir, "source-live.sqlite3");
    try insertMarkerAndSession(&source, "restored");
    try onlineBackup(allocator, io, &source, source_tmp.dir, "source.sqlite3");
    source.close();

    try source_tmp.dir.setFilePermissions(
        io,
        "source.sqlite3",
        .fromMode(0o644),
        .{ .follow_symlinks = false },
    );
    try std.testing.expectError(
        error.InsecureDatabasePermissions,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "source.sqlite3",
            "before-restore.sqlite3",
            testRestoreAudit(0x47),
        ),
    );
    try expectCounts(allocator, io, state_tmp.dir, database_file, "current", 1);

    try source_tmp.dir.setPermissions(io, .fromMode(0o755));
    try std.testing.expectError(
        error.InsecureDirectoryPermissions,
        restoreStopped(
            allocator,
            io,
            state_tmp.dir,
            source_tmp.dir,
            "source.sqlite3",
            "before-restore.sqlite3",
            testRestoreAudit(0x48),
        ),
    );
}
