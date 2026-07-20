//! Minimal owning SQLite wrapper for the authoritative Master database.
//!
//! This module intentionally exposes prepared statements and explicit
//! transactions instead of a string-building query API. The management-plane
//! repository is expected to serialize access to one `Database` instance.

const std = @import("std");
const builtin = @import("builtin");
const migrations = @import("migrations.zig");

pub const c = @cImport({
    @cInclude("sqlite3.h");
    @cInclude("ntip_sqlite.h");
});

pub const Error = error{
    OpenFailed,
    DatabaseBusy,
    DatabaseLocked,
    DatabaseReadOnly,
    DatabaseCorrupt,
    NotDatabase,
    ConstraintViolation,
    SqliteFailure,
    UnexpectedRow,
    UnexpectedDone,
    InvalidColumn,
    InvalidMigrationRegistry,
    MigrationGap,
    MigrationNameMismatch,
    MigrationChecksumMismatch,
    MigrationSourceChecksumMismatch,
    MigrationStateMismatch,
    UnsupportedSchemaVersion,
    IntegrityCheckFailed,
    CommitHookFailed,
};

pub const current_schema_version = migrations.current_schema_version;
pub const default_busy_timeout_ms: c_int = 5_000;
/// Keep each online-backup lock wait short enough for the serialized owner to
/// return to protocol-critical work between bounded page copies. Contention is
/// retried explicitly below instead of allowing one SQLite call to wait for
/// the connection-wide default timeout.
pub const backup_step_busy_timeout_ms: c_int = 25;
pub const default_backup_pages_per_step: u16 = 64;
pub const default_backup_busy_retry_limit: u8 = 8;

const create_migration_registry_sql: [:0]const u8 =
    \\CREATE TABLE IF NOT EXISTS schema_migrations (
    \\    version INTEGER PRIMARY KEY CHECK (version > 0),
    \\    name TEXT NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 128),
    \\    checksum BLOB NOT NULL CHECK (length(checksum) = 32),
    \\    applied_at INTEGER NOT NULL CHECK (applied_at >= 0)
    \\) STRICT;
;

pub const Step = enum {
    row,
    done,
};

pub const TransactionMode = enum {
    deferred,
    immediate,
};

/// One serialized request may attach a single durable participant to the next
/// explicit transaction. The participant runs immediately before COMMIT on
/// the same SQLite connection, so its write is atomic with the repository
/// mutation. It is marked complete only after COMMIT succeeds.
pub const CommitHook = struct {
    context: *anyopaque,
    before_commit_fn: *const fn (*anyopaque, *Database) anyerror!void,
    armed: bool = false,
    completed: bool = false,

    fn beforeCommit(self: *CommitHook, db: *Database) !void {
        return self.before_commit_fn(self.context, db);
    }
};

/// State observed after one bounded call to `sqlite3_backup_step`. Page counts
/// are advisory progress data and may increase if the live source changes.
pub const BackupProgress = struct {
    remaining_pages: u32,
    total_pages: u32,
};

/// Invoked only between backup steps, after SQLite has released the source
/// read lock held by the preceding step. A live owner may use this seam to
/// advance bounded protocol/runtime work on the same source connection. It
/// must not recursively start another backup or accept another admin request.
pub const BackupCheckpoint = struct {
    context: ?*anyopaque = null,
    checkpoint_fn: *const fn (?*anyopaque, BackupProgress) anyerror!void,

    pub fn run(self: BackupCheckpoint, progress: BackupProgress) !void {
        return self.checkpoint_fn(self.context, progress);
    }
};

pub const BackupOptions = struct {
    pages_per_step: u16 = default_backup_pages_per_step,
    busy_retry_limit: u8 = default_backup_busy_retry_limit,
    checkpoint: ?BackupCheckpoint = null,
};

pub const Database = struct {
    handle: *c.sqlite3,
    commit_hook: ?CommitHook = null,

    pub fn open(path: [:0]const u8) Error!Database {
        return openWithFlags(path, c.SQLITE_OPEN_READWRITE |
            c.SQLITE_OPEN_CREATE |
            c.SQLITE_OPEN_FULLMUTEX);
    }

    /// Opens an existing database without granting SQLite permission to
    /// create or mutate it. Maintenance code uses this for restore artifact
    /// validation before any staged changes are made.
    pub fn openReadOnly(path: [:0]const u8) Error!Database {
        return openWithFlags(path, c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_FULLMUTEX);
    }

    fn openWithFlags(path: [:0]const u8, flags: c_int) Error!Database {
        var handle: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open_v2(path.ptr, &handle, flags, null);
        if (rc != c.SQLITE_OK or handle == null) {
            if (handle) |opened| _ = c.sqlite3_close_v2(opened);
            return error.OpenFailed;
        }
        const db = Database{ .handle = handle.? };
        errdefer db.close();
        try check(db.handle, c.sqlite3_extended_result_codes(db.handle, 1));
        try check(db.handle, c.sqlite3_busy_timeout(db.handle, default_busy_timeout_ms));
        return db;
    }

    pub fn openInitialized(path: [:0]const u8) !Database {
        var db = try open(path);
        errdefer db.close();
        try db.initialize();
        return db;
    }

    pub fn close(self: Database) void {
        // close_v2 defers destruction safely if a caller forgot to finalize a
        // statement. Such a caller is still a bug, but never warrants a leak.
        _ = c.sqlite3_close_v2(self.handle);
    }

    pub fn initialize(self: *Database) !void {
        // WAL must be selected before synchronous is pinned because SQLite
        // maintains a separate WAL synchronous default.
        try self.exec("PRAGMA journal_mode = WAL;");
        try self.exec("PRAGMA synchronous = FULL;");
        try self.exec("PRAGMA foreign_keys = ON;");
        try self.exec("PRAGMA secure_delete = ON;");
        try self.exec("PRAGMA trusted_schema = OFF;");
        try self.exec("PRAGMA recursive_triggers = ON;");
        try self.exec("PRAGMA wal_autocheckpoint = 1000;");

        try self.expectPragmaInt("PRAGMA synchronous;", 2);
        try self.expectPragmaInt("PRAGMA foreign_keys;", 1);
        try self.expectPragmaInt("PRAGMA secure_delete;", 1);
        try self.expectPragmaInt("PRAGMA trusted_schema;", 0);
        try self.expectPragmaText("PRAGMA journal_mode;", "wal");

        try self.applyMigrations();
    }

    pub fn exec(self: *Database, sql: [:0]const u8) Error!void {
        var message: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.handle, sql.ptr, null, null, &message);
        if (message != null) c.sqlite3_free(message);
        try check(self.handle, rc);
    }

    pub fn prepare(self: *Database, sql: [:0]const u8) Error!Statement {
        var statement: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v3(
            self.handle,
            sql.ptr,
            @intCast(sql.len),
            c.SQLITE_PREPARE_PERSISTENT,
            &statement,
            null,
        );
        try check(self.handle, rc);
        return .{ .db = self, .handle = statement orelse return error.SqliteFailure };
    }

    pub fn begin(self: *Database, mode: TransactionMode) Error!Transaction {
        switch (mode) {
            .deferred => try self.exec("BEGIN DEFERRED;"),
            .immediate => try self.exec("BEGIN IMMEDIATE;"),
        }
        return .{ .db = self };
    }

    pub fn installCommitHook(self: *Database, hook: CommitHook) !void {
        if (self.commit_hook != null) return error.CommitHookAlreadyInstalled;
        self.commit_hook = hook;
    }

    pub fn commitHookCompleted(self: *const Database) bool {
        return if (self.commit_hook) |hook| hook.completed else false;
    }

    /// Arm only for a transaction that contains an authoritative audited web
    /// mutation or an explicit idempotent security side effect. Read-only
    /// authentication/session-touch transactions must not consume the hook.
    pub fn armCommitHook(self: *Database) void {
        if (self.commit_hook) |*hook| hook.armed = true;
    }

    pub fn clearCommitHook(self: *Database) void {
        self.commit_hook = null;
    }

    pub fn inTransaction(self: *const Database) bool {
        return c.sqlite3_get_autocommit(self.handle) == 0;
    }

    pub fn quickCheck(self: *Database) !void {
        var statement = try self.prepare("PRAGMA quick_check;");
        defer statement.deinit();
        if (try statement.step() != .row) return error.IntegrityCheckFailed;
        const result = statement.columnText(0) orelse return error.IntegrityCheckFailed;
        if (!std.mem.eql(u8, result, "ok")) return error.IntegrityCheckFailed;
        if (try statement.step() != .done) return error.IntegrityCheckFailed;
    }

    /// Runs SQLite's complete structural and content consistency check. This
    /// is intentionally distinct from `quickCheck`: restore is rare enough
    /// that its stronger validation cost is warranted.
    pub fn integrityCheck(self: *Database) !void {
        var statement = try self.prepare("PRAGMA integrity_check;");
        defer statement.deinit();
        if (try statement.step() != .row) return error.IntegrityCheckFailed;
        const result = statement.columnText(0) orelse return error.IntegrityCheckFailed;
        if (!std.mem.eql(u8, result, "ok")) return error.IntegrityCheckFailed;
        if (try statement.step() != .done) return error.IntegrityCheckFailed;

        // SQLite's integrity_check deliberately does not report foreign-key
        // violations. A restore artifact with orphaned inventory or access
        // rows is not an internally valid NTIP database even when every B-tree
        // is structurally sound, so the stronger maintenance check includes
        // the separate relational consistency pass.
        var foreign_keys = try self.prepare("PRAGMA foreign_key_check;");
        defer foreign_keys.deinit();
        if (try foreign_keys.step() != .done) return error.IntegrityCheckFailed;
    }

    /// Verifies that the database is exactly the schema understood by this
    /// binary and that every applied migration retains its pinned identity.
    /// Unlike `initialize`, this method is read-only.
    pub fn validateCurrentSchema(self: *Database) !void {
        migrations.validateSources() catch return error.MigrationSourceChecksumMismatch;
        if (try self.schemaVersion() != migrations.current_schema_version) {
            return error.UnsupportedSchemaVersion;
        }

        var rows = try self.prepare(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version;",
        );
        defer rows.deinit();
        var index: usize = 0;
        while (try rows.step() == .row) : (index += 1) {
            if (index >= migrations.all.len) return error.InvalidMigrationRegistry;
            const migration = migrations.all[index];
            const raw_version = rows.columnInt64(0);
            if (raw_version <= 0 or raw_version > std.math.maxInt(u32)) {
                return error.InvalidMigrationRegistry;
            }
            if (@as(u32, @intCast(raw_version)) != migration.version) {
                return error.MigrationGap;
            }
            const name = rows.columnText(1) orelse return error.InvalidMigrationRegistry;
            if (!std.mem.eql(u8, name, migration.name)) return error.MigrationNameMismatch;
            const checksum = rows.columnBlob(2) orelse return error.InvalidMigrationRegistry;
            if (checksum.len != migration.sha256.len or
                !std.mem.eql(u8, checksum, &migration.sha256))
            {
                return error.MigrationChecksumMismatch;
            }
        }
        if (index != migrations.all.len) return error.MigrationStateMismatch;
    }

    /// Copies one consistent online snapshot using SQLite's backup API. Both
    /// connections remain owned by their callers. Each step copies a bounded
    /// number of pages and recoverable lock contention is retried a bounded
    /// number of times. `sqlite3_backup_finish` is called exactly once after a
    /// successful init, including when the checkpoint aborts the operation.
    pub fn backupTo(
        self: *Database,
        destination: *Database,
        options: BackupOptions,
    ) !void {
        if (options.pages_per_step == 0) return error.InvalidBackupOptions;

        // The destination is a private temporary database in production. Its
        // busy handler is nevertheless shortened while the backup is active,
        // bounding a single lock wait before control returns to the checkpoint.
        try check(destination.handle, c.sqlite3_busy_timeout(
            destination.handle,
            backup_step_busy_timeout_ms,
        ));
        defer _ = c.sqlite3_busy_timeout(destination.handle, default_busy_timeout_ms);

        const backup = c.sqlite3_backup_init(
            destination.handle,
            "main",
            self.handle,
            "main",
        ) orelse {
            try check(destination.handle, c.sqlite3_errcode(destination.handle));
            return error.SqliteFailure;
        };
        var backup_active = true;
        defer if (backup_active) {
            _ = c.sqlite3_backup_finish(backup);
        };

        var busy_retries: u8 = 0;
        while (true) {
            const step_rc = c.sqlite3_backup_step(backup, @intCast(options.pages_per_step));
            switch (step_rc) {
                c.SQLITE_DONE => break,
                c.SQLITE_OK => busy_retries = 0,
                c.SQLITE_BUSY, c.SQLITE_LOCKED => {
                    if (busy_retries == options.busy_retry_limit) {
                        try check(destination.handle, step_rc);
                        unreachable;
                    }
                    busy_retries += 1;
                },
                else => {
                    try check(destination.handle, step_rc);
                    unreachable;
                },
            }

            if (options.checkpoint) |checkpoint| {
                try checkpoint.run(.{
                    .remaining_pages = backupPageCount(c.sqlite3_backup_remaining(backup)),
                    .total_pages = backupPageCount(c.sqlite3_backup_pagecount(backup)),
                });
            }
        }

        const finish_rc = c.sqlite3_backup_finish(backup);
        backup_active = false;
        try check(destination.handle, finish_rc);
    }

    /// Forces committed WAL frames into the main database and truncates the
    /// WAL. The stopped-service restore path uses this before deleting stale
    /// sidecars and replacing the main file.
    pub fn checkpointTruncate(self: *Database) Error!void {
        var log_frames: c_int = 0;
        var checkpointed_frames: c_int = 0;
        try check(self.handle, c.sqlite3_wal_checkpoint_v2(
            self.handle,
            "main",
            c.SQLITE_CHECKPOINT_TRUNCATE,
            &log_frames,
            &checkpointed_frames,
        ));
    }

    pub fn schemaVersion(self: *Database) !u32 {
        const value = try self.pragmaInt("PRAGMA user_version;");
        if (value < 0 or value > std.math.maxInt(u32)) return error.InvalidMigrationRegistry;
        return @intCast(value);
    }

    pub fn lastErrorMessage(self: *const Database) []const u8 {
        const message = c.sqlite3_errmsg(self.handle);
        if (message == null) return "unknown sqlite error";
        return std.mem.span(message);
    }

    pub fn changes(self: *const Database) u64 {
        return @intCast(c.sqlite3_changes64(self.handle));
    }

    fn applyMigrations(self: *Database) !void {
        migrations.validateSources() catch return error.MigrationSourceChecksumMismatch;

        const before_version = try self.schemaVersion();
        if (before_version > migrations.current_schema_version) {
            return error.UnsupportedSchemaVersion;
        }

        var transaction = try self.begin(.immediate);
        errdefer transaction.rollback() catch {};

        try self.exec(create_migration_registry_sql);

        var applied = [_]bool{false} ** migrations.all.len;
        var rows = try self.prepare(
            "SELECT version, name, checksum FROM schema_migrations ORDER BY version;",
        );
        defer rows.deinit();
        while (try rows.step() == .row) {
            const raw_version = rows.columnInt64(0);
            if (raw_version <= 0 or raw_version > std.math.maxInt(u32)) {
                return error.InvalidMigrationRegistry;
            }
            const version: u32 = @intCast(raw_version);
            const migration = migrations.find(version) orelse return error.UnsupportedSchemaVersion;
            if (version > applied.len or applied[version - 1]) return error.InvalidMigrationRegistry;

            const name = rows.columnText(1) orelse return error.InvalidMigrationRegistry;
            if (!std.mem.eql(u8, name, migration.name)) return error.MigrationNameMismatch;
            const checksum = rows.columnBlob(2) orelse return error.InvalidMigrationRegistry;
            if (checksum.len != migration.sha256.len or
                !std.mem.eql(u8, checksum, &migration.sha256))
            {
                return error.MigrationChecksumMismatch;
            }
            applied[version - 1] = true;
        }

        var saw_gap = false;
        var applied_count: u32 = 0;
        for (applied) |present| {
            if (!present) {
                saw_gap = true;
            } else {
                if (saw_gap) return error.MigrationGap;
                applied_count += 1;
            }
        }
        if (before_version != applied_count) return error.MigrationStateMismatch;

        for (migrations.all) |migration| {
            if (applied[migration.version - 1]) continue;
            try self.exec(migration.sql);
            var insert = try self.prepare(
                "INSERT INTO schema_migrations " ++
                    "(version, name, checksum, applied_at) " ++
                    "VALUES (?1, ?2, ?3, unixepoch());",
            );
            defer insert.deinit();
            try insert.bindInt64(1, migration.version);
            try insert.bindText(2, migration.name);
            try insert.bindBlob(3, &migration.sha256);
            if (try insert.step() != .done) return error.UnexpectedRow;
        }

        const after_version = try self.schemaVersion();
        if (after_version != migrations.current_schema_version) {
            return error.MigrationStateMismatch;
        }
        try transaction.commit();
    }

    fn pragmaInt(self: *Database, sql: [:0]const u8) !i64 {
        var statement = try self.prepare(sql);
        defer statement.deinit();
        if (try statement.step() != .row) return error.UnexpectedDone;
        const value = statement.columnInt64(0);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return value;
    }

    fn expectPragmaInt(self: *Database, sql: [:0]const u8, expected: i64) !void {
        if (try self.pragmaInt(sql) != expected) return error.SqliteFailure;
    }

    fn expectPragmaText(self: *Database, sql: [:0]const u8, expected: []const u8) !void {
        var statement = try self.prepare(sql);
        defer statement.deinit();
        if (try statement.step() != .row) return error.UnexpectedDone;
        const value = statement.columnText(0) orelse return error.InvalidColumn;
        if (!std.ascii.eqlIgnoreCase(value, expected)) return error.SqliteFailure;
        if (try statement.step() != .done) return error.UnexpectedRow;
    }
};

pub const Transaction = struct {
    db: *Database,
    active: bool = true,

    pub fn commit(self: *Transaction) Error!void {
        if (!self.active) return;
        if (self.db.commit_hook) |*hook| if (hook.armed and !hook.completed) {
            hook.beforeCommit(self.db) catch return error.CommitHookFailed;
        };
        try self.db.exec("COMMIT;");
        self.active = false;
        if (self.db.commit_hook) |*hook| {
            if (hook.armed) hook.completed = true;
        }
    }

    pub fn rollback(self: *Transaction) Error!void {
        if (!self.active) return;
        try self.db.exec("ROLLBACK;");
        self.active = false;
    }
};

pub const Statement = struct {
    db: *Database,
    handle: *c.sqlite3_stmt,

    pub fn deinit(self: *Statement) void {
        _ = c.sqlite3_finalize(self.handle);
        self.* = undefined;
    }

    pub fn bindNull(self: *Statement, index: c_int) Error!void {
        try check(self.db.handle, c.sqlite3_bind_null(self.handle, index));
    }

    pub fn bindInt64(self: *Statement, index: c_int, value: anytype) Error!void {
        try check(self.db.handle, c.sqlite3_bind_int64(self.handle, index, @intCast(value)));
    }

    pub fn bindText(self: *Statement, index: c_int, value: []const u8) Error!void {
        try check(self.db.handle, c.ntip_sqlite_bind_text_transient(
            self.handle,
            index,
            value.ptr,
            value.len,
        ));
    }

    pub fn bindBlob(self: *Statement, index: c_int, value: []const u8) Error!void {
        try check(self.db.handle, c.ntip_sqlite_bind_blob_transient(
            self.handle,
            index,
            value.ptr,
            value.len,
        ));
    }

    pub fn clearBindings(self: *Statement) Error!void {
        try check(self.db.handle, c.sqlite3_clear_bindings(self.handle));
    }

    pub fn reset(self: *Statement) Error!void {
        try check(self.db.handle, c.sqlite3_reset(self.handle));
    }

    pub fn step(self: *Statement) Error!Step {
        const rc = c.sqlite3_step(self.handle);
        return switch (rc) {
            c.SQLITE_ROW => .row,
            c.SQLITE_DONE => .done,
            else => {
                try check(self.db.handle, rc);
                unreachable;
            },
        };
    }

    pub fn columnInt64(self: *const Statement, index: c_int) i64 {
        return c.sqlite3_column_int64(self.handle, index);
    }

    pub fn columnIsNull(self: *const Statement, index: c_int) bool {
        return c.sqlite3_column_type(self.handle, index) == c.SQLITE_NULL;
    }

    pub fn columnText(self: *const Statement, index: c_int) ?[]const u8 {
        if (c.sqlite3_column_type(self.handle, index) == c.SQLITE_NULL) return null;
        const pointer = c.sqlite3_column_text(self.handle, index);
        if (pointer == null) return null;
        const length = c.sqlite3_column_bytes(self.handle, index);
        if (length < 0) return null;
        return pointer[0..@intCast(length)];
    }

    pub fn columnBlob(self: *const Statement, index: c_int) ?[]const u8 {
        if (c.sqlite3_column_type(self.handle, index) == c.SQLITE_NULL) return null;
        const pointer = c.sqlite3_column_blob(self.handle, index);
        const length = c.sqlite3_column_bytes(self.handle, index);
        if (length < 0) return null;
        if (length == 0) return &.{};
        if (pointer == null) return null;
        const bytes: [*]const u8 = @ptrCast(pointer);
        return bytes[0..@intCast(length)];
    }
};

fn backupPageCount(value: c_int) u32 {
    if (value <= 0) return 0;
    return @intCast(value);
}

fn check(_: *c.sqlite3, rc: c_int) Error!void {
    if (rc == c.SQLITE_OK) return;
    const primary = rc & 0xff;
    return switch (primary) {
        c.SQLITE_BUSY => error.DatabaseBusy,
        c.SQLITE_LOCKED => error.DatabaseLocked,
        c.SQLITE_READONLY => error.DatabaseReadOnly,
        c.SQLITE_CORRUPT => error.DatabaseCorrupt,
        c.SQLITE_NOTADB => error.NotDatabase,
        c.SQLITE_CONSTRAINT => error.ConstraintViolation,
        else => error.SqliteFailure,
    };
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

test "initialized database applies durable pragmas and the complete schema" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var db = try Database.openInitialized(path);
    defer db.close();
    try std.testing.expectEqual(current_schema_version, try db.schemaVersion());
    try db.quickCheck();

    var tables = try db.prepare(
        "SELECT count(*) FROM sqlite_schema " ++
            "WHERE type = 'table' AND name IN " ++
            "('vnrs','nodes','routes','enrollment_credentials','users'," ++
            "'web_sessions','settings_revisions','runtime_events'," ++
            "'connectivity_checks','audit_entries');",
    );
    defer tables.deinit();
    try std.testing.expectEqual(Step.row, try tables.step());
    try std.testing.expectEqual(@as(i64, 10), tables.columnInt64(0));
}

test "migration is idempotent and detects a changed applied checksum" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var db = try Database.openInitialized(path);
    defer db.close();
    try db.initialize();
    try db.exec("UPDATE schema_migrations SET checksum = zeroblob(32) WHERE version = 1;");
    try std.testing.expectError(error.MigrationChecksumMismatch, db.initialize());
}

test "failed migration rolls back registry and partial schema" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var db = try Database.open(path);
    defer db.close();
    // Deliberately collide with the first statement in migration 1. The
    // preexisting object is outside the migration transaction; everything the
    // runner creates before the collision must roll back.
    try db.exec("CREATE TABLE master_state (collision INTEGER);");
    try std.testing.expectError(error.SqliteFailure, db.initialize());
    try std.testing.expectEqual(@as(u32, 0), try db.schemaVersion());

    var residue = try db.prepare(
        "SELECT " ++
            "(SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='master_state')," ++
            "(SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='schema_migrations')," ++
            "(SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='vnrs');",
    );
    defer residue.deinit();
    try std.testing.expectEqual(Step.row, try residue.step());
    try std.testing.expectEqual(@as(i64, 1), residue.columnInt64(0));
    try std.testing.expectEqual(@as(i64, 0), residue.columnInt64(1));
    try std.testing.expectEqual(@as(i64, 0), residue.columnInt64(2));
    try std.testing.expectEqual(Step.done, try residue.step());

    try db.exec("DROP TABLE master_state;");
    try db.initialize();
    try std.testing.expectEqual(current_schema_version, try db.schemaVersion());
}

test "prepared statements bind values and schema constraints fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var db = try Database.openInitialized(path);
    defer db.close();
    var insert = try db.prepare(
        "INSERT INTO vnrs " ++
            "(name, network, prefix, revision, created_at, updated_at) " ++
            "VALUES (?1, ?2, ?3, 1, ?4, ?4);",
    );
    defer insert.deinit();
    try insert.bindText(1, "vnr0");
    try insert.bindInt64(2, 0x0a01_0000);
    try insert.bindInt64(3, 24);
    try insert.bindInt64(4, 1);
    try std.testing.expectEqual(Step.done, try insert.step());

    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec(
            "INSERT INTO nodes " ++
                "(id,name,vnr_name,address,created_at,updated_at) VALUES " ++
                "(X'01010101010101010101010101010101','node01','missing',167837698,1,1);",
        ),
    );
}

test "schema protects immutable identities and durable history" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var db = try Database.openInitialized(path);
    defer db.close();
    try db.exec(
        "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
            "VALUES ('vnr0',167772160,24,1,1,1);",
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("UPDATE vnrs SET name = 'renamed' WHERE name = 'vnr0';"),
    );
    try db.exec(
        "INSERT INTO nodes (id,name,vnr_name,address,created_at,updated_at) VALUES " ++
            "(X'01010101010101010101010101010101','node01','vnr0',167772162,1,1);",
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec(
            "UPDATE nodes SET id = X'02020202020202020202020202020202' " ++
                "WHERE id = X'01010101010101010101010101010101';",
        ),
    );

    try db.exec(
        "INSERT INTO user_tombstones " ++
            "(username,former_user_id,tombstoned_at,actor_kind) VALUES " ++
            "('retired',X'03030303030303030303030303030303',1,'system');",
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("UPDATE user_tombstones SET username = 'reused' WHERE username = 'retired';"),
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("DELETE FROM user_tombstones WHERE username = 'retired';"),
    );

    try db.exec(
        "INSERT INTO settings_revisions SELECT " ++
            "X'04040404040404040404040404040404',2,1,status,failure_code," ++
            "actor_kind,actor_id,created_at,applied_at,inner_mtu,heartbeat_seconds," ++
            "suspect_seconds,offline_seconds,default_enrollment_lifetime_seconds," ++
            "traffic_cold_seconds,traffic_hot_packets_per_second," ++
            "traffic_hot_bits_per_second,traffic_saturated_queue_percent," ++
            "traffic_hysteresis_seconds,runtime_event_retention_days," ++
            "connectivity_retention_days,maximum_nodes " ++
            "FROM settings_revisions WHERE revision = 1;",
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec(
            "UPDATE settings_revisions SET id = X'05050505050505050505050505050505' " ++
                "WHERE revision = 2;",
        ),
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("DELETE FROM settings_revisions WHERE revision = 2;"),
    );

    try db.exec(
        "INSERT INTO audit_export_receipts " ++
            "(id,exported_through_sequence,entry_count,content_sha256,actor_kind,exported_at) " ++
            "VALUES (X'06060606060606060606060606060606',1,1,zeroblob(32),'local_cli',1);",
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("UPDATE audit_export_receipts SET entry_count = 2;"),
    );
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("DELETE FROM audit_export_receipts;"),
    );

    var applied = try db.prepare(
        "SELECT applied_at IS NOT NULL FROM settings_revisions WHERE revision = 1;",
    );
    defer applied.deinit();
    try std.testing.expectEqual(Step.row, try applied.step());
    try std.testing.expectEqual(@as(i64, 1), applied.columnInt64(0));
}

const TestSettingsRow = struct {
    inner_mtu: i64 = 1380,
    heartbeat_seconds: i64 = 15,
    suspect_seconds: i64 = 30,
    offline_seconds: i64 = 45,
    default_enrollment_lifetime_seconds: i64 = 86_400,
    traffic_cold_seconds: i64 = 30,
    traffic_hot_packets_per_second: i64 = 100_000,
    traffic_hot_bits_per_second: i64 = 1_000_000_000,
    traffic_saturated_queue_percent: i64 = 80,
    traffic_hysteresis_seconds: i64 = 5,
    runtime_event_retention_days: i64 = 90,
    connectivity_retention_days: i64 = 30,
    maximum_nodes: i64 = 4096,
};

fn expectSettingsConstraint(db: *Database, value: TestSettingsRow) !void {
    var insert = try db.prepare(
        "INSERT INTO settings_revisions (" ++
            "id,revision,based_on_revision,status,failure_code,actor_kind,actor_id," ++
            "created_at,applied_at,inner_mtu,heartbeat_seconds,suspect_seconds," ++
            "offline_seconds,default_enrollment_lifetime_seconds,traffic_cold_seconds," ++
            "traffic_hot_packets_per_second,traffic_hot_bits_per_second," ++
            "traffic_saturated_queue_percent,traffic_hysteresis_seconds," ++
            "runtime_event_retention_days,connectivity_retention_days,maximum_nodes" ++
            ") VALUES (X'77777777777777777777777777777777',2,1,'active',NULL," ++
            "'system',NULL,1,1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13);",
    );
    defer insert.deinit();
    inline for (std.meta.fields(TestSettingsRow), 0..) |field, index| {
        try insert.bindInt64(@intCast(index + 1), @field(value, field.name));
    }
    try std.testing.expectError(error.ConstraintViolation, insert.step());
}

test "settings schema enforces the application and OpenAPI ranges" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var db = try Database.openInitialized(path);
    defer db.close();

    try expectSettingsConstraint(&db, .{ .heartbeat_seconds = 0 });
    try expectSettingsConstraint(&db, .{
        .heartbeat_seconds = 65_534,
        .suspect_seconds = 65_535,
        .offline_seconds = 65_536,
    });
    try expectSettingsConstraint(&db, .{ .default_enrollment_lifetime_seconds = 59 });
    try expectSettingsConstraint(&db, .{ .default_enrollment_lifetime_seconds = 2_592_001 });
    try expectSettingsConstraint(&db, .{ .traffic_cold_seconds = 65_536 });
    try expectSettingsConstraint(&db, .{ .traffic_hot_packets_per_second = 4_294_967_296 });
    try expectSettingsConstraint(&db, .{ .traffic_hysteresis_seconds = 0 });
    try expectSettingsConstraint(&db, .{ .traffic_hysteresis_seconds = 3_601 });
}

fn crashWrite(path: [:0]const u8, committed: bool) noreturn {
    var db = Database.openInitialized(path) catch std.c._exit(101);
    if (committed) {
        db.exec(
            "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
                "VALUES ('committed',167772160,24,1,1,1);",
        ) catch std.c._exit(102);
    } else {
        _ = db.begin(.immediate) catch std.c._exit(103);
        db.exec(
            "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
                "VALUES ('uncommitted',167837696,24,1,1,1);",
        ) catch std.c._exit(104);
    }
    // Deliberately bypass SQLite close, Zig defers, and stdio flushing. The
    // parent must recover solely from the durable WAL protocol.
    std.c._exit(0);
}

fn runCrashWriter(path: [:0]const u8, committed: bool) !void {
    const supported = switch (builtin.os.tag) {
        .dragonfly, .freebsd, .linux, .ios, .macos, .netbsd, .openbsd => true,
        else => false,
    };
    if (comptime !supported) return error.SkipZigTest;

    const pid = std.c.fork();
    if (pid < 0) return error.ForkFailed;
    if (pid == 0) crashWrite(path, committed);
    var status: c_int = 0;
    if (std.c.waitpid(pid, &status, 0) != pid) return error.WaitFailed;
    if (status != 0) return error.CrashWriterFailed;
}

test "WAL restart preserves committed frames and discards an interrupted transaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);

    var initialized = try Database.openInitialized(path);
    initialized.close();

    try runCrashWriter(path, true);
    const committed_wal = try tmp.dir.statFile(std.testing.io, "ntip.sqlite3-wal", .{
        .follow_symlinks = false,
    });
    try std.testing.expect(committed_wal.size > 0);

    var recovered = try Database.openInitialized(path);
    try recovered.quickCheck();
    var committed_count = try recovered.prepare(
        "SELECT count(*) FROM vnrs WHERE name = 'committed';",
    );
    try std.testing.expectEqual(Step.row, try committed_count.step());
    try std.testing.expectEqual(@as(i64, 1), committed_count.columnInt64(0));
    committed_count.deinit();
    recovered.close();

    try runCrashWriter(path, false);
    var rolled_back = try Database.openInitialized(path);
    defer rolled_back.close();
    try rolled_back.integrityCheck();
    var uncommitted_count = try rolled_back.prepare(
        "SELECT count(*) FROM vnrs WHERE name = 'uncommitted';",
    );
    defer uncommitted_count.deinit();
    try std.testing.expectEqual(Step.row, try uncommitted_count.step());
    try std.testing.expectEqual(@as(i64, 0), uncommitted_count.columnInt64(0));
}
