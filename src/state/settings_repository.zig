//! Durable desired/effective settings revision state machine.
//!
//! Revision payloads never change. Status and acknowledgement timestamps may
//! transition as the runtime applies a pending snapshot. When one request
//! changes live and restart-only values together, a system-authored projection
//! records the exact live-effective snapshot while the desired revision waits
//! for restart.

const std = @import("std");
const sqlite = @import("sqlite.zig");
const settings = @import("../management/settings.zig");
const management_repository = @import("management_repository.zig");

pub const FailureCode = struct {
    len: u8,
    bytes: [128]u8,

    pub fn parse(value: []const u8) !FailureCode {
        if (value.len == 0 or value.len > 128) return error.InvalidFailureCode;
        for (value) |byte| switch (byte) {
            'a'...'z', '0'...'9', '_' => {},
            else => return error.InvalidFailureCode,
        };
        if (value[0] < 'a' or value[0] > 'z') return error.InvalidFailureCode;
        var result: FailureCode = .{ .len = @intCast(value.len), .bytes = [_]u8{0} ** 128 };
        @memcpy(result.bytes[0..value.len], value);
        return result;
    }

    pub fn slice(self: *const FailureCode) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const Revision = struct {
    id: [16]u8,
    sequence: u64,
    based_on_sequence: ?u64,
    status: settings.RevisionStatus,
    failure_code: ?FailureCode,
    actor_kind: management_repository.ActorKind,
    actor_id: ?[16]u8,
    created_at: i64,
    applied_at: ?i64,
    values: settings.OperationalSettings,
};

pub const State = struct {
    desired: Revision,
    effective: Revision,

    pub fn validate(self: State, current_node_count: usize) !void {
        // Failed desired values remain immutable history; they will not be
        // selected at startup and therefore must not constrain later
        // inventory growth or a restore. Pending values still reserve their
        // future capacity so activation can never be made impossible by a
        // subsequent Node create.
        const desired_node_count = if (self.desired.status == .failed)
            0
        else
            current_node_count;
        self.desired.values.validate(desired_node_count) catch
            return error.CorruptSettingsState;
        self.effective.values.validate(current_node_count) catch
            return error.CorruptSettingsState;
        if (self.effective.status != .active or
            self.effective.failure_code != null or
            self.effective.applied_at == null)
        {
            return error.CorruptSettingsState;
        }

        const plan = settings.classify(self.effective.values, self.desired.values);
        switch (self.desired.status) {
            .active => if (self.desired.sequence != self.effective.sequence or
                !std.meta.eql(self.desired.values, self.effective.values))
            {
                return error.CorruptSettingsState;
            },
            .pending_apply => if (self.desired.sequence == self.effective.sequence or
                !plan.live_change)
            {
                return error.CorruptSettingsState;
            },
            .pending_restart => if (self.desired.sequence == self.effective.sequence or
                plan.live_change or !plan.restart_change)
            {
                return error.CorruptSettingsState;
            },
            .failed => if (self.desired.sequence == self.effective.sequence or
                (!plan.live_change and !plan.restart_change))
            {
                return error.CorruptSettingsState;
            },
        }
    }

    pub fn pendingRestart(self: State) bool {
        return self.desired.status == .pending_restart or
            (self.desired.status == .pending_apply and
                self.desired.values.maximum_nodes != self.effective.values.maximum_nodes);
    }
};

pub const Repository = struct {
    db: *sqlite.Database,

    pub fn init(db: *sqlite.Database) Repository {
        return .{ .db = db };
    }

    pub fn loadState(self: Repository) !State {
        var pointer = try self.db.prepare(
            "SELECT desired_revision, effective_revision FROM settings_state WHERE singleton = 1;",
        );
        defer pointer.deinit();
        if (try pointer.step() != .row) return error.CorruptSettingsState;
        const desired = try positiveU64(pointer.columnInt64(0));
        const effective = try positiveU64(pointer.columnInt64(1));
        if (try pointer.step() != .done) return error.CorruptSettingsState;
        const state: State = .{
            .desired = try self.loadRevision(desired),
            .effective = try self.loadRevision(effective),
        };
        try state.validate(0);
        return state;
    }

    pub fn loadRevision(self: Repository, sequence: u64) !Revision {
        if (sequence == 0 or sequence > std.math.maxInt(i64)) return error.SettingsRevisionNotFound;
        var statement = try self.db.prepare(
            "SELECT id, revision, based_on_revision, status, failure_code, " ++
                "actor_kind, actor_id, created_at, applied_at, " ++
                "inner_mtu, heartbeat_seconds, suspect_seconds, offline_seconds, " ++
                "default_enrollment_lifetime_seconds, maximum_nodes, " ++
                "traffic_cold_seconds, traffic_hot_packets_per_second, " ++
                "traffic_hot_bits_per_second, traffic_saturated_queue_percent, " ++
                "traffic_hysteresis_seconds, runtime_event_retention_days, " ++
                "connectivity_retention_days " ++
                "FROM settings_revisions WHERE revision = ?1;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, sequence);
        if (try statement.step() != .row) return error.SettingsRevisionNotFound;
        const revision = try decodeRevision(&statement);
        if (try statement.step() != .done) return error.CorruptSettingsState;
        revision.values.validate(0) catch return error.CorruptSettingsState;
        return revision;
    }

    pub fn createRevision(
        self: Repository,
        id: [16]u8,
        desired_values: settings.OperationalSettings,
        current_node_count: usize,
        expected_desired_sequence: u64,
        now: i64,
        actor_kind: management_repository.ActorKind,
        actor_id: ?[16]u8,
        audit: management_repository.AuditEntry,
    ) !Revision {
        return self.createRevisionInternal(
            id,
            desired_values,
            current_node_count,
            expected_desired_sequence,
            now,
            actor_kind,
            actor_id,
            audit,
            false,
        );
    }

    /// Rollback always records a new immutable audited revision, including
    /// when the selected historical values already equal the effective
    /// runtime after a failed application.
    pub fn createRollbackRevision(
        self: Repository,
        id: [16]u8,
        desired_values: settings.OperationalSettings,
        current_node_count: usize,
        expected_desired_sequence: u64,
        now: i64,
        actor_kind: management_repository.ActorKind,
        actor_id: ?[16]u8,
        audit: management_repository.AuditEntry,
    ) !Revision {
        return self.createRevisionInternal(
            id,
            desired_values,
            current_node_count,
            expected_desired_sequence,
            now,
            actor_kind,
            actor_id,
            audit,
            true,
        );
    }

    fn createRevisionInternal(
        self: Repository,
        id: [16]u8,
        desired_values: settings.OperationalSettings,
        current_node_count: usize,
        expected_desired_sequence: u64,
        now: i64,
        actor_kind: management_repository.ActorKind,
        actor_id: ?[16]u8,
        audit: management_repository.AuditEntry,
        allow_unchanged: bool,
    ) !Revision {
        if (now < 0 or allZero(&id)) return error.InvalidSettingsRevision;
        try desired_values.validate(current_node_count);
        // SQLite INTEGER and OpenAPI `int64` are signed. The domain model uses
        // u64 so traffic counters can remain naturally unsigned, but a value
        // outside the durable representation must fail instead of trapping in
        // the generic @intCast used by the prepared-statement binder.
        if (desired_values.traffic_hot_bits_per_second > std.math.maxInt(i64)) {
            return error.InvalidSettings;
        }
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        const current = try self.loadState();
        if (current.desired.sequence != expected_desired_sequence) return error.PreconditionFailed;
        if (current.desired.status == .pending_apply) return error.SettingsApplicationInProgress;
        // A failed or restart-pending revision may differ from the effective
        // runtime snapshot. Always classify a new immutable snapshot against
        // what the runtime actually uses so every outstanding live delta is
        // applied before the new revision can become effective.
        const plan = settings.classify(current.effective.values, desired_values);
        const unchanged = !plan.live_change and !plan.restart_change;
        if (unchanged and !allow_unchanged) return error.NoSettingsChanges;
        const sequence = try self.nextSequence();
        const revision: Revision = .{
            .id = id,
            .sequence = sequence,
            .based_on_sequence = current.desired.sequence,
            .status = plan.initialStatus(),
            .failure_code = null,
            .actor_kind = actor_kind,
            .actor_id = actor_id,
            .created_at = now,
            .applied_at = if (unchanged) now else null,
            .values = desired_values,
        };
        try self.insertRevision(revision);
        try self.updateDesired(sequence);
        if (unchanged) try self.updateEffective(sequence);
        try self.insertAudit(audit);
        try transaction.commit();
        return revision;
    }

    /// Durable runtime acknowledgement. `projection_id` is used only when a
    /// mixed live/restart revision needs an exact effective snapshot.
    pub fn acknowledgeApplied(
        self: Repository,
        desired_sequence: u64,
        projection_id: [16]u8,
        now: i64,
        audit: management_repository.AuditEntry,
    ) !State {
        if (now < 0) return error.InvalidTimestamp;
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        const current = try self.loadState();
        if (current.desired.sequence != desired_sequence or current.desired.status != .pending_apply) {
            return error.SettingsAcknowledgementMismatch;
        }
        const plan = settings.classify(current.effective.values, current.desired.values);
        if (!plan.live_change) return error.SettingsAcknowledgementMismatch;

        if (plan.restart_change) {
            if (allZero(&projection_id)) return error.InvalidSettingsRevision;
            const projection: Revision = .{
                .id = projection_id,
                .sequence = try self.nextSequence(),
                .based_on_sequence = current.desired.sequence,
                .status = .active,
                .failure_code = null,
                .actor_kind = .system,
                .actor_id = null,
                .created_at = now,
                .applied_at = now,
                .values = settings.liveProjection(current.desired.values, current.effective.values),
            };
            try self.insertRevision(projection);
            try self.updateStatus(current.desired.sequence, .pending_restart, null, now);
            try self.updateEffective(projection.sequence);
        } else {
            try self.updateStatus(current.desired.sequence, .active, null, now);
            try self.updateEffective(current.desired.sequence);
        }
        // Settings and inventory share one durable configuration generation.
        // The Node publisher observes this generation only after the settings
        // acknowledgement transaction commits, so it can never serialize a
        // desired-but-not-effective settings snapshot.
        _ = try self.advanceDurableGeneration();
        try self.insertAudit(audit);
        try transaction.commit();
        return self.loadState();
    }

    pub fn acknowledgeFailed(
        self: Repository,
        desired_sequence: u64,
        failure: FailureCode,
        now: i64,
        audit: management_repository.AuditEntry,
    ) !State {
        if (now < 0) return error.InvalidTimestamp;
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        const current = try self.loadState();
        if (current.desired.sequence != desired_sequence or current.desired.status != .pending_apply) {
            return error.SettingsAcknowledgementMismatch;
        }
        try self.updateStatus(desired_sequence, .failed, failure.slice(), null);
        try self.insertAudit(audit);
        try transaction.commit();
        return self.loadState();
    }

    /// Called during startup after the restart-required capacity has actually
    /// been used to construct bounded runtime tables.
    pub fn activateAfterRestart(
        self: Repository,
        desired_sequence: u64,
        now: i64,
        audit: management_repository.AuditEntry,
    ) !State {
        if (now < 0) return error.InvalidTimestamp;
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        const current = try self.loadState();
        if (current.desired.sequence != desired_sequence or current.desired.status != .pending_restart) {
            return error.SettingsAcknowledgementMismatch;
        }
        try self.updateStatus(desired_sequence, .active, null, now);
        try self.updateEffective(desired_sequence);
        // Restart activation changes the effective runtime projection just as
        // a live acknowledgement does. Advance the shared generation in this
        // transaction before notifying observers so startup cannot present an
        // already-captured generation as a newly committed snapshot.
        _ = try self.advanceDurableGeneration();
        try self.insertAudit(audit);
        try transaction.commit();
        return self.loadState();
    }

    fn nextSequence(self: Repository) !u64 {
        var statement = try self.db.prepare("SELECT coalesce(max(revision), 0) + 1 FROM settings_revisions;");
        defer statement.deinit();
        if (try statement.step() != .row) return error.CorruptSettingsState;
        const sequence = try positiveU64(statement.columnInt64(0));
        if (try statement.step() != .done) return error.CorruptSettingsState;
        return sequence;
    }

    fn advanceDurableGeneration(self: Repository) !u64 {
        var read = try self.db.prepare(
            "SELECT durable_generation FROM master_state WHERE singleton = 1;",
        );
        defer read.deinit();
        if (try read.step() != .row) return error.CorruptSettingsState;
        const raw = read.columnInt64(0);
        if (raw < 0 or raw == std.math.maxInt(i64)) return error.GenerationOverflow;
        if (try read.step() != .done) return error.CorruptSettingsState;
        const next = raw + 1;

        var write = try self.db.prepare(
            "UPDATE master_state SET durable_generation = ?1 " ++
                "WHERE singleton = 1 AND durable_generation = ?2;",
        );
        defer write.deinit();
        try write.bindInt64(1, next);
        try write.bindInt64(2, raw);
        if (try write.step() != .done or self.db.changes() != 1) {
            return error.SettingsAcknowledgementMismatch;
        }
        return @intCast(next);
    }

    fn insertRevision(self: Repository, revision: Revision) !void {
        var statement = try self.db.prepare(
            "INSERT INTO settings_revisions (" ++
                "id, revision, based_on_revision, status, failure_code, actor_kind, actor_id, " ++
                "created_at, applied_at, inner_mtu, heartbeat_seconds, suspect_seconds, offline_seconds, " ++
                "default_enrollment_lifetime_seconds, maximum_nodes, traffic_cold_seconds, " ++
                "traffic_hot_packets_per_second, traffic_hot_bits_per_second, " ++
                "traffic_saturated_queue_percent, traffic_hysteresis_seconds, " ++
                "runtime_event_retention_days, connectivity_retention_days) VALUES (" ++
                "?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &revision.id);
        try statement.bindInt64(2, revision.sequence);
        if (revision.based_on_sequence) |value| try statement.bindInt64(3, value) else try statement.bindNull(3);
        try statement.bindText(4, @tagName(revision.status));
        if (revision.failure_code) |failure| try statement.bindText(5, failure.slice()) else try statement.bindNull(5);
        try statement.bindText(6, actorText(revision.actor_kind));
        if (revision.actor_id) |actor_id| try statement.bindBlob(7, &actor_id) else try statement.bindNull(7);
        try statement.bindInt64(8, revision.created_at);
        if (revision.applied_at) |value| try statement.bindInt64(9, value) else try statement.bindNull(9);
        try bindSettings(&statement, 10, revision.values);
        const step = statement.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidSettingsRevision,
            else => err,
        };
        if (step != .done) return error.UnexpectedRow;
    }

    fn updateDesired(self: Repository, sequence: u64) !void {
        var statement = try self.db.prepare("UPDATE settings_state SET desired_revision = ?1 WHERE singleton = 1;");
        defer statement.deinit();
        try statement.bindInt64(1, sequence);
        if (try statement.step() != .done or self.db.changes() != 1) return error.CorruptSettingsState;
    }

    fn updateEffective(self: Repository, sequence: u64) !void {
        var statement = try self.db.prepare("UPDATE settings_state SET effective_revision = ?1 WHERE singleton = 1;");
        defer statement.deinit();
        try statement.bindInt64(1, sequence);
        if (try statement.step() != .done or self.db.changes() != 1) return error.CorruptSettingsState;
    }

    fn updateStatus(
        self: Repository,
        sequence: u64,
        status: settings.RevisionStatus,
        failure_code: ?[]const u8,
        applied_at: ?i64,
    ) !void {
        var statement = try self.db.prepare(
            "UPDATE settings_revisions SET status = ?1, failure_code = ?2, applied_at = ?3 WHERE revision = ?4;",
        );
        defer statement.deinit();
        try statement.bindText(1, @tagName(status));
        if (failure_code) |value| try statement.bindText(2, value) else try statement.bindNull(2);
        if (applied_at) |value| try statement.bindInt64(3, value) else try statement.bindNull(3);
        try statement.bindInt64(4, sequence);
        if (try statement.step() != .done or self.db.changes() != 1) return error.SettingsRevisionNotFound;
    }

    fn insertAudit(self: Repository, audit: management_repository.AuditEntry) !void {
        if (audit.occurred_at < 0) return error.InvalidAuditEntry;
        if (audit.actor_kind == .web) self.db.armCommitHook();
        var statement = try self.db.prepare(
            "INSERT INTO audit_entries " ++
                "(id,occurred_at,actor_kind,actor_id,action,resource_type,resource_id,request_id,details_json) " ++
                "VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &audit.id);
        try statement.bindInt64(2, audit.occurred_at);
        try statement.bindText(3, actorText(audit.actor_kind));
        if (audit.actor_id) |actor_id| try statement.bindBlob(4, &actor_id) else try statement.bindNull(4);
        try statement.bindText(5, audit.action);
        try statement.bindText(6, audit.resource_type);
        try statement.bindText(7, audit.resource_id);
        if (audit.request_id) |request_id| try statement.bindBlob(8, &request_id) else try statement.bindNull(8);
        try statement.bindText(9, audit.details_json);
        const step = statement.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        if (step != .done) return error.UnexpectedRow;
    }
};

fn decodeRevision(statement: *const sqlite.Statement) !Revision {
    const id_blob = statement.columnBlob(0) orelse return error.CorruptSettingsState;
    if (id_blob.len != 16) return error.CorruptSettingsState;
    var id: [16]u8 = undefined;
    @memcpy(&id, id_blob);
    const sequence = try positiveU64(statement.columnInt64(1));
    const based_on = if (statement.columnIsNull(2)) null else try positiveU64(statement.columnInt64(2));
    const status_text = statement.columnText(3) orelse return error.CorruptSettingsState;
    const status = std.meta.stringToEnum(settings.RevisionStatus, status_text) orelse return error.CorruptSettingsState;
    const failure = if (statement.columnText(4)) |value| try FailureCode.parse(value) else null;
    const actor = try parseActor(statement.columnText(5) orelse return error.CorruptSettingsState);
    var actor_id: ?[16]u8 = null;
    if (statement.columnBlob(6)) |value| {
        if (value.len != 16) return error.CorruptSettingsState;
        var copied: [16]u8 = undefined;
        @memcpy(&copied, value);
        actor_id = copied;
    }
    const created_at = statement.columnInt64(7);
    if (created_at < 0) return error.CorruptSettingsState;
    const applied_at = if (statement.columnIsNull(8)) null else statement.columnInt64(8);
    return .{
        .id = id,
        .sequence = sequence,
        .based_on_sequence = based_on,
        .status = status,
        .failure_code = failure,
        .actor_kind = actor,
        .actor_id = actor_id,
        .created_at = created_at,
        .applied_at = applied_at,
        .values = try decodeSettings(statement, 9),
    };
}

fn decodeSettings(statement: *const sqlite.Statement, first: c_int) !settings.OperationalSettings {
    return .{
        .inner_mtu = try unsignedColumn(u16, statement, first),
        .heartbeat_idle_seconds = try unsignedColumn(u16, statement, first + 1),
        .suspect_after_seconds = try unsignedColumn(u16, statement, first + 2),
        .offline_after_seconds = try unsignedColumn(u16, statement, first + 3),
        .default_enrollment_lifetime_seconds = try unsignedColumn(u32, statement, first + 4),
        .maximum_nodes = try unsignedColumn(u32, statement, first + 5),
        .traffic_cold_after_seconds = try unsignedColumn(u32, statement, first + 6),
        .traffic_hot_packets_per_second = try unsignedColumn(u64, statement, first + 7),
        .traffic_hot_bits_per_second = try unsignedColumn(u64, statement, first + 8),
        .traffic_saturated_queue_percent = try unsignedColumn(u8, statement, first + 9),
        .traffic_hysteresis_seconds = try unsignedColumn(u32, statement, first + 10),
        .runtime_event_retention_days = try unsignedColumn(u16, statement, first + 11),
        .connectivity_result_retention_days = try unsignedColumn(u16, statement, first + 12),
    };
}

fn bindSettings(statement: *sqlite.Statement, first: c_int, value: settings.OperationalSettings) !void {
    try statement.bindInt64(first, value.inner_mtu);
    try statement.bindInt64(first + 1, value.heartbeat_idle_seconds);
    try statement.bindInt64(first + 2, value.suspect_after_seconds);
    try statement.bindInt64(first + 3, value.offline_after_seconds);
    try statement.bindInt64(first + 4, value.default_enrollment_lifetime_seconds);
    try statement.bindInt64(first + 5, value.maximum_nodes);
    try statement.bindInt64(first + 6, value.traffic_cold_after_seconds);
    try statement.bindInt64(first + 7, value.traffic_hot_packets_per_second);
    try statement.bindInt64(first + 8, value.traffic_hot_bits_per_second);
    try statement.bindInt64(first + 9, value.traffic_saturated_queue_percent);
    try statement.bindInt64(first + 10, value.traffic_hysteresis_seconds);
    try statement.bindInt64(first + 11, value.runtime_event_retention_days);
    try statement.bindInt64(first + 12, value.connectivity_result_retention_days);
}

fn positiveU64(value: i64) !u64 {
    if (value <= 0) return error.CorruptSettingsState;
    return @intCast(value);
}

fn unsignedColumn(comptime T: type, statement: *const sqlite.Statement, index: c_int) !T {
    const value = statement.columnInt64(index);
    if (value < 0 or @as(u64, @intCast(value)) > std.math.maxInt(T)) return error.CorruptSettingsState;
    return @intCast(value);
}

fn actorText(actor: management_repository.ActorKind) []const u8 {
    return switch (actor) {
        .local_cli => "local_cli",
        .web => "web",
        .system => "system",
    };
}

fn parseActor(value: []const u8) !management_repository.ActorKind {
    if (std.mem.eql(u8, value, "local_cli")) return .local_cli;
    if (std.mem.eql(u8, value, "web")) return .web;
    if (std.mem.eql(u8, value, "system")) return .system;
    return error.CorruptSettingsState;
}

fn allZero(bytes: []const u8) bool {
    var accumulator: u8 = 0;
    for (bytes) |byte| accumulator |= byte;
    return accumulator == 0;
}

fn testPath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testAudit(id: u8, now: i64, action: []const u8) management_repository.AuditEntry {
    return .{
        .id = [_]u8{id} ** 16,
        .occurred_at = now,
        .actor_kind = .system,
        .action = action,
        .resource_type = "settings",
    };
}

test "default desired and effective settings load from migration" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const state = try repository.loadState();
    try std.testing.expectEqual(@as(u64, 1), state.desired.sequence);
    try std.testing.expectEqual(@as(u16, 1380), state.effective.values.inner_mtu);
    try std.testing.expect(!state.pendingRestart());
}

test "settings state rejects pending capacity overflow but ignores failed desired capacity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const initial = try repository.loadState();
    try initial.validate(0);

    var split_active = initial;
    split_active.desired.sequence += 1;
    try std.testing.expectError(error.CorruptSettingsState, split_active.validate(0));

    var false_restart = initial;
    false_restart.desired.sequence += 1;
    false_restart.desired.status = .pending_restart;
    false_restart.desired.applied_at = null;
    try std.testing.expectError(error.CorruptSettingsState, false_restart.validate(0));

    var undersized = initial;
    undersized.desired.values.maximum_nodes = 1;
    undersized.effective.values.maximum_nodes = 1;
    try std.testing.expectError(error.CorruptSettingsState, undersized.validate(2));

    var pending_reduction = initial;
    pending_reduction.desired.sequence += 1;
    pending_reduction.desired.status = .pending_restart;
    pending_reduction.desired.applied_at = null;
    pending_reduction.desired.values.maximum_nodes = 1;
    try std.testing.expectError(
        error.CorruptSettingsState,
        pending_reduction.validate(2),
    );

    var failed_reduction = pending_reduction;
    failed_reduction.desired.status = .failed;
    failed_reduction.desired.failure_code = try FailureCode.parse("runtime_apply_failed");
    // The failed desired snapshot is immutable history. Restored inventory is
    // constrained by the effective capacity that startup will actually use.
    try failed_reduction.validate(2);
    try std.testing.expect(!failed_reduction.pendingRestart());
}

test "live revision becomes effective only after durable acknowledgement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    var desired = settings.OperationalSettings{};
    desired.inner_mtu = 1400;
    const pending = try repository.createRevision(.{2} ** 16, desired, 0, 1, 10, .web, .{9} ** 16, testAudit(2, 10, "settings.update"));
    try std.testing.expectEqual(settings.RevisionStatus.pending_apply, pending.status);
    try std.testing.expectEqual(@as(u16, 1380), (try repository.loadState()).effective.values.inner_mtu);
    var superseding = desired;
    superseding.inner_mtu = 1420;
    try std.testing.expectError(
        error.SettingsApplicationInProgress,
        repository.createRevision(.{4} ** 16, superseding, 0, pending.sequence, 10, .web, .{9} ** 16, testAudit(4, 10, "settings.update")),
    );

    const applied = try repository.acknowledgeApplied(pending.sequence, [_]u8{0} ** 16, 11, testAudit(3, 11, "settings.applied"));
    try std.testing.expectEqual(@as(u16, 1400), applied.effective.values.inner_mtu);
    try std.testing.expectEqual(settings.RevisionStatus.active, applied.desired.status);
    try std.testing.expectEqual(@as(u64, 1), try management_repository.Repository.init(&db).durableGeneration());
}

test "mixed revision records exact live projection then activates after restart" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    var desired = settings.OperationalSettings{};
    desired.inner_mtu = 1420;
    desired.maximum_nodes = 8192;
    const pending = try repository.createRevision(.{4} ** 16, desired, 0, 1, 20, .web, .{8} ** 16, testAudit(4, 20, "settings.update"));
    const projected = try repository.acknowledgeApplied(pending.sequence, .{5} ** 16, 21, testAudit(5, 21, "settings.applied"));
    try std.testing.expect(projected.pendingRestart());
    try std.testing.expectEqual(@as(u16, 1420), projected.effective.values.inner_mtu);
    try std.testing.expectEqual(@as(u32, 4096), projected.effective.values.maximum_nodes);
    try std.testing.expectEqual(settings.RevisionStatus.pending_restart, projected.desired.status);

    const restarted = try repository.activateAfterRestart(pending.sequence, 22, testAudit(6, 22, "settings.restart_applied"));
    try std.testing.expect(!restarted.pendingRestart());
    try std.testing.expectEqual(@as(u32, 8192), restarted.effective.values.maximum_nodes);
    try std.testing.expectEqual(
        @as(u64, 2),
        try management_repository.Repository.init(&db).durableGeneration(),
    );
}

test "failed live application keeps the prior effective revision" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    var desired = settings.OperationalSettings{};
    desired.inner_mtu = 1500;
    const pending = try repository.createRevision(.{7} ** 16, desired, 0, 1, 30, .web, null, testAudit(7, 30, "settings.update"));
    const failure = try FailureCode.parse("mtu_apply_failed");
    const failed = try repository.acknowledgeFailed(pending.sequence, failure, 31, testAudit(8, 31, "settings.failed"));
    try std.testing.expectEqual(settings.RevisionStatus.failed, failed.desired.status);
    try std.testing.expectEqual(@as(u16, 1380), failed.effective.values.inner_mtu);
    try std.testing.expectEqualStrings("mtu_apply_failed", failed.desired.failure_code.?.slice());

    const rolled_back = try repository.createRollbackRevision(
        .{9} ** 16,
        .{},
        0,
        pending.sequence,
        32,
        .web,
        null,
        testAudit(9, 32, "settings.rollback"),
    );
    try std.testing.expectEqual(settings.RevisionStatus.active, rolled_back.status);
    const rollback_state = try repository.loadState();
    try std.testing.expectEqual(rolled_back.sequence, rollback_state.desired.sequence);
    try std.testing.expectEqual(rolled_back.sequence, rollback_state.effective.sequence);
}

test "settings payload trigger rejects mutation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    try std.testing.expectError(
        error.ConstraintViolation,
        db.exec("UPDATE settings_revisions SET inner_mtu = 1400 WHERE revision = 1;"),
    );
}

test "settings reject values outside SQLite int64 without trapping" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    var desired = settings.OperationalSettings{};
    desired.traffic_hot_bits_per_second = std.math.maxInt(u64);
    try std.testing.expectError(
        error.InvalidSettings,
        repository.createRevision(
            .{2} ** 16,
            desired,
            0,
            1,
            10,
            .web,
            .{9} ** 16,
            testAudit(2, 10, "settings.update"),
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), (try repository.loadState()).desired.sequence);
}

test "settings pointers status generation and audit commit atomically" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testPath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    try db.exec(
        "INSERT INTO audit_entries " ++
            "(id,occurred_at,actor_kind,action,resource_type) VALUES " ++
            "(X'28282828282828282828282828282828',9,'system','seed','settings');",
    );
    var desired = settings.OperationalSettings{};
    desired.inner_mtu = 1400;

    // The duplicate audit ID fails after the revision and desired pointer have
    // been written inside the transaction. Neither may leak through rollback.
    try std.testing.expectError(
        error.InvalidAuditEntry,
        repository.createRevision(
            .{2} ** 16,
            desired,
            0,
            1,
            10,
            .web,
            .{9} ** 16,
            testAudit(40, 10, "settings.update"),
        ),
    );
    const unchanged = try repository.loadState();
    try std.testing.expectEqual(@as(u64, 1), unchanged.desired.sequence);
    try std.testing.expectEqual(@as(u64, 1), unchanged.effective.sequence);
    try std.testing.expectError(error.SettingsRevisionNotFound, repository.loadRevision(2));

    const pending = try repository.createRevision(
        .{2} ** 16,
        desired,
        0,
        1,
        11,
        .web,
        .{9} ** 16,
        testAudit(41, 11, "settings.update"),
    );
    // Reusing the create audit ID forces the acknowledgement's final write to
    // fail. Effective state, status, and shared generation must all remain at
    // their pre-acknowledgement values.
    try std.testing.expectError(
        error.InvalidAuditEntry,
        repository.acknowledgeApplied(
            pending.sequence,
            [_]u8{0} ** 16,
            12,
            testAudit(41, 12, "settings.applied"),
        ),
    );
    const still_pending = try repository.loadState();
    try std.testing.expectEqual(settings.RevisionStatus.pending_apply, still_pending.desired.status);
    try std.testing.expectEqual(@as(u64, 1), still_pending.effective.sequence);
    try std.testing.expectEqual(
        @as(u64, 0),
        try management_repository.Repository.init(&db).durableGeneration(),
    );

    _ = try repository.acknowledgeApplied(
        pending.sequence,
        [_]u8{0} ** 16,
        13,
        testAudit(42, 13, "settings.applied"),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        try management_repository.Repository.init(&db).durableGeneration(),
    );

    var restart_values = (try repository.loadState()).effective.values;
    restart_values.maximum_nodes = 8192;
    const pending_restart = try repository.createRevision(
        .{43} ** 16,
        restart_values,
        0,
        pending.sequence,
        14,
        .web,
        .{9} ** 16,
        testAudit(43, 14, "settings.update"),
    );
    try std.testing.expectEqual(settings.RevisionStatus.pending_restart, pending_restart.status);

    // Restart activation advances status, the effective pointer, and the
    // shared durable generation before its final audit insert. A duplicate
    // audit ID must roll all three changes back together.
    try std.testing.expectError(
        error.InvalidAuditEntry,
        repository.activateAfterRestart(
            pending_restart.sequence,
            15,
            testAudit(43, 15, "settings.restart_applied"),
        ),
    );
    const still_waiting_for_restart = try repository.loadState();
    try std.testing.expectEqual(
        settings.RevisionStatus.pending_restart,
        still_waiting_for_restart.desired.status,
    );
    try std.testing.expectEqual(pending.sequence, still_waiting_for_restart.effective.sequence);
    try std.testing.expectEqual(
        @as(u64, 1),
        try management_repository.Repository.init(&db).durableGeneration(),
    );

    const restarted = try repository.activateAfterRestart(
        pending_restart.sequence,
        16,
        testAudit(44, 16, "settings.restart_applied"),
    );
    try std.testing.expectEqual(pending_restart.sequence, restarted.effective.sequence);
    try std.testing.expectEqual(
        @as(u64, 2),
        try management_repository.Repository.init(&db).durableGeneration(),
    );
}
