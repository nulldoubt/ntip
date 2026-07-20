//! Durable operations repository for audit, runtime transitions, and
//! Master-originated connectivity checks.
//!
//! The serialized operator worker is the sole caller in production. Every
//! application value is bound through a prepared statement. Audit pruning is
//! intentionally narrower than the schema permits: callers can delete only a
//! sequence prefix covered by an exact, previously committed export receipt,
//! and must also prove both recent password reauthentication and typed
//! confirmation at this defense-in-depth boundary.

const std = @import("std");
const security_policy = @import("../management/security_policy.zig");
const management_repository = @import("management_repository.zig");
const sqlite = @import("sqlite.zig");

pub const default_page_size: u16 = 50;
pub const maximum_page_size: u16 = 200;
pub const default_runtime_retention_days: u16 = 90;
pub const default_connectivity_retention_days: u16 = 30;
pub const default_retention_batch_size: u16 = 1000;
pub const minimum_check_timeout_ms: u16 = 500;
pub const maximum_check_timeout_ms: u16 = 10_000;

const seconds_per_day: i64 = 24 * 60 * 60;

pub const ActorKind = management_repository.ActorKind;
pub const AuditEntry = management_repository.AuditEntry;

pub const AuditCursor = struct {
    /// Listing is newest-first. The next page contains sequences strictly
    /// lower than this value.
    before_sequence: u64,
};

pub const RuntimeEventCursor = struct {
    /// Stable newest-first composite cursor. IDs break timestamp ties.
    observed_at: i64,
    before_id: [16]u8,
};

pub const ConnectivityCheckCursor = struct {
    /// Stable newest-first composite cursor. IDs break timestamp ties.
    requested_at: i64,
    before_id: [16]u8,
};

pub const EventSeverity = enum {
    info,
    warning,
    @"error",
};

pub const ConnectivityStatus = enum {
    queued,
    running,
    succeeded,
    failed,
    timed_out,
    interrupted,

    pub fn isTerminal(self: ConnectivityStatus) bool {
        return switch (self) {
            .queued, .running => false,
            .succeeded, .failed, .timed_out, .interrupted => true,
        };
    }
};

pub const AuditRecord = struct {
    sequence: u64,
    id: [16]u8,
    occurred_at: i64,
    actor_kind: ActorKind,
    actor_id: ?[16]u8,
    action: []u8,
    resource_type: []u8,
    resource_id: []u8,
    request_id: ?[16]u8,
    details_json: []u8,

    pub fn deinit(self: *AuditRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.action);
        allocator.free(self.resource_type);
        allocator.free(self.resource_id);
        allocator.free(self.details_json);
        self.* = undefined;
    }
};

/// A borrowed projection suitable for role-aware serialization. Viewer audit
/// access retains the operational action/resource trail but never exposes
/// actor identifiers, request correlation IDs, or unstructured details.
pub const AuditView = struct {
    sequence: u64,
    id: [16]u8,
    occurred_at: i64,
    actor_kind: ActorKind,
    actor_id: ?[16]u8,
    action: []const u8,
    resource_type: []const u8,
    resource_id: []const u8,
    request_id: ?[16]u8,
    details_json: []const u8,
    redacted: bool,
};

pub fn fullAuditView(record: *const AuditRecord) AuditView {
    return .{
        .sequence = record.sequence,
        .id = record.id,
        .occurred_at = record.occurred_at,
        .actor_kind = record.actor_kind,
        .actor_id = record.actor_id,
        .action = record.action,
        .resource_type = record.resource_type,
        .resource_id = record.resource_id,
        .request_id = record.request_id,
        .details_json = record.details_json,
        .redacted = false,
    };
}

pub fn viewerAuditView(record: *const AuditRecord) AuditView {
    return .{
        .sequence = record.sequence,
        .id = record.id,
        .occurred_at = record.occurred_at,
        .actor_kind = record.actor_kind,
        .actor_id = null,
        .action = record.action,
        .resource_type = record.resource_type,
        .resource_id = record.resource_id,
        .request_id = null,
        .details_json = "{\"redacted\":true}",
        .redacted = true,
    };
}

pub const AuditPage = struct {
    items: []AuditRecord,
    next_cursor: ?AuditCursor,

    pub fn deinit(self: *AuditPage, allocator: std.mem.Allocator) void {
        for (self.items) |*item| item.deinit(allocator);
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const RuntimeEventInput = struct {
    id: [16]u8,
    kind: []const u8,
    severity: EventSeverity,
    node_id: ?[16]u8 = null,
    observed_at: i64,
    details_json: []const u8 = "{}",
};

pub const RuntimeEventRecord = struct {
    id: [16]u8,
    kind: []u8,
    severity: EventSeverity,
    node_id: ?[16]u8,
    observed_at: i64,
    details_json: []u8,

    pub fn deinit(self: *RuntimeEventRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.kind);
        allocator.free(self.details_json);
        self.* = undefined;
    }
};

pub const RuntimeEventPage = struct {
    items: []RuntimeEventRecord,
    next_cursor: ?RuntimeEventCursor,

    pub fn deinit(self: *RuntimeEventPage, allocator: std.mem.Allocator) void {
        for (self.items) |*item| item.deinit(allocator);
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const ConnectivityCheckInput = struct {
    id: [16]u8,
    node_id: [16]u8,
    node_name: []const u8,
    requested_by_kind: ActorKind,
    requested_by_id: ?[16]u8,
    timeout_ms: u16 = 3_000,
    requested_at: i64,
};

pub const ConnectivityCheckRecord = struct {
    id: [16]u8,
    node_id: ?[16]u8,
    node_name: []u8,
    requested_by_kind: ActorKind,
    requested_by_id: ?[16]u8,
    status: ConnectivityStatus,
    timeout_ms: u16,
    requested_at: i64,
    started_at: ?i64,
    completed_at: ?i64,
    rtt_microseconds: ?u64,
    error_code: ?[]u8,

    pub fn deinit(self: *ConnectivityCheckRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.node_name);
        if (self.error_code) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const ConnectivityCheckPage = struct {
    items: []ConnectivityCheckRecord,
    next_cursor: ?ConnectivityCheckCursor,

    pub fn deinit(self: *ConnectivityCheckPage, allocator: std.mem.Allocator) void {
        for (self.items) |*item| item.deinit(allocator);
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const ExportReceipt = struct {
    id: [16]u8,
    exported_through_sequence: u64,
    entry_count: u64,
    content_sha256: [32]u8,
    actor_kind: ActorKind,
    actor_id: ?[16]u8,
    exported_at: i64,
};

/// Hashes the exact canonical bytes written to an export stream while
/// recording the database sequence/count proof committed after the stream
/// closes successfully. Entries must be supplied in increasing sequence.
pub const ExportAccumulator = struct {
    hasher: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    entry_count: u64 = 0,
    through_sequence: u64 = 0,

    pub fn appendEntry(self: *ExportAccumulator, sequence: u64, canonical_bytes: []const u8) !void {
        if (sequence == 0 or sequence <= self.through_sequence) return error.NonMonotonicExport;
        self.hasher.update(canonical_bytes);
        self.entry_count = std.math.add(u64, self.entry_count, 1) catch return error.ExportTooLarge;
        self.through_sequence = sequence;
    }

    pub fn finish(
        self: *ExportAccumulator,
        id: [16]u8,
        actor_kind: ActorKind,
        actor_id: ?[16]u8,
        exported_at: i64,
    ) !ExportReceipt {
        if (self.entry_count == 0 or self.through_sequence == 0) return error.EmptyExport;
        var digest: [32]u8 = undefined;
        self.hasher.final(&digest);
        return .{
            .id = id,
            .exported_through_sequence = self.through_sequence,
            .entry_count = self.entry_count,
            .content_sha256 = digest,
            .actor_kind = actor_kind,
            .actor_id = actor_id,
            .exported_at = exported_at,
        };
    }
};

pub const AuditPruneRequest = struct {
    /// Exact receipt metadata copied from the export response. Supplying only
    /// a receipt ID is deliberately insufficient at this boundary.
    receipt: ExportReceipt,
    prune_through_sequence: u64,
    recent_reauthentication: bool,
    typed_confirmation_matches: bool,
};

pub const Repository = struct {
    db: *sqlite.Database,

    pub fn init(db: *sqlite.Database) Repository {
        return .{ .db = db };
    }

    pub fn appendAudit(self: Repository, audit: AuditEntry) !u64 {
        if (self.db.inTransaction()) {
            try insertAudit(self.db, audit);
            return lastInsertSequence(self.db);
        }
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try insertAudit(self.db, audit);
        const sequence = try lastInsertSequence(self.db);
        try transaction.commit();
        return sequence;
    }

    pub fn listAudit(
        self: Repository,
        allocator: std.mem.Allocator,
        cursor: ?AuditCursor,
        requested_limit: u16,
    ) !AuditPage {
        const limit = try pageLimit(requested_limit);
        var statement = try self.db.prepare(
            "SELECT sequence,id,occurred_at,actor_kind,actor_id,action," ++
                "resource_type,resource_id,request_id,details_json " ++
                "FROM audit_entries " ++
                "WHERE (?1 = 0 OR sequence < ?2) " ++
                "ORDER BY sequence DESC LIMIT ?3;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, @intFromBool(cursor != null));
        if (cursor) |value| {
            if (value.before_sequence == 0 or value.before_sequence > std.math.maxInt(i64)) {
                return error.InvalidCursor;
            }
            try statement.bindInt64(2, value.before_sequence);
        } else {
            try statement.bindInt64(2, 0);
        }
        try statement.bindInt64(3, @as(u32, limit) + 1);

        var items: std.ArrayListUnmanaged(AuditRecord) = .empty;
        errdefer deinitAuditList(&items, allocator);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            try items.append(allocator, try decodeAudit(allocator, &statement));
        }
        const next_cursor: ?AuditCursor = if (saw_more)
            .{ .before_sequence = items.items[items.items.len - 1].sequence }
        else
            null;
        return .{ .items = try items.toOwnedSlice(allocator), .next_cursor = next_cursor };
    }

    /// Commits proof only after the caller's streaming writer has completed.
    /// Count and cutoff are checked against the immutable prefix visible in
    /// this transaction; the receipt and its audit row commit together.
    pub fn commitExportReceipt(
        self: Repository,
        receipt: ExportReceipt,
        audit: AuditEntry,
    ) !void {
        try validateReceipt(receipt);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        const actual_count = try auditCountThrough(self.db, receipt.exported_through_sequence);
        if (actual_count == 0 or actual_count != receipt.entry_count) return error.ExportSnapshotMismatch;
        if (!try auditSequenceExists(self.db, receipt.exported_through_sequence)) {
            return error.ExportSnapshotMismatch;
        }

        var statement = try self.db.prepare(
            "INSERT INTO audit_export_receipts " ++
                "(id,exported_through_sequence,entry_count,content_sha256," ++
                "actor_kind,actor_id,exported_at) VALUES (?1,?2,?3,?4,?5,?6,?7);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &receipt.id);
        try statement.bindInt64(2, receipt.exported_through_sequence);
        try statement.bindInt64(3, receipt.entry_count);
        try statement.bindBlob(4, &receipt.content_sha256);
        try statement.bindText(5, actorText(receipt.actor_kind));
        if (receipt.actor_id) |actor_id| try statement.bindBlob(6, &actor_id) else try statement.bindNull(6);
        try statement.bindInt64(7, receipt.exported_at);
        if (try statement.step() != .done) return error.UnexpectedRow;

        try insertAudit(self.db, audit);
        try transaction.commit();
    }

    /// Deletes one sequence prefix and nothing else. Audit has no retention
    /// path; this method is the sole intentional deletion API.
    pub fn pruneAuditPrefix(
        self: Repository,
        request: AuditPruneRequest,
        audit: AuditEntry,
    ) !u64 {
        if (!request.recent_reauthentication) return error.ReauthenticationRequired;
        if (!request.typed_confirmation_matches) return error.TypedConfirmationRequired;
        if (request.prune_through_sequence == 0 or
            request.prune_through_sequence > std.math.maxInt(i64)) return error.InvalidAuditCutoff;
        try validateReceipt(request.receipt);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        const stored = try self.loadExportReceipt(request.receipt.id);
        if (!receiptsEqual(stored, request.receipt)) return error.ExportReceiptMismatch;
        if (stored.exported_through_sequence < request.prune_through_sequence) {
            return error.ExportReceiptDoesNotCoverPrefix;
        }

        var statement = try self.db.prepare(
            "DELETE FROM audit_entries WHERE sequence <= ?1;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, request.prune_through_sequence);
        if (try statement.step() != .done) return error.UnexpectedRow;
        const deleted = self.db.changes();

        // The prune action itself is immutable and is always newer than the
        // deleted prefix because SQLite AUTOINCREMENT never reuses sequences.
        try insertAudit(self.db, audit);
        try transaction.commit();
        return deleted;
    }

    pub fn appendRuntimeEvent(self: Repository, event: RuntimeEventInput) !void {
        if (event.observed_at < 0) return error.InvalidTimestamp;
        var statement = try self.db.prepare(
            "INSERT INTO runtime_events " ++
                "(id,kind,severity,node_id,observed_at,details_json) " ++
                "VALUES (?1,?2,?3,?4,?5,?6);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &event.id);
        try statement.bindText(2, event.kind);
        try statement.bindText(3, @tagName(event.severity));
        if (event.node_id) |node_id| try statement.bindBlob(4, &node_id) else try statement.bindNull(4);
        try statement.bindInt64(5, event.observed_at);
        try statement.bindText(6, event.details_json);
        if (try statement.step() != .done) return error.UnexpectedRow;
    }

    pub fn listRuntimeEvents(
        self: Repository,
        allocator: std.mem.Allocator,
        cursor: ?RuntimeEventCursor,
        requested_limit: u16,
    ) !RuntimeEventPage {
        const limit = try pageLimit(requested_limit);
        var statement = try self.db.prepare(
            "SELECT id,kind,severity,node_id,observed_at,details_json " ++
                "FROM runtime_events WHERE (?1 = 0 OR observed_at < ?2 OR " ++
                "(observed_at = ?2 AND id < ?3)) " ++
                "ORDER BY observed_at DESC,id DESC LIMIT ?4;",
        );
        defer statement.deinit();
        try bindCompositeCursor(&statement, cursor != null, if (cursor) |value| value.observed_at else 0, if (cursor) |value| value.before_id else [_]u8{0} ** 16);
        try statement.bindInt64(4, @as(u32, limit) + 1);

        var items: std.ArrayListUnmanaged(RuntimeEventRecord) = .empty;
        errdefer deinitRuntimeEventList(&items, allocator);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            try items.append(allocator, try decodeRuntimeEvent(allocator, &statement));
        }
        const next_cursor: ?RuntimeEventCursor = if (saw_more) .{
            .observed_at = items.items[items.items.len - 1].observed_at,
            .before_id = items.items[items.items.len - 1].id,
        } else null;
        return .{ .items = try items.toOwnedSlice(allocator), .next_cursor = next_cursor };
    }

    pub fn pruneRuntimeEvents(self: Repository, now: i64) !u64 {
        return self.pruneRuntimeEventsForDays(now, default_runtime_retention_days);
    }

    pub fn pruneRuntimeEventsForDays(self: Repository, now: i64, retention_days: u16) !u64 {
        const cutoff = try retentionCutoff(now, retention_days);
        var statement = try self.db.prepare(
            "DELETE FROM runtime_events " ++
                "WHERE observed_at < ?1 AND kind NOT GLOB 'security.*';",
        );
        defer statement.deinit();
        try statement.bindInt64(1, cutoff);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    /// Deletes at most `limit` expired observations. Runtime maintenance uses
    /// this form so one daily retention pass cannot monopolize the serialized
    /// SQLite owner ahead of protocol-critical persistence.
    pub fn pruneRuntimeEventsForDaysBounded(
        self: Repository,
        now: i64,
        retention_days: u16,
        limit: u16,
    ) !u64 {
        if (limit == 0) return error.InvalidRetentionBatch;
        const cutoff = try retentionCutoff(now, retention_days);
        var statement = try self.db.prepare(
            "DELETE FROM runtime_events WHERE id IN (" ++
                "SELECT id FROM runtime_events WHERE observed_at < ?1 " ++
                "AND kind NOT GLOB 'security.*' " ++
                "ORDER BY observed_at ASC,id ASC LIMIT ?2);",
        );
        defer statement.deinit();
        try statement.bindInt64(1, cutoff);
        try statement.bindInt64(2, limit);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    /// Security events use a fixed policy retention period and cannot be
    /// shortened through the dashboard's general runtime-event setting.
    pub fn pruneSecurityEventsBounded(
        self: Repository,
        now: i64,
        limit: u16,
    ) !u64 {
        if (limit == 0) return error.InvalidRetentionBatch;
        const cutoff = try retentionCutoff(now, security_policy.security_event_retention_days);
        var statement = try self.db.prepare(
            "DELETE FROM runtime_events WHERE id IN (" ++
                "SELECT id FROM runtime_events WHERE observed_at < ?1 " ++
                "AND kind GLOB 'security.*' " ++
                "ORDER BY observed_at ASC,id ASC LIMIT ?2);",
        );
        defer statement.deinit();
        try statement.bindInt64(1, cutoff);
        try statement.bindInt64(2, limit);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    /// Queues a probe only for an existing Node. The request and immutable
    /// authorization audit record commit together.
    pub fn createConnectivityCheck(
        self: Repository,
        input: ConnectivityCheckInput,
        audit: AuditEntry,
    ) !void {
        try validateConnectivityInput(input);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        var statement = try self.db.prepare(
            "INSERT INTO connectivity_checks " ++
                "(id,node_id,node_name,requested_by_kind,requested_by_id,status," ++
                "timeout_ms,requested_at) VALUES (?1,?2,?3,?4,?5,'queued',?6,?7);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &input.id);
        try statement.bindBlob(2, &input.node_id);
        try statement.bindText(3, input.node_name);
        try statement.bindText(4, actorText(input.requested_by_kind));
        if (input.requested_by_id) |actor_id| try statement.bindBlob(5, &actor_id) else try statement.bindNull(5);
        try statement.bindInt64(6, input.timeout_ms);
        try statement.bindInt64(7, input.requested_at);
        const step = statement.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidConnectivityCheck,
            else => err,
        };
        if (step != .done) return error.UnexpectedRow;

        try insertAudit(self.db, audit);
        try transaction.commit();
    }

    pub fn transitionConnectivityCheck(
        self: Repository,
        id: [16]u8,
        target: ConnectivityStatus,
        now: i64,
        rtt_microseconds: ?u64,
        error_code: ?[]const u8,
    ) !void {
        if (now < 0) return error.InvalidTimestamp;
        if (target == .queued) return error.IllegalConnectivityTransition;
        try validateTransitionPayload(target, rtt_microseconds, error_code);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var lookup = try self.db.prepare(
            "SELECT status,requested_at,started_at FROM connectivity_checks WHERE id = ?1;",
        );
        defer lookup.deinit();
        try lookup.bindBlob(1, &id);
        if (try lookup.step() != .row) return error.ConnectivityCheckNotFound;
        const current = try parseConnectivityStatus(lookup.columnText(0) orelse return error.CorruptConnectivityCheck);
        const requested_at = lookup.columnInt64(1);
        const started_at = if (lookup.columnIsNull(2)) null else lookup.columnInt64(2);
        if (try lookup.step() != .done) return error.CorruptConnectivityCheck;
        if (!transitionAllowed(current, target)) return error.IllegalConnectivityTransition;
        if (now < requested_at or (started_at != null and now < started_at.?)) return error.InvalidTimestamp;

        var update = try self.db.prepare(
            "UPDATE connectivity_checks SET status = ?1," ++
                "started_at = CASE WHEN ?1 = 'running' THEN ?2 ELSE started_at END," ++
                "completed_at = CASE WHEN ?3 = 1 THEN ?2 ELSE NULL END," ++
                "rtt_microseconds = ?4,error_code = ?5 " ++
                "WHERE id = ?6 AND status = ?7;",
        );
        defer update.deinit();
        try update.bindText(1, @tagName(target));
        try update.bindInt64(2, now);
        try update.bindInt64(3, @intFromBool(target.isTerminal()));
        if (rtt_microseconds) |value| {
            if (value > std.math.maxInt(i64)) return error.InvalidRoundTripTime;
            try update.bindInt64(4, value);
        } else try update.bindNull(4);
        if (error_code) |value| try update.bindText(5, value) else try update.bindNull(5);
        try update.bindBlob(6, &id);
        try update.bindText(7, @tagName(current));
        if (try update.step() != .done or self.db.changes() != 1) return error.ConnectivityCheckStateChanged;
        try transaction.commit();
    }

    /// Startup recovery turns every in-flight request into one durable
    /// terminal state before new work is admitted.
    pub fn interruptActiveConnectivityChecks(self: Repository, now: i64) !u64 {
        if (now < 0) return error.InvalidTimestamp;
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        var future = try self.db.prepare(
            "SELECT count(*) FROM connectivity_checks " ++
                "WHERE status IN ('queued','running') AND requested_at > ?1;",
        );
        defer future.deinit();
        try future.bindInt64(1, now);
        if (try future.step() != .row) return error.CorruptConnectivityCheck;
        const future_count = future.columnInt64(0);
        if (try future.step() != .done) return error.CorruptConnectivityCheck;
        if (future_count != 0) return error.InvalidTimestamp;

        var update = try self.db.prepare(
            "UPDATE connectivity_checks SET status = 'interrupted'," ++
                "completed_at = ?1,rtt_microseconds = NULL,error_code = 'service_restarted' " ++
                "WHERE status IN ('queued','running');",
        );
        defer update.deinit();
        try update.bindInt64(1, now);
        if (try update.step() != .done) return error.UnexpectedRow;
        const changed = self.db.changes();
        try transaction.commit();
        return changed;
    }

    pub fn listConnectivityChecks(
        self: Repository,
        allocator: std.mem.Allocator,
        cursor: ?ConnectivityCheckCursor,
        requested_limit: u16,
    ) !ConnectivityCheckPage {
        const limit = try pageLimit(requested_limit);
        var statement = try self.db.prepare(
            "SELECT id,node_id,node_name,requested_by_kind,requested_by_id,status," ++
                "timeout_ms,requested_at,started_at,completed_at,rtt_microseconds,error_code " ++
                "FROM connectivity_checks WHERE (?1 = 0 OR requested_at < ?2 OR " ++
                "(requested_at = ?2 AND id < ?3)) " ++
                "ORDER BY requested_at DESC,id DESC LIMIT ?4;",
        );
        defer statement.deinit();
        try bindCompositeCursor(&statement, cursor != null, if (cursor) |value| value.requested_at else 0, if (cursor) |value| value.before_id else [_]u8{0} ** 16);
        try statement.bindInt64(4, @as(u32, limit) + 1);

        var items: std.ArrayListUnmanaged(ConnectivityCheckRecord) = .empty;
        errdefer deinitConnectivityList(&items, allocator);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            try items.append(allocator, try decodeConnectivityCheck(allocator, &statement));
        }
        const next_cursor: ?ConnectivityCheckCursor = if (saw_more) .{
            .requested_at = items.items[items.items.len - 1].requested_at,
            .before_id = items.items[items.items.len - 1].id,
        } else null;
        return .{ .items = try items.toOwnedSlice(allocator), .next_cursor = next_cursor };
    }

    pub fn pruneConnectivityChecks(self: Repository, now: i64) !u64 {
        return self.pruneConnectivityChecksForDays(now, default_connectivity_retention_days);
    }

    pub fn pruneConnectivityChecksForDays(self: Repository, now: i64, retention_days: u16) !u64 {
        const cutoff = try retentionCutoff(now, retention_days);
        var statement = try self.db.prepare(
            "DELETE FROM connectivity_checks WHERE " ++
                "status IN ('succeeded','failed','timed_out','interrupted') " ++
                "AND completed_at < ?1;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, cutoff);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    pub fn pruneConnectivityChecksForDaysBounded(
        self: Repository,
        now: i64,
        retention_days: u16,
        limit: u16,
    ) !u64 {
        if (limit == 0) return error.InvalidRetentionBatch;
        const cutoff = try retentionCutoff(now, retention_days);
        var statement = try self.db.prepare(
            "DELETE FROM connectivity_checks WHERE id IN (" ++
                "SELECT id FROM connectivity_checks WHERE " ++
                "status IN ('succeeded','failed','timed_out','interrupted') " ++
                "AND completed_at < ?1 ORDER BY completed_at ASC,id ASC LIMIT ?2);",
        );
        defer statement.deinit();
        try statement.bindInt64(1, cutoff);
        try statement.bindInt64(2, limit);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    fn loadExportReceipt(self: Repository, id: [16]u8) !ExportReceipt {
        var statement = try self.db.prepare(
            "SELECT exported_through_sequence,entry_count,content_sha256," ++
                "actor_kind,actor_id,exported_at FROM audit_export_receipts WHERE id = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id);
        if (try statement.step() != .row) return error.ExportReceiptNotFound;
        const through = try positiveU64(statement.columnInt64(0), error.CorruptExportReceipt);
        const count = try positiveU64(statement.columnInt64(1), error.CorruptExportReceipt);
        const digest_blob = statement.columnBlob(2) orelse return error.CorruptExportReceipt;
        if (digest_blob.len != 32) return error.CorruptExportReceipt;
        var digest: [32]u8 = undefined;
        @memcpy(&digest, digest_blob);
        const actor = try parseActor(statement.columnText(3) orelse return error.CorruptExportReceipt);
        var actor_id: ?[16]u8 = null;
        if (statement.columnBlob(4)) |blob| actor_id = try copyId(blob, error.CorruptExportReceipt);
        const exported_at = statement.columnInt64(5);
        if (exported_at < 0) return error.CorruptExportReceipt;
        if (try statement.step() != .done) return error.CorruptExportReceipt;
        return .{
            .id = id,
            .exported_through_sequence = through,
            .entry_count = count,
            .content_sha256 = digest,
            .actor_kind = actor,
            .actor_id = actor_id,
            .exported_at = exported_at,
        };
    }
};

fn insertAudit(db: *sqlite.Database, audit: AuditEntry) !void {
    if (audit.occurred_at < 0) return error.InvalidAuditEntry;
    if (audit.actor_kind == .web) db.armCommitHook();
    var statement = try db.prepare(
        "INSERT INTO audit_entries " ++
            "(id,occurred_at,actor_kind,actor_id,action,resource_type," ++
            "resource_id,request_id,details_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9);",
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
    if (try statement.step() != .done) return error.UnexpectedRow;
}

fn lastInsertSequence(db: *sqlite.Database) !u64 {
    var statement = try db.prepare("SELECT last_insert_rowid();");
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const result = try positiveU64(statement.columnInt64(0), error.CorruptAuditEntry);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return result;
}

fn auditCountThrough(db: *sqlite.Database, through: u64) !u64 {
    if (through == 0 or through > std.math.maxInt(i64)) return error.InvalidExportReceipt;
    var statement = try db.prepare("SELECT count(*) FROM audit_entries WHERE sequence <= ?1;");
    defer statement.deinit();
    try statement.bindInt64(1, through);
    if (try statement.step() != .row) return error.UnexpectedDone;
    const raw = statement.columnInt64(0);
    if (raw < 0) return error.CorruptAuditEntry;
    if (try statement.step() != .done) return error.UnexpectedRow;
    return @intCast(raw);
}

fn auditSequenceExists(db: *sqlite.Database, sequence: u64) !bool {
    var statement = try db.prepare("SELECT 1 FROM audit_entries WHERE sequence = ?1;");
    defer statement.deinit();
    try statement.bindInt64(1, sequence);
    return switch (try statement.step()) {
        .row => blk: {
            if (try statement.step() != .done) return error.UnexpectedRow;
            break :blk true;
        },
        .done => false,
    };
}

fn validateReceipt(receipt: ExportReceipt) !void {
    if (receipt.exported_through_sequence == 0 or
        receipt.exported_through_sequence > std.math.maxInt(i64) or
        receipt.entry_count == 0 or receipt.entry_count > std.math.maxInt(i64) or
        receipt.exported_at < 0) return error.InvalidExportReceipt;
    if (receipt.actor_kind == .system) return error.InvalidExportActor;
}

fn receiptsEqual(left: ExportReceipt, right: ExportReceipt) bool {
    return std.mem.eql(u8, &left.id, &right.id) and
        left.exported_through_sequence == right.exported_through_sequence and
        left.entry_count == right.entry_count and
        std.mem.eql(u8, &left.content_sha256, &right.content_sha256) and
        left.actor_kind == right.actor_kind and
        optionalIdEql(left.actor_id, right.actor_id) and
        left.exported_at == right.exported_at;
}

fn optionalIdEql(left: ?[16]u8, right: ?[16]u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, &left.?, &right.?);
}

fn decodeAudit(allocator: std.mem.Allocator, statement: *const sqlite.Statement) !AuditRecord {
    const sequence = try positiveU64(statement.columnInt64(0), error.CorruptAuditEntry);
    const id = try copyId(statement.columnBlob(1) orelse return error.CorruptAuditEntry, error.CorruptAuditEntry);
    const occurred_at = statement.columnInt64(2);
    if (occurred_at < 0) return error.CorruptAuditEntry;
    const actor_kind = try parseActor(statement.columnText(3) orelse return error.CorruptAuditEntry);
    var actor_id: ?[16]u8 = null;
    if (statement.columnBlob(4)) |blob| actor_id = try copyId(blob, error.CorruptAuditEntry);
    const action = try allocator.dupe(u8, statement.columnText(5) orelse return error.CorruptAuditEntry);
    errdefer allocator.free(action);
    const resource_type = try allocator.dupe(u8, statement.columnText(6) orelse return error.CorruptAuditEntry);
    errdefer allocator.free(resource_type);
    const resource_id = try allocator.dupe(u8, statement.columnText(7) orelse return error.CorruptAuditEntry);
    errdefer allocator.free(resource_id);
    var request_id: ?[16]u8 = null;
    if (statement.columnBlob(8)) |blob| request_id = try copyId(blob, error.CorruptAuditEntry);
    const details_json = try allocator.dupe(u8, statement.columnText(9) orelse return error.CorruptAuditEntry);
    return .{
        .sequence = sequence,
        .id = id,
        .occurred_at = occurred_at,
        .actor_kind = actor_kind,
        .actor_id = actor_id,
        .action = action,
        .resource_type = resource_type,
        .resource_id = resource_id,
        .request_id = request_id,
        .details_json = details_json,
    };
}

fn decodeRuntimeEvent(allocator: std.mem.Allocator, statement: *const sqlite.Statement) !RuntimeEventRecord {
    const id = try copyId(statement.columnBlob(0) orelse return error.CorruptRuntimeEvent, error.CorruptRuntimeEvent);
    const kind = try allocator.dupe(u8, statement.columnText(1) orelse return error.CorruptRuntimeEvent);
    errdefer allocator.free(kind);
    const severity_text = statement.columnText(2) orelse return error.CorruptRuntimeEvent;
    const severity = std.meta.stringToEnum(EventSeverity, severity_text) orelse return error.CorruptRuntimeEvent;
    var node_id: ?[16]u8 = null;
    if (statement.columnBlob(3)) |blob| node_id = try copyId(blob, error.CorruptRuntimeEvent);
    const observed_at = statement.columnInt64(4);
    if (observed_at < 0) return error.CorruptRuntimeEvent;
    const details_json = try allocator.dupe(u8, statement.columnText(5) orelse return error.CorruptRuntimeEvent);
    return .{
        .id = id,
        .kind = kind,
        .severity = severity,
        .node_id = node_id,
        .observed_at = observed_at,
        .details_json = details_json,
    };
}

fn decodeConnectivityCheck(allocator: std.mem.Allocator, statement: *const sqlite.Statement) !ConnectivityCheckRecord {
    const id = try copyId(statement.columnBlob(0) orelse return error.CorruptConnectivityCheck, error.CorruptConnectivityCheck);
    var node_id: ?[16]u8 = null;
    if (statement.columnBlob(1)) |blob| node_id = try copyId(blob, error.CorruptConnectivityCheck);
    const node_name = try allocator.dupe(u8, statement.columnText(2) orelse return error.CorruptConnectivityCheck);
    errdefer allocator.free(node_name);
    const requested_by_kind = try parseActor(statement.columnText(3) orelse return error.CorruptConnectivityCheck);
    var requested_by_id: ?[16]u8 = null;
    if (statement.columnBlob(4)) |blob| requested_by_id = try copyId(blob, error.CorruptConnectivityCheck);
    const status = try parseConnectivityStatus(statement.columnText(5) orelse return error.CorruptConnectivityCheck);
    const timeout_raw = statement.columnInt64(6);
    if (timeout_raw < minimum_check_timeout_ms or timeout_raw > maximum_check_timeout_ms) return error.CorruptConnectivityCheck;
    const requested_at = statement.columnInt64(7);
    if (requested_at < 0) return error.CorruptConnectivityCheck;
    const started_at = if (statement.columnIsNull(8)) null else statement.columnInt64(8);
    const completed_at = if (statement.columnIsNull(9)) null else statement.columnInt64(9);
    var rtt: ?u64 = null;
    if (!statement.columnIsNull(10)) {
        const raw = statement.columnInt64(10);
        if (raw < 0) return error.CorruptConnectivityCheck;
        rtt = @intCast(raw);
    }
    var error_code: ?[]u8 = null;
    if (statement.columnText(11)) |value| error_code = try allocator.dupe(u8, value);
    return .{
        .id = id,
        .node_id = node_id,
        .node_name = node_name,
        .requested_by_kind = requested_by_kind,
        .requested_by_id = requested_by_id,
        .status = status,
        .timeout_ms = @intCast(timeout_raw),
        .requested_at = requested_at,
        .started_at = started_at,
        .completed_at = completed_at,
        .rtt_microseconds = rtt,
        .error_code = error_code,
    };
}

fn validateConnectivityInput(input: ConnectivityCheckInput) !void {
    if (input.timeout_ms < minimum_check_timeout_ms or input.timeout_ms > maximum_check_timeout_ms) {
        return error.InvalidConnectivityTimeout;
    }
    if (input.requested_at < 0 or input.node_name.len == 0 or input.node_name.len > 63) {
        return error.InvalidConnectivityCheck;
    }
}

fn validateTransitionPayload(target: ConnectivityStatus, rtt: ?u64, error_code: ?[]const u8) !void {
    if (error_code) |value| {
        if (value.len == 0 or value.len > 128) return error.InvalidConnectivityError;
    }
    switch (target) {
        .queued => return error.IllegalConnectivityTransition,
        .running, .timed_out => if (rtt != null or error_code != null) return error.InvalidConnectivityResult,
        .succeeded => if (rtt == null or error_code != null) return error.InvalidConnectivityResult,
        .failed, .interrupted => if (rtt != null or error_code == null) return error.InvalidConnectivityResult,
    }
}

fn transitionAllowed(current: ConnectivityStatus, target: ConnectivityStatus) bool {
    return switch (current) {
        .queued => target == .running or target == .failed or target == .interrupted,
        .running => target == .succeeded or target == .failed or target == .timed_out or target == .interrupted,
        .succeeded, .failed, .timed_out, .interrupted => false,
    };
}

fn parseConnectivityStatus(value: []const u8) !ConnectivityStatus {
    return std.meta.stringToEnum(ConnectivityStatus, value) orelse error.CorruptConnectivityCheck;
}

fn parseActor(value: []const u8) !ActorKind {
    return std.meta.stringToEnum(ActorKind, value) orelse error.CorruptActorKind;
}

fn actorText(actor: ActorKind) []const u8 {
    return @tagName(actor);
}

fn bindCompositeCursor(statement: *sqlite.Statement, present: bool, timestamp: i64, id: [16]u8) !void {
    if (present and timestamp < 0) return error.InvalidCursor;
    try statement.bindInt64(1, @intFromBool(present));
    try statement.bindInt64(2, timestamp);
    try statement.bindBlob(3, &id);
}

fn pageLimit(requested: u16) !u16 {
    if (requested == 0 or requested > maximum_page_size) return error.InvalidPageSize;
    return requested;
}

fn retentionCutoff(now: i64, retention_days: u16) !i64 {
    if (now < 0 or retention_days == 0 or retention_days > 3650) return error.InvalidRetention;
    const duration = std.math.mul(i64, retention_days, seconds_per_day) catch return error.InvalidRetention;
    return if (now > duration) now - duration else 0;
}

fn positiveU64(value: i64, comptime corruption_error: anyerror) !u64 {
    if (value <= 0) return corruption_error;
    return @intCast(value);
}

fn copyId(blob: []const u8, comptime corruption_error: anyerror) ![16]u8 {
    if (blob.len != 16) return corruption_error;
    var id: [16]u8 = undefined;
    @memcpy(&id, blob);
    return id;
}

fn deinitAuditList(items: *std.ArrayListUnmanaged(AuditRecord), allocator: std.mem.Allocator) void {
    for (items.items) |*item| item.deinit(allocator);
    items.deinit(allocator);
}

fn deinitRuntimeEventList(items: *std.ArrayListUnmanaged(RuntimeEventRecord), allocator: std.mem.Allocator) void {
    for (items.items) |*item| item.deinit(allocator);
    items.deinit(allocator);
}

fn deinitConnectivityList(items: *std.ArrayListUnmanaged(ConnectivityCheckRecord), allocator: std.mem.Allocator) void {
    for (items.items) |*item| item.deinit(allocator);
    items.deinit(allocator);
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testAudit(id_byte: u8, action: []const u8, occurred_at: i64) AuditEntry {
    return .{
        .id = [_]u8{id_byte} ** 16,
        .occurred_at = occurred_at,
        .actor_kind = .web,
        .actor_id = [_]u8{0xa1} ** 16,
        .action = action,
        .resource_type = "operation",
        .resource_id = "target",
        .request_id = [_]u8{0xb1} ** 16,
        .details_json = "{\"secret\":\"hidden\"}",
    };
}

fn insertTestNode(db: *sqlite.Database) ![16]u8 {
    var vnr = try db.prepare(
        "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
            "VALUES ('core',167772160,24,1,1,1);",
    );
    defer vnr.deinit();
    if (try vnr.step() != .done) return error.UnexpectedRow;
    const node_id = [_]u8{0x44} ** 16;
    var node = try db.prepare(
        "INSERT INTO nodes (id,name,vnr_name,address,created_at,updated_at) " ++
            "VALUES (?1,'edge-a','core',167772162,1,1);",
    );
    defer node.deinit();
    try node.bindBlob(1, &node_id);
    if (try node.step() != .done) return error.UnexpectedRow;
    return node_id;
}

fn scalarInt(db: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try db.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const result = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return result;
}

test "audit rows are immutable and viewer projection redacts sensitive context" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    _ = try repository.appendAudit(testAudit(1, "node.update", 100));
    var update = try db.prepare("UPDATE audit_entries SET action = 'tampered' WHERE sequence = 1;");
    defer update.deinit();
    try std.testing.expectError(error.ConstraintViolation, update.step());

    var page = try repository.listAudit(std.testing.allocator, null, default_page_size);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), page.items.len);
    const full = fullAuditView(&page.items[0]);
    const viewer = viewerAuditView(&page.items[0]);
    try std.testing.expect(full.actor_id != null and full.request_id != null);
    try std.testing.expect(std.mem.indexOf(u8, full.details_json, "secret") != null);
    try std.testing.expect(viewer.actor_id == null and viewer.request_id == null);
    try std.testing.expect(viewer.redacted);
    try std.testing.expectEqualStrings("{\"redacted\":true}", viewer.details_json);
}

test "audit prune requires exact receipt proof and can delete only a prefix" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    _ = try repository.appendAudit(testAudit(1, "one", 100));
    _ = try repository.appendAudit(testAudit(2, "two", 101));
    _ = try repository.appendAudit(testAudit(3, "three", 102));

    var stream: ExportAccumulator = .{};
    try stream.appendEntry(1, "one\n");
    try stream.appendEntry(2, "two\n");
    const receipt = try stream.finish([_]u8{0x70} ** 16, .web, [_]u8{0xa1} ** 16, 103);
    try repository.commitExportReceipt(receipt, testAudit(4, "audit.export", 103));

    var missing = receipt;
    missing.id = [_]u8{0x71} ** 16;
    try std.testing.expectError(error.ExportReceiptNotFound, repository.pruneAuditPrefix(.{
        .receipt = missing,
        .prune_through_sequence = 2,
        .recent_reauthentication = true,
        .typed_confirmation_matches = true,
    }, testAudit(5, "audit.prune", 104)));

    var mismatched = receipt;
    mismatched.content_sha256[0] ^= 1;
    try std.testing.expectError(error.ExportReceiptMismatch, repository.pruneAuditPrefix(.{
        .receipt = mismatched,
        .prune_through_sequence = 2,
        .recent_reauthentication = true,
        .typed_confirmation_matches = true,
    }, testAudit(5, "audit.prune", 104)));

    try std.testing.expectError(error.ExportReceiptDoesNotCoverPrefix, repository.pruneAuditPrefix(.{
        .receipt = receipt,
        .prune_through_sequence = 3,
        .recent_reauthentication = true,
        .typed_confirmation_matches = true,
    }, testAudit(5, "audit.prune", 104)));
    try std.testing.expectEqual(@as(i64, 4), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));

    const deleted = try repository.pruneAuditPrefix(.{
        .receipt = receipt,
        .prune_through_sequence = 2,
        .recent_reauthentication = true,
        .typed_confirmation_matches = true,
    }, testAudit(5, "audit.prune", 104));
    try std.testing.expectEqual(@as(u64, 2), deleted);
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE sequence <= 2;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE sequence = 3;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE action = 'audit.prune';"));
}

test "audit prune independently requires reauthentication and typed confirmation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);
    _ = try repository.appendAudit(testAudit(1, "one", 100));
    var stream: ExportAccumulator = .{};
    try stream.appendEntry(1, "one\n");
    const receipt = try stream.finish([_]u8{0x70} ** 16, .web, [_]u8{0xa1} ** 16, 101);
    try repository.commitExportReceipt(receipt, testAudit(2, "audit.export", 101));
    try std.testing.expectError(error.ReauthenticationRequired, repository.pruneAuditPrefix(.{
        .receipt = receipt,
        .prune_through_sequence = 1,
        .recent_reauthentication = false,
        .typed_confirmation_matches = true,
    }, testAudit(3, "audit.prune", 102)));
    try std.testing.expectError(error.TypedConfirmationRequired, repository.pruneAuditPrefix(.{
        .receipt = receipt,
        .prune_through_sequence = 1,
        .recent_reauthentication = true,
        .typed_confirmation_matches = false,
    }, testAudit(3, "audit.prune", 102)));
}

test "runtime and terminal connectivity retention honor default boundaries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);
    const node_id = try insertTestNode(&db);
    const now = 120 * seconds_per_day;

    try repository.appendRuntimeEvent(.{ .id = [_]u8{1} ** 16, .kind = "node.offline", .severity = .warning, .observed_at = now - 91 * seconds_per_day });
    try repository.appendRuntimeEvent(.{ .id = [_]u8{2} ** 16, .kind = "node.online", .severity = .info, .observed_at = now - 90 * seconds_per_day });
    try repository.appendRuntimeEvent(.{ .id = [_]u8{5} ** 16, .kind = "security.login_lockout", .severity = .warning, .observed_at = now - 91 * seconds_per_day });
    try repository.appendRuntimeEvent(.{ .id = [_]u8{6} ** 16, .kind = "security.login_lockout", .severity = .warning, .observed_at = now - 2 * seconds_per_day });
    try std.testing.expectError(
        error.InvalidRetentionBatch,
        repository.pruneRuntimeEventsForDaysBounded(now, default_runtime_retention_days, 0),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        try repository.pruneRuntimeEventsForDaysBounded(now, default_runtime_retention_days, 1),
    );
    try std.testing.expectEqual(@as(i64, 3), try scalarInt(&db, "SELECT count(*) FROM runtime_events;"));
    try std.testing.expectEqual(
        @as(u64, 1),
        try repository.pruneSecurityEventsBounded(now, 1),
    );
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT count(*) FROM runtime_events;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &db,
        "SELECT count(*) FROM runtime_events WHERE kind GLOB 'security.*';",
    ));
    try std.testing.expectError(
        error.InvalidRetentionBatch,
        repository.pruneSecurityEventsBounded(now, 0),
    );

    const old_check = ConnectivityCheckInput{ .id = [_]u8{3} ** 16, .node_id = node_id, .node_name = "edge-a", .requested_by_kind = .web, .requested_by_id = [_]u8{0xa1} ** 16, .requested_at = now - 31 * seconds_per_day };
    try repository.createConnectivityCheck(old_check, testAudit(10, "check.request", old_check.requested_at));
    try repository.transitionConnectivityCheck(old_check.id, .failed, old_check.requested_at + 1, null, "node_offline");
    const boundary_check = ConnectivityCheckInput{ .id = [_]u8{4} ** 16, .node_id = node_id, .node_name = "edge-a", .requested_by_kind = .web, .requested_by_id = [_]u8{0xa1} ** 16, .requested_at = now - 30 * seconds_per_day };
    try repository.createConnectivityCheck(boundary_check, testAudit(11, "check.request", boundary_check.requested_at));
    try repository.transitionConnectivityCheck(boundary_check.id, .failed, boundary_check.requested_at, null, "node_offline");
    try std.testing.expectEqual(
        @as(u64, 1),
        try repository.pruneConnectivityChecksForDaysBounded(now, default_connectivity_retention_days, 1),
    );
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM connectivity_checks;"));
}

test "connectivity state machine rejects illegal transitions and terminal rewrites" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);
    const node_id = try insertTestNode(&db);
    const input = ConnectivityCheckInput{ .id = [_]u8{0x21} ** 16, .node_id = node_id, .node_name = "edge-a", .requested_by_kind = .web, .requested_by_id = [_]u8{0xa1} ** 16, .requested_at = 100 };
    try repository.createConnectivityCheck(input, testAudit(1, "check.request", 100));
    try std.testing.expectError(error.IllegalConnectivityTransition, repository.transitionConnectivityCheck(input.id, .succeeded, 101, 10, null));
    try repository.transitionConnectivityCheck(input.id, .running, 101, null, null);
    try repository.transitionConnectivityCheck(input.id, .succeeded, 102, 950, null);
    try std.testing.expectError(error.IllegalConnectivityTransition, repository.transitionConnectivityCheck(input.id, .failed, 103, null, "late_failure"));

    var page = try repository.listConnectivityChecks(std.testing.allocator, null, default_page_size);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), page.items.len);
    try std.testing.expectEqual(ConnectivityStatus.succeeded, page.items[0].status);
    try std.testing.expectEqual(@as(?u64, 950), page.items[0].rtt_microseconds);
}

test "startup interrupts queued and running connectivity checks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);
    const node_id = try insertTestNode(&db);
    const queued = ConnectivityCheckInput{ .id = [_]u8{0x31} ** 16, .node_id = node_id, .node_name = "edge-a", .requested_by_kind = .web, .requested_by_id = [_]u8{0xa1} ** 16, .requested_at = 100 };
    const running = ConnectivityCheckInput{ .id = [_]u8{0x32} ** 16, .node_id = node_id, .node_name = "edge-a", .requested_by_kind = .web, .requested_by_id = [_]u8{0xa1} ** 16, .requested_at = 101 };
    try repository.createConnectivityCheck(queued, testAudit(1, "check.request", 100));
    try repository.createConnectivityCheck(running, testAudit(2, "check.request", 101));
    try repository.transitionConnectivityCheck(running.id, .running, 102, null, null);
    try std.testing.expectEqual(@as(u64, 2), try repository.interruptActiveConnectivityChecks(103));

    var page = try repository.listConnectivityChecks(std.testing.allocator, null, default_page_size);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), page.items.len);
    for (page.items) |item| {
        try std.testing.expectEqual(ConnectivityStatus.interrupted, item.status);
        try std.testing.expectEqual(@as(?i64, 103), item.completed_at);
        try std.testing.expectEqualStrings("service_restarted", item.error_code.?);
    }
    try std.testing.expectEqual(@as(u64, 0), try repository.interruptActiveConnectivityChecks(104));
}
