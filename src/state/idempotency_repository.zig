//! Hash-only idempotency records for authenticated management mutations.
//!
//! The serialized application worker normally eliminates local races, but
//! every lookup/reservation/commit transition is still protected by an
//! immediate SQLite transaction and the `(actor_id,key_hash)` primary key.
//! Raw caller keys and canonical request bytes are never persisted.

const std = @import("std");
const sqlite = @import("sqlite.zig");

pub const ActorId = [16]u8;
pub const Digest = [32]u8;
pub const RequestHashKey = [32]u8;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
pub const minimum_key_bytes: usize = 16;
pub const maximum_key_bytes: usize = 128;
pub const maximum_operation_bytes: usize = 128;
pub const maximum_canonical_request_bytes: usize = 64 * 1024;
pub const maximum_response_body_bytes: usize = 64 * 1024;
pub const maximum_prune_batch: u16 = 1_000;

/// Status 102 is never emitted by the management API and is used solely as a
/// durable reservation marker. Committed responses are restricted to
/// ordinary final HTTP statuses (200-599).
const reserved_status: u16 = 102;
/// The authoritative mutation and audit committed, but the exact response
/// envelope has not yet been durably attached. Retries must never execute the
/// mutation again; they receive a stable consumed/conflict response until the
/// normal completion transition succeeds.
const mutation_committed_status: u16 = 103;

pub const Replay = struct {
    status: u16,
    body: []u8,
    created_at: i64,
    expires_at: i64,

    pub fn deinit(self: *Replay, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        self.* = undefined;
    }
};

pub const Lookup = union(enum) {
    missing,
    in_progress,
    committed_without_response,
    replay: Replay,

    pub fn deinit(self: *Lookup, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .replay => |*value| value.deinit(allocator),
            .missing, .in_progress, .committed_without_response => {},
        }
        self.* = undefined;
    }
};

pub const ReserveResult = union(enum) {
    reserved,
    in_progress,
    committed_without_response,
    replay: Replay,

    pub fn deinit(self: *ReserveResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .replay => |*value| value.deinit(allocator),
            .reserved, .in_progress, .committed_without_response => {},
        }
        self.* = undefined;
    }
};

pub const CommitResult = enum {
    committed,
    already_committed,
};

pub const ReservationInput = struct {
    actor_id: ActorId,
    raw_key: []const u8,
    request_hash: Digest,
    now: i64,
    expires_at: i64,
};

pub const CommitInput = struct {
    actor_id: ActorId,
    raw_key: []const u8,
    request_hash: Digest,
    status: u16,
    response_body: []const u8,
    now: i64,
};

pub const MutationCommitInput = struct {
    actor_id: ActorId,
    raw_key: []const u8,
    request_hash: Digest,
    now: i64,
};

pub const Repository = struct {
    db: *sqlite.Database,

    pub fn init(db: *sqlite.Database) Repository {
        return .{ .db = db };
    }

    /// Looks up an actor-scoped key. Expired records are removed in the same
    /// transaction and behave as if they had never existed.
    pub fn lookup(
        self: Repository,
        allocator: std.mem.Allocator,
        actor_id: ActorId,
        raw_key: []const u8,
        expected_request_hash: Digest,
        now: i64,
    ) !Lookup {
        try validateTimestamp(now);
        const key_hash = try keyHash(raw_key);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        const row = try self.loadRecord(allocator, actor_id, key_hash);
        if (row == null) {
            try transaction.commit();
            return .missing;
        }
        var record = row.?;
        errdefer record.deinit(allocator);
        if (record.expires_at <= now) {
            record.deinit(allocator);
            try self.deleteExact(actor_id, key_hash);
            try transaction.commit();
            return .missing;
        }
        if (!std.crypto.timing_safe.eql(Digest, record.request_hash, expected_request_hash)) {
            return error.IdempotencyConflict;
        }
        if (record.status == reserved_status) {
            record.deinit(allocator);
            try transaction.commit();
            return .in_progress;
        }
        if (record.status == mutation_committed_status) {
            record.deinit(allocator);
            try transaction.commit();
            return .committed_without_response;
        }
        var replay = record.intoReplay();
        errdefer replay.deinit(allocator);
        try transaction.commit();
        return .{ .replay = replay };
    }

    /// Claims a key or returns the existing in-progress/completed state. The
    /// unique key plus immediate transaction makes two racing reservations
    /// converge on one durable winner.
    pub fn reserve(
        self: Repository,
        allocator: std.mem.Allocator,
        input: ReservationInput,
    ) !ReserveResult {
        try validateReservation(input);
        const key_hash = try keyHash(input.raw_key);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        if (try self.loadRecord(allocator, input.actor_id, key_hash)) |loaded| {
            var record = loaded;
            errdefer record.deinit(allocator);
            if (record.expires_at <= input.now) {
                record.deinit(allocator);
                try self.deleteExact(input.actor_id, key_hash);
            } else {
                if (!std.crypto.timing_safe.eql(Digest, record.request_hash, input.request_hash)) {
                    return error.IdempotencyConflict;
                }
                if (record.status == reserved_status) {
                    record.deinit(allocator);
                    try transaction.commit();
                    return .in_progress;
                }
                if (record.status == mutation_committed_status) {
                    record.deinit(allocator);
                    try transaction.commit();
                    return .committed_without_response;
                }
                var replay = record.intoReplay();
                errdefer replay.deinit(allocator);
                try transaction.commit();
                return .{ .replay = replay };
            }
        }

        var insert = try self.db.prepare(
            "INSERT INTO idempotency_records " ++
                "(actor_id,key_hash,request_hash,response_status,response_body,created_at,expires_at) " ++
                "VALUES (?1,?2,?3,?4,x'',?5,?6);",
        );
        defer insert.deinit();
        try insert.bindBlob(1, &input.actor_id);
        try insert.bindBlob(2, &key_hash);
        try insert.bindBlob(3, &input.request_hash);
        try insert.bindInt64(4, reserved_status);
        try insert.bindInt64(5, input.now);
        try insert.bindInt64(6, input.expires_at);
        const inserted = insert.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.IdempotencyRace,
            else => err,
        };
        if (inserted != .done) return error.UnexpectedRow;
        try transaction.commit();
        return .reserved;
    }

    /// Advances a live reservation inside the repository mutation's already
    /// open transaction. This method deliberately does not begin or commit a
    /// transaction: the SQLite commit hook calls it after an audited operation
    /// inserts its web audit row, or after an explicitly armed security side
    /// effect such as a failed-login throttle update, immediately before the
    /// same COMMIT.
    pub fn markMutationCommitted(self: Repository, input: MutationCommitInput) !void {
        try validateTimestamp(input.now);
        if (!self.db.inTransaction()) return error.MutationMarkerRequiresTransaction;
        const key_hash = try keyHash(input.raw_key);
        var update = try self.db.prepare(
            "UPDATE idempotency_records SET response_status=?1,response_body=x'' " ++
                "WHERE actor_id=?2 AND key_hash=?3 AND request_hash=?4 " ++
                "AND response_status=?5 AND expires_at>?6;",
        );
        defer update.deinit();
        try update.bindInt64(1, mutation_committed_status);
        try update.bindBlob(2, &input.actor_id);
        try update.bindBlob(3, &key_hash);
        try update.bindBlob(4, &input.request_hash);
        try update.bindInt64(5, reserved_status);
        try update.bindInt64(6, input.now);
        if (try update.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.ReservationNotFound;
    }

    /// Completes a live reservation. Retrying the identical commit is safe;
    /// attempting to change an already committed response is rejected.
    pub fn commit(self: Repository, input: CommitInput) !CommitResult {
        try validateTimestamp(input.now);
        if (input.status < 200 or input.status > 599) return error.InvalidResponseStatus;
        if (input.response_body.len > maximum_response_body_bytes) return error.ResponseTooLarge;
        const key_hash = try keyHash(input.raw_key);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var statement = try self.db.prepare(
            "SELECT request_hash,response_status,response_body,expires_at " ++
                "FROM idempotency_records WHERE actor_id=?1 AND key_hash=?2;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &input.actor_id);
        try statement.bindBlob(2, &key_hash);
        if (try statement.step() != .row) return error.ReservationNotFound;
        const stored_request = statement.columnBlob(0) orelse return error.CorruptIdempotencyState;
        if (stored_request.len != 32) return error.CorruptIdempotencyState;
        if (!std.crypto.timing_safe.eql(Digest, stored_request[0..32].*, input.request_hash)) {
            return error.IdempotencyConflict;
        }
        const stored_status_raw = statement.columnInt64(1);
        if (stored_status_raw < 100 or stored_status_raw > 599) return error.CorruptIdempotencyState;
        const stored_status: u16 = @intCast(stored_status_raw);
        const stored_body = statement.columnBlob(2) orelse return error.CorruptIdempotencyState;
        const expires_at = statement.columnInt64(3);
        if (expires_at <= input.now) {
            if (try statement.step() != .done) return error.CorruptIdempotencyState;
            try self.deleteExact(input.actor_id, key_hash);
            try transaction.commit();
            return error.ReservationExpired;
        }
        if (stored_status != reserved_status and stored_status != mutation_committed_status) {
            if (stored_status != input.status or !std.mem.eql(u8, stored_body, input.response_body)) {
                return error.IdempotencyCommitConflict;
            }
            if (try statement.step() != .done) return error.CorruptIdempotencyState;
            try transaction.commit();
            return .already_committed;
        }
        if (stored_body.len != 0) return error.CorruptIdempotencyState;
        if (try statement.step() != .done) return error.CorruptIdempotencyState;

        var update = try self.db.prepare(
            "UPDATE idempotency_records SET response_status=?1,response_body=?2 " ++
                "WHERE actor_id=?3 AND key_hash=?4 AND request_hash=?5 " ++
                "AND response_status IN (?6,?7);",
        );
        defer update.deinit();
        try update.bindInt64(1, input.status);
        try update.bindBlob(2, input.response_body);
        try update.bindBlob(3, &input.actor_id);
        try update.bindBlob(4, &key_hash);
        try update.bindBlob(5, &input.request_hash);
        try update.bindInt64(6, reserved_status);
        try update.bindInt64(7, mutation_committed_status);
        if (try update.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.IdempotencyRace;
        try transaction.commit();
        return .committed;
    }

    /// Releases a reservation when request validation or the authoritative
    /// mutation fails before a response can be committed. A completed record
    /// is never removed through this path.
    pub fn cancel(
        self: Repository,
        actor_id: ActorId,
        raw_key: []const u8,
        expected_request_hash: Digest,
    ) !void {
        const key_hash = try keyHash(raw_key);
        var remove = try self.db.prepare(
            "DELETE FROM idempotency_records WHERE actor_id=?1 AND key_hash=?2 " ++
                "AND request_hash=?3 AND response_status=?4;",
        );
        defer remove.deinit();
        try remove.bindBlob(1, &actor_id);
        try remove.bindBlob(2, &key_hash);
        try remove.bindBlob(3, &expected_request_hash);
        try remove.bindInt64(4, reserved_status);
        if (try remove.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.ReservationNotFound;
    }

    /// Bounded opportunistic retention cleanup. Request-path lookup also
    /// deletes the exact expired key synchronously.
    pub fn pruneExpired(self: Repository, now: i64, requested_limit: u16) !u64 {
        try validateTimestamp(now);
        if (requested_limit == 0 or requested_limit > maximum_prune_batch) {
            return error.InvalidPruneLimit;
        }
        var statement = try self.db.prepare(
            "DELETE FROM idempotency_records WHERE (actor_id,key_hash) IN (" ++
                "SELECT actor_id,key_hash FROM idempotency_records " ++
                "WHERE expires_at <= ?1 ORDER BY expires_at,actor_id,key_hash LIMIT ?2);",
        );
        defer statement.deinit();
        try statement.bindInt64(1, now);
        try statement.bindInt64(2, requested_limit);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    /// No request survives an `ntsrv` process restart. Startup may therefore
    /// release only pre-mutation reservations, while retaining status 103
    /// rows whose authoritative mutation already committed and must never be
    /// executed again.
    pub fn recoverInterruptedReservations(self: Repository) !u64 {
        var statement = try self.db.prepare(
            "DELETE FROM idempotency_records WHERE response_status = ?1;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, reserved_status);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    fn loadRecord(
        self: Repository,
        allocator: std.mem.Allocator,
        actor_id: ActorId,
        key_hash: Digest,
    ) !?StoredRecord {
        var statement = try self.db.prepare(
            "SELECT request_hash,response_status,response_body,created_at,expires_at " ++
                "FROM idempotency_records WHERE actor_id=?1 AND key_hash=?2;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &actor_id);
        try statement.bindBlob(2, &key_hash);
        if (try statement.step() == .done) return null;
        const request_blob = statement.columnBlob(0) orelse return error.CorruptIdempotencyState;
        const body_blob = statement.columnBlob(2) orelse return error.CorruptIdempotencyState;
        if (request_blob.len != 32 or body_blob.len > maximum_response_body_bytes) {
            return error.CorruptIdempotencyState;
        }
        var request_hash: Digest = undefined;
        @memcpy(&request_hash, request_blob);
        const status_raw = statement.columnInt64(1);
        if (status_raw < 100 or status_raw > 599) return error.CorruptIdempotencyState;
        const created_at = statement.columnInt64(3);
        const expires_at = statement.columnInt64(4);
        if (created_at < 0 or expires_at <= created_at) return error.CorruptIdempotencyState;
        const body = try allocator.dupe(u8, body_blob);
        errdefer allocator.free(body);
        if (try statement.step() != .done) return error.CorruptIdempotencyState;
        return .{
            .request_hash = request_hash,
            .status = @intCast(status_raw),
            .body = body,
            .created_at = created_at,
            .expires_at = expires_at,
        };
    }

    fn deleteExact(self: Repository, actor_id: ActorId, key_hash: Digest) !void {
        var remove = try self.db.prepare(
            "DELETE FROM idempotency_records WHERE actor_id=?1 AND key_hash=?2;",
        );
        defer remove.deinit();
        try remove.bindBlob(1, &actor_id);
        try remove.bindBlob(2, &key_hash);
        if (try remove.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.IdempotencyRace;
    }
};

const StoredRecord = struct {
    request_hash: Digest,
    status: u16,
    body: ?[]u8,
    created_at: i64,
    expires_at: i64,

    fn deinit(self: *StoredRecord, allocator: std.mem.Allocator) void {
        if (self.body) |body| allocator.free(body);
        self.body = null;
    }

    fn intoReplay(self: *StoredRecord) Replay {
        const replay = Replay{
            .status = self.status,
            .body = self.body orelse unreachable,
            .created_at = self.created_at,
            .expires_at = self.expires_at,
        };
        self.body = null;
        return replay;
    }
};

pub fn keyHash(raw_key: []const u8) !Digest {
    try validateRawKey(raw_key);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("ntip-idempotency-key-v0.2\x00");
    hasher.update(raw_key);
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

/// Derives a purpose-specific request-hash key from the Master identity
/// secret, which is stored outside SQLite. A database or online-backup reader
/// therefore cannot turn a successful auth request record into a fast offline
/// verifier for the canonicalized plaintext password.
pub fn deriveRequestHashKey(master_identity_secret: *const [32]u8) RequestHashKey {
    var key: RequestHashKey = undefined;
    HmacSha256.create(
        &key,
        "ntip-idempotency-request-key-v0.2\x00",
        master_identity_secret,
    );
    return key;
}

/// Canonical request hashing binds an idempotency key to one operation and
/// the exact canonical request representation selected by the application
/// service. The MAC key must be derived from secret state outside SQLite.
pub fn requestHash(
    request_hash_key: *const RequestHashKey,
    raw_key: []const u8,
    operation: []const u8,
    canonical_request: []const u8,
) !Digest {
    try validateRawKey(raw_key);
    if (operation.len == 0 or operation.len > maximum_operation_bytes) {
        return error.InvalidOperation;
    }
    if (canonical_request.len > maximum_canonical_request_bytes) return error.RequestTooLarge;

    // Bind the MAC to both secret Master state and the high-entropy caller
    // key, neither of which is present in SQLite. Even disclosure of the full
    // state directory therefore does not expose a password verifier unless
    // the corresponding request header is also known.
    var per_request_key: RequestHashKey = undefined;
    defer std.crypto.secureZero(u8, &per_request_key);
    var key_deriver = HmacSha256.init(request_hash_key);
    key_deriver.update("ntip-idempotency-caller-key-v0.2\x00");
    key_deriver.update(raw_key);
    key_deriver.final(&per_request_key);

    var hasher = HmacSha256.init(&per_request_key);
    hasher.update("ntip-idempotency-request-v0.2\x00");
    hasher.update(operation);
    hasher.update("\x00");
    hasher.update(canonical_request);
    var digest: Digest = undefined;
    hasher.final(&digest);
    return digest;
}

fn validateRawKey(raw_key: []const u8) !void {
    if (raw_key.len < minimum_key_bytes or raw_key.len > maximum_key_bytes) {
        return error.InvalidIdempotencyKey;
    }
    for (raw_key) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '_', ':', '-' => {},
        else => return error.InvalidIdempotencyKey,
    };
}

fn validateReservation(input: ReservationInput) !void {
    try validateTimestamp(input.now);
    if (input.expires_at <= input.now) return error.InvalidExpiry;
    _ = try keyHash(input.raw_key);
}

fn validateTimestamp(now: i64) !void {
    if (now < 0) return error.InvalidTimestamp;
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn scalarInt(db: *sqlite.Database, sql_text: [:0]const u8) !i64 {
    var statement = try db.prepare(sql_text);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const value = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return value;
}

const test_request_hash_key = [_]u8{0x42} ** 32;

test "key and canonical request hashing enforce the public bounds" {
    const key = "0123456789abcdef";
    const digest = try keyHash(key);
    try std.testing.expect(!std.mem.eql(u8, &digest, key));
    try std.testing.expectError(error.InvalidIdempotencyKey, keyHash("short"));
    try std.testing.expectError(error.InvalidIdempotencyKey, keyHash("0123456789abcde!"));
    const first = try requestHash(&test_request_hash_key, key, "createNode", "{\"name\":\"a\"}");
    const second = try requestHash(&test_request_hash_key, key, "createRoute", "{\"name\":\"a\"}");
    try std.testing.expect(!std.crypto.timing_safe.eql(Digest, first, second));
    try std.testing.expectError(error.InvalidOperation, requestHash(&test_request_hash_key, key, "", "{}"));

    const other_identity = [_]u8{0x24} ** 32;
    const other_key = deriveRequestHashKey(&other_identity);
    const other_hash = try requestHash(&other_key, key, "createNode", "{\"name\":\"a\"}");
    try std.testing.expect(!std.crypto.timing_safe.eql(Digest, first, other_hash));
    const other_caller_hash = try requestHash(
        &test_request_hash_key,
        "fedcba9876543210",
        "createNode",
        "{\"name\":\"a\"}",
    );
    try std.testing.expect(!std.crypto.timing_safe.eql(Digest, first, other_caller_hash));
}

test "reserve converges, replays exact responses, conflicts, and expires" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const allocator = std.testing.allocator;
    const actor = [_]u8{1} ** 16;
    const key = "request-key-0001";
    const request = try requestHash(&test_request_hash_key, key, "createNode", "{\"name\":\"node-a\"}");
    const other = try requestHash(&test_request_hash_key, key, "createNode", "{\"name\":\"node-b\"}");

    var first = try repository.reserve(allocator, .{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .now = 100,
        .expires_at = 200,
    });
    defer first.deinit(allocator);
    try std.testing.expect(first == .reserved);
    var raced = try repository.reserve(allocator, .{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .now = 101,
        .expires_at = 300,
    });
    defer raced.deinit(allocator);
    try std.testing.expect(raced == .in_progress);
    try std.testing.expectError(error.IdempotencyConflict, repository.reserve(allocator, .{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = other,
        .now = 101,
        .expires_at = 300,
    }));

    try std.testing.expectEqual(CommitResult.committed, try repository.commit(.{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .status = 201,
        .response_body = "{\"id\":\"node-a\"}",
        .now = 102,
    }));
    try std.testing.expectEqual(CommitResult.already_committed, try repository.commit(.{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .status = 201,
        .response_body = "{\"id\":\"node-a\"}",
        .now = 103,
    }));
    try std.testing.expectError(error.IdempotencyCommitConflict, repository.commit(.{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .status = 200,
        .response_body = "{}",
        .now = 103,
    }));

    var replayed = try repository.lookup(allocator, actor, key, request, 104);
    defer replayed.deinit(allocator);
    try std.testing.expect(replayed == .replay);
    try std.testing.expectEqual(@as(u16, 201), replayed.replay.status);
    try std.testing.expectEqualStrings("{\"id\":\"node-a\"}", replayed.replay.body);
    try std.testing.expectEqual(@as(i64, 200), replayed.replay.expires_at);

    var expired = try repository.lookup(allocator, actor, key, request, 200);
    defer expired.deinit(allocator);
    try std.testing.expect(expired == .missing);
    var reused = try repository.reserve(allocator, .{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = other,
        .now = 200,
        .expires_at = 250,
    });
    defer reused.deinit(allocator);
    try std.testing.expect(reused == .reserved);
}

test "records are actor scoped, raw keys are absent, and pruning is bounded" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const allocator = std.testing.allocator;
    const key = "shared-key-00001";
    const request = try requestHash(&test_request_hash_key, key, "resetPassword", "{}");

    for ([_]u8{ 1, 2 }) |byte| {
        var result = try repository.reserve(allocator, .{
            .actor_id = [_]u8{byte} ** 16,
            .raw_key = key,
            .request_hash = request,
            .now = 10,
            .expires_at = 20,
        });
        result.deinit(allocator);
    }
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT count(*) FROM idempotency_records;"));
    var storage = try db.prepare(
        "SELECT length(key_hash),typeof(key_hash),instr(CAST(key_hash AS TEXT),?1) " ++
            "FROM idempotency_records LIMIT 1;",
    );
    defer storage.deinit();
    try storage.bindText(1, key);
    try std.testing.expectEqual(sqlite.Step.row, try storage.step());
    try std.testing.expectEqual(@as(i64, 32), storage.columnInt64(0));
    try std.testing.expectEqualStrings("blob", storage.columnText(1).?);
    try std.testing.expectEqual(@as(i64, 0), storage.columnInt64(2));

    try std.testing.expectEqual(@as(u64, 1), try repository.pruneExpired(20, 1));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM idempotency_records;"));
    try std.testing.expectEqual(@as(u64, 1), try repository.pruneExpired(20, 10));
    try std.testing.expectError(error.InvalidPruneLimit, repository.pruneExpired(20, 0));
}

test "commit enforces reservation identity and the 64 KiB response bound" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const allocator = std.testing.allocator;
    const actor = [_]u8{3} ** 16;
    const key = "response-bound-01";
    const request = try requestHash(&test_request_hash_key, key, "auditExport", "{}");
    var result = try repository.reserve(allocator, .{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .now = 100,
        .expires_at = 110,
    });
    result.deinit(allocator);

    const too_large = try allocator.alloc(u8, maximum_response_body_bytes + 1);
    defer allocator.free(too_large);
    @memset(too_large, 'x');
    try std.testing.expectError(error.ResponseTooLarge, repository.commit(.{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .status = 200,
        .response_body = too_large,
        .now = 101,
    }));
    try std.testing.expectError(error.InvalidResponseStatus, repository.commit(.{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .status = reserved_status,
        .response_body = "",
        .now = 101,
    }));
    try std.testing.expectError(error.ReservationExpired, repository.commit(.{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .status = 200,
        .response_body = "{}",
        .now = 110,
    }));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM idempotency_records;"));
}

test "only an exact live reservation can be cancelled" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const actor = [_]u8{4} ** 16;
    const key = "cancel-key-00001";
    const request = try requestHash(&test_request_hash_key, key, "createVnr", "{}");
    var reserved = try repository.reserve(std.testing.allocator, .{
        .actor_id = actor,
        .raw_key = key,
        .request_hash = request,
        .now = 100,
        .expires_at = 200,
    });
    reserved.deinit(std.testing.allocator);
    try repository.cancel(actor, key, request);
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM idempotency_records;"));
    try std.testing.expectError(
        error.ReservationNotFound,
        repository.cancel(actor, key, request),
    );
}

test "startup recovery releases only pre-mutation reservations" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const allocator = std.testing.allocator;
    const committed_actor = [_]u8{0x51} ** 16;
    const interrupted_actor = [_]u8{0x52} ** 16;
    const committed_key = "committed-key-0001";
    const interrupted_key = "interrupted-key-01";
    const committed_request = try requestHash(&test_request_hash_key, committed_key, "createVnr", "{}");
    const interrupted_request = try requestHash(&test_request_hash_key, interrupted_key, "createNode", "{}");

    var committed_reservation = try repository.reserve(allocator, .{
        .actor_id = committed_actor,
        .raw_key = committed_key,
        .request_hash = committed_request,
        .now = 100,
        .expires_at = 1_000,
    });
    committed_reservation.deinit(allocator);
    var transaction = try db.begin(.immediate);
    errdefer transaction.rollback() catch {};
    try repository.markMutationCommitted(.{
        .actor_id = committed_actor,
        .raw_key = committed_key,
        .request_hash = committed_request,
        .now = 101,
    });
    try transaction.commit();

    var interrupted_reservation = try repository.reserve(allocator, .{
        .actor_id = interrupted_actor,
        .raw_key = interrupted_key,
        .request_hash = interrupted_request,
        .now = 102,
        .expires_at = 1_000,
    });
    interrupted_reservation.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), try repository.recoverInterruptedReservations());

    var committed = try repository.lookup(
        allocator,
        committed_actor,
        committed_key,
        committed_request,
        103,
    );
    defer committed.deinit(allocator);
    try std.testing.expect(committed == .committed_without_response);
    var interrupted = try repository.lookup(
        allocator,
        interrupted_actor,
        interrupted_key,
        interrupted_request,
        103,
    );
    defer interrupted.deinit(allocator);
    try std.testing.expect(interrupted == .missing);
}
