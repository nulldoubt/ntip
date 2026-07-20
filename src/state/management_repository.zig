//! Transactional application repository for v0.2 management-plane state.
//!
//! A caller serializes access to the owning `sqlite.Database`. This layer
//! accepts only validated domain projections, binds every application value
//! through prepared statements, and commits inventory/enrollment mutations,
//! their immutable audit entry, and one durable generation as one unit.

const std = @import("std");
const model = @import("../domain/model.zig");
const sqlite = @import("sqlite.zig");

pub const ActorKind = enum {
    local_cli,
    web,
    system,

    fn databaseValue(self: ActorKind) []const u8 {
        return switch (self) {
            .local_cli => "local_cli",
            .web => "web",
            .system => "system",
        };
    }
};

pub const AuditEntry = struct {
    id: [16]u8,
    occurred_at: i64,
    actor_kind: ActorKind,
    actor_id: ?[16]u8 = null,
    action: []const u8,
    resource_type: []const u8,
    resource_id: []const u8 = "",
    request_id: ?[16]u8 = null,
    details_json: []const u8 = "{}",
};

pub const ConsumedEnrollment = struct {
    node_id: model.NodeId,
    generation: u64,
};

pub const PendingEnrollment = struct {
    node_id: model.NodeId,
    handle: [16]u8,
    derived_psk: [32]u8,
    expires_at: i64,
};

pub const Repository = struct {
    db: *sqlite.Database,

    pub fn init(db: *sqlite.Database) Repository {
        return .{ .db = db };
    }

    /// Loads a committed immutable projection into the existing domain model.
    /// Database rows are treated as untrusted durable input and revalidated by
    /// the same domain invariants used by mutation commands.
    pub fn loadInventory(self: Repository, allocator: std.mem.Allocator) !model.Store {
        var store = model.Store.init(allocator);
        errdefer store.deinit();

        store.generation = try self.durableGeneration();

        var vnrs = try self.db.prepare(
            "SELECT name, network, prefix FROM vnrs ORDER BY name;",
        );
        defer vnrs.deinit();
        while (try vnrs.step() == .row) {
            const name_text = vnrs.columnText(0) orelse return error.CorruptInventory;
            const name = model.Name.parse(name_text) catch return error.CorruptInventory;
            const network = try columnU32(&vnrs, 1);
            const prefix = try columnU8(&vnrs, 2);
            try store.vnrs.append(allocator, .{
                .name = name,
                .range = .{ .network = .{ .value = network }, .prefix = prefix },
            });
        }

        var nodes = try self.db.prepare(
            "SELECT id, name, vnr_name, address, enrollment_state, public_key " ++
                "FROM nodes ORDER BY name;",
        );
        defer nodes.deinit();
        while (try nodes.step() == .row) {
            const id_blob = nodes.columnBlob(0) orelse return error.CorruptInventory;
            if (id_blob.len != 16) return error.CorruptInventory;
            var id: model.NodeId = undefined;
            @memcpy(&id.bytes, id_blob);

            const name_text = nodes.columnText(1) orelse return error.CorruptInventory;
            const vnr_text = nodes.columnText(2) orelse return error.CorruptInventory;
            const name = model.Name.parse(name_text) catch return error.CorruptInventory;
            const vnr = model.Name.parse(vnr_text) catch return error.CorruptInventory;
            const address = try columnU32(&nodes, 3);
            const state_text = nodes.columnText(4) orelse return error.CorruptInventory;
            const enrollment_state: model.EnrollmentState = if (std.mem.eql(u8, state_text, "unenrolled"))
                .unenrolled
            else if (std.mem.eql(u8, state_text, "enrolled"))
                .enrolled
            else
                return error.CorruptInventory;

            var public_key: ?[32]u8 = null;
            if (nodes.columnBlob(5)) |key_blob| {
                if (key_blob.len != 32) return error.CorruptInventory;
                var key: [32]u8 = undefined;
                @memcpy(&key, key_blob);
                public_key = key;
            }
            try store.nodes.append(allocator, .{
                .id = id,
                .name = name,
                .vnr = vnr,
                .address = .{ .value = address },
                .enrollment_state = enrollment_state,
                .public_key = public_key,
            });
        }

        var routes = try self.db.prepare(
            "SELECT routes.id, routes.network, routes.prefix, nodes.name " ++
                "FROM routes JOIN nodes ON nodes.id = routes.node_id " ++
                "ORDER BY routes.network, routes.prefix, nodes.name;",
        );
        defer routes.deinit();
        while (try routes.step() == .row) {
            const id_blob = routes.columnBlob(0) orelse return error.CorruptInventory;
            if (id_blob.len != 16) return error.CorruptInventory;
            var id: model.RouteId = undefined;
            @memcpy(&id.bytes, id_blob);
            const network = try columnU32(&routes, 1);
            const prefix = try columnU8(&routes, 2);
            const node_text = routes.columnText(3) orelse return error.CorruptInventory;
            const node = model.Name.parse(node_text) catch return error.CorruptInventory;
            try store.routes.append(allocator, .{
                .id = id,
                .prefix = .{ .network = .{ .value = network }, .prefix = prefix },
                .node = node,
            });
        }

        validateProjection(&store) catch return error.CorruptInventory;
        return store;
    }

    pub fn durableGeneration(self: Repository) !u64 {
        var statement = try self.db.prepare(
            "SELECT durable_generation FROM master_state WHERE singleton = 1;",
        );
        defer statement.deinit();
        if (try statement.step() != .row) return error.CorruptInventory;
        const raw = statement.columnInt64(0);
        if (raw < 0) return error.CorruptInventory;
        if (try statement.step() != .done) return error.CorruptInventory;
        return @intCast(raw);
    }

    /// Returns the maximum Node count that a new inventory mutation may
    /// admit now. The constructed/effective capacity remains authoritative
    /// until restart, but a lower desired capacity must reserve its future
    /// bound while it is waiting for live application or restart. Otherwise
    /// a later Node create could make the pending revision impossible to
    /// activate on the next process start. Failed revisions deliberately do
    /// not constrain inventory because startup retains the effective values.
    pub fn nodeAdmissionCapacity(self: Repository) !u32 {
        var statement = try self.db.prepare(
            "SELECT state.desired_revision,state.effective_revision," ++
                "desired.status,desired.maximum_nodes," ++
                "effective.status,effective.maximum_nodes " ++
                "FROM settings_state AS state " ++
                "JOIN settings_revisions AS desired " ++
                "ON desired.revision=state.desired_revision " ++
                "JOIN settings_revisions AS effective " ++
                "ON effective.revision=state.effective_revision " ++
                "WHERE state.singleton=1;",
        );
        defer statement.deinit();
        if (try statement.step() != .row) return error.CorruptSettingsState;
        const desired_sequence = try positiveU64(statement.columnInt64(0));
        const effective_sequence = try positiveU64(statement.columnInt64(1));
        // SQLite owns column text and may invalidate it on the next step, so
        // decode statuses before advancing the statement to `done`.
        const desired_status = try settingsStatus(statement.columnText(2));
        const desired_capacity = try settingsCapacity(statement.columnInt64(3));
        const effective_status = try settingsStatus(statement.columnText(4));
        const effective_capacity = try settingsCapacity(statement.columnInt64(5));
        if (try statement.step() != .done) return error.CorruptSettingsState;
        if (effective_status != .active) return error.CorruptSettingsState;

        return switch (desired_status) {
            .active => active: {
                if (desired_sequence != effective_sequence or desired_capacity != effective_capacity) {
                    return error.CorruptSettingsState;
                }
                break :active effective_capacity;
            },
            .failed => failed: {
                if (desired_sequence == effective_sequence) return error.CorruptSettingsState;
                break :failed effective_capacity;
            },
            .pending_apply, .pending_restart => pending: {
                if (desired_sequence == effective_sequence) return error.CorruptSettingsState;
                break :pending @min(desired_capacity, effective_capacity);
            },
        };
    }

    /// Reconciles a candidate produced by exactly one domain mutation. The
    /// optimistic precondition, inventory, audit row, and generation advance
    /// are committed together or none of them are visible.
    pub fn persistInventory(
        self: Repository,
        candidate: *const model.Store,
        expected_generation: u64,
        now: i64,
        audit: AuditEntry,
    ) !u64 {
        try validateProjection(candidate);
        if (now < 0) return error.InvalidTimestamp;
        const next_generation = std.math.add(u64, expected_generation, 1) catch
            return error.GenerationOverflow;
        if (candidate.generation != next_generation or next_generation > std.math.maxInt(i64)) {
            return error.InvalidCandidateGeneration;
        }

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.requireGeneration(expected_generation);
        try self.requireNodeAdmission(candidate.nodes.items.len);
        try self.requireEnrollmentProjection(candidate);

        self.reconcileInventory(candidate, now) catch |err| return switch (err) {
            error.ConstraintViolation => error.InventoryConstraintViolation,
            else => err,
        };
        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try self.advanceGeneration(expected_generation, next_generation);
        try transaction.commit();
        return next_generation;
    }

    /// Commits an inventory projection and the initial enrollment verifier for
    /// one of its Nodes as one logical mutation. This is the creation path used
    /// after a one-time credential has been delivered to a CLI file or staged
    /// for an HTTP response: either both the Node and usable verifier become
    /// authoritative, or neither does.
    pub fn persistInventoryWithEnrollment(
        self: Repository,
        candidate: *const model.Store,
        enrollment: PendingEnrollment,
        expected_generation: u64,
        now: i64,
        audit: AuditEntry,
    ) !u64 {
        try validateProjection(candidate);
        if (now < 0 or enrollment.expires_at <= now) return error.InvalidCredentialLifetime;
        const next_generation = std.math.add(u64, expected_generation, 1) catch
            return error.GenerationOverflow;
        if (candidate.generation != next_generation or next_generation > std.math.maxInt(i64)) {
            return error.InvalidCandidateGeneration;
        }
        const node = candidate.findNodeById(enrollment.node_id) orelse return error.NodeNotFound;
        if (node.enrollment_state != .unenrolled or node.public_key != null) {
            return error.NodeAlreadyEnrolled;
        }

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.requireGeneration(expected_generation);
        try self.requireNodeAdmission(candidate.nodes.items.len);
        try self.requireEnrollmentProjection(candidate);
        self.reconcileInventory(candidate, now) catch |err| return switch (err) {
            error.ConstraintViolation => error.InventoryConstraintViolation,
            else => err,
        };

        var revoke = try self.db.prepare(
            "UPDATE enrollment_credentials " ++
                "SET derived_psk = NULL, status = 'revoked', revoked_at = ?1 " ++
                "WHERE node_id = ?2 AND status = 'unused';",
        );
        defer revoke.deinit();
        try revoke.bindInt64(1, now);
        try revoke.bindBlob(2, &enrollment.node_id.bytes);
        if (try revoke.step() != .done) return error.UnexpectedRow;

        var insert = try self.db.prepare(
            "INSERT INTO enrollment_credentials " ++
                "(handle, node_id, derived_psk, created_at, expires_at, status) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, 'unused');",
        );
        defer insert.deinit();
        try insert.bindBlob(1, &enrollment.handle);
        try insert.bindBlob(2, &enrollment.node_id.bytes);
        try insert.bindBlob(3, &enrollment.derived_psk);
        try insert.bindInt64(4, now);
        try insert.bindInt64(5, enrollment.expires_at);
        const insert_step = insert.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.EnrollmentConstraintViolation,
            else => err,
        };
        if (insert_step != .done) return error.UnexpectedRow;

        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try self.advanceGeneration(expected_generation, next_generation);
        try transaction.commit();
        return next_generation;
    }

    /// Issues or replaces a credential. Only the derived verifier reaches the
    /// database. Any unused predecessor is revoked in the same transaction.
    /// An enrolled Node is rejected unless the separately authorized reset
    /// operation explicitly passes `reset_active_association = true`.
    pub fn replaceEnrollment(
        self: Repository,
        node_id: model.NodeId,
        handle: [16]u8,
        derived_psk: [32]u8,
        reset_active_association: bool,
        created_at: i64,
        expires_at: i64,
        expected_generation: u64,
        audit: AuditEntry,
    ) !u64 {
        if (created_at < 0 or expires_at <= created_at) return error.InvalidCredentialLifetime;
        const next_generation = try checkedNextGeneration(expected_generation);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.requireGeneration(expected_generation);
        const node_is_enrolled = try self.nodeIsEnrolled(node_id);
        if (node_is_enrolled and !reset_active_association) return error.NodeAlreadyEnrolled;

        var revoke = try self.db.prepare(
            "UPDATE enrollment_credentials " ++
                "SET derived_psk = NULL, status = 'revoked', revoked_at = ?1 " ++
                "WHERE node_id = ?2 AND status = 'unused';",
        );
        defer revoke.deinit();
        try revoke.bindInt64(1, created_at);
        try revoke.bindBlob(2, &node_id.bytes);
        if (try revoke.step() != .done) return error.UnexpectedRow;

        if (node_is_enrolled) {
            var reset = try self.db.prepare(
                "UPDATE nodes SET enrollment_state = 'unenrolled', public_key = NULL, " ++
                    "revision = revision + 1, updated_at = ?1 WHERE id = ?2;",
            );
            defer reset.deinit();
            try reset.bindInt64(1, created_at);
            try reset.bindBlob(2, &node_id.bytes);
            if (try reset.step() != .done) return error.UnexpectedRow;
            if (self.db.changes() != 1) return error.NodeNotFound;
        }

        var insert = try self.db.prepare(
            "INSERT INTO enrollment_credentials " ++
                "(handle, node_id, derived_psk, created_at, expires_at, status) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, 'unused');",
        );
        defer insert.deinit();
        try insert.bindBlob(1, &handle);
        try insert.bindBlob(2, &node_id.bytes);
        try insert.bindBlob(3, &derived_psk);
        try insert.bindInt64(4, created_at);
        try insert.bindInt64(5, expires_at);
        const insert_step = insert.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.EnrollmentConstraintViolation,
            else => err,
        };
        if (insert_step != .done) return error.UnexpectedRow;

        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try self.advanceGeneration(expected_generation, next_generation);
        try transaction.commit();
        return next_generation;
    }

    /// Revokes any unused credential and returns the Node to its unenrolled
    /// state without issuing replacement material. This is the browser/API
    /// reset action; the human CLI's reset-and-reissue workflow continues to
    /// use `replaceEnrollment`.
    ///
    /// The verifier clear, optional public-key clear and Node revision bump,
    /// immutable audit row, and durable generation advance are one transaction.
    pub fn resetEnrollment(
        self: Repository,
        node_id: model.NodeId,
        reset_at: i64,
        expected_generation: u64,
        audit: AuditEntry,
    ) !u64 {
        if (reset_at < 0) return error.InvalidTimestamp;
        const next_generation = try checkedNextGeneration(expected_generation);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.requireGeneration(expected_generation);
        const node_is_enrolled = try self.nodeIsEnrolled(node_id);

        var revoke = try self.db.prepare(
            "UPDATE enrollment_credentials " ++
                "SET derived_psk = NULL, status = 'revoked', revoked_at = ?1 " ++
                "WHERE node_id = ?2 AND status = 'unused';",
        );
        defer revoke.deinit();
        try revoke.bindInt64(1, reset_at);
        try revoke.bindBlob(2, &node_id.bytes);
        if (try revoke.step() != .done) return error.UnexpectedRow;

        if (node_is_enrolled) {
            var reset = try self.db.prepare(
                "UPDATE nodes SET enrollment_state = 'unenrolled', public_key = NULL, " ++
                    "revision = revision + 1, updated_at = ?1 " ++
                    "WHERE id = ?2 AND enrollment_state = 'enrolled';",
            );
            defer reset.deinit();
            try reset.bindInt64(1, reset_at);
            try reset.bindBlob(2, &node_id.bytes);
            if (try reset.step() != .done) return error.UnexpectedRow;
            if (self.db.changes() != 1) return error.EnrollmentStateChanged;
        }

        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try self.advanceGeneration(expected_generation, next_generation);
        try transaction.commit();
        return next_generation;
    }

    /// Authenticates and consumes a credential, binds the Node public key, and
    /// clears the verifier before the caller may install a live session.
    pub fn consumeEnrollment(
        self: Repository,
        handle: [16]u8,
        presented_derived_psk: [32]u8,
        public_key: [32]u8,
        consumed_at: i64,
        expected_generation: u64,
        audit: AuditEntry,
    ) !ConsumedEnrollment {
        if (consumed_at < 0) return error.InvalidTimestamp;
        var key_nonzero = false;
        for (public_key) |byte| key_nonzero = key_nonzero or byte != 0;
        if (!key_nonzero) return error.InvalidPublicKey;
        const next_generation = try checkedNextGeneration(expected_generation);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.requireGeneration(expected_generation);

        var lookup = try self.db.prepare(
            "SELECT node_id, derived_psk, expires_at, status " ++
                "FROM enrollment_credentials WHERE handle = ?1;",
        );
        defer lookup.deinit();
        try lookup.bindBlob(1, &handle);
        if (try lookup.step() != .row) return error.EnrollmentCredentialNotFound;
        const node_blob = lookup.columnBlob(0) orelse return error.CorruptEnrollmentCredential;
        if (node_blob.len != 16) return error.CorruptEnrollmentCredential;
        var node_id: model.NodeId = undefined;
        @memcpy(&node_id.bytes, node_blob);
        const stored_blob = lookup.columnBlob(1);
        const expires_at = lookup.columnInt64(2);
        const status = lookup.columnText(3) orelse return error.CorruptEnrollmentCredential;

        if (std.mem.eql(u8, status, "consumed")) return error.EnrollmentCredentialConsumed;
        if (std.mem.eql(u8, status, "revoked")) return error.EnrollmentCredentialRevoked;
        if (!std.mem.eql(u8, status, "unused")) return error.CorruptEnrollmentCredential;
        const stored = stored_blob orelse return error.CorruptEnrollmentCredential;
        if (stored.len != 32) return error.CorruptEnrollmentCredential;
        if (consumed_at >= expires_at) return error.EnrollmentCredentialExpired;
        if (!timingSafeEql32(stored, &presented_derived_psk)) return error.InvalidEnrollmentCredential;
        if (try lookup.step() != .done) return error.CorruptEnrollmentCredential;

        var bind_key = try self.db.prepare(
            "UPDATE nodes SET enrollment_state = 'enrolled', public_key = ?1, " ++
                "revision = revision + 1, updated_at = ?2 WHERE id = ?3;",
        );
        defer bind_key.deinit();
        try bind_key.bindBlob(1, &public_key);
        try bind_key.bindInt64(2, consumed_at);
        try bind_key.bindBlob(3, &node_id.bytes);
        const bind_step = bind_key.step() catch |err| return switch (err) {
            error.ConstraintViolation => error.PublicKeyInUse,
            else => err,
        };
        if (bind_step != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.NodeNotFound;

        var consume = try self.db.prepare(
            "UPDATE enrollment_credentials " ++
                "SET derived_psk = NULL, status = 'consumed', consumed_at = ?1 " ++
                "WHERE handle = ?2 AND status = 'unused';",
        );
        defer consume.deinit();
        try consume.bindInt64(1, consumed_at);
        try consume.bindBlob(2, &handle);
        if (try consume.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.EnrollmentCredentialStateChanged;

        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try self.advanceGeneration(expected_generation, next_generation);
        try transaction.commit();
        return .{ .node_id = node_id, .generation = next_generation };
    }

    pub fn revokeEnrollment(
        self: Repository,
        handle: [16]u8,
        revoked_at: i64,
        expected_generation: u64,
        audit: AuditEntry,
    ) !u64 {
        if (revoked_at < 0) return error.InvalidTimestamp;
        const next_generation = try checkedNextGeneration(expected_generation);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.requireGeneration(expected_generation);

        var lookup = try self.db.prepare(
            "SELECT status FROM enrollment_credentials WHERE handle = ?1;",
        );
        defer lookup.deinit();
        try lookup.bindBlob(1, &handle);
        if (try lookup.step() != .row) return error.EnrollmentCredentialNotFound;
        const status = lookup.columnText(0) orelse return error.CorruptEnrollmentCredential;
        if (std.mem.eql(u8, status, "consumed")) return error.EnrollmentCredentialConsumed;
        if (std.mem.eql(u8, status, "revoked")) return error.EnrollmentCredentialRevoked;
        if (!std.mem.eql(u8, status, "unused")) return error.CorruptEnrollmentCredential;
        if (try lookup.step() != .done) return error.CorruptEnrollmentCredential;

        var revoke = try self.db.prepare(
            "UPDATE enrollment_credentials " ++
                "SET derived_psk = NULL, status = 'revoked', revoked_at = ?1 " ++
                "WHERE handle = ?2 AND status = 'unused';",
        );
        defer revoke.deinit();
        try revoke.bindInt64(1, revoked_at);
        try revoke.bindBlob(2, &handle);
        if (try revoke.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.EnrollmentCredentialStateChanged;

        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try self.advanceGeneration(expected_generation, next_generation);
        try transaction.commit();
        return next_generation;
    }

    fn requireGeneration(self: Repository, expected: u64) !void {
        if (expected > std.math.maxInt(i64)) return error.GenerationOverflow;
        if (try self.durableGeneration() != expected) return error.PreconditionFailed;
    }

    /// Must run inside the inventory mutation transaction. Comparing against
    /// the currently committed count allows deletions to repair an already
    /// over-capacity database while preventing every count-increasing write
    /// from overtaking a pending reduction.
    fn requireNodeAdmission(self: Repository, candidate_count: usize) !void {
        if (!self.db.inTransaction()) return error.NodeAdmissionRequiresTransaction;
        var statement = try self.db.prepare("SELECT count(*) FROM nodes;");
        defer statement.deinit();
        if (try statement.step() != .row) return error.CorruptInventory;
        const raw_count = statement.columnInt64(0);
        if (raw_count < 0 or raw_count > std.math.maxInt(usize)) return error.CorruptInventory;
        const current_count: usize = @intCast(raw_count);
        if (try statement.step() != .done) return error.CorruptInventory;
        if (candidate_count <= current_count) return;
        if (candidate_count > @as(usize, try self.nodeAdmissionCapacity())) {
            return error.MaximumNodesExceeded;
        }
    }

    fn advanceGeneration(self: Repository, expected: u64, next: u64) !void {
        if (expected > std.math.maxInt(i64) or next > std.math.maxInt(i64)) {
            return error.GenerationOverflow;
        }
        var statement = try self.db.prepare(
            "UPDATE master_state SET durable_generation = ?1 " ++
                "WHERE singleton = 1 AND durable_generation = ?2;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, next);
        try statement.bindInt64(2, expected);
        if (try statement.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.PreconditionFailed;
    }

    fn nodeIsEnrolled(self: Repository, node_id: model.NodeId) !bool {
        var statement = try self.db.prepare(
            "SELECT enrollment_state FROM nodes WHERE id = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &node_id.bytes);
        if (try statement.step() != .row) return error.NodeNotFound;
        const state = statement.columnText(0) orelse return error.CorruptInventory;
        const enrolled = if (std.mem.eql(u8, state, "enrolled"))
            true
        else if (std.mem.eql(u8, state, "unenrolled"))
            false
        else
            return error.CorruptInventory;
        if (try statement.step() != .done) return error.CorruptInventory;
        return enrolled;
    }

    /// Generic inventory reconciliation must not become an alternate public-
    /// key or enrollment-state mutation path. Existing bindings may change
    /// only through consume/reset, and a newly inserted Node must begin
    /// unenrolled. The check runs under the same immediate transaction and
    /// generation precondition as the subsequent reconciliation.
    fn requireEnrollmentProjection(self: Repository, candidate: *const model.Store) !void {
        var lookup = try self.db.prepare(
            "SELECT enrollment_state, public_key FROM nodes WHERE id = ?1;",
        );
        defer lookup.deinit();

        for (candidate.nodes.items) |node| {
            try lookup.bindBlob(1, &node.id.bytes);
            switch (try lookup.step()) {
                .done => {
                    if (node.enrollment_state != .unenrolled or node.public_key != null) {
                        return error.InvalidEnrollmentProjection;
                    }
                },
                .row => {
                    const state_text = lookup.columnText(0) orelse
                        return error.CorruptInventory;
                    const state: model.EnrollmentState = if (std.mem.eql(u8, state_text, "unenrolled"))
                        .unenrolled
                    else if (std.mem.eql(u8, state_text, "enrolled"))
                        .enrolled
                    else
                        return error.CorruptInventory;
                    if (state != node.enrollment_state or
                        !optionalPublicKeysEqual(lookup.columnBlob(1), node.public_key))
                    {
                        return error.InvalidEnrollmentProjection;
                    }
                    if (try lookup.step() != .done) return error.CorruptInventory;
                },
            }
            try lookup.reset();
            try lookup.clearBindings();
        }
    }

    fn reconcileInventory(self: Repository, candidate: *const model.Store, now: i64) !void {
        // Remove route identities absent from the candidate before deleting
        // Nodes. Retained IDs are upserted below so creation time and revision
        // survive both prefix and owner edits.
        var existing_routes = try self.db.prepare("SELECT id, network, prefix FROM routes;");
        defer existing_routes.deinit();
        var delete_route = try self.db.prepare("DELETE FROM routes WHERE id = ?1;");
        defer delete_route.deinit();
        while (try existing_routes.step() == .row) {
            const id_blob = existing_routes.columnBlob(0) orelse return error.CorruptInventory;
            if (id_blob.len != 16) return error.CorruptInventory;
            var id: [16]u8 = undefined;
            @memcpy(&id, id_blob);
            if (candidate.findRouteById(.{ .bytes = id }) != null) continue;
            try delete_route.bindBlob(1, &id);
            if (try delete_route.step() != .done) return error.UnexpectedRow;
            try delete_route.reset();
            try delete_route.clearBindings();
        }

        var existing_nodes = try self.db.prepare("SELECT id FROM nodes;");
        defer existing_nodes.deinit();
        var delete_node = try self.db.prepare("DELETE FROM nodes WHERE id = ?1;");
        defer delete_node.deinit();
        while (try existing_nodes.step() == .row) {
            const blob = existing_nodes.columnBlob(0) orelse return error.CorruptInventory;
            if (blob.len != 16) return error.CorruptInventory;
            var id: model.NodeId = undefined;
            @memcpy(&id.bytes, blob);
            if (candidate.findNodeById(id) != null) continue;
            try delete_node.bindBlob(1, &id.bytes);
            if (try delete_node.step() != .done) return error.UnexpectedRow;
            try delete_node.reset();
            try delete_node.clearBindings();
        }

        var existing_vnrs = try self.db.prepare("SELECT name FROM vnrs;");
        defer existing_vnrs.deinit();
        var delete_vnr = try self.db.prepare("DELETE FROM vnrs WHERE name = ?1;");
        defer delete_vnr.deinit();
        while (try existing_vnrs.step() == .row) {
            const text = existing_vnrs.columnText(0) orelse return error.CorruptInventory;
            const name = model.Name.parse(text) catch return error.CorruptInventory;
            if (candidate.findVnr(name.slice()) != null) continue;
            try delete_vnr.bindText(1, name.slice());
            if (try delete_vnr.step() != .done) return error.UnexpectedRow;
            try delete_vnr.reset();
            try delete_vnr.clearBindings();
        }

        var upsert_vnr = try self.db.prepare(
            "INSERT INTO vnrs " ++
                "(name, network, prefix, revision, created_at, updated_at) " ++
                "VALUES (?1, ?2, ?3, 1, ?4, ?4) " ++
                "ON CONFLICT(name) DO UPDATE SET " ++
                "network = excluded.network, prefix = excluded.prefix, " ++
                "revision = CASE WHEN network != excluded.network OR prefix != excluded.prefix " ++
                "THEN revision + 1 ELSE revision END, " ++
                "updated_at = CASE WHEN network != excluded.network OR prefix != excluded.prefix " ++
                "THEN excluded.updated_at ELSE updated_at END;",
        );
        defer upsert_vnr.deinit();
        for (candidate.vnrs.items) |vnr| {
            try upsert_vnr.bindText(1, vnr.name.slice());
            try upsert_vnr.bindInt64(2, vnr.range.network.value);
            try upsert_vnr.bindInt64(3, vnr.range.prefix);
            try upsert_vnr.bindInt64(4, now);
            if (try upsert_vnr.step() != .done) return error.UnexpectedRow;
            try upsert_vnr.reset();
            try upsert_vnr.clearBindings();
        }

        var upsert_node = try self.db.prepare(
            "INSERT INTO nodes " ++
                "(id, name, vnr_name, address, enrollment_state, public_key, " ++
                "revision, created_at, updated_at) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7, ?7) " ++
                "ON CONFLICT(id) DO UPDATE SET " ++
                "name = excluded.name, vnr_name = excluded.vnr_name, address = excluded.address, " ++
                "enrollment_state = excluded.enrollment_state, public_key = excluded.public_key, " ++
                "revision = CASE WHEN name != excluded.name OR vnr_name != excluded.vnr_name OR " ++
                "address != excluded.address OR enrollment_state != excluded.enrollment_state OR " ++
                "public_key IS NOT excluded.public_key THEN revision + 1 ELSE revision END, " ++
                "updated_at = CASE WHEN name != excluded.name OR vnr_name != excluded.vnr_name OR " ++
                "address != excluded.address OR enrollment_state != excluded.enrollment_state OR " ++
                "public_key IS NOT excluded.public_key THEN excluded.updated_at ELSE updated_at END;",
        );
        defer upsert_node.deinit();
        for (candidate.nodes.items) |node| {
            try upsert_node.bindBlob(1, &node.id.bytes);
            try upsert_node.bindText(2, node.name.slice());
            try upsert_node.bindText(3, node.vnr.slice());
            try upsert_node.bindInt64(4, node.address.value);
            try upsert_node.bindText(5, @tagName(node.enrollment_state));
            if (node.public_key) |key| {
                try upsert_node.bindBlob(6, &key);
            } else {
                try upsert_node.bindNull(6);
            }
            try upsert_node.bindInt64(7, now);
            if (try upsert_node.step() != .done) return error.UnexpectedRow;
            try upsert_node.reset();
            try upsert_node.clearBindings();
        }

        var insert_route = try self.db.prepare(
            "INSERT INTO routes " ++
                "(id, network, prefix, node_id, revision, created_at, updated_at) " ++
                "VALUES (?1, ?2, ?3, ?4, 1, ?5, ?5) " ++
                "ON CONFLICT(id) DO UPDATE SET " ++
                "network = excluded.network, prefix = excluded.prefix, node_id = excluded.node_id, " ++
                "revision = CASE WHEN network != excluded.network OR prefix != excluded.prefix OR node_id != excluded.node_id " ++
                "THEN revision + 1 ELSE revision END, " ++
                "updated_at = CASE WHEN network != excluded.network OR prefix != excluded.prefix OR node_id != excluded.node_id " ++
                "THEN excluded.updated_at ELSE updated_at END;",
        );
        defer insert_route.deinit();
        for (candidate.routes.items) |route| {
            const node = candidate.findNode(route.node.slice()) orelse return error.NodeNotFound;
            try insert_route.bindBlob(1, &route.id.bytes);
            try insert_route.bindInt64(2, route.prefix.network.value);
            try insert_route.bindInt64(3, route.prefix.prefix);
            try insert_route.bindBlob(4, &node.id.bytes);
            try insert_route.bindInt64(5, now);
            if (try insert_route.step() != .done) return error.UnexpectedRow;
            try insert_route.reset();
            try insert_route.clearBindings();
        }
    }

    fn insertAudit(self: Repository, audit: AuditEntry) !void {
        if (audit.occurred_at < 0) return error.InvalidAuditEntry;
        if (audit.actor_kind == .web) self.db.armCommitHook();
        var statement = try self.db.prepare(
            "INSERT INTO audit_entries " ++
                "(id, occurred_at, actor_kind, actor_id, action, resource_type, " ++
                "resource_id, request_id, details_json) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &audit.id);
        try statement.bindInt64(2, audit.occurred_at);
        try statement.bindText(3, audit.actor_kind.databaseValue());
        if (audit.actor_id) |actor_id| {
            try statement.bindBlob(4, &actor_id);
        } else {
            try statement.bindNull(4);
        }
        try statement.bindText(5, audit.action);
        try statement.bindText(6, audit.resource_type);
        try statement.bindText(7, audit.resource_id);
        if (audit.request_id) |request_id| {
            try statement.bindBlob(8, &request_id);
        } else {
            try statement.bindNull(8);
        }
        try statement.bindText(9, audit.details_json);
        if (try statement.step() != .done) return error.UnexpectedRow;
    }
};

fn validateProjection(candidate: *const model.Store) !void {
    // CIDRs loaded from SQLite or supplied by a non-parser caller are not
    // automatically canonical merely because their fields fit. Guard the
    // prefix before calling helpers whose bit shifts assume 0...32, then
    // reject host bits in every durable network value.
    for (candidate.vnrs.items) |vnr| {
        if (!canonicalCidr(vnr.range)) return error.InvalidVnrRange;
    }
    for (candidate.routes.items) |route| {
        if (!canonicalCidr(route.prefix)) return error.InvalidRouteRange;
    }
    try candidate.validate();
    // `Store.validate` protects cross-object invariants. Keep the repository's
    // durable-input boundary explicit about per-route canonical/reserved range
    // checks as well, even if a caller bypassed `Store.addRoute`.
    for (candidate.routes.items) |route| try route.prefix.validateRouted();
}

fn canonicalCidr(value: model.Cidr) bool {
    if (value.prefix > 32) return false;
    return value.network.value & ~model.Cidr.mask(value.prefix) == 0;
}

fn checkedNextGeneration(expected: u64) !u64 {
    const next = std.math.add(u64, expected, 1) catch return error.GenerationOverflow;
    if (next > std.math.maxInt(i64)) return error.GenerationOverflow;
    return next;
}

fn positiveU64(value: i64) !u64 {
    if (value <= 0) return error.CorruptSettingsState;
    return @intCast(value);
}

const SettingsStatus = enum {
    pending_apply,
    active,
    failed,
    pending_restart,
};

fn settingsStatus(value: ?[]const u8) !SettingsStatus {
    const text = value orelse return error.CorruptSettingsState;
    return std.meta.stringToEnum(SettingsStatus, text) orelse return error.CorruptSettingsState;
}

fn settingsCapacity(value: i64) !u32 {
    if (value <= 0 or value > 65_536) return error.CorruptSettingsState;
    return @intCast(value);
}

fn columnU32(statement: *const sqlite.Statement, index: c_int) !u32 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u32)) return error.CorruptInventory;
    return @intCast(value);
}

fn columnU8(statement: *const sqlite.Statement, index: c_int) !u8 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u8)) return error.CorruptInventory;
    return @intCast(value);
}

fn timingSafeEql32(stored: []const u8, presented: *const [32]u8) bool {
    std.debug.assert(stored.len == 32);
    var difference: u8 = 0;
    for (stored, presented) |left, right| difference |= left ^ right;
    return difference == 0;
}

fn optionalPublicKeysEqual(stored: ?[]const u8, projected: ?[32]u8) bool {
    if (stored == null or projected == null) return stored == null and projected == null;
    return stored.?.len == 32 and std.mem.eql(u8, stored.?, &projected.?);
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testAudit(byte: u8, action: []const u8, occurred_at: i64) AuditEntry {
    return .{
        .id = [_]u8{byte} ** 16,
        .occurred_at = occurred_at,
        .actor_kind = .system,
        .action = action,
        .resource_type = "inventory",
    };
}

fn insertDesiredSettingsForTest(
    db: *sqlite.Database,
    id_byte: u8,
    sequence: u64,
    based_on_sequence: u64,
    status: []const u8,
    inner_mtu: u16,
    maximum_nodes: u32,
) !void {
    var statement = try db.prepare(
        "INSERT INTO settings_revisions (" ++
            "id,revision,based_on_revision,status,failure_code,actor_kind,actor_id," ++
            "created_at,applied_at,inner_mtu,heartbeat_seconds,suspect_seconds,offline_seconds," ++
            "default_enrollment_lifetime_seconds,maximum_nodes,traffic_cold_seconds," ++
            "traffic_hot_packets_per_second,traffic_hot_bits_per_second," ++
            "traffic_saturated_queue_percent,traffic_hysteresis_seconds," ++
            "runtime_event_retention_days,connectivity_retention_days) " ++
            "SELECT ?1,?2,?3,?4,NULL,'system',NULL,?2,NULL,?5," ++
            "heartbeat_seconds,suspect_seconds,offline_seconds," ++
            "default_enrollment_lifetime_seconds,?6,traffic_cold_seconds," ++
            "traffic_hot_packets_per_second,traffic_hot_bits_per_second," ++
            "traffic_saturated_queue_percent,traffic_hysteresis_seconds," ++
            "runtime_event_retention_days,connectivity_retention_days " ++
            "FROM settings_revisions WHERE revision=1;",
    );
    defer statement.deinit();
    const id = [_]u8{id_byte} ** 16;
    try statement.bindBlob(1, &id);
    try statement.bindInt64(2, sequence);
    try statement.bindInt64(3, based_on_sequence);
    try statement.bindText(4, status);
    try statement.bindInt64(5, inner_mtu);
    try statement.bindInt64(6, maximum_nodes);
    if (try statement.step() != .done or db.changes() != 1) return error.UnexpectedRow;
    var pointer = try db.prepare(
        "UPDATE settings_state SET desired_revision=?1 WHERE singleton=1;",
    );
    defer pointer.deinit();
    try pointer.bindInt64(1, sequence);
    if (try pointer.step() != .done or db.changes() != 1) return error.UnexpectedRow;
}

fn testInventory(allocator: std.mem.Allocator) !model.Store {
    var store = model.Store.init(allocator);
    errdefer store.deinit();
    _ = try store.createVnr("core", try model.Cidr.parse("10.24.0.0/24"));
    try store.createNode(
        .{ .bytes = [_]u8{0x11} ** 16 },
        "edge-a",
        "core",
        try model.Ipv4.parse("10.24.0.2"),
    );
    try store.addRoute(try model.Cidr.parse("172.20.0.0/24"), "edge-a");
    // A fresh database publishes a complete bootstrap projection once.
    store.generation = 1;
    return store;
}

fn scalarInt(db: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try db.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const result = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return result;
}

test "inventory, audit, and one durable generation commit atomically" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    try std.testing.expectEqual(@as(u64, 1), try repository.persistInventory(
        &candidate,
        0,
        100,
        testAudit(1, "inventory.bootstrap", 100),
    ));

    var loaded = try repository.loadInventory(std.testing.allocator);
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u64, 1), loaded.generation);
    try std.testing.expect(loaded.findVnr("core") != null);
    try std.testing.expect(loaded.findNode("edge-a") != null);
    try std.testing.expect(loaded.findRoute(try model.Cidr.parse("172.20.0.0/24")) != null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
}

test "pending capacity reduction blocks transactional Node admission while failed desired does not" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    _ = try repository.persistInventory(
        &candidate,
        0,
        100,
        testAudit(0x31, "inventory.bootstrap", 100),
    );
    try std.testing.expectEqual(@as(u32, 4096), try repository.nodeAdmissionCapacity());

    // A pure restart-only reduction to the current count must reserve that
    // count before the runtime itself is reconstructed at the lower bound.
    try insertDesiredSettingsForTest(&db, 0x41, 2, 1, "pending_restart", 1380, 1);
    try std.testing.expectEqual(@as(u32, 1), try repository.nodeAdmissionCapacity());
    const second_node: model.NodeId = .{ .bytes = [_]u8{0x22} ** 16 };
    try candidate.createNode(
        second_node,
        "edge-b",
        "core",
        try model.Ipv4.parse("10.24.0.3"),
    );
    const enrollment: PendingEnrollment = .{
        .node_id = second_node,
        .handle = [_]u8{0x51} ** 16,
        .derived_psk = [_]u8{0x61} ** 32,
        .expires_at = 300,
    };
    try std.testing.expectError(
        error.MaximumNodesExceeded,
        repository.persistInventoryWithEnrollment(
            &candidate,
            enrollment,
            1,
            110,
            testAudit(0x32, "node.create.blocked", 110),
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.durableGeneration());
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM nodes;"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(
        &db,
        "SELECT count(*) FROM enrollment_credentials;",
    ));

    // Model a later mixed revision whose live application failed. Its lower
    // desired capacity is historical only; the effective capacity remains
    // the admission and restore boundary.
    try insertDesiredSettingsForTest(&db, 0x42, 3, 2, "pending_apply", 1400, 1);
    try db.exec(
        "UPDATE settings_revisions SET status='failed'," ++
            "failure_code='runtime_apply_failed' WHERE revision=3;",
    );
    try std.testing.expectEqual(@as(u32, 4096), try repository.nodeAdmissionCapacity());
    try std.testing.expectEqual(@as(u64, 2), try repository.persistInventoryWithEnrollment(
        &candidate,
        enrollment,
        1,
        120,
        testAudit(0x33, "node.create", 120),
    ));
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT count(*) FROM nodes;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &db,
        "SELECT count(*) FROM enrollment_credentials WHERE status='unused';",
    ));
}

test "Node creation and initial enrollment are one durable mutation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    const node_id: model.NodeId = .{ .bytes = [_]u8{0x11} ** 16 };
    const enrollment: PendingEnrollment = .{
        .node_id = node_id,
        .handle = [_]u8{0x51} ** 16,
        .derived_psk = [_]u8{0x61} ** 32,
        .expires_at = 200,
    };
    try std.testing.expectEqual(@as(u64, 1), try repository.persistInventoryWithEnrollment(
        &candidate,
        enrollment,
        0,
        100,
        testAudit(20, "node.create", 100),
    ));
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused' AND derived_psk IS NOT NULL;"),
    );

    try candidate.updateNode(
        node_id,
        "edge-b",
        "core",
        try model.Ipv4.parse("10.24.0.3"),
    );
    try std.testing.expectError(
        error.EnrollmentConstraintViolation,
        repository.persistInventoryWithEnrollment(
            &candidate,
            enrollment,
            1,
            101,
            testAudit(21, "node.update", 101),
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.durableGeneration());
    var loaded = try repository.loadInventory(std.testing.allocator);
    defer loaded.deinit();
    try std.testing.expect(loaded.findNode("edge-a") != null);
    try std.testing.expect(loaded.findNode("edge-b") == null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
}

test "route identity survives prefix and owner edits" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    _ = try repository.persistInventory(&candidate, 0, 100, testAudit(22, "bootstrap", 100));
    const route_id = candidate.routes.items[0].id;

    try candidate.updateRoute(
        try model.Cidr.parse("172.20.0.0/24"),
        try model.Cidr.parse("172.21.0.0/24"),
        "edge-a",
    );
    _ = try repository.persistInventory(&candidate, 1, 101, testAudit(23, "route.update", 101));

    var loaded = try repository.loadInventory(std.testing.allocator);
    defer loaded.deinit();
    const route = loaded.findRoute(try model.Cidr.parse("172.21.0.0/24")) orelse
        return error.TestExpectedEqual;
    try std.testing.expect(route.id.eql(route_id));
    try std.testing.expect(loaded.findRoute(try model.Cidr.parse("172.20.0.0/24")) == null);
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT revision FROM routes;"));
}

test "stale preconditions and invalid candidates leave no partial rows" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    _ = try repository.persistInventory(&candidate, 0, 100, testAudit(2, "bootstrap", 100));

    try candidate.updateNode(
        .{ .bytes = [_]u8{0x11} ** 16 },
        "edge-b",
        "core",
        try model.Ipv4.parse("10.24.0.3"),
    );
    candidate.generation = 1;
    try std.testing.expectError(
        error.PreconditionFailed,
        repository.persistInventory(&candidate, 0, 101, testAudit(3, "node.update", 101)),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.durableGeneration());
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));

    try candidate.vnrs.append(std.testing.allocator, .{
        .name = try model.Name.parse("overlap"),
        .range = try model.Cidr.parse("10.24.0.128/25"),
    });
    candidate.generation = 2;
    try std.testing.expectError(
        error.VnrOverlap,
        repository.persistInventory(&candidate, 1, 102, testAudit(4, "invalid", 102)),
    );
    var loaded = try repository.loadInventory(std.testing.allocator);
    defer loaded.deinit();
    try std.testing.expect(loaded.findNode("edge-a") != null);
    try std.testing.expect(loaded.findNode("edge-b") == null);
}

test "audit constraint failure rolls inventory and generation back" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    const repeated_audit = testAudit(5, "bootstrap", 100);
    _ = try repository.persistInventory(&candidate, 0, 100, repeated_audit);
    try candidate.updateNode(
        .{ .bytes = [_]u8{0x11} ** 16 },
        "edge-b",
        "core",
        try model.Ipv4.parse("10.24.0.3"),
    );
    try std.testing.expectError(
        error.InvalidAuditEntry,
        repository.persistInventory(&candidate, 1, 101, repeated_audit),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.durableGeneration());
    var loaded = try repository.loadInventory(std.testing.allocator);
    defer loaded.deinit();
    try std.testing.expect(loaded.findNode("edge-a") != null);
    try std.testing.expect(loaded.findNode("edge-b") == null);
}

test "generic inventory persistence cannot mutate enrollment bindings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    _ = try repository.persistInventory(&candidate, 0, 100, testAudit(6, "bootstrap", 100));

    candidate.nodes.items[0].enrollment_state = .enrolled;
    candidate.nodes.items[0].public_key = [_]u8{0x61} ** 32;
    candidate.generation = 2;
    try std.testing.expectError(
        error.InvalidEnrollmentProjection,
        repository.persistInventory(
            &candidate,
            1,
            101,
            testAudit(7, "inventory.invalid_enrollment", 101),
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.durableGeneration());
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM audit_entries;"),
    );
    try std.testing.expectEqual(
        @as(i64, 0),
        try scalarInt(&db, "SELECT count(*) FROM nodes WHERE enrollment_state = 'enrolled';"),
    );
}

test "enrollment replacement consumption and revocation clear derived secrets" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    _ = try repository.persistInventory(&candidate, 0, 100, testAudit(10, "bootstrap", 100));
    const node_id: model.NodeId = .{ .bytes = [_]u8{0x11} ** 16 };
    const first_handle = [_]u8{0x21} ** 16;
    const second_handle = [_]u8{0x22} ** 16;
    const third_handle = [_]u8{0x23} ** 16;
    const first_psk = [_]u8{0x31} ** 32;
    const second_psk = [_]u8{0x32} ** 32;
    const third_psk = [_]u8{0x33} ** 32;

    _ = try repository.replaceEnrollment(
        node_id,
        first_handle,
        first_psk,
        false,
        110,
        210,
        1,
        testAudit(11, "enrollment.issue", 110),
    );
    _ = try repository.replaceEnrollment(
        node_id,
        second_handle,
        second_psk,
        false,
        120,
        220,
        2,
        testAudit(12, "enrollment.replace", 120),
    );
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'revoked' AND derived_psk IS NULL;"),
    );

    var wrong_psk = second_psk;
    wrong_psk[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEnrollmentCredential,
        repository.consumeEnrollment(
            second_handle,
            wrong_psk,
            [_]u8{0x41} ** 32,
            130,
            3,
            testAudit(13, "enrollment.consume", 130),
        ),
    );
    try std.testing.expectEqual(@as(u64, 3), try repository.durableGeneration());

    const consumed = try repository.consumeEnrollment(
        second_handle,
        second_psk,
        [_]u8{0x41} ** 32,
        131,
        3,
        testAudit(14, "enrollment.consume", 131),
    );
    try std.testing.expect(consumed.node_id.eql(node_id));
    try std.testing.expectEqual(@as(u64, 4), consumed.generation);
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'consumed' AND derived_psk IS NULL;"),
    );

    try std.testing.expectError(
        error.NodeAlreadyEnrolled,
        repository.replaceEnrollment(
            node_id,
            third_handle,
            third_psk,
            false,
            140,
            240,
            4,
            testAudit(15, "enrollment.issue", 140),
        ),
    );
    try std.testing.expectEqual(@as(u64, 4), try repository.durableGeneration());
    _ = try repository.replaceEnrollment(
        node_id,
        third_handle,
        third_psk,
        true,
        141,
        241,
        4,
        testAudit(16, "enrollment.reset", 141),
    );
    _ = try repository.revokeEnrollment(
        third_handle,
        150,
        5,
        testAudit(17, "enrollment.revoke", 150),
    );
    try std.testing.expectEqual(
        @as(i64, 3),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE derived_psk IS NULL;"),
    );
    try std.testing.expectEqual(@as(i64, 6), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
}

test "credential-free enrollment reset is atomic and inserts no replacement" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    var candidate = try testInventory(std.testing.allocator);
    defer candidate.deinit();
    _ = try repository.persistInventory(&candidate, 0, 100, testAudit(30, "bootstrap", 100));
    const node_id: model.NodeId = .{ .bytes = [_]u8{0x11} ** 16 };
    const repeated_audit = testAudit(31, "enrollment.credential.issue", 110);
    _ = try repository.replaceEnrollment(
        node_id,
        [_]u8{0x41} ** 16,
        [_]u8{0x51} ** 32,
        false,
        110,
        210,
        1,
        repeated_audit,
    );

    // An audit constraint failure proves the verifier clear and generation
    // advance are inside the same transaction.
    try std.testing.expectError(
        error.InvalidAuditEntry,
        repository.resetEnrollment(node_id, 120, 2, repeated_audit),
    );
    try std.testing.expectEqual(@as(u64, 2), try repository.durableGeneration());
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused' AND derived_psk IS NOT NULL;"),
    );

    try std.testing.expectEqual(@as(u64, 3), try repository.resetEnrollment(
        node_id,
        121,
        2,
        testAudit(32, "enrollment.reset", 121),
    ));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials;"));
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'revoked' AND derived_psk IS NULL;"),
    );
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT revision FROM nodes WHERE id = x'11111111111111111111111111111111';"),
    );
    try std.testing.expectEqual(@as(i64, 3), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
}

test "durable inventory rejects noncanonical and reserved CIDRs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = Repository.init(&db);

    // SQL integer/prefix checks cannot express CIDR canonicality. Durable
    // input validation must reject host bits even if the file was modified
    // with foreign keys and ordinary CHECK constraints enabled.
    try db.exec(
        "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
            "VALUES ('bad',167772161,24,1,1,1);",
    );
    try std.testing.expectError(
        error.CorruptInventory,
        repository.loadInventory(std.testing.allocator),
    );
    try db.exec("DELETE FROM vnrs WHERE name = 'bad';");

    try db.exec(
        "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
            "VALUES ('core',167772160,24,1,1,1);" ++
            "INSERT INTO nodes (id,name,vnr_name,address,created_at,updated_at) VALUES " ++
            "(X'11111111111111111111111111111111','edge-a','core',167772162,1,1);" ++
            "INSERT INTO routes (id,network,prefix,node_id,created_at,updated_at) VALUES " ++
            "(X'12121212121212121212121212121212',2130706432,8," ++
            "X'11111111111111111111111111111111',1,1);",
    );
    try std.testing.expectError(
        error.CorruptInventory,
        repository.loadInventory(std.testing.allocator),
    );
}
