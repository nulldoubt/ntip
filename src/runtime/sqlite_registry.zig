//! SQLite-backed handshake registry for the authoritative Master.
//!
//! The operator worker owns the database, this adapter, and the mutable
//! `model.Store`. Enrollment lookup is read-only. Completion delegates the
//! credential verification, credential consumption, Node key binding, audit
//! insertion, and generation advance to one repository transaction. Only
//! after that transaction commits does the adapter update and publish its
//! in-memory projection, preserving the coordinator's persist-before-session-
//! install boundary.

const std = @import("std");
const model = @import("../domain/model.zig");
const management_repository = @import("../state/management_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const handshake = @import("handshake_coordinator.zig");

pub const WallClock = union(enum) {
    system,
    fixed: i64,

    pub fn nowSeconds(self: WallClock, io: std.Io) !i64 {
        return switch (self) {
            .fixed => |seconds| if (seconds < 0) error.ClockBeforeUnixEpoch else seconds,
            .system => blk: {
                const seconds = std.Io.Clock.real.now(io).toSeconds();
                if (seconds < 0) return error.ClockBeforeUnixEpoch;
                if (seconds > std.math.maxInt(i64)) return error.ClockOutOfRange;
                break :blk @intCast(seconds);
            },
        };
    }
};

/// Audit IDs are random in production. The fixed source is intentionally
/// exposed for deterministic transaction-rollback tests.
pub const AuditIdSource = union(enum) {
    random,
    fixed: [16]u8,

    fn next(self: AuditIdSource, io: std.Io) [16]u8 {
        return switch (self) {
            .fixed => |id| id,
            .random => blk: {
                var id: [16]u8 = undefined;
                io.random(&id);
                id[6] = (id[6] & 0x0f) | 0x40;
                id[8] = (id[8] & 0x3f) | 0x80;
                break :blk id;
            },
        };
    }
};

/// Runs synchronously after both the durable commit and the in-memory Store
/// update. The callback receives a read-only view valid only for the duration
/// of the call and must copy any immutable projection it wants to retain.
pub const GenerationPublisher = struct {
    context: *anyopaque,
    publish_fn: *const fn (*anyopaque, *const model.Store, u64) void,

    pub fn publish(self: GenerationPublisher, store: *const model.Store, generation: u64) void {
        self.publish_fn(self.context, store, generation);
    }
};

pub const MasterRegistryAdapter = struct {
    io: std.Io,
    repository: management_repository.Repository,
    store: *model.Store,
    clock: WallClock = .system,
    audit_ids: AuditIdSource = .random,
    publisher: ?GenerationPublisher = null,

    pub fn init(
        io: std.Io,
        db: *sqlite.Database,
        store: *model.Store,
    ) MasterRegistryAdapter {
        return .{
            .io = io,
            .repository = management_repository.Repository.init(db),
            .store = store,
        };
    }

    pub fn interface(self: *MasterRegistryAdapter) handshake.MasterRegistry {
        return .{
            .context = self,
            .lookup_enrollment_fn = lookupEnrollmentOpaque,
            .consume_and_bind_fn = consumeAndBindOpaque,
            .lookup_node_fn = lookupNodeOpaque,
        };
    }

    /// Resolves only an unused, unexpired verifier and its current assignment.
    /// The raw browser credential is never present in this database or DTO.
    pub fn lookupEnrollment(self: *MasterRegistryAdapter, handle: [16]u8) !handshake.EnrollmentRecord {
        if (allZero(&handle)) return error.EnrollmentNotFound;
        const now = try self.clock.nowSeconds(self.io);

        var statement = try self.repository.db.prepare(
            "SELECT credentials.node_id, credentials.derived_psk, " ++
                "credentials.expires_at, credentials.status, nodes.address, " ++
                "nodes.enrollment_state, nodes.public_key, vnrs.network, " ++
                "vnrs.prefix, master_state.durable_generation " ++
                "FROM enrollment_credentials AS credentials " ++
                "JOIN nodes ON nodes.id = credentials.node_id " ++
                "JOIN vnrs ON vnrs.name = nodes.vnr_name " ++
                "CROSS JOIN master_state " ++
                "WHERE credentials.handle = ?1 AND master_state.singleton = 1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &handle);
        if (try statement.step() != .row) return error.EnrollmentNotFound;

        const node_blob = statement.columnBlob(0) orelse return error.InvalidEnrollmentState;
        if (node_blob.len != 16) return error.InvalidEnrollmentState;
        var node_uuid: [16]u8 = undefined;
        @memcpy(&node_uuid, node_blob);
        validateNodeUuid(node_uuid) catch return error.InvalidEnrollmentState;

        const psk_blob = statement.columnBlob(1);
        const expires_at = statement.columnInt64(2);
        const status = statement.columnText(3) orelse return error.InvalidEnrollmentState;
        if (std.mem.eql(u8, status, "consumed")) return error.EnrollmentConsumed;
        if (std.mem.eql(u8, status, "revoked")) return error.EnrollmentRevoked;
        if (!std.mem.eql(u8, status, "unused")) return error.InvalidEnrollmentState;
        if (expires_at < 0 or now >= expires_at) return error.EnrollmentExpired;
        const stored_psk = psk_blob orelse return error.InvalidEnrollmentState;
        if (stored_psk.len != 32) return error.InvalidEnrollmentState;
        var derived_psk: [32]u8 = undefined;
        @memcpy(&derived_psk, stored_psk);
        errdefer std.crypto.secureZero(u8, &derived_psk);
        if (allZero(&derived_psk)) return error.InvalidEnrollmentState;

        const assigned_address = try columnU32(&statement, 4);
        const enrollment_state = statement.columnText(5) orelse return error.InvalidEnrollmentState;
        if (!std.mem.eql(u8, enrollment_state, "unenrolled") or statement.columnBlob(6) != null) {
            return error.NodeAlreadyEnrolled;
        }
        const vnr_network = try columnU32(&statement, 7);
        const vnr_prefix = try columnU8(&statement, 8);
        const generation = try columnU64(&statement, 9);
        if (try statement.step() != .done) return error.InvalidEnrollmentState;

        const range = model.Cidr{
            .network = .{ .value = vnr_network },
            .prefix = vnr_prefix,
        };
        range.validateVnr() catch return error.InvalidEnrollmentState;
        const address = model.Ipv4{ .value = assigned_address };
        if (!range.isUsableHost(address) or address.value == range.firstUsable().?.value) {
            return error.InvalidEnrollmentState;
        }

        return .{
            .node_uuid = node_uuid,
            .assigned_ipv4 = address.octets(),
            .vnr_network = range.network.octets(),
            .vnr_prefix_len = range.prefix,
            .config_generation = generation,
            .owner = ownerFromUuid(node_uuid),
            .psk = derived_psk,
        };
    }

    /// Rechecks the exact PSK inside the repository transaction. A credential
    /// replaced after the handshake lookup therefore cannot consume either
    /// its revoked predecessor or its successor with stale key material.
    pub fn consumeAndBind(
        self: *MasterRegistryAdapter,
        handle: [16]u8,
        node_uuid: [16]u8,
        verified_psk: [32]u8,
        public_key: [32]u8,
    ) !void {
        if (allZero(&handle)) return error.EnrollmentNotFound;
        try validateNodeUuid(node_uuid);
        if (allZero(&public_key)) return error.InvalidPublicKey;
        if (allZero(&verified_psk)) return error.InvalidEnrollmentCredential;

        var checked_psk = verified_psk;
        defer std.crypto.secureZero(u8, &checked_psk);
        var current = try self.lookupEnrollment(handle);
        defer std.crypto.secureZero(u8, &current.psk);
        if (!timingSafeEqual(&current.node_uuid, &node_uuid)) return error.RegistryIdentityMismatch;
        if (!timingSafeEqual(&current.psk, &checked_psk)) return error.InvalidEnrollmentCredential;
        const node_index = try self.requireMatchingProjection(current);
        const now = try self.clock.nowSeconds(self.io);

        var node_id_text: [32]u8 = undefined;
        const resource_id = (model.NodeId{ .bytes = node_uuid }).write(&node_id_text);
        const consumed = try self.repository.consumeEnrollment(
            handle,
            checked_psk,
            public_key,
            now,
            current.config_generation,
            .{
                .id = self.audit_ids.next(self.io),
                .occurred_at = now,
                .actor_kind = .system,
                .action = "enrollment.consume",
                .resource_type = "node",
                .resource_id = resource_id,
                .details_json = "{\"source\":\"handshake\"}",
            },
        );
        if (!consumed.node_id.eql(.{ .bytes = node_uuid })) {
            // This cannot occur through the repository API because a handle's
            // Node binding is immutable. Fail closed if a database modified
            // outside the serialized owner violates that contract.
            return error.RegistryIdentityMismatchAfterCommit;
        }
        if (consumed.generation != current.config_generation + 1) {
            return error.InvalidCommittedGeneration;
        }

        // No fallible work occurs between the durable commit and projection
        // install. The preflight above proved this exact slot corresponds to
        // the committed Node; SQLite proved key uniqueness transactionally.
        self.store.nodes.items[node_index].public_key = public_key;
        self.store.nodes.items[node_index].enrollment_state = .enrolled;
        self.store.generation = consumed.generation;
        if (self.publisher) |publisher| publisher.publish(self.store, consumed.generation);
    }

    pub fn lookupNode(self: *MasterRegistryAdapter, node_uuid: [16]u8) !handshake.NodeRecord {
        validateNodeUuid(node_uuid) catch return error.NodeNotFound;
        var statement = try self.repository.db.prepare(
            "SELECT nodes.enrollment_state, nodes.public_key, nodes.address, " ++
                "vnrs.network, vnrs.prefix, master_state.durable_generation " ++
                "FROM nodes JOIN vnrs ON vnrs.name = nodes.vnr_name " ++
                "CROSS JOIN master_state " ++
                "WHERE nodes.id = ?1 AND master_state.singleton = 1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &node_uuid);
        if (try statement.step() != .row) return error.NodeNotFound;
        const state = statement.columnText(0) orelse return error.InvalidEnrollmentState;
        if (!std.mem.eql(u8, state, "enrolled")) return error.NodeNotEnrolled;
        const key_blob = statement.columnBlob(1) orelse return error.InvalidEnrollmentState;
        if (key_blob.len != 32) return error.InvalidEnrollmentState;
        var public_key: [32]u8 = undefined;
        @memcpy(&public_key, key_blob);
        if (allZero(&public_key)) return error.InvalidPublicKey;
        const address = model.Ipv4{ .value = try columnU32(&statement, 2) };
        const range = model.Cidr{
            .network = .{ .value = try columnU32(&statement, 3) },
            .prefix = try columnU8(&statement, 4),
        };
        const generation = try columnU64(&statement, 5);
        if (try statement.step() != .done) return error.InvalidEnrollmentState;
        range.validateVnr() catch return error.InvalidEnrollmentState;
        if (!range.isUsableHost(address) or address.value == range.firstUsable().?.value) {
            return error.InvalidEnrollmentState;
        }
        return .{
            .node_uuid = node_uuid,
            .public_key = public_key,
            .config_generation = generation,
            .owner = ownerFromUuid(node_uuid),
        };
    }

    fn requireMatchingProjection(
        self: *MasterRegistryAdapter,
        current: handshake.EnrollmentRecord,
    ) !usize {
        if (self.store.generation != current.config_generation) return error.StoreProjectionStale;
        const node_id: model.NodeId = .{ .bytes = current.node_uuid };
        var node_index: ?usize = null;
        for (self.store.nodes.items, 0..) |node, index| {
            if (node.id.eql(node_id)) node_index = index;
        }
        const index = node_index orelse return error.StoreProjectionStale;
        const node = &self.store.nodes.items[index];
        if (node.enrollment_state != .unenrolled or node.public_key != null) {
            return error.StoreProjectionStale;
        }
        const vnr = self.store.findVnr(node.vnr.slice()) orelse return error.StoreProjectionStale;
        const assigned_ipv4 = node.address.octets();
        const vnr_network = vnr.range.network.octets();
        if (!std.mem.eql(u8, &assigned_ipv4, &current.assigned_ipv4) or
            !std.mem.eql(u8, &vnr_network, &current.vnr_network) or
            vnr.range.prefix != current.vnr_prefix_len)
        {
            return error.StoreProjectionStale;
        }
        return index;
    }

    fn lookupEnrollmentOpaque(raw: *anyopaque, handle: [16]u8) anyerror!handshake.EnrollmentRecord {
        const self: *MasterRegistryAdapter = @ptrCast(@alignCast(raw));
        return self.lookupEnrollment(handle);
    }

    fn consumeAndBindOpaque(
        raw: *anyopaque,
        handle: [16]u8,
        node_uuid: [16]u8,
        verified_psk: [32]u8,
        public_key: [32]u8,
    ) anyerror!void {
        const self: *MasterRegistryAdapter = @ptrCast(@alignCast(raw));
        return self.consumeAndBind(handle, node_uuid, verified_psk, public_key);
    }

    fn lookupNodeOpaque(raw: *anyopaque, node_uuid: [16]u8) anyerror!handshake.NodeRecord {
        const self: *MasterRegistryAdapter = @ptrCast(@alignCast(raw));
        return self.lookupNode(node_uuid);
    }
};

fn columnU32(statement: *const sqlite.Statement, index: c_int) !u32 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u32)) return error.InvalidEnrollmentState;
    return @intCast(value);
}

fn columnU8(statement: *const sqlite.Statement, index: c_int) !u8 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u8)) return error.InvalidEnrollmentState;
    return @intCast(value);
}

fn columnU64(statement: *const sqlite.Statement, index: c_int) !u64 {
    const value = statement.columnInt64(index);
    if (value < 0) return error.InvalidEnrollmentState;
    return @intCast(value);
}

fn validateNodeUuid(uuid: [16]u8) !void {
    if (allZero(&uuid)) return error.InvalidNodeIdentity;
    if (uuid[6] & 0xf0 != 0x40 or uuid[8] & 0xc0 != 0x80) return error.InvalidNodeIdentity;
}

fn ownerFromUuid(uuid: [16]u8) u128 {
    return std.mem.readInt(u128, &uuid, .big);
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

fn timingSafeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    for (left, right) |a, b| difference |= a ^ b;
    return difference == 0;
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testUuid(fill: u8) model.NodeId {
    var bytes = [_]u8{fill} ** 16;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    return .{ .bytes = bytes };
}

fn testHandle(index: usize) [16]u8 {
    return [_]u8{@intCast(0x20 + index)} ** 16;
}

fn testPsk(index: usize) [32]u8 {
    return [_]u8{@intCast(0x30 + index)} ** 32;
}

fn testAudit(byte: u8, action: []const u8, occurred_at: i64) management_repository.AuditEntry {
    return .{
        .id = [_]u8{byte} ** 16,
        .occurred_at = occurred_at,
        .actor_kind = .system,
        .action = action,
        .resource_type = "test",
    };
}

const Fixture = struct {
    db: sqlite.Database = undefined,
    store: model.Store = undefined,
    initialized: bool = false,

    fn init(
        self: *Fixture,
        tmp: *const std.testing.TmpDir,
        node_count: usize,
        expires_at: i64,
    ) !void {
        var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path = try testDatabasePath(tmp, &path_buffer);
        self.db = try sqlite.Database.openInitialized(path);
        errdefer self.db.close();
        self.store = model.Store.init(std.testing.allocator);
        errdefer self.store.deinit();

        _ = try self.store.createVnr("core", try model.Cidr.parse("10.24.0.0/24"));
        for (0..node_count) |index| {
            var name_buffer: [16]u8 = undefined;
            const name = try std.fmt.bufPrint(&name_buffer, "edge-{d}", .{index + 1});
            try self.store.createNode(
                testUuid(@intCast(0x40 + index)),
                name,
                "core",
                .{ .value = 0x0a18_0002 + @as(u32, @intCast(index)) },
            );
        }
        // A fresh database publishes its complete bootstrap projection once.
        self.store.generation = 1;
        const repository = management_repository.Repository.init(&self.db);
        _ = try repository.persistInventory(
            &self.store,
            0,
            10,
            testAudit(1, "inventory.bootstrap", 10),
        );
        for (0..node_count) |index| {
            const generation = try repository.replaceEnrollment(
                testUuid(@intCast(0x40 + index)),
                testHandle(index),
                testPsk(index),
                false,
                20 + @as(i64, @intCast(index)),
                expires_at,
                self.store.generation,
                testAudit(@intCast(10 + index), "enrollment.issue", 20 + @as(i64, @intCast(index))),
            );
            self.store.generation = generation;
        }
        self.initialized = true;
    }

    fn deinit(self: *Fixture) void {
        if (!self.initialized) return;
        self.store.deinit();
        self.db.close();
        self.initialized = false;
    }
};

const CredentialStatus = enum { unused, consumed, revoked };

fn credentialStatus(db: *sqlite.Database, handle: [16]u8) !CredentialStatus {
    var statement = try db.prepare("SELECT status FROM enrollment_credentials WHERE handle = ?1;");
    defer statement.deinit();
    try statement.bindBlob(1, &handle);
    if (try statement.step() != .row) return error.EnrollmentNotFound;
    const status = statement.columnText(0) orelse return error.InvalidEnrollmentState;
    const result: CredentialStatus = if (std.mem.eql(u8, status, "unused"))
        .unused
    else if (std.mem.eql(u8, status, "consumed"))
        .consumed
    else if (std.mem.eql(u8, status, "revoked"))
        .revoked
    else
        return error.InvalidEnrollmentState;
    if (try statement.step() != .done) return error.InvalidEnrollmentState;
    return result;
}

fn auditCount(db: *sqlite.Database) !i64 {
    var statement = try db.prepare("SELECT count(*) FROM audit_entries;");
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const count = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return count;
}

test "SQLite registry expires credentials at lookup and consume" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture: Fixture = .{};
    try fixture.init(&tmp, 1, 100);
    defer fixture.deinit();

    var adapter = MasterRegistryAdapter.init(std.testing.io, &fixture.db, &fixture.store);
    adapter.clock = .{ .fixed = 99 };
    const looked_up = try adapter.lookupEnrollment(testHandle(0));
    var psk = looked_up.psk;
    defer std.crypto.secureZero(u8, &psk);
    adapter.clock = .{ .fixed = 100 };
    try std.testing.expectError(error.EnrollmentExpired, adapter.lookupEnrollment(testHandle(0)));
    try std.testing.expectError(
        error.EnrollmentExpired,
        adapter.consumeAndBind(testHandle(0), testUuid(0x40).bytes, psk, .{0x51} ** 32),
    );
    try std.testing.expectEqual(CredentialStatus.unused, try credentialStatus(&fixture.db, testHandle(0)));
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, fixture.store.nodes.items[0].enrollment_state);
}

test "SQLite registry rejects wrong and replaced PSKs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture: Fixture = .{};
    try fixture.init(&tmp, 1, 1000);
    defer fixture.deinit();
    var adapter = MasterRegistryAdapter.init(std.testing.io, &fixture.db, &fixture.store);
    adapter.clock = .{ .fixed = 100 };

    const old = try adapter.lookupEnrollment(testHandle(0));
    var wrong = old.psk;
    wrong[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEnrollmentCredential,
        adapter.consumeAndBind(testHandle(0), testUuid(0x40).bytes, wrong, .{0x52} ** 32),
    );

    const repository = management_repository.Repository.init(&fixture.db);
    const replacement_handle = [_]u8{0x71} ** 16;
    const replacement_psk = [_]u8{0x72} ** 32;
    fixture.store.generation = try repository.replaceEnrollment(
        testUuid(0x40),
        replacement_handle,
        replacement_psk,
        false,
        101,
        1000,
        fixture.store.generation,
        testAudit(31, "enrollment.replace", 101),
    );
    try std.testing.expectError(
        error.EnrollmentRevoked,
        adapter.consumeAndBind(testHandle(0), testUuid(0x40).bytes, old.psk, .{0x52} ** 32),
    );
    try std.testing.expectError(
        error.InvalidEnrollmentCredential,
        adapter.consumeAndBind(replacement_handle, testUuid(0x40).bytes, old.psk, .{0x52} ** 32),
    );
    try std.testing.expectEqual(CredentialStatus.revoked, try credentialStatus(&fixture.db, testHandle(0)));
    try std.testing.expectEqual(CredentialStatus.unused, try credentialStatus(&fixture.db, replacement_handle));
}

test "two stale enrollment lookups have one durable winner" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture: Fixture = .{};
    try fixture.init(&tmp, 1, 1000);
    defer fixture.deinit();
    var adapter = MasterRegistryAdapter.init(std.testing.io, &fixture.db, &fixture.store);
    adapter.clock = .{ .fixed = 100 };

    const first = try adapter.lookupEnrollment(testHandle(0));
    const second = try adapter.lookupEnrollment(testHandle(0));
    try adapter.consumeAndBind(testHandle(0), first.node_uuid, first.psk, .{0x53} ** 32);
    try std.testing.expectError(
        error.EnrollmentConsumed,
        adapter.consumeAndBind(testHandle(0), second.node_uuid, second.psk, .{0x54} ** 32),
    );
    try std.testing.expectEqual(CredentialStatus.consumed, try credentialStatus(&fixture.db, testHandle(0)));
    try std.testing.expectEqual(model.EnrollmentState.enrolled, fixture.store.nodes.items[0].enrollment_state);
    const enrolled = try adapter.lookupNode(first.node_uuid);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x53} ** 32), &enrolled.public_key);
}

test "SQLite unique public key constraint rolls back the losing enrollment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture: Fixture = .{};
    try fixture.init(&tmp, 2, 1000);
    defer fixture.deinit();
    var adapter = MasterRegistryAdapter.init(std.testing.io, &fixture.db, &fixture.store);
    adapter.clock = .{ .fixed = 100 };
    const key = [_]u8{0x61} ** 32;

    try adapter.consumeAndBind(testHandle(0), testUuid(0x40).bytes, testPsk(0), key);
    const generation = fixture.store.generation;
    try std.testing.expectError(
        error.PublicKeyInUse,
        adapter.consumeAndBind(testHandle(1), testUuid(0x41).bytes, testPsk(1), key),
    );
    try std.testing.expectEqual(generation, fixture.store.generation);
    try std.testing.expectEqual(CredentialStatus.unused, try credentialStatus(&fixture.db, testHandle(1)));
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, fixture.store.nodes.items[1].enrollment_state);
}

test "audit failure rolls back consume, binding, and generation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture: Fixture = .{};
    try fixture.init(&tmp, 1, 1000);
    defer fixture.deinit();
    var adapter = MasterRegistryAdapter.init(std.testing.io, &fixture.db, &fixture.store);
    adapter.clock = .{ .fixed = 100 };
    // Collides with the bootstrap audit row after the repository has staged
    // both enrollment and Node changes inside its transaction.
    adapter.audit_ids = .{ .fixed = [_]u8{1} ** 16 };
    const generation = fixture.store.generation;
    const audits = try auditCount(&fixture.db);

    try std.testing.expectError(
        error.InvalidAuditEntry,
        adapter.consumeAndBind(testHandle(0), testUuid(0x40).bytes, testPsk(0), .{0x62} ** 32),
    );
    try std.testing.expectEqual(generation, try adapter.repository.durableGeneration());
    try std.testing.expectEqual(audits, try auditCount(&fixture.db));
    try std.testing.expectEqual(CredentialStatus.unused, try credentialStatus(&fixture.db, testHandle(0)));
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, fixture.store.nodes.items[0].enrollment_state);
}

const TestPublisher = struct {
    db: *sqlite.Database,
    handle: [16]u8,
    calls: usize = 0,
    saw_committed_database: bool = false,
    saw_installed_store: bool = false,
    generation: u64 = 0,

    fn interface(self: *TestPublisher) GenerationPublisher {
        return .{ .context = self, .publish_fn = publishOpaque };
    }

    fn publishOpaque(raw: *anyopaque, store: *const model.Store, generation: u64) void {
        const self: *TestPublisher = @ptrCast(@alignCast(raw));
        self.calls += 1;
        self.generation = generation;
        self.saw_installed_store = store.generation == generation and
            store.nodes.items[0].enrollment_state == .enrolled;
        const status = credentialStatus(self.db, self.handle) catch return;
        self.saw_committed_database = status == .consumed;
    }
};

test "successful consume publishes only after durable and in-memory install" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var fixture: Fixture = .{};
    try fixture.init(&tmp, 1, 1000);
    defer fixture.deinit();
    var adapter = MasterRegistryAdapter.init(std.testing.io, &fixture.db, &fixture.store);
    adapter.clock = .{ .fixed = 100 };
    var publisher = TestPublisher{ .db = &fixture.db, .handle = testHandle(0) };
    adapter.publisher = publisher.interface();

    const before = fixture.store.generation;
    try adapter.interface().consumeAndBind(
        testHandle(0),
        testUuid(0x40).bytes,
        testPsk(0),
        .{0x63} ** 32,
    );
    try std.testing.expectEqual(@as(usize, 1), publisher.calls);
    try std.testing.expectEqual(before + 1, publisher.generation);
    try std.testing.expect(publisher.saw_committed_database);
    try std.testing.expect(publisher.saw_installed_store);
}
