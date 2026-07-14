//! Durable adapters between the handshake coordinators and authoritative state.
//!
//! These adapters deliberately keep persistence out of the protocol state
//! machines.  The Master stages mutations in private clones, durably commits
//! both authoritative files through the recoverable two-file transaction, and
//! only then publishes the new in-memory state.  The Node stages its
//! authenticated assignment before acknowledging enrollment and removes its
//! one-time token only after the enrolled marker is durable.

const std = @import("std");
const model = @import("../domain/model.zig");
const credential_protocol = @import("../protocol/credential.zig");
const client_state = @import("../state/client.zig");
const enrollments = @import("../state/enrollments.zig");
const atomic = @import("../state/atomic_file.zig");
const repository_mod = @import("../state/repository.zig");
const secret_store = @import("../state/secret_store.zig");
const server_transaction = @import("../state/server_transaction.zig");
const handshake = @import("handshake_coordinator.zig");

pub const enrollment_token_file = "enrollment.token";

/// Normal startup invokes this after loading a durably enrolled assignment so
/// a crash between the enrolled-state sync and one-time-token deletion cannot
/// preserve a consumed bearer credential indefinitely.
pub fn cleanupConsumedEnrollmentToken(
    io: std.Io,
    dir: std.Io.Dir,
    persistent_state: client_state.PersistentState,
) !void {
    if (persistent_state.enrollment_state != .enrolled) return;
    atomic.deleteDurable(dir, io, enrollment_token_file) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// Injectable only so expiry boundaries can be tested deterministically.  A
/// production adapter uses `.system` and reads CLOCK_REALTIME for every lookup
/// and consume operation; a lookup never "blesses" a credential for later use.
pub const WallClock = union(enum) {
    system,
    fixed: u64,

    pub fn nowSeconds(self: WallClock, io: std.Io) !u64 {
        return switch (self) {
            .fixed => |seconds| seconds,
            .system => blk: {
                const seconds = std.Io.Clock.real.now(io).toSeconds();
                if (seconds < 0) return error.ClockBeforeUnixEpoch;
                break :blk @intCast(seconds);
            },
        };
    }
};

/// Fault hooks are inert in production and exercise the same recovery path an
/// interrupted or failed filesystem operation uses in a real daemon.
pub const MasterCommitFault = server_transaction.FaultPoint;

pub const MasterRegistryAdapter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: repository_mod.Repository,
    store: *model.Store,
    enrollments: *enrollments.Registry,
    clock: WallClock = .system,
    commit_fault: MasterCommitFault = .none,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository: repository_mod.Repository,
        store: *model.Store,
        enrollment_registry: *enrollments.Registry,
    ) MasterRegistryAdapter {
        return .{
            .allocator = allocator,
            .io = io,
            .repository = repository,
            .store = store,
            .enrollments = enrollment_registry,
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

    pub fn lookupEnrollment(self: *MasterRegistryAdapter, handle: [16]u8) !handshake.EnrollmentRecord {
        if (allZero(&handle)) return error.EnrollmentNotFound;
        const now = try self.clock.nowSeconds(self.io);
        const record = findEnrollment(self.enrollments, handle) orelse return error.EnrollmentNotFound;
        switch (record.status) {
            .unused => {},
            .consumed => return error.EnrollmentConsumed,
            .revoked => return error.EnrollmentRevoked,
        }
        if (now >= record.expires_at) return error.EnrollmentExpired;
        if (allZero(&record.derived_psk)) return error.InvalidEnrollmentState;

        const node = self.store.findNode(record.node.slice()) orelse return error.NodeNotFound;
        if (!constantTimeEqual(&node.id.bytes, &record.node_id.bytes)) {
            return error.InvalidEnrollmentState;
        }
        const vnr = try validateNodeAssignment(self.store, node);
        if (node.enrollment_state != .unenrolled or node.public_key != null) return error.NodeAlreadyEnrolled;
        return .{
            .node_uuid = node.id.bytes,
            .assigned_ipv4 = node.address.octets(),
            .vnr_network = vnr.range.network.octets(),
            .vnr_prefix_len = vnr.range.prefix,
            .config_generation = self.store.generation,
            .owner = ownerFromUuid(node.id.bytes),
            .psk = record.derived_psk,
        };
    }

    pub fn consumeAndBind(
        self: *MasterRegistryAdapter,
        handle: [16]u8,
        node_uuid: [16]u8,
        public_key: [32]u8,
    ) !void {
        if (allZero(&handle)) return error.EnrollmentNotFound;
        try validateNodeUuid(node_uuid);
        if (allZero(&public_key)) return error.InvalidPublicKey;
        const now = try self.clock.nowSeconds(self.io);

        var candidate_store = try cloneStore(self.allocator, self.store);
        var candidate_store_owned = true;
        defer if (candidate_store_owned) candidate_store.deinit();
        var candidate_enrollments = try cloneRegistry(self.allocator, self.enrollments);
        var candidate_enrollments_owned = true;
        defer if (candidate_enrollments_owned) candidate_enrollments.deinit();

        var consumed = try candidate_enrollments.consume(handle, now);
        defer std.crypto.secureZero(u8, &consumed.derived_psk);
        const node = candidate_store.findNode(consumed.node.slice()) orelse return error.NodeNotFound;
        if (!constantTimeEqual(&node.id.bytes, &consumed.node_id.bytes)) {
            return error.InvalidEnrollmentState;
        }
        _ = try validateNodeAssignment(&candidate_store, node);
        if (!constantTimeEqual(&node.id.bytes, &node_uuid)) return error.RegistryIdentityMismatch;
        if (node.enrollment_state != .unenrolled or node.public_key != null) return error.NodeAlreadyEnrolled;
        try candidate_store.bindNodePublicKey(consumed.node.slice(), public_key);

        server_transaction.commitFaultInjected(
            self.allocator,
            self.io,
            self.repository.dir,
            &candidate_store,
            &candidate_enrollments,
            self.commit_fault,
        ) catch |commit_error| {
            // A synced intent may have made the candidate authoritative even
            // though the caller did not receive success.  Recover and reload
            // immediately so IK lost-ack recovery observes the on-disk truth.
            try self.recoverLiveState();
            return commit_error;
        };

        installRegistry(self.enrollments, &candidate_enrollments);
        candidate_enrollments_owned = false;
        installStore(self.store, &candidate_store);
        candidate_store_owned = false;
    }

    pub fn lookupNode(self: *MasterRegistryAdapter, node_uuid: [16]u8) !handshake.NodeRecord {
        validateNodeUuid(node_uuid) catch return error.NodeNotFound;
        const node = findNodeById(self.store, node_uuid) orelse return error.NodeNotFound;
        _ = try validateNodeAssignment(self.store, node);
        if (node.enrollment_state != .enrolled) return error.NodeNotEnrolled;
        const public_key = node.public_key orelse return error.InvalidEnrollmentState;
        if (allZero(&public_key)) return error.InvalidPublicKey;
        return .{
            .node_uuid = node.id.bytes,
            .public_key = public_key,
            .config_generation = self.store.generation,
            .owner = ownerFromUuid(node.id.bytes),
        };
    }

    fn recoverLiveState(self: *MasterRegistryAdapter) !void {
        _ = try server_transaction.recover(self.allocator, self.io, self.repository.dir);
        var recovered_store = try self.repository.loadOrEmpty(self.allocator, self.io);
        var recovered_store_owned = true;
        defer if (recovered_store_owned) recovered_store.deinit();
        var recovered_enrollments = try (enrollments.File{ .dir = self.repository.dir }).loadOrEmpty(self.allocator, self.io);
        var recovered_enrollments_owned = true;
        defer if (recovered_enrollments_owned) recovered_enrollments.deinit();
        installRegistry(self.enrollments, &recovered_enrollments);
        recovered_enrollments_owned = false;
        installStore(self.store, &recovered_store);
        recovered_store_owned = false;
    }

    fn lookupEnrollmentOpaque(raw: *anyopaque, handle: [16]u8) anyerror!handshake.EnrollmentRecord {
        const self: *MasterRegistryAdapter = @ptrCast(@alignCast(raw));
        return self.lookupEnrollment(handle);
    }

    fn consumeAndBindOpaque(
        raw: *anyopaque,
        handle: [16]u8,
        node_uuid: [16]u8,
        public_key: [32]u8,
    ) anyerror!void {
        const self: *MasterRegistryAdapter = @ptrCast(@alignCast(raw));
        return self.consumeAndBind(handle, node_uuid, public_key);
    }

    fn lookupNodeOpaque(raw: *anyopaque, node_uuid: [16]u8) anyerror!handshake.NodeRecord {
        const self: *MasterRegistryAdapter = @ptrCast(@alignCast(raw));
        return self.lookupNode(node_uuid);
    }
};

pub const NodeCompletionFault = enum {
    none,
    after_enrolled_state,
};

pub const NodePersistenceAdapter = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    persistent_state: *client_state.PersistentState,
    expected_master_public: [32]u8,
    completion_fault: NodeCompletionFault = .none,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        persistent_state: *client_state.PersistentState,
        expected_master_public: [32]u8,
    ) !NodePersistenceAdapter {
        if (allZero(&expected_master_public)) return error.InvalidMasterIdentity;
        try persistent_state.validate();
        if (persistent_state.node_id) |node_id| try validateNodeUuid(node_id.bytes);
        if (persistent_state.vnr_range) |range| {
            if (range.network.value & model.Cidr.mask(range.prefix) != range.network.value) {
                return error.InvalidVnrAssignment;
            }
        }
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .persistent_state = persistent_state,
            .expected_master_public = expected_master_public,
        };
    }

    pub fn interface(self: *NodePersistenceAdapter) handshake.NodePersistence {
        return .{
            .context = self,
            .stage_assignment_fn = stageAssignmentOpaque,
            .complete_enrollment_fn = completeEnrollmentOpaque,
        };
    }

    pub fn generationStore(self: *NodePersistenceAdapter) @import("configuration_runtime.zig").GenerationStore {
        return .{ .context = self, .persist_fn = persistGenerationOpaque };
    }

    pub fn persistGeneration(self: *NodePersistenceAdapter, generation: u64, allow_rollback: bool) !void {
        if (generation == 0) return error.InvalidGeneration;
        if (!allow_rollback and generation < self.persistent_state.generation) return error.StaleConfigurationGeneration;
        if (generation == self.persistent_state.generation) return;
        var candidate = self.persistent_state.*;
        candidate.generation = generation;
        try (client_state.File{ .dir = self.dir }).save(self.allocator, self.io, candidate);
        self.persistent_state.* = candidate;
    }

    pub fn stageAssignment(self: *NodePersistenceAdapter, assignment: handshake.EnrollmentAssignment) !void {
        if (!constantTimeEqual(&assignment.master_public, &self.expected_master_public)) {
            return error.MasterIdentityMismatch;
        }
        const candidate = try persistentStateFromAssignment(assignment);
        const current = self.persistent_state.*;
        if (current.enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;
        if (current.node_id != null) {
            if (!sameAssignment(current, candidate)) return error.StagedAssignmentMismatch;
            // Retransmitted authenticated message 1 is idempotent.  Do not
            // rewrite a generation that is already durable.
            if (current.generation == candidate.generation) return;
            if (candidate.generation < current.generation) return error.StaleConfigurationGeneration;
        }
        try (client_state.File{ .dir = self.dir }).save(self.allocator, self.io, candidate);
        self.persistent_state.* = candidate;
    }

    pub fn completeEnrollment(self: *NodePersistenceAdapter, node_uuid: [16]u8) !void {
        try validateNodeUuid(node_uuid);
        const staged_id = self.persistent_state.node_id orelse return error.NoStagedEnrollment;
        if (!constantTimeEqual(&staged_id.bytes, &node_uuid)) return error.StagedIdentityMismatch;
        try self.persistent_state.validate();

        if (self.persistent_state.enrollment_state == .unenrolled) {
            var enrolled = self.persistent_state.*;
            enrolled.enrollment_state = .enrolled;
            try enrolled.validate();
            try (client_state.File{ .dir = self.dir }).save(self.allocator, self.io, enrolled);
            self.persistent_state.* = enrolled;
        }
        if (self.completion_fault == .after_enrolled_state) return error.InjectedFailure;

        // Missing is success: a retry after a crash between durable state and
        // durable deletion must converge without resurrecting the credential.
        try cleanupConsumedEnrollmentToken(self.io, self.dir, self.persistent_state.*);
    }

    fn stageAssignmentOpaque(raw: *anyopaque, assignment: handshake.EnrollmentAssignment) anyerror!void {
        const self: *NodePersistenceAdapter = @ptrCast(@alignCast(raw));
        return self.stageAssignment(assignment);
    }

    fn completeEnrollmentOpaque(raw: *anyopaque, node_uuid: [16]u8) anyerror!void {
        const self: *NodePersistenceAdapter = @ptrCast(@alignCast(raw));
        return self.completeEnrollment(node_uuid);
    }

    fn persistGenerationOpaque(raw: *anyopaque, generation: u64, allow_rollback: bool) anyerror!void {
        const self: *NodePersistenceAdapter = @ptrCast(@alignCast(raw));
        return self.persistGeneration(generation, allow_rollback);
    }
};

/// Loads and validates the private enrollment token without leaving its text
/// representation in allocator-backed memory.  The pinned public key is
/// checked independently of DNS and before a coordinator is constructed.
pub fn loadEnrollmentCredential(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    expected_master_public: [32]u8,
) !credential_protocol.Credential {
    if (allZero(&expected_master_public)) return error.InvalidMasterIdentity;
    const bytes = try (secret_store.FileSecretStore{ .dir = dir }).load(
        allocator,
        io,
        enrollment_token_file,
        .enrollment_token,
    );
    defer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    var credential = try credential_protocol.Credential.decode(bytes);
    errdefer credential.deinit();
    if (!constantTimeEqual(&credential.master_public, &expected_master_public)) {
        return error.MasterIdentityMismatch;
    }
    return credential;
}

/// Strict decoder for the public-key field already syntax-checked by the JSON
/// configuration layer.  Keeping it here avoids an ad-hoc parser in service
/// assembly and makes the identity comparison testable.
pub fn parseMasterPublicKey(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidMasterPublicKey;
    var result: [32]u8 = undefined;
    var combined: u8 = 0;
    for (&result, 0..) |*byte, index| {
        const hi = decodeLowerHex(text[index * 2]) orelse return error.InvalidMasterPublicKey;
        const lo = decodeLowerHex(text[index * 2 + 1]) orelse return error.InvalidMasterPublicKey;
        byte.* = (hi << 4) | lo;
        combined |= byte.*;
    }
    if (combined == 0) return error.InvalidMasterPublicKey;
    return result;
}

fn persistentStateFromAssignment(assignment: handshake.EnrollmentAssignment) !client_state.PersistentState {
    try validateNodeUuid(assignment.node_uuid);
    if (allZero(&assignment.master_public)) return error.InvalidMasterIdentity;
    if (assignment.vnr_prefix_len < 1 or assignment.vnr_prefix_len > 30) return error.InvalidVnrAssignment;
    const address = ipv4FromOctets(assignment.assigned_ipv4);
    const network = ipv4FromOctets(assignment.vnr_network);
    const range: model.Cidr = .{ .network = network, .prefix = assignment.vnr_prefix_len };
    if (network.value & model.Cidr.mask(range.prefix) != network.value) return error.InvalidVnrAssignment;
    range.validateVnr() catch return error.InvalidVnrAssignment;
    if (!range.isUsableHost(address) or address.value == range.firstUsable().?.value) {
        return error.InvalidVnrAssignment;
    }
    const result: client_state.PersistentState = .{
        .generation = assignment.config_generation,
        .enrollment_state = .unenrolled,
        .node_id = .{ .bytes = assignment.node_uuid },
        .assigned_address = address,
        .vnr_range = range,
    };
    try result.validate();
    return result;
}

fn validateNodeAssignment(store: *const model.Store, node: *const model.Node) !*const model.Vnr {
    try validateNodeUuid(node.id.bytes);
    const vnr = store.findVnr(node.vnr.slice()) orelse return error.VnrNotFound;
    vnr.range.validateVnr() catch return error.InvalidVnrAssignment;
    if (vnr.range.network.value & model.Cidr.mask(vnr.range.prefix) != vnr.range.network.value) {
        return error.InvalidVnrAssignment;
    }
    if (!vnr.range.isUsableHost(node.address) or node.address.value == vnr.masterAddress().value) {
        return error.InvalidVnrAssignment;
    }
    return vnr;
}

fn sameAssignment(left: client_state.PersistentState, right: client_state.PersistentState) bool {
    return constantTimeEqual(&left.node_id.?.bytes, &right.node_id.?.bytes) and
        left.assigned_address.?.value == right.assigned_address.?.value and
        left.vnr_range.?.network.value == right.vnr_range.?.network.value and
        left.vnr_range.?.prefix == right.vnr_range.?.prefix;
}

fn cloneStore(allocator: std.mem.Allocator, source: *const model.Store) !model.Store {
    var result = model.Store.init(allocator);
    errdefer result.deinit();
    result.generation = source.generation;
    try result.vnrs.appendSlice(allocator, source.vnrs.items);
    try result.nodes.appendSlice(allocator, source.nodes.items);
    try result.routes.appendSlice(allocator, source.routes.items);
    return result;
}

fn cloneRegistry(allocator: std.mem.Allocator, source: *const enrollments.Registry) !enrollments.Registry {
    var result = enrollments.Registry.init(allocator);
    errdefer result.deinit();
    result.generation = source.generation;
    try result.records.appendSlice(allocator, source.records.items);
    return result;
}

fn installStore(target: *model.Store, candidate: *model.Store) void {
    const old = target.*;
    target.* = candidate.*;
    candidate.* = old;
    candidate.deinit();
}

fn installRegistry(target: *enrollments.Registry, candidate: *enrollments.Registry) void {
    const old = target.*;
    target.* = candidate.*;
    candidate.* = old;
    candidate.deinit();
}

fn findEnrollment(registry: *const enrollments.Registry, handle: [16]u8) ?*const enrollments.Record {
    var found: ?*const enrollments.Record = null;
    for (registry.records.items) |*record| {
        if (constantTimeEqual(&record.handle, &handle)) found = record;
    }
    return found;
}

fn findNodeById(store: *const model.Store, node_uuid: [16]u8) ?*const model.Node {
    var found: ?*const model.Node = null;
    for (store.nodes.items) |*node| {
        if (constantTimeEqual(&node.id.bytes, &node_uuid)) found = node;
    }
    return found;
}

fn ipv4FromOctets(bytes: [4]u8) model.Ipv4 {
    return .{ .value = (@as(u32, bytes[0]) << 24) |
        (@as(u32, bytes[1]) << 16) |
        (@as(u32, bytes[2]) << 8) |
        bytes[3] };
}

fn ownerFromUuid(uuid: [16]u8) u128 {
    return std.mem.readInt(u128, &uuid, .big);
}

fn validateNodeUuid(uuid: [16]u8) !void {
    if (allZero(&uuid)) return error.InvalidNodeIdentity;
    if (uuid[6] & 0xf0 != 0x40 or uuid[8] & 0xc0 != 0x80) return error.InvalidNodeIdentity;
}

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    for (left, right) |a, b| difference |= a ^ b;
    return difference == 0;
}

fn decodeLowerHex(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        else => null,
    };
}

fn createMasterFixture(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    expires_at: u64,
) !struct { model.Store, enrollments.Registry, [16]u8, model.NodeId } {
    var store = model.Store.init(allocator);
    errdefer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    const node_id: model.NodeId = .{ .bytes = testUuid(0x42) };
    try store.createNode(node_id, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    var registry = enrollments.Registry.init(allocator);
    errdefer registry.deinit();
    const handle = [_]u8{0x24} ** 16;
    try registry.issueWithHandle("node01", node_id, handle, .{0x35} ** 32, 1, expires_at);
    try server_transaction.commit(allocator, io, dir, &store, &registry);
    return .{ store, registry, handle, node_id };
}

fn testUuid(fill: u8) [16]u8 {
    var uuid = [_]u8{fill} ** 16;
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    return uuid;
}

test "Master registry expires at lookup and rechecks at atomic consume" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fixture = try createMasterFixture(std.testing.allocator, std.testing.io, tmp.dir, 100);
    var store = fixture[0];
    defer store.deinit();
    var registry = fixture[1];
    defer registry.deinit();
    const handle = fixture[2];
    const node_id = fixture[3];
    var adapter = MasterRegistryAdapter.init(
        std.testing.allocator,
        std.testing.io,
        .{ .dir = tmp.dir },
        &store,
        &registry,
    );
    adapter.clock = .{ .fixed = 99 };
    _ = try adapter.interface().lookupEnrollment(handle);
    adapter.clock = .{ .fixed = 100 };
    try std.testing.expectError(error.EnrollmentExpired, adapter.interface().lookupEnrollment(handle));
    try std.testing.expectError(
        error.EnrollmentExpired,
        adapter.interface().consumeAndBind(handle, node_id.bytes, .{0x55} ** 32),
    );
    try std.testing.expectEqual(enrollments.Status.unused, registry.records.items[0].status);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, store.nodes.items[0].enrollment_state);
}

test "Master registry resolves stale-lookups as one durable winner" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fixture = try createMasterFixture(std.testing.allocator, std.testing.io, tmp.dir, 1000);
    var store = fixture[0];
    defer store.deinit();
    var registry = fixture[1];
    defer registry.deinit();
    const handle = fixture[2];
    const node_id = fixture[3];
    var adapter = MasterRegistryAdapter.init(std.testing.allocator, std.testing.io, .{ .dir = tmp.dir }, &store, &registry);
    adapter.clock = .{ .fixed = 10 };
    _ = try adapter.lookupEnrollment(handle);
    _ = try adapter.lookupEnrollment(handle);
    try adapter.consumeAndBind(handle, node_id.bytes, .{0x55} ** 32);
    try std.testing.expectError(error.EnrollmentConsumed, adapter.consumeAndBind(handle, node_id.bytes, .{0x56} ** 32));
    try std.testing.expectEqual(model.EnrollmentState.enrolled, store.nodes.items[0].enrollment_state);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x55} ** 32), &store.nodes.items[0].public_key.?);
    _ = try adapter.lookupNode(node_id.bytes);
}

test "Master registry fails closed when an enrollment record names the wrong Node UUID" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const fixture = try createMasterFixture(std.testing.allocator, std.testing.io, tmp.dir, 1000);
    var store = fixture[0];
    defer store.deinit();
    var registry = fixture[1];
    defer registry.deinit();
    const handle = fixture[2];
    const node_id = fixture[3];
    registry.records.items[0].node_id = .{ .bytes = testUuid(0x77) };

    var adapter = MasterRegistryAdapter.init(std.testing.allocator, std.testing.io, .{ .dir = tmp.dir }, &store, &registry);
    adapter.clock = .{ .fixed = 10 };
    try std.testing.expectError(error.InvalidEnrollmentState, adapter.lookupEnrollment(handle));
    try std.testing.expectError(
        error.InvalidEnrollmentState,
        adapter.consumeAndBind(handle, node_id.bytes, .{0x55} ** 32),
    );
    try std.testing.expectEqual(enrollments.Status.unused, registry.records.items[0].status);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, store.nodes.items[0].enrollment_state);
}

test "Master commit interruption recovers bound identity for IK lost-ack recovery" {
    inline for (.{ MasterCommitFault.after_intent, .after_enrollments, .after_state }) |fault| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const fixture = try createMasterFixture(std.testing.allocator, std.testing.io, tmp.dir, 1000);
        var store = fixture[0];
        defer store.deinit();
        var registry = fixture[1];
        defer registry.deinit();
        const handle = fixture[2];
        const node_id = fixture[3];
        var adapter = MasterRegistryAdapter.init(std.testing.allocator, std.testing.io, .{ .dir = tmp.dir }, &store, &registry);
        adapter.clock = .{ .fixed = 10 };
        adapter.commit_fault = fault;
        try std.testing.expectError(
            error.InjectedFailure,
            adapter.consumeAndBind(handle, node_id.bytes, .{0x61} ** 32),
        );
        try std.testing.expectEqual(enrollments.Status.consumed, registry.records.items[0].status);
        try std.testing.expectEqual(model.EnrollmentState.enrolled, store.nodes.items[0].enrollment_state);
        try std.testing.expectEqualSlices(u8, &([_]u8{0x61} ** 32), &store.nodes.items[0].public_key.?);
        _ = try adapter.lookupNode(node_id.bytes);
        try std.testing.expect(!(try server_transaction.recover(std.testing.allocator, std.testing.io, tmp.dir)));
    }
}

test "Node persistence stages strictly and completes lost acknowledgement idempotently" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const master_public = [_]u8{0x71} ** 32;
    const credential = credential_protocol.Credential{
        .handle = .{0x11} ** 16,
        .secret = .{0x22} ** 32,
        .master_public = master_public,
    };
    var text: [credential_protocol.text_len]u8 = undefined;
    try (secret_store.FileSecretStore{ .dir = tmp.dir }).write(
        std.testing.allocator,
        std.testing.io,
        enrollment_token_file,
        .enrollment_token,
        credential.encode(&text),
    );
    var state: client_state.PersistentState = .{};
    var adapter = try NodePersistenceAdapter.init(std.testing.allocator, std.testing.io, tmp.dir, &state, master_public);
    const assignment: handshake.EnrollmentAssignment = .{
        .node_uuid = testUuid(0x41),
        .assigned_ipv4 = .{ 10, 1, 0, 2 },
        .vnr_network = .{ 10, 1, 0, 0 },
        .vnr_prefix_len = 24,
        .config_generation = 9,
        .master_public = master_public,
    };
    try adapter.interface().stageAssignment(assignment);
    try adapter.interface().stageAssignment(assignment);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, state.enrollment_state);
    const staged_token = try (secret_store.FileSecretStore{ .dir = tmp.dir }).load(
        std.testing.allocator,
        std.testing.io,
        enrollment_token_file,
        .enrollment_token,
    );
    defer {
        @memset(staged_token, 0);
        std.testing.allocator.free(staged_token);
    }

    // Simulate restart after XK message 2 was sent but ENROLLMENT_COMPLETE was
    // lost.  IK recovery calls the same completion hook.
    var restarted_state = try (client_state.File{ .dir = tmp.dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
    var restarted = try NodePersistenceAdapter.init(std.testing.allocator, std.testing.io, tmp.dir, &restarted_state, master_public);
    try restarted.interface().completeEnrollment(assignment.node_uuid);
    try std.testing.expectEqual(model.EnrollmentState.enrolled, restarted_state.enrollment_state);
    try std.testing.expectError(
        error.FileNotFound,
        (secret_store.FileSecretStore{ .dir = tmp.dir }).load(
            std.testing.allocator,
            std.testing.io,
            enrollment_token_file,
            .enrollment_token,
        ),
    );
    try restarted.interface().completeEnrollment(assignment.node_uuid);
}

test "normal Node startup removes a token retained after the enrolled marker" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const master_public = [_]u8{0x72} ** 32;
    const credential = credential_protocol.Credential{
        .handle = .{0x12} ** 16,
        .secret = .{0x23} ** 32,
        .master_public = master_public,
    };
    var text: [credential_protocol.text_len]u8 = undefined;
    try (secret_store.FileSecretStore{ .dir = tmp.dir }).write(
        std.testing.allocator,
        std.testing.io,
        enrollment_token_file,
        .enrollment_token,
        credential.encode(&text),
    );
    var state: client_state.PersistentState = .{};
    var adapter = try NodePersistenceAdapter.init(std.testing.allocator, std.testing.io, tmp.dir, &state, master_public);
    const assignment: handshake.EnrollmentAssignment = .{
        .node_uuid = testUuid(0x43),
        .assigned_ipv4 = .{ 10, 2, 0, 2 },
        .vnr_network = .{ 10, 2, 0, 0 },
        .vnr_prefix_len = 24,
        .config_generation = 3,
        .master_public = master_public,
    };
    try adapter.stageAssignment(assignment);
    adapter.completion_fault = .after_enrolled_state;
    try std.testing.expectError(error.InjectedFailure, adapter.completeEnrollment(assignment.node_uuid));
    try std.testing.expectEqual(model.EnrollmentState.enrolled, state.enrollment_state);
    const retained = try (secret_store.FileSecretStore{ .dir = tmp.dir }).load(
        std.testing.allocator,
        std.testing.io,
        enrollment_token_file,
        .enrollment_token,
    );
    defer {
        @memset(retained, 0);
        std.testing.allocator.free(retained);
    }
    try cleanupConsumedEnrollmentToken(std.testing.io, tmp.dir, state);
    try std.testing.expectError(
        error.FileNotFound,
        (secret_store.FileSecretStore{ .dir = tmp.dir }).load(
            std.testing.allocator,
            std.testing.io,
            enrollment_token_file,
            .enrollment_token,
        ),
    );
}

test "Node staging rejects malformed identity VNR address and Master binding" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const master_public = [_]u8{0x74} ** 32;
    var state: client_state.PersistentState = .{};
    var adapter = try NodePersistenceAdapter.init(std.testing.allocator, std.testing.io, tmp.dir, &state, master_public);
    const valid: handshake.EnrollmentAssignment = .{
        .node_uuid = testUuid(0x45),
        .assigned_ipv4 = .{ 10, 4, 0, 2 },
        .vnr_network = .{ 10, 4, 0, 0 },
        .vnr_prefix_len = 24,
        .config_generation = 4,
        .master_public = master_public,
    };
    var malformed_uuid = valid;
    malformed_uuid.node_uuid[8] = 0;
    try std.testing.expectError(error.InvalidNodeIdentity, adapter.stageAssignment(malformed_uuid));
    var wrong_master = valid;
    wrong_master.master_public[0] ^= 1;
    try std.testing.expectError(error.MasterIdentityMismatch, adapter.stageAssignment(wrong_master));
    var noncanonical_vnr = valid;
    noncanonical_vnr.vnr_network[3] = 1;
    try std.testing.expectError(error.InvalidVnrAssignment, adapter.stageAssignment(noncanonical_vnr));
    var master_address = valid;
    master_address.assigned_ipv4[3] = 1;
    try std.testing.expectError(error.InvalidVnrAssignment, adapter.stageAssignment(master_address));
    try std.testing.expect(state.node_id == null);
}

test "token helper binds the credential to the configured Master" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const credential = credential_protocol.Credential{
        .handle = .{1} ** 16,
        .secret = .{2} ** 32,
        .master_public = .{3} ** 32,
    };
    var text: [credential_protocol.text_len]u8 = undefined;
    try (secret_store.FileSecretStore{ .dir = tmp.dir }).write(
        std.testing.allocator,
        std.testing.io,
        enrollment_token_file,
        .enrollment_token,
        credential.encode(&text),
    );
    var loaded = try loadEnrollmentCredential(std.testing.allocator, std.testing.io, tmp.dir, .{3} ** 32);
    defer loaded.deinit();
    try std.testing.expectEqual(credential.handle, loaded.handle);
    try std.testing.expectError(
        error.MasterIdentityMismatch,
        loadEnrollmentCredential(std.testing.allocator, std.testing.io, tmp.dir, .{4} ** 32),
    );
    const parsed = try parseMasterPublicKey("0100000000000000000000000000000000000000000000000000000000000000");
    try std.testing.expectEqual(@as(u8, 1), parsed[0]);
    try std.testing.expectError(
        error.InvalidMasterPublicKey,
        parseMasterPublicKey("010000000000000000000000000000000000000000000000000000000000000A"),
    );
}

test "configuration generation is monotonic per session and rollback-safe after reconnect" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var persistent: client_state.PersistentState = .{
        .generation = 4,
        .enrollment_state = .enrolled,
        .node_id = .{ .bytes = testUuid(0x48) },
        .assigned_address = try model.Ipv4.parse("10.8.0.2"),
        .vnr_range = try model.Cidr.parse("10.8.0.0/24"),
    };
    try (client_state.File{ .dir = tmp.dir }).save(std.testing.allocator, std.testing.io, persistent);
    var adapter = try NodePersistenceAdapter.init(
        std.testing.allocator,
        std.testing.io,
        tmp.dir,
        &persistent,
        .{0x75} ** 32,
    );
    try adapter.generationStore().persist(9, false);
    try std.testing.expectEqual(@as(u64, 9), persistent.generation);
    const loaded = try (client_state.File{ .dir = tmp.dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
    try std.testing.expectEqual(@as(u64, 9), loaded.generation);
    try std.testing.expectError(error.StaleConfigurationGeneration, adapter.generationStore().persist(8, false));

    // A fresh authenticated Noise session may carry a coherent older Master
    // snapshot after operator rollback. Its first full generation replaces the
    // persisted diagnostic marker; subsequent frames are monotonic again.
    try adapter.generationStore().persist(3, true);
    try std.testing.expectEqual(@as(u64, 3), persistent.generation);
    try std.testing.expectError(error.StaleConfigurationGeneration, adapter.generationStore().persist(2, false));
    try std.testing.expectError(error.InvalidGeneration, adapter.generationStore().persist(0, true));
}
