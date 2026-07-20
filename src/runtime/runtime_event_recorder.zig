//! Bounded, transport-independent recording of durable Node runtime state
//! transitions.
//!
//! The serialized Master loop supplies the exact durable Node set on each
//! tick. Runtime observations come only through the public management read
//! model seam, and durable output goes only through `operations_repository`.
//! The first observation of a Node establishes a silent baseline: restarting
//! the Master therefore cannot manufacture an online/offline event flood.
//!
//! Each Node retains at most one pending transition per public state
//! dimension. If SQLite is temporarily busy, later samples coalesce that
//! pending transition from the last durably recorded state to the latest
//! observed state. A retry of an unchanged transition preserves its event ID.
//! Removing a Node evicts its baseline and pending runtime observations; the
//! inventory deletion's immutable audit row is authoritative, so this module
//! does not synthesize a post-deletion event that could violate the Node
//! foreign key.

const std = @import("std");
const model = @import("../domain/model.zig");
const read_models = @import("../management/read_models_service.zig");
const operations_repository = @import("../state/operations_repository.zig");
const sqlite = @import("../state/sqlite.zig");

pub const Config = struct {
    /// Allocation and scan bound. The recorder performs no allocation after
    /// construction and never retains state for more than this many Nodes.
    maximum_nodes: usize,
};

pub const TickBudget = struct {
    /// Bounds SQLite work without preventing a full bounded observation scan.
    /// Zero is useful when protocol-critical persistence has priority: the
    /// latest transitions are retained for a later tick.
    maximum_event_writes: u16 = 16,
};

pub const TickResult = struct {
    observed_nodes: usize = 0,
    initialized_nodes: usize = 0,
    removed_nodes: usize = 0,
    removed_pending_transitions: usize = 0,
    transitions_observed: usize = 0,
    transitions_coalesced: usize = 0,
    event_write_attempts: usize = 0,
    events_appended: usize = 0,
    events_pending: usize = 0,
    database_pressure: bool = false,
};

const Dimension = enum(u8) {
    liveness,
    session,
    traffic,
};

const Snapshot = struct {
    liveness: read_models.LivenessState,
    session: read_models.RuntimeSessionState,
    traffic: read_models.TrafficState,

    fn fromObservation(observation: read_models.RuntimeObservation) Snapshot {
        return .{
            .liveness = observation.liveness,
            .session = observation.session_state,
            .traffic = observation.traffic_state,
        };
    }
};

const PendingTransition = struct {
    active: bool = false,
    from: u8 = 0,
    to: u8 = 0,
    observed_at: i64 = 0,
    id: [16]u8 = [_]u8{0} ** 16,
};

const Entry = struct {
    node_id: model.NodeId,
    initialized: bool = false,
    present: bool = false,
    durable: Snapshot = undefined,
    latest: Snapshot = undefined,
    pending_liveness: PendingTransition = .{},
    pending_session: PendingTransition = .{},
    pending_traffic: PendingTransition = .{},

    fn pendingCount(self: *const Entry) usize {
        return @as(usize, @intFromBool(self.pending_liveness.active)) +
            @as(usize, @intFromBool(self.pending_session.active)) +
            @as(usize, @intFromBool(self.pending_traffic.active));
    }
};

comptime {
    // Only the stable management Node ID and contract-safe state enums are
    // retained. In particular, endpoints, keys, receiver IDs, wire session
    // IDs, and authenticated activity samples cannot leak into event details.
    std.debug.assert(!@hasField(Entry, "public_key"));
    std.debug.assert(!@hasField(Entry, "private_key"));
    std.debug.assert(!@hasField(Entry, "derived_psk"));
    std.debug.assert(!@hasField(Entry, "receiver_id"));
    std.debug.assert(!@hasField(Entry, "protocol_session_id"));
    std.debug.assert(!@hasField(Entry, "observed_endpoint"));
    std.debug.assert(!@hasField(Entry, "authenticated_rx_at"));
    std.debug.assert(!@hasField(Entry, "authenticated_tx_at"));
}

const EventAppender = struct {
    context: ?*anyopaque,
    append_fn: *const fn (?*anyopaque, operations_repository.RuntimeEventInput) anyerror!void,

    fn append(self: EventAppender, event: operations_repository.RuntimeEventInput) !void {
        return self.append_fn(self.context, event);
    }
};

/// Fixed-capacity recorder intended to be owned by the serialized Master
/// operator worker. `tick` is single-threaded and must not be called
/// concurrently.
pub const Recorder = struct {
    allocator: std.mem.Allocator,
    source: read_models.RuntimeSource,
    appender: EventAppender,
    event_namespace: [16]u8,
    entries: []Entry,
    scratch_ids: []model.NodeId,
    entry_count: usize = 0,
    transition_sequence: u64 = 0,
    last_tick_at: ?i64 = null,

    /// `event_namespace` is a per-Master-process random identifier. It makes
    /// derived event IDs deterministic for retry while preventing a restart
    /// from reproducing a historical ID if the same transition occurs in the
    /// same wall-clock second.
    pub fn init(
        allocator: std.mem.Allocator,
        source: read_models.RuntimeSource,
        operations: *operations_repository.Repository,
        event_namespace: [16]u8,
        config: Config,
    ) !Recorder {
        return initWithAppender(
            allocator,
            source,
            repositoryAppender(operations),
            event_namespace,
            config,
        );
    }

    fn initWithAppender(
        allocator: std.mem.Allocator,
        source: read_models.RuntimeSource,
        appender: EventAppender,
        event_namespace: [16]u8,
        config: Config,
    ) !Recorder {
        if (config.maximum_nodes == 0) return error.InvalidMaximumNodes;
        const entries = try allocator.alloc(Entry, config.maximum_nodes);
        errdefer allocator.free(entries);
        const scratch_ids = try allocator.alloc(model.NodeId, config.maximum_nodes);
        return .{
            .allocator = allocator,
            .source = source,
            .appender = appender,
            .event_namespace = event_namespace,
            .entries = entries,
            .scratch_ids = scratch_ids,
        };
    }

    pub fn deinit(self: *Recorder) void {
        self.allocator.free(self.scratch_ids);
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn maximumNodes(self: *const Recorder) usize {
        return self.entries.len;
    }

    pub fn trackedNodeCount(self: *const Recorder) usize {
        return self.entry_count;
    }

    pub fn pendingEventCount(self: *const Recorder) usize {
        var result: usize = 0;
        for (self.entries[0..self.entry_count]) |*entry| result += entry.pendingCount();
        return result;
    }

    /// Observes the complete durable Node set, coalesces public state changes,
    /// and appends at most `budget.maximum_event_writes` events. The input may
    /// be in any order, but IDs must be unique. A busy/locked SQLite database
    /// is reported in the result rather than returned as an error; the exact
    /// latest pending transition remains available for retry.
    pub fn tick(
        self: *Recorder,
        durable_node_ids: []const model.NodeId,
        observed_at: i64,
        budget: TickBudget,
    ) !TickResult {
        if (observed_at < 0) return error.InvalidTimestamp;
        if (self.last_tick_at) |previous| {
            if (observed_at < previous) return error.NonMonotonicTimestamp;
        }
        if (durable_node_ids.len > self.entries.len) return error.NodeCapacityExceeded;

        @memcpy(self.scratch_ids[0..durable_node_ids.len], durable_node_ids);
        const sorted_ids = self.scratch_ids[0..durable_node_ids.len];
        std.mem.sort(model.NodeId, sorted_ids, {}, nodeIdLessThan);
        if (sorted_ids.len > 1) {
            for (sorted_ids[1..], sorted_ids[0 .. sorted_ids.len - 1]) |current, previous| {
                if (current.eql(previous)) return error.DuplicateNodeId;
            }
        }

        self.last_tick_at = observed_at;
        var result: TickResult = .{};
        try self.reconcileNodes(sorted_ids, &result);

        // Sorting makes callback order, transition nonces, write order, and
        // resulting IDs independent of inventory insertion order.
        std.mem.sort(Entry, self.entries[0..self.entry_count], {}, entryLessThan);
        for (self.entries[0..self.entry_count]) |*entry| {
            const observation = (try self.source.observe(entry.node_id, observed_at)) orelse
                read_models.RuntimeObservation.unavailable();
            result.observed_nodes += 1;
            if (!entry.initialized) {
                const baseline = Snapshot.fromObservation(observation);
                entry.durable = baseline;
                entry.latest = baseline;
                entry.initialized = true;
                result.initialized_nodes += 1;
                continue;
            }
            try self.stageObservation(entry, Snapshot.fromObservation(observation), observed_at, &result);
        }

        try self.flushPending(budget.maximum_event_writes, &result);
        result.events_pending = self.pendingEventCount();
        return result;
    }

    fn reconcileNodes(
        self: *Recorder,
        sorted_ids: []const model.NodeId,
        result: *TickResult,
    ) !void {
        for (self.entries[0..self.entry_count]) |*entry| entry.present = false;
        for (sorted_ids) |node_id| {
            if (self.findEntry(node_id)) |entry| {
                entry.present = true;
            } else {
                if (self.entry_count == self.entries.len) return error.NodeCapacityExceeded;
                self.entries[self.entry_count] = .{ .node_id = node_id, .present = true };
                self.entry_count += 1;
            }
        }

        var write_index: usize = 0;
        for (self.entries[0..self.entry_count]) |entry| {
            if (!entry.present) {
                result.removed_nodes += 1;
                result.removed_pending_transitions += entry.pendingCount();
                continue;
            }
            self.entries[write_index] = entry;
            write_index += 1;
        }
        self.entry_count = write_index;
    }

    fn findEntry(self: *Recorder, node_id: model.NodeId) ?*Entry {
        for (self.entries[0..self.entry_count]) |*entry| {
            if (entry.node_id.eql(node_id)) return entry;
        }
        return null;
    }

    fn stageObservation(
        self: *Recorder,
        entry: *Entry,
        observation: Snapshot,
        observed_at: i64,
        result: *TickResult,
    ) !void {
        try self.stageDimension(
            entry,
            .liveness,
            enumCode(entry.durable.liveness),
            enumCode(entry.latest.liveness),
            enumCode(observation.liveness),
            &entry.pending_liveness,
            observed_at,
            result,
        );
        entry.latest.liveness = observation.liveness;

        try self.stageDimension(
            entry,
            .session,
            enumCode(entry.durable.session),
            enumCode(entry.latest.session),
            enumCode(observation.session),
            &entry.pending_session,
            observed_at,
            result,
        );
        entry.latest.session = observation.session;

        try self.stageDimension(
            entry,
            .traffic,
            enumCode(entry.durable.traffic),
            enumCode(entry.latest.traffic),
            enumCode(observation.traffic),
            &entry.pending_traffic,
            observed_at,
            result,
        );
        entry.latest.traffic = observation.traffic;
    }

    fn stageDimension(
        self: *Recorder,
        entry: *Entry,
        dimension: Dimension,
        durable: u8,
        previous_latest: u8,
        latest: u8,
        pending: *PendingTransition,
        observed_at: i64,
        result: *TickResult,
    ) !void {
        if (latest == previous_latest) return;
        result.transitions_observed += 1;
        const replaced_or_cancelled = pending.active;
        if (latest == durable) {
            pending.* = .{};
            if (replaced_or_cancelled) result.transitions_coalesced += 1;
            return;
        }

        const next_sequence = std.math.add(u64, self.transition_sequence, 1) catch
            return error.TransitionSequenceExhausted;
        const replacement: PendingTransition = .{
            .active = true,
            .from = durable,
            .to = latest,
            .observed_at = observed_at,
            .id = deriveEventId(
                self.event_namespace,
                entry.node_id,
                dimension,
                durable,
                latest,
                observed_at,
                next_sequence,
            ),
        };
        self.transition_sequence = next_sequence;
        pending.* = replacement;
        if (replaced_or_cancelled) result.transitions_coalesced += 1;
    }

    fn flushPending(
        self: *Recorder,
        maximum_writes: u16,
        result: *TickResult,
    ) !void {
        var writes_remaining = maximum_writes;
        const dimensions = [_]Dimension{ .liveness, .session, .traffic };
        for (self.entries[0..self.entry_count]) |*entry| {
            for (dimensions) |dimension| {
                if (writes_remaining == 0) return;
                const pending = pendingFor(entry, dimension);
                if (!pending.active) continue;

                var details_buffer: [96]u8 = undefined;
                const details = std.fmt.bufPrint(
                    &details_buffer,
                    "{{\"from\":\"{s}\",\"to\":\"{s}\"}}",
                    .{ stateName(dimension, pending.from), stateName(dimension, pending.to) },
                ) catch unreachable;
                result.event_write_attempts += 1;
                self.appender.append(.{
                    .id = pending.id,
                    .kind = eventKind(dimension, pending.to),
                    .severity = eventSeverity(dimension, pending.to),
                    .node_id = entry.node_id.bytes,
                    .observed_at = pending.observed_at,
                    .details_json = details,
                }) catch |err| switch (err) {
                    error.DatabaseBusy, error.DatabaseLocked => {
                        result.database_pressure = true;
                        return;
                    },
                    else => return err,
                };

                setDurableState(entry, dimension, pending.to);
                pending.* = .{};
                writes_remaining -= 1;
                result.events_appended += 1;
            }
        }
    }
};

fn repositoryAppender(repository: *operations_repository.Repository) EventAppender {
    return .{ .context = repository, .append_fn = appendToRepository };
}

fn appendToRepository(
    raw: ?*anyopaque,
    event: operations_repository.RuntimeEventInput,
) !void {
    const repository: *operations_repository.Repository = @ptrCast(@alignCast(raw.?));
    try repository.appendRuntimeEvent(event);
}

fn pendingFor(entry: *Entry, dimension: Dimension) *PendingTransition {
    return switch (dimension) {
        .liveness => &entry.pending_liveness,
        .session => &entry.pending_session,
        .traffic => &entry.pending_traffic,
    };
}

fn setDurableState(entry: *Entry, dimension: Dimension, code: u8) void {
    switch (dimension) {
        .liveness => entry.durable.liveness = @enumFromInt(code),
        .session => entry.durable.session = @enumFromInt(code),
        .traffic => entry.durable.traffic = @enumFromInt(code),
    }
}

fn enumCode(value: anytype) u8 {
    return @intCast(@intFromEnum(value));
}

fn stateName(dimension: Dimension, code: u8) []const u8 {
    return switch (dimension) {
        .liveness => @tagName(@as(read_models.LivenessState, @enumFromInt(code))),
        .session => @tagName(@as(read_models.RuntimeSessionState, @enumFromInt(code))),
        .traffic => @tagName(@as(read_models.TrafficState, @enumFromInt(code))),
    };
}

fn eventKind(dimension: Dimension, code: u8) []const u8 {
    return switch (dimension) {
        .liveness => switch (@as(read_models.LivenessState, @enumFromInt(code))) {
            .unknown => "node.liveness_unknown",
            .online => "node.online",
            .suspect => "node.suspect",
            .offline => "node.offline",
        },
        .session => switch (@as(read_models.RuntimeSessionState, @enumFromInt(code))) {
            .disconnected => "node.session.disconnected",
            .enrolling => "node.session.enrolling",
            .connecting => "node.session.connecting",
            .established => "node.session.established",
        },
        .traffic => switch (@as(read_models.TrafficState, @enumFromInt(code))) {
            .unknown => "node.traffic.unknown",
            .cold => "node.traffic.cold",
            .warm => "node.traffic.warm",
            .hot => "node.traffic.hot",
            .saturated => "node.traffic.saturated",
        },
    };
}

fn eventSeverity(
    dimension: Dimension,
    code: u8,
) operations_repository.EventSeverity {
    return switch (dimension) {
        .liveness => switch (@as(read_models.LivenessState, @enumFromInt(code))) {
            .online => .info,
            .suspect, .unknown => .warning,
            .offline => .@"error",
        },
        .session => switch (@as(read_models.RuntimeSessionState, @enumFromInt(code))) {
            .disconnected => .warning,
            .enrolling, .connecting, .established => .info,
        },
        .traffic => switch (@as(read_models.TrafficState, @enumFromInt(code))) {
            .unknown => .warning,
            .cold, .warm, .hot => .info,
            .saturated => .warning,
        },
    };
}

fn deriveEventId(
    namespace: [16]u8,
    node_id: model.NodeId,
    dimension: Dimension,
    from: u8,
    to: u8,
    observed_at: i64,
    sequence: u64,
) [16]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("ntip-runtime-transition-v0.2\x00");
    hash.update(&namespace);
    hash.update(&node_id.bytes);
    hash.update(&.{ @intFromEnum(dimension), from, to });
    var timestamp_bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &timestamp_bytes, observed_at, .big);
    hash.update(&timestamp_bytes);
    var sequence_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &sequence_bytes, sequence, .big);
    hash.update(&sequence_bytes);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    var result: [16]u8 = digest[0..16].*;
    result[6] = (result[6] & 0x0f) | 0x50;
    result[8] = (result[8] & 0x3f) | 0x80;
    return result;
}

fn nodeIdLessThan(_: void, left: model.NodeId, right: model.NodeId) bool {
    return std.mem.order(u8, &left.bytes, &right.bytes) == .lt;
}

fn entryLessThan(_: void, left: Entry, right: Entry) bool {
    return nodeIdLessThan({}, left.node_id, right.node_id);
}

const FakeRuntime = struct {
    observation: read_models.RuntimeObservation = .{
        .liveness = .online,
        .session_state = .established,
        .traffic_state = .warm,
    },
    calls: usize = 0,
    fail: bool = false,

    fn source(self: *FakeRuntime) read_models.RuntimeSource {
        return .{ .context = self, .observe_fn = observeOpaque };
    }

    fn observeOpaque(
        raw: ?*anyopaque,
        _: model.NodeId,
        _: i64,
    ) !?read_models.RuntimeObservation {
        const self: *FakeRuntime = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
        if (self.fail) return error.RuntimeUnavailable;
        return self.observation;
    }
};

const FaultAppender = struct {
    repository: *operations_repository.Repository,
    mode: enum { pass, busy, locked, fail } = .pass,
    attempted_id: ?[16]u8 = null,
    calls: usize = 0,

    fn appender(self: *FaultAppender) EventAppender {
        return .{ .context = self, .append_fn = appendOpaque };
    }

    fn appendOpaque(
        raw: ?*anyopaque,
        event: operations_repository.RuntimeEventInput,
    ) !void {
        const self: *FaultAppender = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
        self.attempted_id = event.id;
        switch (self.mode) {
            .pass => try self.repository.appendRuntimeEvent(event),
            .busy => return error.DatabaseBusy,
            .locked => return error.DatabaseLocked,
            .fail => return error.SqliteFailure,
        }
    }
};

fn testNodeId(value: u8) model.NodeId {
    var id: model.NodeId = .{ .bytes = [_]u8{0} ** 16 };
    id.bytes[15] = value;
    return id;
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn insertTestNodes(db: *sqlite.Database, ids: []const model.NodeId) !void {
    try db.exec(
        "INSERT INTO vnrs (name,network,prefix,created_at,updated_at) " ++
            "VALUES ('core',167772160,24,1,1);",
    );
    for (ids, 0..) |id, index| {
        var name_buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "node-{d}", .{index + 1});
        var statement = try db.prepare(
            "INSERT INTO nodes (id,name,vnr_name,address,created_at,updated_at) " ++
                "VALUES (?1,?2,'core',?3,1,1);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id.bytes);
        try statement.bindText(2, name);
        try statement.bindInt64(3, @as(i64, @intCast(167772162 + index)));
        if (try statement.step() != .done) return error.UnexpectedRow;
    }
}

fn countRows(db: *sqlite.Database, comptime sql_text: [:0]const u8) !i64 {
    var statement = try db.prepare(sql_text);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const result = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return result;
}

fn findEvent(
    page: *const operations_repository.RuntimeEventPage,
    kind: []const u8,
) ?*const operations_repository.RuntimeEventRecord {
    for (page.items) |*item| {
        if (std.mem.eql(u8, item.kind, kind)) return item;
    }
    return null;
}

test "silent baseline records only deterministic public state transitions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const node_id = testNodeId(1);
    try insertTestNodes(&db, &.{node_id});
    var repository = operations_repository.Repository.init(&db);
    var runtime: FakeRuntime = .{};
    var recorder = try Recorder.init(
        std.testing.allocator,
        runtime.source(),
        &repository,
        [_]u8{0xa5} ** 16,
        .{ .maximum_nodes = 4 },
    );
    defer recorder.deinit();

    const initial = try recorder.tick(&.{node_id}, 100, .{ .maximum_event_writes = 8 });
    try std.testing.expectEqual(@as(usize, 1), initial.initialized_nodes);
    try std.testing.expectEqual(@as(usize, 0), initial.events_appended);
    try std.testing.expectEqual(@as(i64, 0), try countRows(&db, "SELECT count(*) FROM runtime_events;"));

    runtime.observation = .{
        .liveness = .offline,
        .session_state = .disconnected,
        .observed_endpoint = try read_models.EndpointText.parse("198.51.100.8:51900"),
        .traffic_state = .unknown,
        .authenticated_rx_at = 98,
        .authenticated_tx_at = 99,
    };
    const changed = try recorder.tick(&.{node_id}, 101, .{ .maximum_event_writes = 8 });
    try std.testing.expectEqual(@as(usize, 3), changed.transitions_observed);
    try std.testing.expectEqual(@as(usize, 3), changed.events_appended);
    try std.testing.expectEqual(@as(usize, 0), changed.events_pending);

    var page = try repository.listRuntimeEvents(std.testing.allocator, null, 10);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), page.items.len);
    const offline = findEvent(&page, "node.offline").?;
    try std.testing.expectEqual(operations_repository.EventSeverity.@"error", offline.severity);
    try std.testing.expectEqual(@as(?[16]u8, node_id.bytes), offline.node_id);
    try std.testing.expectEqual(@as(i64, 101), offline.observed_at);
    try std.testing.expectEqualStrings("{\"from\":\"online\",\"to\":\"offline\"}", offline.details_json);
    try std.testing.expect(findEvent(&page, "node.session.disconnected") != null);
    try std.testing.expect(findEvent(&page, "node.traffic.unknown") != null);
    for (page.items) |event| {
        try std.testing.expect(std.mem.indexOf(u8, event.details_json, "198.51.100.8") == null);
        try std.testing.expect(std.mem.indexOf(u8, event.details_json, "session") == null);
        try std.testing.expect((event.id[6] & 0xf0) == 0x50);
        try std.testing.expect((event.id[8] & 0xc0) == 0x80);
    }

    const unchanged = try recorder.tick(&.{node_id}, 102, .{ .maximum_event_writes = 8 });
    try std.testing.expectEqual(@as(usize, 0), unchanged.transitions_observed);
    try std.testing.expectEqual(@as(usize, 0), unchanged.events_appended);
    try std.testing.expectEqual(@as(i64, 3), try countRows(&db, "SELECT count(*) FROM runtime_events;"));
}

test "busy SQLite preserves retry identity and coalesces to the latest transition" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const node_id = testNodeId(2);
    try insertTestNodes(&db, &.{node_id});
    var repository = operations_repository.Repository.init(&db);
    var runtime: FakeRuntime = .{};
    var fault: FaultAppender = .{ .repository = &repository };
    var recorder = try Recorder.initWithAppender(
        std.testing.allocator,
        runtime.source(),
        fault.appender(),
        [_]u8{0xb6} ** 16,
        .{ .maximum_nodes = 1 },
    );
    defer recorder.deinit();
    _ = try recorder.tick(&.{node_id}, 200, .{});

    runtime.observation = .{
        .liveness = .offline,
        .session_state = .disconnected,
        .traffic_state = .unknown,
    };
    fault.mode = .busy;
    const pressured = try recorder.tick(&.{node_id}, 201, .{ .maximum_event_writes = 3 });
    try std.testing.expect(pressured.database_pressure);
    try std.testing.expectEqual(@as(usize, 3), pressured.events_pending);
    const original_attempt = fault.attempted_id.?;

    // An unchanged sample retries the exact event identity.
    fault.mode = .locked;
    const locked = try recorder.tick(&.{node_id}, 202, .{ .maximum_event_writes = 3 });
    try std.testing.expect(locked.database_pressure);
    try std.testing.expectEqual(original_attempt, fault.attempted_id.?);

    // Before SQLite recovers all three dimensions move again. The recorder
    // keeps a single transition from the last durable baseline to this latest
    // observation, rather than emitting the stale offline sample.
    runtime.observation = .{
        .liveness = .suspect,
        .session_state = .connecting,
        .traffic_state = .cold,
    };
    const coalesced = try recorder.tick(&.{node_id}, 203, .{ .maximum_event_writes = 0 });
    try std.testing.expectEqual(@as(usize, 3), coalesced.transitions_coalesced);
    try std.testing.expectEqual(@as(usize, 3), coalesced.events_pending);

    fault.mode = .pass;
    const first_write = try recorder.tick(&.{node_id}, 204, .{ .maximum_event_writes = 1 });
    try std.testing.expectEqual(@as(usize, 1), first_write.events_appended);
    try std.testing.expectEqual(@as(usize, 2), first_write.events_pending);
    const remaining = try recorder.tick(&.{node_id}, 205, .{ .maximum_event_writes = 2 });
    try std.testing.expectEqual(@as(usize, 2), remaining.events_appended);
    try std.testing.expectEqual(@as(usize, 0), remaining.events_pending);

    var page = try repository.listRuntimeEvents(std.testing.allocator, null, 10);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), page.items.len);
    const suspect = findEvent(&page, "node.suspect").?;
    try std.testing.expectEqualStrings("{\"from\":\"online\",\"to\":\"suspect\"}", suspect.details_json);
    try std.testing.expect(findEvent(&page, "node.offline") == null);
    try std.testing.expect(findEvent(&page, "node.session.connecting") != null);
    try std.testing.expect(findEvent(&page, "node.traffic.cold") != null);
}

test "unexpected append failure also retains the exact pending event" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const node_id = testNodeId(3);
    try insertTestNodes(&db, &.{node_id});
    var repository = operations_repository.Repository.init(&db);
    var runtime: FakeRuntime = .{};
    var fault: FaultAppender = .{ .repository = &repository };
    var recorder = try Recorder.initWithAppender(
        std.testing.allocator,
        runtime.source(),
        fault.appender(),
        [_]u8{0xc7} ** 16,
        .{ .maximum_nodes = 1 },
    );
    defer recorder.deinit();
    _ = try recorder.tick(&.{node_id}, 300, .{});
    runtime.observation.liveness = .offline;
    fault.mode = .fail;
    try std.testing.expectError(
        error.SqliteFailure,
        recorder.tick(&.{node_id}, 301, .{ .maximum_event_writes = 1 }),
    );
    try std.testing.expectEqual(@as(usize, 1), recorder.pendingEventCount());
    const failed_id = fault.attempted_id.?;

    fault.mode = .pass;
    const retry = try recorder.tick(&.{node_id}, 302, .{ .maximum_event_writes = 1 });
    try std.testing.expectEqual(@as(usize, 1), retry.events_appended);
    var page = try repository.listRuntimeEvents(std.testing.allocator, null, 10);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), page.items.len);
    try std.testing.expectEqual(failed_id, page.items[0].id);
}

test "removal evicts pending observations and reappearance starts silently" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const first = testNodeId(4);
    const second = testNodeId(5);
    try insertTestNodes(&db, &.{ first, second });
    var repository = operations_repository.Repository.init(&db);
    var runtime: FakeRuntime = .{};
    var recorder = try Recorder.init(
        std.testing.allocator,
        runtime.source(),
        &repository,
        [_]u8{0xd8} ** 16,
        .{ .maximum_nodes = 2 },
    );
    defer recorder.deinit();
    _ = try recorder.tick(&.{ second, first }, 400, .{});
    runtime.observation = .{
        .liveness = .offline,
        .session_state = .disconnected,
        .traffic_state = .unknown,
    };
    _ = try recorder.tick(&.{ first, second }, 401, .{ .maximum_event_writes = 0 });
    try std.testing.expectEqual(@as(usize, 6), recorder.pendingEventCount());

    const removed = try recorder.tick(&.{first}, 402, .{ .maximum_event_writes = 0 });
    try std.testing.expectEqual(@as(usize, 1), removed.removed_nodes);
    try std.testing.expectEqual(@as(usize, 3), removed.removed_pending_transitions);
    try std.testing.expectEqual(@as(usize, 3), removed.events_pending);
    const empty = try recorder.tick(&.{}, 403, .{ .maximum_event_writes = 0 });
    try std.testing.expectEqual(@as(usize, 1), empty.removed_nodes);
    try std.testing.expectEqual(@as(usize, 3), empty.removed_pending_transitions);
    try std.testing.expectEqual(@as(usize, 0), recorder.trackedNodeCount());

    // The same management ID is treated as a fresh durable Node and its
    // current state becomes a new silent baseline.
    const reappeared = try recorder.tick(&.{first}, 404, .{});
    try std.testing.expectEqual(@as(usize, 1), reappeared.initialized_nodes);
    try std.testing.expectEqual(@as(usize, 0), reappeared.events_appended);
    try std.testing.expectEqual(@as(i64, 0), try countRows(&db, "SELECT count(*) FROM runtime_events;"));
}

test "tick rejects unbounded ambiguous and backwards input before observation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const first = testNodeId(6);
    const second = testNodeId(7);
    try insertTestNodes(&db, &.{ first, second });
    var repository = operations_repository.Repository.init(&db);
    var runtime: FakeRuntime = .{};
    try std.testing.expectError(
        error.InvalidMaximumNodes,
        Recorder.init(std.testing.allocator, runtime.source(), &repository, [_]u8{0} ** 16, .{ .maximum_nodes = 0 }),
    );
    var recorder = try Recorder.init(
        std.testing.allocator,
        runtime.source(),
        &repository,
        [_]u8{0xe9} ** 16,
        .{ .maximum_nodes = 2 },
    );
    defer recorder.deinit();
    try std.testing.expectError(error.InvalidTimestamp, recorder.tick(&.{first}, -1, .{}));
    try std.testing.expectError(error.DuplicateNodeId, recorder.tick(&.{ first, first }, 1, .{}));
    try std.testing.expectError(
        error.NodeCapacityExceeded,
        recorder.tick(&.{ first, second, testNodeId(8) }, 1, .{}),
    );
    try std.testing.expectEqual(@as(usize, 0), runtime.calls);
    _ = try recorder.tick(&.{first}, 10, .{});
    try std.testing.expectError(error.NonMonotonicTimestamp, recorder.tick(&.{first}, 9, .{}));
    try std.testing.expectEqual(@as(usize, 1), runtime.calls);

    runtime.fail = true;
    try std.testing.expectError(error.RuntimeUnavailable, recorder.tick(&.{first}, 11, .{}));
    try std.testing.expectEqual(@as(usize, 1), recorder.trackedNodeCount());
}
