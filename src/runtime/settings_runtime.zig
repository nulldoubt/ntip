//! Durable live-settings application for the Master runtime.
//!
//! The HTTP/operator layer commits an immutable `pending_apply` revision and
//! then publishes it into a one-slot coalescing mailbox. The serialized
//! control worker applies kernel and control-plane state, submits the exact
//! DATA-plane settings snapshot, and waits for the DATA worker's bounded-queue
//! acknowledgement. Only then does it mark the revision effective and publish
//! the new durable configuration generation to Nodes.

const std = @import("std");
const model = @import("../domain/model.zig");
const routes_mod = @import("../platform/linux/routes.zig");
const management_settings = @import("../management/settings.zig");
const operations_service = @import("../management/operations_service.zig");
const access_repository = @import("../state/access_repository.zig");
const idempotency_repository = @import("../state/idempotency_repository.zig");
const management_repository = @import("../state/management_repository.zig");
const operations_repository = @import("../state/operations_repository.zig");
const settings_repository = @import("../state/settings_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const control_plane = @import("control_plane.zig");
const data_worker = @import("data_worker.zig");
const traffic = @import("traffic.zig");

const retention_interval_ns: u64 = 24 * std.time.ns_per_hour;
const retention_retry_ns: u64 = std.time.ns_per_hour;

pub const Command = struct {
    sequence: u64,
    values: management_settings.OperationalSettings,
};

/// Capacity-one mailbox. Production publication and consumption are both on
/// the serialized operator thread; coalescing still makes admission explicit
/// and keeps a future cross-thread adapter from growing an unbounded queue.
pub const Mailbox = struct {
    pending: ?Command = null,

    pub fn publisher(self: *Mailbox) operations_service.SettingsPublisher {
        return .{ .context = self, .publish_fn = publishOpaque };
    }

    pub fn publish(self: *Mailbox, sequence: u64, values: management_settings.OperationalSettings) void {
        if (sequence == 0) return;
        if (self.pending) |current| {
            if (sequence <= current.sequence) return;
        }
        self.pending = .{ .sequence = sequence, .values = values };
    }

    fn take(self: *Mailbox) ?Command {
        const command = self.pending;
        self.pending = null;
        return command;
    }

    fn restore(self: *Mailbox, command: Command) void {
        if (self.pending) |current| {
            if (current.sequence >= command.sequence) return;
        }
        self.pending = command;
    }

    fn publishOpaque(
        raw: ?*anyopaque,
        sequence: u64,
        values: management_settings.OperationalSettings,
    ) void {
        const self: *Mailbox = @ptrCast(@alignCast(raw.?));
        self.publish(sequence, values);
    }
};

/// Infallible notification of a newly committed effective snapshot. The live
/// operator callback either retains that exact immutable generation in its
/// reserved publication slot or makes the service terminal before another
/// Store mutation is admitted; startup recovery then projects SQLite.
pub const EffectiveObserver = struct {
    context: *anyopaque,
    stage_mtu_fn: *const fn (*anyopaque, u16) void,
    committed_fn: *const fn (
        *anyopaque,
        management_settings.OperationalSettings,
        u64,
    ) void,

    pub fn stageMtu(self: EffectiveObserver, mtu: u16) void {
        self.stage_mtu_fn(self.context, mtu);
    }

    pub fn committed(
        self: EffectiveObserver,
        values: management_settings.OperationalSettings,
        generation: u64,
    ) void {
        self.committed_fn(self.context, values, generation);
    }
};

const InFlight = struct {
    command: Command,
    previous: management_settings.OperationalSettings,
};

pub const Applier = struct {
    io: std.Io,
    settings: *settings_repository.Repository,
    operations: *operations_repository.Repository,
    access: access_repository.Repository,
    idempotency: idempotency_repository.Repository,
    store: *const model.Store,
    control: *control_plane.ControlPlane,
    worker: *data_worker.DataWorker,
    routes: routes_mod.Controller,
    interface_name: []const u8,
    mailbox: *Mailbox,
    observer: EffectiveObserver,
    runtime_capacity: u32,
    in_flight: ?InFlight = null,
    acknowledged_sequence: ?u64 = null,
    acknowledgement_mismatch: bool = false,
    next_retention_ns: u64 = 0,

    pub fn init(
        io: std.Io,
        settings: *settings_repository.Repository,
        operations: *operations_repository.Repository,
        access: access_repository.Repository,
        idempotency: idempotency_repository.Repository,
        store: *const model.Store,
        control: *control_plane.ControlPlane,
        worker: *data_worker.DataWorker,
        routes: routes_mod.Controller,
        interface_name: []const u8,
        mailbox: *Mailbox,
        observer: EffectiveObserver,
        runtime_capacity: u32,
    ) Applier {
        return .{
            .io = io,
            .settings = settings,
            .operations = operations,
            .access = access,
            .idempotency = idempotency,
            .store = store,
            .control = control,
            .worker = worker,
            .routes = routes,
            .interface_name = interface_name,
            .mailbox = mailbox,
            .observer = observer,
            .runtime_capacity = runtime_capacity,
        };
    }

    pub fn attach(self: *Applier) void {
        self.control.setRuntimeSettingsObserver(.{
            .context = self,
            .applied_fn = appliedOpaque,
        });
    }

    pub fn deinit(self: *Applier) void {
        self.control.setRuntimeSettingsObserver(null);
        self.* = undefined;
    }

    /// Recovers a durable state left by a crash. A live revision re-enters the
    /// exact same runtime path as an online mutation. A restart-only revision
    /// is activated only when this process was actually constructed with its
    /// requested bounded capacity.
    pub fn recover(self: *Applier, initial: settings_repository.State) !void {
        switch (initial.desired.status) {
            .pending_apply => self.mailbox.publish(initial.desired.sequence, initial.desired.values),
            .pending_restart => try self.activateRestart(initial),
            .active, .failed => {},
        }
    }

    pub fn tick(self: *Applier, now_ns: u64) !void {
        if (self.acknowledgement_mismatch) return error.SettingsAcknowledgementMismatch;

        if (self.in_flight) |pending| {
            if (self.acknowledged_sequence) |sequence| {
                if (sequence != pending.command.sequence) return error.SettingsAcknowledgementMismatch;
                try self.commitApplied(pending.command);
                // Clear the non-droppable acknowledgement only after the
                // durable effective/audit commit succeeds. A failed commit
                // exits into startup recovery without pretending the runtime
                // acknowledgement was consumed.
                self.acknowledged_sequence = null;
                self.in_flight = null;
            }
            // Settings acknowledgements and committed mutations take priority
            // over best-effort retention maintenance.
            return;
        }

        if (self.mailbox.take()) |command| {
            try self.begin(command);
            return;
        }

        if (now_ns < self.next_retention_ns) return;
        const backlog_possible = self.runRetention() catch |err| {
            std.log.warn("bounded retention maintenance failed: {s}", .{@errorName(err)});
            self.next_retention_ns = now_ns +| retention_retry_ns;
            return;
        };
        // A full batch may mean more expired rows remain. Continue catching up
        // in bounded hourly passes; return to the daily cadence once a pass is
        // known not to have saturated either deletion limit.
        self.next_retention_ns = now_ns +| (if (backlog_possible)
            retention_retry_ns
        else
            retention_interval_ns);
    }

    fn begin(self: *Applier, command: Command) !void {
        const current = try self.settings.loadState();
        if (current.desired.sequence != command.sequence or current.desired.status != .pending_apply) {
            // A coalesced or already-reconciled notification is harmless; the
            // durable settings pointer remains authoritative.
            return;
        }
        if (!std.meta.eql(current.desired.values, command.values)) {
            return error.SettingsAcknowledgementMismatch;
        }

        const previous = current.effective.values;
        // Inventory kernel reconciliation can run later in this same control
        // loop. Stage its MTU before touching the kernel so it cannot race the
        // live transition and restore an obsolete route metric.
        self.observer.stageMtu(command.values.inner_mtu);
        self.applyKernel(command.values.inner_mtu) catch {
            self.applyKernel(previous.inner_mtu) catch return error.SettingsRuntimeRollbackFailed;
            self.observer.stageMtu(previous.inner_mtu);
            try self.commitFailed(command.sequence, "mtu_apply_failed");
            return;
        };
        self.control.configureLiveness(
            command.values.heartbeat_idle_seconds,
            command.values.suspect_after_seconds,
            command.values.offline_after_seconds,
        ) catch {
            self.applyKernel(previous.inner_mtu) catch return error.SettingsRuntimeRollbackFailed;
            self.observer.stageMtu(previous.inner_mtu);
            try self.commitFailed(command.sequence, "liveness_apply_failed");
            return;
        };

        const accepted = self.worker.submit(data_worker.DataCommand.applyRuntimeSettings(
            command.sequence,
            trafficConfig(command.values),
            command.values.inner_mtu,
        ));
        if (!accepted) {
            // Queue saturation is transient, not a revision failure. Restore
            // every synchronously changed component before retrying so the
            // previous effective snapshot remains the coherent public state.
            try self.control.configureLiveness(
                previous.heartbeat_idle_seconds,
                previous.suspect_after_seconds,
                previous.offline_after_seconds,
            );
            self.applyKernel(previous.inner_mtu) catch return error.SettingsRuntimeRollbackFailed;
            self.observer.stageMtu(previous.inner_mtu);
            self.mailbox.restore(command);
            return;
        }
        self.in_flight = .{ .command = command, .previous = previous };
    }

    fn commitApplied(self: *Applier, command: Command) !void {
        const now = try wallSeconds(self.io);
        var applied_resource: [32]u8 = undefined;
        var applied = try self.settings.acknowledgeApplied(
            command.sequence,
            randomUuid(self.io),
            now,
            systemAudit(self.io, command.sequence, now, "settings.runtime_applied", &applied_resource),
        );
        if (applied.desired.status == .pending_restart and
            applied.desired.values.maximum_nodes == self.runtime_capacity)
        {
            var restart_resource: [32]u8 = undefined;
            applied = try self.settings.activateAfterRestart(
                applied.desired.sequence,
                now,
                systemAudit(self.io, applied.desired.sequence, now, "settings.restart_activate", &restart_resource),
            );
        }
        const generation = try management_repository.Repository.init(self.settings.db).durableGeneration();
        self.observer.committed(applied.effective.values, generation);
    }

    fn activateRestart(self: *Applier, current: settings_repository.State) !void {
        if (current.desired.values.maximum_nodes != self.runtime_capacity) return;
        const now = try wallSeconds(self.io);
        var resource: [32]u8 = undefined;
        const applied = try self.settings.activateAfterRestart(
            current.desired.sequence,
            now,
            systemAudit(self.io, current.desired.sequence, now, "settings.restart_activate", &resource),
        );
        const generation = try management_repository.Repository.init(self.settings.db).durableGeneration();
        self.observer.committed(applied.effective.values, generation);
    }

    fn commitFailed(self: *Applier, sequence: u64, code: []const u8) !void {
        const now = try wallSeconds(self.io);
        const failure = try settings_repository.FailureCode.parse(code);
        var resource: [32]u8 = undefined;
        _ = try self.settings.acknowledgeFailed(
            sequence,
            failure,
            now,
            systemAudit(self.io, sequence, now, "settings.runtime_failed", &resource),
        );
    }

    fn applyKernel(self: *Applier, mtu: u16) !void {
        try self.routes.configureLink(self.interface_name, mtu);
        for (self.store.routes.items) |route| {
            var buffer: [18]u8 = undefined;
            try self.routes.replaceRoute(self.interface_name, try route.prefix.write(&buffer), mtu);
        }
    }

    fn runRetention(self: *Applier) !bool {
        const current = try self.settings.loadState();
        const now = try wallSeconds(self.io);
        const batch = operations_repository.default_retention_batch_size;
        const events = try self.operations.pruneRuntimeEventsForDaysBounded(
            now,
            current.effective.values.runtime_event_retention_days,
            batch,
        );
        const checks = try self.operations.pruneConnectivityChecksForDaysBounded(
            now,
            current.effective.values.connectivity_result_retention_days,
            batch,
        );
        const security_events = try self.operations.pruneSecurityEventsBounded(now, batch);
        const sessions = try self.access.pruneExpiredSessions(now, batch);
        const throttles = try self.access.pruneStaleLoginThrottles(now, batch);
        const idempotency = try self.idempotency.pruneExpired(now, batch);
        if (events != 0 or checks != 0 or security_events != 0 or sessions != 0 or
            throttles != 0 or idempotency != 0)
        {
            std.log.info(
                "bounded retention removed events={d} security_events={d} checks={d} sessions={d} throttles={d} idempotency={d}",
                .{ events, security_events, checks, sessions, throttles, idempotency },
            );
        }
        return events == batch or checks == batch or security_events == batch or
            sessions == batch or throttles == batch or idempotency == batch;
    }

    fn appliedOpaque(raw: *anyopaque, sequence: u64) void {
        const self: *Applier = @ptrCast(@alignCast(raw));
        if (self.in_flight) |pending| {
            if (pending.command.sequence == sequence and self.acknowledged_sequence == null) {
                self.acknowledged_sequence = sequence;
                return;
            }
        }
        self.acknowledgement_mismatch = true;
    }
};

fn trafficConfig(values: management_settings.OperationalSettings) traffic.Config {
    return .{
        .cold_after_ns = @as(u64, values.traffic_cold_after_seconds) * std.time.ns_per_s,
        .hot_pps = @intCast(values.traffic_hot_packets_per_second),
        .hot_bits_per_second = values.traffic_hot_bits_per_second,
        .saturated_queue_percent = values.traffic_saturated_queue_percent,
        .hysteresis_ns = @as(u64, values.traffic_hysteresis_seconds) * std.time.ns_per_s,
    };
}

fn systemAudit(
    io: std.Io,
    sequence: u64,
    now: i64,
    action: []const u8,
    resource_buffer: *[32]u8,
) management_repository.AuditEntry {
    const resource_id = std.fmt.bufPrint(resource_buffer, "{d}", .{sequence}) catch unreachable;
    return .{
        .id = randomUuid(io),
        .occurred_at = now,
        .actor_kind = .system,
        .action = action,
        .resource_type = "settings_revision",
        .resource_id = resource_id,
        .details_json = "{\"source\":\"runtime\"}",
    };
}

fn randomUuid(io: std.Io) [16]u8 {
    var id: [16]u8 = undefined;
    io.random(&id);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    return id;
}

fn wallSeconds(io: std.Io) !i64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.ClockBeforeUnixEpoch;
    return seconds;
}

test "settings mailbox is bounded and coalesces the newest durable revision" {
    var mailbox: Mailbox = .{};
    const publisher = mailbox.publisher();
    var first = management_settings.OperationalSettings{};
    first.inner_mtu = 1400;
    var second = first;
    second.inner_mtu = 1420;

    publisher.publish(2, first);
    publisher.publish(1, .{});
    publisher.publish(3, second);
    const selected = mailbox.take().?;
    try std.testing.expectEqual(@as(u64, 3), selected.sequence);
    try std.testing.expectEqual(@as(u16, 1420), selected.values.inner_mtu);
    try std.testing.expect(mailbox.take() == null);

    mailbox.restore(selected);
    publisher.publish(4, first);
    mailbox.restore(selected);
    try std.testing.expectEqual(@as(u64, 4), mailbox.take().?.sequence);
}

test "runtime traffic projection preserves validated thresholds" {
    var values = management_settings.OperationalSettings{};
    values.traffic_cold_after_seconds = 7;
    values.traffic_hot_packets_per_second = 1234;
    values.traffic_hot_bits_per_second = 9_876_543;
    values.traffic_saturated_queue_percent = 73;
    values.traffic_hysteresis_seconds = 9;
    const projected = trafficConfig(values);
    try std.testing.expectEqual(@as(u64, 7 * std.time.ns_per_s), projected.cold_after_ns);
    try std.testing.expectEqual(@as(u32, 1234), projected.hot_pps);
    try std.testing.expectEqual(@as(u64, 9_876_543), projected.hot_bits_per_second);
    try std.testing.expectEqual(@as(u8, 73), projected.saturated_queue_percent);
    try std.testing.expectEqual(@as(u64, 9 * std.time.ns_per_s), projected.hysteresis_ns);
}

const GenerationObserver = struct {
    previous_generation: u64,
    committed_generation: ?u64 = null,
    committed_values: ?management_settings.OperationalSettings = null,
    stale_commit: bool = false,

    fn observer(self: *GenerationObserver) EffectiveObserver {
        return .{
            .context = self,
            .stage_mtu_fn = stageMtu,
            .committed_fn = committed,
        };
    }

    fn stageMtu(_: *anyopaque, _: u16) void {}

    fn committed(
        raw: *anyopaque,
        values: management_settings.OperationalSettings,
        generation: u64,
    ) void {
        const self: *GenerationObserver = @ptrCast(@alignCast(raw));
        self.stale_commit = generation <= self.previous_generation;
        self.committed_generation = generation;
        self.committed_values = values;
    }
};

fn runtimeSettingsTestPath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

test "startup restart activation crosses the committed generation barrier" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try runtimeSettingsTestPath(&tmp, &path_buffer));
    defer db.close();

    var repository = settings_repository.Repository.init(&db);
    var desired = management_settings.OperationalSettings{};
    desired.maximum_nodes = 8192;
    const pending = try repository.createRevision(
        .{21} ** 16,
        desired,
        0,
        1,
        10,
        .system,
        null,
        .{
            .id = .{22} ** 16,
            .occurred_at = 10,
            .actor_kind = .system,
            .action = "settings.update",
            .resource_type = "settings_revision",
        },
    );
    try std.testing.expectEqual(management_settings.RevisionStatus.pending_restart, pending.status);

    const generation_before = try management_repository.Repository.init(&db).durableGeneration();
    var generation_observer: GenerationObserver = .{ .previous_generation = generation_before };
    var mailbox: Mailbox = .{};
    // Startup restart recovery only touches the fields initialized below. The
    // data/control dependencies are deliberately absent: activation must be a
    // durable repository transition followed by one committed notification.
    var applier: Applier = .{
        .io = std.testing.io,
        .settings = &repository,
        .operations = undefined,
        .access = undefined,
        .idempotency = undefined,
        .store = undefined,
        .control = undefined,
        .worker = undefined,
        .routes = undefined,
        .interface_name = "ntip-test",
        .mailbox = &mailbox,
        .observer = generation_observer.observer(),
        .runtime_capacity = desired.maximum_nodes,
    };

    try applier.recover(try repository.loadState());

    try std.testing.expect(!generation_observer.stale_commit);
    try std.testing.expectEqual(generation_before + 1, generation_observer.committed_generation.?);
    try std.testing.expectEqual(
        generation_observer.committed_generation.?,
        try management_repository.Repository.init(&db).durableGeneration(),
    );
    try std.testing.expectEqual(
        desired.maximum_nodes,
        generation_observer.committed_values.?.maximum_nodes,
    );
    const recovered = try repository.loadState();
    try std.testing.expectEqual(management_settings.RevisionStatus.active, recovered.desired.status);
    try std.testing.expectEqual(recovered.desired.sequence, recovered.effective.sequence);
}
