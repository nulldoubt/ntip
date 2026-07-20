//! Serialized application-owner seam for the v0.2 management plane.
//!
//! `Service` is the concrete owner around `management_repository.Repository`.
//! `SerializedOwner` is public so deterministic tests and adapters can use the
//! same scheduling rules with a repository facade. All methods are called by
//! the dedicated operator worker; cross-thread runtime producers first use an
//! existing bounded SPSC hand-off and the worker drains it here.
//!
//! An execution callback returning a committed result is a strict contract:
//! the repository transaction (including its immutable audit row) has already
//! committed. A command that can publish must declare that fact at admission,
//! allowing the owner to reserve bounded publication capacity before touching
//! durable state. The resulting immutable projection is retained until the
//! runtime sink accepts it.

const std = @import("std");
const management_repository = @import("../state/management_repository.zig");

pub const command_queue_capacity: usize = 64;
pub const command_critical_reserve: usize = 8;
pub const observation_queue_capacity: usize = 256;
pub const publication_queue_capacity: usize = 16;

comptime {
    std.debug.assert(command_critical_reserve < command_queue_capacity);
    std.debug.assert(publication_queue_capacity > 0);
}

pub const Priority = enum {
    /// Enrollment completion and other protocol state that must persist before
    /// a live session or data-plane change can be installed.
    protocol_persistence,
    /// An inventory, access, settings, or service mutation with its audit row.
    audited_mutation,
    /// Bounded CLI/API reads. Local CLI authorization is carried by `Source`.
    interactive_read,
    /// Potentially long-running audit or backup streaming work.
    bulk_export,

    fn rank(self: Priority) u2 {
        return switch (self) {
            .protocol_persistence => 0,
            .audited_mutation => 1,
            .interactive_read => 2,
            .bulk_export => 3,
        };
    }
};

pub const Source = union(enum) {
    local_cli: struct {
        uid: u32,
        pid: u32,
    },
    service: struct {
        peer_uid: u32,
        actor_id: ?[16]u8 = null,
        session_id: ?[16]u8 = null,
    },
    runtime,
    system,
};

pub const Completion = union(enum) {
    completed,
    failed: anyerror,
    /// Only read/export commands may be displaced to admit protocol-critical
    /// persistence. The original handler receives this explicit terminal
    /// completion and may retry; audited work is never preempted.
    preempted,
    expired,
};

pub const ProjectionKind = enum {
    inventory,
    enrollment,
    settings,
    access,
};

/// Immutable repository-owned projection. `value` remains valid until the
/// publication sink returns. If `release` is set, the owner invokes it exactly
/// once after publication; otherwise lifetime remains with the producer.
pub const CommittedProjection = struct {
    kind: ProjectionKind,
    generation: u64,
    value: ?*const anyopaque = null,
    release_context: ?*anyopaque = null,
    release: ?*const fn (?*anyopaque, ?*const anyopaque) void = null,
};

pub const SettingsDesired = struct {
    revision: u64,
    generation: u64,
};

pub const SettingsAcknowledgement = struct {
    revision: u64,
    generation: u64,
    applied: bool,
};

/// Desired and effective settings advance only from committed repository
/// outcomes. A failed runtime acknowledgement clears pending apply while
/// retaining the prior effective revision/generation.
pub const SettingsReconciliation = struct {
    desired_revision: u64 = 0,
    desired_generation: u64 = 0,
    effective_revision: u64 = 0,
    effective_generation: u64 = 0,
    awaiting_runtime_ack: bool = false,

    pub fn noteDesired(self: *SettingsReconciliation, desired: SettingsDesired) !void {
        if (desired.revision == 0 or desired.generation == 0) return error.InvalidSettingsGeneration;
        if (desired.revision <= self.desired_revision or
            desired.generation <= self.desired_generation)
        {
            return error.NonMonotonicSettingsGeneration;
        }
        self.desired_revision = desired.revision;
        self.desired_generation = desired.generation;
        self.awaiting_runtime_ack = true;
    }

    pub fn acknowledge(
        self: *SettingsReconciliation,
        acknowledgement: SettingsAcknowledgement,
    ) !void {
        if (!self.awaiting_runtime_ack or
            acknowledgement.revision != self.desired_revision or
            acknowledgement.generation != self.desired_generation)
        {
            return error.StaleSettingsAcknowledgement;
        }
        self.awaiting_runtime_ack = false;
        if (!acknowledgement.applied) return;
        self.effective_revision = acknowledgement.revision;
        self.effective_generation = acknowledgement.generation;
    }
};

pub const ExecutionOutcome = union(enum) {
    completed,
    committed_projection: CommittedProjection,
    settings_desired_committed: struct {
        desired: SettingsDesired,
        projection: CommittedProjection,
    },
    settings_ack_committed: struct {
        acknowledgement: SettingsAcknowledgement,
        /// Present only when a successful acknowledgement produced a new
        /// effective runtime projection.
        projection: ?CommittedProjection = null,
    },
};

pub const CommandContract = enum {
    no_publication,
    publishes_projection,
};

pub const ObservationState = enum(u2) {
    online,
    suspect,
    offline,
    unknown,
};

pub const TrafficState = enum(u2) {
    cold,
    warm,
    hot,
    saturated,
};

pub const ObservationPayload = union(enum) {
    liveness: struct {
        state: ObservationState,
        session_active: bool,
    },
    endpoint: struct {
        address: [16]u8,
        address_length: u8,
        port: u16,
    },
    traffic: struct {
        state: TrafficState,
        authenticated_rx_bytes: u64,
        authenticated_tx_bytes: u64,
    },
    authenticated_activity: struct {
        last_rx_ns: ?u64,
        last_tx_ns: ?u64,
    },
};

/// Allocation-free observation value suitable for a bounded runtime hand-off.
/// Queue identity is `(node_id, payload tag)`, so a newer observation replaces
/// an older queued observation of the same aspect under pressure.
pub const RuntimeObservation = struct {
    node_id: [16]u8,
    sequence: u64,
    observed_at_ns: u64,
    payload: ObservationPayload,

    fn sameKey(left: RuntimeObservation, right: RuntimeObservation) bool {
        return std.mem.eql(u8, &left.node_id, &right.node_id) and
            std.meta.activeTag(left.payload) == std.meta.activeTag(right.payload);
    }
};

pub const ObservationAdmission = enum {
    queued,
    replaced_older,
    ignored_stale,
};

pub fn SerializedOwner(comptime RepositoryType: type) type {
    return struct {
        const Self = @This();

        pub const ExecuteFn = *const fn (
            repository: *RepositoryType,
            context: ?*anyopaque,
        ) anyerror!ExecutionOutcome;

        pub const CompletionFn = *const fn (
            context: ?*anyopaque,
            completion: Completion,
        ) void;

        pub const PublishFn = *const fn (
            context: ?*anyopaque,
            projection: CommittedProjection,
        ) void;

        pub const Command = struct {
            request_id: [16]u8,
            source: Source,
            priority: Priority,
            contract: CommandContract,
            /// Zero disables expiry. The owner compares this with the
            /// monotonic time passed to `processOne` before execution.
            deadline_ns: u64 = 0,
            context: ?*anyopaque = null,
            execute: ExecuteFn,
            complete: ?CompletionFn = null,
        };

        repository: RepositoryType,
        commands: [command_queue_capacity]Command = undefined,
        command_count: usize = 0,
        observations: [observation_queue_capacity]RuntimeObservation = undefined,
        observation_count: usize = 0,
        publications: [publication_queue_capacity]CommittedProjection = undefined,
        publication_head: usize = 0,
        publication_count: usize = 0,
        settings: SettingsReconciliation = .{},
        processing: bool = false,

        pub fn init(repository: RepositoryType) Self {
            return .{ .repository = repository };
        }

        pub fn queuedCommands(self: *const Self) usize {
            return self.command_count;
        }

        pub fn queuedObservations(self: *const Self) usize {
            return self.observation_count;
        }

        pub fn queuedPublications(self: *const Self) usize {
            return self.publication_count;
        }

        /// Enqueues one CLI-shaped or typed-service command. Protocol-critical
        /// work can displace a read/export when the queue is otherwise full;
        /// all displacement and admission failure is explicit.
        pub fn submit(self: *Self, command: Command) !void {
            if (command.priority == .interactive_read or command.priority == .bulk_export) {
                if (self.command_count >= command_queue_capacity - command_critical_reserve) {
                    return error.CommandQueueReserved;
                }
            }

            if (self.command_count == command_queue_capacity) {
                if (command.priority != .protocol_persistence) return error.CommandQueueFull;
                const victim = self.preemptionCandidate() orelse return error.CommandQueueFull;
                const displaced = self.removeCommand(victim);
                if (displaced.complete) |complete| complete(displaced.context, .preempted);
            }

            self.commands[self.command_count] = command;
            self.command_count += 1;
        }

        /// Executes at most one command. Only this method touches the owned
        /// repository. A publish-capable command waits before execution when
        /// the bounded publication queue is full, preserving commit-before-
        /// publish without losing a committed generation.
        pub fn processOne(self: *Self, now_ns: u64) !bool {
            if (self.processing) return error.ReentrantOperatorWorker;
            if (self.command_count == 0) return false;

            const index = self.bestCommandIndex();
            const pending = self.commands[index];
            if (pending.contract == .publishes_projection and
                self.publication_count == publication_queue_capacity)
            {
                return error.PublicationBackpressure;
            }

            const command = self.removeCommand(index);
            if (command.deadline_ns != 0 and now_ns >= command.deadline_ns) {
                if (command.complete) |complete| complete(command.context, .expired);
                return true;
            }

            self.processing = true;
            defer self.processing = false;
            const outcome = command.execute(&self.repository, command.context) catch |err| {
                if (command.complete) |complete| complete(command.context, .{ .failed = err });
                return true;
            };

            self.acceptOutcome(command.contract, outcome) catch |err| {
                if (command.complete) |complete| complete(command.context, .{ .failed = err });
                return true;
            };
            if (command.complete) |complete| complete(command.context, .completed);
            return true;
        }

        /// Delivers one already-committed immutable projection to the runtime.
        /// The sink is deliberately non-failing: it represents a pre-reserved
        /// bounded runtime slot. Backpressure is handled before repository work.
        pub fn publishOne(
            self: *Self,
            context: ?*anyopaque,
            publish: PublishFn,
        ) bool {
            const projection = self.popPublication() orelse return false;
            publish(context, projection);
            if (projection.release) |release| {
                release(projection.release_context, projection.value);
            }
            return true;
        }

        pub fn submitObservation(
            self: *Self,
            observation: RuntimeObservation,
        ) !ObservationAdmission {
            for (self.observations[0..self.observation_count]) |*queued| {
                if (!RuntimeObservation.sameKey(queued.*, observation)) continue;
                if (observation.sequence <= queued.sequence) return .ignored_stale;
                queued.* = observation;
                return .replaced_older;
            }
            if (self.observation_count == observation_queue_capacity) {
                return error.ObservationQueueFull;
            }
            self.observations[self.observation_count] = observation;
            self.observation_count += 1;
            return .queued;
        }

        /// Stable FIFO for distinct observation keys. Replacement does not
        /// move the key, preventing a noisy Node from starving other Nodes.
        pub fn takeObservation(self: *Self) ?RuntimeObservation {
            if (self.observation_count == 0) return null;
            const first = self.observations[0];
            var index: usize = 1;
            while (index < self.observation_count) : (index += 1) {
                self.observations[index - 1] = self.observations[index];
            }
            self.observation_count -= 1;
            return first;
        }

        fn acceptOutcome(
            self: *Self,
            contract: CommandContract,
            outcome: ExecutionOutcome,
        ) !void {
            const publishes = switch (outcome) {
                .completed => false,
                .committed_projection => true,
                .settings_desired_committed => true,
                .settings_ack_committed => |value| value.projection != null,
            };
            if (publishes != (contract == .publishes_projection)) {
                return error.CommandContractViolated;
            }

            switch (outcome) {
                .completed => {},
                .committed_projection => |projection| self.pushPublication(projection),
                .settings_desired_committed => |value| {
                    if (value.projection.generation != value.desired.generation) {
                        return error.SettingsProjectionGenerationMismatch;
                    }
                    var next_settings = self.settings;
                    try next_settings.noteDesired(value.desired);
                    self.settings = next_settings;
                    self.pushPublication(value.projection);
                },
                .settings_ack_committed => |value| {
                    if (value.acknowledgement.applied) {
                        const projection = value.projection orelse
                            return error.SettingsProjectionRequired;
                        if (projection.generation != value.acknowledgement.generation) {
                            return error.SettingsProjectionGenerationMismatch;
                        }
                    } else if (value.projection != null) {
                        return error.SettingsProjectionForbidden;
                    }
                    var next_settings = self.settings;
                    try next_settings.acknowledge(value.acknowledgement);
                    self.settings = next_settings;
                    if (value.projection) |projection| self.pushPublication(projection);
                },
            }
        }

        fn pushPublication(self: *Self, projection: CommittedProjection) void {
            std.debug.assert(self.publication_count < publication_queue_capacity);
            const index = (self.publication_head + self.publication_count) % publication_queue_capacity;
            self.publications[index] = projection;
            self.publication_count += 1;
        }

        fn popPublication(self: *Self) ?CommittedProjection {
            if (self.publication_count == 0) return null;
            const projection = self.publications[self.publication_head];
            self.publication_head = (self.publication_head + 1) % publication_queue_capacity;
            self.publication_count -= 1;
            return projection;
        }

        fn bestCommandIndex(self: *const Self) usize {
            var best: usize = 0;
            var index: usize = 1;
            while (index < self.command_count) : (index += 1) {
                if (self.commands[index].priority.rank() < self.commands[best].priority.rank()) {
                    best = index;
                }
            }
            return best;
        }

        fn preemptionCandidate(self: *const Self) ?usize {
            var candidate: ?usize = null;
            for (self.commands[0..self.command_count], 0..) |command, index| {
                if (command.priority != .interactive_read and command.priority != .bulk_export) continue;
                if (candidate == null or
                    command.priority.rank() > self.commands[candidate.?].priority.rank())
                {
                    candidate = index;
                }
            }
            return candidate;
        }

        fn removeCommand(self: *Self, index: usize) Command {
            const removed = self.commands[index];
            var cursor = index + 1;
            while (cursor < self.command_count) : (cursor += 1) {
                self.commands[cursor - 1] = self.commands[cursor];
            }
            self.command_count -= 1;
            return removed;
        }
    };
}

pub const Service = SerializedOwner(management_repository.Repository);

const FakeRepository = struct {
    log: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    fn append(self: *FakeRepository, value: u8) !void {
        try self.log.append(self.allocator, value);
    }
};

const TestService = SerializedOwner(FakeRepository);

const TestContext = struct {
    marker: u8,
    log: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    outcome: ExecutionOutcome = .completed,
    completions: usize = 0,
    failures: usize = 0,
    preemptions: usize = 0,
};

fn testExecute(repository: *FakeRepository, opaque_context: ?*anyopaque) !ExecutionOutcome {
    const context: *TestContext = @ptrCast(@alignCast(opaque_context.?));
    try repository.append(context.marker);
    return context.outcome;
}

fn testComplete(opaque_context: ?*anyopaque, completion: Completion) void {
    const context: *TestContext = @ptrCast(@alignCast(opaque_context.?));
    switch (completion) {
        .completed, .expired => context.completions += 1,
        .failed => {
            context.completions += 1;
            context.failures += 1;
        },
        .preempted => context.preemptions += 1,
    }
}

fn testCommand(context: *TestContext, priority: Priority) TestService.Command {
    return .{
        .request_id = [_]u8{context.marker} ** 16,
        .source = .system,
        .priority = priority,
        .contract = .no_publication,
        .context = context,
        .execute = testExecute,
        .complete = testComplete,
    };
}

test "protocol persistence and audited mutations outrank reads and exports" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    var export_context = TestContext{ .marker = 'e', .log = &log, .allocator = std.testing.allocator };
    var read_context = TestContext{ .marker = 'r', .log = &log, .allocator = std.testing.allocator };
    var mutation_context = TestContext{ .marker = 'm', .log = &log, .allocator = std.testing.allocator };
    var protocol_context = TestContext{ .marker = 'p', .log = &log, .allocator = std.testing.allocator };

    try service.submit(testCommand(&export_context, .bulk_export));
    try service.submit(testCommand(&read_context, .interactive_read));
    try service.submit(testCommand(&mutation_context, .audited_mutation));
    try service.submit(testCommand(&protocol_context, .protocol_persistence));
    while (try service.processOne(1)) {}

    try std.testing.expectEqualStrings("pmre", log.items);
}

test "bounded admission reports saturation and never silently drops audited work" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    var contexts: [command_queue_capacity + 1]TestContext = undefined;
    for (&contexts, 0..) |*context, index| {
        context.* = .{
            .marker = @intCast(index),
            .log = &log,
            .allocator = std.testing.allocator,
        };
    }
    for (contexts[0..command_queue_capacity]) |*context| {
        try service.submit(testCommand(context, .audited_mutation));
    }
    try std.testing.expectError(
        error.CommandQueueFull,
        service.submit(testCommand(&contexts[command_queue_capacity], .audited_mutation)),
    );
    try std.testing.expectEqual(command_queue_capacity, service.queuedCommands());
    try std.testing.expectEqual(@as(usize, 0), contexts[command_queue_capacity].completions);
    try std.testing.expectEqual(@as(usize, 0), contexts[command_queue_capacity].preemptions);
}

test "critical admission explicitly preempts only disposable queued work" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    var export_context = TestContext{ .marker = 'e', .log = &log, .allocator = std.testing.allocator };
    var read_context = TestContext{ .marker = 'r', .log = &log, .allocator = std.testing.allocator };
    var mutation_context = TestContext{ .marker = 'm', .log = &log, .allocator = std.testing.allocator };
    var critical_context = TestContext{ .marker = 'p', .log = &log, .allocator = std.testing.allocator };

    try service.submit(testCommand(&export_context, .bulk_export));
    var reads: usize = 1;
    while (reads < command_queue_capacity - command_critical_reserve) : (reads += 1) {
        try service.submit(testCommand(&read_context, .interactive_read));
    }
    var mutations: usize = 0;
    while (mutations < command_critical_reserve) : (mutations += 1) {
        try service.submit(testCommand(&mutation_context, .audited_mutation));
    }
    try std.testing.expectEqual(command_queue_capacity, service.queuedCommands());
    try service.submit(testCommand(&critical_context, .protocol_persistence));
    try std.testing.expectEqual(command_queue_capacity, service.queuedCommands());
    try std.testing.expectEqual(@as(usize, 1), export_context.preemptions);
    try std.testing.expectEqual(@as(usize, 0), mutation_context.preemptions);
}

fn failingExecute(_: *FakeRepository, _: ?*anyopaque) !ExecutionOutcome {
    return error.InjectedRepositoryFailure;
}

test "repository failures have an explicit terminal completion" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    var context = TestContext{ .marker = 'f', .log = &log, .allocator = std.testing.allocator };
    var command = testCommand(&context, .audited_mutation);
    command.execute = failingExecute;
    try service.submit(command);
    try std.testing.expect(try service.processOne(1));
    try std.testing.expectEqual(@as(usize, 1), context.completions);
    try std.testing.expectEqual(@as(usize, 1), context.failures);
    try std.testing.expectEqual(@as(usize, 0), service.queuedPublications());
}

const PublishContext = struct {
    log: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    observed_generation: u64 = 0,
};

fn testPublish(opaque_context: ?*anyopaque, projection: CommittedProjection) void {
    const context: *PublishContext = @ptrCast(@alignCast(opaque_context.?));
    context.log.append(context.allocator, 'p') catch unreachable;
    context.observed_generation = projection.generation;
}

test "repository commit completes before an immutable projection is published" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    var command_context = TestContext{
        .marker = 'c',
        .log = &log,
        .allocator = std.testing.allocator,
        .outcome = .{ .committed_projection = .{
            .kind = .inventory,
            .generation = 7,
        } },
    };
    var command = testCommand(&command_context, .audited_mutation);
    command.contract = .publishes_projection;
    try service.submit(command);
    try std.testing.expect(try service.processOne(1));
    try std.testing.expectEqualStrings("c", log.items);
    try std.testing.expectEqual(@as(usize, 1), service.queuedPublications());

    var publish_context = PublishContext{ .log = &log, .allocator = std.testing.allocator };
    try std.testing.expect(service.publishOne(&publish_context, testPublish));
    try std.testing.expectEqualStrings("cp", log.items);
    try std.testing.expectEqual(@as(u64, 7), publish_context.observed_generation);
}

test "publication saturation backpressures before durable execution" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    service.publication_count = publication_queue_capacity;
    var command_context = TestContext{
        .marker = 'c',
        .log = &log,
        .allocator = std.testing.allocator,
        .outcome = .{ .committed_projection = .{
            .kind = .inventory,
            .generation = 8,
        } },
    };
    var command = testCommand(&command_context, .protocol_persistence);
    command.contract = .publishes_projection;
    try service.submit(command);
    try std.testing.expectError(error.PublicationBackpressure, service.processOne(1));
    try std.testing.expectEqual(@as(usize, 1), service.queuedCommands());
    try std.testing.expectEqual(@as(usize, 0), command_context.completions);
    try std.testing.expectEqual(@as(usize, 0), log.items.len);
}

test "runtime observations coalesce by node and aspect without reordering keys" {
    var log: std.ArrayListUnmanaged(u8) = .empty;
    defer log.deinit(std.testing.allocator);
    var service = TestService.init(.{ .log = &log, .allocator = std.testing.allocator });
    const node_a = [_]u8{0xaa} ** 16;
    const node_b = [_]u8{0xbb} ** 16;
    try std.testing.expectEqual(ObservationAdmission.queued, try service.submitObservation(.{
        .node_id = node_a,
        .sequence = 1,
        .observed_at_ns = 10,
        .payload = .{ .liveness = .{ .state = .suspect, .session_active = true } },
    }));
    try std.testing.expectEqual(ObservationAdmission.queued, try service.submitObservation(.{
        .node_id = node_b,
        .sequence = 1,
        .observed_at_ns = 11,
        .payload = .{ .traffic = .{
            .state = .warm,
            .authenticated_rx_bytes = 1,
            .authenticated_tx_bytes = 2,
        } },
    }));
    try std.testing.expectEqual(ObservationAdmission.replaced_older, try service.submitObservation(.{
        .node_id = node_a,
        .sequence = 2,
        .observed_at_ns = 12,
        .payload = .{ .liveness = .{ .state = .online, .session_active = true } },
    }));
    try std.testing.expectEqual(ObservationAdmission.ignored_stale, try service.submitObservation(.{
        .node_id = node_a,
        .sequence = 1,
        .observed_at_ns = 9,
        .payload = .{ .liveness = .{ .state = .offline, .session_active = false } },
    }));

    try std.testing.expectEqual(@as(usize, 2), service.queuedObservations());
    const first = service.takeObservation().?;
    try std.testing.expectEqual(node_a, first.node_id);
    try std.testing.expectEqual(@as(u64, 2), first.sequence);
    try std.testing.expectEqual(ObservationState.online, first.payload.liveness.state);
    const second = service.takeObservation().?;
    try std.testing.expectEqual(node_b, second.node_id);
}

test "settings runtime acknowledgement advances effective state only after success" {
    var reconciliation: SettingsReconciliation = .{};
    try reconciliation.noteDesired(.{ .revision = 1, .generation = 8 });
    try reconciliation.acknowledge(.{ .revision = 1, .generation = 8, .applied = false });
    try std.testing.expectEqual(@as(u64, 0), reconciliation.effective_revision);
    try std.testing.expect(!reconciliation.awaiting_runtime_ack);

    try reconciliation.noteDesired(.{ .revision = 2, .generation = 9 });
    try std.testing.expectError(error.StaleSettingsAcknowledgement, reconciliation.acknowledge(.{
        .revision = 1,
        .generation = 8,
        .applied = true,
    }));
    try reconciliation.acknowledge(.{ .revision = 2, .generation = 9, .applied = true });
    try std.testing.expectEqual(@as(u64, 2), reconciliation.effective_revision);
    try std.testing.expectEqual(@as(u64, 9), reconciliation.effective_generation);
}
