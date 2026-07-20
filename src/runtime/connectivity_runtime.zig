//! Control-side bridge for Master-originated connectivity checks.
//!
//! The serialized operator thread resolves an existing Node to its VNR's
//! Master address, materializes random ICMP correlation fields, and performs
//! non-blocking admission into the DATA worker. Terminal results are drained
//! back on the same serialized thread and persisted through the operations
//! repository. No arbitrary destination can enter this seam.

const std = @import("std");
const model = @import("../domain/model.zig");
const operations_service = @import("../management/operations_service.zig");
const operations_repository = @import("../state/operations_repository.zig");
const connectivity = @import("connectivity.zig");
const data_worker = @import("data_worker.zig");

pub const production_capacity: usize = 64;

pub const RequestSink = struct {
    context: *anyopaque,
    submit_fn: *const fn (*anyopaque, connectivity.Request) bool,

    pub fn submit(self: RequestSink, request: connectivity.Request) bool {
        return self.submit_fn(self.context, request);
    }

    pub fn fromWorker(worker: *data_worker.DataWorker) RequestSink {
        return .{ .context = worker, .submit_fn = submitToWorker };
    }

    fn submitToWorker(raw: *anyopaque, request: connectivity.Request) bool {
        const worker: *data_worker.DataWorker = @ptrCast(@alignCast(raw));
        return worker.submitConnectivity(request);
    }
};

pub const CompletionSource = struct {
    context: *anyopaque,
    next_fn: *const fn (*anyopaque) ?connectivity.Completion,

    pub fn next(self: CompletionSource) ?connectivity.Completion {
        return self.next_fn(self.context);
    }

    pub fn fromWorker(worker: *data_worker.DataWorker) CompletionSource {
        return .{ .context = worker, .next_fn = nextFromWorker };
    }

    fn nextFromWorker(raw: *anyopaque) ?connectivity.Completion {
        const worker: *data_worker.DataWorker = @ptrCast(@alignCast(raw));
        return worker.nextConnectivityCompletion();
    }
};

pub const Dispatcher = struct {
    io: std.Io,
    store: *const model.Store,
    sink: RequestSink,

    pub fn interface(self: *Dispatcher) operations_service.ConnectivityDispatcher {
        return .{ .context = self, .dispatch_fn = dispatchOpaque };
    }

    fn dispatchOpaque(
        raw: ?*anyopaque,
        check_id: [16]u8,
        node_id: [16]u8,
        node_address: []const u8,
        timeout_milliseconds: u16,
    ) !void {
        const self: *Dispatcher = @ptrCast(@alignCast(raw orelse return error.MissingConnectivityDispatcher));
        if (timeout_milliseconds < connectivity.minimum_timeout_ms or
            timeout_milliseconds > connectivity.maximum_timeout_ms)
        {
            return error.InvalidConnectivityTimeout;
        }
        const node = self.store.findNodeById(.{ .bytes = node_id }) orelse return error.NodeNotFound;
        const parsed_address = try model.Ipv4.parse(node_address);
        if (parsed_address.value != node.address.value) return error.NodeAddressChanged;
        const vnr = self.store.findVnr(node.vnr.slice()) orelse return error.VnrNotFound;

        var request: connectivity.Request = .{
            .check_id = check_id,
            .node_id = node_id,
            .source = vnr.masterAddress().octets(),
            .target = node.address.octets(),
            .identifier = undefined,
            .sequence = undefined,
            .nonce = undefined,
            .ipv4_id = undefined,
            .timeout_ms = timeout_milliseconds,
        };
        var correlation: [6]u8 = undefined;
        self.io.random(&correlation);
        request.identifier = std.mem.readInt(u16, correlation[0..2], .big);
        request.sequence = std.mem.readInt(u16, correlation[2..4], .big);
        request.ipv4_id = std.mem.readInt(u16, correlation[4..6], .big);
        self.io.random(&request.nonce);
        if (allZero(&request.nonce)) request.nonce[0] = 1;

        if (!self.sink.submit(request)) return error.ConnectivityQueueFull;
    }
};

/// Durable terminal-result consumer. A failed database transition retains the
/// popped completion locally and retries it on the next tick; a result is
/// therefore never discarded due to transient operator-thread failure.
pub const CompletionRecorder = struct {
    io: std.Io,
    repository: operations_repository.Repository,
    source: CompletionSource,
    pending: ?connectivity.Completion = null,

    pub fn poll(self: *CompletionRecorder) !usize {
        var persisted: usize = 0;
        while (true) {
            if (self.pending == null) self.pending = self.source.next() orelse return persisted;
            const completion = self.pending.?;
            const now = try wallSeconds(self.io);
            const mapped = mapCompletion(completion);
            try self.repository.transitionConnectivityCheck(
                completion.check_id,
                mapped.status,
                now,
                completion.rtt_microseconds,
                mapped.error_code,
            );
            self.pending = null;
            persisted += 1;
        }
    }
};

const MappedCompletion = struct {
    status: operations_repository.ConnectivityStatus,
    error_code: ?[]const u8 = null,
};

fn mapCompletion(completion: connectivity.Completion) MappedCompletion {
    return switch (completion.status) {
        .succeeded => .{ .status = .succeeded },
        .timed_out => .{ .status = .timed_out },
        .interrupted => .{ .status = .interrupted, .error_code = "service_interrupted" },
        .failed => .{
            .status = .failed,
            .error_code = if (completion.failure) |failure| @tagName(failure) else "probe_failed",
        },
    };
}

fn wallSeconds(io: std.Io) !i64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.ClockBeforeUnixEpoch;
    return seconds;
}

fn allZero(bytes: []const u8) bool {
    var accumulator: u8 = 0;
    for (bytes) |byte| accumulator |= byte;
    return accumulator == 0;
}

const TestSink = struct {
    accepted: bool = true,
    request: ?connectivity.Request = null,

    fn submit(raw: *anyopaque, request: connectivity.Request) bool {
        const self: *TestSink = @ptrCast(@alignCast(raw));
        if (!self.accepted) return false;
        self.request = request;
        return true;
    }
};

test "dispatcher resolves only the durable Node address and VNR Master source" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("core", try model.Cidr.parse("10.1.0.0/24"));
    const node_id = model.NodeId{ .bytes = [_]u8{0x22} ** 16 };
    try store.createNode(node_id, "edge-a", "core", try model.Ipv4.parse("10.1.0.2"));
    var sink: TestSink = .{};
    var dispatcher: Dispatcher = .{
        .io = std.testing.io,
        .store = &store,
        .sink = .{ .context = &sink, .submit_fn = TestSink.submit },
    };
    try dispatcher.interface().dispatch(
        [_]u8{0x11} ** 16,
        node_id.bytes,
        "10.1.0.2",
        connectivity.default_timeout_ms,
    );
    const request = sink.request.?;
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 1 }, &request.source);
    try std.testing.expectEqualSlices(u8, &.{ 10, 1, 0, 2 }, &request.target);
    try std.testing.expect(!allZero(&request.nonce));

    try std.testing.expectError(error.NodeAddressChanged, dispatcher.interface().dispatch(
        [_]u8{0x12} ** 16,
        node_id.bytes,
        "10.1.0.3",
        connectivity.default_timeout_ms,
    ));
    sink.accepted = false;
    try std.testing.expectError(error.ConnectivityQueueFull, dispatcher.interface().dispatch(
        [_]u8{0x13} ** 16,
        node_id.bytes,
        "10.1.0.2",
        connectivity.default_timeout_ms,
    ));
}

test "terminal completion mapping is stable" {
    const failed = mapCompletion(.{
        .check_id = [_]u8{1} ** 16,
        .node_id = [_]u8{2} ** 16,
        .status = .failed,
        .completed_at_ns = 3,
        .failure = .node_offline,
    });
    try std.testing.expectEqual(operations_repository.ConnectivityStatus.failed, failed.status);
    try std.testing.expectEqualStrings("node_offline", failed.error_code.?);
    const timeout = mapCompletion(.{
        .check_id = [_]u8{1} ** 16,
        .node_id = [_]u8{2} ** 16,
        .status = .timed_out,
        .completed_at_ns = 3,
    });
    try std.testing.expectEqual(operations_repository.ConnectivityStatus.timed_out, timeout.status);
    try std.testing.expect(timeout.error_code == null);
}
