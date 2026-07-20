//! Bounded correlation for Master-originated connectivity checks.
//!
//! The control worker reserves a check and injects `Pending.buildRequest`
//! through the ordinary authenticated DATA path. The data worker calls
//! `matchReply` before normal TUN delivery; only an exact, checksummed echo
//! reply carrying the per-check nonce is consumed.

const std = @import("std");
const icmp = @import("icmp.zig");
const queues = @import("bounded_queue.zig");

pub const default_timeout_ms: u32 = 3_000;
pub const minimum_timeout_ms: u32 = 500;
pub const maximum_timeout_ms: u32 = 10_000;
pub const maximum_pending_checks: usize = 1_024;
pub const nonce_bytes: usize = 16;

pub const Status = enum {
    succeeded,
    failed,
    timed_out,
    interrupted,
};

pub const Failure = enum {
    node_offline,
    route_unavailable,
    packet_rejected,
    transport_unavailable,
};

pub const Completion = struct {
    check_id: [16]u8,
    node_id: [16]u8,
    status: Status,
    completed_at_ns: u64,
    rtt_microseconds: ?u64 = null,
    failure: ?Failure = null,
};

/// Fully materialized control-to-data request. Random correlation material is
/// chosen by the serialized control side, then copied through a bounded SPSC
/// queue. No borrowed storage crosses the thread boundary.
pub const Request = struct {
    check_id: [16]u8,
    node_id: [16]u8,
    source: [4]u8,
    target: [4]u8,
    identifier: u16,
    sequence: u16,
    nonce: [nonce_bytes]u8,
    ipv4_id: u16,
    timeout_ms: u32,
};

pub const RequestQueue = queues.SpscQueue(Request);
pub const CompletionQueue = queues.SpscQueue(Completion);

/// Bounded bidirectional seam between the serialized operator/control thread
/// and the DATA worker. Each accepted request reserves one completion slot;
/// the reservation is released only when the control side consumes that
/// terminal result. Consequently the DATA worker can always publish exactly
/// one terminal result without blocking or dropping it.
pub const Channel = struct {
    requests: RequestQueue,
    completions: CompletionQueue,
    correlator: Correlator,
    expiration_scratch: []Completion,
    outstanding: std.atomic.Value(usize) = .init(0),
    maximum_outstanding: usize,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Channel {
        if (capacity < 2 or capacity > maximum_pending_checks) return error.InvalidCapacity;
        var requests = try RequestQueue.init(allocator, capacity);
        errdefer requests.deinit();
        var completions = try CompletionQueue.init(allocator, capacity);
        errdefer completions.deinit();
        var correlator = try Correlator.init(allocator, capacity);
        errdefer correlator.deinit();
        const expiration_scratch = try allocator.alloc(Completion, capacity);
        return .{
            .requests = requests,
            .completions = completions,
            .correlator = correlator,
            .expiration_scratch = expiration_scratch,
            .maximum_outstanding = capacity,
        };
    }

    pub fn deinit(self: *Channel) void {
        const allocator = self.requests.allocator;
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.expiration_scratch));
        allocator.free(self.expiration_scratch);
        self.correlator.deinit();
        self.completions.deinit();
        self.requests.deinit();
        self.* = undefined;
    }

    /// Single control-side producer. Returning false means no work was
    /// admitted and therefore no completion will follow.
    pub fn submit(self: *Channel, request: Request) bool {
        if (!validRequest(request)) return false;
        const previous = self.outstanding.fetchAdd(1, .acq_rel);
        if (previous >= self.maximum_outstanding) {
            _ = self.outstanding.fetchSub(1, .acq_rel);
            return false;
        }
        if (!self.requests.push(request)) {
            _ = self.outstanding.fetchSub(1, .acq_rel);
            return false;
        }
        return true;
    }

    /// Single DATA-side consumer. The vacated slot is wiped because it holds
    /// the per-check nonce.
    pub fn nextRequest(self: *Channel) ?Request {
        return self.requests.popSecure();
    }

    pub fn begin(self: *Channel, request: Request, now_ns: u64) !Pending {
        return self.correlator.begin(
            request.check_id,
            request.node_id,
            request.source,
            request.target,
            request.identifier,
            request.sequence,
            request.nonce,
            now_ns,
            request.timeout_ms,
        );
    }

    /// Called only after authenticated DATA has passed normal transport and
    /// source/destination policy validation.
    pub fn matchReply(self: *Channel, packet: []const u8, now_ns: u64) bool {
        const completion = self.correlator.matchReply(packet, now_ns) orelse return false;
        self.publish(completion);
        return true;
    }

    pub fn fail(self: *Channel, request: Request, now_ns: u64, failure: Failure) void {
        self.publish(.{
            .check_id = request.check_id,
            .node_id = request.node_id,
            .status = .failed,
            .completed_at_ns = now_ns,
            .failure = failure,
        });
    }

    pub fn failPending(self: *Channel, check_id: [16]u8, now_ns: u64, failure: Failure) void {
        const pending = self.correlator.cancel(check_id) orelse return;
        self.publish(.{
            .check_id = pending.check_id,
            .node_id = pending.node_id,
            .status = .failed,
            .completed_at_ns = now_ns,
            .failure = failure,
        });
    }

    pub fn expire(self: *Channel, now_ns: u64) usize {
        const count = self.correlator.expire(now_ns, self.expiration_scratch);
        for (self.expiration_scratch[0..count]) |completion| self.publish(completion);
        return count;
    }

    pub fn interruptAll(self: *Channel, now_ns: u64) usize {
        var total: usize = 0;
        while (self.nextRequest()) |request| {
            self.publish(.{
                .check_id = request.check_id,
                .node_id = request.node_id,
                .status = .interrupted,
                .completed_at_ns = now_ns,
            });
            total += 1;
        }
        const count = self.correlator.interruptAll(now_ns, self.expiration_scratch);
        for (self.expiration_scratch[0..count]) |completion| self.publish(completion);
        return total + count;
    }

    /// Single control-side consumer. Consuming the terminal result releases
    /// the admission reservation for a later request.
    pub fn nextCompletion(self: *Channel) ?Completion {
        const completion = self.completions.pop() orelse return null;
        const previous = self.outstanding.fetchSub(1, .acq_rel);
        std.debug.assert(previous != 0);
        return completion;
    }

    pub fn outstandingCount(self: *const Channel) usize {
        return self.outstanding.load(.acquire);
    }

    fn publish(self: *Channel, completion: Completion) void {
        // Admission reserves this exact slot. A failed push is therefore an
        // internal invariant violation, not runtime backpressure that may be
        // handled by dropping an operational result.
        std.debug.assert(self.completions.push(completion));
    }
};

pub const Pending = struct {
    check_id: [16]u8,
    node_id: [16]u8,
    source: [4]u8,
    target: [4]u8,
    identifier: u16,
    sequence: u16,
    nonce: [nonce_bytes]u8,
    started_at_ns: u64,
    deadline_ns: u64,

    pub fn buildRequest(self: Pending, destination: []u8, ipv4_id: u16) ![]u8 {
        return icmp.echoRequest(
            destination,
            self.source,
            self.target,
            ipv4_id,
            self.identifier,
            self.sequence,
            &self.nonce,
        );
    }
};

const Slot = struct {
    pending: ?Pending = null,
};

/// Fixed-capacity, single-owner correlation table. It performs no allocation
/// after initialization and therefore cannot add pressure to the packet path.
pub const Correlator = struct {
    allocator: std.mem.Allocator,
    slots: []Slot,
    count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Correlator {
        if (capacity == 0 or capacity > maximum_pending_checks) return error.InvalidCapacity;
        const slots = try allocator.alloc(Slot, capacity);
        @memset(slots, .{});
        return .{ .allocator = allocator, .slots = slots };
    }

    pub fn deinit(self: *Correlator) void {
        self.allocator.free(self.slots);
        self.* = undefined;
    }

    pub fn begin(
        self: *Correlator,
        check_id: [16]u8,
        node_id: [16]u8,
        source: [4]u8,
        target: [4]u8,
        identifier: u16,
        sequence: u16,
        nonce: [nonce_bytes]u8,
        now_ns: u64,
        timeout_ms: u32,
    ) !Pending {
        if (timeout_ms < minimum_timeout_ms or timeout_ms > maximum_timeout_ms) {
            return error.InvalidTimeout;
        }
        if (allZero(&check_id) or allZero(&node_id) or allZero(&nonce)) return error.InvalidCorrelation;

        var available: ?*Slot = null;
        for (self.slots) |*slot| {
            const current = slot.pending orelse {
                if (available == null) available = slot;
                continue;
            };
            if (std.mem.eql(u8, &current.check_id, &check_id)) return error.CheckAlreadyPending;
            if (current.identifier == identifier and current.sequence == sequence) {
                return error.CorrelationInUse;
            }
        }
        const slot = available orelse return error.QueueFull;
        const timeout_ns = std.math.mul(u64, timeout_ms, std.time.ns_per_ms) catch return error.InvalidTimeout;
        const pending: Pending = .{
            .check_id = check_id,
            .node_id = node_id,
            .source = source,
            .target = target,
            .identifier = identifier,
            .sequence = sequence,
            .nonce = nonce,
            .started_at_ns = now_ns,
            .deadline_ns = std.math.add(u64, now_ns, timeout_ns) catch return error.InvalidTimeout,
        };
        slot.pending = pending;
        self.count += 1;
        return pending;
    }

    /// Returns a completion only for the exact pending check. Valid but
    /// unrelated replies remain available to the normal TUN delivery path.
    pub fn matchReply(self: *Correlator, packet: []const u8, now_ns: u64) ?Completion {
        const reply = icmp.parseEchoReply(packet) catch return null;
        for (self.slots) |*slot| {
            const pending = slot.pending orelse continue;
            if (pending.identifier != reply.identifier or pending.sequence != reply.sequence) continue;
            if (!std.mem.eql(u8, &pending.target, &reply.source) or
                !std.mem.eql(u8, &pending.source, &reply.destination)) continue;
            if (!std.mem.eql(u8, &pending.nonce, reply.payload)) continue;

            slot.pending = null;
            self.count -= 1;
            return .{
                .check_id = pending.check_id,
                .node_id = pending.node_id,
                .status = .succeeded,
                .completed_at_ns = now_ns,
                .rtt_microseconds = if (now_ns >= pending.started_at_ns)
                    (now_ns - pending.started_at_ns) / std.time.ns_per_us
                else
                    0,
            };
        }
        return null;
    }

    pub fn expire(self: *Correlator, now_ns: u64, destination: []Completion) usize {
        return self.finishMatching(now_ns, destination, .timed_out, false);
    }

    pub fn interruptAll(self: *Correlator, now_ns: u64, destination: []Completion) usize {
        return self.finishMatching(now_ns, destination, .interrupted, true);
    }

    pub fn cancel(self: *Correlator, check_id: [16]u8) ?Pending {
        for (self.slots) |*slot| {
            const pending = slot.pending orelse continue;
            if (!std.mem.eql(u8, &pending.check_id, &check_id)) continue;
            slot.pending = null;
            self.count -= 1;
            return pending;
        }
        return null;
    }

    fn finishMatching(
        self: *Correlator,
        now_ns: u64,
        destination: []Completion,
        status: Status,
        all: bool,
    ) usize {
        var written: usize = 0;
        for (self.slots) |*slot| {
            if (written == destination.len) break;
            const pending = slot.pending orelse continue;
            if (!all and now_ns < pending.deadline_ns) continue;
            destination[written] = .{
                .check_id = pending.check_id,
                .node_id = pending.node_id,
                .status = status,
                .completed_at_ns = now_ns,
            };
            written += 1;
            slot.pending = null;
            self.count -= 1;
        }
        return written;
    }
};

fn allZero(bytes: []const u8) bool {
    var accumulator: u8 = 0;
    for (bytes) |byte| accumulator |= byte;
    return accumulator == 0;
}

fn validRequest(request: Request) bool {
    if (request.timeout_ms < minimum_timeout_ms or request.timeout_ms > maximum_timeout_ms) return false;
    if (allZero(&request.check_id) or allZero(&request.node_id) or allZero(&request.nonce)) return false;
    if (allZero(&request.source) or allZero(&request.target)) return false;
    return !std.mem.eql(u8, &request.source, &request.target);
}

test "correlator consumes only an exact authenticated echo reply" {
    var correlator = try Correlator.init(std.testing.allocator, 2);
    defer correlator.deinit();
    const pending = try correlator.begin(
        [_]u8{1} ** 16,
        [_]u8{2} ** 16,
        .{ 10, 1, 0, 1 },
        .{ 10, 1, 0, 2 },
        7,
        9,
        [_]u8{0xa5} ** nonce_bytes,
        1_000_000_000,
        default_timeout_ms,
    );

    var storage: [128]u8 = undefined;
    const packet = try pending.buildRequest(&storage, 11);
    try std.testing.expect(correlator.matchReply(packet, 1_010_000_000) == null);

    packet[12..16].* = pending.target;
    packet[16..20].* = pending.source;
    packet[10..12].* = .{ 0, 0 };
    std.mem.writeInt(u16, packet[10..12], icmp.checksum(packet[0..20]), .big);
    packet[20] = 0;
    packet[22..24].* = .{ 0, 0 };
    std.mem.writeInt(u16, packet[22..24], icmp.checksum(packet[20..]), .big);

    const completion = correlator.matchReply(packet, 1_010_000_000).?;
    try std.testing.expectEqual(Status.succeeded, completion.status);
    try std.testing.expectEqual(@as(?u64, 10_000), completion.rtt_microseconds);
    try std.testing.expectEqual(@as(usize, 0), correlator.count);
}

test "correlator is bounded and expires or interrupts pending checks" {
    var correlator = try Correlator.init(std.testing.allocator, 1);
    defer correlator.deinit();
    _ = try correlator.begin(
        [_]u8{1} ** 16,
        [_]u8{2} ** 16,
        .{ 10, 1, 0, 1 },
        .{ 10, 1, 0, 2 },
        1,
        1,
        [_]u8{3} ** nonce_bytes,
        0,
        minimum_timeout_ms,
    );
    try std.testing.expectError(error.QueueFull, correlator.begin(
        [_]u8{4} ** 16,
        [_]u8{5} ** 16,
        .{ 10, 2, 0, 1 },
        .{ 10, 2, 0, 2 },
        2,
        2,
        [_]u8{6} ** nonce_bytes,
        0,
        minimum_timeout_ms,
    ));

    var completions: [1]Completion = undefined;
    try std.testing.expectEqual(@as(usize, 0), correlator.expire(499 * std.time.ns_per_ms, &completions));
    try std.testing.expectEqual(@as(usize, 1), correlator.expire(500 * std.time.ns_per_ms, &completions));
    try std.testing.expectEqual(Status.timed_out, completions[0].status);

    _ = try correlator.begin(
        [_]u8{7} ** 16,
        [_]u8{8} ** 16,
        .{ 10, 3, 0, 1 },
        .{ 10, 3, 0, 2 },
        3,
        3,
        [_]u8{9} ** nonce_bytes,
        0,
        default_timeout_ms,
    );
    try std.testing.expectEqual(@as(usize, 1), correlator.interruptAll(1, &completions));
    try std.testing.expectEqual(Status.interrupted, completions[0].status);
}

test "connectivity timeout bounds are fixed security policy" {
    var correlator = try Correlator.init(std.testing.allocator, 1);
    defer correlator.deinit();
    try std.testing.expectError(error.InvalidTimeout, correlator.begin(
        [_]u8{1} ** 16,
        [_]u8{2} ** 16,
        .{ 10, 1, 0, 1 },
        .{ 10, 1, 0, 2 },
        1,
        1,
        [_]u8{3} ** nonce_bytes,
        0,
        minimum_timeout_ms - 1,
    ));
}

test "channel reserves terminal capacity and releases it only after completion consumption" {
    var channel = try Channel.init(std.testing.allocator, 2);
    defer channel.deinit();
    const first: Request = .{
        .check_id = [_]u8{1} ** 16,
        .node_id = [_]u8{2} ** 16,
        .source = .{ 10, 1, 0, 1 },
        .target = .{ 10, 1, 0, 2 },
        .identifier = 1,
        .sequence = 2,
        .nonce = [_]u8{3} ** nonce_bytes,
        .ipv4_id = 4,
        .timeout_ms = minimum_timeout_ms,
    };
    var second = first;
    second.check_id = [_]u8{4} ** 16;
    second.node_id = [_]u8{5} ** 16;
    second.identifier = 5;
    second.nonce = [_]u8{6} ** nonce_bytes;
    var third = second;
    third.check_id = [_]u8{7} ** 16;

    try std.testing.expect(channel.submit(first));
    try std.testing.expect(channel.submit(second));
    try std.testing.expect(!channel.submit(third));
    try std.testing.expectEqual(@as(usize, 2), channel.outstandingCount());

    const admitted_first = channel.nextRequest().?;
    _ = try channel.begin(admitted_first, 0);
    channel.fail(channel.nextRequest().?, 1, .node_offline);
    try std.testing.expect(!channel.submit(third));

    const failed = channel.nextCompletion().?;
    try std.testing.expectEqual(Status.failed, failed.status);
    try std.testing.expectEqual(Failure.node_offline, failed.failure.?);
    try std.testing.expect(channel.submit(third));

    try std.testing.expectEqual(@as(usize, 1), channel.expire(minimum_timeout_ms * std.time.ns_per_ms));
    try std.testing.expectEqual(Status.timed_out, channel.nextCompletion().?.status);
    // Consume and interrupt the newly admitted request so deinit has no
    // outstanding work and verifies the queued-interruption path.
    try std.testing.expectEqual(@as(usize, 1), channel.interruptAll(2));
    try std.testing.expectEqual(Status.interrupted, channel.nextCompletion().?.status);
    try std.testing.expectEqual(@as(usize, 0), channel.outstandingCount());
}

test "channel rejects malformed requests before reserving capacity" {
    var channel = try Channel.init(std.testing.allocator, 2);
    defer channel.deinit();
    const invalid: Request = .{
        .check_id = [_]u8{1} ** 16,
        .node_id = [_]u8{2} ** 16,
        .source = .{ 10, 1, 0, 1 },
        .target = .{ 10, 1, 0, 1 },
        .identifier = 1,
        .sequence = 1,
        .nonce = [_]u8{3} ** nonce_bytes,
        .ipv4_id = 1,
        .timeout_ms = default_timeout_ms,
    };
    try std.testing.expect(!channel.submit(invalid));
    try std.testing.expectEqual(@as(usize, 0), channel.outstandingCount());
}
