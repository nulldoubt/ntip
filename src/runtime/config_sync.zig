const std = @import("std");
const control = @import("../protocol/control.zig");
const configuration = @import("../protocol/configuration.zig");

pub const Sender = struct {
    bytes: []const u8,
    hash: [control.snapshot_hash_len]u8,
    chunk_count: u16,

    pub fn init(bytes: []const u8) !Sender {
        _ = try configuration.View.decode(bytes);
        const count = std.math.divCeil(usize, bytes.len, control.ConfigurationChunk.max_data_len) catch unreachable;
        if (count == 0 or count > std.math.maxInt(u16)) return error.TooManyChunks;
        return .{
            .bytes = bytes,
            .hash = control.hashConfiguration(bytes),
            .chunk_count = @intCast(count),
        };
    }

    pub fn begin(self: Sender) control.ConfigurationBegin {
        return .{
            .hash = self.hash,
            .total_len = @intCast(self.bytes.len),
            .chunk_count = self.chunk_count,
        };
    }

    pub fn chunk(self: Sender, index: u16) !control.ConfigurationChunk {
        if (index >= self.chunk_count) return error.ChunkOutOfBounds;
        const offset = @as(usize, index) * control.ConfigurationChunk.max_data_len;
        const end = @min(offset + control.ConfigurationChunk.max_data_len, self.bytes.len);
        return .{ .index = index, .offset = @intCast(offset), .data = self.bytes[offset..end] };
    }
};

pub const Receiver = struct {
    allocator: std.mem.Allocator,
    generation: u64 = 0,
    expected_hash: [control.snapshot_hash_len]u8 = [_]u8{0} ** control.snapshot_hash_len,
    storage: []u8 = &.{},
    received: []bool = &.{},
    offsets: []u32 = &.{},
    lengths: []u16 = &.{},
    received_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Receiver {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Receiver) void {
        self.reset();
        self.* = undefined;
    }

    pub fn reset(self: *Receiver) void {
        if (self.storage.len != 0) self.allocator.free(self.storage);
        if (self.received.len != 0) self.allocator.free(self.received);
        if (self.offsets.len != 0) self.allocator.free(self.offsets);
        if (self.lengths.len != 0) self.allocator.free(self.lengths);
        self.storage = &.{};
        self.received = &.{};
        self.offsets = &.{};
        self.lengths = &.{};
        self.received_count = 0;
        self.generation = 0;
        @memset(&self.expected_hash, 0);
    }

    pub fn start(self: *Receiver, generation: u64, begin: control.ConfigurationBegin) !void {
        if (generation == 0) return error.InvalidGeneration;
        if (begin.total_len < configuration.header_len or begin.total_len > configuration.maximum_snapshot_len) {
            return error.InvalidSnapshotLength;
        }
        if (begin.chunk_count == 0 or begin.chunk_count > begin.total_len) return error.InvalidChunkCount;

        self.reset();
        errdefer self.reset();
        self.storage = try self.allocator.alloc(u8, begin.total_len);
        self.received = try self.allocator.alloc(bool, begin.chunk_count);
        self.offsets = try self.allocator.alloc(u32, begin.chunk_count);
        self.lengths = try self.allocator.alloc(u16, begin.chunk_count);
        @memset(self.storage, 0);
        @memset(self.received, false);
        @memset(self.offsets, 0);
        @memset(self.lengths, 0);
        self.generation = generation;
        self.expected_hash = begin.hash;
    }

    /// Returns true for a new chunk and false for an identical idempotent
    /// retransmission. Conflicting duplicates or overlaps fail closed.
    pub fn accept(self: *Receiver, chunk: control.ConfigurationChunk) !bool {
        if (self.storage.len == 0) return error.NoConfigurationInProgress;
        if (chunk.index >= self.received.len) return error.ChunkOutOfBounds;
        const chunk_start: usize = chunk.offset;
        const end = std.math.add(usize, chunk_start, chunk.data.len) catch return error.ChunkOutOfBounds;
        if (end > self.storage.len) return error.ChunkOutOfBounds;

        if (self.received[chunk.index]) {
            const prior_start = self.offsets[chunk.index];
            const prior_len = self.lengths[chunk.index];
            if (prior_start != chunk.offset or prior_len != chunk.data.len) return error.ConflictingChunk;
            if (!std.mem.eql(u8, self.storage[chunk_start..end], chunk.data)) return error.ConflictingChunk;
            return false;
        }
        for (self.received, 0..) |present, index| {
            if (!present) continue;
            const other_start: usize = self.offsets[index];
            const other_end = other_start + self.lengths[index];
            if (chunk_start < other_end and other_start < end) return error.OverlappingChunk;
        }

        @memcpy(self.storage[chunk_start..end], chunk.data);
        self.received[chunk.index] = true;
        self.offsets[chunk.index] = chunk.offset;
        self.lengths[chunk.index] = @intCast(chunk.data.len);
        self.received_count += 1;
        return true;
    }

    pub fn complete(self: *const Receiver) bool {
        return self.received.len != 0 and self.received_count == self.received.len;
    }

    /// Verifies full byte coverage, snapshot hash, and the normative binary
    /// schema before exposing a borrowed immutable view for atomic application.
    pub fn finish(self: *const Receiver) !configuration.View {
        if (!self.complete()) return error.ConfigurationIncomplete;
        var cursor: usize = 0;
        while (cursor < self.storage.len) {
            var covered = false;
            for (self.received, 0..) |present, index| {
                if (!present) continue;
                const chunk_start: usize = self.offsets[index];
                const end = chunk_start + self.lengths[index];
                if (cursor >= chunk_start and cursor < end) {
                    cursor = end;
                    covered = true;
                    break;
                }
            }
            if (!covered) return error.ConfigurationHasGap;
        }
        const actual_hash = control.hashConfiguration(self.storage);
        if (!std.crypto.timing_safe.eql([control.snapshot_hash_len]u8, actual_hash, self.expected_hash)) {
            return error.ConfigurationHashMismatch;
        }
        return configuration.View.decode(self.storage);
    }
};

fn sampleSnapshot(storage: []u8) ![]u8 {
    const routes = [_]configuration.Route{
        .{ .network = .{ 10, 1, 0, 0 }, .prefix_len = 24, .kind = .vnr },
        .{ .network = .{ 192, 168, 178, 0 }, .prefix_len = 24, .kind = .routed_prefix },
    };
    return (configuration.Snapshot{
        .node_uuid = [_]u8{1} ** 16,
        .own_address = .{ 10, 1, 0, 2 },
        .own_vnr_network = .{ 10, 1, 0, 0 },
        .own_vnr_prefix_len = 24,
        .master_address = .{ 10, 1, 0, 1 },
        .inner_mtu = 1380,
        .heartbeat_seconds = 15,
        .suspect_seconds = 30,
        .offline_seconds = 45,
        .cold_seconds = 30,
        .hysteresis_seconds = 5,
        .hot_packets_per_second = 100_000,
        .hot_bits_per_second = 1_000_000_000,
        .saturated_queue_percent = 80,
        .routes = &routes,
    }).encode(storage);
}

test "configuration sync accepts out-of-order idempotent chunks atomically" {
    var snapshot_storage: [configuration.maximum_snapshot_len]u8 = undefined;
    const snapshot = try sampleSnapshot(&snapshot_storage);
    const sender = try Sender.init(snapshot);
    var receiver = Receiver.init(std.testing.allocator);
    defer receiver.deinit();
    try receiver.start(9, sender.begin());
    var index: usize = sender.chunk_count;
    while (index > 0) {
        index -= 1;
        const chunk = try sender.chunk(@intCast(index));
        try std.testing.expect(try receiver.accept(chunk));
        try std.testing.expect(!(try receiver.accept(chunk)));
    }
    const view = try receiver.finish();
    try std.testing.expectEqual(@as(u16, 2), view.route_count);
}

test "configuration sync rejects overlap and hash mismatch" {
    var snapshot_storage: [configuration.maximum_snapshot_len]u8 = undefined;
    const snapshot = try sampleSnapshot(&snapshot_storage);
    const sender = try Sender.init(snapshot);
    var receiver = Receiver.init(std.testing.allocator);
    defer receiver.deinit();
    var begin = sender.begin();
    begin.chunk_count = 2;
    try receiver.start(1, begin);
    try std.testing.expect(try receiver.accept(.{ .index = 0, .offset = 0, .data = snapshot[0..64] }));
    try std.testing.expectError(error.OverlappingChunk, receiver.accept(.{ .index = 1, .offset = 63, .data = snapshot[63..] }));

    receiver.reset();
    begin = sender.begin();
    begin.hash[0] ^= 1;
    try receiver.start(2, begin);
    var index: u16 = 0;
    while (index < sender.chunk_count) : (index += 1) _ = try receiver.accept(try sender.chunk(index));
    try std.testing.expectError(error.ConfigurationHashMismatch, receiver.finish());
}
