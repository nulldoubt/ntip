const std = @import("std");

/// Accommodates the v0.1 1380-byte inner MTU, the 34-byte transport overhead,
/// and bounded control/handshake frames without jumbo allocations.
pub const packet_capacity = 2048;

pub const PacketBuffer = struct {
    bytes: [packet_capacity]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *PacketBuffer) []u8 {
        return self.bytes[0..self.len];
    }

    pub fn writable(self: *PacketBuffer) []u8 {
        return &self.bytes;
    }
};

/// Single-owner pool used by the v0.1 data worker. It is intentionally not
/// synchronized: worker ownership is the concurrency boundary.
pub const Pool = struct {
    allocator: std.mem.Allocator,
    buffers: []PacketBuffer,
    free_indices: []u32,
    free_len: usize,

    pub fn init(allocator: std.mem.Allocator, count: usize) !Pool {
        if (count == 0 or count > std.math.maxInt(u32)) return error.InvalidCapacity;
        const buffers = try allocator.alloc(PacketBuffer, count);
        errdefer allocator.free(buffers);
        const indices = try allocator.alloc(u32, count);
        for (indices, 0..) |*slot, index| slot.* = @intCast(index);
        return .{
            .allocator = allocator,
            .buffers = buffers,
            .free_indices = indices,
            .free_len = count,
        };
    }

    pub fn deinit(self: *Pool) void {
        self.allocator.free(self.free_indices);
        self.allocator.free(self.buffers);
        self.* = undefined;
    }

    pub fn acquire(self: *Pool) ?u32 {
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        const index = self.free_indices[self.free_len];
        self.buffers[index].len = 0;
        return index;
    }

    pub fn get(self: *Pool, index: u32) *PacketBuffer {
        return &self.buffers[index];
    }

    pub fn release(self: *Pool, index: u32) void {
        std.debug.assert(index < self.buffers.len);
        std.debug.assert(self.free_len < self.free_indices.len);
        self.free_indices[self.free_len] = index;
        self.free_len += 1;
    }

    pub fn available(self: *const Pool) usize {
        return self.free_len;
    }
};

test "buffer pool is bounded and reusable" {
    var pool = try Pool.init(std.testing.allocator, 2);
    defer pool.deinit();
    const first = pool.acquire().?;
    const second = pool.acquire().?;
    try std.testing.expect(pool.acquire() == null);
    pool.release(first);
    try std.testing.expectEqual(first, pool.acquire().?);
    pool.release(second);
}
