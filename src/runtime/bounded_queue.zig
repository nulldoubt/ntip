const std = @import("std");

/// Bounded single-producer/single-consumer ring used for control/data worker
/// hand-off. Allocation happens once in `init`; push/pop are allocation-free.
pub fn SpscQueue(comptime T: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        storage: []T,
        head: std.atomic.Value(usize) = .init(0),
        tail: std.atomic.Value(usize) = .init(0),

        pub fn init(allocator: std.mem.Allocator, desired_capacity: usize) !Self {
            if (desired_capacity < 2) return error.InvalidCapacity;
            return .{
                .allocator = allocator,
                .storage = try allocator.alloc(T, desired_capacity + 1),
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn push(self: *Self, value: T) bool {
            const head = self.head.load(.monotonic);
            const next_index = self.next(head);
            if (next_index == self.tail.load(.acquire)) return false;
            self.storage[head] = value;
            self.head.store(next_index, .release);
            return true;
        }

        pub fn pop(self: *Self) ?T {
            const tail = self.tail.load(.monotonic);
            if (tail == self.head.load(.acquire)) return null;
            const value = self.storage[tail];
            self.tail.store(self.next(tail), .release);
            return value;
        }

        /// Pops and immediately erases the vacated ring slot. Use this for
        /// queues whose values may contain ephemeral session key material.
        pub fn popSecure(self: *Self) ?T {
            const tail = self.tail.load(.monotonic);
            if (tail == self.head.load(.acquire)) return null;
            const value = self.storage[tail];
            std.crypto.secureZero(u8, std.mem.asBytes(&self.storage[tail]));
            self.tail.store(self.next(tail), .release);
            return value;
        }

        pub fn capacity(self: *const Self) usize {
            return self.storage.len - 1;
        }

        pub fn occupancy(self: *const Self) usize {
            const head = self.head.load(.acquire);
            const tail = self.tail.load(.acquire);
            if (head >= tail) return head - tail;
            return self.storage.len - tail + head;
        }

        fn next(self: *const Self, index: usize) usize {
            const incremented = index + 1;
            return if (incremented == self.storage.len) 0 else incremented;
        }
    };
}

test "bounded SPSC queue refuses overflow" {
    var queue = try SpscQueue(u8).init(std.testing.allocator, 2);
    defer queue.deinit();
    try std.testing.expect(queue.push(1));
    try std.testing.expect(queue.push(2));
    try std.testing.expect(!queue.push(3));
    try std.testing.expectEqual(@as(usize, 2), queue.occupancy());
    try std.testing.expectEqual(@as(u8, 1), queue.pop().?);
    try std.testing.expectEqual(@as(u8, 2), queue.pop().?);
    try std.testing.expect(queue.pop() == null);
}
