const std = @import("std");

pub fn SessionTable(comptime Value: type) type {
    return struct {
        const Self = @This();
        const SlotState = enum(u2) { empty, occupied, tombstone };
        const Slot = struct {
            state: SlotState = .empty,
            key: u64 = 0,
            value: Value = undefined,
        };

        allocator: std.mem.Allocator,
        slots: []Slot,
        count: usize = 0,
        cleanup_fn: ?*const fn (*Value) void = null,

        pub fn init(allocator: std.mem.Allocator, requested_capacity: usize) !Self {
            return initWithCleanup(allocator, requested_capacity, null);
        }

        /// Installs a value cleanup hook used on replacement, removal, and
        /// table teardown. The hook runs on the single control/data owner and
        /// must not allocate or retain the value pointer.
        pub fn initWithCleanup(
            allocator: std.mem.Allocator,
            requested_capacity: usize,
            cleanup_fn: ?*const fn (*Value) void,
        ) !Self {
            if (requested_capacity == 0) return error.InvalidCapacity;
            const capacity = std.math.ceilPowerOfTwo(usize, requested_capacity) catch return error.InvalidCapacity;
            const slots = try allocator.alloc(Slot, capacity);
            @memset(slots, .{});
            return .{ .allocator = allocator, .slots = slots, .cleanup_fn = cleanup_fn };
        }

        pub fn deinit(self: *Self) void {
            for (self.slots) |*slot| {
                if (slot.state == .occupied) self.cleanupValue(&slot.value);
            }
            self.allocator.free(self.slots);
            self.* = undefined;
        }

        pub fn put(self: *Self, key: u64, value: Value) !void {
            if (key == 0) return error.InvalidSessionId;
            if ((self.count + 1) * 10 > self.slots.len * 7) return error.TableFull;
            var first_tombstone: ?usize = null;
            var index = hash(key) & (self.slots.len - 1);
            var probed: usize = 0;
            while (probed < self.slots.len) : (probed += 1) {
                const slot = &self.slots[index];
                switch (slot.state) {
                    .empty => {
                        const destination = &self.slots[first_tombstone orelse index];
                        destination.* = .{ .state = .occupied, .key = key, .value = value };
                        self.count += 1;
                        return;
                    },
                    .tombstone => if (first_tombstone == null) {
                        first_tombstone = index;
                    },
                    .occupied => if (slot.key == key) {
                        self.cleanupValue(&slot.value);
                        slot.value = value;
                        return;
                    },
                }
                index = (index + 1) & (self.slots.len - 1);
            }
            return error.TableFull;
        }

        pub fn get(self: *Self, key: u64) ?*Value {
            const slot = self.find(key) orelse return null;
            return &slot.value;
        }

        pub fn getConst(self: *const Self, key: u64) ?*const Value {
            const slot = self.findConst(key) orelse return null;
            return &slot.value;
        }

        pub fn remove(self: *Self, key: u64) bool {
            const slot = self.find(key) orelse return false;
            self.cleanupValue(&slot.value);
            slot.state = .tombstone;
            slot.key = 0;
            self.count -= 1;
            return true;
        }

        pub const Iterator = struct {
            table: *Self,
            index: usize = 0,

            pub fn next(self: *Iterator) ?*Value {
                while (self.index < self.table.slots.len) {
                    const slot = &self.table.slots[self.index];
                    self.index += 1;
                    if (slot.state == .occupied) return &slot.value;
                }
                return null;
            }
        };

        /// Iteration is reserved for control-path maintenance performed by the
        /// single data-plane owner (for example, rebinding an immutable route
        /// policy to the newest confirmed session). It is never used by the
        /// per-packet lookup path.
        pub fn iterator(self: *Self) Iterator {
            return .{ .table = self };
        }

        fn find(self: *Self, key: u64) ?*Slot {
            if (key == 0) return null;
            var index = hash(key) & (self.slots.len - 1);
            var probed: usize = 0;
            while (probed < self.slots.len) : (probed += 1) {
                const slot = &self.slots[index];
                if (slot.state == .empty) return null;
                if (slot.state == .occupied and slot.key == key) return slot;
                index = (index + 1) & (self.slots.len - 1);
            }
            return null;
        }

        fn findConst(self: *const Self, key: u64) ?*const Slot {
            if (key == 0) return null;
            var index = hash(key) & (self.slots.len - 1);
            var probed: usize = 0;
            while (probed < self.slots.len) : (probed += 1) {
                const slot = &self.slots[index];
                if (slot.state == .empty) return null;
                if (slot.state == .occupied and slot.key == key) return slot;
                index = (index + 1) & (self.slots.len - 1);
            }
            return null;
        }

        fn cleanupValue(self: *Self, value: *Value) void {
            if (self.cleanup_fn) |cleanup| cleanup(value);
        }

        fn hash(key: u64) usize {
            var value = key;
            value ^= value >> 30;
            value *%= 0xbf58476d1ce4e5b9;
            value ^= value >> 27;
            value *%= 0x94d049bb133111eb;
            value ^= value >> 31;
            return @truncate(value);
        }
    };
}

test "session table has bounded insert lookup and removal" {
    var table = try SessionTable(u32).init(std.testing.allocator, 8);
    defer table.deinit();
    try table.put(42, 7);
    try std.testing.expectEqual(@as(u32, 7), table.get(42).?.*);
    try table.put(42, 9);
    try std.testing.expectEqual(@as(u32, 9), table.getConst(42).?.*);
    try std.testing.expect(table.remove(42));
    try std.testing.expect(table.get(42) == null);
}

test "session table iterator visits only occupied values" {
    var table = try SessionTable(u32).init(std.testing.allocator, 8);
    defer table.deinit();
    try table.put(1, 11);
    try table.put(2, 22);
    try table.put(3, 33);
    try std.testing.expect(table.remove(2));

    var sum: u32 = 0;
    var iterator = table.iterator();
    while (iterator.next()) |value| sum += value.*;
    try std.testing.expectEqual(@as(u32, 44), sum);
}

test "session table cleanup runs on replacement removal and deinit" {
    const Secret = struct {
        bytes: [32]u8,
        cleanup_count: *usize,

        fn wipe(value: *@This()) void {
            value.cleanup_count.* += 1;
            std.crypto.secureZero(u8, &value.bytes);
        }
    };

    var cleanup_count: usize = 0;
    var table = try SessionTable(Secret).initWithCleanup(std.testing.allocator, 8, Secret.wipe);
    try table.put(1, .{ .bytes = [_]u8{0x11} ** 32, .cleanup_count = &cleanup_count });
    try table.put(1, .{ .bytes = [_]u8{0x22} ** 32, .cleanup_count = &cleanup_count });
    try std.testing.expectEqual(@as(usize, 1), cleanup_count);
    try table.put(2, .{ .bytes = [_]u8{0x33} ** 32, .cleanup_count = &cleanup_count });
    const removed_storage = table.get(1).?;
    try std.testing.expect(table.remove(1));
    try std.testing.expectEqual(@as(usize, 2), cleanup_count);
    try std.testing.expectEqual([_]u8{0} ** 32, removed_storage.bytes);
    table.deinit();
    try std.testing.expectEqual(@as(usize, 3), cleanup_count);
}
