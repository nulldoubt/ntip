const std = @import("std");

pub const Entry = struct {
    network: u32,
    prefix_len: u8,
    owner: u128,
    receiver_session_id: u64 = 0,

    pub fn matches(self: Entry, address: u32) bool {
        return (address & mask(self.prefix_len)) == self.network;
    }
};

/// Immutable longest-prefix-match snapshot. Building a new snapshot allocates;
/// packet lookups do not. The control worker swaps snapshots at a quiescent
/// hand-off point owned by the data worker.
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,

    pub fn init(allocator: std.mem.Allocator, source: []const Entry) !Snapshot {
        const entries = try allocator.dupe(Entry, source);
        std.mem.sort(Entry, entries, {}, lessThan);
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn lookup(self: *const Snapshot, destination: u32) ?*const Entry {
        for (self.entries) |*entry| {
            if (entry.matches(destination)) return entry;
        }
        return null;
    }

    /// Session bindings are ephemeral and are updated only by the single data
    /// worker. Prefixes and ownership remain immutable after construction.
    pub fn bindOwner(self: *Snapshot, owner: u128, receiver_session_id: u64) void {
        for (self.entries) |*entry| {
            if (entry.owner == owner) entry.receiver_session_id = receiver_session_id;
        }
    }
};

fn lessThan(_: void, lhs: Entry, rhs: Entry) bool {
    if (lhs.prefix_len != rhs.prefix_len) return lhs.prefix_len > rhs.prefix_len;
    return lhs.network < rhs.network;
}

fn mask(prefix_len: u8) u32 {
    if (prefix_len == 0) return 0;
    const shift: u5 = @intCast(32 - prefix_len);
    return @as(u32, std.math.maxInt(u32)) << shift;
}

test "snapshot performs longest-prefix matching" {
    var snapshot = try Snapshot.init(std.testing.allocator, &.{
        .{ .network = 0x0a000000, .prefix_len = 8, .owner = 1 },
        .{ .network = 0x0a010000, .prefix_len = 16, .owner = 2 },
        .{ .network = 0x0a010203, .prefix_len = 32, .owner = 3 },
    });
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u128, 3), snapshot.lookup(0x0a010203).?.owner);
    try std.testing.expectEqual(@as(u128, 2), snapshot.lookup(0x0a010204).?.owner);
    try std.testing.expectEqual(@as(u128, 1), snapshot.lookup(0x0affffff).?.owner);
    try std.testing.expect(snapshot.lookup(0xc0000201) == null);

    snapshot.bindOwner(2, 91);
    try std.testing.expectEqual(@as(u64, 91), snapshot.lookup(0x0a010204).?.receiver_session_id);
    try std.testing.expectEqual(@as(u64, 0), snapshot.lookup(0x0affffff).?.receiver_session_id);
}
