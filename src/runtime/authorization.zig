const std = @import("std");

pub const Entry = struct {
    owner: u128,
    network: u32,
    prefix_len: u8,

    pub fn contains(self: Entry, address: u32) bool {
        return address & mask(self.prefix_len) == self.network;
    }
};

/// Immutable source/destination ownership policy installed by the control
/// worker. Authorization performs a bounded linear scan in v0.1; entries are
/// grouped by owner to keep the common per-Node set tiny.
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

    pub fn permits(self: *const Snapshot, owner: u128, address: u32) bool {
        for (self.entries) |entry| {
            if (entry.owner > owner) return false;
            if (entry.owner == owner and entry.contains(address)) return true;
        }
        return false;
    }
};

fn lessThan(_: void, lhs: Entry, rhs: Entry) bool {
    if (lhs.owner != rhs.owner) return lhs.owner < rhs.owner;
    return lhs.prefix_len > rhs.prefix_len;
}

fn mask(prefix_len: u8) u32 {
    std.debug.assert(prefix_len <= 32);
    if (prefix_len == 0) return 0;
    const shift: u5 = @intCast(32 - prefix_len);
    return @as(u32, std.math.maxInt(u32)) << shift;
}

test "authorization binds prefixes to owners" {
    var snapshot = try Snapshot.init(std.testing.allocator, &.{
        .{ .owner = 1, .network = 0x0a010002, .prefix_len = 32 },
        .{ .owner = 1, .network = 0xc0a8b200, .prefix_len = 24 },
        .{ .owner = 2, .network = 0x0a010003, .prefix_len = 32 },
    });
    defer snapshot.deinit();
    try std.testing.expect(snapshot.permits(1, 0x0a010002));
    try std.testing.expect(snapshot.permits(1, 0xc0a8b22a));
    try std.testing.expect(!snapshot.permits(1, 0x0a010003));
}
