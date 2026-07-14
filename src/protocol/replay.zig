const std = @import("std");

pub const window_size: usize = 2048;
const word_count = window_size / @bitSizeOf(u64);

/// A bounded sliding replay window. Call `check` before authentication, then
/// `commit` only after the packet's AEAD tag has been verified. In particular,
/// checking a forged far-future sequence never advances `highest`.
pub const Window = struct {
    initialized: bool = false,
    highest: u64 = 0,
    words: [word_count]u64 = [_]u64{0} ** word_count,

    pub fn check(self: *const Window, sequence: u64) !void {
        if (!self.initialized or sequence > self.highest) return;
        const distance = self.highest - sequence;
        if (distance >= window_size) return error.TooOld;
        const word_index: usize = @intCast(distance / 64);
        const bit_index: u6 = @intCast(distance % 64);
        if ((self.words[word_index] & (@as(u64, 1) << bit_index)) != 0) {
            return error.Duplicate;
        }
    }

    pub fn commit(self: *Window, sequence: u64) !void {
        try self.check(sequence);
        if (!self.initialized) {
            self.initialized = true;
            self.highest = sequence;
            self.words[0] = 1;
            return;
        }
        if (sequence > self.highest) {
            const distance = sequence - self.highest;
            self.shift(@intCast(@min(distance, window_size)));
            self.highest = sequence;
            self.words[0] |= 1;
            return;
        }

        const distance = self.highest - sequence;
        const word_index: usize = @intCast(distance / 64);
        const bit_index: u6 = @intCast(distance % 64);
        self.words[word_index] |= @as(u64, 1) << bit_index;
    }

    fn shift(self: *Window, amount: usize) void {
        if (amount >= window_size) {
            self.words = [_]u64{0} ** word_count;
            return;
        }
        if (amount == 0) return;

        const whole = amount / 64;
        const bits: usize = amount % 64;
        var index: usize = word_count;
        while (index > 0) {
            index -= 1;
            var value: u64 = 0;
            if (index >= whole) {
                const source = index - whole;
                const left_shift: u6 = @intCast(bits);
                value = self.words[source] << left_shift;
                if (bits != 0 and source > 0) {
                    const right_shift: u6 = @intCast(64 - bits);
                    value |= self.words[source - 1] >> right_shift;
                }
            }
            self.words[index] = value;
        }
    }
};

test "replay check does not mutate until commit" {
    var window = Window{};
    try window.commit(10);
    try window.check(100_000);
    try std.testing.expectEqual(@as(u64, 10), window.highest);
    try std.testing.expectError(error.Duplicate, window.check(10));
    try window.commit(12);
    try window.commit(11);
    try std.testing.expectError(error.Duplicate, window.commit(11));
}

test "replay window shifts across words and rejects stale packets" {
    var window = Window{};
    try window.commit(0);
    try window.commit(63);
    try window.commit(64);
    try std.testing.expectError(error.Duplicate, window.check(63));
    try std.testing.expectError(error.Duplicate, window.check(0));
    try window.commit(2047);
    try std.testing.expectError(error.Duplicate, window.check(0));
    try window.commit(2048);
    try std.testing.expectError(error.TooOld, window.check(0));
    try window.check(1);
}
