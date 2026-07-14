//! Operating-system adapters.

pub const linux = @import("linux/root.zig");

test {
    _ = linux;
}
