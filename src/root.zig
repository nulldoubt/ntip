//! NTIP shared library.
//!
//! Platform-neutral domain, persistence, protocol, and forwarding code lives
//! here. Linux-specific system integration is isolated below `platform`.

pub const version = @import("build_options").version;

pub const domain = @import("domain/root.zig");
pub const state = @import("state/root.zig");
pub const cli = @import("cli/root.zig");
pub const protocol = @import("protocol/mod.zig");
pub const platform = @import("platform/root.zig");
pub const runtime = @import("runtime/root.zig");
pub const management = @import("management/root.zig");

test {
    _ = domain;
    _ = state;
    _ = cli;
    _ = protocol;
    _ = platform;
    _ = runtime;
    _ = management;
}
