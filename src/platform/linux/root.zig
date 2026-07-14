//! Linux-only TUN, network, IPC, and lifecycle adapters.
//!
//! Declarations remain importable on non-Linux development hosts. Calls that
//! require Linux return `error.UnsupportedPlatform`.

pub const tun = @import("tun.zig");
pub const routes = @import("routes.zig");
pub const lifecycle = @import("lifecycle.zig");
pub const udp = @import("udp.zig");
pub const ipc_socket = @import("ipc_socket.zig");
pub const account = @import("account.zig");

test {
    _ = tun;
    _ = routes;
    _ = lifecycle;
    _ = udp;
    _ = ipc_socket;
    _ = account;
}
