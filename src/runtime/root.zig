//! Runtime state and bounded data-plane building blocks.

pub const traffic = @import("traffic.zig");
pub const forwarding = @import("forwarding.zig");
pub const session_table = @import("session_table.zig");
pub const bounded_queue = @import("bounded_queue.zig");
pub const buffer_pool = @import("buffer_pool.zig");
pub const ipc = @import("ipc.zig");
pub const endpoint = @import("endpoint.zig");
pub const icmp = @import("icmp.zig");
pub const authorization = @import("authorization.zig");
pub const data_plane = @import("data_plane.zig");
pub const data_worker = @import("data_worker.zig");
pub const control_plane = @import("control_plane.zig");
pub const handshake_coordinator = @import("handshake_coordinator.zig");
pub const service_state = @import("service_state.zig");
pub const config_sync = @import("config_sync.zig");
pub const configuration_runtime = @import("configuration_runtime.zig");
pub const ipc_server = @import("ipc_server.zig");
pub const live_admin = @import("live_admin.zig");
pub const topology = @import("topology.zig");
pub const service = @import("service.zig");

test {
    _ = traffic;
    _ = forwarding;
    _ = session_table;
    _ = bounded_queue;
    _ = buffer_pool;
    _ = ipc;
    _ = endpoint;
    _ = icmp;
    _ = authorization;
    _ = data_plane;
    _ = data_worker;
    _ = control_plane;
    _ = handshake_coordinator;
    _ = service_state;
    _ = config_sync;
    _ = configuration_runtime;
    _ = ipc_server;
    _ = live_admin;
    _ = topology;
    _ = service;
}
