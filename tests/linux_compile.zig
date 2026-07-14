const builtin = @import("builtin");
const std = @import("std");
const ntip = @import("ntip");

const ProbeContext = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    plane: *ntip.runtime.data_plane.DataPlane,
    queue: *ntip.runtime.data_worker.ControlQueue,
    command_queue: *ntip.runtime.data_worker.CommandQueue,
    retirement_queue: *ntip.runtime.data_worker.RetirementQueue,
    service_uid: u32,
    service_gid: u32,
};

fn compileLinuxRuntime(context: *ProbeContext) void {
    if (comptime builtin.os.tag != .linux) return;

    var tun = ntip.platform.linux.tun.Device.openExclusive("ntip0") catch return;
    defer tun.close();
    var udp = ntip.platform.linux.udp.DualStack.bind(context.io, ntip.platform.linux.udp.default_port) catch return;
    defer udp.close();
    var worker = ntip.runtime.data_worker.DataWorker.init(
        context.io,
        &tun,
        &udp,
        context.plane,
        context.queue,
        context.command_queue,
        context.retirement_queue,
    ) catch return;
    defer worker.deinit();

    const routes: ntip.platform.linux.routes.Controller = .{ .allocator = context.allocator, .io = context.io };
    routes.configureLink("ntip0", 1380) catch return;
    _ = routes.forwardingEnabled() catch return;

    var listener = ntip.platform.linux.ipc_socket.Listener.listen(context.io, "/run/ntip/compile-probe.sock", context.service_gid) catch return;
    defer listener.close();
    var connection = listener.accept() catch return;
    defer connection.close(context.io);

    switch (ntip.platform.linux.lifecycle.forkForDaemon() catch return) {
        .parent => |parent| ntip.platform.linux.lifecycle.waitForReadiness(parent.readiness_fd) catch return,
        .child => |child| ntip.platform.linux.lifecycle.reportReadiness(child.readiness_fd, false),
    }
    ntip.platform.linux.lifecycle.dropToServiceUser(context.service_uid, context.service_gid, context.service_gid) catch return;
    worker.run() catch return;
}

/// Exporting the probe forces semantic analysis/code generation of Linux-only
/// adapters during cross-builds. The test runner never calls this symbol.
export fn ntip_linux_compile_probe(raw_context: *anyopaque) void {
    const context: *ProbeContext = @ptrCast(@alignCast(raw_context));
    compileLinuxRuntime(context);
}

test "Linux runtime compile probe is linked" {
    try std.testing.expect(true);
}
