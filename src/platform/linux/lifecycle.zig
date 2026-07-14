const std = @import("std");
const builtin = @import("builtin");

pub const service_user = "ntip";
pub const admin_group = "ntip-admin";
pub const required_capability = "CAP_NET_ADMIN";

// Linux UAPI `struct __user_cap_header_struct` uses a 32-bit pid. Zig 0.16.0's
// std.os.linux.cap_user_header_t currently declares pid as usize, which puts
// it at offset eight on 64-bit targets while the kernel reads offset four.
// Keep the wire-to-kernel ABI explicit and use the raw syscall below.
const CapabilityHeader = extern struct {
    version: u32,
    pid: i32,
};

pub const Paths = struct {
    config: []const u8,
    state_dir: []const u8,
    runtime_dir: []const u8,

    pub const server: Paths = .{
        .config = "/etc/ntip/server.json",
        .state_dir = "/var/lib/ntip/server",
        .runtime_dir = "/run/ntip",
    };

    pub const client: Paths = .{
        .config = "/etc/ntip/client.json",
        .state_dir = "/var/lib/ntip/client",
        .runtime_dir = "/run/ntip",
    };
};

pub const Readiness = enum(u8) {
    initializing,
    ready,
    failed,
    stopping,
};

/// Tracks ownership so startup rollback and shutdown remove only resources
/// created by this process.
pub const OwnedResources = struct {
    tun_created: bool = false,
    udp4_bound: bool = false,
    udp6_bound: bool = false,
    ipc_bound: bool = false,
    state_locked: bool = false,

    pub fn clear(self: *OwnedResources) void {
        self.* = .{};
    }
};

pub const Limits = struct {
    ipc_message_bytes: usize = 1024 * 1024,
    control_queue_entries: usize = 1024,
    data_queue_entries: usize = 4096,
    control_frame_bytes: usize = 1200,

    pub fn validate(self: Limits) !void {
        if (self.ipc_message_bytes == 0 or self.ipc_message_bytes > 1024 * 1024) return error.InvalidIpcLimit;
        if (self.control_queue_entries == 0 or self.data_queue_entries == 0) return error.InvalidQueueLimit;
        if (self.control_frame_bytes == 0 or self.control_frame_bytes > 1200) return error.InvalidControlFrameLimit;
    }
};

var stop_requested: std.atomic.Value(bool) = .init(false);

pub fn installTerminationHandlers() void {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return;
    const action: std.posix.Sigaction = .{
        .handler = .{ .handler = terminationHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.INT, &action, null);
    std.posix.sigaction(.TERM, &action, null);
}

pub fn shouldStop() bool {
    return stop_requested.load(.acquire);
}

pub fn requestStop() void {
    stop_requested.store(true, .release);
}

pub fn resetStopForTest() void {
    stop_requested.store(false, .release);
}

fn terminationHandler(_: std.posix.SIG) callconv(.c) void {
    stop_requested.store(true, .release);
}

pub const ForkResult = union(enum) {
    parent: struct { child_pid: i32, readiness_fd: i32 },
    child: struct { readiness_fd: i32 },
};

/// Forks before runtime worker threads exist and creates a one-byte readiness
/// channel. The child creates a new session immediately.
pub fn forkForDaemon() !ForkResult {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    var pipe_fds: [2]i32 = undefined;
    switch (linux.errno(linux.pipe2(&pipe_fds, .{ .CLOEXEC = true }))) {
        .SUCCESS => {},
        else => return error.ReadinessPipeFailed,
    }
    errdefer {
        _ = linux.close(pipe_fds[0]);
        _ = linux.close(pipe_fds[1]);
    }

    const result = linux.fork();
    switch (linux.errno(result)) {
        .SUCCESS => {},
        else => return error.ForkFailed,
    }
    if (result == 0) {
        _ = linux.close(pipe_fds[0]);
        switch (linux.errno(linux.setsid())) {
            .SUCCESS => {},
            else => return error.CreateSessionFailed,
        }
        try detachStandardStreams();
        return .{ .child = .{ .readiness_fd = pipe_fds[1] } };
    }

    _ = linux.close(pipe_fds[1]);
    return .{ .parent = .{ .child_pid = @intCast(result), .readiness_fd = pipe_fds[0] } };
}

fn detachStandardStreams() !void {
    const linux = std.os.linux;
    const opened = linux.open("/dev/null", .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
    switch (linux.errno(opened)) {
        .SUCCESS => {},
        else => return error.OpenDevNullFailed,
    }
    const fd: i32 = @intCast(opened);
    defer _ = linux.close(fd);
    for (0..3) |target| {
        switch (linux.errno(linux.dup2(fd, @intCast(target)))) {
            .SUCCESS => {},
            else => return error.RedirectStandardStreamFailed,
        }
    }
}

pub fn waitForReadiness(fd: i32) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    defer _ = std.os.linux.close(fd);
    var status: [1]u8 = undefined;
    const linux = std.os.linux;
    var poll_fds = [_]std.posix.pollfd{.{
        .fd = fd,
        .events = std.posix.POLL.IN | std.posix.POLL.ERR | std.posix.POLL.HUP,
        .revents = 0,
    }};
    if (try std.posix.poll(&poll_fds, 30_000) == 0) return error.ReadinessTimeout;
    const result = linux.read(fd, &status, status.len);
    switch (linux.errno(result)) {
        .SUCCESS => {},
        else => return error.ReadinessReadFailed,
    }
    if (result != 1 or status[0] != 1) return error.DaemonStartupFailed;
}

pub fn terminateFailedChild(pid: i32) void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    _ = linux.kill(pid, .TERM);
    var status: u32 = 0;
    _ = linux.waitpid(pid, &status, 0);
}

pub fn reportReadiness(fd: i32, ready: bool) void {
    if (comptime builtin.os.tag != .linux) return;
    defer _ = std.os.linux.close(fd);
    const linux = std.os.linux;
    const status = [1]u8{@intFromBool(ready)};
    _ = linux.write(fd, &status, status.len);
}

/// Drops every inherited supplementary group except the dedicated local IPC
/// administration group, then retains only CAP_NET_ADMIN in the effective and
/// permitted capability sets. The retained group lets the unprivileged daemon
/// unlink its own root:ntip-admin socket from the protected runtime directory.
pub fn dropToServiceUser(uid: u32, gid: u32, admin_gid: u32) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    const pr_set_keepcaps = 8;
    const pr_set_no_new_privs = 38;
    const pr_cap_ambient = 47;
    const pr_cap_ambient_raise = 2;

    switch (linux.errno(linux.prctl(pr_set_keepcaps, 1, 0, 0, 0))) {
        .SUCCESS => {},
        else => return error.KeepCapabilitiesFailed,
    }
    var retained_groups = [_]linux.gid_t{@intCast(admin_gid)};
    switch (linux.errno(linux.setgroups(retained_groups.len, &retained_groups))) {
        .SUCCESS => {},
        else => return error.DropSupplementaryGroupsFailed,
    }
    switch (linux.errno(linux.setgid(gid))) {
        .SUCCESS => {},
        else => return error.SetGidFailed,
    }
    switch (linux.errno(linux.setuid(uid))) {
        .SUCCESS => {},
        else => return error.SetUidFailed,
    }

    var header: CapabilityHeader = .{ .version = 0x20080522, .pid = 0 };
    var capabilities = [_]linux.cap_user_data_t{.{ .effective = 0, .permitted = 0, .inheritable = 0 }} ** 2;
    const cap_net_admin: u5 = 12;
    const capability_bit = @as(u32, 1) << cap_net_admin;
    capabilities[0].effective = capability_bit;
    capabilities[0].permitted = capability_bit;
    capabilities[0].inheritable = capability_bit;
    switch (linux.errno(linux.syscall2(
        .capset,
        @intFromPtr(&header),
        @intFromPtr(&capabilities[0]),
    ))) {
        .SUCCESS => {},
        else => return error.SetCapabilitiesFailed,
    }
    // Fixed-argument iproute2 children need the same sole capability for live
    // route reconciliation after the daemon has dropped uid 0.
    switch (linux.errno(linux.prctl(pr_cap_ambient, pr_cap_ambient_raise, cap_net_admin, 0, 0))) {
        .SUCCESS => {},
        else => return error.SetAmbientCapabilityFailed,
    }
    switch (linux.errno(linux.prctl(pr_set_no_new_privs, 1, 0, 0, 0))) {
        .SUCCESS => {},
        else => return error.NoNewPrivilegesFailed,
    }
}

test "lifecycle limits remain bounded" {
    try (Limits{}).validate();
    var invalid: Limits = .{};
    invalid.ipc_message_bytes += 1;
    try std.testing.expectError(error.InvalidIpcLimit, invalid.validate());
}

test "capability header matches the Linux UAPI layout" {
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(CapabilityHeader));
    try std.testing.expectEqual(@as(usize, 4), @offsetOf(CapabilityHeader, "pid"));
}
