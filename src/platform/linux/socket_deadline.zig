//! Absolute, phase-scoped deadlines for the serialized Unix admin sockets.
//!
//! Kernel `SO_RCVTIMEO`/`SO_SNDTIMEO` values are inactivity timeouts: every
//! successful partial transfer starts another wait.  These helpers instead
//! retain one monotonic deadline across every partial transfer in a request
//! read or response-frame write.

const std = @import("std");
const builtin = @import("builtin");

pub const phase_timeout_milliseconds: u64 = 100;

pub const Deadline = struct {
    timestamp: std.Io.Clock.Timestamp,

    pub fn start(io: std.Io) Deadline {
        return .{ .timestamp = .fromNow(io, .{
            .raw = .fromMilliseconds(phase_timeout_milliseconds),
            .clock = .awake,
        }) };
    }

    fn initAtNanoseconds(start_ns: i96, milliseconds: u64) Deadline {
        return .{ .timestamp = .{
            .raw = .{ .nanoseconds = start_ns +
                @as(i96, @intCast(milliseconds)) * std.time.ns_per_ms },
            .clock = .awake,
        } };
    }

    pub fn timeout(self: Deadline) std.Io.Timeout {
        return .{ .deadline = self.timestamp };
    }

    fn remainingNanosecondsAt(self: Deadline, now_ns: i96) !u64 {
        const expires_ns = self.timestamp.raw.nanoseconds;
        if (now_ns >= expires_ns) return error.SocketIoDeadlineExceeded;
        return @intCast(expires_ns - now_ns);
    }

    fn remainingNanoseconds(self: Deadline, io: std.Io) !u64 {
        return self.remainingNanosecondsAt(std.Io.Clock.now(.awake, io).nanoseconds);
    }
};

pub fn readExact(
    io: std.Io,
    stream: std.Io.net.Stream,
    destination: []u8,
    deadline: Deadline,
) !void {
    var offset: usize = 0;
    while (offset < destination.len) {
        const message = stream.socket.receiveTimeout(
            io,
            destination[offset..],
            deadline.timeout(),
        ) catch |failure| return switch (failure) {
            error.Timeout => error.SocketIoDeadlineExceeded,
            else => failure,
        };
        if (message.data.len == 0) return error.EndOfStream;
        offset += message.data.len;
    }
}

/// Sends every byte without changing the socket's blocking mode.  `MSG_DONTWAIT`
/// makes each syscall nonblocking; `ppoll` is then bounded by the original
/// monotonic deadline.  Partial sends never refresh that deadline.
pub fn writeAll(
    io: std.Io,
    socket: std.Io.net.Socket,
    bytes: []const u8,
    deadline: Deadline,
) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;

    var offset: usize = 0;
    while (offset < bytes.len) {
        _ = try deadline.remainingNanoseconds(io);
        const written = sendNonblocking(socket.handle, bytes[offset..]) catch |failure| switch (failure) {
            error.WouldBlock => {
                try waitWritable(io, socket.handle, deadline);
                continue;
            },
            else => return failure,
        };
        if (written == 0) return error.EndOfStream;
        offset += written;
    }
}

fn sendNonblocking(handle: std.Io.net.Socket.Handle, bytes: []const u8) !usize {
    const linux = std.os.linux;
    while (true) {
        const result = linux.sendto(
            handle,
            bytes.ptr,
            bytes.len,
            linux.MSG.DONTWAIT | linux.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (linux.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .PIPE => return error.BrokenPipe,
            .CONNRESET => return error.ConnectionResetByPeer,
            .NOTCONN => return error.SocketUnconnected,
            else => return error.SocketWriteFailed,
        }
    }
}

fn waitWritable(
    io: std.Io,
    handle: std.Io.net.Socket.Handle,
    deadline: Deadline,
) !void {
    while (true) {
        const remaining_ns = try deadline.remainingNanoseconds(io);
        var timeout: std.posix.timespec = .{
            .sec = @intCast(remaining_ns / std.time.ns_per_s),
            .nsec = @intCast(remaining_ns % std.time.ns_per_s),
        };
        var descriptors = [_]std.posix.pollfd{.{
            .fd = handle,
            .events = std.posix.POLL.OUT | std.posix.POLL.ERR | std.posix.POLL.HUP,
            .revents = 0,
        }};
        const ready = std.posix.ppoll(&descriptors, &timeout, null) catch |failure| switch (failure) {
            error.SignalInterrupt => continue,
            else => return failure,
        };
        if (ready == 0) return error.SocketIoDeadlineExceeded;
        if (descriptors[0].revents & std.posix.POLL.OUT != 0) return;
        if (descriptors[0].revents & (std.posix.POLL.ERR |
            std.posix.POLL.HUP | std.posix.POLL.NVAL) != 0)
        {
            return error.SocketUnconnected;
        }
    }
}

test "partial progress cannot refresh an absolute socket deadline" {
    const deadline = Deadline.initAtNanoseconds(0, phase_timeout_milliseconds);
    const almost_expired = @as(i96, phase_timeout_milliseconds * std.time.ns_per_ms - 1);

    // Model arbitrary prefix/body or partial-send progress.  Every observation
    // is evaluated against the one original expiry, never against the prior
    // progress instant.
    try std.testing.expectEqual(
        @as(u64, phase_timeout_milliseconds * std.time.ns_per_ms),
        try deadline.remainingNanosecondsAt(0),
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        try deadline.remainingNanosecondsAt(almost_expired),
    );
    try std.testing.expectError(
        error.SocketIoDeadlineExceeded,
        deadline.remainingNanosecondsAt(
            @as(i96, phase_timeout_milliseconds * std.time.ns_per_ms),
        ),
    );
}
