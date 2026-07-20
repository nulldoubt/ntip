const std = @import("std");
const builtin = @import("builtin");
const socket_deadline = @import("socket_deadline.zig");

pub const socket_mode: std.Io.File.Permissions = @enumFromInt(0o660);
/// Human-admin connections are OS-authorized but still untrusted for
/// availability. One incomplete request is hard-closed after this slice; the
/// serialized owner rechecks protocol work before accepting another.
pub const io_timeout_milliseconds: i64 = socket_deadline.phase_timeout_milliseconds;

pub const PeerCredentials = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

pub const Listener = struct {
    server: std.Io.net.Server,
    io: std.Io,
    path: []const u8,

    pub fn listen(io: std.Io, path: []const u8, admin_gid: std.Io.File.Gid) !Listener {
        const address = try std.Io.net.UnixAddress.init(path);
        var server = try address.listen(io, .{});
        errdefer server.deinit(io);

        if (comptime builtin.os.tag == .linux) try secureSocketPath(path, admin_gid);
        return .{ .server = server, .io = io, .path = path };
    }

    pub fn accept(self: *Listener) !Connection {
        const stream = try self.server.accept(self.io);
        errdefer stream.close(self.io);
        try installIoDeadline(stream.socket.handle);
        return .{
            .stream = stream,
            .credentials = try peerCredentials(stream.socket.handle),
        };
    }

    pub fn handle(self: *const Listener) std.Io.net.Socket.Handle {
        return self.server.socket.handle;
    }

    pub fn close(self: *Listener) void {
        self.server.deinit(self.io);
        std.Io.Dir.cwd().deleteFile(self.io, self.path) catch {};
        self.* = undefined;
    }
};

fn secureSocketPath(path: []const u8, admin_gid: std.Io.File.Gid) !void {
    const linux = std.os.linux;
    if (path.len > std.Io.net.UnixAddress.max_len) return error.NameTooLong;
    var path_z: [std.Io.net.UnixAddress.max_len + 1:0]u8 = [_:0]u8{0} ** (std.Io.net.UnixAddress.max_len + 1);
    @memcpy(path_z[0..path.len], path);
    switch (linux.errno(linux.chmod(&path_z, @intFromEnum(socket_mode)))) {
        .SUCCESS => {},
        else => return error.SocketPermissionSetupFailed,
    }
    switch (linux.errno(linux.fchownat(linux.AT.FDCWD, &path_z, 0, admin_gid, linux.AT.SYMLINK_NOFOLLOW))) {
        .SUCCESS => {},
        else => return error.SocketOwnershipSetupFailed,
    }
}

fn installIoDeadline(handle: std.Io.net.Socket.Handle) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const timeout: linux.timeval = .{
        .sec = 0,
        .usec = io_timeout_milliseconds * std.time.us_per_ms,
    };
    try std.posix.setsockopt(handle, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try std.posix.setsockopt(handle, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&timeout));
}

pub const Connection = struct {
    stream: std.Io.net.Stream,
    credentials: PeerCredentials,

    pub fn close(self: *Connection, io: std.Io) void {
        self.stream.close(io);
        self.* = undefined;
    }
};

pub fn peerCredentials(handle: std.Io.net.Socket.Handle) !PeerCredentials {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    var credentials: PeerCredentials = undefined;
    var length: linux.socklen_t = @sizeOf(PeerCredentials);
    switch (linux.errno(linux.getsockopt(
        handle,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &length,
    ))) {
        .SUCCESS => {},
        else => return error.PeerCredentialLookupFailed,
    }
    if (length != @sizeOf(PeerCredentials)) return error.PeerCredentialLookupFailed;
    return credentials;
}

test "peer credential structure matches Linux ucred" {
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(PeerCredentials));
}

test "human admin I/O slice preserves protocol progress bound" {
    try std.testing.expect(io_timeout_milliseconds > 0);
    try std.testing.expect(io_timeout_milliseconds <= 250);
}
