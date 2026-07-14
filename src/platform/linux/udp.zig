const std = @import("std");
const builtin = @import("builtin");

pub const default_port: u16 = 49152;

pub const DualStack = struct {
    ipv4: std.Io.net.Socket,
    ipv6: std.Io.net.Socket,
    io: std.Io,

    pub fn bind(io: std.Io, port: u16) !DualStack {
        const address4: std.Io.net.IpAddress = .{ .ip4 = .unspecified(port) };
        const socket4 = try address4.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket4.close(io);

        const socket6 = try bindIpv6Only(io, port);
        errdefer socket6.close(io);

        try requireNoFragment(socket4.handle, .ipv4);
        try requireNoFragment(socket6.handle, .ipv6);
        return .{ .ipv4 = socket4, .ipv6 = socket6, .io = io };
    }

    pub fn close(self: *DualStack) void {
        self.ipv4.close(self.io);
        self.ipv6.close(self.io);
        self.* = undefined;
    }

    pub fn send(self: *const DualStack, destination: *const std.Io.net.IpAddress, bytes: []const u8) !void {
        switch (destination.*) {
            .ip4 => try self.ipv4.send(self.io, destination, bytes),
            .ip6 => try self.ipv6.send(self.io, destination, bytes),
        }
    }

    pub fn receiveIpv4(self: *const DualStack, buffer: []u8) !std.Io.net.IncomingMessage {
        return self.ipv4.receive(self.io, buffer);
    }

    pub fn receiveIpv6(self: *const DualStack, buffer: []u8) !std.Io.net.IncomingMessage {
        return self.ipv6.receive(self.io, buffer);
    }
};

fn bindIpv6Only(io: std.Io, port: u16) !std.Io.net.Socket {
    if (comptime builtin.os.tag != .linux) {
        const address: std.Io.net.IpAddress = .{ .ip6 = .unspecified(port) };
        return address.bind(io, .{ .mode = .dgram, .protocol = .udp, .ip6_only = true });
    }

    // Zig 0.16.0's POSIX std.Io backend applies IPV6_V6ONLY with a zero
    // value when BindOptions.ip6_only is true. Linux therefore leaves the
    // socket dual-stack and its bind collides with the explicit IPv4 socket.
    // Create this one socket directly so V6ONLY=1 is installed before bind.
    const linux = std.os.linux;
    const result = linux.socket(
        linux.AF.INET6,
        linux.SOCK.DGRAM | linux.SOCK.CLOEXEC,
        @intFromEnum(std.Io.net.Protocol.udp),
    );
    const handle: linux.fd_t = switch (linux.errno(result)) {
        .SUCCESS => @intCast(result),
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    };
    errdefer _ = linux.close(handle);

    const enabled: c_int = 1;
    try std.posix.setsockopt(
        handle,
        linux.IPPROTO.IPV6,
        linux.IPV6.V6ONLY,
        std.mem.asBytes(&enabled),
    );

    var native_address: linux.sockaddr.in6 = .{
        .port = std.mem.nativeToBig(u16, port),
        .flowinfo = 0,
        .addr = @splat(0),
        .scope_id = 0,
    };
    while (true) switch (linux.errno(linux.bind(
        handle,
        @ptrCast(&native_address),
        @sizeOf(linux.sockaddr.in6),
    ))) {
        .SUCCESS => break,
        .INTR => continue,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressUnavailable,
        .AFNOSUPPORT => return error.AddressFamilyUnsupported,
        .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    };

    if (port == 0) {
        var length: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
        switch (linux.errno(linux.getsockname(handle, @ptrCast(&native_address), &length))) {
            .SUCCESS => {},
            else => return error.Unexpected,
        }
    }

    return .{
        .handle = handle,
        .address = .{ .ip6 = .unspecified(std.mem.bigToNative(u16, native_address.port)) },
    };
}

const Family = enum { ipv4, ipv6 };

fn requireNoFragment(handle: std.Io.net.Socket.Handle, family: Family) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const value: c_int = switch (family) {
        .ipv4 => linux.IP.PMTUDISC_DO,
        .ipv6 => linux.IPV6.PMTUDISC_DO,
    };
    switch (family) {
        .ipv4 => try std.posix.setsockopt(handle, linux.IPPROTO.IP, linux.IP.MTU_DISCOVER, std.mem.asBytes(&value)),
        .ipv6 => try std.posix.setsockopt(handle, linux.IPPROTO.IPV6, linux.IPV6.MTU_DISCOVER, std.mem.asBytes(&value)),
    }
}

test "default port remains in the dynamic/private range" {
    try std.testing.expect(default_port >= 49152);
}
