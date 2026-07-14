const std = @import("std");
const builtin = @import("builtin");

pub const default_name = "ntip0";
pub const default_mtu: u16 = 1380;

pub const Device = struct {
    fd: std.posix.fd_t,
    name: [name_capacity]u8,
    name_len: u8,

    pub fn openExclusive(name: []const u8) !Device {
        if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
        if (!validInterfaceName(name)) return error.InvalidInterfaceName;

        const fd = try std.posix.openat(
            std.posix.AT.FDCWD,
            "/dev/net/tun",
            .{ .ACCMODE = .RDWR, .CLOEXEC = true },
            0,
        );
        errdefer _ = std.os.linux.close(fd);

        var request: Ifreq = .{};
        @memcpy(request.name[0..name.len], name);
        request.flags = iff_tun | iff_no_pi | iff_tun_excl;

        const linux = std.os.linux;
        switch (linux.errno(linux.ioctl(fd, tun_set_iff, @intFromPtr(&request)))) {
            .SUCCESS => {},
            .BUSY, .EXIST => return error.InterfaceAlreadyExists,
            .PERM, .ACCES => return error.PermissionDenied,
            .NODEV, .NOENT => return error.TunUnavailable,
            .INVAL => return error.UnsupportedTunConfiguration,
            else => return error.UnexpectedIoctlFailure,
        }

        var device: Device = .{ .fd = fd, .name = [_]u8{0} ** name_capacity, .name_len = @intCast(name.len) };
        @memcpy(device.name[0..name.len], name);
        return device;
    }

    pub fn close(self: *Device) void {
        if (comptime builtin.os.tag == .linux) _ = std.os.linux.close(self.fd);
        self.* = undefined;
    }

    pub fn interfaceName(self: *const Device) []const u8 {
        return self.name[0..self.name_len];
    }

    pub fn read(self: *const Device, io: std.Io, destination: []u8) !usize {
        const handle_file = self.file();
        var vectors: [1][]u8 = .{destination};
        return handle_file.readStreaming(io, &vectors);
    }

    pub fn write(self: *const Device, io: std.Io, packet: []const u8) !void {
        try self.file().writeStreamingAll(io, packet);
    }

    fn file(self: *const Device) std.Io.File {
        return .{ .handle = self.fd, .flags = .{ .nonblocking = false } };
    }
};

const name_capacity = 16;
const iff_tun: i16 = 0x0001;
const iff_no_pi: i16 = 0x1000;
const iff_tun_excl: i16 = @bitCast(@as(u16, 0x8000));
const tun_set_iff: u32 = 0x400454ca;

const Ifreq = extern struct {
    name: [name_capacity]u8 = [_]u8{0} ** name_capacity,
    flags: i16 = 0,
    padding: [22]u8 = [_]u8{0} ** 22,
};

pub fn validInterfaceName(name: []const u8) bool {
    if (name.len == 0 or name.len >= name_capacity) return false;
    for (name) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.' => {},
        else => return false,
    };
    return true;
}

test "interface name validation is strict" {
    try std.testing.expect(validInterfaceName("ntip0"));
    try std.testing.expect(!validInterfaceName(""));
    try std.testing.expect(!validInterfaceName("ntip0;ip link"));
    try std.testing.expect(!validInterfaceName("0123456789abcdef"));
}

test "ifreq layout matches Linux ABI" {
    try std.testing.expectEqual(@as(usize, 40), @sizeOf(Ifreq));
}
