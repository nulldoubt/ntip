const std = @import("std");
const tun = @import("tun.zig");

pub const Error = error{IpRoute2Failed};

/// Runs only fixed-argument `iproute2` commands. No input ever reaches a shell.
pub const Controller = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    executable: []const u8 = "ip",

    pub fn configureLink(self: Controller, interface_name: []const u8, mtu: u16) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        var mtu_buffer: [5]u8 = undefined;
        const mtu_text = try std.fmt.bufPrint(&mtu_buffer, "{d}", .{mtu});
        try self.run(&.{ self.executable, "link", "set", "dev", interface_name, "mtu", mtu_text, "up" });
    }

    pub fn addAddress(self: Controller, interface_name: []const u8, canonical_cidr: []const u8) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        try self.run(&.{ self.executable, "address", "add", canonical_cidr, "dev", interface_name });
    }

    pub fn replaceAddress(self: Controller, interface_name: []const u8, canonical_cidr: []const u8) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        try self.run(&.{ self.executable, "address", "replace", canonical_cidr, "dev", interface_name });
    }

    pub fn deleteAddress(self: Controller, interface_name: []const u8, canonical_cidr: []const u8) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        try self.run(&.{ self.executable, "address", "delete", canonical_cidr, "dev", interface_name });
    }

    pub fn addRoute(self: Controller, interface_name: []const u8, canonical_cidr: []const u8, mtu: u16) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        var mtu_buffer: [5]u8 = undefined;
        const mtu_text = try std.fmt.bufPrint(&mtu_buffer, "{d}", .{mtu});
        try self.run(&.{ self.executable, "route", "add", canonical_cidr, "dev", interface_name, "mtu", mtu_text });
    }

    pub fn replaceRoute(self: Controller, interface_name: []const u8, canonical_cidr: []const u8, mtu: u16) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        var mtu_buffer: [5]u8 = undefined;
        const mtu_text = try std.fmt.bufPrint(&mtu_buffer, "{d}", .{mtu});
        try self.run(&.{ self.executable, "route", "replace", canonical_cidr, "dev", interface_name, "mtu", mtu_text });
    }

    pub fn deleteRoute(self: Controller, interface_name: []const u8, canonical_cidr: []const u8) !void {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        try self.run(&.{ self.executable, "route", "delete", canonical_cidr, "dev", interface_name });
    }

    pub fn forwardingEnabled(self: Controller) !bool {
        return try self.sysctlValue("net.ipv4.ip_forward") == 1;
    }

    pub fn reversePathFilter(self: Controller, interface_name: []const u8) !u8 {
        if (!tun.validInterfaceName(interface_name)) return error.InvalidInterfaceName;
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "net.ipv4.conf.{s}.rp_filter", .{interface_name});
        const value = try self.sysctlValue(name);
        if (value > 2) return error.InvalidSysctlValue;
        return @intCast(value);
    }

    pub fn allReversePathFilter(self: Controller) !u8 {
        const value = try self.sysctlValue("net.ipv4.conf.all.rp_filter");
        if (value > 2) return error.InvalidSysctlValue;
        return @intCast(value);
    }

    fn sysctlValue(self: Controller, name: []const u8) !u32 {
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ "sysctl", "-n", name },
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (!successful(result.term)) {
            logFailure("sysctl", name, result.term, result.stderr);
            return error.SysctlProbeFailed;
        }
        const text = std.mem.trim(u8, result.stdout, " \t\r\n");
        return std.fmt.parseInt(u32, text, 10) catch error.InvalidSysctlValue;
    }

    fn run(self: Controller, argv: []const []const u8) !void {
        const result = try std.process.run(self.allocator, self.io, .{ .argv = argv });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        if (!successful(result.term)) {
            const operation = if (argv.len > 1) argv[1] else "unknown";
            logFailure("iproute2", operation, result.term, result.stderr);
            return error.IpRoute2Failed;
        }
    }
};

fn logFailure(tool: []const u8, operation: []const u8, term: std.process.Child.Term, stderr: []const u8) void {
    const maximum = @min(stderr.len, 512);
    const detail = std.mem.trim(u8, stderr[0..maximum], " \t\r\n");
    std.log.err("{s} operation failed operation={s} term={any} stderr={s}", .{
        tool,
        operation,
        term,
        if (detail.len == 0) "-" else detail,
    });
}

fn successful(term: std.process.Child.Term) bool {
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

test "route controller interface validation rejects injection text" {
    const controller: Controller = .{ .allocator = std.testing.allocator, .io = std.testing.io };
    try std.testing.expectError(error.InvalidInterfaceName, controller.configureLink("ntip0;true", 1380));
}
