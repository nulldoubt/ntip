const std = @import("std");
const builtin = @import("builtin");

pub const User = struct {
    uid: u32,
    gid: u32,
};

pub fn lookupUser(allocator: std.mem.Allocator, io: std.Io, name: []const u8) !User {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, "/etc/passwd", allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    return parseUser(bytes, name) orelse error.ServiceUserNotFound;
}

pub fn lookupGroup(allocator: std.mem.Allocator, io: std.Io, name: []const u8) !u32 {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, "/etc/group", allocator, .limited(1024 * 1024));
    defer allocator.free(bytes);
    return parseGroup(bytes, name) orelse error.AdminGroupNotFound;
}

fn parseUser(bytes: []const u8, wanted: []const u8) ?User {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const uid_text = fields.next() orelse continue;
        const gid_text = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, wanted)) continue;
        const uid = std.fmt.parseInt(u32, uid_text, 10) catch return null;
        const gid = std.fmt.parseInt(u32, gid_text, 10) catch return null;
        return .{ .uid = uid, .gid = gid };
    }
    return null;
}

fn parseGroup(bytes: []const u8, wanted: []const u8) ?u32 {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next() orelse continue;
        _ = fields.next() orelse continue;
        const gid_text = fields.next() orelse continue;
        if (!std.mem.eql(u8, name, wanted)) continue;
        return std.fmt.parseInt(u32, gid_text, 10) catch null;
    }
    return null;
}

test "passwd and group parsers are exact" {
    const passwd = "root:x:0:0:root:/root:/bin/sh\nntip:x:987:986:NTIP:/var/lib/ntip:/usr/sbin/nologin\n";
    const user = parseUser(passwd, "ntip").?;
    try std.testing.expectEqual(@as(u32, 987), user.uid);
    try std.testing.expectEqual(@as(u32, 986), user.gid);
    try std.testing.expect(parseUser(passwd, "nti") == null);

    const groups = "root:x:0:\nntip-admin:x:985:operator\n";
    try std.testing.expectEqual(@as(u32, 985), parseGroup(groups, "ntip-admin").?);
}
