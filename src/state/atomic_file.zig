const std = @import("std");
const builtin = @import("builtin");

pub const private_file_permissions = std.Io.File.Permissions.fromMode(0o600);
pub const public_config_permissions = std.Io.File.Permissions.fromMode(0o644);
pub const private_dir_permissions = std.Io.File.Permissions.fromMode(0o700);

pub const FaultPoint = enum {
    none,
    before_sync,
    before_rename,
};

/// Atomically replaces `sub_path` inside an already-open directory. A durable
/// commit is file write -> file sync -> rename -> parent directory sync.
pub fn replace(
    dir: std.Io.Dir,
    io: std.Io,
    sub_path: []const u8,
    bytes: []const u8,
    permissions: std.Io.File.Permissions,
) !void {
    return replaceFaultInjected(dir, io, sub_path, bytes, permissions, .none);
}

pub fn replaceFaultInjected(
    dir: std.Io.Dir,
    io: std.Io,
    sub_path: []const u8,
    bytes: []const u8,
    permissions: std.Io.File.Permissions,
    fault: FaultPoint,
) !void {
    var atomic = try dir.createFileAtomic(io, sub_path, .{
        .permissions = permissions,
        .replace = true,
    });
    defer atomic.deinit(io);

    // Offline administration commonly runs as root while the daemon runs as
    // the owner of its private state directory. Preserve that directory's
    // uid/gid on every replacement so a root-written 0600 file cannot lock the
    // service account out on the next restart.
    try inheritDirectoryOwner(dir, atomic.file);
    try atomic.file.writeStreamingAll(io, bytes);
    if (fault == .before_sync) return error.InjectedFailure;
    try atomic.file.sync(io);
    if (fault == .before_rename) return error.InjectedFailure;
    try atomic.replace(io);
    try syncDirectory(dir, io);
}

pub fn readAlloc(
    dir: std.Io.Dir,
    io: std.Io,
    sub_path: []const u8,
    allocator: std.mem.Allocator,
    max_bytes: usize,
) ![]u8 {
    var file = try dir.openFile(io, sub_path, .{ .follow_symlinks = false });
    defer file.close(io);
    const metadata = try file.stat(io);
    if (metadata.kind != .file) return error.InvalidFileType;
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |other| return other,
    };
}

pub fn ensurePrivateDirectory(parent: std.Io.Dir, io: std.Io, sub_path: []const u8) !std.Io.Dir {
    parent.makePath(io, sub_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    try parent.setFilePermissions(io, sub_path, private_dir_permissions, .{});
    return parent.openDir(io, sub_path, .{ .follow_symlinks = false });
}

pub fn deleteDurable(dir: std.Io.Dir, io: std.Io, sub_path: []const u8) !void {
    try dir.deleteFile(io, sub_path);
    try syncDirectory(dir, io);
}

fn syncDirectory(dir: std.Io.Dir, io: std.Io) !void {
    // std.Io's Linux threaded backend may represent an open directory with an
    // O_PATH descriptor. That descriptor is safe for relative filesystem
    // operations but Linux rejects fsync(O_PATH) with EBADF. Re-open `.`
    // relative to the trusted handle so the durability barrier uses a regular
    // read-only directory descriptor.
    if (comptime builtin.os.tag == .linux) {
        const sync_handle = try std.posix.openat(dir.handle, ".", .{
            .ACCMODE = .RDONLY,
            .DIRECTORY = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, 0);
        const directory_file: std.Io.File = .{
            .handle = sync_handle,
            .flags = .{ .nonblocking = false },
        };
        defer directory_file.close(io);
        try directory_file.sync(io);
        return;
    }

    // On the other POSIX platform supported by the development toolchain,
    // std.Io.Dir already owns an fsync-able descriptor.
    const directory_file: std.Io.File = .{
        .handle = dir.handle,
        .flags = .{ .nonblocking = false },
    };
    try directory_file.sync(io);
}

pub const LifetimeLock = struct {
    file: std.Io.File,

    pub fn acquire(dir: std.Io.Dir, io: std.Io, sub_path: []const u8, nonblocking: bool) !LifetimeLock {
        const file = try dir.createFile(io, sub_path, .{
            .read = true,
            .truncate = false,
            .lock = .exclusive,
            .lock_nonblocking = nonblocking,
            .permissions = private_file_permissions,
        });
        errdefer file.close(io);
        try inheritDirectoryOwner(dir, file);
        return .{ .file = file };
    }

    pub fn release(self: *LifetimeLock, io: std.Io) void {
        self.file.close(io);
        self.* = undefined;
    }
};

fn inheritDirectoryOwner(dir: std.Io.Dir, file: std.Io.File) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const request: linux.STATX = .{ .UID = true, .GID = true };
    var directory_stat = std.mem.zeroes(linux.Statx);
    var file_stat = std.mem.zeroes(linux.Statx);
    switch (linux.errno(linux.statx(dir.handle, "", linux.AT.EMPTY_PATH, request, &directory_stat))) {
        .SUCCESS => {},
        else => return error.OwnerLookupFailed,
    }
    switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, request, &file_stat))) {
        .SUCCESS => {},
        else => return error.OwnerLookupFailed,
    }
    if (directory_stat.uid == file_stat.uid and directory_stat.gid == file_stat.gid) return;
    switch (linux.errno(linux.fchown(file.handle, directory_stat.uid, directory_stat.gid))) {
        .SUCCESS => {},
        .PERM, .ACCES => return error.OwnerPreservationDenied,
        else => return error.OwnerPreservationFailed,
    }
}

test "atomic failure before rename preserves prior state" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try replace(tmp.dir, io, "state.json", "old", private_file_permissions);
    const stat = try tmp.dir.statFile(io, "state.json", .{ .follow_symlinks = false });
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);
    try std.testing.expectError(error.InjectedFailure, replaceFaultInjected(
        tmp.dir,
        io,
        "state.json",
        "new",
        private_file_permissions,
        .before_rename,
    ));
    const actual = try readAlloc(tmp.dir, io, "state.json", std.testing.allocator, 64);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings("old", actual);
}

test "exclusive state lock rejects duplicate owner" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var first = try LifetimeLock.acquire(tmp.dir, io, "state.lock", true);
    defer first.release(io);
    try std.testing.expectError(error.WouldBlock, LifetimeLock.acquire(tmp.dir, io, "state.lock", true));
}

test "bounded state reads never follow a symbolic link" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "target", .data = "secret" });
    try tmp.dir.symLink(io, "target", "state.json", .{});
    if (readAlloc(tmp.dir, io, "state.json", std.testing.allocator, 64)) |bytes| {
        std.testing.allocator.free(bytes);
        return error.SymbolicLinkWasFollowed;
    } else |_| {}
}
