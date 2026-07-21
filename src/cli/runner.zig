const std = @import("std");
const common = @import("common.zig");
const atomic = @import("../state/atomic_file.zig");
const runtime_ipc = @import("../runtime/ipc.zig");

pub const SocketState = enum {
    absent,
    socket,
};

pub fn mapError(err: anyerror) common.ExitCode {
    return switch (err) {
        error.InvalidArguments,
        error.MissingCommand,
        error.MissingSubcommand,
        error.MissingOptionValue,
        error.MissingRequiredOption,
        error.UnknownCommand,
        error.UnknownSubcommand,
        error.UnknownOption,
        error.DuplicateOption,
        error.InvalidDuration,
        error.InvalidEndpoint,
        error.InvalidName,
        error.InvalidIpv4,
        error.NonCanonicalIpv4,
        error.InvalidCidr,
        error.InvalidPrefix,
        error.NonCanonicalCidr,
        error.InvalidVnrPrefix,
        error.InvalidVnrRange,
        error.InvalidRoutePrefix,
        error.InvalidRouteRange,
        error.InvalidAddress,
        error.InvalidConfig,
        error.InvalidConfigJson,
        error.UnsupportedSchemaVersion,
        error.InvalidSecretLength,
        error.InvalidExpiry,
        error.InvalidPath,
        error.InsecurePermissions,
        error.InsecureStateDirectory,
        error.InsecureConfigFile,
        error.InsecureDirectoryMetadata,
        error.InsecureOwner,
        error.InvalidCredentialFileType,
        error.CredentialFileNotFound,
        error.EmptyCredential,
        error.CredentialTooLong,
        error.RequestTooLarge,
        error.UnsupportedPlatform,
        error.ServiceUserNotFound,
        error.AdminGroupNotFound,
        error.ServiceIdentityMismatch,
        error.LegacyMasterStateUnsupported,
        error.InsecureStateDirectoryPermissions,
        error.InsecureDatabasePermissions,
        error.InvalidDatabaseFileType,
        error.InvalidUsername,
        error.InvalidPassword,
        error.EmptyPassword,
        error.PasswordTooLong,
        error.RootRequired,
        => .usage_or_config,

        error.VnrExists,
        error.VnrNotFound,
        error.VnrOverlap,
        error.VnrInUse,
        error.NodeExists,
        error.NodeIdInUse,
        error.NodeNotFound,
        error.NodeAlreadyEnrolled,
        error.NodeAddressOutsideVnr,
        error.NodeAddressReserved,
        error.AddressInUse,
        error.NodeHasRoutes,
        error.RouteExists,
        error.RouteNotFound,
        error.RouteOverlap,
        error.RouteOverlapsVnr,
        error.PublicKeyInUse,
        error.EnrollmentNotFound,
        error.EnrollmentConsumed,
        error.EnrollmentRevoked,
        error.EnrollmentExpired,
        error.EnrollmentHandleInUse,
        error.AlreadyRunning,
        error.DaemonRunning,
        error.MaximumNodesExceeded,
        error.AlreadyBootstrapped,
        => .conflict_or_not_found,

        error.DaemonUnavailable,
        error.ConnectionRefused,
        error.WouldBlock,
        => .daemon_unavailable,

        error.InvalidCredentialLength,
        error.InvalidCredentialPrefix,
        error.InvalidCredentialEncoding,
        error.NonCanonicalCredential,
        error.InvalidCredentialComponent,
        error.InvalidPublicKey,
        error.InvalidPsk,
        error.InvalidPrivateKey,
        error.InvalidDhPublicKey,
        error.AuthenticationFailed,
        error.CorruptSecret,
        error.UnexpectedSecretKind,
        error.UnsupportedSecretVersion,
        error.MasterIdentityMismatch,
        => .authentication_or_protocol,

        else => .internal_failure,
    };
}

pub fn reportError(stderr: *std.Io.Writer, program: []const u8, err: anyerror) !common.ExitCode {
    const code = mapError(err);
    switch (code) {
        .daemon_unavailable => try stderr.print("{s}: daemon unavailable ({s})\n", .{ program, @errorName(err) }),
        .authentication_or_protocol => try stderr.print("{s}: authentication/protocol failure ({s})\n", .{ program, @errorName(err) }),
        else => try stderr.print("{s}: {s}\n", .{ program, @errorName(err) }),
    }
    return code;
}

pub fn openPrivateDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    if (path.len == 0) return error.InvalidPath;
    const cwd = std.Io.Dir.cwd();
    _ = try cwd.createDirPathStatus(io, path, atomic.private_dir_permissions);
    const dir = try openDirectory(io, path);
    errdefer dir.close(io);
    const stat = try dir.stat(io);
    if (stat.kind != .directory) return error.InvalidStateDirectory;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecureStateDirectory;
    return dir;
}

pub fn socketPath(allocator: std.mem.Allocator, runtime_dir: []const u8, basename: []const u8) ![]u8 {
    return std.fs.path.join(allocator, &.{ runtime_dir, basename });
}

pub fn socketState(io: std.Io, path: []const u8) !SocketState {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return .absent,
        else => return err,
    };
    if (stat.kind != .unix_domain_socket) return error.InvalidRuntimeEntry;
    return .socket;
}

pub fn writePrivatePath(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const parts = try openParent(io, path, false, atomic.private_dir_permissions);
    defer parts.dir.close(io);
    try atomic.replace(parts.dir, io, parts.basename, bytes, atomic.private_file_permissions);
}

/// Reserves a new private disclosure path before the caller commits any
/// authoritative state. The exclusive create rejects existing regular files,
/// symbolic links, and concurrent writers. A small synced allocation also
/// catches an unavailable or unwritable target before one-time material is
/// issued. Call `commit` exactly once after the durable mutation succeeds;
/// `deinit` removes an uncommitted reservation.
pub const PrivatePathReservation = struct {
    io: std.Io,
    dir: std.Io.Dir,
    basename: []const u8,
    committed: bool = false,

    pub fn commit(self: *PrivatePathReservation, bytes: []const u8) !void {
        if (self.committed) return error.OutputAlreadyCommitted;
        try atomic.replace(self.dir, self.io, self.basename, bytes, atomic.private_file_permissions);
        self.committed = true;
    }

    pub fn deinit(self: *PrivatePathReservation) void {
        if (!self.committed) {
            atomic.deleteDurable(self.dir, self.io, self.basename) catch {};
        }
        self.dir.close(self.io);
        self.* = undefined;
    }
};

pub fn reservePrivatePath(io: std.Io, path: []const u8, reserve_bytes: usize) !PrivatePathReservation {
    if (reserve_bytes == 0 or reserve_bytes > 4096) return error.InvalidReservationSize;
    const parts = try openParent(io, path, false, atomic.private_dir_permissions);
    errdefer parts.dir.close(io);
    var file = try parts.dir.createFile(io, parts.basename, .{
        .read = true,
        .exclusive = true,
        .permissions = atomic.private_file_permissions,
    });
    var file_open = true;
    errdefer {
        if (file_open) file.close(io);
        parts.dir.deleteFile(io, parts.basename) catch {};
    }
    try file.setPermissions(io, atomic.private_file_permissions);
    var zeroes: [4096]u8 = [_]u8{0} ** 4096;
    defer std.crypto.secureZero(u8, &zeroes);
    try file.writeStreamingAll(io, zeroes[0..reserve_bytes]);
    try file.sync(io);
    file.close(io);
    file_open = false;
    return .{ .io = io, .dir = parts.dir, .basename = parts.basename };
}

pub fn writeConfigPath(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const public_dir_permissions = std.Io.File.Permissions.fromMode(0o755);
    const parts = try openParent(io, path, true, public_dir_permissions);
    defer parts.dir.close(io);
    try atomic.replace(parts.dir, io, parts.basename, bytes, atomic.public_config_permissions);
}

pub fn readCredentialPath(allocator: std.mem.Allocator, io: std.Io, path: []const u8, maximum: usize) ![]u8 {
    const parts = try openParent(io, path, false, atomic.private_dir_permissions);
    defer parts.dir.close(io);
    const stat = try parts.dir.statFile(io, parts.basename, .{ .follow_symlinks = false });
    if (stat.kind != .file) return error.InvalidCredentialFileType;
    if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
    const bytes = try atomic.readAlloc(parts.dir, io, parts.basename, allocator, maximum + 2);
    return trimCredentialOwned(allocator, bytes);
}

pub fn readCredentialInput(allocator: std.mem.Allocator, reader: *std.Io.Reader, maximum: usize) ![]u8 {
    const line = (try reader.takeDelimiter('\n')) orelse return error.EmptyCredential;
    if (line.len > maximum + 1) return error.CredentialTooLong;
    const trimmed = trimCarriageReturn(line);
    if (trimmed.len == 0 or trimmed.len > maximum) return error.InvalidCredentialLength;
    return allocator.dupe(u8, trimmed);
}

pub fn promptCredential(allocator: std.mem.Allocator, io: std.Io, stderr: *std.Io.Writer, maximum: usize) ![]u8 {
    var tty = try std.Io.Dir.openFileAbsolute(io, "/dev/tty", .{ .mode = .read_write });
    defer tty.close(io);
    const original = try std.posix.tcgetattr(tty.handle);
    var hidden = original;
    hidden.lflag.ECHO = false;
    try std.posix.tcsetattr(tty.handle, .FLUSH, hidden);
    defer std.posix.tcsetattr(tty.handle, .FLUSH, original) catch {};

    try stderr.writeAll("Enrollment credential: ");
    try stderr.flush();
    var input_buffer: [256]u8 = undefined;
    var input = std.Io.File.Reader.init(tty, io, &input_buffer);
    const credential = readCredentialInput(allocator, &input.interface, maximum) catch |err| {
        try stderr.writeByte('\n');
        return err;
    };
    try stderr.writeByte('\n');
    return credential;
}

pub fn unixSeconds(io: std.Io) !u64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.ClockBeforeUnixEpoch;
    return @intCast(seconds);
}

pub fn invokeIpc(
    allocator: std.mem.Allocator,
    io: std.Io,
    socket_path: []const u8,
    args: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !common.ExitCode {
    var argument_bytes: usize = 0;
    for (args) |arg| {
        argument_bytes = std.math.add(usize, argument_bytes, arg.len) catch return error.RequestTooLarge;
        if (argument_bytes > runtime_ipc.maximum_message_bytes / 2) return error.RequestTooLarge;
    }
    var stream = try connectIpc(io, socket_path);
    defer stream.close(io);

    var request_id: u64 = 0;
    while (request_id == 0) io.random(std.mem.asBytes(&request_id));
    const request = struct {
        version: u16,
        request_id: u64,
        command: []const u8,
        arguments: struct { argv: []const []const u8 },
    }{
        .version = runtime_ipc.protocol_version,
        .request_id = request_id,
        .command = try canonicalIpcCommand(args),
        .arguments = .{ .argv = args },
    };
    const request_body = try std.json.Stringify.valueAlloc(allocator, request, .{});
    defer allocator.free(request_body);

    var write_buffer: [4096]u8 = undefined;
    var stream_writer = std.Io.net.Stream.Writer.init(stream, io, &write_buffer);
    try runtime_ipc.writeFrame(&stream_writer.interface, request_body);

    var read_buffer: [4096]u8 = undefined;
    var stream_reader = std.Io.net.Stream.Reader.init(stream, io, &read_buffer);
    const response_buffer = try allocator.alloc(u8, runtime_ipc.maximum_message_bytes);
    defer allocator.free(response_buffer);
    const response_body = try runtime_ipc.readFrame(&stream_reader.interface, response_buffer);
    const parsed = runtime_ipc.decodeResponse(allocator, response_body) catch return error.InvalidIpcResponse;
    defer parsed.deinit();
    const response = parsed.value;
    if (response.request_id != request_id) return error.InvalidIpcResponse;
    const code: common.ExitCode = switch (response.exit_code) {
        0 => .success,
        1 => .internal_failure,
        2 => .usage_or_config,
        3 => .conflict_or_not_found,
        4 => .daemon_unavailable,
        5 => .authentication_or_protocol,
        else => return error.InvalidIpcResponse,
    };
    if (response.result) |result| {
        const object = result.object;
        var wrote_stdout = false;
        if (object.get("stdout")) |value| switch (value) {
            .string => |message| {
                try stdout.writeAll(message);
                wrote_stdout = true;
            },
            else => return error.InvalidIpcResponse,
        };
        if (object.get("stderr")) |value| switch (value) {
            .string => |message| try stderr.writeAll(message),
            else => return error.InvalidIpcResponse,
        };
        if (!wrote_stdout and response.ok) {
            try std.json.Stringify.value(result, .{}, stdout);
            try stdout.writeByte('\n');
        }
    }
    if (response.@"error") |body| {
        try stderr.print("{s}: {s}\n", .{ body.code, body.message });
    }
    return code;
}

fn connectIpc(io: std.Io, path: []const u8) !std.Io.net.Stream {
    if (path.len > std.Io.net.UnixAddress.max_len) return error.NameTooLong;
    if (comptime @import("builtin").os.tag == .windows) {
        const address = try std.Io.net.UnixAddress.init(path);
        return address.connect(io) catch return error.DaemonUnavailable;
    }

    // Zig 0.16.0's threaded Unix connector omits ECONNREFUSED from its Darwin
    // mapping. Use the underlying POSIX call so an ordinary stale pathname is
    // a quiet, expected liveness result on both development macOS and Linux.
    const posix = std.posix;
    const raw_fd = posix.system.socket(posix.AF.UNIX, posix.SOCK.STREAM, 0);
    if (posix.errno(raw_fd) != .SUCCESS) return error.DaemonUnavailable;
    const fd: posix.fd_t = @intCast(raw_fd);
    errdefer _ = posix.system.close(fd);
    switch (posix.errno(posix.system.fcntl(fd, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC)))) {
        .SUCCESS => {},
        else => return error.DaemonUnavailable,
    }

    var address: posix.sockaddr.un = std.mem.zeroes(posix.sockaddr.un);
    address.family = posix.AF.UNIX;
    @memcpy(address.path[0..path.len], path);
    var path_bytes = path.len;
    if (address.path.len > path_bytes) {
        address.path[path_bytes] = 0;
        path_bytes += 1;
    }
    const address_len: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path_bytes);
    if (comptime @hasField(posix.sockaddr.un, "len")) address.len = @intCast(address_len);

    while (true) switch (posix.errno(posix.system.connect(fd, @ptrCast(&address), address_len))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.DaemonUnavailable,
    };
    return .{ .socket = .{
        .handle = fd,
        .address = .{ .ip4 = .loopback(0) },
    } };
}

/// Invokes the daemon only when its Unix socket is both present and
/// connectable. A Unix socket pathname can survive an unclean daemon exit, so
/// its file type alone is not proof of liveness. Only failure to establish the
/// connection is treated as stale; once connected, framing/authentication
/// errors are returned and must never be reinterpreted as permission to mutate
/// state offline. This helper never removes the socket pathname.
pub fn tryInvokeIpc(
    allocator: std.mem.Allocator,
    io: std.Io,
    socket_path: []const u8,
    args: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !?common.ExitCode {
    if (try socketState(io, socket_path) == .absent) return null;
    return invokeIpc(allocator, io, socket_path, args, stdout, stderr) catch |err| switch (err) {
        error.DaemonUnavailable => null,
        else => return err,
    };
}

pub fn canonicalIpcCommand(args: []const []const u8) ![]const u8 {
    var index: usize = 0;
    while (index < args.len) {
        if (std.mem.eql(u8, args[index], "--config") or
            std.mem.eql(u8, args[index], "--state-dir") or
            std.mem.eql(u8, args[index], "--runtime-dir"))
        {
            if (index + 1 >= args.len) return error.InvalidArguments;
            index += 2;
            continue;
        }
        break;
    }
    if (index >= args.len) return error.InvalidArguments;
    const primary = args[index];
    if (std.mem.eql(u8, primary, "vnr") or std.mem.eql(u8, primary, "route")) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        const sub = args[index + 1];
        if (std.mem.eql(u8, primary, "vnr")) {
            if (std.mem.eql(u8, sub, "create")) return "vnr.create";
            if (std.mem.eql(u8, sub, "delete")) return "vnr.delete";
            if (std.mem.eql(u8, sub, "list")) return "vnr.list";
            if (std.mem.eql(u8, sub, "show")) return "vnr.show";
        } else {
            if (std.mem.eql(u8, sub, "add")) return "route.add";
            if (std.mem.eql(u8, sub, "delete")) return "route.delete";
            if (std.mem.eql(u8, sub, "list")) return "route.list";
            if (std.mem.eql(u8, sub, "show")) return "route.show";
        }
    } else if (std.mem.eql(u8, primary, "node")) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        const sub = args[index + 1];
        if (std.mem.eql(u8, sub, "create")) return "node.create";
        if (std.mem.eql(u8, sub, "delete")) return "node.delete";
        if (std.mem.eql(u8, sub, "list")) return "node.list";
        if (std.mem.eql(u8, sub, "show")) return "node.show";
        if (std.mem.eql(u8, sub, "enrollment")) {
            if (index + 2 >= args.len) return error.InvalidArguments;
            if (std.mem.eql(u8, args[index + 2], "renew")) return "node.enrollment.renew";
            if (std.mem.eql(u8, args[index + 2], "reset")) return "node.enrollment.reset";
        }
    } else if (std.mem.eql(u8, primary, "user")) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        if (std.mem.eql(u8, args[index + 1], "bootstrap")) return "user.bootstrap";
    } else {
        if (std.mem.eql(u8, primary, "up")) return "up";
        if (std.mem.eql(u8, primary, "down")) return "down";
        if (std.mem.eql(u8, primary, "status")) return "status";
        if (std.mem.eql(u8, primary, "backup")) return "backup";
        if (std.mem.eql(u8, primary, "restore")) return "restore";
        if (std.mem.eql(u8, primary, "config")) return "config";
        if (std.mem.eql(u8, primary, "version")) return "version";
    }
    return error.InvalidArguments;
}

const Parent = struct {
    dir: std.Io.Dir,
    basename: []const u8,
};

fn openParent(io: std.Io, path: []const u8, create: bool, permissions: std.Io.File.Permissions) !Parent {
    if (path.len == 0) return error.InvalidPath;
    const dirname = std.fs.path.dirname(path) orelse ".";
    const basename = std.fs.path.basename(path);
    if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidPath;
    const dir = openDirectory(io, dirname) catch |err| switch (err) {
        error.FileNotFound => blk: {
            if (!create) return err;
            _ = try std.Io.Dir.cwd().createDirPathStatus(io, dirname, permissions);
            break :blk try openDirectory(io, dirname);
        },
        else => return err,
    };
    return .{ .dir = dir, .basename = basename };
}

fn openDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    return if (std.fs.path.isAbsolute(path))
        std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false })
    else
        std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false });
}

fn trimCredentialOwned(allocator: std.mem.Allocator, owned: []u8) ![]u8 {
    var bytes: []const u8 = owned;
    if (bytes.len > 0 and bytes[bytes.len - 1] == '\n') bytes = bytes[0 .. bytes.len - 1];
    bytes = trimCarriageReturn(bytes);
    if (bytes.len == 0) {
        std.crypto.secureZero(u8, owned);
        allocator.free(owned);
        return error.EmptyCredential;
    }
    if (bytes.ptr == owned.ptr and bytes.len == owned.len) return owned;
    const result = allocator.dupe(u8, bytes) catch |err| {
        std.crypto.secureZero(u8, owned);
        allocator.free(owned);
        return err;
    };
    std.crypto.secureZero(u8, owned);
    allocator.free(owned);
    return result;
}

fn trimCarriageReturn(bytes: []const u8) []const u8 {
    return if (bytes.len > 0 and bytes[bytes.len - 1] == '\r') bytes[0 .. bytes.len - 1] else bytes;
}

test "exit errors map to the public CLI contract" {
    try std.testing.expectEqual(common.ExitCode.usage_or_config, mapError(error.InvalidArguments));
    try std.testing.expectEqual(common.ExitCode.conflict_or_not_found, mapError(error.VnrInUse));
    try std.testing.expectEqual(common.ExitCode.daemon_unavailable, mapError(error.DaemonUnavailable));
    try std.testing.expectEqual(common.ExitCode.authentication_or_protocol, mapError(error.InvalidCredentialPrefix));
    try std.testing.expectEqual(common.ExitCode.authentication_or_protocol, mapError(error.InvalidCredentialComponent));
    try std.testing.expectEqual(common.ExitCode.authentication_or_protocol, mapError(error.MasterIdentityMismatch));
    try std.testing.expectEqual(common.ExitCode.internal_failure, mapError(error.OutOfMemory));
}

test "credential input trims only the transport newline" {
    var reader = std.Io.Reader.fixed("ntip-enroll-v1.test\r\n");
    const credential = try readCredentialInput(std.testing.allocator, &reader, 128);
    defer std.testing.allocator.free(credential);
    try std.testing.expectEqualStrings("ntip-enroll-v1.test", credential);
}

test "private output reservation is exclusive, no-follow, and mode 0600" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const existing = try std.fs.path.join(std.testing.allocator, &.{ root, "existing.json" });
    defer std.testing.allocator.free(existing);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "existing.json", .data = "keep" });
    try std.testing.expectError(
        error.PathAlreadyExists,
        reservePrivatePath(std.testing.io, existing, 128),
    );

    try tmp.dir.symLink(std.testing.io, "existing.json", "linked.json", .{});
    const linked = try std.fs.path.join(std.testing.allocator, &.{ root, "linked.json" });
    defer std.testing.allocator.free(linked);
    try std.testing.expectError(
        error.PathAlreadyExists,
        reservePrivatePath(std.testing.io, linked, 128),
    );

    const fresh = try std.fs.path.join(std.testing.allocator, &.{ root, "bootstrap.json" });
    defer std.testing.allocator.free(fresh);
    var reservation = try reservePrivatePath(std.testing.io, fresh, 128);
    defer reservation.deinit();
    const reserved_stat = try std.Io.Dir.cwd().statFile(std.testing.io, fresh, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.file, reserved_stat.kind);
    try std.testing.expectEqual(@as(u32, 0o600), reserved_stat.permissions.toMode() & 0o777);
    try reservation.commit("{\"ok\":true}\n");
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "bootstrap.json", std.testing.allocator, .limited(64));
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("{\"ok\":true}\n", bytes);
    const existing_bytes = try tmp.dir.readFileAlloc(std.testing.io, "existing.json", std.testing.allocator, .limited(16));
    defer std.testing.allocator.free(existing_bytes);
    try std.testing.expectEqualStrings("keep", existing_bytes);
}

test "IPC commands use a bounded canonical namespace" {
    const args = [_][]const u8{ "--runtime-dir", "/tmp/ntip", "node", "enrollment", "reset", "node01" };
    try std.testing.expectEqualStrings("node.enrollment.reset", try canonicalIpcCommand(&args));
}

test "stale Unix socket is unavailable and remains untouched" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/control.sock", .{tmp.sub_path});
    defer std.testing.allocator.free(path);

    const address = try std.Io.net.UnixAddress.init(path);
    var listener = try address.listen(std.testing.io, .{});
    listener.deinit(std.testing.io);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};

    try std.testing.expectEqual(SocketState.socket, try socketState(std.testing.io, path));
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{"status"};
    try std.testing.expect((try tryInvokeIpc(
        std.testing.allocator,
        std.testing.io,
        path,
        &args,
        &out.writer,
        &err.writer,
    )) == null);
    try std.testing.expectEqual(SocketState.socket, try socketState(std.testing.io, path));
}

test "reachable Unix socket is routed through IPC" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/control.sock", .{tmp.sub_path});
    defer std.testing.allocator.free(path);

    const address = try std.Io.net.UnixAddress.init(path);
    var listener = try address.listen(std.testing.io, .{});
    defer {
        listener.deinit(std.testing.io);
        std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    }

    const Responder = struct {
        io: std.Io,
        listener: *std.Io.net.Server,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.respond() catch |err| {
                self.failure = err;
            };
        }

        fn respond(self: *@This()) !void {
            var stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var read_buffer: [4096]u8 = undefined;
            var stream_reader = std.Io.net.Stream.Reader.init(stream, self.io, &read_buffer);
            var request_storage: [runtime_ipc.maximum_message_bytes]u8 = undefined;
            const request_body = try runtime_ipc.readFrame(&stream_reader.interface, &request_storage);

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            const parsed = try runtime_ipc.decodeRequest(arena.allocator(), request_body);
            defer parsed.deinit();
            const response = runtime_ipc.Response{
                .version = runtime_ipc.protocol_version,
                .request_id = parsed.value.request_id,
                .ok = true,
                .exit_code = 0,
                .result = null,
                .@"error" = null,
            };
            const encoded = try runtime_ipc.encodeResponse(arena.allocator(), response);
            var write_buffer: [4096]u8 = undefined;
            var stream_writer = std.Io.net.Stream.Writer.init(stream, self.io, &write_buffer);
            try runtime_ipc.writeFrame(&stream_writer.interface, encoded);
        }
    };
    var responder: Responder = .{ .io = std.testing.io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Responder.run, .{&responder});

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{"status"};
    const result = try tryInvokeIpc(
        std.testing.allocator,
        std.testing.io,
        path,
        &args,
        &out.writer,
        &err.writer,
    );
    thread.join();
    if (responder.failure) |failure| return failure;
    try std.testing.expectEqual(common.ExitCode.success, result.?);
}
