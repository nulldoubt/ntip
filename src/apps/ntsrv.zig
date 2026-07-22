const std = @import("std");
const builtin = @import("builtin");
const ntip = @import("ntip");

const ExitCode = ntip.cli.common.ExitCode;
const Command = ntip.cli.server.Command;

const usage =
    \\NTIP Master
    \\usage: ntsrv [--config PATH] [--state-dir PATH] [--runtime-dir PATH] COMMAND
    \\
    \\commands:
    \\  up [-d] | down | status [--json]
    \\  vnr create NAME CIDR | vnr delete NAME | vnr list [--json] | vnr show NAME [--json]
    \\  node create NAME --vnr VNR --addr IPV4 [--expires DURATION] (--bootstrap-out FILE | --no-bootstrap)
    \\  node delete NAME | node list [--json] | node show NAME [--json]
    \\  node enrollment renew NAME --bootstrap-out FILE
    \\  node enrollment reset NAME --bootstrap-out FILE
    \\  route add CIDR NODE | route delete CIDR | route list [--json] | route show CIDR [--json]
    \\  user bootstrap USERNAME --password-stdin
    \\  backup --output-dir DIR | restore --input FILE
    \\  version
    \\
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const process_args = try init.minimal.args.toSlice(allocator);
    const args = if (process_args.len > 0) process_args[1..] else process_args;
    var stdin_buffer: [2048]u8 = undefined;
    defer std.crypto.secureZero(u8, &stdin_buffer);
    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdin_file = std.Io.File.Reader.init(.stdin(), init.io, &stdin_buffer);
    var stdout_file = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    var stderr_file = std.Io.File.Writer.init(.stderr(), init.io, &stderr_buffer);
    const code = try runWithInput(
        allocator,
        init.io,
        args,
        &stdin_file.interface,
        &stdout_file.interface,
        &stderr_file.interface,
    );
    try stdout_file.interface.flush();
    try stderr_file.interface.flush();
    if (code != .success) std.process.exit(@intFromEnum(code));
}

fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !ExitCode {
    var stdin = std.Io.Reader.fixed("");
    return runWithInput(allocator, io, args, &stdin, stdout, stderr);
}

fn runWithInput(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !ExitCode {
    if (args.len == 0 or (args.len == 1 and isHelp(args[0]))) {
        try stdout.writeAll(usage);
        return .success;
    }
    const parsed = ntip.cli.server.parse(args) catch |err| {
        const code = try ntip.cli.runner.reportError(stderr, "ntsrv", err);
        try stderr.writeAll(usage);
        return code;
    };
    return execute(allocator, io, args, parsed, stdin, stdout, stderr) catch |err|
        ntip.cli.runner.reportError(stderr, "ntsrv", err);
}

fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    parsed: ntip.cli.server.Parsed,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !ExitCode {
    if (parsed.command == .version) {
        try stdout.print("ntsrv {s}\n", .{ntip.version});
        return .success;
    }
    try validateCommand(parsed.command);

    switch (parsed.command) {
        .up => |up| return startRuntime(allocator, io, parsed.paths, up.daemonize, stdout),
        .down, .status => {},
        else => {},
    }

    const ipc_path = try ntip.cli.runner.socketPath(allocator, parsed.paths.runtime_dir, "ntsrv.sock");
    defer allocator.free(ipc_path);
    // A stale socket is only a hint that a daemon once existed. Connect first;
    // if that fails, the state lock below is the final authority before any
    // offline access or mutation.
    const ipc_result = try ntip.cli.runner.tryInvokeIpc(allocator, io, ipc_path, args, stdout, stderr);
    if (ipc_result) |code| return code;
    if (parsed.command == .down) return error.DaemonUnavailable;

    var state_dir = try ntip.cli.runner.openPrivateDirectory(io, parsed.paths.state_dir);
    defer state_dir.close(io);
    var lifetime_lock = try ntip.state.atomic_file.LifetimeLock.acquire(state_dir, io, "state.lock", true);
    defer lifetime_lock.release(io);

    if (parsed.command == .restore) {
        try restoreDatabase(allocator, io, state_dir, parsed.paths.state_dir, parsed.command.restore.input, stdout);
        return .success;
    }

    var sqlite_owner = try ntip.state.sqlite_repository.Repository.open(allocator, io, state_dir);
    defer sqlite_owner.deinit();
    if (parsed.command == .user_bootstrap) {
        try bootstrapUser(
            allocator,
            io,
            &sqlite_owner.db,
            parsed.command.user_bootstrap.username,
            stdin,
            stdout,
        );
        return .success;
    }
    var repository = ntip.state.management_repository.Repository.init(&sqlite_owner.db);
    var store = try repository.loadInventory(allocator);
    defer store.deinit();
    const settings_state = try (ntip.state.settings_repository.Repository.init(&sqlite_owner.db)).loadState();
    const settings = settings_state.effective.values;
    try settings.validate(store.nodes.items.len);
    var identity = try ntip.state.identity.loadOrCreate(allocator, io, state_dir);
    defer std.crypto.secureZero(u8, &identity.secret);
    var enrollment_bootstrap = try ntip.management.bootstrap_service.Service.init(
        &repository,
        io,
        &identity.secret,
        identity.public,
    );
    defer enrollment_bootstrap.deinit();
    var application = try ntip.management.server_application.Application.init(
        allocator,
        io,
        repository,
        &store,
        identity.public,
        settings,
        ntip.version,
    );
    application.setBootstrapService(&enrollment_bootstrap);
    application.service_state = "stopped";
    try application.execute(parsed.command, stdout, stderr);
    return .success;
}

fn bootstrapUser(
    allocator: std.mem.Allocator,
    io: std.Io,
    db: *ntip.state.sqlite.Database,
    username_text: []const u8,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
) !void {
    try requireRoot();
    const username = try ntip.management.auth.Username.parse(username_text);
    const password = try readPasswordInput(allocator, stdin);
    defer {
        std.crypto.secureZero(u8, password);
        allocator.free(password);
    }
    var password_hash = try ntip.management.auth.PasswordHash.create(allocator, io, password);
    defer std.crypto.secureZero(u8, &password_hash.bytes);
    const now = try wallSeconds(io);
    const repository = ntip.state.access_repository.Repository.init(db);
    _ = try repository.bootstrapFirstSuperuser(.{
        .id = randomUuid(io),
        .username = username.slice(),
        .role = .superuser,
        .password_phc = password_hash.slice(),
        .password_change_required = false,
        .now = now,
    }, .{
        .id = randomUuid(io),
        .occurred_at = now,
        .actor_kind = .local_cli,
        .action = "user.bootstrap",
        .resource_type = "user",
        .resource_id = username.slice(),
        .details_json = "{}",
    });
    try stdout.print("Bootstrapped superuser \"{s}\"\n", .{username.slice()});
}

fn restoreDatabase(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_dir: std.Io.Dir,
    state_path: []const u8,
    input_path: []const u8,
    stdout: *std.Io.Writer,
) !void {
    const source_basename = std.fs.path.basename(input_path);
    if (source_basename.len == 0 or std.mem.eql(u8, source_basename, ".") or
        std.mem.eql(u8, source_basename, "..")) return error.InvalidPath;
    const source_path = std.fs.path.dirname(input_path) orelse ".";
    var source_dir = if (std.fs.path.isAbsolute(source_path))
        try std.Io.Dir.openDirAbsolute(io, source_path, .{ .follow_symlinks = false })
    else
        try std.Io.Dir.cwd().openDir(io, source_path, .{ .follow_symlinks = false });
    defer source_dir.close(io);

    const now = try wallSeconds(io);
    var entropy: [8]u8 = undefined;
    io.random(&entropy);
    var suffix: [entropy.len * 2]u8 = undefined;
    encodeLowerHex(&entropy, &suffix);
    const recovery_name = try std.fmt.allocPrint(
        allocator,
        "ntip-pre-restore-{d}-{s}.sqlite3",
        .{ now, suffix },
    );
    defer allocator.free(recovery_name);

    const result = try ntip.state.sqlite_maintenance.restoreStopped(
        allocator,
        io,
        state_dir,
        source_dir,
        source_basename,
        recovery_name,
        .{
            .id = randomUuid(io),
            .bootstrap_revoke_id = randomUuid(io),
            .occurred_at = now,
        },
    );
    try stdout.print(
        "Database restored; revoked {d} web session(s) and {d} setup invitation(s)\nRecoverable copy: {s}/{s}\n",
        .{ result.revoked_sessions, result.revoked_bootstraps, state_path, recovery_name },
    );
}

fn readPasswordInput(allocator: std.mem.Allocator, stdin: *std.Io.Reader) ![]u8 {
    const line = (try stdin.takeDelimiter('\n')) orelse return error.EmptyPassword;
    if (line.len > ntip.management.auth.password_max_bytes + 1) return error.PasswordTooLong;
    const trimmed = if (line.len > 0 and line[line.len - 1] == '\r') line[0 .. line.len - 1] else line;
    try ntip.management.auth.validatePassword(trimmed);
    return allocator.dupe(u8, trimmed);
}

fn requireRoot() !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    if (std.os.linux.geteuid() != 0) return error.RootRequired;
}

fn wallSeconds(io: std.Io) !i64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.ClockBeforeUnixEpoch;
    return seconds;
}

fn randomUuid(io: std.Io) [16]u8 {
    var id: [16]u8 = undefined;
    io.random(&id);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    return id;
}

fn encodeLowerHex(bytes: []const u8, output: []u8) void {
    std.debug.assert(output.len == bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
}

fn startRuntime(
    _: std.mem.Allocator,
    io: std.Io,
    paths: ntip.cli.common.Paths,
    daemonize: bool,
    stdout: *std.Io.Writer,
) !ExitCode {
    const service_paths: ntip.runtime.service.Paths = .{
        .config = paths.config,
        .state_dir = paths.state_dir,
        .runtime_dir = paths.runtime_dir,
    };
    if (!daemonize) {
        try runMasterProcess(io, service_paths, null);
        return .success;
    }
    switch (try ntip.platform.linux.lifecycle.forkForDaemon()) {
        .parent => |parent| {
            ntip.platform.linux.lifecycle.waitForReadiness(parent.readiness_fd) catch |err| {
                ntip.platform.linux.lifecycle.terminateFailedChild(parent.child_pid);
                return err;
            };
            try stdout.print("ntsrv started (pid {d})\n", .{parent.child_pid});
            return .success;
        },
        .child => |child| {
            try runMasterProcess(io, service_paths, child.readiness_fd);
            return .success;
        },
    }
}

/// `runMaster` has already unwound its sockets, worker thread, TUN device,
/// database, and lifetime lock before this function observes a managed-restart
/// signal. Exiting with the dedicated status then lets systemd restart the
/// fully stopped service without turning normal shutdown into a failure.
fn runMasterProcess(
    io: std.Io,
    paths: ntip.runtime.service.Paths,
    readiness_fd: ?i32,
) !void {
    const status = try runtimeTerminationStatus(ntip.runtime.service.runMaster(
        std.heap.smp_allocator,
        io,
        paths,
        readiness_fd,
    ));
    if (status) |value| std.process.exit(value);
}

fn runtimeTerminationStatus(result: anyerror!void) anyerror!?u8 {
    result catch |err| {
        if (err == error.ManagedRestartRequested) {
            return ntip.management.operations_service.restart_exit_status;
        }
        return err;
    };
    return null;
}

fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h");
}

fn validateCommand(command: Command) !void {
    switch (command) {
        .vnr_create => |create| {
            _ = try ntip.domain.model.Name.parse(create.name);
            const range = try ntip.domain.ipv4.Cidr.parse(create.cidr);
            try range.validateVnr();
        },
        .vnr_delete => |name| _ = try ntip.domain.model.Name.parse(name),
        .vnr_show => |show| _ = try ntip.domain.model.Name.parse(show.name),
        .node_create => |create| {
            _ = try ntip.domain.model.Name.parse(create.name);
            _ = try ntip.domain.model.Name.parse(create.vnr);
            _ = try ntip.domain.ipv4.Ipv4.parse(create.address);
        },
        .node_delete => |name| _ = try ntip.domain.model.Name.parse(name),
        .node_show => |show| _ = try ntip.domain.model.Name.parse(show.name),
        .node_enrollment_renew, .node_enrollment_reset => |request| {
            _ = try ntip.domain.model.Name.parse(request.name);
            if (request.bootstrap_out.len == 0) return error.InvalidPath;
        },
        .route_add => |add| {
            const prefix = try ntip.domain.ipv4.Cidr.parse(add.cidr);
            try prefix.validateRouted();
            _ = try ntip.domain.model.Name.parse(add.node);
        },
        .route_delete => |text| {
            const prefix = try ntip.domain.ipv4.Cidr.parse(text);
            try prefix.validateRouted();
        },
        .route_show => |show| {
            const prefix = try ntip.domain.ipv4.Cidr.parse(show.cidr);
            try prefix.validateRouted();
        },
        .user_bootstrap => |bootstrap| {
            _ = try ntip.management.auth.Username.parse(bootstrap.username);
            if (!bootstrap.password_stdin) return error.InvalidArguments;
        },
        .backup => |backup| if (backup.output_dir.len == 0) return error.InvalidPath,
        .restore => |restore| if (restore.input.len == 0) return error.InvalidPath,
        .up, .down, .status, .vnr_list, .node_list, .route_list, .version => {},
    }
}

test "offline VNR mutation is durable and SQLite-readable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const create_args = [_][]const u8{ "--state-dir", state_path, "--runtime-dir", runtime_path, "vnr", "create", "vnr0", "10.1.0.0/24" };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &create_args, &out.writer, &err.writer));

    var json_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer json_out.deinit();
    const list_args = [_][]const u8{ "--state-dir", state_path, "--runtime-dir", runtime_path, "vnr", "list", "--json" };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &list_args, &json_out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, json_out.written(), "\"name\":\"vnr0\"") != null);
}

test "offline Master rejects legacy JSON without modifying it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);
    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    const legacy_bytes = "{\"schema_version\":1,\"generation\":0,\"vnrs\":[],\"nodes\":[],\"routes\":[]}";
    var legacy = try state_dir.createFile(std.testing.io, "state.json", .{
        .permissions = .fromMode(0o600),
    });
    try legacy.writeStreamingAll(std.testing.io, legacy_bytes);
    legacy.close(std.testing.io);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{ "--state-dir", state_path, "--runtime-dir", runtime_path, "status", "--json" };
    try std.testing.expectEqual(
        ExitCode.usage_or_config,
        try run(std.testing.allocator, std.testing.io, &args, &out.writer, &err.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "LegacyMasterStateUnsupported") != null);
    const after = try state_dir.readFileAlloc(
        std.testing.io,
        "state.json",
        std.testing.allocator,
        .limited(1024),
    );
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualStrings(legacy_bytes, after);
    try std.testing.expectError(
        error.FileNotFound,
        state_dir.statFile(std.testing.io, "ntip.sqlite3", .{ .follow_symlinks = false }),
    );
}

test "offline bootstrap output preflight failure leaves node and enrollment state unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ root, "missing", "node01.enroll" });
    defer std.testing.allocator.free(credential_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);

    var setup_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_out.deinit();
    var setup_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_err.deinit();
    const vnr_args = [_][]const u8{ "--state-dir", state_path, "--runtime-dir", runtime_path, "vnr", "create", "vnr0", "10.1.0.0/24" };
    try std.testing.expectEqual(
        ExitCode.success,
        try run(std.testing.allocator, std.testing.io, &vnr_args, &setup_out.writer, &setup_err.writer),
    );

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const create_args = [_][]const u8{
        "--state-dir",
        state_path,
        "--runtime-dir",
        runtime_path,
        "node",
        "create",
        "node01",
        "--vnr",
        "vnr0",
        "--addr",
        "10.1.0.2",
        "--bootstrap-out",
        credential_path,
    };
    try std.testing.expectEqual(
        ExitCode.internal_failure,
        try run(std.testing.allocator, std.testing.io, &create_args, &out.writer, &err.writer),
    );
    try std.testing.expectEqualStrings("", out.written());
    try std.testing.expect(std.mem.indexOf(u8, out.written(), ntip.protocol.credential.prefix) == null);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, credential_path, .{ .follow_symlinks = false }),
    );

    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    var sqlite_owner = try ntip.state.sqlite_repository.Repository.open(
        std.testing.allocator,
        std.testing.io,
        state_dir,
    );
    defer sqlite_owner.deinit();
    const repository = ntip.state.management_repository.Repository.init(&sqlite_owner.db);
    var store = try repository.loadInventory(std.testing.allocator);
    defer store.deinit();
    try std.testing.expectEqual(@as(u64, 1), store.generation);
    try std.testing.expect(store.findVnr("vnr0") != null);
    try std.testing.expect(store.findNode("node01") == null);
    var enrollment_count = try sqlite_owner.db.prepare("SELECT count(*) FROM enrollment_credentials;");
    defer enrollment_count.deinit();
    try std.testing.expectEqual(ntip.state.sqlite.Step.row, try enrollment_count.step());
    try std.testing.expectEqual(@as(i64, 0), enrollment_count.columnInt64(0));
    try std.testing.expectEqual(ntip.state.sqlite.Step.done, try enrollment_count.step());
}

test "offline bootstrap output success is private and contains no internal credential" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const bootstrap_path = try std.fs.path.join(std.testing.allocator, &.{ state_path, "node01-bootstrap.json" });
    defer std.testing.allocator.free(bootstrap_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);

    var setup_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_out.deinit();
    var setup_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_err.deinit();
    const vnr_args = [_][]const u8{ "--state-dir", state_path, "--runtime-dir", runtime_path, "vnr", "create", "vnr0", "10.1.0.0/24" };
    try std.testing.expectEqual(
        ExitCode.success,
        try run(std.testing.allocator, std.testing.io, &vnr_args, &setup_out.writer, &setup_err.writer),
    );

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const create_args = [_][]const u8{
        "--state-dir",
        state_path,
        "--runtime-dir",
        runtime_path,
        "node",
        "create",
        "node01",
        "--vnr",
        "vnr0",
        "--addr",
        "10.1.0.2",
        "--bootstrap-out",
        bootstrap_path,
    };
    try std.testing.expectEqual(
        ExitCode.success,
        try run(std.testing.allocator, std.testing.io, &create_args, &out.writer, &err.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "Created node \"node01\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), bootstrap_path) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), ntip.protocol.credential.prefix) == null);

    const stat = try std.Io.Dir.cwd().statFile(std.testing.io, bootstrap_path, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.file, stat.kind);
    try std.testing.expectEqual(@as(u32, 0o600), stat.permissions.toMode() & 0o777);
    const bootstrap_bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        bootstrap_path,
        std.testing.allocator,
        .limited(256),
    );
    defer {
        std.crypto.secureZero(u8, bootstrap_bytes);
        std.testing.allocator.free(bootstrap_bytes);
    }
    try std.testing.expectEqual(@as(u8, '\n'), bootstrap_bytes[bootstrap_bytes.len - 1]);
    try std.testing.expect(std.mem.indexOf(u8, bootstrap_bytes, ntip.protocol.credential.prefix) == null);
    const Disclosure = struct {
        bootstrapId: []const u8,
        secretCode: []const u8,
        expiresAt: []const u8,
    };
    const parsed = try std.json.parseFromSlice(Disclosure, std.testing.allocator, bootstrap_bytes, .{
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, ntip.management.bootstrap_service.locator_len), parsed.value.bootstrapId.len);
    try std.testing.expectEqual(@as(usize, ntip.management.bootstrap_service.code_text_len), parsed.value.secretCode.len);
    try std.testing.expectEqual(@as(usize, ntip.management.api_response.timestamp_text_len), parsed.value.expiresAt.len);

    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    var sqlite_owner = try ntip.state.sqlite_repository.Repository.open(
        std.testing.allocator,
        std.testing.io,
        state_dir,
    );
    defer sqlite_owner.deinit();
    const repository = ntip.state.management_repository.Repository.init(&sqlite_owner.db);
    var store = try repository.loadInventory(std.testing.allocator);
    defer store.deinit();
    const node = store.findNode("node01") orelse return error.TestExpectedEqual;
    var enrollment = try sqlite_owner.db.prepare(
        "SELECT node_id, derived_psk FROM enrollment_credentials WHERE status = 'unused';",
    );
    defer enrollment.deinit();
    try std.testing.expectEqual(ntip.state.sqlite.Step.row, try enrollment.step());
    try std.testing.expectEqualSlices(u8, &node.id.bytes, enrollment.columnBlob(0).?);
    try std.testing.expectEqual(@as(usize, 32), enrollment.columnBlob(1).?.len);
    try std.testing.expectEqual(ntip.state.sqlite.Step.done, try enrollment.step());
    var invitations = try sqlite_owner.db.prepare(
        "SELECT count(*) FROM enrollment_bootstraps WHERE locator=?1 AND status='active';",
    );
    defer invitations.deinit();
    try invitations.bindText(1, parsed.value.bootstrapId);
    try std.testing.expectEqual(ntip.state.sqlite.Step.row, try invitations.step());
    try std.testing.expectEqual(@as(i64, 1), invitations.columnInt64(0));
}

test "down without a daemon fails explicitly with exit code four" {
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{ "--runtime-dir", "/definitely/not/an/ntip/runtime", "down" };
    try std.testing.expectEqual(ExitCode.daemon_unavailable, try run(std.testing.allocator, std.testing.io, &args, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "daemon unavailable") != null);
}

test "offline status reports stopped using the stable JSON schema" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{ "--state-dir", state_path, "--runtime-dir", runtime_path, "status", "--json" };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &args, &out.writer, &err.writer));
    try std.testing.expectEqualStrings("{\"schema_version\":1,\"state\":\"stopped\",\"generation\":0,\"nodes\":0}\n", out.written());
}

test "stale IPC socket falls back to locked offline mutation without removing it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);
    _ = try std.Io.Dir.cwd().createDirPathStatus(std.testing.io, runtime_path, .default_dir);
    const socket_path = try std.fs.path.join(std.testing.allocator, &.{ runtime_path, "ntsrv.sock" });
    defer std.testing.allocator.free(socket_path);
    const address = try std.Io.net.UnixAddress.init(socket_path);
    var listener = try address.listen(std.testing.io, .{});
    listener.deinit(std.testing.io);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, socket_path) catch {};

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{
        "--state-dir", state_path, "--runtime-dir", runtime_path, "vnr", "create", "vnr0", "10.1.0.0/24",
    };
    try std.testing.expectEqual(ExitCode.success, try run(
        std.testing.allocator,
        std.testing.io,
        &args,
        &out.writer,
        &err.writer,
    ));
    try std.testing.expectEqual(
        ntip.cli.runner.SocketState.socket,
        try ntip.cli.runner.socketState(std.testing.io, socket_path),
    );
}

test "stale IPC fallback cannot bypass a live daemon lifetime lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);
    _ = try std.Io.Dir.cwd().createDirPathStatus(std.testing.io, runtime_path, .default_dir);
    const socket_path = try std.fs.path.join(std.testing.allocator, &.{ runtime_path, "ntsrv.sock" });
    defer std.testing.allocator.free(socket_path);
    const address = try std.Io.net.UnixAddress.init(socket_path);
    var listener = try address.listen(std.testing.io, .{});
    listener.deinit(std.testing.io);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, socket_path) catch {};

    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    var daemon_lock = try ntip.state.atomic_file.LifetimeLock.acquire(state_dir, std.testing.io, "state.lock", true);
    defer daemon_lock.release(std.testing.io);

    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{
        "--state-dir", state_path, "--runtime-dir", runtime_path, "vnr", "create", "vnr0", "10.1.0.0/24",
    };
    try std.testing.expectEqual(ExitCode.daemon_unavailable, try run(
        std.testing.allocator,
        std.testing.io,
        &args,
        &out.writer,
        &err.writer,
    ));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "daemon unavailable") != null);
    try std.testing.expectEqual(
        ntip.cli.runner.SocketState.socket,
        try ntip.cli.runner.socketState(std.testing.io, socket_path),
    );
}

test "managed restart signal maps to the dedicated systemd exit status" {
    const success: anyerror!void = {};
    try std.testing.expectEqual(@as(?u8, null), try runtimeTerminationStatus(success));
    try std.testing.expectEqual(
        @as(?u8, ntip.management.operations_service.restart_exit_status),
        try runtimeTerminationStatus(error.ManagedRestartRequested),
    );
    try std.testing.expectError(
        error.DataWorkerFailed,
        runtimeTerminationStatus(error.DataWorkerFailed),
    );
}
