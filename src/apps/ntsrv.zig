const std = @import("std");
const ntip = @import("ntip");

const ExitCode = ntip.cli.common.ExitCode;
const Command = ntip.cli.server.Command;
const Credential = ntip.protocol.credential.Credential;

const usage =
    \\NTIP Master
    \\usage: ntsrv [--config PATH] [--state-dir PATH] [--runtime-dir PATH] COMMAND
    \\
    \\commands:
    \\  up [-d] | down | status [--json]
    \\  vnr create NAME CIDR | vnr delete NAME | vnr list [--json] | vnr show NAME [--json]
    \\  node create NAME --vnr VNR --addr IPV4 [--expires DURATION] [--credential-out FILE]
    \\  node delete NAME | node list [--json] | node show NAME [--json]
    \\  node enrollment renew NAME | node enrollment reset NAME
    \\  route add CIDR NODE | route delete CIDR | route list [--json] | route show CIDR [--json]
    \\  version
    \\
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const process_args = try init.minimal.args.toSlice(allocator);
    const args = if (process_args.len > 0) process_args[1..] else process_args;
    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdout_file = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    var stderr_file = std.Io.File.Writer.init(.stderr(), init.io, &stderr_buffer);
    const code = try run(allocator, init.io, args, &stdout_file.interface, &stderr_file.interface);
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
    if (args.len == 0 or (args.len == 1 and isHelp(args[0]))) {
        try stdout.writeAll(usage);
        return .success;
    }
    const parsed = ntip.cli.server.parse(args) catch |err| {
        const code = try ntip.cli.runner.reportError(stderr, "ntsrv", err);
        try stderr.writeAll(usage);
        return code;
    };
    return execute(allocator, io, args, parsed, stdout, stderr) catch |err|
        ntip.cli.runner.reportError(stderr, "ntsrv", err);
}

fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    parsed: ntip.cli.server.Parsed,
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
    const repository = ntip.state.repository.Repository{ .dir = state_dir };
    var transaction = try repository.begin(allocator, io, true);
    defer transaction.deinit();

    switch (parsed.command) {
        .vnr_list => |format| try ntip.cli.view.writeVnrList(stdout, &transaction.store, format),
        .vnr_show => |show| try ntip.cli.view.writeVnrShow(stdout, &transaction.store, show.name, show.output),
        .node_list => |format| try ntip.cli.view.writeNodeList(stdout, &transaction.store, format),
        .node_show => |show| try ntip.cli.view.writeNodeShow(stdout, &transaction.store, show.name, show.output),
        .route_list => |format| try ntip.cli.view.writeRouteList(stdout, &transaction.store, format),
        .status => |format| try ntip.cli.view.writeServerStatus(stdout, &transaction.store, "stopped", format),
        .route_show => |show| {
            const prefix = ntip.domain.ipv4.Cidr.parse(show.cidr) catch return error.InvalidCidr;
            try ntip.cli.view.writeRouteShow(stdout, &transaction.store, prefix, show.output);
        },
        .vnr_create => |create| {
            const outcome = try ntip.cli.dispatch.applyServerMutation(&transaction.store, io, parsed.command);
            try transaction.commit();
            const vnr = transaction.store.findVnr(create.name).?;
            var range_buffer: [18]u8 = undefined;
            var master_buffer: [15]u8 = undefined;
            try stdout.print("Created VNR \"{s}\"\n\nRange:          {s}\nMaster address: {s}\n", .{
                create.name,
                try vnr.range.write(&range_buffer),
                try vnr.masterAddress().write(&master_buffer),
            });
            if (outcome.vnr_created.public_range_warning) {
                try stderr.writeAll("warning: this VNR is not wholly within RFC 1918 private address space\n");
            }
        },
        .vnr_delete => |name| {
            _ = try ntip.cli.dispatch.applyServerMutation(&transaction.store, io, parsed.command);
            try transaction.commit();
            try stdout.print("Deleted VNR \"{s}\"\n", .{name});
        },
        .route_add => |add| {
            _ = try ntip.cli.dispatch.applyServerMutation(&transaction.store, io, parsed.command);
            try transaction.commit();
            try stdout.print("Added route {s} via {s}\n", .{ add.cidr, add.node });
        },
        .route_delete => |prefix| {
            _ = try ntip.cli.dispatch.applyServerMutation(&transaction.store, io, parsed.command);
            try transaction.commit();
            try stdout.print("Deleted route {s}\n", .{prefix});
        },
        .node_create => |create| {
            const defaults = try configuredAdministrativeDefaults(allocator, io, parsed.paths.config);
            if (transaction.store.nodes.items.len >= defaults.maximum_nodes) return error.MaximumNodesExceeded;
            try createNode(
                allocator,
                io,
                state_dir,
                &transaction,
                parsed.command,
                create,
                create.expires_seconds orelse defaults.enrollment_lifetime_seconds,
                stdout,
            );
        },
        .node_delete => |name| try deleteNode(allocator, io, state_dir, &transaction, parsed.command, name, stdout),
        .node_enrollment_renew => |name| {
            const defaults = try configuredAdministrativeDefaults(allocator, io, parsed.paths.config);
            try renewEnrollment(allocator, io, state_dir, &transaction, name, false, defaults.enrollment_lifetime_seconds, stdout);
        },
        .node_enrollment_reset => |name| {
            const defaults = try configuredAdministrativeDefaults(allocator, io, parsed.paths.config);
            try renewEnrollment(allocator, io, state_dir, &transaction, name, true, defaults.enrollment_lifetime_seconds, stdout);
        },
        .up, .down, .version => unreachable,
    }
    return .success;
}

const AdministrativeDefaults = struct {
    maximum_nodes: u32,
    enrollment_lifetime_seconds: u64,
};

fn configuredAdministrativeDefaults(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !AdministrativeDefaults {
    const bytes = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(ntip.state.config.max_config_bytes),
    ) catch |err| switch (err) {
        error.FileNotFound => return .{ .maximum_nodes = 4096, .enrollment_lifetime_seconds = 24 * 60 * 60 },
        else => return err,
    };
    defer allocator.free(bytes);
    const parsed = try ntip.state.config.decodeServer(allocator, bytes);
    defer parsed.deinit();
    return .{
        .maximum_nodes = parsed.value.maximum_nodes,
        .enrollment_lifetime_seconds = parsed.value.default_enrollment_lifetime_seconds,
    };
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
        try ntip.runtime.service.runMaster(std.heap.smp_allocator, io, service_paths, null);
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
            try ntip.runtime.service.runMaster(std.heap.smp_allocator, io, service_paths, child.readiness_fd);
            return .success;
        },
    }
}

fn createNode(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_dir: std.Io.Dir,
    transaction: *ntip.state.repository.Transaction,
    command: Command,
    create: ntip.cli.server.NodeCreate,
    lifetime_seconds: u64,
    stdout: *std.Io.Writer,
) !void {
    _ = try ntip.cli.dispatch.applyServerMutation(&transaction.store, io, command);
    const node = transaction.store.findNode(create.name).?;
    var identity = try ensureServerIdentity(allocator, io, state_dir);
    defer std.crypto.secureZero(u8, &identity.secret);
    var enrollments = try (ntip.state.enrollments.File{ .dir = state_dir }).loadOrEmpty(allocator, io);
    defer enrollments.deinit();
    var credential = try issueCredential(io, &enrollments, create.name, node.id, identity.public, lifetime_seconds);
    defer std.crypto.secureZero(u8, &credential.secret);

    // An explicitly requested credential file must be delivered before the
    // durable node and enrollment mutation is published. A failed write then
    // leaves both state files unchanged and emits no credential on stdout. A
    // later commit failure leaves either an unused credential or a recoverable
    // transaction intent that is still paired with the delivered credential.
    if (create.credential_out) |path| try writeCredentialFile(io, credential, path);
    try ntip.state.server_transaction.commit(allocator, io, state_dir, &transaction.store, &enrollments);

    var address_buffer: [15]u8 = undefined;
    try stdout.print("Created node \"{s}\"\n\nVNR:      {s}\nAddress:  {s}\nState:    unenrolled\n", .{
        create.name,
        create.vnr,
        try node.address.write(&address_buffer),
    });
    try reportCredential(credential, create.credential_out, stdout);
}

fn deleteNode(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_dir: std.Io.Dir,
    transaction: *ntip.state.repository.Transaction,
    command: Command,
    name: []const u8,
    stdout: *std.Io.Writer,
) !void {
    _ = try ntip.cli.dispatch.applyServerMutation(&transaction.store, io, command);
    var enrollments = try (ntip.state.enrollments.File{ .dir = state_dir }).loadOrEmpty(allocator, io);
    defer enrollments.deinit();
    const before = enrollments.generation;
    enrollments.revokeNode(name) catch |err| switch (err) {
        error.EnrollmentNotFound => {},
        else => return err,
    };
    _ = before;
    try ntip.state.server_transaction.commit(allocator, io, state_dir, &transaction.store, &enrollments);
    try stdout.print("Deleted node \"{s}\"\n", .{name});
}

fn renewEnrollment(
    allocator: std.mem.Allocator,
    io: std.Io,
    state_dir: std.Io.Dir,
    transaction: *ntip.state.repository.Transaction,
    name: []const u8,
    reset: bool,
    lifetime_seconds: u64,
    stdout: *std.Io.Writer,
) !void {
    const node = transaction.store.findNode(name) orelse return error.NodeNotFound;
    if (!reset and node.enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;
    if (reset) try transaction.store.resetNodeEnrollment(name);
    var identity = try ensureServerIdentity(allocator, io, state_dir);
    defer std.crypto.secureZero(u8, &identity.secret);
    var enrollments = try (ntip.state.enrollments.File{ .dir = state_dir }).loadOrEmpty(allocator, io);
    defer enrollments.deinit();
    var credential = try issueCredential(io, &enrollments, name, node.id, identity.public, lifetime_seconds);
    defer std.crypto.secureZero(u8, &credential.secret);
    if (reset) {
        try ntip.state.server_transaction.commit(allocator, io, state_dir, &transaction.store, &enrollments);
    } else {
        try (ntip.state.enrollments.File{ .dir = state_dir }).save(allocator, io, &enrollments);
    }
    try stdout.print("Enrollment {s} for node \"{s}\"\n", .{ if (reset) "reset" else "renewed", name });
    try emitCredential(io, credential, null, stdout);
}

fn ensureServerIdentity(allocator: std.mem.Allocator, io: std.Io, state_dir: std.Io.Dir) !ntip.protocol.noise.KeyPair {
    const secrets = ntip.state.secret_store.FileSecretStore{ .dir = state_dir };
    const loaded = secrets.load(allocator, io, "identity.key", .identity_key) catch |err| switch (err) {
        error.FileNotFound => {
            while (true) {
                var secret: [32]u8 = undefined;
                io.random(&secret);
                const identity = ntip.protocol.noise.KeyPair.fromSecret(secret) catch continue;
                try secrets.write(allocator, io, "identity.key", .identity_key, &secret);
                std.crypto.secureZero(u8, &secret);
                return identity;
            }
        },
        else => return err,
    };
    defer {
        std.crypto.secureZero(u8, loaded);
        allocator.free(loaded);
    }
    if (loaded.len != 32) return error.InvalidSecretLength;
    return ntip.protocol.noise.KeyPair.fromSecret(loaded[0..32].*);
}

fn issueCredential(
    io: std.Io,
    enrollments: *ntip.state.enrollments.Registry,
    node: []const u8,
    node_id: ntip.domain.model.NodeId,
    master_public: [32]u8,
    lifetime_seconds: u64,
) !Credential {
    const now = try ntip.cli.runner.unixSeconds(io);
    const expires_at = std.math.add(u64, now, lifetime_seconds) catch return error.InvalidExpiry;
    while (true) {
        var credential = Credential{ .handle = undefined, .secret = undefined, .master_public = master_public };
        io.random(&credential.handle);
        io.random(&credential.secret);
        var psk = credential.derivePsk();
        defer std.crypto.secureZero(u8, &psk);
        enrollments.issueWithHandle(node, node_id, credential.handle, psk, now, expires_at) catch |err| switch (err) {
            error.EnrollmentHandleInUse => continue,
            else => return err,
        };
        return credential;
    }
}

fn emitCredential(io: std.Io, credential: Credential, output_path: ?[]const u8, stdout: *std.Io.Writer) !void {
    if (output_path) |path| try writeCredentialFile(io, credential, path);
    try reportCredential(credential, output_path, stdout);
}

fn writeCredentialFile(io: std.Io, credential: Credential, path: []const u8) !void {
    var text_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    const text = credential.encode(&text_buffer);
    defer std.crypto.secureZero(u8, &text_buffer);
    var with_newline: [ntip.protocol.credential.text_len + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &with_newline);
    @memcpy(with_newline[0..text.len], text);
    with_newline[text.len] = '\n';
    try ntip.cli.runner.writePrivatePath(io, path, &with_newline);
}

fn reportCredential(credential: Credential, output_path: ?[]const u8, stdout: *std.Io.Writer) !void {
    if (output_path) |path| {
        try stdout.print("\nEnrollment credential written to {s}\n", .{path});
    } else {
        var text_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
        const text = credential.encode(&text_buffer);
        defer std.crypto.secureZero(u8, &text_buffer);
        try stdout.print("\nEnrollment credential (single use):\n{s}\n", .{text});
    }
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
        .node_enrollment_renew, .node_enrollment_reset => |name| _ = try ntip.domain.model.Name.parse(name),
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
        .up, .down, .status, .vnr_list, .node_list, .route_list, .version => {},
    }
}

test "offline VNR mutation is durable and JSON-readable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const state_path = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}/server", .{tmp.sub_path});
    defer std.testing.allocator.free(state_path);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const create_args = [_][]const u8{ "--state-dir", state_path, "vnr", "create", "vnr0", "10.1.0.0/24" };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &create_args, &out.writer, &err.writer));

    var json_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer json_out.deinit();
    const list_args = [_][]const u8{ "--state-dir", state_path, "vnr", "list", "--json" };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &list_args, &json_out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, json_out.written(), "\"name\":\"vnr0\"") != null);
}

test "offline credential output failure leaves node and enrollment state unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ root, "missing", "node01.enroll" });
    defer std.testing.allocator.free(credential_path);

    var setup_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_out.deinit();
    var setup_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_err.deinit();
    const vnr_args = [_][]const u8{ "--state-dir", state_path, "vnr", "create", "vnr0", "10.1.0.0/24" };
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
        "node",
        "create",
        "node01",
        "--vnr",
        "vnr0",
        "--addr",
        "10.1.0.2",
        "--credential-out",
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
    var store = try (ntip.state.repository.Repository{ .dir = state_dir }).load(std.testing.allocator, std.testing.io);
    defer store.deinit();
    var enrollments = try (ntip.state.enrollments.File{ .dir = state_dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
    defer enrollments.deinit();
    try std.testing.expectEqual(@as(u64, 1), store.generation);
    try std.testing.expect(store.findVnr("vnr0") != null);
    try std.testing.expect(store.findNode("node01") == null);
    try std.testing.expectEqual(@as(u64, 0), enrollments.generation);
    try std.testing.expectEqual(@as(usize, 0), enrollments.records.items.len);
}

test "offline credential output success is private and matches durable enrollment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "server" });
    defer std.testing.allocator.free(state_path);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ state_path, "node01.enroll" });
    defer std.testing.allocator.free(credential_path);

    var setup_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_out.deinit();
    var setup_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer setup_err.deinit();
    const vnr_args = [_][]const u8{ "--state-dir", state_path, "vnr", "create", "vnr0", "10.1.0.0/24" };
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
        "node",
        "create",
        "node01",
        "--vnr",
        "vnr0",
        "--addr",
        "10.1.0.2",
        "--credential-out",
        credential_path,
    };
    try std.testing.expectEqual(
        ExitCode.success,
        try run(std.testing.allocator, std.testing.io, &create_args, &out.writer, &err.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, out.written(), "Created node \"node01\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), credential_path) != null);
    try std.testing.expect(std.mem.indexOf(u8, out.written(), ntip.protocol.credential.prefix) == null);

    const stat = try std.Io.Dir.cwd().statFile(std.testing.io, credential_path, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.file, stat.kind);
    try std.testing.expectEqual(@as(u32, 0o600), stat.permissions.toMode() & 0o777);
    const credential_bytes = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        credential_path,
        std.testing.allocator,
        .limited(ntip.protocol.credential.text_len + 2),
    );
    defer {
        std.crypto.secureZero(u8, credential_bytes);
        std.testing.allocator.free(credential_bytes);
    }
    try std.testing.expectEqual(@as(usize, ntip.protocol.credential.text_len + 1), credential_bytes.len);
    try std.testing.expectEqual(@as(u8, '\n'), credential_bytes[credential_bytes.len - 1]);
    var credential = try Credential.decode(credential_bytes[0..ntip.protocol.credential.text_len]);
    defer credential.deinit();
    var derived_psk = credential.derivePsk();
    defer std.crypto.secureZero(u8, &derived_psk);

    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    var store = try (ntip.state.repository.Repository{ .dir = state_dir }).load(std.testing.allocator, std.testing.io);
    defer store.deinit();
    var enrollments = try (ntip.state.enrollments.File{ .dir = state_dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
    defer enrollments.deinit();
    const node = store.findNode("node01") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 1), enrollments.records.items.len);
    const record = enrollments.records.items[0];
    try std.testing.expect(record.node_id.eql(node.id));
    try std.testing.expectEqualSlices(u8, &credential.handle, &record.handle);
    try std.testing.expectEqualSlices(u8, &derived_psk, &record.derived_psk);
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
