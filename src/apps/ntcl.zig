const std = @import("std");
const ntip = @import("ntip");

const ExitCode = ntip.cli.common.ExitCode;
const Credential = ntip.protocol.credential.Credential;

const usage =
    \\NTIP Node
    \\usage: ntcl [--config PATH] [--state-dir PATH] [--runtime-dir PATH] COMMAND
    \\
    \\commands:
    \\  config MASTER_ENDPOINT NODE [ENROLLMENT_CREDENTIAL]
    \\         [--credential-file FILE | --credential-stdin]
    \\  bootstrap-import --stdin
    \\  up [-d] | down | status [--json]
    \\  version
    \\
;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const process_args = try init.minimal.args.toSlice(allocator);
    const args = if (process_args.len > 0) process_args[1..] else process_args;
    var stdin_buffer: [4096]u8 = undefined;
    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdin_file = std.Io.File.Reader.init(.stdin(), init.io, &stdin_buffer);
    var stdout_file = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    var stderr_file = std.Io.File.Writer.init(.stderr(), init.io, &stderr_buffer);
    const code = try run(allocator, init.io, args, &stdin_file.interface, &stdout_file.interface, &stderr_file.interface);
    try stdout_file.interface.flush();
    try stderr_file.interface.flush();
    if (code != .success) std.process.exit(@intFromEnum(code));
}

fn run(
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
    const bootstrap_paths = parseBootstrapImport(args) catch |err| {
        const code = try ntip.cli.runner.reportError(stderr, "ntcl", err);
        try stderr.writeAll(usage);
        return code;
    };
    if (bootstrap_paths) |paths| {
        return bootstrapImport(allocator, io, paths, stdin, stdout) catch |err|
            reportBootstrapError(stderr, err);
    }
    const parsed = ntip.cli.client.parse(args) catch |err| {
        const code = try ntip.cli.runner.reportError(stderr, "ntcl", err);
        try stderr.writeAll(usage);
        return code;
    };
    return execute(allocator, io, args, parsed, stdin, stdout, stderr) catch |err|
        ntip.cli.runner.reportError(stderr, "ntcl", err);
}

fn parseBootstrapImport(args: []const []const u8) !?ntip.cli.common.Paths {
    var paths = ntip.cli.common.Paths.client_defaults;
    var index: usize = 0;
    while (try ntip.cli.common.consumeGlobal(args, &index, &paths)) {}
    if (index >= args.len or !std.mem.eql(u8, args[index], "bootstrap-import")) return null;
    const rest = args[index + 1 ..];
    if (rest.len != 1 or !std.mem.eql(u8, rest[0], "--stdin")) return error.InvalidArguments;
    return paths;
}

fn bootstrapImport(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: ntip.cli.common.Paths,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
) !ExitCode {
    const bundle_bytes = stdin.allocRemaining(
        allocator,
        .limited(ntip.state.client_bootstrap.maximum_bundle_bytes),
    ) catch |err| switch (err) {
        error.StreamTooLong => return error.RequestTooLarge,
        else => return err,
    };
    defer {
        std.crypto.secureZero(u8, bundle_bytes);
        allocator.free(bundle_bytes);
    }

    const now = std.Io.Clock.real.now(io).toSeconds();
    if (now < 0) return error.ClockBeforeUnixEpoch;
    var validated = try ntip.state.client_bootstrap.parseAndValidate(allocator, bundle_bytes, now);
    defer validated.deinit(allocator);

    // Nothing on disk is touched until the complete strict bundle, including
    // expiry, archive projection, endpoint, identity anchor, and credential,
    // has passed validation.
    var state_dir = try ntip.cli.runner.openPrivateDirectory(io, paths.state_dir);
    defer state_dir.close(io);
    var lock = ntip.state.atomic_file.LifetimeLock.acquire(state_dir, io, "state.lock", true) catch |err| switch (err) {
        error.WouldBlock => return error.DaemonRunning,
        else => return err,
    };
    defer lock.release(io);

    _ = try ntip.state.client_transaction.recover(allocator, io, state_dir, paths.config);
    const persistent_state = try (ntip.state.client.File{ .dir = state_dir }).loadOrEmpty(allocator, io);
    if (persistent_state.enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;

    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &credential_buffer);
    const credential_text = validated.credential.encode(&credential_buffer);

    if (try ntip.state.client_bootstrap.loadMarker(allocator, state_dir, io)) |existing_id| {
        if (!std.mem.eql(u8, &existing_id, &validated.bootstrap_id)) return error.AlreadyBootstrapped;
        try validateResumeStateDirectory(state_dir, io);
        const existing_config = (try readConfigOptional(allocator, io, paths.config)) orelse
            return error.AlreadyBootstrapped;
        defer allocator.free(existing_config);
        if (!std.mem.eql(u8, existing_config, validated.config_json)) return error.AlreadyBootstrapped;
        const existing_credential = (ntip.state.secret_store.FileSecretStore{ .dir = state_dir }).load(
            allocator,
            io,
            "enrollment.token",
            .enrollment_token,
        ) catch |err| switch (err) {
            error.FileNotFound => return error.AlreadyBootstrapped,
            else => return err,
        };
        defer {
            std.crypto.secureZero(u8, existing_credential);
            allocator.free(existing_credential);
        }
        if (!constantTimeEqual(existing_credential, credential_text)) return error.AlreadyBootstrapped;
        try stdout.print("Bootstrap {s} is already imported; enrollment can resume.\n", .{&validated.bootstrap_id});
        return .success;
    }

    try validateFreshStateDirectory(state_dir, io);
    const existing_config = try readConfigOptional(allocator, io, paths.config);
    defer if (existing_config) |bytes| allocator.free(bytes);
    if (existing_config) |bytes| {
        if (!std.mem.eql(u8, bytes, packaged_client_sample)) return error.AlreadyBootstrapped;
    }

    try ntip.state.client_transaction.commitBootstrap(
        allocator,
        io,
        state_dir,
        paths.config,
        validated.config_json,
        credential_text,
        validated.bootstrap_id,
    );
    try stdout.print("Imported bootstrap {s} for node configuration; enrollment can start.\n", .{&validated.bootstrap_id});
    return .success;
}

fn validateFreshStateDirectory(dir: std.Io.Dir, io: std.Io) !void {
    var iterable_dir = try dir.openDir(io, ".", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer iterable_dir.close(io);
    var iterator = iterable_dir.iterateAssumeFirstIteration();
    while (try iterator.next(io)) |entry| {
        if (std.mem.eql(u8, entry.name, "state.lock")) continue;
        return error.AlreadyBootstrapped;
    }
}

fn validateResumeStateDirectory(dir: std.Io.Dir, io: std.Io) !void {
    var found_state = false;
    var iterable_dir = try dir.openDir(io, ".", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    defer iterable_dir.close(io);
    var iterator = iterable_dir.iterateAssumeFirstIteration();
    while (try iterator.next(io)) |entry| {
        if (std.mem.eql(u8, entry.name, "state.lock") or
            std.mem.eql(u8, entry.name, ntip.state.client_bootstrap.marker_file) or
            std.mem.eql(u8, entry.name, "enrollment.token") or
            std.mem.eql(u8, entry.name, "identity.key"))
        {
            continue;
        }
        if (std.mem.eql(u8, entry.name, "state.json")) {
            found_state = true;
            continue;
        }
        return error.AlreadyBootstrapped;
    }
    if (!found_state) return error.AlreadyBootstrapped;
}

fn readConfigOptional(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !?[]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        }
    else
        std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
    defer file.close(io);
    const metadata = try file.stat(io);
    if (metadata.kind != .file or metadata.permissions.toMode() & 0o022 != 0) {
        return error.InsecureConfigFile;
    }
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(ntip.state.config.max_config_bytes)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |other| return other,
    };
}

fn constantTimeEqual(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    var difference: u8 = 0;
    for (left, right) |a, b| difference |= a ^ b;
    return difference == 0;
}

fn reportBootstrapError(stderr: *std.Io.Writer, err: anyerror) !ExitCode {
    return switch (err) {
        error.InvalidBootstrapBundle,
        error.UnsupportedBootstrapSchema,
        error.InvalidBootstrapId,
        error.InvalidBootstrapExpiry,
        error.InvalidBootstrapArchive,
        error.InvalidBootstrapMarker,
        error.InvalidBootstrapMarkerType,
        => blk: {
            try stderr.print("ntcl: invalid bootstrap data ({s})\n", .{@errorName(err)});
            break :blk .usage_or_config;
        },
        error.ExpiredBootstrapBundle => blk: {
            try stderr.writeAll("ntcl: bootstrap invitation has expired\n");
            break :blk .conflict_or_not_found;
        },
        error.InvalidBootstrapCredential => blk: {
            try stderr.writeAll("ntcl: authentication/protocol failure (InvalidBootstrapCredential)\n");
            break :blk .authentication_or_protocol;
        },
        else => ntip.cli.runner.reportError(stderr, "ntcl", err),
    };
}

const packaged_client_sample =
    \\{
    \\  "schema_version": 1,
    \\  "master": "203.0.113.10:49152",
    \\  "node": "node01",
    \\  "master_public_key": "0100000000000000000000000000000000000000000000000000000000000000",
    \\  "tun_name": "ntip0",
    \\  "inner_mtu": 1380
    \\}
    \\
;

fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    parsed: ntip.cli.client.Parsed,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !ExitCode {
    if (parsed.command == .version) {
        try stdout.print("ntcl {s}\n", .{ntip.version});
        return .success;
    }

    switch (parsed.command) {
        .config => |config| {
            try configure(allocator, io, parsed, config, stdin, stdout, stderr);
            return .success;
        },
        .up => |up| return startRuntime(allocator, io, parsed.paths, up.daemonize, stdout),
        .down, .status => {},
        .version => unreachable,
    }

    const ipc_path = try ntip.cli.runner.socketPath(allocator, parsed.paths.runtime_dir, "ntcl.sock");
    defer allocator.free(ipc_path);
    const ipc_result = try ntip.cli.runner.tryInvokeIpc(allocator, io, ipc_path, args, stdout, stderr);
    switch (parsed.command) {
        .down => return ipc_result orelse error.DaemonUnavailable,
        .status => |format| {
            if (ipc_result) |code| return code;
            try ntip.cli.view.writeClientStatus(stdout, "stopped", format);
            return .success;
        },
        .config, .up, .version => unreachable,
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
        try ntip.runtime.service.runNode(std.heap.smp_allocator, io, service_paths, null);
        return .success;
    }
    switch (try ntip.platform.linux.lifecycle.forkForDaemon()) {
        .parent => |parent| {
            ntip.platform.linux.lifecycle.waitForReadiness(parent.readiness_fd) catch |err| {
                ntip.platform.linux.lifecycle.terminateFailedChild(parent.child_pid);
                return err;
            };
            try stdout.print("ntcl started (pid {d})\n", .{parent.child_pid});
            return .success;
        },
        .child => |child| {
            try ntip.runtime.service.runNode(std.heap.smp_allocator, io, service_paths, child.readiness_fd);
            return .success;
        },
    }
}

fn configure(
    allocator: std.mem.Allocator,
    io: std.Io,
    parsed: ntip.cli.client.Parsed,
    config: ntip.cli.client.Config,
    stdin: *std.Io.Reader,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !void {
    var state_dir = try ntip.cli.runner.openPrivateDirectory(io, parsed.paths.state_dir);
    defer state_dir.close(io);
    // The lifetime lock, rather than a possibly stale socket pathname, is the
    // authority for whether offline reconfiguration is safe. Preserve the
    // public conflict result when the daemon owns it.
    var lock = ntip.state.atomic_file.LifetimeLock.acquire(state_dir, io, "state.lock", true) catch |err| switch (err) {
        error.WouldBlock => return error.DaemonRunning,
        else => return err,
    };
    defer lock.release(io);

    const credential_text = switch (config.credential) {
        .hidden_tty_prompt => try ntip.cli.runner.promptCredential(allocator, io, stderr, ntip.protocol.credential.text_len),
        .positional => |value| blk: {
            try stderr.writeAll("warning: positional credentials may be exposed through shell history and process listings; prefer --credential-file or --credential-stdin\n");
            break :blk try allocator.dupe(u8, value);
        },
        .file => |path| ntip.cli.runner.readCredentialPath(allocator, io, path, ntip.protocol.credential.text_len) catch |err| switch (err) {
            error.FileNotFound => return error.CredentialFileNotFound,
            else => return err,
        },
        .stdin => try ntip.cli.runner.readCredentialInput(allocator, stdin, ntip.protocol.credential.text_len),
    };
    defer {
        std.crypto.secureZero(u8, credential_text);
        allocator.free(credential_text);
    }
    var credential = try Credential.decode(credential_text);
    defer credential.deinit();

    // Finish an interrupted earlier reconfiguration before starting another
    // one. This prevents a new command from overwriting a still-live intent.
    _ = try ntip.state.client_transaction.recover(allocator, io, state_dir, parsed.paths.config);
    const existing_state = try (ntip.state.client.File{ .dir = state_dir }).loadOrEmpty(allocator, io);
    const identity_exists = blk: {
        const stat = state_dir.statFile(io, "identity.key", .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => break :blk false,
            else => return err,
        };
        if (stat.kind != .file) return error.InvalidSecretFileType;
        break :blk true;
    };

    const config_json = try ntip.state.config.encodeClient(allocator, config.master_endpoint, config.node, credential.master_public);
    defer allocator.free(config_json);
    try ntip.state.client_transaction.commit(
        allocator,
        io,
        state_dir,
        parsed.paths.config,
        config_json,
        credential_text,
    );
    if (existing_state.node_id != null or identity_exists) {
        try stderr.writeAll("warning: existing local enrollment and private identity were revoked; ntcl up will generate a new identity\n");
    }
    try stdout.print("Configured node \"{s}\" for Master {s}\nEnrollment material stored in {s}/enrollment.token\n", .{
        config.node,
        config.master_endpoint,
        parsed.paths.state_dir,
    });
}

fn isHelp(arg: []const u8) bool {
    return std.mem.eql(u8, arg, "help") or std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h");
}

test "bootstrap sample guard matches the packaged Node configuration exactly" {
    const packaged = try std.Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "packaging/config/client.json",
        std.testing.allocator,
        .limited(ntip.state.config.max_config_bytes),
    );
    defer std.testing.allocator.free(packaged);
    try std.testing.expectEqualStrings(packaged_client_sample, packaged);
}

test "config with a credential file persists public config and private enrollment state" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ root, "credential" });
    defer std.testing.allocator.free(credential_path);

    const credential = Credential{ .handle = .{1} ** 16, .secret = .{2} ** 32, .master_public = .{3} ** 32 };
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    try ntip.cli.runner.writePrivatePath(std.testing.io, credential_path, credential.encode(&credential_buffer));
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{
        "--config", config_path, "--state-dir", state_path, "config", "master.example:49152", "node01", "--credential-file", credential_path,
    };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &args, &input, &out.writer, &err.writer));

    const config_bytes = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, config_path, std.testing.allocator, .limited(4096));
    defer std.testing.allocator.free(config_bytes);
    const decoded = try ntip.state.config.decodeClient(std.testing.allocator, config_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualStrings("node01", decoded.value.node);

    var state_dir = try std.Io.Dir.cwd().openDir(std.testing.io, state_path, .{});
    defer state_dir.close(std.testing.io);
    const stored = try (ntip.state.secret_store.FileSecretStore{ .dir = state_dir }).load(std.testing.allocator, std.testing.io, "enrollment.token", .enrollment_token);
    defer std.testing.allocator.free(stored);
    try std.testing.expectEqualStrings(credential.encode(&credential_buffer), stored);
}

test "positional credentials are accepted with an explicit warning" {
    const credential = Credential{ .handle = .{1} ** 16, .secret = .{2} ** 32, .master_public = .{3} ** 32 };
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    const text = credential.encode(&credential_buffer);
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    const args = [_][]const u8{ "--config", config_path, "--state-dir", state_path, "config", "203.0.113.10:49152", "node01", text };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &args, &input, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "shell history") != null);
}

test "credential component failures use the authentication exit contract" {
    const credential = Credential{ .handle = .{0} ** 16, .secret = .{2} ** 32, .master_public = .{3} ** 32 };
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    const text = credential.encode(&credential_buffer);
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    const args = [_][]const u8{ "--config", config_path, "--state-dir", state_path, "config", "203.0.113.10:49152", "node01", text };

    try std.testing.expectEqual(
        ExitCode.authentication_or_protocol,
        try run(std.testing.allocator, std.testing.io, &args, &input, &out.writer, &err.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "InvalidCredentialComponent") != null);
}

test "offline status reports stopped instead of daemon unavailable" {
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{ "--runtime-dir", "/definitely/not/an/ntip/runtime", "status", "--json" };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &args, &input, &out.writer, &err.writer));
    try std.testing.expectEqualStrings("{\"schema_version\":1,\"state\":\"stopped\"}\n", out.written());
}

test "config after server-side reset clears assignment and revokes the old identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ root, "credential" });
    defer std.testing.allocator.free(credential_path);

    {
        var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
        defer state_dir.close(std.testing.io);
        const identity = [_]u8{9} ** 32;
        try (ntip.state.secret_store.FileSecretStore{ .dir = state_dir }).write(
            std.testing.allocator,
            std.testing.io,
            "identity.key",
            .identity_key,
            &identity,
        );
        try (ntip.state.client.File{ .dir = state_dir }).save(std.testing.allocator, std.testing.io, .{
            .generation = 4,
            .enrollment_state = .enrolled,
            .node_id = .{ .bytes = .{7} ** 16 },
            .assigned_address = try ntip.domain.ipv4.Ipv4.parse("10.1.0.2"),
            .vnr_range = try ntip.domain.ipv4.Cidr.parse("10.1.0.0/24"),
        });
    }

    const credential = Credential{ .handle = .{1} ** 16, .secret = .{2} ** 32, .master_public = .{3} ** 32 };
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    try ntip.cli.runner.writePrivatePath(std.testing.io, credential_path, credential.encode(&credential_buffer));
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    const args = [_][]const u8{
        "--config", config_path, "--state-dir", state_path, "config", "master.example:49152", "node01", "--credential-file", credential_path,
    };
    try std.testing.expectEqual(ExitCode.success, try run(std.testing.allocator, std.testing.io, &args, &input, &out.writer, &err.writer));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "private identity were revoked") != null);

    var state_dir = try std.Io.Dir.cwd().openDir(std.testing.io, state_path, .{});
    defer state_dir.close(std.testing.io);
    const state = try (ntip.state.client.File{ .dir = state_dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
    try std.testing.expectEqual(ntip.domain.model.EnrollmentState.unenrolled, state.enrollment_state);
    try std.testing.expect(state.node_id == null);
    try std.testing.expectError(
        error.FileNotFound,
        state_dir.statFile(std.testing.io, "identity.key", .{ .follow_symlinks = false }),
    );
    try std.testing.expectError(
        error.FileNotFound,
        state_dir.statFile(std.testing.io, ntip.state.client_transaction.intent_file, .{ .follow_symlinks = false }),
    );
}

test "stale IPC socket does not block client configuration and is not removed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    const runtime_path = try std.fs.path.join(std.testing.allocator, &.{ root, "run" });
    defer std.testing.allocator.free(runtime_path);
    _ = try std.Io.Dir.cwd().createDirPathStatus(std.testing.io, runtime_path, .default_dir);
    const socket_path = try std.fs.path.join(std.testing.allocator, &.{ runtime_path, "ntcl.sock" });
    defer std.testing.allocator.free(socket_path);
    const address = try std.Io.net.UnixAddress.init(socket_path);
    var listener = try address.listen(std.testing.io, .{});
    listener.deinit(std.testing.io);
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, socket_path) catch {};

    const credential = Credential{ .handle = .{1} ** 16, .secret = .{2} ** 32, .master_public = .{3} ** 32 };
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    const args = [_][]const u8{
        "--config",      config_path,
        "--state-dir",   state_path,
        "--runtime-dir", runtime_path,
        "config",        "master.example:49152",
        "node01",        credential.encode(&credential_buffer),
    };
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(ExitCode.success, try run(
        std.testing.allocator,
        std.testing.io,
        &args,
        &input,
        &out.writer,
        &err.writer,
    ));
    try std.testing.expectEqual(
        ntip.cli.runner.SocketState.socket,
        try ntip.cli.runner.socketState(std.testing.io, socket_path),
    );
}

test "client configuration reports a live daemon from the lifetime lock" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    var daemon_lock = try ntip.state.atomic_file.LifetimeLock.acquire(state_dir, std.testing.io, "state.lock", true);
    defer daemon_lock.release(std.testing.io);

    const credential = Credential{ .handle = .{1} ** 16, .secret = .{2} ** 32, .master_public = .{3} ** 32 };
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    const args = [_][]const u8{
        "--config", config_path, "--state-dir", state_path, "config", "master.example:49152", "node01", credential.encode(&credential_buffer),
    };
    var input = std.Io.Reader.fixed("");
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(ExitCode.conflict_or_not_found, try run(
        std.testing.allocator,
        std.testing.io,
        &args,
        &input,
        &out.writer,
        &err.writer,
    ));
    try std.testing.expect(std.mem.indexOf(u8, err.written(), "DaemonRunning") != null);
}

test "bootstrap import accepts the packaged sample and same ticket resumes exactly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    try ntip.cli.runner.writeConfigPath(std.testing.io, config_path, packaged_client_sample);

    var credential = Credential{
        .handle = .{0x11} ** 16,
        .secret = .{0x22} ** 32,
        .master_public = .{0x33} ** 32,
    };
    defer credential.deinit();
    const bundle = try testBootstrapBundle(std.testing.allocator, "ABC23456", credential);
    defer {
        std.crypto.secureZero(u8, bundle);
        std.testing.allocator.free(bundle);
    }
    const args = [_][]const u8{ "--config", config_path, "--state-dir", state_path, "bootstrap-import", "--stdin" };

    var first_input = std.Io.Reader.fixed(bundle);
    var first_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer first_out.deinit();
    var first_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer first_err.deinit();
    try std.testing.expectEqual(
        ExitCode.success,
        try run(std.testing.allocator, std.testing.io, &args, &first_input, &first_out.writer, &first_err.writer),
    );

    var state_dir = try std.Io.Dir.cwd().openDir(std.testing.io, state_path, .{});
    defer state_dir.close(std.testing.io);
    const marker = (try ntip.state.client_bootstrap.loadMarker(std.testing.allocator, state_dir, std.testing.io)).?;
    try std.testing.expectEqualStrings("ABC23456", &marker);
    const state = try (ntip.state.client.File{ .dir = state_dir }).loadOrEmpty(std.testing.allocator, std.testing.io);
    try std.testing.expectEqual(ntip.domain.model.EnrollmentState.unenrolled, state.enrollment_state);
    try std.testing.expect(state.node_id == null);

    var retry_input = std.Io.Reader.fixed(bundle);
    var retry_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer retry_out.deinit();
    var retry_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer retry_err.deinit();
    try std.testing.expectEqual(
        ExitCode.success,
        try run(std.testing.allocator, std.testing.io, &args, &retry_input, &retry_out.writer, &retry_err.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, retry_out.written(), "already imported") != null);

    const other_bundle = try testBootstrapBundle(std.testing.allocator, "DEF23456", credential);
    defer {
        std.crypto.secureZero(u8, other_bundle);
        std.testing.allocator.free(other_bundle);
    }
    var other_input = std.Io.Reader.fixed(other_bundle);
    var other_out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer other_out.deinit();
    var other_err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer other_err.deinit();
    try std.testing.expectEqual(
        ExitCode.conflict_or_not_found,
        try run(std.testing.allocator, std.testing.io, &args, &other_input, &other_out.writer, &other_err.writer),
    );
    try std.testing.expect(std.mem.indexOf(u8, other_err.written(), "AlreadyBootstrapped") != null);
}

test "bootstrap import rejects unrelated Node identity without replacing it" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const state_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client" });
    defer std.testing.allocator.free(state_path);
    const config_path = try std.fs.path.join(std.testing.allocator, &.{ root, "client.json" });
    defer std.testing.allocator.free(config_path);
    var state_dir = try ntip.cli.runner.openPrivateDirectory(std.testing.io, state_path);
    defer state_dir.close(std.testing.io);
    const identity = [_]u8{0x77} ** 32;
    try (ntip.state.secret_store.FileSecretStore{ .dir = state_dir }).write(
        std.testing.allocator,
        std.testing.io,
        "identity.key",
        .identity_key,
        &identity,
    );

    var credential = Credential{
        .handle = .{0x11} ** 16,
        .secret = .{0x22} ** 32,
        .master_public = .{0x33} ** 32,
    };
    defer credential.deinit();
    const bundle = try testBootstrapBundle(std.testing.allocator, "ABC23456", credential);
    defer {
        std.crypto.secureZero(u8, bundle);
        std.testing.allocator.free(bundle);
    }
    const args = [_][]const u8{ "--config", config_path, "--state-dir", state_path, "bootstrap-import", "--stdin" };
    var input = std.Io.Reader.fixed(bundle);
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    var err: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer err.deinit();
    try std.testing.expectEqual(
        ExitCode.conflict_or_not_found,
        try run(std.testing.allocator, std.testing.io, &args, &input, &out.writer, &err.writer),
    );
    const persisted = try (ntip.state.secret_store.FileSecretStore{ .dir = state_dir }).load(
        std.testing.allocator,
        std.testing.io,
        "identity.key",
        .identity_key,
    );
    defer {
        std.crypto.secureZero(u8, persisted);
        std.testing.allocator.free(persisted);
    }
    try std.testing.expectEqualSlices(u8, &identity, persisted);
}

fn testBootstrapBundle(
    allocator: std.mem.Allocator,
    bootstrap_id: []const u8,
    credential: Credential,
) ![]u8 {
    var credential_buffer: [ntip.protocol.credential.text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &credential_buffer);
    return std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":1,\"bootstrapId\":\"{s}\",\"nodeName\":\"node01\",\"masterEndpoint\":\"203.0.113.10:49152\",\"expiresAt\":\"2099-01-02T03:04:05Z\",\"enrollmentCredential\":\"{s}\",\"archives\":[{{\"version\":\"0.2.0\",\"target\":\"x86_64-linux-musl\",\"path\":\"/enrollment/assets/ntip-node-v0.2.0-x86_64-linux-musl.tar.gz\",\"sha256\":\"abababababababababababababababababababababababababababababababab\",\"sizeBytes\":1234}},{{\"version\":\"0.2.0\",\"target\":\"aarch64-linux-musl\",\"path\":\"/enrollment/assets/ntip-node-v0.2.0-aarch64-linux-musl.tar.gz\",\"sha256\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"sizeBytes\":1234}}]}}",
        .{ bootstrap_id, credential.encode(&credential_buffer) },
    );
}
