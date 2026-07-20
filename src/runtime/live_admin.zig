//! Durable live-administration handlers used by the local IPC service.
//!
//! The daemon owns the lifetime state lock before constructing these handlers.
//! Each request is additionally serialized by an in-process mutex. Mutations
//! are applied to cloned state, persisted, and only then swapped into the live
//! model. Credential operations span `state.json` and `enrollments.json` using
//! a synced intent that recovery deterministically rolls forward.

const std = @import("std");
const build_options = @import("build_options");
const ipc = @import("ipc.zig");
const ipc_server = @import("ipc_server.zig");
const cli_server = @import("../cli/server.zig");
const cli_client = @import("../cli/client.zig");
const cli_dispatch = @import("../cli/dispatch.zig");
const cli_view = @import("../cli/view.zig");
const cli_runner = @import("../cli/runner.zig");
const common = @import("../cli/common.zig");
const model = @import("../domain/model.zig");
const state_repository = @import("../state/repository.zig");
const atomic = @import("../state/atomic_file.zig");
const enrollments_mod = @import("../state/enrollments.zig");
const server_transaction = @import("../state/server_transaction.zig");
const credential_mod = @import("../protocol/credential.zig");
const socket = @import("../platform/linux/ipc_socket.zig");

pub const credential_persistence_guarantee = enum {
    /// A synced, checksummed private intent is rolled forward on startup, so
    /// state.json and enrollments.json expose one complete logical generation.
    recoverable_two_file_transaction,
}.recoverable_two_file_transaction;

pub const GenerationCallback = struct {
    context: *anyopaque,
    changed_fn: *const fn (*anyopaque, u64) void,

    pub fn changed(self: GenerationCallback, generation: u64) void {
        self.changed_fn(self.context, generation);
    }
};

pub const ShutdownCallback = struct {
    context: *anyopaque,
    request_fn: *const fn (*anyopaque) void,

    pub fn request(self: ShutdownCallback) void {
        self.request_fn(self.context);
    }
};

pub const AssociationCallback = struct {
    context: *anyopaque,
    retire_fn: *const fn (*anyopaque, [16]u8) void,

    pub fn retire(self: AssociationCallback, node_uuid: [16]u8) void {
        self.retire_fn(self.context, node_uuid);
    }
};

pub const ServerAdmin = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: state_repository.Repository,
    enrollment_file: enrollments_mod.File,
    lifetime_lock: *atomic.LifetimeLock,
    store: *model.Store,
    enrollments: *enrollments_mod.Registry,
    master_public: [32]u8,
    maximum_nodes: u32 = 4096,
    default_enrollment_lifetime_seconds: u64 = 24 * 60 * 60,
    generation_callback: ?GenerationCallback = null,
    association_callback: ?AssociationCallback = null,
    runtime_lookup: ?cli_view.RuntimeLookup = null,
    shutdown_callback: ?ShutdownCallback = null,
    mutex: std.Io.Mutex = .init,

    pub fn handler(self: *ServerAdmin) ipc_server.Handler {
        return .{ .context = self, .handle_fn = handleOpaque };
    }

    fn handleOpaque(
        raw: *anyopaque,
        _: socket.PeerCredentials,
        request: ipc.Request,
        request_allocator: std.mem.Allocator,
    ) !ipc.Response {
        const self: *ServerAdmin = @ptrCast(@alignCast(raw));
        return self.handle(request, request_allocator);
    }

    /// `request_allocator` must remain valid until the returned response has
    /// been encoded. The IPC server supplies a per-request arena.
    pub fn handle(self: *ServerAdmin, request: ipc.Request, request_allocator: std.mem.Allocator) ipc.Response {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return self.handleLocked(request, request_allocator) catch |err| errorResponse(request.request_id, err);
    }

    fn handleLocked(self: *ServerAdmin, request: ipc.Request, request_allocator: std.mem.Allocator) !ipc.Response {
        _ = self.lifetime_lock;
        const argv = try requestArgv(request_allocator, request.arguments);
        if (!std.mem.eql(u8, request.command, try cli_runner.canonicalIpcCommand(argv))) return error.InvalidArguments;
        const parsed = cli_server.parse(argv) catch |err| return errorResponse(request.request_id, err);

        var stdout: std.Io.Writer.Allocating = .init(request_allocator);
        var stderr: std.Io.Writer.Allocating = .init(request_allocator);
        try self.execute(parsed.command, &stdout.writer, &stderr.writer);
        return try successResponse(request_allocator, request.request_id, stdout.written(), stderr.written());
    }

    fn execute(
        self: *ServerAdmin,
        command: cli_server.Command,
        stdout: *std.Io.Writer,
        stderr: *std.Io.Writer,
    ) !void {
        switch (command) {
            .up => return error.AlreadyRunning,
            .down => {
                if (self.shutdown_callback) |callback| callback.request();
                try stdout.writeAll("Shutdown requested\n");
            },
            .status => |format| try self.writeStatus(stdout, format),
            .version => try stdout.print("ntsrv {s}\n", .{build_options.version}),
            .vnr_list => |format| try cli_view.writeVnrList(stdout, self.store, format),
            .vnr_show => |show| try cli_view.writeVnrShow(stdout, self.store, show.name, show.output),
            .node_list => |format| try cli_view.writeNodeListRuntime(stdout, self.store, format, self.runtime_lookup),
            .node_show => |show| try cli_view.writeNodeShowRuntime(stdout, self.store, show.name, show.output, self.runtime_lookup),
            .route_list => |format| try cli_view.writeRouteList(stdout, self.store, format),
            .route_show => |show| {
                const prefix = model.Cidr.parse(show.cidr) catch return error.InvalidCidr;
                try cli_view.writeRouteShow(stdout, self.store, prefix, show.output);
            },
            .vnr_create, .vnr_delete, .route_add, .route_delete => try self.storeOnlyMutation(command, stdout, stderr),
            .node_create => |create| try self.createNode(command, create, stdout),
            .node_delete => |name| try self.deleteNode(command, name, stdout),
            .node_enrollment_renew => |name| try self.renewEnrollment(name, false, stdout),
            .node_enrollment_reset => |name| try self.renewEnrollment(name, true, stdout),
            .user_bootstrap, .restore => return error.DaemonRunning,
            .backup => return error.UnsupportedCommand,
        }
    }

    fn writeStatus(self: *ServerAdmin, writer: *std.Io.Writer, format: common.OutputFormat) !void {
        try cli_view.writeServerStatus(writer, self.store, "running", format);
    }

    fn storeOnlyMutation(
        self: *ServerAdmin,
        command: cli_server.Command,
        stdout: *std.Io.Writer,
        stderr: *std.Io.Writer,
    ) !void {
        var candidate = try cloneStore(self.allocator, self.store);
        errdefer candidate.deinit();
        const outcome = try cli_dispatch.applyServerMutation(&candidate, self.io, command);
        try self.repository.save(self.allocator, self.io, &candidate);
        self.installStore(&candidate);
        switch (command) {
            .vnr_create => |create| {
                const vnr = self.store.findVnr(create.name).?;
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
            .vnr_delete => |name| try stdout.print("Deleted VNR \"{s}\"\n", .{name}),
            .route_add => |add| try stdout.print("Added route {s} via {s}\n", .{ add.cidr, add.node }),
            .route_delete => |prefix| try stdout.print("Deleted route {s}\n", .{prefix}),
            else => unreachable,
        }
    }

    fn createNode(
        self: *ServerAdmin,
        command: cli_server.Command,
        create: cli_server.NodeCreate,
        stdout: *std.Io.Writer,
    ) !void {
        if (self.store.nodes.items.len >= self.maximum_nodes) return error.MaximumNodesExceeded;
        var candidate_store = try cloneStore(self.allocator, self.store);
        errdefer candidate_store.deinit();
        var candidate_enrollments = try cloneRegistry(self.allocator, self.enrollments);
        errdefer candidate_enrollments.deinit();
        _ = try cli_dispatch.applyServerMutation(&candidate_store, self.io, command);
        var credential = try issueCredential(
            self.io,
            &candidate_enrollments,
            create.name,
            candidate_store.findNode(create.name).?.id,
            self.master_public,
            create.expires_seconds orelse self.default_enrollment_lifetime_seconds,
        );
        defer std.crypto.secureZero(u8, &credential.secret);

        // Deliver an explicitly requested credential file before publishing
        // the durable mutation. A failed write therefore leaves both live and
        // on-disk administrative state unchanged. If the subsequent commit
        // fails, the file contains only an unusable, never-issued credential.
        if (create.credential_out) |path| try writeCredentialFile(credential, path, self.io);
        try server_transaction.commit(self.allocator, self.io, self.repository.dir, &candidate_store, &candidate_enrollments);
        self.installRegistry(&candidate_enrollments);
        self.installStore(&candidate_store);
        const node = self.store.findNode(create.name).?;
        var address_buffer: [15]u8 = undefined;
        try stdout.print("Created node \"{s}\"\n\nVNR:      {s}\nAddress:  {s}\nState:    unenrolled\n", .{
            create.name,
            create.vnr,
            try node.address.write(&address_buffer),
        });
        try reportCredential(credential, create.credential_out, stdout);
    }

    fn deleteNode(self: *ServerAdmin, command: cli_server.Command, name: []const u8, stdout: *std.Io.Writer) !void {
        const node_uuid = (self.store.findNode(name) orelse return error.NodeNotFound).id.bytes;
        var candidate_store = try cloneStore(self.allocator, self.store);
        errdefer candidate_store.deinit();
        var candidate_enrollments = try cloneRegistry(self.allocator, self.enrollments);
        errdefer candidate_enrollments.deinit();
        _ = try cli_dispatch.applyServerMutation(&candidate_store, self.io, command);
        candidate_enrollments.revokeNode(name) catch |err| switch (err) {
            error.EnrollmentNotFound => {},
            else => return err,
        };
        try server_transaction.commit(self.allocator, self.io, self.repository.dir, &candidate_store, &candidate_enrollments);
        self.installRegistry(&candidate_enrollments);
        self.installStore(&candidate_store);
        if (self.association_callback) |callback| callback.retire(node_uuid);
        try stdout.print("Deleted node \"{s}\"\n", .{name});
    }

    fn renewEnrollment(
        self: *ServerAdmin,
        name: []const u8,
        reset: bool,
        stdout: *std.Io.Writer,
    ) !void {
        var candidate_store = try cloneStore(self.allocator, self.store);
        var candidate_store_owned = true;
        defer if (candidate_store_owned) candidate_store.deinit();
        var candidate_enrollments = try cloneRegistry(self.allocator, self.enrollments);
        errdefer candidate_enrollments.deinit();
        const node = candidate_store.findNode(name) orelse return error.NodeNotFound;
        const node_uuid = node.id.bytes;
        if (!reset and node.enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;
        if (reset) try candidate_store.resetNodeEnrollment(name);
        var credential = try issueCredential(
            self.io,
            &candidate_enrollments,
            name,
            node.id,
            self.master_public,
            self.default_enrollment_lifetime_seconds,
        );
        defer std.crypto.secureZero(u8, &credential.secret);
        if (reset) {
            try server_transaction.commit(self.allocator, self.io, self.repository.dir, &candidate_store, &candidate_enrollments);
        } else {
            try self.enrollment_file.save(self.allocator, self.io, &candidate_enrollments);
        }
        self.installRegistry(&candidate_enrollments);
        if (reset) {
            self.installStore(&candidate_store);
            candidate_store_owned = false;
            if (self.association_callback) |callback| callback.retire(node_uuid);
        }
        try stdout.print("Enrollment {s} for node \"{s}\"\n", .{ if (reset) "reset" else "renewed", name });
        try reportCredential(credential, null, stdout);
    }

    fn installStore(self: *ServerAdmin, candidate: *model.Store) void {
        const old = self.store.*;
        self.store.* = candidate.*;
        candidate.* = old;
        candidate.deinit();
        if (self.generation_callback) |callback| callback.changed(self.store.generation);
    }

    fn installRegistry(self: *ServerAdmin, candidate: *enrollments_mod.Registry) void {
        const old = self.enrollments.*;
        self.enrollments.* = candidate.*;
        candidate.* = old;
        candidate.deinit();
    }
};

pub const ClientAdmin = struct {
    io: std.Io,
    state: []const u8 = "running",
    state_callback: ?ClientStateCallback = null,
    shutdown_callback: ?ShutdownCallback = null,
    mutex: std.Io.Mutex = .init,

    pub fn handler(self: *ClientAdmin) ipc_server.Handler {
        return .{ .context = self, .handle_fn = handleOpaque };
    }

    fn handleOpaque(
        raw: *anyopaque,
        _: socket.PeerCredentials,
        request: ipc.Request,
        request_allocator: std.mem.Allocator,
    ) !ipc.Response {
        const self: *ClientAdmin = @ptrCast(@alignCast(raw));
        return self.handle(request, request_allocator);
    }

    pub fn handle(self: *ClientAdmin, request: ipc.Request, allocator: std.mem.Allocator) ipc.Response {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const argv = requestArgv(allocator, request.arguments) catch |err| return errorResponse(request.request_id, err);
        const canonical = cli_runner.canonicalIpcCommand(argv) catch |err| return errorResponse(request.request_id, err);
        if (!std.mem.eql(u8, request.command, canonical)) return errorResponse(request.request_id, error.InvalidArguments);
        const parsed = cli_client.parse(argv) catch |err| return errorResponse(request.request_id, err);
        var output: std.Io.Writer.Allocating = .init(allocator);
        switch (parsed.command) {
            .status => |format| cli_view.writeClientStatus(&output.writer, self.currentState(), format) catch |err| return errorResponse(request.request_id, err),
            .down => {
                if (self.shutdown_callback) |callback| callback.request();
                output.writer.writeAll("Shutdown requested\n") catch |err| return errorResponse(request.request_id, err);
            },
            .up => return errorResponse(request.request_id, error.AlreadyRunning),
            .config => return errorResponse(request.request_id, error.DaemonRunning),
            .version => output.writer.print("ntcl {s}\n", .{build_options.version}) catch |err| return errorResponse(request.request_id, err),
        }
        return successResponse(allocator, request.request_id, output.written(), "") catch |err| errorResponse(request.request_id, err);
    }

    fn currentState(self: *ClientAdmin) []const u8 {
        return if (self.state_callback) |callback| callback.state() else self.state;
    }
};

pub const ClientStateCallback = struct {
    context: *anyopaque,
    state_fn: *const fn (*anyopaque) []const u8,

    pub fn state(self: ClientStateCallback) []const u8 {
        return self.state_fn(self.context);
    }
};

fn requestArgv(allocator: std.mem.Allocator, arguments: std.json.Value) ![]const []const u8 {
    if (arguments != .object) return error.InvalidArguments;
    if (arguments.object.count() != 1) return error.InvalidArguments;
    const argv_value = arguments.object.get("argv") orelse return error.InvalidArguments;
    if (argv_value != .array or argv_value.array.items.len == 0) return error.InvalidArguments;
    const argv = try allocator.alloc([]const u8, argv_value.array.items.len);
    for (argv_value.array.items, 0..) |value, index| argv[index] = switch (value) {
        .string => |string| string,
        else => return error.InvalidArguments,
    };
    return argv;
}

fn successResponse(allocator: std.mem.Allocator, request_id: u64, stdout: []const u8, stderr: []const u8) !ipc.Response {
    var result: std.json.ObjectMap = .empty;
    try result.put(allocator, "stdout", .{ .string = try allocator.dupe(u8, stdout) });
    try result.put(allocator, "stderr", .{ .string = try allocator.dupe(u8, stderr) });
    return .{
        .version = ipc.protocol_version,
        .request_id = request_id,
        .ok = true,
        .exit_code = 0,
        .result = .{ .object = result },
        .@"error" = null,
    };
}

fn errorResponse(request_id: u64, err: anyerror) ipc.Response {
    const exit_code = @intFromEnum(cli_runner.mapError(err));
    return .{
        .version = ipc.protocol_version,
        .request_id = request_id,
        .ok = false,
        .exit_code = exit_code,
        .result = null,
        .@"error" = .{ .code = errorCode(exit_code), .message = @errorName(err) },
    };
}

fn errorCode(exit_code: u8) []const u8 {
    return switch (exit_code) {
        2 => "usage_or_config",
        3 => "conflict_or_not_found",
        4 => "daemon_unavailable",
        5 => "authentication_or_protocol",
        else => "internal_failure",
    };
}

fn cloneStore(allocator: std.mem.Allocator, source: *const model.Store) !model.Store {
    var result = model.Store.init(allocator);
    errdefer result.deinit();
    result.generation = source.generation;
    try result.vnrs.appendSlice(allocator, source.vnrs.items);
    try result.nodes.appendSlice(allocator, source.nodes.items);
    try result.routes.appendSlice(allocator, source.routes.items);
    return result;
}

fn cloneRegistry(allocator: std.mem.Allocator, source: *const enrollments_mod.Registry) !enrollments_mod.Registry {
    var result = enrollments_mod.Registry.init(allocator);
    errdefer result.deinit();
    result.generation = source.generation;
    try result.records.appendSlice(allocator, source.records.items);
    return result;
}

fn issueCredential(
    io: std.Io,
    registry: *enrollments_mod.Registry,
    node: []const u8,
    node_id: model.NodeId,
    master_public: [32]u8,
    lifetime_seconds: u64,
) !credential_mod.Credential {
    const now = try cli_runner.unixSeconds(io);
    const expires_at = std.math.add(u64, now, lifetime_seconds) catch return error.InvalidExpiry;
    while (true) {
        var credential = credential_mod.Credential{ .handle = undefined, .secret = undefined, .master_public = master_public };
        io.random(&credential.handle);
        io.random(&credential.secret);
        var psk = credential.derivePsk();
        defer std.crypto.secureZero(u8, &psk);
        registry.issueWithHandle(node, node_id, credential.handle, psk, now, expires_at) catch |err| switch (err) {
            error.EnrollmentHandleInUse => continue,
            else => return err,
        };
        return credential;
    }
}

fn writeCredentialFile(
    credential: credential_mod.Credential,
    output_path: []const u8,
    io: std.Io,
) !void {
    var text_buffer: [credential_mod.text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &text_buffer);
    const text = credential.encode(&text_buffer);
    var with_newline: [credential_mod.text_len + 1]u8 = undefined;
    defer std.crypto.secureZero(u8, &with_newline);
    @memcpy(with_newline[0..text.len], text);
    with_newline[text.len] = '\n';
    try cli_runner.writePrivatePath(io, output_path, &with_newline);
}

fn reportCredential(
    credential: credential_mod.Credential,
    output_path: ?[]const u8,
    stdout: *std.Io.Writer,
) !void {
    if (output_path) |path| {
        try stdout.print("Enrollment credential written to {s}\n", .{path});
        return;
    }
    var text_buffer: [credential_mod.text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &text_buffer);
    try stdout.print("Enrollment credential (single use):\n{s}\n", .{credential.encode(&text_buffer)});
}

fn requestFor(allocator: std.mem.Allocator, request_id: u64, argv: []const []const u8) !ipc.Request {
    var array = std.json.Array.init(allocator);
    for (argv) |arg| try array.append(.{ .string = arg });
    var object: std.json.ObjectMap = .empty;
    try object.put(allocator, "argv", .{ .array = array });
    return .{
        .version = 1,
        .request_id = request_id,
        .command = try cli_runner.canonicalIpcCommand(argv),
        .arguments = .{ .object = object },
    };
}

test "server admin persists before publishing generation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var lock = try atomic.LifetimeLock.acquire(tmp.dir, std.testing.io, "state.lock", true);
    defer lock.release(std.testing.io);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    var enrollments = enrollments_mod.Registry.init(std.testing.allocator);
    defer enrollments.deinit();
    const Seen = struct {
        generation: u64 = 0,
        fn changed(raw: *anyopaque, generation: u64) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.generation = generation;
        }
    };
    var seen: Seen = .{};
    var admin: ServerAdmin = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .repository = .{ .dir = tmp.dir },
        .enrollment_file = .{ .dir = tmp.dir },
        .lifetime_lock = &lock,
        .store = &store,
        .enrollments = &enrollments,
        .master_public = .{3} ** 32,
        .generation_callback = .{ .context = &seen, .changed_fn = Seen.changed },
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try requestFor(arena.allocator(), 7, &.{ "vnr", "create", "vnr0", "10.1.0.0/24" });
    const response = admin.handle(request, arena.allocator());
    try std.testing.expect(response.ok);
    try std.testing.expectEqual(@as(u64, 1), seen.generation);
    var disk = try admin.repository.load(std.testing.allocator, std.testing.io);
    defer disk.deinit();
    try std.testing.expect(disk.findVnr("vnr0") != null);
}

test "server admin conflict is non-mutating and credential persistence is recoverable" {
    try std.testing.expectEqual(.recoverable_two_file_transaction, credential_persistence_guarantee);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var lock = try atomic.LifetimeLock.acquire(tmp.dir, std.testing.io, "state.lock", true);
    defer lock.release(std.testing.io);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    var enrollments = enrollments_mod.Registry.init(std.testing.allocator);
    defer enrollments.deinit();
    var admin: ServerAdmin = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .repository = .{ .dir = tmp.dir },
        .enrollment_file = .{ .dir = tmp.dir },
        .lifetime_lock = &lock,
        .store = &store,
        .enrollments = &enrollments,
        .master_public = .{3} ** 32,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try requestFor(arena.allocator(), 8, &.{ "vnr", "create", "other", "10.1.0.0/24" });
    const response = admin.handle(request, arena.allocator());
    try std.testing.expect(!response.ok);
    try std.testing.expectEqual(@as(u8, 3), response.exit_code);
    try std.testing.expectEqual(@as(u64, 1), store.generation);
}

test "live credential output failure does not issue or disclose credential" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ root, "missing", "node01.enroll" });
    defer std.testing.allocator.free(credential_path);

    var lock = try atomic.LifetimeLock.acquire(tmp.dir, std.testing.io, "state.lock", true);
    defer lock.release(std.testing.io);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    var enrollments = enrollments_mod.Registry.init(std.testing.allocator);
    defer enrollments.deinit();
    try server_transaction.commit(std.testing.allocator, std.testing.io, tmp.dir, &store, &enrollments);

    var admin: ServerAdmin = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .repository = .{ .dir = tmp.dir },
        .enrollment_file = .{ .dir = tmp.dir },
        .lifetime_lock = &lock,
        .store = &store,
        .enrollments = &enrollments,
        .master_public = .{3} ** 32,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try requestFor(arena.allocator(), 10, &.{
        "node",
        "create",
        "node01",
        "--vnr",
        "vnr0",
        "--addr",
        "10.1.0.2",
        "--credential-out",
        credential_path,
    });
    const response = admin.handle(request, arena.allocator());
    try std.testing.expect(!response.ok);
    try std.testing.expectEqual(@as(u8, 1), response.exit_code);
    try std.testing.expect(response.result == null);
    try std.testing.expectEqual(@as(usize, 0), store.nodes.items.len);
    try std.testing.expectEqual(@as(usize, 0), enrollments.records.items.len);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(std.testing.io, credential_path, .{ .follow_symlinks = false }),
    );

    var disk_store = try admin.repository.load(std.testing.allocator, std.testing.io);
    defer disk_store.deinit();
    var disk_enrollments = try admin.enrollment_file.loadOrEmpty(std.testing.allocator, std.testing.io);
    defer disk_enrollments.deinit();
    try std.testing.expectEqual(@as(u64, 1), disk_store.generation);
    try std.testing.expectEqual(@as(usize, 0), disk_store.nodes.items.len);
    try std.testing.expectEqual(@as(usize, 0), disk_enrollments.records.items.len);
}

test "server enrollment reset retires the association before returning success" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var lock = try atomic.LifetimeLock.acquire(tmp.dir, std.testing.io, "state.lock", true);
    defer lock.release(std.testing.io);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    const node_id: model.NodeId = .{ .bytes = .{0x31} ** 16 };
    try store.createNode(node_id, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    try store.bindNodePublicKey("node01", .{0x44} ** 32);
    var enrollments = enrollments_mod.Registry.init(std.testing.allocator);
    defer enrollments.deinit();
    try server_transaction.commit(std.testing.allocator, std.testing.io, tmp.dir, &store, &enrollments);

    const Seen = struct {
        retired: ?[16]u8 = null,
        fn retire(raw: *anyopaque, node_uuid: [16]u8) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.retired = node_uuid;
        }
    };
    var seen: Seen = .{};
    var admin: ServerAdmin = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .repository = .{ .dir = tmp.dir },
        .enrollment_file = .{ .dir = tmp.dir },
        .lifetime_lock = &lock,
        .store = &store,
        .enrollments = &enrollments,
        .master_public = .{3} ** 32,
        .association_callback = .{ .context = &seen, .retire_fn = Seen.retire },
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try requestFor(arena.allocator(), 9, &.{ "node", "enrollment", "reset", "node01" });
    const response = admin.handle(request, arena.allocator());
    try std.testing.expect(response.ok);
    try std.testing.expectEqualSlices(u8, &node_id.bytes, &seen.retired.?);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, store.findNode("node01").?.enrollment_state);
    try std.testing.expect(store.findNode("node01").?.public_key == null);
    try std.testing.expectEqual(@as(usize, 1), enrollments.records.items.len);
    try std.testing.expect(enrollments.records.items[0].node_id.eql(node_id));
}

test "client admin status and down are explicit" {
    const Seen = struct {
        down: bool = false,
        fn request(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.down = true;
        }
    };
    var seen: Seen = .{};
    var admin: ClientAdmin = .{ .io = std.testing.io, .shutdown_callback = .{ .context = &seen, .request_fn = Seen.request } };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const status = try requestFor(arena.allocator(), 1, &.{ "status", "--json" });
    try std.testing.expect(admin.handle(status, arena.allocator()).ok);
    const down = try requestFor(arena.allocator(), 2, &.{"down"});
    try std.testing.expect(admin.handle(down, arena.allocator()).ok);
    try std.testing.expect(seen.down);
}
