//! Shared SQLite-backed Master application for offline and live human CLI use.
//!
//! The caller owns the state-directory lifetime lock and the SQLite database.
//! This object serializes command execution, commits every inventory mutation
//! with a `local_cli` audit entry, and publishes a new in-memory projection only
//! after the corresponding SQLite transaction has committed.

const std = @import("std");
const ipc = @import("../runtime/ipc.zig");
const ipc_server = @import("../runtime/ipc_server.zig");
const cli_server = @import("../cli/server.zig");
const cli_dispatch = @import("../cli/dispatch.zig");
const cli_view = @import("../cli/view.zig");
const cli_runner = @import("../cli/runner.zig");
const model = @import("../domain/model.zig");
const credential_mod = @import("../protocol/credential.zig");
const socket = @import("../platform/linux/ipc_socket.zig");
const management_repository = @import("../state/management_repository.zig");
const operations_repository = @import("../state/operations_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const sqlite_maintenance = @import("../state/sqlite_maintenance.zig");
const settings_mod = @import("settings.zig");

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

pub const Application = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: management_repository.Repository,
    store: *model.Store,
    master_public: [32]u8,
    settings: settings_mod.OperationalSettings,
    version: []const u8,
    service_state: []const u8 = "running",
    generation_callback: ?GenerationCallback = null,
    association_callback: ?AssociationCallback = null,
    runtime_lookup: ?cli_view.RuntimeLookup = null,
    shutdown_callback: ?ShutdownCallback = null,
    /// Production advances bounded protocol/runtime work between SQLite
    /// backup page batches. Offline execution leaves this unset because it
    /// owns the lifetime lock and has no live data plane to service.
    backup_checkpoint: ?sqlite.BackupCheckpoint = null,
    mutex: std.Io.Mutex = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository: management_repository.Repository,
        store: *model.Store,
        master_public: [32]u8,
        settings: settings_mod.OperationalSettings,
        version: []const u8,
    ) !Application {
        try settings.validate(store.nodes.items.len);
        if (allZero(&master_public)) return error.InvalidPublicKey;
        if (try repository.durableGeneration() != store.generation) return error.PreconditionFailed;
        return .{
            .allocator = allocator,
            .io = io,
            .repository = repository,
            .store = store,
            .master_public = master_public,
            .settings = settings,
            .version = version,
        };
    }

    pub fn handler(self: *Application) ipc_server.Handler {
        return .{ .context = self, .handle_fn = handleOpaque };
    }

    fn handleOpaque(
        raw: *anyopaque,
        _: socket.PeerCredentials,
        request: ipc.Request,
        request_allocator: std.mem.Allocator,
    ) !ipc.Response {
        const self: *Application = @ptrCast(@alignCast(raw));
        return self.handle(request, request_allocator);
    }

    /// Adapts the unchanged human CLI framing and argv-shaped command body to
    /// the shared direct executor. The request allocator must outlive response
    /// encoding; the IPC server provides a request-local arena for that purpose.
    pub fn handle(self: *Application, request: ipc.Request, request_allocator: std.mem.Allocator) ipc.Response {
        const argv = requestArgv(request_allocator, request.arguments) catch |err| {
            return errorResponse(request.request_id, err);
        };
        const canonical = cli_runner.canonicalIpcCommand(argv) catch |err| {
            return errorResponse(request.request_id, err);
        };
        if (!std.mem.eql(u8, request.command, canonical)) {
            return errorResponse(request.request_id, error.InvalidArguments);
        }
        const parsed = cli_server.parse(argv) catch |err| return errorResponse(request.request_id, err);

        var stdout: std.Io.Writer.Allocating = .init(request_allocator);
        var stderr: std.Io.Writer.Allocating = .init(request_allocator);
        self.execute(parsed.command, &stdout.writer, &stderr.writer) catch |err| {
            return errorResponse(request.request_id, err);
        };
        return successResponse(
            request_allocator,
            request.request_id,
            stdout.written(),
            stderr.written(),
        ) catch |err| errorResponse(request.request_id, err);
    }

    /// Executes one parsed human command. Offline callers use this entry point
    /// while holding the state-directory lifetime lock; live callers normally
    /// reach it through `handler`. Both paths share the same serialization.
    pub fn execute(
        self: *Application,
        command: cli_server.Command,
        stdout: *std.Io.Writer,
        stderr: *std.Io.Writer,
    ) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.executeLocked(command, stdout, stderr);
    }

    fn executeLocked(
        self: *Application,
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
            .status => |format| try cli_view.writeServerStatus(stdout, self.store, self.service_state, format),
            .version => try stdout.print("ntsrv {s}\n", .{self.version}),
            .vnr_list => |format| try cli_view.writeVnrList(stdout, self.store, format),
            .vnr_show => |show| try cli_view.writeVnrShow(stdout, self.store, show.name, show.output),
            .node_list => |format| try cli_view.writeNodeListRuntime(stdout, self.store, format, self.runtime_lookup),
            .node_show => |show| try cli_view.writeNodeShowRuntime(stdout, self.store, show.name, show.output, self.runtime_lookup),
            .route_list => |format| try cli_view.writeRouteList(stdout, self.store, format),
            .route_show => |show| {
                const prefix = model.Cidr.parse(show.cidr) catch return error.InvalidCidr;
                try cli_view.writeRouteShow(stdout, self.store, prefix, show.output);
            },
            .vnr_create, .vnr_delete, .route_add, .route_delete => {
                try self.inventoryMutation(command, stdout, stderr);
            },
            .node_create => |create| try self.createNode(command, create, stdout),
            .node_delete => |name| try self.deleteNode(command, name, stdout),
            .node_enrollment_renew => |name| try self.replaceEnrollment(name, false, stdout),
            .node_enrollment_reset => |name| try self.replaceEnrollment(name, true, stdout),
            .backup => |request| try self.backup(request.output_dir, stdout),
            // Bootstrap and restore require stopped-service checks which only
            // the outer `ntsrv` process can prove while holding `state.lock`.
            .user_bootstrap, .restore => return error.DaemonRunning,
        }
    }

    fn backup(self: *Application, output_dir: []const u8, stdout: *std.Io.Writer) !void {
        var destination = try cli_runner.openPrivateDirectory(self.io, output_dir);
        defer destination.close(self.io);

        const now = try unixTimestamp(self.io);
        var entropy: [8]u8 = undefined;
        self.io.random(&entropy);
        var suffix: [entropy.len * 2]u8 = undefined;
        encodeLowerHex(&entropy, &suffix);
        const name = try std.fmt.allocPrint(
            self.allocator,
            "ntip-backup-{d}-{s}.sqlite3",
            .{ now, suffix },
        );
        defer self.allocator.free(name);

        try sqlite_maintenance.onlineBackupWithOptions(
            self.allocator,
            self.io,
            self.repository.db,
            destination,
            name,
            .{ .checkpoint = self.backup_checkpoint },
        );
        _ = try (operations_repository.Repository.init(self.repository.db)).appendAudit(.{
            .id = randomUuid(self.io),
            .occurred_at = now,
            .actor_kind = .local_cli,
            .action = "database.backup",
            .resource_type = "database",
            .details_json = "{\"mode\":\"online\"}",
        });
        try stdout.print("Backup created: {s}/{s}\n", .{ output_dir, name });
    }

    fn inventoryMutation(
        self: *Application,
        command: cli_server.Command,
        stdout: *std.Io.Writer,
        stderr: *std.Io.Writer,
    ) !void {
        var candidate = try cloneStore(self.allocator, self.store);
        defer candidate.deinit();
        const expected_generation = self.store.generation;
        const outcome = try cli_dispatch.applyServerMutation(&candidate, self.io, command);
        const now = try unixTimestamp(self.io);
        const audit = self.auditFor(command, now);
        _ = try self.repository.persistInventory(&candidate, expected_generation, now, audit);
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
        self: *Application,
        command: cli_server.Command,
        create: cli_server.NodeCreate,
        stdout: *std.Io.Writer,
    ) !void {
        const admission_capacity = @min(
            self.settings.maximum_nodes,
            try self.repository.nodeAdmissionCapacity(),
        );
        if (self.store.nodes.items.len >= admission_capacity) return error.MaximumNodesExceeded;
        var candidate = try cloneStore(self.allocator, self.store);
        defer candidate.deinit();
        const expected_generation = self.store.generation;
        const outcome = try cli_dispatch.applyServerMutation(&candidate, self.io, command);
        const node_id = outcome.node_created;
        const now = try unixTimestamp(self.io);
        var issued = try self.issueCredential(
            node_id,
            now,
            create.expires_seconds orelse self.settings.default_enrollment_lifetime_seconds,
        );
        defer issued.deinit();

        // A specifically requested private file is delivered first. Failure
        // therefore leaves both SQLite and the live projection untouched.
        if (create.credential_out) |path| try writeCredentialFile(&issued.credential, path, self.io);
        _ = try self.repository.persistInventoryWithEnrollment(
            &candidate,
            issued.pending,
            expected_generation,
            now,
            self.auditFor(command, now),
        );
        self.installStore(&candidate);

        const node = self.store.findNode(create.name).?;
        var address_buffer: [15]u8 = undefined;
        try stdout.print("Created node \"{s}\"\n\nVNR:      {s}\nAddress:  {s}\nState:    unenrolled\n", .{
            create.name,
            create.vnr,
            try node.address.write(&address_buffer),
        });
        try reportCredential(&issued.credential, create.credential_out, stdout);
    }

    fn deleteNode(
        self: *Application,
        command: cli_server.Command,
        name: []const u8,
        stdout: *std.Io.Writer,
    ) !void {
        const node_uuid = (self.store.findNode(name) orelse return error.NodeNotFound).id.bytes;
        var candidate = try cloneStore(self.allocator, self.store);
        defer candidate.deinit();
        const expected_generation = self.store.generation;
        _ = try cli_dispatch.applyServerMutation(&candidate, self.io, command);
        const now = try unixTimestamp(self.io);
        _ = try self.repository.persistInventory(
            &candidate,
            expected_generation,
            now,
            self.auditFor(command, now),
        );
        // SQLite cascades enrollment credentials with the deleted Node. Only
        // after that commit may the runtime projection and association change.
        self.installStore(&candidate);
        if (self.association_callback) |callback| callback.retire(node_uuid);
        try stdout.print("Deleted node \"{s}\"\n", .{name});
    }

    fn replaceEnrollment(
        self: *Application,
        name: []const u8,
        reset: bool,
        stdout: *std.Io.Writer,
    ) !void {
        const node = self.store.findNode(name) orelse return error.NodeNotFound;
        if (!reset and node.enrollment_state == .enrolled) return error.NodeAlreadyEnrolled;
        const node_id = node.id;
        const was_enrolled = node.enrollment_state == .enrolled;
        const expected_generation = self.store.generation;

        // Allocate the complete next live projection before committing. This
        // removes a post-commit allocation failure window between durability
        // and publication.
        var candidate = try cloneStore(self.allocator, self.store);
        defer candidate.deinit();
        if (reset) {
            try candidate.resetNodeEnrollment(name);
        } else {
            candidate.generation = std.math.add(u64, candidate.generation, 1) catch
                return error.GenerationOverflow;
        }

        const now = try unixTimestamp(self.io);
        var issued = try self.issueCredential(
            node_id,
            now,
            self.settings.default_enrollment_lifetime_seconds,
        );
        defer issued.deinit();
        const command: cli_server.Command = if (reset)
            .{ .node_enrollment_reset = name }
        else
            .{ .node_enrollment_renew = name };
        _ = try self.repository.replaceEnrollment(
            node_id,
            issued.credential.handle,
            issued.pending.derived_psk,
            reset,
            now,
            issued.pending.expires_at,
            expected_generation,
            self.auditFor(command, now),
        );
        self.installStore(&candidate);
        if (reset and was_enrolled) {
            if (self.association_callback) |callback| callback.retire(node_id.bytes);
        }
        try stdout.print("Enrollment {s} for node \"{s}\"\n", .{ if (reset) "reset" else "renewed", name });
        try reportCredential(&issued.credential, null, stdout);
    }

    fn issueCredential(
        self: *Application,
        node_id: model.NodeId,
        created_at: i64,
        lifetime_seconds: u64,
    ) !IssuedCredential {
        if (lifetime_seconds == 0) return error.InvalidExpiry;
        const lifetime: i64 = std.math.cast(i64, lifetime_seconds) orelse return error.InvalidExpiry;
        const expires_at = std.math.add(i64, created_at, lifetime) catch return error.InvalidExpiry;
        while (true) {
            var issued = IssuedCredential{
                .credential = .{
                    .handle = undefined,
                    .secret = undefined,
                    .master_public = self.master_public,
                },
                .pending = .{
                    .node_id = node_id,
                    .handle = undefined,
                    .derived_psk = undefined,
                    .expires_at = expires_at,
                },
            };
            self.io.random(&issued.credential.handle);
            self.io.random(&issued.credential.secret);
            if (allZero(&issued.credential.handle) or allZero(&issued.credential.secret)) {
                issued.deinit();
                continue;
            }
            if (try self.enrollmentHandleExists(issued.credential.handle)) {
                issued.deinit();
                continue;
            }
            issued.pending.handle = issued.credential.handle;
            issued.pending.derived_psk = issued.credential.derivePsk();
            return issued;
        }
    }

    fn enrollmentHandleExists(self: *Application, enrollment_handle: [16]u8) !bool {
        var statement = try self.repository.db.prepare(
            "SELECT 1 FROM enrollment_credentials WHERE handle = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &enrollment_handle);
        return switch (try statement.step()) {
            .done => false,
            .row => blk: {
                if (try statement.step() != .done) return error.CorruptEnrollmentCredential;
                break :blk true;
            },
        };
    }

    fn auditFor(self: *Application, command: cli_server.Command, now: i64) management_repository.AuditEntry {
        const metadata = mutationMetadata(command);
        return .{
            .id = randomUuid(self.io),
            .occurred_at = now,
            .actor_kind = .local_cli,
            .action = metadata.action,
            .resource_type = metadata.resource_type,
            .resource_id = metadata.resource_id,
            // Deliberately fixed and secret-free. Command arguments, generated
            // credential material, and PSK verifiers never enter audit details.
            .details_json = "{}",
        };
    }

    fn installStore(self: *Application, candidate: *model.Store) void {
        const previous = self.store.*;
        self.store.* = candidate.*;
        candidate.* = previous;
        if (self.generation_callback) |callback| callback.changed(self.store.generation);
    }
};

const IssuedCredential = struct {
    credential: credential_mod.Credential,
    pending: management_repository.PendingEnrollment,

    fn deinit(self: *IssuedCredential) void {
        self.credential.deinit();
        std.crypto.secureZero(u8, &self.pending.handle);
        std.crypto.secureZero(u8, &self.pending.derived_psk);
        self.pending.node_id = .{ .bytes = [_]u8{0} ** 16 };
        self.pending.expires_at = 0;
    }
};

const MutationMetadata = struct {
    action: []const u8,
    resource_type: []const u8,
    resource_id: []const u8,
};

fn mutationMetadata(command: cli_server.Command) MutationMetadata {
    return switch (command) {
        .vnr_create => |value| .{ .action = "vnr.create", .resource_type = "vnr", .resource_id = value.name },
        .vnr_delete => |name| .{ .action = "vnr.delete", .resource_type = "vnr", .resource_id = name },
        .node_create => |value| .{ .action = "node.create", .resource_type = "node", .resource_id = value.name },
        .node_delete => |name| .{ .action = "node.delete", .resource_type = "node", .resource_id = name },
        .node_enrollment_renew => |name| .{ .action = "node.enrollment.renew", .resource_type = "node", .resource_id = name },
        .node_enrollment_reset => |name| .{ .action = "node.enrollment.reset", .resource_type = "node", .resource_id = name },
        .route_add => |value| .{ .action = "route.create", .resource_type = "route", .resource_id = value.cidr },
        .route_delete => |prefix| .{ .action = "route.delete", .resource_type = "route", .resource_id = prefix },
        else => unreachable,
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

fn unixTimestamp(io: std.Io) !i64 {
    const seconds = try cli_runner.unixSeconds(io);
    return std.math.cast(i64, seconds) orelse error.ClockOutOfRange;
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

fn allZero(bytes: []const u8) bool {
    var combined: u8 = 0;
    for (bytes) |byte| combined |= byte;
    return combined == 0;
}

fn writeCredentialFile(
    credential: *const credential_mod.Credential,
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
    credential: *const credential_mod.Credential,
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

fn requestArgv(allocator: std.mem.Allocator, arguments: std.json.Value) ![]const []const u8 {
    if (arguments != .object or arguments.object.count() != 1) return error.InvalidArguments;
    const argv_value = arguments.object.get("argv") orelse return error.InvalidArguments;
    if (argv_value != .array or argv_value.array.items.len == 0) return error.InvalidArguments;
    const argv = try allocator.alloc([]const u8, argv_value.array.items.len);
    for (argv_value.array.items, 0..) |value, index| argv[index] = switch (value) {
        .string => |string| string,
        else => return error.InvalidArguments,
    };
    return argv;
}

fn successResponse(
    allocator: std.mem.Allocator,
    request_id: u64,
    stdout: []const u8,
    stderr: []const u8,
) !ipc.Response {
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

fn requestFor(allocator: std.mem.Allocator, request_id: u64, argv: []const []const u8) !ipc.Request {
    var array = std.json.Array.init(allocator);
    for (argv) |arg| try array.append(.{ .string = arg });
    var object: std.json.ObjectMap = .empty;
    try object.put(allocator, "argv", .{ .array = array });
    return .{
        .version = ipc.protocol_version,
        .request_id = request_id,
        .command = try cli_runner.canonicalIpcCommand(argv),
        .arguments = .{ .object = object },
    };
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn scalarInt(db: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try db.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const result = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return result;
}

fn persistTestVnr(repository: management_repository.Repository, store: *model.Store) !void {
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    _ = try repository.persistInventory(store, 0, 1, .{
        .id = [_]u8{0x10} ** 16,
        .occurred_at = 1,
        .actor_kind = .system,
        .action = "test.bootstrap",
        .resource_type = "inventory",
    });
}

test "SQLite application persists before publishing generation" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = management_repository.Repository.init(&db);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();

    const Seen = struct {
        repository: management_repository.Repository,
        published_after_commit: bool = false,
        fn changed(raw: *anyopaque, generation: u64) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            const durable = self.repository.durableGeneration() catch return;
            const count = scalarInt(self.repository.db, "SELECT count(*) FROM vnrs WHERE name = 'vnr0';") catch return;
            self.published_after_commit = generation == 1 and durable == 1 and count == 1;
        }
    };
    var seen: Seen = .{ .repository = repository };
    var app = try Application.init(
        std.testing.allocator,
        std.testing.io,
        repository,
        &store,
        [_]u8{3} ** 32,
        .{},
        "test",
    );
    app.generation_callback = .{ .context = &seen, .changed_fn = Seen.changed };

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var errors: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer errors.deinit();
    try app.execute(.{ .vnr_create = .{ .name = "vnr0", .cidr = "10.1.0.0/24" } }, &output.writer, &errors.writer);
    try std.testing.expect(seen.published_after_commit);
    try std.testing.expect(store.findVnr("vnr0") != null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE actor_kind = 'local_cli';"));
}

test "credential output failure leaves SQLite and live Store unchanged" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = management_repository.Repository.init(&db);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    try persistTestVnr(repository, &store);
    var app = try Application.init(std.testing.allocator, std.testing.io, repository, &store, [_]u8{3} ** 32, .{}, "test");

    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const missing = try std.fs.path.join(std.testing.allocator, &.{ root, "missing", "node01.enroll" });
    defer std.testing.allocator.free(missing);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var errors: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer errors.deinit();
    try std.testing.expectError(error.FileNotFound, app.execute(.{ .node_create = .{
        .name = "node01",
        .vnr = "vnr0",
        .address = "10.1.0.2",
        .credential_out = missing,
    } }, &output.writer, &errors.writer));

    try std.testing.expectEqual(@as(u64, 1), store.generation);
    try std.testing.expectEqual(@as(usize, 0), store.nodes.items.len);
    try std.testing.expectEqual(@as(u64, 1), try repository.durableGeneration());
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM nodes;"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
}

test "Node and one-time credential commit atomically" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = management_repository.Repository.init(&db);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    try persistTestVnr(repository, &store);
    var app = try Application.init(std.testing.allocator, std.testing.io, repository, &store, [_]u8{3} ** 32, .{}, "test");

    const root = try std.fmt.allocPrint(std.testing.allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    defer std.testing.allocator.free(root);
    const credential_path = try std.fs.path.join(std.testing.allocator, &.{ root, "node01.enroll" });
    defer std.testing.allocator.free(credential_path);
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var errors: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer errors.deinit();
    try app.execute(.{ .node_create = .{
        .name = "node01",
        .vnr = "vnr0",
        .address = "10.1.0.2",
        .credential_out = credential_path,
    } }, &output.writer, &errors.writer);

    try std.testing.expectEqual(@as(u64, 2), store.generation);
    try std.testing.expect(store.findNode("node01") != null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM nodes WHERE name = 'node01';"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused' AND derived_psk IS NOT NULL;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE action = 'node.create' AND details_json = '{}';"));
    const stat = try std.Io.Dir.cwd().statFile(std.testing.io, credential_path, .{ .follow_symlinks = false });
    try std.testing.expectEqual(std.Io.File.Kind.file, stat.kind);
    try std.testing.expectEqual(@as(u32, 0), stat.permissions.toMode() & 0o077);

    try app.execute(.{ .node_delete = "node01" }, &output.writer, &errors.writer);
    try std.testing.expect(store.findNode("node01") == null);
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM nodes;"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials;"));
}

test "enrollment reset commits before retiring active association" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = management_repository.Repository.init(&db);
    var candidate = model.Store.init(std.testing.allocator);
    defer candidate.deinit();
    try persistTestVnr(repository, &candidate);
    try candidate.createNode(.{ .bytes = [_]u8{0x31} ** 16 }, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    const node_id = candidate.findNode("node01").?.id;
    _ = try repository.persistInventoryWithEnrollment(&candidate, .{
        .node_id = node_id,
        .handle = [_]u8{0x41} ** 16,
        .derived_psk = [_]u8{0x42} ** 32,
        .expires_at = 100,
    }, 1, 2, .{
        .id = [_]u8{0x43} ** 16,
        .occurred_at = 2,
        .actor_kind = .system,
        .action = "test.bootstrap",
        .resource_type = "inventory",
    });
    _ = try repository.consumeEnrollment(
        [_]u8{0x41} ** 16,
        [_]u8{0x42} ** 32,
        [_]u8{0x44} ** 32,
        3,
        2,
        .{
            .id = [_]u8{0x45} ** 16,
            .occurred_at = 3,
            .actor_kind = .system,
            .action = "test.consume",
            .resource_type = "node",
        },
    );
    var store = try repository.loadInventory(std.testing.allocator);
    defer store.deinit();

    const Seen = struct {
        db: *sqlite.Database,
        node_id: model.NodeId,
        retired_after_commit: bool = false,
        fn retire(raw: *anyopaque, retired: [16]u8) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            var statement = self.db.prepare("SELECT enrollment_state, public_key FROM nodes WHERE id = ?1;") catch return;
            defer statement.deinit();
            statement.bindBlob(1, &self.node_id.bytes) catch return;
            if ((statement.step() catch return) != .row) return;
            const state = statement.columnText(0) orelse return;
            self.retired_after_commit = std.mem.eql(u8, &retired, &self.node_id.bytes) and
                std.mem.eql(u8, state, "unenrolled") and statement.columnIsNull(1);
        }
    };
    var seen: Seen = .{ .db = &db, .node_id = node_id };
    var app = try Application.init(std.testing.allocator, std.testing.io, repository, &store, [_]u8{3} ** 32, .{}, "test");
    app.association_callback = .{ .context = &seen, .retire_fn = Seen.retire };
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var errors: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer errors.deinit();
    try app.execute(.{ .node_enrollment_reset = "node01" }, &output.writer, &errors.writer);

    try std.testing.expect(seen.retired_after_commit);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, store.findNode("node01").?.enrollment_state);
    try std.testing.expect(store.findNode("node01").?.public_key == null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE status = 'unused' AND derived_psk IS NOT NULL;"));
}

test "human IPC handler preserves CLI-shaped status response" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    const repository = management_repository.Repository.init(&db);
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    var app = try Application.init(std.testing.allocator, std.testing.io, repository, &store, [_]u8{3} ** 32, .{}, "test");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const request = try requestFor(arena.allocator(), 77, &.{ "status", "--json" });
    const response = try app.handler().handle(.{ .pid = 1, .uid = 2, .gid = 3 }, request, arena.allocator());
    try std.testing.expect(response.ok);
    try std.testing.expectEqual(@as(u64, 77), response.request_id);
    const result = response.result.?.object;
    const stdout = result.get("stdout").?.string;
    try std.testing.expect(std.mem.indexOf(u8, stdout, "\"schema_version\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, stdout, "\"generation\":0") != null);
}
