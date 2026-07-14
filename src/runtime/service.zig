//! Linux runtime assembly for the two public executables.
//!
//! Startup remains deliberately explicit: acquire the lifetime lock, parse all
//! durable state, create only NTIP-owned kernel resources, drop privileges,
//! report readiness, then enter the control loop. Closing the exclusive,
//! non-persistent TUN descriptor is the rollback mechanism for addresses and
//! dependent routes installed on `ntip0`.

const std = @import("std");
const builtin = @import("builtin");
const linux_platform = @import("../platform/linux/root.zig");
const state = @import("../state/root.zig");
const model = @import("../domain/model.zig");
const topology = @import("topology.zig");
const forwarding = @import("forwarding.zig");
const authorization = @import("authorization.zig");
const data_plane = @import("data_plane.zig");
const data_worker = @import("data_worker.zig");
const control_plane = @import("control_plane.zig");
const ipc_server = @import("ipc_server.zig");
const live_admin = @import("live_admin.zig");
const endpoint = @import("endpoint.zig");
const handshake_coordinator = @import("handshake_coordinator.zig");
const configuration_runtime = @import("configuration_runtime.zig");
const service_state = @import("service_state.zig");
const protocol_cookie = @import("../protocol/cookie.zig");
const protocol_credential = @import("../protocol/credential.zig");
const protocol_endpoint = @import("../protocol/endpoint.zig");
const cli_view = @import("../cli/view.zig");

pub const Paths = struct {
    config: []const u8,
    state_dir: []const u8,
    runtime_dir: []const u8,
};

pub const Readiness = struct {
    fd: ?i32 = null,
    reported: bool = false,

    pub fn ready(self: *Readiness) void {
        const descriptor = self.fd orelse return;
        linux_platform.lifecycle.reportReadiness(descriptor, true);
        self.reported = true;
        self.fd = null;
    }

    pub fn fail(self: *Readiness) void {
        if (self.reported) return;
        const descriptor = self.fd orelse return;
        linux_platform.lifecycle.reportReadiness(descriptor, false);
        self.fd = null;
    }
};

pub fn runMaster(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: Paths,
    readiness_fd: ?i32,
) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return runMasterLinux(allocator, io, paths, readiness_fd);
}

pub fn runNode(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: Paths,
    readiness_fd: ?i32,
) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    return runNodeLinux(allocator, io, paths, readiness_fd);
}

fn runMasterLinux(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: Paths,
    readiness_fd: ?i32,
) !void {
    var readiness: Readiness = .{ .fd = readiness_fd };
    defer readiness.fail();
    linux_platform.lifecycle.resetStopForTest();
    linux_platform.lifecycle.installTerminationHandlers();

    const config_bytes = try readBounded(allocator, io, paths.config, state.config.max_config_bytes);
    defer allocator.free(config_bytes);
    const parsed_config = try state.config.decodeServer(allocator, config_bytes);
    defer parsed_config.deinit();
    const config = parsed_config.value;
    const accounts = try runtimeAccounts(allocator, io);

    var state_dir = try openPrivateDirectory(io, paths.state_dir);
    defer state_dir.close(io);
    try validateDirectoryIdentity(state_dir, io, accounts.user.uid, accounts.user.gid, 0o700);
    var lifetime_lock = try state.atomic_file.LifetimeLock.acquire(state_dir, io, "state.lock", true);
    defer lifetime_lock.release(io);
    _ = try state.server_transaction.recover(allocator, io, state_dir);

    const repository: state.repository.Repository = .{ .dir = state_dir };
    var store = try repository.loadOrEmpty(allocator, io);
    defer store.deinit();
    const enrollment_file: state.enrollments.File = .{ .dir = state_dir };
    var enrollments = try enrollment_file.loadOrEmpty(allocator, io);
    defer enrollments.deinit();
    var identity = try state.identity.loadOrCreate(allocator, io, state_dir);
    defer std.crypto.secureZero(u8, &identity.secret);

    if (store.nodes.items.len > config.maximum_nodes) return error.MaximumNodesExceeded;
    const snapshots = try topology.createMaster(allocator, &store, &.{});
    var snapshots_owned_by_worker = false;
    defer if (!snapshots_owned_by_worker) snapshots.destroy();
    var plane = try data_plane.DataPlane.init(
        allocator,
        sessionTableCapacity(config.maximum_nodes),
        &snapshots.forwarding,
        &snapshots.sources,
        &snapshots.destinations,
    );
    defer plane.deinit();
    plane.destination_policy_owner = topology.masterDestinationOwner();
    plane.inner_mtu = config.inner_mtu;
    plane.configureTraffic(.{
        .cold_after_ns = @as(u64, config.traffic.cold_after_seconds) * std.time.ns_per_s,
        .hot_pps = config.traffic.hot_packets_per_second,
        .hot_bits_per_second = config.traffic.hot_bits_per_second,
        .saturated_queue_percent = config.traffic.saturated_queue_percent,
        .hysteresis_ns = @as(u64, config.traffic.hysteresis_seconds) * std.time.ns_per_s,
    });

    var tun = try linux_platform.tun.Device.openExclusive(config.tun_name);
    defer tun.close();
    const routes: linux_platform.routes.Controller = .{ .allocator = allocator, .io = io };
    try routes.configureLink(config.tun_name, config.inner_mtu);
    try configureMasterRoutes(routes, config.tun_name, config.inner_mtu, &store);
    warnNetworkPrerequisites(routes, config.tun_name, true);

    var udp = try linux_platform.udp.DualStack.bind(io, config.listen_port);
    defer udp.close();
    var control_events = try data_worker.ControlQueue.init(allocator, 1024);
    defer control_events.deinit();
    var data_commands = try data_worker.CommandQueue.init(allocator, 4096);
    defer data_commands.deinit();
    var retirements = try data_worker.RetirementQueue.init(allocator, sessionTableCapacity(config.maximum_nodes));
    defer retirements.deinit();
    var worker = try data_worker.DataWorker.init(io, &tun, &udp, &plane, &control_events, &data_commands, &retirements);
    defer worker.deinit();
    try worker.adoptMasterSnapshot(snapshots);
    snapshots_owned_by_worker = true;
    var control = control_plane.ControlPlane.init(
        allocator,
        io,
        &control_events,
        control_plane.CommandSink.fromWorker(&worker),
    );
    try control.configureLiveness(
        config.heartbeat_idle_seconds,
        config.suspect_after_seconds,
        config.offline_after_seconds,
    );

    var generation_notice: GenerationNotice = .{};
    var snapshot_installer = try SnapshotInstaller.init(
        allocator,
        &store,
        &worker,
        &generation_notice,
        routes,
        config.tun_name,
        config.inner_mtu,
    );
    control.setSnapshotObserver(snapshot_installer.observer());
    const runtime_capacity: usize = @intCast(config.maximum_nodes);
    var publisher = try configuration_runtime.MasterPublisher.init(
        allocator,
        &control,
        &store,
        &config,
        runtime_capacity,
    );
    control.setConfigurationObserver(publisher.observer());
    var registry_adapter = service_state.MasterRegistryAdapter.init(
        allocator,
        io,
        repository,
        &store,
        &enrollments,
    );
    var retry_rotator = try RetryRotator.init(io);
    var coordinator = try handshake_coordinator.MasterCoordinator.init(
        allocator,
        io,
        &control,
        control_plane.CommandSink.fromWorker(&worker),
        registry_adapter.interface(),
        publisher.readyCallback(),
        identity,
        retry_rotator.policy(false),
        runtime_capacity,
    );
    coordinator.attach();
    publisher.setAssociationRetirer(.{ .context = &coordinator, .retire_fn = retireMasterAssociation });
    var runtime_view: MasterRuntimeView = .{ .coordinator = &coordinator, .control = &control };
    defer {
        control.deinit();
        coordinator.deinit();
        publisher.deinit();
        snapshot_installer.deinit();
        retry_rotator.deinit();
    }
    var admin: live_admin.ServerAdmin = .{
        .allocator = allocator,
        .io = io,
        .repository = repository,
        .enrollment_file = enrollment_file,
        .lifetime_lock = &lifetime_lock,
        .store = &store,
        .enrollments = &enrollments,
        .master_public = identity.public,
        .maximum_nodes = config.maximum_nodes,
        .default_enrollment_lifetime_seconds = config.default_enrollment_lifetime_seconds,
        .generation_callback = generation_notice.callback(),
        .association_callback = .{ .context = &coordinator, .retire_fn = retireMasterAssociation },
        .runtime_lookup = runtime_view.lookup(),
        .shutdown_callback = shutdownCallback(),
    };
    const socket_path = try std.fs.path.join(allocator, &.{ paths.runtime_dir, "ntsrv.sock" });
    defer allocator.free(socket_path);
    try validateRuntimeDirectory(io, paths.runtime_dir, accounts.admin_gid);
    try removeStaleSocket(io, socket_path);
    var ipc = try ipc_server.Server.init(allocator, io, socket_path, accounts.admin_gid, admin.handler());
    defer ipc.deinit();

    try dropPrivilegesIfNeeded(accounts.user, accounts.admin_gid);
    var data_thread_state: DataThreadState = .{ .worker = &worker };
    const thread = try std.Thread.spawn(.{}, DataThreadState.run, .{&data_thread_state});
    defer {
        linux_platform.lifecycle.requestStop();
        _ = worker.submit(.{ .kind = .remove_session, .receiver_session_id = 0 });
        thread.join();
    }

    readiness.ready();
    var loop: MasterLoop = .{
        .coordinator = &coordinator,
        .publisher = &publisher,
        .retry_rotator = &retry_rotator,
    };
    try runControlLoop(&ipc, &control, &snapshot_installer, loop.hook());
    if (data_thread_state.failed.load(.acquire)) return error.DataWorkerFailed;
}

fn runNodeLinux(
    allocator: std.mem.Allocator,
    io: std.Io,
    paths: Paths,
    readiness_fd: ?i32,
) !void {
    var readiness: Readiness = .{ .fd = readiness_fd };
    defer readiness.fail();
    linux_platform.lifecycle.resetStopForTest();
    linux_platform.lifecycle.installTerminationHandlers();

    var state_dir = try openPrivateDirectory(io, paths.state_dir);
    defer state_dir.close(io);
    const accounts = try runtimeAccounts(allocator, io);
    try validateDirectoryIdentity(state_dir, io, accounts.user.uid, accounts.user.gid, 0o700);
    var lifetime_lock = try state.atomic_file.LifetimeLock.acquire(state_dir, io, "state.lock", true);
    defer lifetime_lock.release(io);
    // Reconfiguration may span the public config, enrollment token, static
    // identity, and assignment. Roll any durable intent forward before loading
    // even one of those inputs so startup can never observe a mixed identity.
    _ = try state.client_transaction.recover(allocator, io, state_dir, paths.config);

    const config_bytes = try readBounded(allocator, io, paths.config, state.config.max_config_bytes);
    defer allocator.free(config_bytes);
    const parsed_config = try state.config.decodeClient(allocator, config_bytes);
    defer parsed_config.deinit();
    const config = parsed_config.value;
    // Resolve before creating kernel state. DNS is endpoint discovery only;
    // the pinned public key in the configuration authenticates the Master.
    const master_endpoint = try (try endpoint.parse(config.master)).resolve(io);
    const master_public = try service_state.parseMasterPublicKey(config.master_public_key);

    const client_file: state.client.File = .{ .dir = state_dir };
    var client_state = try client_file.loadOrEmpty(allocator, io);
    try service_state.cleanupConsumedEnrollmentToken(io, state_dir, client_state);
    var identity = try state.identity.loadOrCreate(allocator, io, state_dir);
    defer std.crypto.secureZero(u8, &identity.secret);

    const client_snapshots = try topology.createEmptyClient(allocator);
    var snapshots_owned_by_worker = false;
    defer if (!snapshots_owned_by_worker) client_snapshots.destroy();
    var plane = try data_plane.DataPlane.init(
        allocator,
        8,
        &client_snapshots.forwarding,
        &client_snapshots.sources,
        &client_snapshots.destinations,
    );
    defer plane.deinit();
    plane.destination_policy_owner = local_owner;
    plane.reject_same_owner_destination = false;
    plane.inner_mtu = config.inner_mtu;

    var tun = try linux_platform.tun.Device.openExclusive(config.tun_name);
    defer tun.close();
    const routes: linux_platform.routes.Controller = .{ .allocator = allocator, .io = io };
    try routes.configureLink(config.tun_name, config.inner_mtu);
    warnNetworkPrerequisites(routes, config.tun_name, false);

    var udp = try linux_platform.udp.DualStack.bind(io, 0);
    defer udp.close();
    var control_events = try data_worker.ControlQueue.init(allocator, 1024);
    defer control_events.deinit();
    var data_commands = try data_worker.CommandQueue.init(allocator, 4096);
    defer data_commands.deinit();
    var retirements = try data_worker.RetirementQueue.init(allocator, 8);
    defer retirements.deinit();
    var worker = try data_worker.DataWorker.init(io, &tun, &udp, &plane, &control_events, &data_commands, &retirements);
    defer worker.deinit();
    try worker.adoptClientSnapshot(client_snapshots);
    snapshots_owned_by_worker = true;
    var control = control_plane.ControlPlane.init(
        allocator,
        io,
        &control_events,
        control_plane.CommandSink.fromWorker(&worker),
    );
    var persistence = try service_state.NodePersistenceAdapter.init(
        allocator,
        io,
        state_dir,
        &client_state,
        master_public,
    );
    var applier = configuration_runtime.NodeApplier.init(
        allocator,
        io,
        &control,
        &worker,
        routes,
        config.tun_name,
        &client_state,
    );
    applier.setGenerationStore(persistence.generationStore());
    control.setConfigurationObserver(applier.observer());
    control.setClientSnapshotObserver(applier.snapshotObserver());
    var coordinator = handshake_coordinator.NodeCoordinator.init(
        io,
        &control,
        control_plane.CommandSink.fromWorker(&worker),
        persistence.interface(),
    );
    coordinator.attach();
    const enrollment_credential: ?protocol_credential.Credential = if (client_state.enrollment_state == .unenrolled)
        try service_state.loadEnrollmentCredential(allocator, io, state_dir, master_public)
    else
        null;
    var loop: NodeLoop = .{
        .io = io,
        .coordinator = &coordinator,
        .applier = &applier,
        .persistent = &client_state,
        .endpoint = master_endpoint,
        .identity = identity,
        .master_public = master_public,
        .credential = enrollment_credential,
    };
    defer {
        control.deinit();
        coordinator.deinit();
        loop.deinit();
        applier.deinit();
    }

    var admin: live_admin.ClientAdmin = .{
        .io = io,
        .state_callback = loop.stateCallback(),
        .shutdown_callback = shutdownCallback(),
    };
    const socket_path = try std.fs.path.join(allocator, &.{ paths.runtime_dir, "ntcl.sock" });
    defer allocator.free(socket_path);
    try validateRuntimeDirectory(io, paths.runtime_dir, accounts.admin_gid);
    try removeStaleSocket(io, socket_path);
    var ipc = try ipc_server.Server.init(allocator, io, socket_path, accounts.admin_gid, admin.handler());
    defer ipc.deinit();

    try dropPrivilegesIfNeeded(accounts.user, accounts.admin_gid);
    var data_thread_state: DataThreadState = .{ .worker = &worker };
    const thread = try std.Thread.spawn(.{}, DataThreadState.run, .{&data_thread_state});
    defer {
        linux_platform.lifecycle.requestStop();
        _ = worker.submit(.{ .kind = .remove_session, .receiver_session_id = 0 });
        thread.join();
    }

    try loop.start(monotonicNow(io));
    readiness.ready();
    try runControlLoop(&ipc, &control, null, loop.hook());
    if (data_thread_state.failed.load(.acquire)) return error.DataWorkerFailed;
}

const Accounts = struct {
    user: linux_platform.account.User,
    admin_gid: std.Io.File.Gid,
};

fn runtimeAccounts(allocator: std.mem.Allocator, io: std.Io) !Accounts {
    return .{
        .user = try linux_platform.account.lookupUser(allocator, io, linux_platform.lifecycle.service_user),
        .admin_gid = @intCast(try linux_platform.account.lookupGroup(allocator, io, linux_platform.lifecycle.admin_group)),
    };
}

fn dropPrivilegesIfNeeded(user: linux_platform.account.User, admin_gid: std.Io.File.Gid) !void {
    const current = std.os.linux.geteuid();
    if (current == user.uid) return;
    if (current != 0) return error.ServiceIdentityMismatch;
    try linux_platform.lifecycle.dropToServiceUser(user.uid, user.gid, @intCast(admin_gid));
}

const DataThreadState = struct {
    worker: *data_worker.DataWorker,
    failed: std.atomic.Value(bool) = .init(false),

    fn run(self: *DataThreadState) void {
        self.worker.run() catch {
            self.failed.store(true, .release);
            linux_platform.lifecycle.requestStop();
        };
    }
};

const GenerationNotice = struct {
    changed: std.atomic.Value(bool) = .init(false),
    generation: std.atomic.Value(u64) = .init(0),

    fn callback(self: *GenerationNotice) live_admin.GenerationCallback {
        return .{ .context = self, .changed_fn = changedFn };
    }

    fn changedFn(raw: *anyopaque, generation: u64) void {
        const self: *GenerationNotice = @ptrCast(@alignCast(raw));
        self.generation.store(generation, .release);
        self.changed.store(true, .release);
    }
};

const SnapshotInstaller = struct {
    allocator: std.mem.Allocator,
    store: *const model.Store,
    worker: *data_worker.DataWorker,
    notice: *GenerationNotice,
    routes: linux_platform.routes.Controller,
    interface_name: []const u8,
    mtu: u16,
    installed_vnrs: std.ArrayList(model.Cidr) = .empty,
    installed_routes: std.ArrayList(model.Cidr) = .empty,
    in_flight: bool = false,
    expected_generation: u64 = 0,
    acknowledgement_mismatch: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        store: *const model.Store,
        worker: *data_worker.DataWorker,
        notice: *GenerationNotice,
        routes: linux_platform.routes.Controller,
        interface_name: []const u8,
        mtu: u16,
    ) !SnapshotInstaller {
        var self: SnapshotInstaller = .{
            .allocator = allocator,
            .store = store,
            .worker = worker,
            .notice = notice,
            .routes = routes,
            .interface_name = interface_name,
            .mtu = mtu,
        };
        errdefer self.deinit();
        for (store.vnrs.items) |vnr| try self.installed_vnrs.append(allocator, vnr.range);
        for (store.routes.items) |route| try self.installed_routes.append(allocator, route.prefix);
        return self;
    }

    fn deinit(self: *SnapshotInstaller) void {
        self.installed_vnrs.deinit(self.allocator);
        self.installed_routes.deinit(self.allocator);
    }

    fn observer(self: *SnapshotInstaller) control_plane.SnapshotObserver {
        return .{ .context = self, .installed_fn = installedFn };
    }

    fn poll(self: *SnapshotInstaller) !void {
        if (self.acknowledgement_mismatch) return error.SnapshotAcknowledgementMismatch;
        if (self.in_flight) return;
        if (!self.notice.changed.swap(false, .acq_rel)) return;

        const generation = self.notice.generation.load(.acquire);
        try self.reconcileKernel();
        const snapshot = try topology.createMaster(self.allocator, self.store, &.{});
        if (!self.worker.submit(data_worker.DataCommand.installMasterSnapshot(snapshot, generation))) {
            snapshot.destroy();
            // Queue pressure is transient. Coalesce further changes and retry
            // the newest durable generation on the next control-loop tick.
            self.notice.changed.store(true, .release);
            return;
        }
        self.expected_generation = generation;
        self.in_flight = true;
    }

    fn reconcileKernel(self: *SnapshotInstaller) !void {
        for (self.store.vnrs.items) |vnr| {
            var address_buffer: [15]u8 = undefined;
            var cidr_buffer: [18]u8 = undefined;
            const cidr = try std.fmt.bufPrint(&cidr_buffer, "{s}/{d}", .{
                try vnr.masterAddress().write(&address_buffer),
                vnr.range.prefix,
            });
            try self.routes.replaceAddress(self.interface_name, cidr);
        }
        for (self.installed_vnrs.items) |old| {
            if (storeHasVnr(self.store, old)) continue;
            var address_buffer: [15]u8 = undefined;
            var cidr_buffer: [18]u8 = undefined;
            const cidr = try std.fmt.bufPrint(&cidr_buffer, "{s}/{d}", .{
                try old.firstUsable().?.write(&address_buffer),
                old.prefix,
            });
            try self.routes.deleteAddress(self.interface_name, cidr);
        }
        for (self.store.routes.items) |route| {
            var buffer: [18]u8 = undefined;
            try self.routes.replaceRoute(self.interface_name, try route.prefix.write(&buffer), self.mtu);
        }
        for (self.installed_routes.items) |old| {
            if (storeHasRoute(self.store, old)) continue;
            var buffer: [18]u8 = undefined;
            try self.routes.deleteRoute(self.interface_name, try old.write(&buffer));
        }
        self.installed_vnrs.clearRetainingCapacity();
        self.installed_routes.clearRetainingCapacity();
        for (self.store.vnrs.items) |vnr| try self.installed_vnrs.append(self.allocator, vnr.range);
        for (self.store.routes.items) |route| try self.installed_routes.append(self.allocator, route.prefix);
    }

    fn installedFn(raw: *anyopaque, generation: u64, retired: ?*topology.MasterSnapshots) void {
        const self: *SnapshotInstaller = @ptrCast(@alignCast(raw));
        if (retired) |snapshot| snapshot.destroy();
        if (!self.in_flight or generation != self.expected_generation) {
            self.acknowledgement_mismatch = true;
            return;
        }
        self.in_flight = false;
        std.log.info("installed durable forwarding generation {d}", .{generation});
    }
};

fn shutdownCallback() live_admin.ShutdownCallback {
    return .{ .context = &shutdown_context, .request_fn = requestShutdown };
}

fn requestShutdown(_: *anyopaque) void {
    linux_platform.lifecycle.requestStop();
}

fn runControlLoop(
    ipc: *ipc_server.Server,
    control: *control_plane.ControlPlane,
    snapshot_installer: ?*SnapshotInstaller,
    hook: LoopHook,
) !void {
    const linux = std.os.linux;
    const created = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    switch (linux.errno(created)) {
        .SUCCESS => {},
        else => return error.EpollCreateFailed,
    }
    const epoll_fd: i32 = @intCast(created);
    defer _ = linux.close(epoll_fd);
    var event: linux.epoll_event = .{
        .events = linux.EPOLL.IN | linux.EPOLL.ERR | linux.EPOLL.HUP,
        .data = .{ .fd = ipc.listener.handle() },
    };
    switch (linux.errno(linux.epoll_ctl(epoll_fd, linux.EPOLL.CTL_ADD, ipc.listener.handle(), &event))) {
        .SUCCESS => {},
        else => return error.EpollAddFailed,
    }

    var events: [4]linux.epoll_event = undefined;
    while (!linux_platform.lifecycle.shouldStop()) {
        const now_ns = monotonicNow(control.io);
        control.poll(now_ns);
        try hook.tick(now_ns);
        if (snapshot_installer) |installer| try installer.poll();
        const result = linux.epoll_wait(epoll_fd, &events, events.len, 100);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.EpollWaitFailed,
        }
        const count: usize = @intCast(result);
        for (events[0..count]) |ready_event| {
            if (ready_event.data.fd != ipc.listener.handle()) continue;
            ipc.serveOne() catch |err| std.log.warn("local IPC request failed: {s}", .{@errorName(err)});
        }
    }
}

const LoopHook = struct {
    context: *anyopaque,
    tick_fn: *const fn (*anyopaque, u64) anyerror!void,

    fn tick(self: LoopHook, now_ns: u64) !void {
        return self.tick_fn(self.context, now_ns);
    }
};

const MasterLoop = struct {
    coordinator: *handshake_coordinator.MasterCoordinator,
    publisher: *configuration_runtime.MasterPublisher,
    retry_rotator: *RetryRotator,

    fn hook(self: *MasterLoop) LoopHook {
        return .{ .context = self, .tick_fn = tickOpaque };
    }

    fn tickOpaque(raw: *anyopaque, now_ns: u64) !void {
        const self: *MasterLoop = @ptrCast(@alignCast(raw));
        self.coordinator.tick(now_ns);
        try self.publisher.tick(now_ns);
        try self.retry_rotator.tick(self.coordinator, now_ns);
    }
};

const NodeLoop = struct {
    io: std.Io,
    coordinator: *handshake_coordinator.NodeCoordinator,
    applier: *configuration_runtime.NodeApplier,
    persistent: *state.client.PersistentState,
    endpoint: std.Io.net.IpAddress,
    identity: @import("../protocol/noise.zig").KeyPair,
    master_public: [32]u8,
    credential: ?protocol_credential.Credential,
    recovery_attempted: bool = false,
    reconnect: ReconnectBackoff = .{},

    fn deinit(self: *NodeLoop) void {
        self.clearCredential();
        std.crypto.secureZero(u8, &self.identity.secret);
    }

    fn hook(self: *NodeLoop) LoopHook {
        return .{ .context = self, .tick_fn = tickOpaque };
    }

    fn stateCallback(self: *NodeLoop) live_admin.ClientStateCallback {
        return .{ .context = self, .state_fn = stateOpaque };
    }

    fn start(self: *NodeLoop, now_ns: u64) !void {
        if (self.coordinator.inProgress()) return;
        if (self.persistent.enrollment_state == .enrolled) {
            const node_id = self.persistent.node_id orelse return error.MissingPersistentAssignment;
            return self.coordinator.beginSession(
                self.endpoint,
                node_id.bytes,
                self.identity,
                self.master_public,
                now_ns,
            );
        }
        if (self.persistent.node_id) |node_id| {
            if (!self.recovery_attempted) {
                self.recovery_attempted = true;
                return self.coordinator.beginRecovery(
                    self.endpoint,
                    node_id.bytes,
                    self.identity,
                    self.master_public,
                    now_ns,
                );
            }
        }
        const credential = if (self.credential) |*value| value else return error.EnrollmentCredentialUnavailable;
        return self.coordinator.beginEnrollment(self.endpoint, credential, self.identity, now_ns);
    }

    fn tickOpaque(raw: *anyopaque, now_ns: u64) !void {
        const self: *NodeLoop = @ptrCast(@alignCast(raw));
        const attempt_was_in_progress = self.coordinator.inProgress();
        self.coordinator.tick(now_ns);
        try self.applier.tick(now_ns);
        if (self.persistent.enrollment_state == .enrolled) self.clearCredential();
        if (self.coordinator.inProgress()) return;
        if (attempt_was_in_progress) self.scheduleReconnect(now_ns);
        if (self.coordinator.activeReceiver()) |receiver_id| {
            switch (self.applier.control.peerState(receiver_id) orelse .offline) {
                .online, .suspect => {
                    self.reconnect.reset();
                    return;
                },
                .awaiting_confirmation => return,
                .rekey_required => {
                    if (!self.reconnect.ready(now_ns)) return;
                    const node_id = self.persistent.node_id orelse return error.MissingPersistentAssignment;
                    self.coordinator.beginRekey(
                        self.endpoint,
                        node_id.bytes,
                        self.identity,
                        self.master_public,
                        now_ns,
                    ) catch |err| switch (err) {
                        error.CommandQueueFull => self.scheduleReconnect(now_ns),
                        else => return err,
                    };
                    return;
                },
                .offline => {},
            }
        }
        if (!self.reconnect.ready(now_ns)) return;
        self.start(now_ns) catch |err| switch (err) {
            error.CommandQueueFull => self.scheduleReconnect(now_ns),
            else => return err,
        };
    }

    fn clearCredential(self: *NodeLoop) void {
        if (self.credential) |*credential| credential.deinit();
        self.credential = null;
    }

    fn scheduleReconnect(self: *NodeLoop, now_ns: u64) void {
        var random: u32 = undefined;
        self.io.random(std.mem.asBytes(&random));
        self.reconnect.schedule(now_ns, random);
    }

    fn stateOpaque(raw: *anyopaque) []const u8 {
        const self: *NodeLoop = @ptrCast(@alignCast(raw));
        if (self.coordinator.activeReceiver()) |receiver_id| {
            return switch (self.applier.control.peerState(receiver_id) orelse .offline) {
                .online => "online",
                .suspect => "suspect",
                .rekey_required => "rekeying",
                .awaiting_confirmation => "connecting",
                .offline => "reconnecting",
            };
        }
        if (self.persistent.enrollment_state == .enrolled) return "connecting";
        if (self.persistent.node_id != null and self.recovery_attempted) return "recovering";
        return "enrolling";
    }
};

const ReconnectBackoff = struct {
    const initial_ns: u64 = 500 * std.time.ns_per_ms;
    const maximum_ns: u64 = 30 * std.time.ns_per_s;

    delay_ns: u64 = initial_ns,
    next_attempt_ns: u64 = 0,

    fn ready(self: ReconnectBackoff, now_ns: u64) bool {
        return now_ns >= self.next_attempt_ns;
    }

    fn reset(self: *ReconnectBackoff) void {
        self.* = .{};
    }

    fn schedule(self: *ReconnectBackoff, now_ns: u64, random: u32) void {
        const jitter_window = self.delay_ns / 4;
        const jitter = if (jitter_window == 0) 0 else @as(u64, random) % (jitter_window + 1);
        self.next_attempt_ns = now_ns +| self.delay_ns +| jitter;
        self.delay_ns = @min(self.delay_ns *| 2, maximum_ns);
    }
};

const RetryRotator = struct {
    io: std.Io,
    current_secret: [32]u8,
    previous_secret: [32]u8,
    epoch: u64,
    required: bool = false,
    admission: AdmissionPressure = .{},

    fn init(io: std.Io) !RetryRotator {
        var current: [32]u8 = undefined;
        var previous: [32]u8 = undefined;
        io.random(&current);
        io.random(&previous);
        return .{
            .io = io,
            .current_secret = current,
            .previous_secret = previous,
            .epoch = protocol_cookie.epochFromUnixSeconds(try unixSeconds(io)),
        };
    }

    fn deinit(self: *RetryRotator) void {
        std.crypto.secureZero(u8, &self.current_secret);
        std.crypto.secureZero(u8, &self.previous_secret);
    }

    fn policy(self: *const RetryRotator, required: bool) handshake_coordinator.RetryPolicy {
        return .{
            .verifier = .{
                .current_secret = self.current_secret,
                .previous_secret = self.previous_secret,
                .current_epoch = self.epoch,
            },
            .required = required,
        };
    }

    fn tick(self: *RetryRotator, coordinator: *handshake_coordinator.MasterCoordinator, now_ns: u64) !void {
        var changed = false;
        const epoch = protocol_cookie.epochFromUnixSeconds(try unixSeconds(self.io));
        if (epoch != self.epoch) {
            std.crypto.secureZero(u8, &self.previous_secret);
            self.previous_secret = self.current_secret;
            self.io.random(&self.current_secret);
            self.epoch = epoch;
            changed = true;
        }
        const required = self.admission.update(
            now_ns,
            coordinator.admissionSnapshot(),
            coordinator.activeCount(),
            coordinator.slots.len,
        );
        if (required != self.required) {
            self.required = required;
            changed = true;
        }
        if (changed) coordinator.updateRetryPolicy(self.policy(self.required));
    }
};

const AdmissionPressure = struct {
    const sample_interval_ns: u64 = 100 * std.time.ns_per_ms;
    const request_burst_threshold: u64 = 32;
    const authentication_failure_threshold: u64 = 8;
    const hold_ns: u64 = 30 * std.time.ns_per_s;

    last_sample_ns: u64 = 0,
    last_requests: u64 = 0,
    last_failures: u64 = 0,
    required_until_ns: u64 = 0,

    fn update(
        self: *AdmissionPressure,
        now_ns: u64,
        snapshot: handshake_coordinator.AdmissionSnapshot,
        active: usize,
        capacity: usize,
    ) bool {
        const slot_threshold = @max(@as(usize, 1), (capacity * 3) / 4);
        const slot_pressure = active >= slot_threshold;

        if (self.last_sample_ns == 0) {
            self.last_sample_ns = now_ns;
            self.last_requests = snapshot.initial_requests;
            self.last_failures = snapshot.authentication_failures;
        } else if (now_ns -| self.last_sample_ns >= sample_interval_ns) {
            const requests = snapshot.initial_requests -| self.last_requests;
            const failures = snapshot.authentication_failures -| self.last_failures;
            self.last_sample_ns = now_ns;
            self.last_requests = snapshot.initial_requests;
            self.last_failures = snapshot.authentication_failures;
            if (requests >= request_burst_threshold or failures >= authentication_failure_threshold) {
                self.required_until_ns = now_ns +| hold_ns;
            }
        }
        return slot_pressure or now_ns < self.required_until_ns;
    }
};

const MasterRuntimeView = struct {
    coordinator: *handshake_coordinator.MasterCoordinator,
    control: *control_plane.ControlPlane,

    fn lookup(self: *MasterRuntimeView) cli_view.RuntimeLookup {
        return .{ .context = self, .lookup_fn = lookupOpaque };
    }

    fn lookupOpaque(raw: *anyopaque, node: model.Node, endpoint_buffer: []u8) cli_view.RuntimeNode {
        const self: *MasterRuntimeView = @ptrCast(@alignCast(raw));
        const receiver_id = self.coordinator.activeReceiverFor(node.id.bytes) orelse return .{
            .state = if (node.enrollment_state == .enrolled) "offline" else "unenrolled",
            .online = false,
        };
        const peer_state = self.control.peerState(receiver_id) orelse .offline;
        const endpoint_text = if (self.control.peerEndpoint(receiver_id)) |observed|
            formatEndpoint(observed, endpoint_buffer)
        else
            null;
        return .{
            .state = switch (peer_state) {
                .online => "online",
                .suspect => "suspect",
                .rekey_required => "rekeying",
                .awaiting_confirmation => "connecting",
                .offline => "offline",
            },
            .online = peer_state == .online or peer_state == .suspect or peer_state == .rekey_required,
            .traffic_state = if (self.control.peerTrafficState(receiver_id)) |traffic_state| @tagName(traffic_state) else null,
            .endpoint = endpoint_text,
        };
    }
};

fn formatEndpoint(value: protocol_endpoint.Endpoint, buffer: []u8) ?[]const u8 {
    const address: std.Io.net.IpAddress = switch (value.family) {
        .ipv4 => .{ .ip4 = .{ .bytes = value.address[0..4].*, .port = value.port } },
        .ipv6 => .{ .ip6 = .{ .bytes = value.address, .port = value.port } },
    };
    return std.fmt.bufPrint(buffer, "{f}", .{address}) catch null;
}

fn unixSeconds(io: std.Io) !u64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.ClockBeforeUnixEpoch;
    return @intCast(seconds);
}

fn retireMasterAssociation(raw: *anyopaque, node_uuid: [16]u8) void {
    const coordinator: *handshake_coordinator.MasterCoordinator = @ptrCast(@alignCast(raw));
    coordinator.retireAssociation(node_uuid);
}

fn readBounded(allocator: std.mem.Allocator, io: std.Io, path: []const u8, limit: usize) ![]u8 {
    var file = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false })
    else
        try std.Io.Dir.cwd().openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    const metadata = try file.stat(io);
    if (metadata.kind != .file or metadata.permissions.toMode() & 0o022 != 0) {
        return error.InsecureConfigFile;
    }
    try validateHandleIdentity(file.handle, 0, null);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(limit)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |other| return other,
    };
}

fn openPrivateDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    _ = try std.Io.Dir.cwd().createDirPathStatus(io, path, state.atomic_file.private_dir_permissions);
    const dir = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.openDirAbsolute(io, path, .{})
    else
        try std.Io.Dir.cwd().openDir(io, path, .{});
    errdefer dir.close(io);
    const stat = try dir.stat(io);
    if (stat.kind != .directory or stat.permissions.toMode() & 0o077 != 0) return error.InsecureStateDirectory;
    return dir;
}

fn validateRuntimeDirectory(io: std.Io, path: []const u8, admin_gid: u32) !void {
    var dir = if (std.fs.path.isAbsolute(path))
        try std.Io.Dir.openDirAbsolute(io, path, .{ .follow_symlinks = false })
    else
        try std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false });
    defer dir.close(io);
    try validateDirectoryIdentity(dir, io, 0, admin_gid, 0o770);
}

fn validateDirectoryIdentity(
    dir: std.Io.Dir,
    io: std.Io,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: std.posix.mode_t,
) !void {
    const metadata = try dir.stat(io);
    if (metadata.kind != .directory or metadata.permissions.toMode() & 0o777 != expected_mode) {
        return error.InsecureDirectoryMetadata;
    }
    try validateHandleIdentity(dir.handle, expected_uid, expected_gid);
}

fn validateHandleIdentity(handle: std.posix.fd_t, expected_uid: u32, expected_gid: ?u32) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const request: linux.STATX = .{ .UID = true, .GID = true };
    var metadata = std.mem.zeroes(linux.Statx);
    switch (linux.errno(linux.statx(handle, "", linux.AT.EMPTY_PATH, request, &metadata))) {
        .SUCCESS => {},
        else => return error.MetadataLookupFailed,
    }
    if (metadata.uid != expected_uid) return error.InsecureOwner;
    if (expected_gid) |gid| if (metadata.gid != gid) return error.InsecureOwner;
}

fn removeStaleSocket(io: std.Io, path: []const u8) !void {
    const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind != .unix_domain_socket) return error.InvalidRuntimeEntry;
    // The lifetime state lock is already held, so no live peer can own this
    // pathname. It is necessarily residue from an unclean exit.
    try std.Io.Dir.cwd().deleteFile(io, path);
}

fn configureMasterRoutes(
    controller: linux_platform.routes.Controller,
    interface_name: []const u8,
    mtu: u16,
    store: *const model.Store,
) !void {
    for (store.vnrs.items) |vnr| {
        var address_buffer: [15]u8 = undefined;
        var cidr_buffer: [18]u8 = undefined;
        const cidr = try std.fmt.bufPrint(&cidr_buffer, "{s}/{d}", .{
            try vnr.masterAddress().write(&address_buffer),
            vnr.range.prefix,
        });
        try controller.addAddress(interface_name, cidr);
    }
    for (store.routes.items) |route| {
        var buffer: [18]u8 = undefined;
        try controller.addRoute(interface_name, try route.prefix.write(&buffer), mtu);
    }
}

fn warnNetworkPrerequisites(
    controller: linux_platform.routes.Controller,
    interface_name: []const u8,
    forwarding_required: bool,
) void {
    if (forwarding_required) {
        const enabled = controller.forwardingEnabled() catch |err| {
            std.log.warn("could not inspect net.ipv4.ip_forward ({s})", .{@errorName(err)});
            return;
        };
        if (!enabled) {
            std.log.warn("IPv4 forwarding is disabled; Node-to-Node and routed-prefix forwarding will not work", .{});
        }
    }
    const all_filter = controller.allReversePathFilter() catch |err| {
        std.log.warn("could not inspect net.ipv4.conf.all.rp_filter ({s})", .{@errorName(err)});
        return;
    };
    const interface_filter = controller.reversePathFilter(interface_name) catch |err| {
        std.log.warn("could not inspect rp_filter for {s} ({s})", .{ interface_name, @errorName(err) });
        return;
    };
    if (all_filter == 1 or interface_filter == 1) {
        std.log.warn("strict reverse-path filtering may reject valid NTIP traffic (all={d}, {s}={d})", .{
            all_filter,
            interface_name,
            interface_filter,
        });
    }
}

fn configureInitialClientRoutes(
    controller: linux_platform.routes.Controller,
    interface_name: []const u8,
    mtu: u16,
    client_state: state.client.PersistentState,
) !void {
    const address = client_state.assigned_address orelse return;
    const range = client_state.vnr_range.?;
    var address_buffer: [15]u8 = undefined;
    var cidr_buffer: [18]u8 = undefined;
    const address_cidr = try std.fmt.bufPrint(&cidr_buffer, "{s}/32", .{try address.write(&address_buffer)});
    try controller.addAddress(interface_name, address_cidr);
    var range_buffer: [18]u8 = undefined;
    try controller.addRoute(interface_name, try range.write(&range_buffer), mtu);
}

fn initialClientForwarding(
    allocator: std.mem.Allocator,
    client_state: state.client.PersistentState,
) !forwarding.Snapshot {
    const range = client_state.vnr_range orelse return forwarding.Snapshot.init(allocator, &.{});
    return forwarding.Snapshot.init(allocator, &.{.{
        .network = range.network.value,
        .prefix_len = range.prefix,
        .owner = master_owner,
        .receiver_session_id = 0,
    }});
}

fn initialClientDestinations(
    allocator: std.mem.Allocator,
    client_state: state.client.PersistentState,
) !authorization.Snapshot {
    const address = client_state.assigned_address orelse return authorization.Snapshot.init(allocator, &.{});
    return authorization.Snapshot.init(allocator, &.{.{
        .owner = local_owner,
        .network = address.value,
        .prefix_len = 32,
    }});
}

fn sessionTableCapacity(maximum_nodes: u32) usize {
    const associations: usize = maximum_nodes;
    // Keep enough load-factor headroom for a current and one draining receive
    // session per Node during full rekey.
    return std.math.mul(usize, associations, 4) catch associations;
}

fn storeHasVnr(store: *const model.Store, range: model.Cidr) bool {
    for (store.vnrs.items) |vnr| {
        if (vnr.range.network.value == range.network.value and vnr.range.prefix == range.prefix) return true;
    }
    return false;
}

fn storeHasRoute(store: *const model.Store, prefix: model.Cidr) bool {
    for (store.routes.items) |route| {
        if (route.prefix.network.value == prefix.network.value and route.prefix.prefix == prefix.prefix) return true;
    }
    return false;
}

fn monotonicNow(io: std.Io) u64 {
    const raw = std.Io.Clock.now(.awake, io).nanoseconds;
    return if (raw <= 0) 0 else @intCast(@min(raw, std.math.maxInt(u64)));
}

const master_owner: u128 = 1;
const local_owner: u128 = 2;
var shutdown_context: u8 = 0;

test "client initial snapshots remain offline until a session is installed" {
    const client_state: state.client.PersistentState = .{
        .enrollment_state = .enrolled,
        .node_id = .{ .bytes = .{1} ** 16 },
        .assigned_address = try model.Ipv4.parse("10.1.0.2"),
        .vnr_range = try model.Cidr.parse("10.1.0.0/24"),
    };
    var routes = try initialClientForwarding(std.testing.allocator, client_state);
    defer routes.deinit();
    try std.testing.expectEqual(@as(u64, 0), routes.lookup(0x0a010003).?.receiver_session_id);
}

test "retry-cookie admission reacts to bursts failures and slot pressure" {
    var pressure: AdmissionPressure = .{};
    const start = std.time.ns_per_s;
    try std.testing.expect(!pressure.update(start, .{
        .initial_requests = 0,
        .authentication_failures = 0,
    }, 0, 100));

    try std.testing.expect(pressure.update(start + AdmissionPressure.sample_interval_ns, .{
        .initial_requests = AdmissionPressure.request_burst_threshold,
        .authentication_failures = 0,
    }, 0, 100));
    try std.testing.expect(pressure.update(start + AdmissionPressure.hold_ns, .{
        .initial_requests = AdmissionPressure.request_burst_threshold,
        .authentication_failures = 0,
    }, 0, 100));
    try std.testing.expect(!pressure.update(start + AdmissionPressure.hold_ns + AdmissionPressure.sample_interval_ns, .{
        .initial_requests = AdmissionPressure.request_burst_threshold,
        .authentication_failures = 0,
    }, 0, 100));

    try std.testing.expect(pressure.update(start + AdmissionPressure.hold_ns + 2 * AdmissionPressure.sample_interval_ns, .{
        .initial_requests = AdmissionPressure.request_burst_threshold,
        .authentication_failures = AdmissionPressure.authentication_failure_threshold,
    }, 0, 100));
    try std.testing.expect(pressure.update(start + 2 * AdmissionPressure.hold_ns, .{
        .initial_requests = AdmissionPressure.request_burst_threshold,
        .authentication_failures = AdmissionPressure.authentication_failure_threshold,
    }, 75, 100));
}

test "Node reconnect backoff is bounded jittered and resettable" {
    var backoff: ReconnectBackoff = .{};
    const start = std.time.ns_per_s;
    try std.testing.expect(backoff.ready(start));
    backoff.schedule(start, 0);
    try std.testing.expectEqual(start + ReconnectBackoff.initial_ns, backoff.next_attempt_ns);
    try std.testing.expect(!backoff.ready(backoff.next_attempt_ns - 1));
    try std.testing.expect(backoff.ready(backoff.next_attempt_ns));
    try std.testing.expectEqual(2 * ReconnectBackoff.initial_ns, backoff.delay_ns);

    var index: usize = 0;
    while (index < 16) : (index += 1) backoff.schedule(backoff.next_attempt_ns, std.math.maxInt(u32));
    try std.testing.expectEqual(ReconnectBackoff.maximum_ns, backoff.delay_ns);
    backoff.reset();
    try std.testing.expectEqual(ReconnectBackoff.initial_ns, backoff.delay_ns);
    try std.testing.expectEqual(@as(u64, 0), backoff.next_attempt_ns);
}
