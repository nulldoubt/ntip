//! Linux runtime assembly for the two public executables.
//!
//! Startup remains deliberately explicit: acquire the lifetime lock, parse all
//! durable state, create only NTIP-owned kernel resources, drop privileges,
//! report readiness, then enter the control loop. Closing the exclusive,
//! non-persistent TUN descriptor is the rollback mechanism for addresses and
//! dependent routes installed on `ntip0`.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const linux_platform = @import("../platform/linux/root.zig");
const state = @import("../state/root.zig");
const model = @import("../domain/model.zig");
const topology = @import("topology.zig");
const forwarding = @import("forwarding.zig");
const authorization = @import("authorization.zig");
const data_plane = @import("data_plane.zig");
const data_worker = @import("data_worker.zig");
const connectivity = @import("connectivity.zig");
const connectivity_runtime = @import("connectivity_runtime.zig");
const control_plane = @import("control_plane.zig");
const ipc_server = @import("ipc_server.zig");
const live_admin = @import("live_admin.zig");
const endpoint = @import("endpoint.zig");
const handshake_coordinator = @import("handshake_coordinator.zig");
const configuration_runtime = @import("configuration_runtime.zig");
const settings_runtime = @import("settings_runtime.zig");
const runtime_event_recorder = @import("runtime_event_recorder.zig");
const service_state = @import("service_state.zig");
const sqlite_registry = @import("sqlite_registry.zig");
const server_application = @import("../management/server_application.zig");
const service_server = @import("../management/service_server.zig");
const auth_application = @import("../management/auth_application.zig");
const api_application = @import("../management/api_application.zig");
const enrollment_service = @import("../management/enrollment_service.zig");
const inventory_service = @import("../management/inventory_service.zig");
const operations_service = @import("../management/operations_service.zig");
const read_models_service = @import("../management/read_models_service.zig");
const management_settings = @import("../management/settings.zig");
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

    const config_bytes = try readBounded(allocator, io, paths.config, state.config.max_server_bootstrap_bytes);
    defer allocator.free(config_bytes);
    const parsed_bootstrap = try state.config.decodeServerBootstrap(allocator, config_bytes);
    defer parsed_bootstrap.deinit();
    const bootstrap = parsed_bootstrap.value;
    const accounts = try runtimeAccounts(allocator, io);
    const api_account = try runtimeApiAccount(allocator, io);
    try validateIdentitySeparation(accounts, api_account);

    var state_dir = try openPrivateDirectory(io, paths.state_dir);
    defer state_dir.close(io);
    try validateDirectoryIdentity(state_dir, io, accounts.user.uid, accounts.user.gid, 0o700);
    var lifetime_lock = try state.atomic_file.LifetimeLock.acquire(state_dir, io, "state.lock", true);
    defer lifetime_lock.release(io);

    var sqlite_owner = try state.sqlite_repository.Repository.open(allocator, io, state_dir);
    defer sqlite_owner.deinit();
    var repository = state.management_repository.Repository.init(&sqlite_owner.db);
    var store = try repository.loadInventory(allocator);
    defer store.deinit();
    var settings_repository = state.settings_repository.Repository.init(&sqlite_owner.db);
    const settings_state = try settings_repository.loadState();
    const operational = try startupOperationalSettings(settings_state, store.nodes.items.len);
    var config = runtimeServerConfig(bootstrap, operational);
    var identity = try state.identity.loadOrCreate(allocator, io, state_dir);
    defer std.crypto.secureZero(u8, &identity.secret);
    var idempotency_request_hash_key = state.idempotency_repository.deriveRequestHashKey(&identity.secret);
    defer std.crypto.secureZero(u8, &idempotency_request_hash_key);

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
    var runtime_barrier_acknowledgements = try data_worker.RuntimeBarrierAcknowledgementQueue.init(allocator, 2);
    defer runtime_barrier_acknowledgements.deinit();
    var data_commands = try data_worker.CommandQueue.init(allocator, 4096);
    defer data_commands.deinit();
    var retirements = try data_worker.RetirementQueue.init(allocator, sessionTableCapacity(config.maximum_nodes));
    defer retirements.deinit();
    var connectivity_channel = try connectivity.Channel.init(allocator, connectivity_runtime.production_capacity);
    defer connectivity_channel.deinit();
    var worker = try data_worker.DataWorker.init(io, &tun, &udp, &plane, &control_events, &data_commands, &retirements);
    defer worker.deinit();
    try worker.attachConnectivityChannel(&connectivity_channel);
    try worker.attachRuntimeBarrierAcknowledgements(&runtime_barrier_acknowledgements);
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

    var snapshot_installer = try SnapshotInstaller.init(
        allocator,
        &store,
        &worker,
        &control,
        &runtime_barrier_acknowledgements,
        routes,
        config.tun_name,
        config.inner_mtu,
    );
    const runtime_capacity: usize = @intCast(config.maximum_nodes);
    var publisher = try configuration_runtime.MasterPublisher.init(
        allocator,
        &control,
        &store,
        &config,
        runtime_capacity,
    );
    control.setConfigurationObserver(publisher.observer());
    var registry_adapter = sqlite_registry.MasterRegistryAdapter.init(io, &sqlite_owner.db, &store);
    registry_adapter.publisher = snapshot_installer.sqlitePublisher();
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
    var runtime_view: MasterRuntimeView = .{
        .coordinator = &coordinator,
        .control = &control,
        .store = &store,
    };
    defer {
        control.deinit();
        coordinator.deinit();
        publisher.deinit();
        snapshot_installer.deinit();
        retry_rotator.deinit();
    }
    var admin = try server_application.Application.init(
        allocator,
        io,
        repository,
        &store,
        identity.public,
        operational,
        build_options.version,
    );
    admin.generation_callback = snapshot_installer.applicationCallback();
    admin.association_callback = .{ .context = &coordinator, .retire_fn = retireMasterAssociation };
    admin.runtime_lookup = runtime_view.lookup();
    admin.shutdown_callback = applicationShutdownCallback();

    var api_callbacks: ApiInventoryCallbacks = .{
        .coordinator = &coordinator,
        .snapshot_installer = &snapshot_installer,
    };
    var inventory = inventory_service.Service.init(
        &repository,
        &store,
        allocator,
        io,
        .{
            .context = &api_callbacks,
            .retire_associations = ApiInventoryCallbacks.retire,
            .publish_generation = ApiInventoryCallbacks.publish,
        },
    );
    inventory.setMaximumNodesSource(&config.maximum_nodes);
    var enrollment = try enrollment_service.Service.init(
        &repository,
        &store,
        allocator,
        io,
        identity.public,
        .{
            .context = &api_callbacks,
            .retire_associations = ApiInventoryCallbacks.retire,
            .publish_generation = ApiInventoryCallbacks.publish,
        },
    );
    var read_models = try read_models_service.Service.init(
        allocator,
        &inventory,
        &settings_repository,
        runtime_view.runtimeSource(),
    );
    var authentication = try auth_application.Application.initProduction(
        allocator,
        io,
        state.access_repository.Repository.init(&sqlite_owner.db),
    );
    defer authentication.deinit();
    var operations_repository = state.operations_repository.Repository.init(&sqlite_owner.db);
    _ = try operations_repository.interruptActiveConnectivityChecks(try wallSeconds(io));
    var connectivity_dispatcher: connectivity_runtime.Dispatcher = .{
        .io = io,
        .store = &store,
        .sink = connectivity_runtime.RequestSink.fromWorker(&worker),
    };
    var connectivity_recorder: connectivity_runtime.CompletionRecorder = .{
        .io = io,
        .repository = operations_repository,
        .source = connectivity_runtime.CompletionSource.fromWorker(&worker),
    };
    var operations_control: operations_service.ControlState = .{
        .instance_id = randomUuid(io),
        .managed_restart_supported = managedRestartSupported(),
    };
    var runtime_events = try runtime_event_recorder.Recorder.init(
        allocator,
        runtime_view.runtimeSource(),
        &operations_repository,
        operations_control.instance_id,
        .{ .maximum_nodes = runtime_capacity },
    );
    defer runtime_events.deinit();
    const runtime_event_node_ids = try allocator.alloc(model.NodeId, runtime_capacity);
    defer allocator.free(runtime_event_node_ids);
    var settings_mailbox: settings_runtime.Mailbox = .{};
    const idempotency_store = state.idempotency_repository.Repository.init(&sqlite_owner.db);
    _ = try idempotency_store.recoverInterruptedReservations();
    var effective_settings_context: EffectiveSettingsContext = .{
        .config = &config,
        .store = &store,
        .admin = &admin,
        .snapshot_installer = &snapshot_installer,
        .publisher = &publisher,
    };
    var runtime_settings = settings_runtime.Applier.init(
        io,
        &settings_repository,
        &operations_repository,
        authentication.repository,
        idempotency_store,
        &store,
        &control,
        &worker,
        routes,
        config.tun_name,
        &settings_mailbox,
        effective_settings_context.observer(),
        config.maximum_nodes,
    );
    runtime_settings.attach();
    defer runtime_settings.deinit();
    try runtime_settings.recover(settings_state);
    var operations = operations_service.Service.init(
        allocator,
        io,
        &operations_repository,
        &settings_repository,
        &operations_control,
        connectivity_dispatcher.interface(),
        settings_mailbox.publisher(),
    );
    var api = api_application.Application.init(
        allocator,
        io,
        &authentication,
        &inventory,
        &operations,
        idempotency_store,
        &idempotency_request_hash_key,
    );
    api.setEnrollmentService(&enrollment);
    api.setReadModelsService(&read_models);

    const socket_path = try std.fs.path.join(allocator, &.{ paths.runtime_dir, "ntsrv.sock" });
    defer allocator.free(socket_path);
    try validateRuntimeDirectory(io, paths.runtime_dir, accounts.admin_gid);
    try removeStaleSocket(io, socket_path);
    var ipc = try ipc_server.Server.init(allocator, io, socket_path, accounts.admin_gid, admin.handler());
    defer ipc.deinit();

    try validateServiceSocketDirectory(
        io,
        bootstrap.service_socket_path,
        accounts.user.uid,
        api_account.group_gid,
    );
    try removeStaleSocket(io, bootstrap.service_socket_path);
    var service_ipc_server = try service_server.Server.init(
        allocator,
        io,
        bootstrap.service_socket_path,
        accounts.user.uid,
        api_account.group_gid,
        api_account.user.uid,
        api.handler(),
    );
    defer service_ipc_server.deinit();

    try dropPrivilegesIfNeeded(accounts.user, accounts.admin_gid);
    var data_thread_state: DataThreadState = .{ .worker = &worker };
    const thread = try std.Thread.spawn(.{}, DataThreadState.run, .{&data_thread_state});
    defer {
        linux_platform.lifecycle.requestStop();
        _ = worker.submit(.{ .kind = .remove_session, .receiver_session_id = 0 });
        thread.join();
        _ = connectivity_recorder.poll() catch |err| {
            // The next startup's interrupted-check recovery remains the final
            // safety net if durable shutdown completion cannot be written.
            std.log.warn("could not persist interrupted connectivity checks: {s}", .{@errorName(err)});
        };
    }

    readiness.ready();
    var loop: MasterLoop = .{
        .io = io,
        .store = &store,
        .coordinator = &coordinator,
        .publisher = &publisher,
        .retry_rotator = &retry_rotator,
        .connectivity_recorder = &connectivity_recorder,
        .runtime_settings = &runtime_settings,
        .runtime_events = &runtime_events,
        .runtime_event_node_ids = runtime_event_node_ids,
        .snapshot_installer = &snapshot_installer,
    };
    var export_runtime_checkpoint: ExportRuntimeCheckpoint = .{
        .io = io,
        .control = &control,
        .snapshot_installer = &snapshot_installer,
        .loop = &loop,
    };
    authentication.setAuthProgressCheckpoint(export_runtime_checkpoint.authCheckpoint());
    admin.backup_checkpoint = export_runtime_checkpoint.backupCheckpoint();
    operations.export_checkpoint = export_runtime_checkpoint.checkpoint();
    try runControlLoop(
        &ipc,
        &service_ipc_server,
        &operations_control,
        &control,
        &snapshot_installer,
        loop.hook(),
    );
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
    try runControlLoop(&ipc, null, null, &control, null, loop.hook());
    if (data_thread_state.failed.load(.acquire)) return error.DataWorkerFailed;
}

const Accounts = struct {
    user: linux_platform.account.User,
    admin_gid: std.Io.File.Gid,
};

const ApiAccount = struct {
    user: linux_platform.account.User,
    group_gid: std.Io.File.Gid,
};

fn startupOperationalSettings(
    settings_state: state.settings_repository.State,
    node_count: usize,
) !management_settings.OperationalSettings {
    // Live values always begin from the last acknowledged effective snapshot.
    // A process start is the application boundary for an already
    // restart-pending capacity revision. A mixed revision still waiting for
    // live application uses the old effective capacity; after its live ack it
    // becomes pending_restart and requires one clean restart. This prevents a
    // failed live application from exposing an unacknowledged capacity.
    var selected = settings_state.effective.values;
    if (settings_state.desired.status == .pending_restart) {
        selected.maximum_nodes = settings_state.desired.values.maximum_nodes;
    }
    try selected.validate(node_count);
    return selected;
}

fn runtimeServerConfig(
    bootstrap: state.config.ServerBootstrapConfig,
    settings: management_settings.OperationalSettings,
) state.config.ServerConfig {
    return .{
        // `ServerConfig` remains an internal runtime projection while the only
        // decoded Master file is the strict schema-2 bootstrap above.
        .schema_version = state.config.schema_version,
        .listen_port = bootstrap.listen_port,
        .tun_name = bootstrap.tun_name,
        .inner_mtu = settings.inner_mtu,
        .heartbeat_idle_seconds = settings.heartbeat_idle_seconds,
        .suspect_after_seconds = settings.suspect_after_seconds,
        .offline_after_seconds = settings.offline_after_seconds,
        .default_enrollment_lifetime_seconds = settings.default_enrollment_lifetime_seconds,
        .maximum_nodes = settings.maximum_nodes,
        .traffic = .{
            .cold_after_seconds = settings.traffic_cold_after_seconds,
            .hot_packets_per_second = settings.traffic_hot_packets_per_second,
            .hot_bits_per_second = settings.traffic_hot_bits_per_second,
            .saturated_queue_percent = settings.traffic_saturated_queue_percent,
            .hysteresis_seconds = settings.traffic_hysteresis_seconds,
        },
    };
}

test "startup never treats pending live values as effective" {
    const Revision = state.settings_repository.Revision;
    const makeRevision = struct {
        fn make(
            sequence: u64,
            status: management_settings.RevisionStatus,
            values: management_settings.OperationalSettings,
        ) Revision {
            return .{
                .id = [_]u8{@intCast(sequence)} ** 16,
                .sequence = sequence,
                .based_on_sequence = if (sequence == 1) null else sequence - 1,
                .status = status,
                .failure_code = null,
                .actor_kind = .system,
                .actor_id = null,
                .created_at = 1,
                .applied_at = if (status == .active) 1 else null,
                .values = values,
            };
        }
    }.make;

    const effective = management_settings.OperationalSettings{};
    var desired = effective;
    desired.inner_mtu = 1420;
    desired.maximum_nodes = 8192;
    const pending_live = try startupOperationalSettings(.{
        .desired = makeRevision(2, .pending_apply, desired),
        .effective = makeRevision(1, .active, effective),
    }, 0);
    try std.testing.expectEqual(effective.inner_mtu, pending_live.inner_mtu);
    try std.testing.expectEqual(effective.maximum_nodes, pending_live.maximum_nodes);

    var live_projected = desired;
    live_projected.maximum_nodes = effective.maximum_nodes;
    const pending_restart = try startupOperationalSettings(.{
        .desired = makeRevision(3, .pending_restart, desired),
        .effective = makeRevision(2, .active, live_projected),
    }, 0);
    try std.testing.expectEqual(desired.inner_mtu, pending_restart.inner_mtu);
    try std.testing.expectEqual(desired.maximum_nodes, pending_restart.maximum_nodes);
}

fn randomUuid(io: std.Io) [16]u8 {
    var id: [16]u8 = undefined;
    io.random(&id);
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    return id;
}

fn managedRestartSupported() bool {
    if (comptime builtin.os.tag != .linux or !builtin.link_libc) return false;
    const value = std.c.getenv("INVOCATION_ID") orelse return false;
    return std.mem.span(value).len != 0;
}

fn wallSeconds(io: std.Io) !i64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.ClockBeforeUnixEpoch;
    return seconds;
}

fn runtimeAccounts(allocator: std.mem.Allocator, io: std.Io) !Accounts {
    const user = try linux_platform.account.lookupUser(
        allocator,
        io,
        linux_platform.lifecycle.service_user,
    );
    const service_gid: std.Io.File.Gid = @intCast(try linux_platform.account.lookupGroup(
        allocator,
        io,
        linux_platform.lifecycle.service_user,
    ));
    const admin_gid: std.Io.File.Gid = @intCast(try linux_platform.account.lookupGroup(
        allocator,
        io,
        linux_platform.lifecycle.admin_group,
    ));
    try validateCoreIdentity(user, service_gid, admin_gid);
    return .{ .user = user, .admin_gid = admin_gid };
}

fn runtimeApiAccount(allocator: std.mem.Allocator, io: std.Io) !ApiAccount {
    const user = try linux_platform.account.lookupUser(
        allocator,
        io,
        linux_platform.lifecycle.api_service_user,
    );
    const group_gid: std.Io.File.Gid = @intCast(try linux_platform.account.lookupGroup(
        allocator,
        io,
        linux_platform.lifecycle.api_service_group,
    ));
    try validateApiIdentity(user, group_gid);
    return .{ .user = user, .group_gid = group_gid };
}

fn validateCoreIdentity(
    user: linux_platform.account.User,
    service_gid: std.Io.File.Gid,
    admin_gid: std.Io.File.Gid,
) !void {
    if (user.uid == 0 or service_gid == 0 or admin_gid == 0 or
        user.gid != service_gid or service_gid == admin_gid)
    {
        return error.ServiceIdentityMismatch;
    }
}

fn validateApiIdentity(
    user: linux_platform.account.User,
    group_gid: std.Io.File.Gid,
) !void {
    if (user.uid == 0 or group_gid == 0 or user.gid != group_gid) {
        return error.ServiceIdentityMismatch;
    }
}

fn validateIdentitySeparation(accounts: Accounts, api_account: ApiAccount) !void {
    // Linux credentials are numeric. Distinct account/group names are not a
    // boundary when passwd or group aliases resolve to the same UID/GID.
    if (accounts.user.uid == api_account.user.uid or
        accounts.user.gid == api_account.group_gid or
        accounts.admin_gid == api_account.group_gid)
    {
        return error.ServiceIdentityMismatch;
    }
}

test "service and API credentials require distinct numeric identities" {
    const core: Accounts = .{
        .user = .{ .uid = 980, .gid = 980 },
        .admin_gid = 981,
    };
    const api: ApiAccount = .{
        .user = .{ .uid = 982, .gid = 982 },
        .group_gid = 982,
    };
    try validateCoreIdentity(core.user, core.user.gid, core.admin_gid);
    try validateApiIdentity(api.user, api.group_gid);
    try validateIdentitySeparation(core, api);

    try std.testing.expectError(
        error.ServiceIdentityMismatch,
        validateCoreIdentity(.{ .uid = 980, .gid = 981 }, 980, 981),
    );
    try std.testing.expectError(
        error.ServiceIdentityMismatch,
        validateCoreIdentity(.{ .uid = 980, .gid = 980 }, 980, 980),
    );
    try std.testing.expectError(
        error.ServiceIdentityMismatch,
        validateApiIdentity(.{ .uid = 982, .gid = 981 }, 982),
    );

    var aliased_api = api;
    aliased_api.user.uid = core.user.uid;
    try std.testing.expectError(
        error.ServiceIdentityMismatch,
        validateIdentitySeparation(core, aliased_api),
    );

    aliased_api = api;
    aliased_api.user.gid = core.user.gid;
    aliased_api.group_gid = core.user.gid;
    try std.testing.expectError(
        error.ServiceIdentityMismatch,
        validateIdentitySeparation(core, aliased_api),
    );

    aliased_api = api;
    aliased_api.user.gid = core.admin_gid;
    aliased_api.group_gid = core.admin_gid;
    try std.testing.expectError(
        error.ServiceIdentityMismatch,
        validateIdentitySeparation(core, aliased_api),
    );
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

const ApiInventoryCallbacks = struct {
    coordinator: *handshake_coordinator.MasterCoordinator,
    snapshot_installer: *SnapshotInstaller,

    fn retire(raw: ?*anyopaque, node_ids: []const model.NodeId) void {
        const self: *ApiInventoryCallbacks = @ptrCast(@alignCast(raw.?));
        for (node_ids) |node_id| self.coordinator.retireAssociation(node_id.bytes);
    }

    fn publish(raw: ?*anyopaque, generation: u64, store: *const model.Store) void {
        const self: *ApiInventoryCallbacks = @ptrCast(@alignCast(raw.?));
        self.snapshot_installer.captureCommitted(store, generation);
    }
};

const EffectiveSettingsContext = struct {
    config: *state.config.ServerConfig,
    store: *model.Store,
    admin: *server_application.Application,
    snapshot_installer: *SnapshotInstaller,
    publisher: *configuration_runtime.MasterPublisher,

    fn observer(self: *EffectiveSettingsContext) settings_runtime.EffectiveObserver {
        return .{
            .context = self,
            .stage_mtu_fn = stageMtuOpaque,
            .committed_fn = committedOpaque,
        };
    }

    fn stageMtuOpaque(raw: *anyopaque, mtu: u16) void {
        const self: *EffectiveSettingsContext = @ptrCast(@alignCast(raw));
        self.snapshot_installer.mtu = mtu;
    }

    fn committedOpaque(
        raw: *anyopaque,
        values: management_settings.OperationalSettings,
        generation: u64,
    ) void {
        const self: *EffectiveSettingsContext = @ptrCast(@alignCast(raw));
        std.debug.assert(generation >= self.store.generation);

        // This callback is intentionally infallible and runs on the serialized
        // worker after the settings acknowledgement commits. Publish the
        // generation only after every in-memory consumer sees one complete
        // effective snapshot.
        self.config.inner_mtu = values.inner_mtu;
        self.config.heartbeat_idle_seconds = values.heartbeat_idle_seconds;
        self.config.suspect_after_seconds = values.suspect_after_seconds;
        self.config.offline_after_seconds = values.offline_after_seconds;
        self.config.default_enrollment_lifetime_seconds = values.default_enrollment_lifetime_seconds;
        self.config.maximum_nodes = values.maximum_nodes;
        self.config.traffic = .{
            .cold_after_seconds = values.traffic_cold_after_seconds,
            .hot_packets_per_second = values.traffic_hot_packets_per_second,
            .hot_bits_per_second = values.traffic_hot_bits_per_second,
            .saturated_queue_percent = values.traffic_saturated_queue_percent,
            .hysteresis_seconds = values.traffic_hysteresis_seconds,
        };
        self.admin.settings = values;
        self.snapshot_installer.mtu = values.inner_mtu;
        self.store.generation = generation;
        self.publisher.generationChanged(generation);
        self.snapshot_installer.captureCommitted(self.store, generation);
    }
};

/// One allocation-owned, immutable representation of an exact committed
/// generation. Kernel route inputs are copied alongside the packet-path
/// snapshots so neither publication stage ever rereads the mutable Store.
const CommittedRuntimeProjection = struct {
    generation: u64,
    snapshot: ?*topology.MasterSnapshots,
    vnrs: std.ArrayList(model.Cidr) = .empty,
    routes: std.ArrayList(model.Cidr) = .empty,
    mtu: u16,
    kernel_reconciled: bool = false,

    fn capture(
        allocator: std.mem.Allocator,
        store: *const model.Store,
        generation: u64,
        mtu: u16,
    ) !CommittedRuntimeProjection {
        if (store.generation != generation) return error.ProjectionGenerationMismatch;
        var projection: CommittedRuntimeProjection = .{
            .generation = generation,
            .snapshot = try topology.createMaster(allocator, store, &.{}),
            .mtu = mtu,
        };
        errdefer projection.deinit(allocator);
        try projection.vnrs.ensureTotalCapacityPrecise(allocator, store.vnrs.items.len);
        try projection.routes.ensureTotalCapacityPrecise(allocator, store.routes.items.len);
        for (store.vnrs.items) |vnr| projection.vnrs.appendAssumeCapacity(vnr.range);
        for (store.routes.items) |route| projection.routes.appendAssumeCapacity(route.prefix);
        return projection;
    }

    fn deinit(self: *CommittedRuntimeProjection, allocator: std.mem.Allocator) void {
        if (self.snapshot) |snapshot| snapshot.destroy();
        self.vnrs.deinit(allocator);
        self.routes.deinit(allocator);
        self.* = undefined;
    }
};

const SnapshotInstaller = struct {
    allocator: std.mem.Allocator,
    store: *const model.Store,
    worker: *data_worker.DataWorker,
    control: *control_plane.ControlPlane,
    acknowledgements: *data_worker.RuntimeBarrierAcknowledgementQueue,
    routes: linux_platform.routes.Controller,
    interface_name: []const u8,
    mtu: u16,
    installed_vnrs: std.ArrayList(model.Cidr) = .empty,
    installed_routes: std.ArrayList(model.Cidr) = .empty,
    pending: ?CommittedRuntimeProjection = null,
    in_flight: bool = false,
    expected_generation: u64 = 0,
    last_captured_generation: u64,
    failure: ?anyerror = null,

    fn init(
        allocator: std.mem.Allocator,
        store: *const model.Store,
        worker: *data_worker.DataWorker,
        control: *control_plane.ControlPlane,
        acknowledgements: *data_worker.RuntimeBarrierAcknowledgementQueue,
        routes: linux_platform.routes.Controller,
        interface_name: []const u8,
        mtu: u16,
    ) !SnapshotInstaller {
        var self: SnapshotInstaller = .{
            .allocator = allocator,
            .store = store,
            .worker = worker,
            .control = control,
            .acknowledgements = acknowledgements,
            .routes = routes,
            .interface_name = interface_name,
            .mtu = mtu,
            .last_captured_generation = store.generation,
        };
        errdefer self.deinit();
        for (store.vnrs.items) |vnr| try self.installed_vnrs.append(allocator, vnr.range);
        for (store.routes.items) |route| try self.installed_routes.append(allocator, route.prefix);
        return self;
    }

    fn deinit(self: *SnapshotInstaller) void {
        if (self.pending) |*projection| projection.deinit(self.allocator);
        while (self.acknowledgements.pop()) |acknowledgement| {
            switch (acknowledgement) {
                .master_snapshot => |snapshot_acknowledgement| {
                    if (snapshot_acknowledgement.retired) |snapshot| snapshot.destroy();
                },
                .runtime_settings => {},
            }
        }
        self.installed_vnrs.deinit(self.allocator);
        self.installed_routes.deinit(self.allocator);
    }

    fn applicationCallback(self: *SnapshotInstaller) server_application.GenerationCallback {
        return .{ .context = self, .changed_fn = applicationPublishedFn };
    }

    fn sqlitePublisher(self: *SnapshotInstaller) sqlite_registry.GenerationPublisher {
        return .{ .context = self, .publish_fn = sqlitePublishedFn };
    }

    fn applicationPublishedFn(raw: *anyopaque, generation: u64) void {
        const self: *SnapshotInstaller = @ptrCast(@alignCast(raw));
        self.captureCommitted(self.store, generation);
    }

    fn sqlitePublishedFn(raw: *anyopaque, store: *const model.Store, generation: u64) void {
        const self: *SnapshotInstaller = @ptrCast(@alignCast(raw));
        self.captureCommitted(store, generation);
    }

    /// Callback adapters are intentionally infallible because their database
    /// transactions have already committed. A capture failure becomes a
    /// terminal operator-loop error before another mutation is admitted; the
    /// durable generation is recovered and fully projected on restart.
    fn captureCommitted(self: *SnapshotInstaller, store: *const model.Store, generation: u64) void {
        if (self.failure != null) return;
        self.capture(store, generation) catch |err| {
            self.failure = err;
            // The just-committed SQLite generation is the recovery source of
            // truth. Stop before the serialized loop can admit another Store
            // mutation; startup will materialize this exact latest generation
            // as its initial immutable DATA projection.
            linux_platform.lifecycle.requestStop();
            if (!builtin.is_test) {
                std.log.err("could not retain committed runtime generation {d}: {s}", .{
                    generation,
                    @errorName(err),
                });
            }
        };
    }

    fn capture(self: *SnapshotInstaller, store: *const model.Store, generation: u64) !void {
        if (!self.readyForMutation()) return error.RuntimePublicationAdmissionViolated;
        if (generation <= self.last_captured_generation) return error.NonMonotonicRuntimeGeneration;
        self.pending = try CommittedRuntimeProjection.capture(
            self.allocator,
            store,
            generation,
            self.mtu,
        );
        self.last_captured_generation = generation;
    }

    fn readyForMutation(self: *const SnapshotInstaller) bool {
        return self.failure == null and self.pending == null and !self.in_flight;
    }

    fn poll(self: *SnapshotInstaller) !void {
        try self.drainAcknowledgements();
        if (self.failure) |failure| return failure;
        if (self.in_flight) return;
        const projection = if (self.pending) |*value| value else return;
        if (!projection.kernel_reconciled) {
            try self.reconcileKernel(projection);
            projection.kernel_reconciled = true;
        }
        const snapshot = projection.snapshot orelse return error.MissingCommittedRuntimeSnapshot;
        if (!self.worker.submit(data_worker.DataCommand.installMasterSnapshot(
            snapshot,
            projection.generation,
        ))) return;

        const generation = projection.generation;
        projection.snapshot = null;
        projection.deinit(self.allocator);
        self.pending = null;
        self.expected_generation = generation;
        self.in_flight = true;
    }

    fn reconcileKernel(
        self: *SnapshotInstaller,
        projection: *CommittedRuntimeProjection,
    ) !void {
        for (projection.vnrs.items) |vnr| {
            var address_buffer: [15]u8 = undefined;
            var cidr_buffer: [18]u8 = undefined;
            const cidr = try std.fmt.bufPrint(&cidr_buffer, "{s}/{d}", .{
                try vnr.firstUsable().?.write(&address_buffer),
                vnr.prefix,
            });
            try self.routes.replaceAddress(self.interface_name, cidr);
        }
        for (self.installed_vnrs.items) |old| {
            if (projectionHasCidr(projection.vnrs.items, old)) continue;
            var address_buffer: [15]u8 = undefined;
            var cidr_buffer: [18]u8 = undefined;
            const cidr = try std.fmt.bufPrint(&cidr_buffer, "{s}/{d}", .{
                try old.firstUsable().?.write(&address_buffer),
                old.prefix,
            });
            try self.routes.deleteAddress(self.interface_name, cidr);
        }
        for (projection.routes.items) |route| {
            var buffer: [18]u8 = undefined;
            try self.routes.replaceRoute(
                self.interface_name,
                try route.write(&buffer),
                projection.mtu,
            );
        }
        for (self.installed_routes.items) |old| {
            if (projectionHasCidr(projection.routes.items, old)) continue;
            var buffer: [18]u8 = undefined;
            try self.routes.deleteRoute(self.interface_name, try old.write(&buffer));
        }

        // Ownership swaps are allocation-free. The projection now carries the
        // previous installed kernel inputs and releases them after submission.
        std.mem.swap(std.ArrayList(model.Cidr), &self.installed_vnrs, &projection.vnrs);
        std.mem.swap(std.ArrayList(model.Cidr), &self.installed_routes, &projection.routes);
    }

    fn drainAcknowledgements(self: *SnapshotInstaller) !void {
        while (self.acknowledgements.pop()) |acknowledgement| {
            switch (acknowledgement) {
                .runtime_settings => |sequence| self.control.runtimeSettingsApplied(sequence),
                .master_snapshot => |snapshot_acknowledgement| {
                    if (snapshot_acknowledgement.retired) |snapshot| snapshot.destroy();
                    if (!self.in_flight or
                        snapshot_acknowledgement.generation != self.expected_generation)
                    {
                        return error.SnapshotAcknowledgementMismatch;
                    }
                    self.in_flight = false;
                    std.log.info("installed durable forwarding generation {d}", .{
                        snapshot_acknowledgement.generation,
                    });
                },
            }
        }
    }
};

fn projectionHasCidr(items: []const model.Cidr, expected: model.Cidr) bool {
    for (items) |candidate| {
        if (candidate.network.value == expected.network.value and
            candidate.prefix == expected.prefix) return true;
    }
    return false;
}

test "runtime projection admission preserves each immutable committed generation" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    const node_id: model.NodeId = .{ .bytes = .{0x71} ** 16 };
    const old_address = try model.Ipv4.parse("10.1.0.2");
    const new_address = try model.Ipv4.parse("10.1.0.3");
    try store.createNode(node_id, "node01", "vnr0", old_address);

    var acknowledgements = try data_worker.RuntimeBarrierAcknowledgementQueue.init(
        std.testing.allocator,
        2,
    );
    defer acknowledgements.deinit();
    var installer: SnapshotInstaller = .{
        .allocator = std.testing.allocator,
        .store = &store,
        .worker = undefined,
        .control = undefined,
        .acknowledgements = &acknowledgements,
        .routes = undefined,
        .interface_name = "test0",
        .mtu = 1380,
        .last_captured_generation = store.generation - 1,
    };
    defer installer.deinit();

    try installer.capture(&store, store.generation);
    const first_snapshot = installer.pending.?.snapshot.?;
    try std.testing.expect(first_snapshot.forwarding.lookup(old_address.value) != null);
    try std.testing.expect(first_snapshot.forwarding.lookup(new_address.value) == null);

    // A saturated one-projection reservation rejects another producer before
    // it can commit, and retains the first generation byte-for-byte.
    try std.testing.expectError(
        error.RuntimePublicationAdmissionViolated,
        installer.capture(&store, store.generation + 1),
    );
    try std.testing.expect(installer.pending.?.snapshot.? == first_snapshot);

    // Model a successful bounded hand-off and acknowledgement, then admit the
    // next commit. Mutating the Store cannot alter the detached first snapshot.
    var first = installer.pending.?;
    installer.pending = null;
    installer.in_flight = true;
    installer.expected_generation = first.generation;
    try std.testing.expect(!installer.readyForMutation());
    installer.in_flight = false;
    try store.updateNode(node_id, "node01", "vnr0", new_address);
    try installer.capture(&store, store.generation);
    defer first.deinit(std.testing.allocator);

    try std.testing.expect(first.snapshot.?.forwarding.lookup(old_address.value) != null);
    try std.testing.expect(first.snapshot.?.forwarding.lookup(new_address.value) == null);
    try std.testing.expect(installer.pending.?.snapshot.?.forwarding.lookup(old_address.value) == null);
    try std.testing.expect(installer.pending.?.snapshot.?.forwarding.lookup(new_address.value) != null);
    try std.testing.expectEqual(first.generation + 1, installer.pending.?.generation);
}

test "post-commit projection allocation failure closes admission for restart recovery" {
    linux_platform.lifecycle.resetStopForTest();
    defer linux_platform.lifecycle.resetStopForTest();

    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.2.0.0/24"));

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var acknowledgements = try data_worker.RuntimeBarrierAcknowledgementQueue.init(
        std.testing.allocator,
        2,
    );
    defer acknowledgements.deinit();
    var installer: SnapshotInstaller = .{
        .allocator = failing.allocator(),
        .store = &store,
        .worker = undefined,
        .control = undefined,
        .acknowledgements = &acknowledgements,
        .routes = undefined,
        .interface_name = "test0",
        .mtu = 1380,
        .last_captured_generation = store.generation - 1,
    };
    defer installer.deinit();

    installer.captureCommitted(&store, store.generation);
    try std.testing.expectEqual(error.OutOfMemory, installer.failure.?);
    try std.testing.expect(!installer.readyForMutation());
    try std.testing.expect(installer.pending == null);
    try std.testing.expect(linux_platform.lifecycle.shouldStop());
}

fn shutdownCallback() live_admin.ShutdownCallback {
    return .{ .context = &shutdown_context, .request_fn = requestShutdown };
}

fn applicationShutdownCallback() server_application.ShutdownCallback {
    return .{ .context = &shutdown_context, .request_fn = requestShutdown };
}

fn requestShutdown(_: *anyopaque) void {
    linux_platform.lifecycle.requestStop();
}

/// At most one accepted management connection may run between full runtime
/// checkpoints. Combined with the 100 ms hard-close slice on both Unix-socket
/// protocols, a continuous slow-peer or request flood cannot chain management
/// work ahead of protocol-critical persistence.
const management_requests_per_runtime_checkpoint: usize = 1;

const ManagementIterationBudget = struct {
    consumed: usize = 0,

    fn take(self: *ManagementIterationBudget) bool {
        if (self.consumed >= management_requests_per_runtime_checkpoint) return false;
        self.consumed += 1;
        return true;
    }
};

fn runControlLoop(
    ipc: *ipc_server.Server,
    api_ipc: ?*service_server.Server,
    operations_control: ?*operations_service.ControlState,
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
    if (api_ipc) |server| {
        var api_event: linux.epoll_event = .{
            .events = linux.EPOLL.IN | linux.EPOLL.ERR | linux.EPOLL.HUP,
            .data = .{ .fd = server.listenerHandle() },
        };
        switch (linux.errno(linux.epoll_ctl(
            epoll_fd,
            linux.EPOLL.CTL_ADD,
            server.listenerHandle(),
            &api_event,
        ))) {
            .SUCCESS => {},
            else => return error.EpollAddFailed,
        }
    }

    var events: [4]linux.epoll_event = undefined;
    while (!linux_platform.lifecycle.shouldStop()) {
        const now_ns = monotonicNow(control.io);
        try advanceRuntime(control, snapshot_installer, hook, now_ns);
        const result = linux.epoll_wait(epoll_fd, &events, events.len, 100);
        switch (linux.errno(result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.EpollWaitFailed,
        }
        const count: usize = @intCast(result);
        var management_budget: ManagementIterationBudget = .{};
        for (events[0..count]) |ready_event| {
            if (!management_budget.take()) break;
            // Recheck protocol events immediately before each admitted
            // management request. The one-request budget then returns to the
            // outer checkpoint even when both listeners remain continuously
            // readable.
            try advanceRuntime(control, snapshot_installer, hook, monotonicNow(control.io));
            if (snapshot_installer) |installer| {
                try installer.poll();
                if (!installer.readyForMutation()) break;
            }
            if (ready_event.data.fd == ipc.listener.handle()) {
                ipc.serveOne() catch |err| std.log.warn("local IPC request failed: {s}", .{@errorName(err)});
                if (snapshot_installer) |installer| try installer.poll();
                break;
            }
            if (api_ipc) |server| {
                if (ready_event.data.fd == server.listenerHandle()) {
                    server.serveOne() catch |err| std.log.warn("service IPC request failed: {s}", .{@errorName(err)});
                    if (snapshot_installer) |installer| try installer.poll();
                    // A service-control decision is set only after its audit
                    // record commits. `serveOne` writes and flushes each typed
                    // response frame before returning, so execution cannot
                    // overtake the accepted 202 response on the normal path.
                    // If the peer disconnects during delivery the committed
                    // decision still executes instead of leaving the service
                    // permanently stuck in an in-progress state.
                    switch (serviceControlDisposition(operations_control)) {
                        .continue_running => {},
                        .shutdown => {
                            linux_platform.lifecycle.requestStop();
                            return;
                        },
                        .restart => {
                            linux_platform.lifecycle.requestStop();
                            return error.ManagedRestartRequested;
                        },
                    }
                    break;
                }
            }
        }
    }
}

test "management flood yields after one request to the runtime checkpoint" {
    var budget: ManagementIterationBudget = .{};
    try std.testing.expect(budget.take());
    try std.testing.expect(!budget.take());
    try std.testing.expectEqual(@as(usize, 1), budget.consumed);
}

/// Advances runtime work without admitting a second Store mutation until the
/// immutable projection for the first commit has crossed the bounded DATA
/// queue and its dedicated acknowledgement barrier. Non-mutating events are
/// drained in one tick; the first publishing callback closes the gate.
fn advanceRuntime(
    control: *control_plane.ControlPlane,
    snapshot_installer: ?*SnapshotInstaller,
    hook: LoopHook,
    now_ns: u64,
) !void {
    const installer = snapshot_installer orelse {
        control.poll(now_ns);
        try hook.tick(now_ns);
        return;
    };

    try installer.poll();
    if (!installer.readyForMutation()) return;
    while (control.pollOneEvent(now_ns)) {
        try installer.poll();
        if (!installer.readyForMutation()) return;
    }
    control.pollTimers(now_ns);
    try hook.tick(now_ns);
    try installer.poll();
}

const ServiceControlDisposition = enum {
    continue_running,
    shutdown,
    restart,
};

fn serviceControlDisposition(
    control: ?*const operations_service.ControlState,
) ServiceControlDisposition {
    const decision = (control orelse return .continue_running).pending orelse
        return .continue_running;
    return switch (decision.kind) {
        .shutdown => .shutdown,
        .restart => .restart,
    };
}

const LoopHook = struct {
    context: *anyopaque,
    tick_fn: *const fn (*anyopaque, u64) anyerror!void,

    fn tick(self: LoopHook, now_ns: u64) !void {
        return self.tick_fn(self.context, now_ns);
    }
};

const MasterLoop = struct {
    const runtime_event_interval_ns: u64 = std.time.ns_per_s;
    const runtime_event_write_budget: u16 = 16;

    io: std.Io,
    store: *const model.Store,
    coordinator: *handshake_coordinator.MasterCoordinator,
    publisher: *configuration_runtime.MasterPublisher,
    retry_rotator: *RetryRotator,
    connectivity_recorder: *connectivity_runtime.CompletionRecorder,
    runtime_settings: *settings_runtime.Applier,
    runtime_events: *runtime_event_recorder.Recorder,
    runtime_event_node_ids: []model.NodeId,
    snapshot_installer: *SnapshotInstaller,
    next_runtime_event_tick_ns: u64 = 0,
    last_runtime_event_wall_seconds: ?i64 = null,

    fn hook(self: *MasterLoop) LoopHook {
        return .{ .context = self, .tick_fn = tickOpaque };
    }

    fn tickOpaque(raw: *anyopaque, now_ns: u64) !void {
        const self: *MasterLoop = @ptrCast(@alignCast(raw));
        self.coordinator.tick(now_ns);
        try self.publisher.tick(now_ns);
        try self.retry_rotator.tick(self.coordinator, now_ns);
        _ = try self.connectivity_recorder.poll();
        // This is the only hook substep that can commit and publish a new
        // Store/settings generation. Close the admission gate immediately;
        // later maintenance must not be allowed to grow into a second
        // generation-producing substep without an equivalent checkpoint.
        try self.runtime_settings.tick(now_ns);
        try self.snapshot_installer.poll();
        if (!self.snapshot_installer.readyForMutation()) return;
        try self.tickRuntimeEvents(now_ns);
    }

    fn tickRuntimeEvents(self: *MasterLoop, now_ns: u64) !void {
        if (now_ns < self.next_runtime_event_tick_ns) return;
        self.next_runtime_event_tick_ns = std.math.add(u64, now_ns, runtime_event_interval_ns) catch
            std.math.maxInt(u64);
        if (self.store.nodes.items.len > self.runtime_event_node_ids.len) {
            return error.MaximumNodesExceeded;
        }
        for (self.store.nodes.items, 0..) |node, index| {
            self.runtime_event_node_ids[index] = node.id;
        }
        var observed_at = try wallSeconds(self.io);
        if (self.last_runtime_event_wall_seconds) |previous| {
            // A backwards wall-clock adjustment must not take the authoritative
            // service down or produce non-monotonic event timestamps.
            observed_at = @max(observed_at, previous);
        }
        self.last_runtime_event_wall_seconds = observed_at;
        _ = try self.runtime_events.tick(
            self.runtime_event_node_ids[0..self.store.nodes.items.len],
            observed_at,
            .{ .maximum_event_writes = runtime_event_write_budget },
        );
    }
};

/// Audit export, online backup, and admitted Argon2 work run inside serialized
/// IPC handlers. Between finalized export batches, bounded SQLite page copies,
/// or password-worker wait slices, these callbacks advance the same
/// protocol/runtime work as the outer control loop without accepting another
/// request or recursively entering the management layer.
const ExportRuntimeCheckpoint = struct {
    io: std.Io,
    control: *control_plane.ControlPlane,
    snapshot_installer: *SnapshotInstaller,
    loop: *MasterLoop,

    fn checkpoint(self: *ExportRuntimeCheckpoint) operations_service.ExportCheckpoint {
        return .{ .context = self, .checkpoint_fn = runOpaque };
    }

    fn backupCheckpoint(self: *ExportRuntimeCheckpoint) state.sqlite.BackupCheckpoint {
        return .{ .context = self, .checkpoint_fn = backupOpaque };
    }

    fn authCheckpoint(self: *ExportRuntimeCheckpoint) auth_application.AuthProgressCheckpoint {
        return .{ .context = self, .checkpoint_fn = authOpaque };
    }

    fn runOpaque(raw: ?*anyopaque, deadline_unix_ms: i64) anyerror!void {
        const self: *ExportRuntimeCheckpoint = @ptrCast(@alignCast(raw orelse
            return error.InvalidExportCheckpoint));
        try ensureExportDeadline(self.io, deadline_unix_ms);
        try self.checkpointRuntime();
        try ensureExportDeadline(self.io, deadline_unix_ms);
    }

    fn backupOpaque(
        raw: ?*anyopaque,
        _: state.sqlite.BackupProgress,
    ) anyerror!void {
        const self: *ExportRuntimeCheckpoint = @ptrCast(@alignCast(raw orelse
            return error.InvalidBackupCheckpoint));
        try self.checkpointRuntime();
    }

    fn authOpaque(raw: ?*anyopaque) anyerror!void {
        const self: *ExportRuntimeCheckpoint = @ptrCast(@alignCast(raw orelse
            return error.InvalidAuthProgressCheckpoint));
        try self.checkpointRuntime();
    }

    fn checkpointRuntime(self: *ExportRuntimeCheckpoint) !void {
        const now_ns = monotonicNow(self.io);
        try advanceRuntime(
            self.control,
            self.snapshot_installer,
            self.loop.hook(),
            now_ns,
        );
    }
};

fn ensureExportDeadline(io: std.Io, deadline_unix_ms: i64) !void {
    if (deadline_unix_ms <= 0 or
        std.Io.Clock.real.now(io).toMilliseconds() >= deadline_unix_ms)
    {
        return error.DeadlineExceeded;
    }
}

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
    store: *const model.Store,

    fn lookup(self: *MasterRuntimeView) cli_view.RuntimeLookup {
        return .{ .context = self, .lookup_fn = lookupOpaque };
    }

    fn runtimeSource(self: *MasterRuntimeView) read_models_service.RuntimeSource {
        return .{ .context = self, .observe_fn = observeOpaque };
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

    fn observeOpaque(
        raw: ?*anyopaque,
        node_id: model.NodeId,
        observed_at: i64,
    ) !?read_models_service.RuntimeObservation {
        const self: *MasterRuntimeView = @ptrCast(@alignCast(raw.?));
        const node = self.store.findNodeById(node_id) orelse return null;
        const receiver_id = self.coordinator.activeReceiverFor(node_id.bytes) orelse return .{
            .liveness = if (node.enrollment_state == .enrolled) .offline else .unknown,
            .session_state = if (node.enrollment_state == .enrolled) .disconnected else .enrolling,
        };
        const peer_state = self.control.peerState(receiver_id) orelse .offline;
        var endpoint_buffer: [read_models_service.maximum_endpoint_bytes]u8 = undefined;
        const observed_endpoint = if (self.control.peerEndpoint(receiver_id)) |endpoint_value|
            if (formatEndpoint(endpoint_value, &endpoint_buffer)) |text|
                try read_models_service.EndpointText.parse(text)
            else
                null
        else
            null;
        const activity: control_plane.ControlPlane.PeerActivity = self.control.peerActivity(receiver_id) orelse .{
            .authenticated_rx_ns = null,
            .authenticated_tx_ns = null,
        };
        const now_ns = monotonicNow(self.control.io);
        return .{
            .liveness = switch (peer_state) {
                .online => .online,
                .suspect, .rekey_required => .suspect,
                .offline => .offline,
                .awaiting_confirmation => .unknown,
            },
            .session_state = switch (peer_state) {
                .online, .suspect => .established,
                .rekey_required, .awaiting_confirmation => .connecting,
                .offline => .disconnected,
            },
            .observed_endpoint = observed_endpoint,
            .traffic_state = if (self.control.peerTrafficState(receiver_id)) |traffic_state| switch (traffic_state) {
                .cold => .cold,
                .warm => .warm,
                .hot => .hot,
                .saturated => .saturated,
            } else .unknown,
            .authenticated_rx_at = monotonicActivityToWall(
                observed_at,
                now_ns,
                activity.authenticated_rx_ns,
            ),
            .authenticated_tx_at = monotonicActivityToWall(
                observed_at,
                now_ns,
                activity.authenticated_tx_ns,
            ),
        };
    }
};

fn monotonicActivityToWall(observed_at: i64, now_ns: u64, event_ns: ?u64) ?i64 {
    const value = event_ns orelse return null;
    const elapsed_seconds: i64 = @intCast((now_ns -| value) / std.time.ns_per_s);
    return @max(@as(i64, 0), observed_at -| elapsed_seconds);
}

test "authenticated monotonic activity converts to bounded wall time" {
    try std.testing.expect(monotonicActivityToWall(100, 10 * std.time.ns_per_s, null) == null);
    try std.testing.expectEqual(
        @as(?i64, 97),
        monotonicActivityToWall(100, 10 * std.time.ns_per_s, 7 * std.time.ns_per_s),
    );
    try std.testing.expectEqual(
        @as(?i64, 0),
        monotonicActivityToWall(2, 10 * std.time.ns_per_s, 1 * std.time.ns_per_s),
    );
    // A future monotonic sample is clamped to the current observation rather
    // than producing a wall timestamp beyond `observedAt`.
    try std.testing.expectEqual(
        @as(?i64, 100),
        monotonicActivityToWall(100, 10 * std.time.ns_per_s, 11 * std.time.ns_per_s),
    );
}

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

fn validateServiceSocketDirectory(
    io: std.Io,
    socket_path: []const u8,
    expected_uid: u32,
    expected_gid: u32,
) !void {
    const parent = std.fs.path.dirname(socket_path) orelse return error.InvalidServiceSocketPath;
    if (!std.fs.path.isAbsolute(parent) or parent.len <= 1) return error.InvalidServiceSocketPath;

    var components = std.mem.splitScalar(u8, parent[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidServiceSocketPath;
        }
    }

    var dir = try std.Io.Dir.openDirAbsolute(io, parent, .{ .follow_symlinks = false });
    defer dir.close(io);
    try validateDirectoryIdentity(dir, io, expected_uid, expected_gid, 0o750);
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

test "typed service control decisions map to loop termination only when pending" {
    try std.testing.expectEqual(
        ServiceControlDisposition.continue_running,
        serviceControlDisposition(null),
    );
    var control: operations_service.ControlState = .{
        .instance_id = [_]u8{0x31} ** 16,
        .managed_restart_supported = true,
    };
    try std.testing.expectEqual(
        ServiceControlDisposition.continue_running,
        serviceControlDisposition(&control),
    );

    control.pending = .{
        .id = [_]u8{0x41} ** 16,
        .kind = .shutdown,
        .accepted_at = 100,
        .exit_status = operations_service.shutdown_exit_status,
    };
    try std.testing.expectEqual(
        ServiceControlDisposition.shutdown,
        serviceControlDisposition(&control),
    );

    control.pending.?.kind = .restart;
    control.pending.?.exit_status = operations_service.restart_exit_status;
    try std.testing.expectEqual(
        ServiceControlDisposition.restart,
        serviceControlDisposition(&control),
    );
}
