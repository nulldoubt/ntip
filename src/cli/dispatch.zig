const std = @import("std");
const model = @import("../domain/model.zig");
const server = @import("server.zig");
const client = @import("client.zig");

pub const Target = enum {
    offline_state,
    daemon_ipc,
    daemon_start,
    local_config,
    local_version,
};

pub fn serverTarget(command: server.Command, daemon_running: bool) !Target {
    return switch (command) {
        .up => if (daemon_running) error.AlreadyRunning else .daemon_start,
        .down => if (daemon_running) .daemon_ipc else error.DaemonUnavailable,
        .status => if (daemon_running) .daemon_ipc else .offline_state,
        .user_bootstrap, .restore => if (daemon_running) error.DaemonRunning else .offline_state,
        .version => .local_version,
        else => if (daemon_running) .daemon_ipc else .offline_state,
    };
}

pub fn clientTarget(command: client.Command, daemon_running: bool) !Target {
    return switch (command) {
        .config => if (daemon_running) error.DaemonRunning else .local_config,
        .up => if (daemon_running) error.AlreadyRunning else .daemon_start,
        .down => if (daemon_running) .daemon_ipc else error.DaemonUnavailable,
        .status => if (daemon_running) .daemon_ipc else .offline_state,
        .version => .local_version,
    };
}

pub const MutationOutcome = union(enum) {
    vnr_created: struct { public_range_warning: bool },
    vnr_deleted,
    node_created: model.NodeId,
    node_deleted,
    route_added,
    route_deleted,
    enrollment_renew_required: []const u8,
    enrollment_reset_required: []const u8,
};

/// Applies only the in-memory domain mutation. The SQLite-backed caller owns
/// the atomic inventory/invitation commit and publishes the resulting
/// projection only after that transaction succeeds.
pub fn applyServerMutation(store: *model.Store, io: std.Io, command: server.Command) !MutationOutcome {
    return switch (command) {
        .vnr_create => |create| blk: {
            const range = model.Cidr.parse(create.cidr) catch return error.InvalidCidr;
            const result = try store.createVnr(create.name, range);
            break :blk .{ .vnr_created = .{ .public_range_warning = result.public_range_warning } };
        },
        .vnr_delete => |name| blk: {
            try store.deleteVnr(name);
            break :blk .vnr_deleted;
        },
        .node_create => |create| blk: {
            const address = model.Ipv4.parse(create.address) catch return error.InvalidAddress;
            const id = try store.createNodeRandom(io, create.name, create.vnr, address);
            break :blk .{ .node_created = id };
        },
        .node_delete => |name| blk: {
            try store.deleteNode(name);
            break :blk .node_deleted;
        },
        .route_add => |add| blk: {
            const prefix = model.Cidr.parse(add.cidr) catch return error.InvalidCidr;
            _ = try store.addRouteRandom(io, prefix, add.node);
            break :blk .route_added;
        },
        .route_delete => |text| blk: {
            const prefix = model.Cidr.parse(text) catch return error.InvalidCidr;
            try store.deleteRoute(prefix);
            break :blk .route_deleted;
        },
        .node_enrollment_renew => |request| blk: {
            if (store.findNode(request.name) == null) return error.NodeNotFound;
            break :blk .{ .enrollment_renew_required = request.name };
        },
        .node_enrollment_reset => |request| blk: {
            try store.resetNodeEnrollment(request.name);
            break :blk .{ .enrollment_reset_required = request.name };
        },
        else => error.NotMutation,
    };
}

test "daemon target selection keeps durable admin commands coherent" {
    const create = server.Command{ .vnr_create = .{ .name = "vnr0", .cidr = "10.1.0.0/24" } };
    try std.testing.expectEqual(Target.offline_state, try serverTarget(create, false));
    try std.testing.expectEqual(Target.daemon_ipc, try serverTarget(create, true));
    try std.testing.expectEqual(Target.offline_state, try serverTarget(.{ .status = .text }, false));
}

test "domain dispatch applies canonical command mutations" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try applyServerMutation(&store, std.testing.io, .{ .vnr_create = .{ .name = "vnr0", .cidr = "10.1.0.0/24" } });
    _ = try applyServerMutation(&store, std.testing.io, .{ .node_create = .{
        .name = "node01",
        .vnr = "vnr0",
        .address = "10.1.0.2",
    } });
    try std.testing.expect(store.findNode("node01") != null);
}
