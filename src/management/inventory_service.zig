//! Authenticated inventory application boundary for the v0.2 management API.
//!
//! This module deliberately knows nothing about HTTP framing. It turns an
//! authenticated web principal into bounded reads and audited domain
//! mutations. The serialized operator worker is the sole caller in
//! production, so the referenced SQLite repository and live Store cannot be
//! observed halfway through a command.

const std = @import("std");
const model = @import("../domain/model.zig");
const management_repository = @import("../state/management_repository.zig");
const settings_repository = @import("../state/settings_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const auth = @import("auth.zig");
const service_ipc = @import("service_ipc.zig");
const settings = @import("settings.zig");

pub const default_page_size: u16 = 50;
pub const maximum_page_size: u16 = 200;
pub const maximum_cursor_token_bytes: usize = 132;
pub const maximum_etag_bytes: usize = 96;

const enrollment_projection_sql =
    "CASE WHEN nodes.enrollment_state = 'enrolled' THEN 'enrolled' " ++
    "WHEN EXISTS (SELECT 1 FROM enrollment_credentials AS credential " ++
    "WHERE credential.node_id = nodes.id AND credential.status = 'unused' " ++
    "AND credential.expires_at > ?1) THEN 'credential_issued' " ++
    "ELSE 'unenrolled' END";

pub const Principal = struct {
    id: [16]u8,
    role: auth.Role,
};

pub const MutationContext = struct {
    request_id: [16]u8,
    occurred_at: i64,
    user_agent: ?[]const u8 = null,
    proxy_peer: ?[]const u8 = null,
};

pub const ResourceKind = enum {
    vnr,
    node,
    route,
};

/// A strong resource tag. VNR names are represented by a full SHA-256 digest
/// so valid mixed-case names still produce contract-safe lowercase tags.
/// Node and Route identities use their complete opaque 128-bit IDs.
pub const ResourceEtag = struct {
    kind: ResourceKind,
    identity: [32]u8,
    identity_len: u8,
    revision: u64,
    bytes: [maximum_etag_bytes]u8,
    len: u8,

    pub fn forVnr(name: model.Name, revision: u64) ResourceEtag {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(name.slice(), &digest, .{});
        return init(.vnr, &digest, revision);
    }

    pub fn forNode(id: model.NodeId, revision: u64) ResourceEtag {
        return init(.node, &id.bytes, revision);
    }

    pub fn forRoute(id: model.RouteId, revision: u64) ResourceEtag {
        return init(.route, &id.bytes, revision);
    }

    pub fn slice(self: *const ResourceEtag) []const u8 {
        return self.bytes[0..self.len];
    }

    fn init(kind: ResourceKind, identity: []const u8, revision: u64) ResourceEtag {
        std.debug.assert(revision > 0);
        std.debug.assert(identity.len == 16 or identity.len == 32);
        var result: ResourceEtag = .{
            .kind = kind,
            .identity = [_]u8{0} ** 32,
            .identity_len = @intCast(identity.len),
            .revision = revision,
            .bytes = [_]u8{0} ** maximum_etag_bytes,
            .len = 0,
        };
        @memcpy(result.identity[0..identity.len], identity);
        var identity_text: [64]u8 = undefined;
        encodeLowerHex(identity, identity_text[0 .. identity.len * 2]);
        const rendered = std.fmt.bufPrint(
            &result.bytes,
            "\"{s}:{s}:{d}\"",
            .{ @tagName(kind), identity_text[0 .. identity.len * 2], revision },
        ) catch unreachable;
        result.len = @intCast(rendered.len);
        return result;
    }
};

pub const ParsedEtag = struct {
    kind: ResourceKind,
    identity: [32]u8,
    identity_len: u8,
    revision: u64,
};

pub fn parseEtag(text: []const u8) error{InvalidEtag}!ParsedEtag {
    if (text.len < 8 or text.len > maximum_etag_bytes or text[0] != '"' or text[text.len - 1] != '"') {
        return error.InvalidEtag;
    }
    const inner = text[1 .. text.len - 1];
    var parts = std.mem.splitScalar(u8, inner, ':');
    const kind_text = parts.next() orelse return error.InvalidEtag;
    const identity_text = parts.next() orelse return error.InvalidEtag;
    const revision_text = parts.next() orelse return error.InvalidEtag;
    if (parts.next() != null) return error.InvalidEtag;

    const kind: ResourceKind = if (std.mem.eql(u8, kind_text, "vnr"))
        .vnr
    else if (std.mem.eql(u8, kind_text, "node"))
        .node
    else if (std.mem.eql(u8, kind_text, "route"))
        .route
    else
        return error.InvalidEtag;
    const identity_len: usize = if (kind == .vnr) 32 else 16;
    if (identity_text.len != identity_len * 2) return error.InvalidEtag;
    var identity = [_]u8{0} ** 32;
    decodeLowerHex(identity_text, identity[0..identity_len]) catch return error.InvalidEtag;
    const revision = std.fmt.parseInt(u64, revision_text, 10) catch return error.InvalidEtag;
    if (revision == 0) return error.InvalidEtag;
    return .{
        .kind = kind,
        .identity = identity,
        .identity_len = @intCast(identity_len),
        .revision = revision,
    };
}

pub fn requireFreshEtag(supplied: ?[]const u8, current: ResourceEtag) !void {
    const text = supplied orelse return error.PreconditionRequired;
    const parsed = parseEtag(text) catch return error.PreconditionFailed;
    if (parsed.kind != current.kind or parsed.revision != current.revision or
        parsed.identity_len != current.identity_len or
        !std.mem.eql(
            u8,
            parsed.identity[0..parsed.identity_len],
            current.identity[0..current.identity_len],
        ))
    {
        return error.PreconditionFailed;
    }
    // Parsing proves this is one strong tag for the expected resource and
    // revision; byte equality additionally rejects non-canonical spellings
    // such as a leading-zero revision.
    if (!std.mem.eql(u8, text, current.slice())) return error.PreconditionFailed;
}

pub const VnrRecord = struct {
    name: model.Name,
    range: model.Cidr,
    public_range_warning: bool,
    revision: u64,
    created_at: i64,
    updated_at: i64,

    pub fn masterAddress(self: VnrRecord) model.Ipv4 {
        return self.range.firstUsable().?;
    }

    pub fn etag(self: VnrRecord) ResourceEtag {
        return ResourceEtag.forVnr(self.name, self.revision);
    }
};

/// Public management projection only. The protocol/domain Store deliberately
/// retains its two-state `model.EnrollmentState`; an unexpired unused verifier
/// is represented here without changing Node wire compatibility.
pub const EnrollmentState = enum {
    unenrolled,
    credential_issued,
    enrolled,
};

pub const NodeRecord = struct {
    id: model.NodeId,
    name: model.Name,
    vnr: model.Name,
    address: model.Ipv4,
    enrollment_state: EnrollmentState,
    revision: u64,
    created_at: i64,
    updated_at: i64,

    pub fn etag(self: NodeRecord) ResourceEtag {
        return ResourceEtag.forNode(self.id, self.revision);
    }
};

pub const RouteRecord = struct {
    id: model.RouteId,
    prefix: model.Cidr,
    node_id: model.NodeId,
    node_name: model.Name,
    revision: u64,
    created_at: i64,
    updated_at: i64,

    pub fn etag(self: RouteRecord) ResourceEtag {
        return ResourceEtag.forRoute(self.id, self.revision);
    }
};

comptime {
    // Public inventory projections must never grow a credential-bearing field.
    std.debug.assert(!@hasField(VnrRecord, "public_key"));
    std.debug.assert(!@hasField(NodeRecord, "public_key"));
    std.debug.assert(!@hasField(RouteRecord, "public_key"));
    std.debug.assert(!@hasField(NodeRecord, "derived_psk"));
}

pub const VnrCursor = struct { after_name: model.Name };
pub const NodeCursor = struct { after_id: model.NodeId };
pub const RouteCursor = struct { after_id: model.RouteId };

pub fn encodeVnrCursor(cursor: VnrCursor, buffer: *[maximum_cursor_token_bytes]u8) []const u8 {
    return encodeCursorName("v1:v:", cursor.after_name, buffer);
}

pub fn decodeVnrCursor(text: []const u8) !VnrCursor {
    if (!std.mem.startsWith(u8, text, "v1:v:")) return error.InvalidCursor;
    const encoded = text[5..];
    if (encoded.len == 0 or encoded.len > model.max_name_len * 2 or encoded.len % 2 != 0) {
        return error.InvalidCursor;
    }
    var name_text: [model.max_name_len]u8 = undefined;
    const name_len = encoded.len / 2;
    decodeLowerHex(encoded, name_text[0..name_len]) catch return error.InvalidCursor;
    return .{ .after_name = model.Name.parse(name_text[0..name_len]) catch return error.InvalidCursor };
}

pub fn encodeNodeCursor(cursor: NodeCursor, buffer: *[maximum_cursor_token_bytes]u8) []const u8 {
    return encodeCursorId("v1:n:", cursor.after_id, buffer);
}

pub fn decodeNodeCursor(text: []const u8) !NodeCursor {
    return .{ .after_id = try decodeCursorId("v1:n:", text) };
}

pub fn encodeRouteCursor(cursor: RouteCursor, buffer: *[maximum_cursor_token_bytes]u8) []const u8 {
    return encodeCursorId("v1:r:", cursor.after_id, buffer);
}

pub fn decodeRouteCursor(text: []const u8) !RouteCursor {
    return .{ .after_id = try decodeCursorId("v1:r:", text) };
}

pub const VnrPage = struct {
    items: []VnrRecord,
    next_cursor: ?VnrCursor,

    pub fn deinit(self: *VnrPage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const NodePage = struct {
    items: []NodeRecord,
    next_cursor: ?NodeCursor,

    pub fn deinit(self: *NodePage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const RoutePage = struct {
    items: []RouteRecord,
    next_cursor: ?RouteCursor,

    pub fn deinit(self: *RoutePage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const NodeFilter = struct {
    vnr: ?model.Name = null,
    enrollment_state: ?EnrollmentState = null,
};

pub const RouteFilter = struct {
    node_id: ?model.NodeId = null,
};

pub const CreateVnrInput = struct {
    name: []const u8,
    range: model.Cidr,
};

pub const UpdateVnrInput = struct {
    range: model.Cidr,
};

pub const CreateNodeInput = struct {
    name: []const u8,
    vnr: []const u8,
    address: model.Ipv4,
};

pub const UpdateNodeInput = struct {
    name: ?[]const u8 = null,
    vnr: ?[]const u8 = null,
    address: ?model.Ipv4 = null,
};

pub const CreateRouteInput = struct {
    prefix: model.Cidr,
    node_id: model.NodeId,
};

pub const UpdateRouteInput = struct {
    prefix: ?model.Cidr = null,
    node_id: ?model.NodeId = null,
};

pub const Callbacks = struct {
    context: ?*anyopaque = null,
    /// Called synchronously after the new Store projection is installed.
    retire_associations: ?*const fn (?*anyopaque, []const model.NodeId) void = null,
    /// Called exactly once after each committed inventory mutation.
    publish_generation: ?*const fn (?*anyopaque, u64, *const model.Store) void = null,
};

pub const Service = struct {
    repository: *management_repository.Repository,
    live: *model.Store,
    allocator: std.mem.Allocator,
    io: std.Io,
    callbacks: Callbacks = .{},
    /// Points at the constructed runtime capacity in production. A
    /// restart-required settings revision does not change this value until
    /// that revision becomes effective during a clean restart.
    maximum_nodes_source: ?*const u32 = null,

    pub fn init(
        repository: *management_repository.Repository,
        live: *model.Store,
        allocator: std.mem.Allocator,
        io: std.Io,
        callbacks: Callbacks,
    ) Service {
        return .{
            .repository = repository,
            .live = live,
            .allocator = allocator,
            .io = io,
            .callbacks = callbacks,
        };
    }

    pub fn setMaximumNodesSource(self: *Service, source: *const u32) void {
        self.maximum_nodes_source = source;
    }

    pub fn getVnr(self: *Service, principal: Principal, name: []const u8) !VnrRecord {
        try authorize(principal.role, .read);
        return self.readVnr(name);
    }

    pub fn listVnrs(
        self: *Service,
        principal: Principal,
        cursor: ?VnrCursor,
        requested_limit: ?u16,
    ) !VnrPage {
        try authorize(principal.role, .read);
        const limit = try normalizePageLimit(requested_limit);
        var statement = try self.repository.db.prepare(
            "SELECT name, network, prefix, revision, created_at, updated_at " ++
                "FROM vnrs WHERE (?1 = 0 OR name > ?2) " ++
                "ORDER BY name LIMIT ?3;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, @intFromBool(cursor != null));
        try statement.bindText(2, if (cursor) |value| value.after_name.slice() else "");
        try statement.bindInt64(3, @as(u32, limit) + 1);

        var items: std.ArrayList(VnrRecord) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            items.appendAssumeCapacity(try readVnrRow(&statement));
        }
        const next_cursor: ?VnrCursor = if (saw_more)
            .{ .after_name = items.items[items.items.len - 1].name }
        else
            null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next_cursor };
    }

    pub fn getNode(self: *Service, principal: Principal, id: model.NodeId) !NodeRecord {
        try authorize(principal.role, .read);
        return self.readNodeAt(id, try wallSeconds(self.io));
    }

    pub fn listNodes(
        self: *Service,
        principal: Principal,
        cursor: ?NodeCursor,
        requested_limit: ?u16,
        filter: NodeFilter,
    ) !NodePage {
        try authorize(principal.role, .read);
        const limit = try normalizePageLimit(requested_limit);
        const observed_at = try wallSeconds(self.io);
        var statement = try self.repository.db.prepare(
            "WITH projected_nodes AS (SELECT nodes.id,nodes.name,nodes.vnr_name,nodes.address," ++
                enrollment_projection_sql ++
                " AS public_enrollment_state,nodes.revision,nodes.created_at,nodes.updated_at " ++
                "FROM nodes) SELECT id,name,vnr_name,address,public_enrollment_state," ++
                "revision,created_at,updated_at FROM projected_nodes " ++
                "WHERE (?2 = 0 OR id > ?3) AND (?4 = 0 OR vnr_name = ?5) " ++
                "AND (?6 = 0 OR public_enrollment_state = ?7) ORDER BY id LIMIT ?8;",
        );
        defer statement.deinit();
        const zero_id = [_]u8{0} ** 16;
        try statement.bindInt64(1, observed_at);
        try statement.bindInt64(2, @intFromBool(cursor != null));
        try statement.bindBlob(3, if (cursor) |value| &value.after_id.bytes else &zero_id);
        try statement.bindInt64(4, @intFromBool(filter.vnr != null));
        try statement.bindText(5, if (filter.vnr) |value| value.slice() else "");
        try statement.bindInt64(6, @intFromBool(filter.enrollment_state != null));
        try statement.bindText(7, if (filter.enrollment_state) |value| @tagName(value) else "");
        try statement.bindInt64(8, @as(u32, limit) + 1);

        var items: std.ArrayList(NodeRecord) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            items.appendAssumeCapacity(try readNodeRow(&statement));
        }
        const next_cursor: ?NodeCursor = if (saw_more)
            .{ .after_id = items.items[items.items.len - 1].id }
        else
            null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next_cursor };
    }

    pub fn getRoute(self: *Service, principal: Principal, id: model.RouteId) !RouteRecord {
        try authorize(principal.role, .read);
        return self.readRoute(id);
    }

    pub fn listRoutes(
        self: *Service,
        principal: Principal,
        cursor: ?RouteCursor,
        requested_limit: ?u16,
        filter: RouteFilter,
    ) !RoutePage {
        try authorize(principal.role, .read);
        const limit = try normalizePageLimit(requested_limit);
        var statement = try self.repository.db.prepare(
            "SELECT routes.id, routes.network, routes.prefix, nodes.id, nodes.name, " ++
                "routes.revision, routes.created_at, routes.updated_at " ++
                "FROM routes JOIN nodes ON nodes.id = routes.node_id " ++
                "WHERE (?1 = 0 OR routes.id > ?2) " ++
                "AND (?3 = 0 OR routes.node_id = ?4) " ++
                "ORDER BY routes.id LIMIT ?5;",
        );
        defer statement.deinit();
        const zero_id = [_]u8{0} ** 16;
        try statement.bindInt64(1, @intFromBool(cursor != null));
        try statement.bindBlob(2, if (cursor) |value| &value.after_id.bytes else &zero_id);
        try statement.bindInt64(3, @intFromBool(filter.node_id != null));
        try statement.bindBlob(4, if (filter.node_id) |value| &value.bytes else &zero_id);
        try statement.bindInt64(5, @as(u32, limit) + 1);

        var items: std.ArrayList(RouteRecord) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            items.appendAssumeCapacity(try readRouteRow(&statement));
        }
        const next_cursor: ?RouteCursor = if (saw_more)
            .{ .after_id = items.items[items.items.len - 1].id }
        else
            null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next_cursor };
    }

    pub fn createVnr(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        input: CreateVnrInput,
    ) !VnrRecord {
        try authorize(principal.role, .update_inventory);
        try validateMutationContext(context);
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        const outcome = try candidate.createVnr(input.name, input.range);
        const name = model.Name.parse(input.name) catch unreachable;
        const record: VnrRecord = .{
            .name = name,
            .range = input.range,
            .public_range_warning = outcome.public_range_warning,
            .revision = 1,
            .created_at = context.occurred_at,
            .updated_at = context.occurred_at,
        };
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "vnr.create",
            "vnr",
            name.slice(),
            &.{},
        );
        return record;
    }

    pub fn updateVnr(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        name: []const u8,
        supplied_etag: ?[]const u8,
        input: UpdateVnrInput,
    ) !VnrRecord {
        try authorize(principal.role, .update_inventory);
        try validateMutationContext(context);
        const current = try self.readVnr(name);
        try requireFreshEtag(supplied_etag, current.etag());
        if (sameCidr(current.range, input.range)) return error.NoChanges;
        const revision = try nextRevision(current.revision);

        var retire: std.ArrayList(model.NodeId) = .empty;
        defer retire.deinit(self.allocator);
        for (self.live.nodes.items) |node| if (node.vnr.eql(current.name)) {
            try retire.append(self.allocator, node.id);
        };

        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.updateVnrRange(name, input.range);
        const record: VnrRecord = .{
            .name = current.name,
            .range = input.range,
            .public_range_warning = !input.range.isPrivateRange(),
            .revision = revision,
            .created_at = current.created_at,
            .updated_at = context.occurred_at,
        };
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "vnr.update",
            "vnr",
            current.name.slice(),
            retire.items,
        );
        return record;
    }

    pub fn deleteVnr(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        name: []const u8,
        supplied_etag: ?[]const u8,
    ) !void {
        try authorize(principal.role, .delete_inventory);
        try validateMutationContext(context);
        const current = try self.readVnr(name);
        try requireFreshEtag(supplied_etag, current.etag());
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.deleteVnr(name);
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "vnr.delete",
            "vnr",
            current.name.slice(),
            &.{},
        );
    }

    pub fn createNode(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        input: CreateNodeInput,
    ) !NodeRecord {
        try authorize(principal.role, .update_inventory);
        try validateMutationContext(context);
        const maximum_nodes = if (self.maximum_nodes_source) |source|
            source.*
        else
            (settings.OperationalSettings{}).maximum_nodes;
        const admission_capacity = @min(
            maximum_nodes,
            try self.repository.nodeAdmissionCapacity(),
        );
        if (self.live.nodes.items.len >= admission_capacity) return error.MaximumNodesExceeded;
        const id = self.generateUnusedNodeId();
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.createNode(id, input.name, input.vnr, input.address);
        const record: NodeRecord = .{
            .id = id,
            .name = model.Name.parse(input.name) catch unreachable,
            .vnr = model.Name.parse(input.vnr) catch unreachable,
            .address = input.address,
            .enrollment_state = .unenrolled,
            .revision = 1,
            .created_at = context.occurred_at,
            .updated_at = context.occurred_at,
        };
        var id_text: [32]u8 = undefined;
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "node.create",
            "node",
            id.write(&id_text),
            &.{},
        );
        return record;
    }

    pub fn updateNode(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        id: model.NodeId,
        supplied_etag: ?[]const u8,
        input: UpdateNodeInput,
    ) !NodeRecord {
        try authorize(principal.role, .update_inventory);
        try validateMutationContext(context);
        if (input.name == null and input.vnr == null and input.address == null) return error.NoChanges;
        const current = try self.readNode(id);
        try requireFreshEtag(supplied_etag, current.etag());
        const name = if (input.name) |value| value else current.name.slice();
        const vnr = if (input.vnr) |value| value else current.vnr.slice();
        const address = input.address orelse current.address;
        if (current.name.eqlSlice(name) and current.vnr.eqlSlice(vnr) and current.address.value == address.value) {
            return error.NoChanges;
        }
        const revision = try nextRevision(current.revision);

        var retire: std.ArrayList(model.NodeId) = .empty;
        defer retire.deinit(self.allocator);
        try retire.append(self.allocator, id);
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.updateNode(id, name, vnr, address);
        const record: NodeRecord = .{
            .id = id,
            .name = model.Name.parse(name) catch unreachable,
            .vnr = model.Name.parse(vnr) catch unreachable,
            .address = address,
            .enrollment_state = current.enrollment_state,
            .revision = revision,
            .created_at = current.created_at,
            .updated_at = context.occurred_at,
        };
        var id_text: [32]u8 = undefined;
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "node.update",
            "node",
            id.write(&id_text),
            retire.items,
        );
        return record;
    }

    pub fn deleteNode(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        id: model.NodeId,
        supplied_etag: ?[]const u8,
    ) !void {
        try authorize(principal.role, .delete_inventory);
        try validateMutationContext(context);
        const current = try self.readNode(id);
        try requireFreshEtag(supplied_etag, current.etag());
        var retire: std.ArrayList(model.NodeId) = .empty;
        defer retire.deinit(self.allocator);
        try retire.append(self.allocator, id);
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.deleteNode(current.name.slice());
        var id_text: [32]u8 = undefined;
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "node.delete",
            "node",
            id.write(&id_text),
            retire.items,
        );
    }

    pub fn createRoute(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        input: CreateRouteInput,
    ) !RouteRecord {
        try authorize(principal.role, .update_inventory);
        try validateMutationContext(context);
        const owner = self.live.findNodeById(input.node_id) orelse return error.NodeNotFound;
        const id = self.generateUnusedRouteId();
        var retire: std.ArrayList(model.NodeId) = .empty;
        defer retire.deinit(self.allocator);
        try retire.append(self.allocator, owner.id);
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.addRouteWithId(id, input.prefix, owner.name.slice());
        const record: RouteRecord = .{
            .id = id,
            .prefix = input.prefix,
            .node_id = owner.id,
            .node_name = owner.name,
            .revision = 1,
            .created_at = context.occurred_at,
            .updated_at = context.occurred_at,
        };
        var id_text: [32]u8 = undefined;
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "route.create",
            "route",
            id.write(&id_text),
            retire.items,
        );
        return record;
    }

    pub fn updateRoute(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        id: model.RouteId,
        supplied_etag: ?[]const u8,
        input: UpdateRouteInput,
    ) !RouteRecord {
        try authorize(principal.role, .update_inventory);
        try validateMutationContext(context);
        if (input.prefix == null and input.node_id == null) return error.NoChanges;
        const current = try self.readRoute(id);
        try requireFreshEtag(supplied_etag, current.etag());
        const prefix = input.prefix orelse current.prefix;
        const owner_id = input.node_id orelse current.node_id;
        if (sameCidr(prefix, current.prefix) and owner_id.eql(current.node_id)) return error.NoChanges;
        const owner = self.live.findNodeById(owner_id) orelse return error.NodeNotFound;
        const revision = try nextRevision(current.revision);

        var retire: std.ArrayList(model.NodeId) = .empty;
        defer retire.deinit(self.allocator);
        try retire.append(self.allocator, current.node_id);
        if (!owner_id.eql(current.node_id)) try retire.append(self.allocator, owner_id);
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.updateRoute(current.prefix, prefix, owner.name.slice());
        const record: RouteRecord = .{
            .id = id,
            .prefix = prefix,
            .node_id = owner.id,
            .node_name = owner.name,
            .revision = revision,
            .created_at = current.created_at,
            .updated_at = context.occurred_at,
        };
        var id_text: [32]u8 = undefined;
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "route.update",
            "route",
            id.write(&id_text),
            retire.items,
        );
        return record;
    }

    pub fn deleteRoute(
        self: *Service,
        principal: Principal,
        context: MutationContext,
        id: model.RouteId,
        supplied_etag: ?[]const u8,
    ) !void {
        try authorize(principal.role, .delete_inventory);
        try validateMutationContext(context);
        const current = try self.readRoute(id);
        try requireFreshEtag(supplied_etag, current.etag());
        var retire: std.ArrayList(model.NodeId) = .empty;
        defer retire.deinit(self.allocator);
        try retire.append(self.allocator, current.node_id);
        var candidate = try cloneStore(self.allocator, self.live);
        defer candidate.deinit();
        try candidate.deleteRoute(current.prefix);
        var id_text: [32]u8 = undefined;
        try self.commitCandidate(
            &candidate,
            principal,
            context,
            "route.delete",
            "route",
            id.write(&id_text),
            retire.items,
        );
    }

    fn readVnr(self: *Service, name: []const u8) !VnrRecord {
        var statement = try self.repository.db.prepare(
            "SELECT name, network, prefix, revision, created_at, updated_at " ++
                "FROM vnrs WHERE name = ?1;",
        );
        defer statement.deinit();
        try statement.bindText(1, name);
        if (try statement.step() != .row) return error.VnrNotFound;
        const result = try readVnrRow(&statement);
        if (try statement.step() != .done) return error.CorruptInventory;
        return result;
    }

    fn readNode(self: *Service, id: model.NodeId) !NodeRecord {
        return self.readNodeAt(id, try wallSeconds(self.io));
    }

    fn readNodeAt(self: *Service, id: model.NodeId, observed_at: i64) !NodeRecord {
        if (observed_at < 0) return error.InvalidTimestamp;
        var statement = try self.repository.db.prepare(
            "SELECT nodes.id,nodes.name,nodes.vnr_name,nodes.address," ++
                enrollment_projection_sql ++
                ",nodes.revision,nodes.created_at,nodes.updated_at FROM nodes WHERE nodes.id = ?2;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, observed_at);
        try statement.bindBlob(2, &id.bytes);
        if (try statement.step() != .row) return error.NodeNotFound;
        const result = try readNodeRow(&statement);
        if (try statement.step() != .done) return error.CorruptInventory;
        return result;
    }

    fn readRoute(self: *Service, id: model.RouteId) !RouteRecord {
        var statement = try self.repository.db.prepare(
            "SELECT routes.id, routes.network, routes.prefix, nodes.id, nodes.name, " ++
                "routes.revision, routes.created_at, routes.updated_at " ++
                "FROM routes JOIN nodes ON nodes.id = routes.node_id WHERE routes.id = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id.bytes);
        if (try statement.step() != .row) return error.RouteNotFound;
        const result = try readRouteRow(&statement);
        if (try statement.step() != .done) return error.CorruptInventory;
        return result;
    }

    fn generateUnusedNodeId(self: *Service) model.NodeId {
        while (true) {
            const id = model.NodeId.generate(self.io);
            if (self.live.findNodeById(id) == null) return id;
        }
    }

    fn generateUnusedRouteId(self: *Service) model.RouteId {
        while (true) {
            const id = model.RouteId.generate(self.io);
            if (self.live.findRouteById(id) == null) return id;
        }
    }

    /// The repository commit is the final fallible operation. Candidate Store
    /// ownership, retirement storage, resource records, and callback arguments
    /// are all prepared by the caller before entering this function.
    fn commitCandidate(
        self: *Service,
        candidate: *model.Store,
        principal: Principal,
        context: MutationContext,
        action: []const u8,
        resource_type: []const u8,
        resource_id: []const u8,
        retire_ids: []const model.NodeId,
    ) !void {
        const audit_id = model.NodeId.generate(self.io);
        const audit_details = try encodeAuditDetails(self.allocator, context);
        defer self.allocator.free(audit_details);
        const committed_generation = try self.repository.persistInventory(
            candidate,
            self.live.generation,
            context.occurred_at,
            .{
                .id = audit_id.bytes,
                .occurred_at = context.occurred_at,
                .actor_kind = .web,
                .actor_id = principal.id,
                .action = action,
                .resource_type = resource_type,
                .resource_id = resource_id,
                .request_id = context.request_id,
                // Structured details contain transport attribution only: no
                // credential, key material, or private resource projection.
                .details_json = audit_details,
            },
        );
        std.debug.assert(committed_generation == candidate.generation);

        std.mem.swap(model.Store, self.live, candidate);
        if (retire_ids.len != 0) if (self.callbacks.retire_associations) |retire| {
            retire(self.callbacks.context, retire_ids);
        };
        if (self.callbacks.publish_generation) |publish| {
            publish(self.callbacks.context, committed_generation, self.live);
        }
    }
};

fn authorize(role: auth.Role, permission: auth.Permission) !void {
    if (!auth.allows(role, permission)) return error.Forbidden;
}

fn validateMutationContext(context: MutationContext) !void {
    if (context.occurred_at < 0) return error.InvalidTimestamp;
    try validateAuditText(context.user_agent, service_ipc.maximum_user_agent_bytes);
    try validateAuditText(context.proxy_peer, 255);
    if (context.proxy_peer) |peer| if (!std.mem.eql(u8, peer, "loopback")) {
        return error.InvalidAuditMetadata;
    };
}

fn validateAuditText(value: ?[]const u8, maximum: usize) !void {
    const text = value orelse return;
    if (text.len > maximum or !std.unicode.utf8ValidateSlice(text)) {
        return error.InvalidAuditMetadata;
    }
    for (text) |byte| if (byte < 0x20 or byte == 0x7f) {
        return error.InvalidAuditMetadata;
    };
}

fn encodeAuditDetails(allocator: std.mem.Allocator, context: MutationContext) ![]u8 {
    const Details = struct {
        userAgent: ?[]const u8 = null,
        proxyPeer: ?[]const u8 = null,
    };
    return std.json.Stringify.valueAlloc(allocator, Details{
        .userAgent = context.user_agent,
        .proxyPeer = context.proxy_peer,
    }, .{ .emit_null_optional_fields = false });
}

fn normalizePageLimit(requested: ?u16) !u16 {
    const limit = requested orelse default_page_size;
    if (limit == 0 or limit > maximum_page_size) return error.InvalidPageLimit;
    return limit;
}

fn nextRevision(current: u64) !u64 {
    const next = std.math.add(u64, current, 1) catch return error.RevisionOverflow;
    if (next > std.math.maxInt(i64)) return error.RevisionOverflow;
    return next;
}

fn wallSeconds(io: std.Io) !i64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.InvalidTimestamp;
    return seconds;
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

fn readVnrRow(statement: *const sqlite.Statement) !VnrRecord {
    const name_text = statement.columnText(0) orelse return error.CorruptInventory;
    const range: model.Cidr = .{
        .network = .{ .value = try columnU32(statement, 1) },
        .prefix = try columnU8(statement, 2),
    };
    range.validateVnr() catch return error.CorruptInventory;
    return .{
        .name = model.Name.parse(name_text) catch return error.CorruptInventory,
        .range = range,
        .public_range_warning = !range.isPrivateRange(),
        .revision = try columnRevision(statement, 3),
        .created_at = try columnTimestamp(statement, 4),
        .updated_at = try columnTimestamp(statement, 5),
    };
}

fn readNodeRow(statement: *const sqlite.Statement) !NodeRecord {
    const state_text = statement.columnText(4) orelse return error.CorruptInventory;
    const state: EnrollmentState = if (std.mem.eql(u8, state_text, "unenrolled"))
        .unenrolled
    else if (std.mem.eql(u8, state_text, "credential_issued"))
        .credential_issued
    else if (std.mem.eql(u8, state_text, "enrolled"))
        .enrolled
    else
        return error.CorruptInventory;
    return .{
        .id = try columnId(statement, 0),
        .name = model.Name.parse(statement.columnText(1) orelse return error.CorruptInventory) catch
            return error.CorruptInventory,
        .vnr = model.Name.parse(statement.columnText(2) orelse return error.CorruptInventory) catch
            return error.CorruptInventory,
        .address = .{ .value = try columnU32(statement, 3) },
        .enrollment_state = state,
        .revision = try columnRevision(statement, 5),
        .created_at = try columnTimestamp(statement, 6),
        .updated_at = try columnTimestamp(statement, 7),
    };
}

fn readRouteRow(statement: *const sqlite.Statement) !RouteRecord {
    const prefix: model.Cidr = .{
        .network = .{ .value = try columnU32(statement, 1) },
        .prefix = try columnU8(statement, 2),
    };
    prefix.validateRouted() catch return error.CorruptInventory;
    return .{
        .id = try columnId(statement, 0),
        .prefix = prefix,
        .node_id = try columnId(statement, 3),
        .node_name = model.Name.parse(statement.columnText(4) orelse return error.CorruptInventory) catch
            return error.CorruptInventory,
        .revision = try columnRevision(statement, 5),
        .created_at = try columnTimestamp(statement, 6),
        .updated_at = try columnTimestamp(statement, 7),
    };
}

fn columnId(statement: *const sqlite.Statement, index: c_int) !model.NodeId {
    const blob = statement.columnBlob(index) orelse return error.CorruptInventory;
    if (blob.len != 16) return error.CorruptInventory;
    var id: model.NodeId = undefined;
    @memcpy(&id.bytes, blob);
    return id;
}

fn columnU32(statement: *const sqlite.Statement, index: c_int) !u32 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u32)) return error.CorruptInventory;
    return @intCast(value);
}

fn columnU8(statement: *const sqlite.Statement, index: c_int) !u8 {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(u8)) return error.CorruptInventory;
    return @intCast(value);
}

fn columnRevision(statement: *const sqlite.Statement, index: c_int) !u64 {
    const value = statement.columnInt64(index);
    if (value <= 0) return error.CorruptInventory;
    return @intCast(value);
}

fn columnTimestamp(statement: *const sqlite.Statement, index: c_int) !i64 {
    const value = statement.columnInt64(index);
    if (value < 0) return error.CorruptInventory;
    return value;
}

fn sameCidr(left: model.Cidr, right: model.Cidr) bool {
    return left.network.value == right.network.value and left.prefix == right.prefix;
}

fn encodeCursorName(prefix: []const u8, name: model.Name, buffer: *[maximum_cursor_token_bytes]u8) []const u8 {
    @memcpy(buffer[0..prefix.len], prefix);
    encodeLowerHex(name.slice(), buffer[prefix.len .. prefix.len + name.slice().len * 2]);
    return buffer[0 .. prefix.len + name.slice().len * 2];
}

fn encodeCursorId(prefix: []const u8, id: model.NodeId, buffer: *[maximum_cursor_token_bytes]u8) []const u8 {
    @memcpy(buffer[0..prefix.len], prefix);
    encodeLowerHex(&id.bytes, buffer[prefix.len .. prefix.len + 32]);
    return buffer[0 .. prefix.len + 32];
}

fn decodeCursorId(prefix: []const u8, text: []const u8) !model.NodeId {
    if (!std.mem.startsWith(u8, text, prefix) or text.len != prefix.len + 32) return error.InvalidCursor;
    var id: model.NodeId = undefined;
    decodeLowerHex(text[prefix.len..], &id.bytes) catch return error.InvalidCursor;
    return id;
}

fn encodeLowerHex(input: []const u8, output: []u8) void {
    std.debug.assert(output.len == input.len * 2);
    const alphabet = "0123456789abcdef";
    for (input, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
}

fn decodeLowerHex(input: []const u8, output: []u8) error{InvalidHex}!void {
    if (input.len != output.len * 2) return error.InvalidHex;
    for (output, 0..) |*byte, index| {
        const high = decodeNibble(input[index * 2]) orelse return error.InvalidHex;
        const low = decodeNibble(input[index * 2 + 1]) orelse return error.InvalidHex;
        byte.* = high << 4 | low;
    }
}

fn decodeNibble(value: u8) ?u8 {
    return switch (value) {
        '0'...'9' => value - '0',
        'a'...'f' => value - 'a' + 10,
        else => null,
    };
}

const CallbackRecorder = struct {
    publish_count: usize = 0,
    last_generation: u64 = 0,
    retire_count: usize = 0,
    retired: [16]model.NodeId = undefined,
    event_sequence: [32]enum { retire, publish } = undefined,
    event_count: usize = 0,

    fn reset(self: *CallbackRecorder) void {
        self.publish_count = 0;
        self.last_generation = 0;
        self.retire_count = 0;
        self.event_count = 0;
    }

    fn onRetire(context: ?*anyopaque, ids: []const model.NodeId) void {
        const self: *CallbackRecorder = @ptrCast(@alignCast(context.?));
        std.debug.assert(ids.len <= self.retired.len);
        @memcpy(self.retired[0..ids.len], ids);
        self.retire_count = ids.len;
        self.event_sequence[self.event_count] = .retire;
        self.event_count += 1;
    }

    fn onPublish(context: ?*anyopaque, generation: u64, store: *const model.Store) void {
        const self: *CallbackRecorder = @ptrCast(@alignCast(context.?));
        std.debug.assert(generation == store.generation);
        self.publish_count += 1;
        self.last_generation = generation;
        self.event_sequence[self.event_count] = .publish;
        self.event_count += 1;
    }

    fn callbacks(self: *CallbackRecorder) Callbacks {
        return .{
            .context = self,
            .retire_associations = onRetire,
            .publish_generation = onPublish,
        };
    }
};

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testPrincipal(role: auth.Role, byte: u8) Principal {
    return .{ .id = [_]u8{byte} ** 16, .role = role };
}

fn testContext(timestamp: i64, byte: u8) MutationContext {
    return .{ .request_id = [_]u8{byte} ** 16, .occurred_at = timestamp };
}

fn testEnrollmentAudit(byte: u8, timestamp: i64, action: []const u8) management_repository.AuditEntry {
    return .{
        .id = [_]u8{byte} ** 16,
        .occurred_at = timestamp,
        .actor_kind = .system,
        .action = action,
        .resource_type = "node",
        .resource_id = "projection-test",
        .details_json = "{}",
    };
}

fn scalarInt(db: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try db.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const value = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return value;
}

test "inventory RBAC and strong resource preconditions fail distinctly" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    var service = Service.init(&repository, &live, std.testing.allocator, std.testing.io, .{});
    const viewer = testPrincipal(.viewer, 1);
    const operator = testPrincipal(.operator, 2);
    const superuser = testPrincipal(.superuser, 3);

    try std.testing.expectError(
        error.Forbidden,
        service.createVnr(viewer, testContext(100, 1), .{
            .name = "Core",
            .range = try model.Cidr.parse("10.24.0.0/24"),
        }),
    );
    var attributed_context = testContext(101, 2);
    attributed_context.user_agent = "ntip-dashboard-test/1";
    attributed_context.proxy_peer = "loopback";
    const created = try service.createVnr(operator, attributed_context, .{
        .name = "Core",
        .range = try model.Cidr.parse("10.24.0.0/24"),
    });
    try std.testing.expectEqual(@as(u64, 1), created.revision);
    var audit_attribution = try db.prepare(
        "SELECT json_extract(details_json, '$.userAgent'), " ++
            "json_extract(details_json, '$.proxyPeer') FROM audit_entries " ++
            "WHERE action = 'vnr.create';",
    );
    defer audit_attribution.deinit();
    try std.testing.expectEqual(sqlite.Step.row, try audit_attribution.step());
    try std.testing.expectEqualStrings(
        "ntip-dashboard-test/1",
        audit_attribution.columnText(0) orelse return error.MissingAuditUserAgent,
    );
    try std.testing.expectEqualStrings(
        "loopback",
        audit_attribution.columnText(1) orelse return error.MissingAuditProxyPeer,
    );
    try std.testing.expectEqual(sqlite.Step.done, try audit_attribution.step());
    var created_tag = created.etag();
    const parsed = try parseEtag(created_tag.slice());
    try std.testing.expectEqual(ResourceKind.vnr, parsed.kind);
    try std.testing.expectEqual(@as(u64, 1), parsed.revision);

    var page = try service.listVnrs(viewer, null, null);
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), page.items.len);
    try std.testing.expectError(
        error.PreconditionRequired,
        service.updateVnr(operator, testContext(102, 3), "Core", null, .{
            .range = try model.Cidr.parse("10.24.0.0/23"),
        }),
    );
    var stale_tag = ResourceEtag.forVnr(created.name, 2);
    try std.testing.expectError(
        error.PreconditionFailed,
        service.updateVnr(operator, testContext(102, 4), "Core", stale_tag.slice(), .{
            .range = try model.Cidr.parse("10.24.0.0/23"),
        }),
    );
    try std.testing.expectError(
        error.VnrNotFound,
        service.getVnr(viewer, "missing"),
    );
    try std.testing.expectError(
        error.Forbidden,
        service.deleteVnr(operator, testContext(103, 5), "Core", created_tag.slice()),
    );

    const updated = try service.updateVnr(operator, testContext(104, 6), "Core", created_tag.slice(), .{
        .range = try model.Cidr.parse("10.24.0.0/23"),
    });
    try std.testing.expectEqual(@as(u64, 2), updated.revision);
    try std.testing.expectEqual(@as(i64, 101), updated.created_at);
    try std.testing.expectEqual(@as(i64, 104), updated.updated_at);
    try std.testing.expectError(
        error.PreconditionFailed,
        service.deleteVnr(superuser, testContext(105, 7), "Core", created_tag.slice()),
    );
    var updated_tag = updated.etag();
    try service.deleteVnr(superuser, testContext(106, 8), "Core", updated_tag.slice());
    try std.testing.expectEqual(@as(u64, 3), live.generation);
    try std.testing.expectEqual(@as(i64, 3), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE actor_kind = 'web';"));

    var invalid_context = testContext(107, 9);
    invalid_context.proxy_peer = "client-supplied";
    try std.testing.expectError(
        error.InvalidAuditMetadata,
        service.createVnr(operator, invalid_context, .{
            .name = "invalid-attribution",
            .range = try model.Cidr.parse("10.25.0.0/24"),
        }),
    );
}

test "cursor pages are bounded deterministic and round trip opaque tokens" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    var service = Service.init(&repository, &live, std.testing.allocator, std.testing.io, .{});
    const operator = testPrincipal(.operator, 1);
    const viewer = testPrincipal(.viewer, 2);

    _ = try service.createVnr(operator, testContext(100, 1), .{ .name = "alpha", .range = try model.Cidr.parse("10.1.0.0/24") });
    _ = try service.createVnr(operator, testContext(101, 2), .{ .name = "bravo", .range = try model.Cidr.parse("10.2.0.0/24") });
    _ = try service.createVnr(operator, testContext(102, 3), .{ .name = "charlie", .range = try model.Cidr.parse("10.3.0.0/24") });
    _ = try service.createVnr(operator, testContext(103, 4), .{ .name = "delta", .range = try model.Cidr.parse("10.4.0.0/24") });

    try std.testing.expectError(error.InvalidPageLimit, service.listVnrs(viewer, null, 0));
    try std.testing.expectError(error.InvalidPageLimit, service.listVnrs(viewer, null, maximum_page_size + 1));
    var first = try service.listVnrs(viewer, null, 2);
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), first.items.len);
    try std.testing.expectEqualStrings("alpha", first.items[0].name.slice());
    try std.testing.expectEqualStrings("bravo", first.items[1].name.slice());
    try std.testing.expect(first.next_cursor != null);

    var token_buffer: [maximum_cursor_token_bytes]u8 = undefined;
    const token = encodeVnrCursor(first.next_cursor.?, &token_buffer);
    const decoded = try decodeVnrCursor(token);
    try std.testing.expect(decoded.after_name.eql(first.next_cursor.?.after_name));
    try std.testing.expectError(error.InvalidCursor, decodeNodeCursor(token));

    var second = try service.listVnrs(viewer, decoded, 2);
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), second.items.len);
    try std.testing.expectEqualStrings("charlie", second.items[0].name.slice());
    try std.testing.expectEqualStrings("delta", second.items[1].name.slice());
    try std.testing.expect(second.next_cursor == null);

    var default_page = try service.listVnrs(viewer, null, null);
    defer default_page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 4), default_page.items.len);
}

test "Node read model derives credential state expiry replacement reset and filters" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    var service = Service.init(&repository, &live, std.testing.allocator, std.testing.io, .{});
    const operator = testPrincipal(.operator, 1);
    const viewer = testPrincipal(.viewer, 2);
    _ = try service.createVnr(operator, testContext(10, 1), .{
        .name = "core",
        .range = try model.Cidr.parse("10.42.0.0/24"),
    });
    const issued_node = try service.createNode(operator, testContext(11, 2), .{
        .name = "edge-issued",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.42.0.2"),
    });
    const expired_node = try service.createNode(operator, testContext(12, 3), .{
        .name = "edge-expired",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.42.0.3"),
    });
    const enrolled_node = try service.createNode(operator, testContext(13, 4), .{
        .name = "edge-enrolled",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.42.0.4"),
    });
    const now = try wallSeconds(std.testing.io);

    live.generation = try repository.replaceEnrollment(
        issued_node.id,
        [_]u8{0x41} ** 16,
        [_]u8{0x51} ** 32,
        false,
        now,
        now + 3600,
        live.generation,
        testEnrollmentAudit(0x61, now, "enrollment.credential.issue"),
    );
    live.generation = try repository.replaceEnrollment(
        expired_node.id,
        [_]u8{0x42} ** 16,
        [_]u8{0x52} ** 32,
        false,
        now - 120,
        now - 60,
        live.generation,
        testEnrollmentAudit(0x62, now - 120, "enrollment.credential.issue"),
    );
    live.generation = try repository.replaceEnrollment(
        enrolled_node.id,
        [_]u8{0x43} ** 16,
        [_]u8{0x53} ** 32,
        false,
        now,
        now + 3600,
        live.generation,
        testEnrollmentAudit(0x63, now, "enrollment.credential.issue"),
    );
    const consumed = try repository.consumeEnrollment(
        [_]u8{0x43} ** 16,
        [_]u8{0x53} ** 32,
        [_]u8{0x73} ** 32,
        now,
        live.generation,
        testEnrollmentAudit(0x64, now, "enrollment.consume"),
    );
    try live.bindNodePublicKey("edge-enrolled", [_]u8{0x73} ** 32);
    try std.testing.expectEqual(consumed.generation, live.generation);

    try std.testing.expectEqual(
        EnrollmentState.credential_issued,
        (try service.getNode(viewer, issued_node.id)).enrollment_state,
    );
    try std.testing.expectEqual(
        EnrollmentState.unenrolled,
        (try service.getNode(viewer, expired_node.id)).enrollment_state,
    );
    try std.testing.expectEqual(
        EnrollmentState.enrolled,
        (try service.getNode(viewer, enrolled_node.id)).enrollment_state,
    );

    var issued_page = try service.listNodes(viewer, null, 50, .{ .enrollment_state = .credential_issued });
    defer issued_page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), issued_page.items.len);
    try std.testing.expect(issued_page.items[0].id.eql(issued_node.id));
    var unenrolled_page = try service.listNodes(viewer, null, 50, .{ .enrollment_state = .unenrolled });
    defer unenrolled_page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), unenrolled_page.items.len);
    try std.testing.expect(unenrolled_page.items[0].id.eql(expired_node.id));
    var enrolled_page = try service.listNodes(viewer, null, 50, .{ .enrollment_state = .enrolled });
    defer enrolled_page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), enrolled_page.items.len);
    try std.testing.expect(enrolled_page.items[0].id.eql(enrolled_node.id));

    live.generation = try repository.replaceEnrollment(
        issued_node.id,
        [_]u8{0x44} ** 16,
        [_]u8{0x54} ** 32,
        false,
        now,
        now + 7200,
        live.generation,
        testEnrollmentAudit(0x65, now, "enrollment.credential.replace"),
    );
    try std.testing.expectEqual(
        EnrollmentState.credential_issued,
        (try service.getNode(viewer, issued_node.id)).enrollment_state,
    );
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(&db, "SELECT count(*) FROM enrollment_credentials WHERE handle=x'41414141414141414141414141414141' AND status='revoked' AND derived_psk IS NULL;"),
    );

    live.generation = try repository.resetEnrollment(
        issued_node.id,
        now,
        live.generation,
        testEnrollmentAudit(0x66, now, "enrollment.reset"),
    );
    try std.testing.expectEqual(
        EnrollmentState.unenrolled,
        (try service.getNode(viewer, issued_node.id)).enrollment_state,
    );
    var after_reset = try service.listNodes(viewer, null, 50, .{ .enrollment_state = .credential_issued });
    defer after_reset.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), after_reset.items.len);
}

test "Node creation reserves a pending restart capacity reduction without side effects" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    var recorder: CallbackRecorder = .{};
    var service = Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        recorder.callbacks(),
    );
    var effective_maximum_nodes: u32 = 4096;
    service.setMaximumNodesSource(&effective_maximum_nodes);
    const operator = testPrincipal(.operator, 1);

    _ = try service.createVnr(operator, testContext(100, 1), .{
        .name = "core",
        .range = try model.Cidr.parse("10.24.0.0/24"),
    });
    _ = try service.createNode(operator, testContext(101, 2), .{
        .name = "edge-a",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.24.0.2"),
    });
    var desired = settings.OperationalSettings{};
    desired.maximum_nodes = 1;
    const pending = try settings_repository.Repository.init(&db).createRevision(
        [_]u8{0x71} ** 16,
        desired,
        live.nodes.items.len,
        1,
        102,
        .system,
        null,
        testEnrollmentAudit(0x72, 102, "settings.capacity.reduce"),
    );
    try std.testing.expectEqual(settings.RevisionStatus.pending_restart, pending.status);
    try std.testing.expectEqual(@as(u32, 1), try repository.nodeAdmissionCapacity());
    const before_generation = live.generation;
    const before_audits = try scalarInt(&db, "SELECT count(*) FROM audit_entries;");
    recorder.reset();

    try std.testing.expectError(
        error.MaximumNodesExceeded,
        service.createNode(operator, testContext(102, 3), .{
            .name = "edge-b",
            .vnr = "core",
            .address = try model.Ipv4.parse("10.24.0.3"),
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), live.nodes.items.len);
    try std.testing.expectEqual(before_generation, live.generation);
    try std.testing.expectEqual(before_generation, try repository.durableGeneration());
    try std.testing.expectEqual(before_audits, try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
    try std.testing.expectEqual(@as(usize, 0), recorder.retire_count);
    try std.testing.expectEqual(@as(usize, 0), recorder.publish_count);
}

test "route IDs survive edits and postcommit retire sets precede one publication" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    var recorder: CallbackRecorder = .{};
    var service = Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        recorder.callbacks(),
    );
    const operator = testPrincipal(.operator, 1);
    const superuser = testPrincipal(.superuser, 2);

    _ = try service.createVnr(operator, testContext(100, 1), .{
        .name = "core",
        .range = try model.Cidr.parse("10.24.0.0/24"),
    });
    const node_a = try service.createNode(operator, testContext(101, 2), .{
        .name = "edge-a",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.24.0.2"),
    });
    const node_b = try service.createNode(operator, testContext(102, 3), .{
        .name = "edge-b",
        .vnr = "core",
        .address = try model.Ipv4.parse("10.24.0.3"),
    });
    const route = try service.createRoute(operator, testContext(103, 4), .{
        .prefix = try model.Cidr.parse("172.20.0.0/24"),
        .node_id = node_a.id,
    });

    recorder.reset();
    var route_tag = route.etag();
    const edited_route = try service.updateRoute(operator, testContext(104, 5), route.id, route_tag.slice(), .{
        .prefix = try model.Cidr.parse("172.21.0.0/24"),
        .node_id = node_b.id,
    });
    try std.testing.expect(edited_route.id.eql(route.id));
    try std.testing.expectEqual(@as(u64, 2), edited_route.revision);
    try std.testing.expectEqual(@as(usize, 2), recorder.retire_count);
    try std.testing.expect(recorder.retired[0].eql(node_a.id));
    try std.testing.expect(recorder.retired[1].eql(node_b.id));
    try std.testing.expectEqual(@as(usize, 1), recorder.publish_count);
    try std.testing.expectEqual(@as(usize, 2), recorder.event_count);
    try std.testing.expectEqual(.retire, recorder.event_sequence[0]);
    try std.testing.expectEqual(.publish, recorder.event_sequence[1]);
    try std.testing.expectEqual(live.generation, recorder.last_generation);

    recorder.reset();
    var node_tag = node_b.etag();
    const edited_node = try service.updateNode(operator, testContext(105, 6), node_b.id, node_tag.slice(), .{
        .name = "edge-renamed",
        .address = try model.Ipv4.parse("10.24.0.4"),
    });
    try std.testing.expect(edited_node.id.eql(node_b.id));
    try std.testing.expectEqual(@as(usize, 1), recorder.retire_count);
    try std.testing.expect(recorder.retired[0].eql(node_b.id));
    try std.testing.expectEqual(@as(usize, 1), recorder.publish_count);
    const route_after_rename = try service.getRoute(testPrincipal(.viewer, 3), route.id);
    try std.testing.expectEqualStrings("edge-renamed", route_after_rename.node_name.slice());
    try std.testing.expectEqual(@as(u64, 2), route_after_rename.revision);

    recorder.reset();
    const vnr = try service.getVnr(testPrincipal(.viewer, 4), "core");
    var vnr_tag = vnr.etag();
    _ = try service.updateVnr(operator, testContext(106, 7), "core", vnr_tag.slice(), .{
        .range = try model.Cidr.parse("10.24.0.0/23"),
    });
    try std.testing.expectEqual(@as(usize, 2), recorder.retire_count);
    try std.testing.expect(recorder.retired[0].eql(node_a.id));
    try std.testing.expect(recorder.retired[1].eql(node_b.id));
    try std.testing.expectEqual(@as(usize, 1), recorder.publish_count);

    recorder.reset();
    var final_route_tag = route_after_rename.etag();
    try service.deleteRoute(superuser, testContext(107, 8), route.id, final_route_tag.slice());
    try std.testing.expectEqual(@as(usize, 1), recorder.retire_count);
    try std.testing.expect(recorder.retired[0].eql(node_b.id));
    try std.testing.expectEqual(@as(usize, 1), recorder.publish_count);
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM routes;"));
    try std.testing.expectEqual(@as(i64, 8), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE details_json = '{}';"));
}

test "domain invariant failure rolls back audit generation projection and callbacks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    var recorder: CallbackRecorder = .{};
    var service = Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        recorder.callbacks(),
    );
    const operator = testPrincipal(.operator, 1);
    _ = try service.createVnr(operator, testContext(100, 1), .{
        .name = "core",
        .range = try model.Cidr.parse("10.40.0.0/24"),
    });
    _ = try service.createVnr(operator, testContext(101, 2), .{
        .name = "other",
        .range = try model.Cidr.parse("10.41.0.0/24"),
    });
    const before_generation = live.generation;
    const before_audits = try scalarInt(&db, "SELECT count(*) FROM audit_entries;");
    const current = try service.getVnr(testPrincipal(.viewer, 2), "core");
    var tag = current.etag();
    recorder.reset();

    try std.testing.expectError(
        error.VnrOverlap,
        service.updateVnr(operator, testContext(102, 3), "core", tag.slice(), .{
            .range = try model.Cidr.parse("10.41.0.0/24"),
        }),
    );
    try std.testing.expectEqual(before_generation, live.generation);
    try std.testing.expectEqual(before_generation, try repository.durableGeneration());
    try std.testing.expectEqual(before_audits, try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
    try std.testing.expectEqual(@as(usize, 0), recorder.retire_count);
    try std.testing.expectEqual(@as(usize, 0), recorder.publish_count);
    const unchanged = try service.getVnr(testPrincipal(.viewer, 3), "core");
    try std.testing.expect(sameCidr(unchanged.range, try model.Cidr.parse("10.40.0.0/24")));
}
