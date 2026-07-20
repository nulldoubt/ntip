//! Contract-shaped management read models for overview, topology, and live Nodes.
//!
//! This boundary is transport-independent. The serialized operator worker calls
//! it with an authenticated principal, then renders the returned fixed/owned
//! values as camelCase JSON. SQLite remains authoritative for durable inventory
//! metadata and settings, while a type-erased callback supplies bounded runtime
//! observations. No credential, key, protocol session identifier, or software
//! version can enter the public runtime projection.

const std = @import("std");
const model = @import("../domain/model.zig");
const management_repository = @import("../state/management_repository.zig");
const settings_repository = @import("../state/settings_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const auth = @import("auth.zig");
const inventory_service = @import("inventory_service.zig");

pub const default_page_size: u16 = 50;
pub const maximum_page_size: u16 = 200;
pub const maximum_cursor_bytes: usize = 38;
pub const maximum_endpoint_bytes: usize = 255;
pub const maximum_etag_bytes: usize = 80;

pub const Principal = inventory_service.Principal;
pub const Vnr = inventory_service.VnrRecord;
pub const Route = inventory_service.RouteRecord;

pub const EnrollmentState = enum {
    unenrolled,
    credential_issued,
    enrolled,
};

pub const LivenessState = enum {
    unknown,
    online,
    suspect,
    offline,
};

pub const RuntimeSessionState = enum {
    disconnected,
    enrolling,
    connecting,
    established,
};

pub const TrafficState = enum {
    unknown,
    cold,
    warm,
    hot,
    saturated,
};

pub const EndpointText = struct {
    len: u16,
    bytes: [maximum_endpoint_bytes]u8,

    pub fn parse(value: []const u8) !EndpointText {
        if (value.len == 0 or value.len > maximum_endpoint_bytes or
            !std.unicode.utf8ValidateSlice(value))
        {
            return error.InvalidRuntimeEndpoint;
        }
        for (value) |byte| if (byte < 0x20 or byte == 0x7f) {
            return error.InvalidRuntimeEndpoint;
        };
        var result: EndpointText = .{
            .len = @intCast(value.len),
            .bytes = [_]u8{0} ** maximum_endpoint_bytes,
        };
        @memcpy(result.bytes[0..value.len], value);
        return result;
    }

    pub fn slice(self: *const EndpointText) []const u8 {
        std.debug.assert(self.len <= self.bytes.len);
        return self.bytes[0..self.len];
    }
};

/// Wall-clock timestamps are Unix seconds. `observed_at` is supplied by this
/// service so every item in one response represents the same observation cut.
pub const RuntimeObservation = struct {
    liveness: LivenessState = .unknown,
    session_state: RuntimeSessionState = .disconnected,
    observed_endpoint: ?EndpointText = null,
    traffic_state: TrafficState = .unknown,
    authenticated_rx_at: ?i64 = null,
    authenticated_tx_at: ?i64 = null,

    pub fn unavailable() RuntimeObservation {
        return .{};
    }
};

/// Type-erased read-only seam implemented by the Master runtime. Returning
/// `null` means no observation exists for the durable Node. Implementations
/// must copy endpoint text into `EndpointText`; no borrowed runtime memory may
/// escape the callback.
pub const RuntimeSource = struct {
    context: ?*anyopaque = null,
    observe_fn: *const fn (?*anyopaque, model.NodeId, i64) anyerror!?RuntimeObservation,

    pub fn observe(
        self: RuntimeSource,
        node_id: model.NodeId,
        observed_at: i64,
    ) !?RuntimeObservation {
        return self.observe_fn(self.context, node_id, observed_at);
    }
};

pub const RuntimeNode = struct {
    node_id: model.NodeId,
    liveness: LivenessState,
    session_state: RuntimeSessionState,
    observed_endpoint: ?EndpointText,
    traffic_state: TrafficState,
    authenticated_rx_at: ?i64,
    authenticated_tx_at: ?i64,
    observed_at: i64,
};

comptime {
    // This is an intentional compile-time guard on the public read model.
    std.debug.assert(!@hasField(RuntimeNode, "public_key"));
    std.debug.assert(!@hasField(RuntimeNode, "private_key"));
    std.debug.assert(!@hasField(RuntimeNode, "derived_psk"));
    std.debug.assert(!@hasField(RuntimeNode, "receiver_session_id"));
    std.debug.assert(!@hasField(RuntimeNode, "protocol_session_id"));
    std.debug.assert(!@hasField(RuntimeNode, "software_version"));
}

pub const Node = struct {
    id: model.NodeId,
    name: model.Name,
    vnr: model.Name,
    address: model.Ipv4,
    enrollment_state: EnrollmentState,
    revision: u64,
    created_at: i64,
    updated_at: i64,
};

pub const InventoryCounts = struct {
    vnrs: u64,
    nodes: u64,
    routes: u64,
};

pub const RuntimeCounts = struct {
    online: u64 = 0,
    suspect: u64 = 0,
    offline: u64 = 0,
    unknown: u64 = 0,

    fn record(self: *RuntimeCounts, state: LivenessState) !void {
        const counter = switch (state) {
            .online => &self.online,
            .suspect => &self.suspect,
            .offline => &self.offline,
            .unknown => &self.unknown,
        };
        counter.* = std.math.add(u64, counter.*, 1) catch return error.CountOverflow;
    }
};

pub const Overview = struct {
    generation: u64,
    inventory: InventoryCounts,
    runtime: RuntimeCounts,
    desired_settings_revision_id: [16]u8,
    effective_settings_revision_id: [16]u8,
    pending_restart: bool,
    observed_at: i64,
};

pub const StrongEtag = struct {
    bytes: [maximum_etag_bytes]u8,
    len: u8,

    pub fn slice(self: *const StrongEtag) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const OverviewResult = struct {
    value: Overview,
    etag: StrongEtag,
};

pub const Topology = struct {
    generation: u64,
    vnrs: []Vnr,
    nodes: []Node,
    routes: []Route,
    runtime: []RuntimeNode,
    observed_at: i64,

    pub fn deinit(self: *Topology, allocator: std.mem.Allocator) void {
        allocator.free(self.vnrs);
        allocator.free(self.nodes);
        allocator.free(self.routes);
        allocator.free(self.runtime);
        self.* = undefined;
    }
};

pub const TopologyResult = struct {
    value: Topology,
    etag: StrongEtag,

    pub fn deinit(self: *TopologyResult, allocator: std.mem.Allocator) void {
        self.value.deinit(allocator);
        self.* = undefined;
    }
};

pub const RuntimeCursor = struct {
    after_node_id: model.NodeId,
};

pub const RuntimeFilter = struct {
    liveness: ?LivenessState = null,
};

pub const RuntimePage = struct {
    items: []RuntimeNode,
    next_cursor: ?RuntimeCursor,
    observed_at: i64,

    pub fn deinit(self: *RuntimePage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub fn encodeRuntimeCursor(
    cursor: RuntimeCursor,
    buffer: *[maximum_cursor_bytes]u8,
) []const u8 {
    const prefix = "v1:rn:";
    @memcpy(buffer[0..prefix.len], prefix);
    encodeLowerHex(&cursor.after_node_id.bytes, buffer[prefix.len..]);
    return buffer[0 .. prefix.len + 32];
}

pub fn decodeRuntimeCursor(value: []const u8) !RuntimeCursor {
    const prefix = "v1:rn:";
    if (value.len != prefix.len + 32 or !std.mem.startsWith(u8, value, prefix)) {
        return error.InvalidCursor;
    }
    return .{
        .after_node_id = model.NodeId.parse(value[prefix.len..]) catch return error.InvalidCursor,
    };
}

pub const Service = struct {
    allocator: std.mem.Allocator,
    inventory: *inventory_service.Service,
    settings: *settings_repository.Repository,
    runtime_source: ?RuntimeSource,

    pub fn init(
        allocator: std.mem.Allocator,
        inventory: *inventory_service.Service,
        settings: *settings_repository.Repository,
        runtime_source: ?RuntimeSource,
    ) !Service {
        if (inventory.repository.db != settings.db) return error.RepositoryMismatch;
        return .{
            .allocator = allocator,
            .inventory = inventory,
            .settings = settings,
            .runtime_source = runtime_source,
        };
    }

    pub fn setRuntimeSource(self: *Service, source: ?RuntimeSource) void {
        self.runtime_source = source;
    }

    pub fn getOverview(
        self: *Service,
        principal: Principal,
        observed_at: i64,
    ) !OverviewResult {
        try authorize(principal.role);
        try validateTimestamp(observed_at);
        const generation = try self.requireCurrentProjection();
        const state = try self.settings.loadState();

        var runtime_counts: RuntimeCounts = .{};
        for (self.inventory.live.nodes.items) |node| {
            const runtime = try self.observeNode(node.id, observed_at);
            try runtime_counts.record(runtime.liveness);
        }
        try self.ensureProjectionUnchanged(generation);

        const value: Overview = .{
            .generation = generation,
            .inventory = .{
                .vnrs = try countFromUsize(self.inventory.live.vnrs.items.len),
                .nodes = try countFromUsize(self.inventory.live.nodes.items.len),
                .routes = try countFromUsize(self.inventory.live.routes.items.len),
            },
            .runtime = runtime_counts,
            .desired_settings_revision_id = state.desired.id,
            .effective_settings_revision_id = state.effective.id,
            .pending_restart = state.pendingRestart(),
            .observed_at = observed_at,
        };
        return .{ .value = value, .etag = overviewEtag(value) };
    }

    /// Returns every durable object and one runtime row for every Node. Each
    /// collection is ordered by its stable identity so layout and ETags remain
    /// deterministic regardless of insertion order.
    pub fn getTopology(
        self: *Service,
        principal: Principal,
        observed_at: i64,
    ) !TopologyResult {
        try authorize(principal.role);
        try validateTimestamp(observed_at);
        const generation = try self.requireCurrentProjection();

        const vnrs = try self.collectVnrs(principal);
        errdefer self.allocator.free(vnrs);
        const inventory_nodes = try self.collectInventoryNodes(principal);
        defer self.allocator.free(inventory_nodes);
        const issued_ids = try self.collectUsableCredentialNodeIds(observed_at);
        defer self.allocator.free(issued_ids);
        const nodes = try self.projectNodes(inventory_nodes, issued_ids);
        errdefer self.allocator.free(nodes);
        const routes = try self.collectRoutes(principal);
        errdefer self.allocator.free(routes);

        var runtime: std.ArrayList(RuntimeNode) = .empty;
        errdefer runtime.deinit(self.allocator);
        try runtime.ensureTotalCapacity(self.allocator, nodes.len);
        for (nodes) |node| {
            runtime.appendAssumeCapacity(try self.observeNode(node.id, observed_at));
        }
        const runtime_owned = try runtime.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(runtime_owned);
        try self.ensureProjectionUnchanged(generation);

        const value: Topology = .{
            .generation = generation,
            .vnrs = vnrs,
            .nodes = nodes,
            .routes = routes,
            .runtime = runtime_owned,
            .observed_at = observed_at,
        };
        return .{ .value = value, .etag = topologyEtag(value) };
    }

    /// Applies the liveness filter before page truncation. The scan itself may
    /// cross several bounded SQLite pages, but the returned allocation is at
    /// most the requested limit and the cursor advances by stable Node ID.
    pub fn listRuntimeNodes(
        self: *Service,
        principal: Principal,
        cursor: ?RuntimeCursor,
        requested_limit: ?u16,
        filter: RuntimeFilter,
        observed_at: i64,
    ) !RuntimePage {
        try authorize(principal.role);
        try validateTimestamp(observed_at);
        const limit = try normalizePageLimit(requested_limit);
        const generation = try self.requireCurrentProjection();

        var items: std.ArrayList(RuntimeNode) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);

        var scan_cursor: ?inventory_service.NodeCursor = if (cursor) |value|
            .{ .after_id = value.after_node_id }
        else
            null;
        var saw_more = false;
        scan: while (true) {
            var page = try self.inventory.listNodes(
                principal,
                scan_cursor,
                maximum_page_size,
                .{},
            );
            defer page.deinit(self.allocator);
            for (page.items) |node| {
                const runtime = try self.observeNode(node.id, observed_at);
                if (filter.liveness) |required| {
                    if (runtime.liveness != required) continue;
                }
                if (items.items.len == limit) {
                    saw_more = true;
                    break :scan;
                }
                items.appendAssumeCapacity(runtime);
            }
            scan_cursor = page.next_cursor;
            if (scan_cursor == null) break;
        }
        try self.ensureProjectionUnchanged(generation);

        const next_cursor: ?RuntimeCursor = if (saw_more)
            .{ .after_node_id = items.items[items.items.len - 1].node_id }
        else
            null;
        return .{
            .items = try items.toOwnedSlice(self.allocator),
            .next_cursor = next_cursor,
            .observed_at = observed_at,
        };
    }

    /// Returns the runtime projection for one durable Node using the same
    /// coherent-generation checks as the overview, topology, and paginated
    /// runtime views. The Node existence check is authoritative and the
    /// callback result is copied into the secret-free public DTO.
    pub fn getRuntimeNode(
        self: *Service,
        principal: Principal,
        node_id: model.NodeId,
        observed_at: i64,
    ) !RuntimeNode {
        try authorize(principal.role);
        try validateTimestamp(observed_at);
        const generation = try self.requireCurrentProjection();
        _ = try self.inventory.getNode(principal, node_id);
        const runtime = try self.observeNode(node_id, observed_at);
        try self.ensureProjectionUnchanged(generation);
        return runtime;
    }

    fn requireCurrentProjection(self: *Service) !u64 {
        const generation = self.inventory.live.generation;
        if (try self.inventory.repository.durableGeneration() != generation) {
            return error.ProjectionMismatch;
        }
        return generation;
    }

    fn ensureProjectionUnchanged(self: *Service, expected_generation: u64) !void {
        if (self.inventory.live.generation != expected_generation or
            try self.inventory.repository.durableGeneration() != expected_generation)
        {
            return error.ProjectionChanged;
        }
    }

    fn observeNode(
        self: *Service,
        node_id: model.NodeId,
        observed_at: i64,
    ) !RuntimeNode {
        const observation = if (self.runtime_source) |source|
            (try source.observe(node_id, observed_at)) orelse RuntimeObservation.unavailable()
        else
            RuntimeObservation.unavailable();
        try validateObservation(observation);
        return .{
            .node_id = node_id,
            .liveness = observation.liveness,
            .session_state = observation.session_state,
            .observed_endpoint = observation.observed_endpoint,
            .traffic_state = observation.traffic_state,
            .authenticated_rx_at = observation.authenticated_rx_at,
            .authenticated_tx_at = observation.authenticated_tx_at,
            .observed_at = observed_at,
        };
    }

    fn collectVnrs(self: *Service, principal: Principal) ![]Vnr {
        var result: std.ArrayList(Vnr) = .empty;
        errdefer result.deinit(self.allocator);
        var cursor: ?inventory_service.VnrCursor = null;
        while (true) {
            var page = try self.inventory.listVnrs(principal, cursor, maximum_page_size);
            defer page.deinit(self.allocator);
            try result.appendSlice(self.allocator, page.items);
            cursor = page.next_cursor;
            if (cursor == null) break;
        }
        return result.toOwnedSlice(self.allocator);
    }

    fn collectInventoryNodes(
        self: *Service,
        principal: Principal,
    ) ![]inventory_service.NodeRecord {
        var result: std.ArrayList(inventory_service.NodeRecord) = .empty;
        errdefer result.deinit(self.allocator);
        var cursor: ?inventory_service.NodeCursor = null;
        while (true) {
            var page = try self.inventory.listNodes(
                principal,
                cursor,
                maximum_page_size,
                .{},
            );
            defer page.deinit(self.allocator);
            try result.appendSlice(self.allocator, page.items);
            cursor = page.next_cursor;
            if (cursor == null) break;
        }
        return result.toOwnedSlice(self.allocator);
    }

    fn collectRoutes(self: *Service, principal: Principal) ![]Route {
        var result: std.ArrayList(Route) = .empty;
        errdefer result.deinit(self.allocator);
        var cursor: ?inventory_service.RouteCursor = null;
        while (true) {
            var page = try self.inventory.listRoutes(
                principal,
                cursor,
                maximum_page_size,
                .{},
            );
            defer page.deinit(self.allocator);
            try result.appendSlice(self.allocator, page.items);
            cursor = page.next_cursor;
            if (cursor == null) break;
        }
        return result.toOwnedSlice(self.allocator);
    }

    /// Read the issued-but-unused state at the response's single `observedAt`
    /// boundary without ever selecting handle or derived PSK. This one bounded
    /// query intentionally supersedes the per-record Inventory Service
    /// observation time for snapshot assembly; expired credentials therefore
    /// project coherently as `unenrolled` throughout the response.
    fn collectUsableCredentialNodeIds(self: *Service, observed_at: i64) ![]model.NodeId {
        var statement = try self.inventory.repository.db.prepare(
            "SELECT node_id FROM enrollment_credentials " ++
                "WHERE status = 'unused' AND expires_at > ?1 ORDER BY node_id;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, observed_at);

        var ids: std.ArrayList(model.NodeId) = .empty;
        errdefer ids.deinit(self.allocator);
        while (try statement.step() == .row) {
            const bytes = statement.columnBlob(0) orelse return error.CorruptInventory;
            if (bytes.len != 16) return error.CorruptInventory;
            var id: model.NodeId = undefined;
            @memcpy(&id.bytes, bytes);
            try ids.append(self.allocator, id);
        }
        return ids.toOwnedSlice(self.allocator);
    }

    fn projectNodes(
        self: *Service,
        records: []const inventory_service.NodeRecord,
        issued_ids: []const model.NodeId,
    ) ![]Node {
        const nodes = try self.allocator.alloc(Node, records.len);
        errdefer self.allocator.free(nodes);
        var issued_index: usize = 0;
        for (records, 0..) |record, index| {
            while (issued_index < issued_ids.len and
                compareIds(issued_ids[issued_index], record.id) == .lt)
            {
                issued_index += 1;
            }
            const has_credential = issued_index < issued_ids.len and
                compareIds(issued_ids[issued_index], record.id) == .eq;
            nodes[index] = .{
                .id = record.id,
                .name = record.name,
                .vnr = record.vnr,
                .address = record.address,
                .enrollment_state = try projectEnrollmentState(record.enrollment_state, has_credential),
                .revision = record.revision,
                .created_at = record.created_at,
                .updated_at = record.updated_at,
            };
        }
        return nodes;
    }
};

fn projectEnrollmentState(value: anytype, has_credential: bool) !EnrollmentState {
    const name = @tagName(value);
    if (std.mem.eql(u8, name, "enrolled")) return .enrolled;
    if (has_credential) return .credential_issued;
    if (std.mem.eql(u8, name, "unenrolled") or std.mem.eql(u8, name, "credential_issued")) {
        return .unenrolled;
    }
    return error.CorruptInventory;
}

fn authorize(role: auth.Role) !void {
    if (!auth.allows(role, .read)) return error.Forbidden;
}

fn validateTimestamp(value: i64) !void {
    if (value < 0) return error.InvalidTimestamp;
}

fn validateObservation(value: RuntimeObservation) !void {
    if (value.authenticated_rx_at) |timestamp| try validateTimestamp(timestamp);
    if (value.authenticated_tx_at) |timestamp| try validateTimestamp(timestamp);
    if (value.observed_endpoint) |endpoint| {
        if (endpoint.len == 0 or endpoint.len > endpoint.bytes.len) {
            return error.InvalidRuntimeObservation;
        }
        const text = endpoint.bytes[0..endpoint.len];
        if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidRuntimeObservation;
        for (text) |byte| if (byte < 0x20 or byte == 0x7f) {
            return error.InvalidRuntimeObservation;
        };
    }
}

fn normalizePageLimit(requested: ?u16) !usize {
    const value = requested orelse default_page_size;
    if (value == 0 or value > maximum_page_size) return error.InvalidPageLimit;
    return value;
}

fn countFromUsize(value: usize) !u64 {
    return std.math.cast(u64, value) orelse error.CountOverflow;
}

fn compareIds(left: model.NodeId, right: model.NodeId) std.math.Order {
    return std.mem.order(u8, &left.bytes, &right.bytes);
}

const CanonicalHash = struct {
    state: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),

    fn domain(self: *CanonicalHash, value: []const u8) void {
        self.state.update(value);
        self.state.update(&.{0});
    }

    fn bytes(self: *CanonicalHash, value: []const u8) void {
        self.unsigned(@intCast(value.len));
        self.state.update(value);
    }

    fn unsigned(self: *CanonicalHash, value: u64) void {
        var buffer: [8]u8 = undefined;
        std.mem.writeInt(u64, &buffer, value, .big);
        self.state.update(&buffer);
    }

    fn signed(self: *CanonicalHash, value: i64) void {
        var buffer: [8]u8 = undefined;
        std.mem.writeInt(i64, &buffer, value, .big);
        self.state.update(&buffer);
    }

    fn boolean(self: *CanonicalHash, value: bool) void {
        self.state.update(&.{@intFromBool(value)});
    }

    fn id(self: *CanonicalHash, value: [16]u8) void {
        self.state.update(&value);
    }

    fn optionalTimestamp(self: *CanonicalHash, value: ?i64) void {
        if (value) |timestamp| {
            self.boolean(true);
            self.signed(timestamp);
        } else {
            self.boolean(false);
        }
    }

    fn finish(self: *CanonicalHash) StrongEtag {
        var digest: [32]u8 = undefined;
        self.state.final(&digest);
        var digest_text: [64]u8 = undefined;
        encodeLowerHex(&digest, &digest_text);
        var result: StrongEtag = .{
            .bytes = [_]u8{0} ** maximum_etag_bytes,
            .len = 0,
        };
        const rendered = std.fmt.bufPrint(&result.bytes, "\"read:{s}\"", .{&digest_text}) catch unreachable;
        result.len = @intCast(rendered.len);
        return result;
    }
};

fn overviewEtag(value: Overview) StrongEtag {
    var hash: CanonicalHash = .{};
    hash.domain("ntip-overview-v0.2");
    hash.unsigned(value.generation);
    hash.unsigned(value.inventory.vnrs);
    hash.unsigned(value.inventory.nodes);
    hash.unsigned(value.inventory.routes);
    hash.unsigned(value.runtime.online);
    hash.unsigned(value.runtime.suspect);
    hash.unsigned(value.runtime.offline);
    hash.unsigned(value.runtime.unknown);
    hash.id(value.desired_settings_revision_id);
    hash.id(value.effective_settings_revision_id);
    hash.boolean(value.pending_restart);
    hash.signed(value.observed_at);
    return hash.finish();
}

fn topologyEtag(value: Topology) StrongEtag {
    var hash: CanonicalHash = .{};
    hash.domain("ntip-topology-v0.2");
    hash.unsigned(value.generation);
    hash.signed(value.observed_at);

    hash.unsigned(@intCast(value.vnrs.len));
    for (value.vnrs) |vnr| {
        hash.bytes(vnr.name.slice());
        hash.unsigned(vnr.range.network.value);
        hash.unsigned(vnr.range.prefix);
        hash.boolean(vnr.public_range_warning);
        hash.unsigned(vnr.revision);
        hash.signed(vnr.created_at);
        hash.signed(vnr.updated_at);
    }
    hash.unsigned(@intCast(value.nodes.len));
    for (value.nodes) |node| {
        hash.id(node.id.bytes);
        hash.bytes(node.name.slice());
        hash.bytes(node.vnr.slice());
        hash.unsigned(node.address.value);
        hash.unsigned(@intFromEnum(node.enrollment_state));
        hash.unsigned(node.revision);
        hash.signed(node.created_at);
        hash.signed(node.updated_at);
    }
    hash.unsigned(@intCast(value.routes.len));
    for (value.routes) |route| {
        hash.id(route.id.bytes);
        hash.unsigned(route.prefix.network.value);
        hash.unsigned(route.prefix.prefix);
        hash.id(route.node_id.bytes);
        hash.bytes(route.node_name.slice());
        hash.unsigned(route.revision);
        hash.signed(route.created_at);
        hash.signed(route.updated_at);
    }
    hash.unsigned(@intCast(value.runtime.len));
    for (value.runtime) |runtime| hashRuntimeNode(&hash, runtime);
    return hash.finish();
}

fn hashRuntimeNode(hash: *CanonicalHash, runtime: RuntimeNode) void {
    hash.id(runtime.node_id.bytes);
    hash.unsigned(@intFromEnum(runtime.liveness));
    hash.unsigned(@intFromEnum(runtime.session_state));
    if (runtime.observed_endpoint) |endpoint| {
        hash.boolean(true);
        hash.bytes(endpoint.slice());
    } else {
        hash.boolean(false);
    }
    hash.unsigned(@intFromEnum(runtime.traffic_state));
    hash.optionalTimestamp(runtime.authenticated_rx_at);
    hash.optionalTimestamp(runtime.authenticated_tx_at);
    hash.signed(runtime.observed_at);
}

fn encodeLowerHex(source: []const u8, destination: []u8) void {
    std.debug.assert(destination.len == source.len * 2);
    const alphabet = "0123456789abcdef";
    for (source, 0..) |byte, index| {
        destination[index * 2] = alphabet[byte >> 4];
        destination[index * 2 + 1] = alphabet[byte & 0x0f];
    }
}

const FakeRuntime = struct {
    calls: usize = 0,

    fn source(self: *FakeRuntime) RuntimeSource {
        return .{ .context = self, .observe_fn = observeOpaque };
    }

    fn observeOpaque(
        raw: ?*anyopaque,
        node_id: model.NodeId,
        observed_at: i64,
    ) !?RuntimeObservation {
        const self: *FakeRuntime = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
        const ordinal = std.mem.readInt(u16, node_id.bytes[14..16], .big);
        const liveness: LivenessState = switch (ordinal % 4) {
            0 => .online,
            1 => .suspect,
            2 => .offline,
            else => .unknown,
        };
        if (liveness == .unknown) return null;
        return .{
            .liveness = liveness,
            .session_state = if (liveness == .offline) .disconnected else .established,
            .observed_endpoint = try EndpointText.parse("198.51.100.4:51900"),
            .traffic_state = if (liveness == .online) .warm else .cold,
            .authenticated_rx_at = observed_at - 2,
            .authenticated_tx_at = observed_at - 1,
        };
    }
};

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testPrincipal(role: auth.Role, byte: u8) Principal {
    return .{ .id = [_]u8{byte} ** 16, .role = role };
}

fn testAudit(byte: u8, occurred_at: i64, action: []const u8) management_repository.AuditEntry {
    return .{
        .id = [_]u8{byte} ** 16,
        .occurred_at = occurred_at,
        .actor_kind = .system,
        .action = action,
        .resource_type = "read_model_test",
    };
}

fn testNodeId(ordinal: u16) model.NodeId {
    var id: model.NodeId = .{ .bytes = [_]u8{0} ** 16 };
    std.mem.writeInt(u16, id.bytes[14..16], ordinal, .big);
    return id;
}

test "runtime cursor and endpoint inputs are strict and bounded" {
    const cursor: RuntimeCursor = .{ .after_node_id = testNodeId(42) };
    var buffer: [maximum_cursor_bytes]u8 = undefined;
    const encoded = encodeRuntimeCursor(cursor, &buffer);
    const decoded = try decodeRuntimeCursor(encoded);
    try std.testing.expect(decoded.after_node_id.eql(cursor.after_node_id));
    try std.testing.expectError(error.InvalidCursor, decodeRuntimeCursor("v1:n:0000000000000000000000000000002a"));
    try std.testing.expectError(error.InvalidCursor, decodeRuntimeCursor("v1:rn:0000000000000000000000000000002A"));
    try std.testing.expectError(error.InvalidRuntimeEndpoint, EndpointText.parse(""));
    try std.testing.expectError(error.InvalidRuntimeEndpoint, EndpointText.parse("bad\nendpoint"));
}

test "SQLite-backed read models are complete deterministic filtered and secret-free" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path = try testDatabasePath(&tmp, &path_buffer);
    var db = try sqlite.Database.openInitialized(path);
    defer db.close();
    var repository = management_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);

    var live = model.Store.init(std.testing.allocator);
    defer live.deinit();
    _ = try live.createVnr("core", try model.Cidr.parse("10.20.0.0/16"));
    for (1..206) |ordinal| {
        var name_buffer: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buffer, "node-{d:0>3}", .{ordinal});
        try live.createNode(
            testNodeId(@intCast(ordinal)),
            name,
            "core",
            .{ .value = 0x0a14_0001 + @as(u32, @intCast(ordinal)) },
        );
    }
    const route_id = testNodeId(500);
    try live.addRouteWithId(route_id, try model.Cidr.parse("192.168.50.0/24"), "node-001");
    live.generation = 1;
    _ = try repository.persistInventory(&live, 0, 10, testAudit(0x11, 10, "inventory.seed"));

    const credential_node = testNodeId(2);
    live.generation = try repository.replaceEnrollment(
        credential_node,
        [_]u8{0x22} ** 16,
        [_]u8{0x33} ** 32,
        false,
        20,
        1_000,
        live.generation,
        testAudit(0x12, 20, "enrollment.issue"),
    );

    var inventory = inventory_service.Service.init(
        &repository,
        &live,
        std.testing.allocator,
        std.testing.io,
        .{},
    );
    var fake_runtime: FakeRuntime = .{};
    var service = try Service.init(
        std.testing.allocator,
        &inventory,
        &settings,
        fake_runtime.source(),
    );
    const viewer = testPrincipal(.viewer, 1);

    const overview = try service.getOverview(viewer, 100);
    try std.testing.expectEqual(@as(u64, 2), overview.value.generation);
    try std.testing.expectEqual(@as(u64, 1), overview.value.inventory.vnrs);
    try std.testing.expectEqual(@as(u64, 205), overview.value.inventory.nodes);
    try std.testing.expectEqual(@as(u64, 1), overview.value.inventory.routes);
    try std.testing.expectEqual(@as(u64, 51), overview.value.runtime.online);
    try std.testing.expectEqual(@as(u64, 52), overview.value.runtime.suspect);
    try std.testing.expectEqual(@as(u64, 51), overview.value.runtime.offline);
    try std.testing.expectEqual(@as(u64, 51), overview.value.runtime.unknown);
    try std.testing.expect(!overview.value.pending_restart);
    try std.testing.expect(std.mem.startsWith(u8, overview.etag.slice(), "\"read:"));

    // Every role in the documented matrix can read the same durable summary.
    const operator_overview = try service.getOverview(testPrincipal(.operator, 2), 100);
    const superuser_overview = try service.getOverview(testPrincipal(.superuser, 3), 100);
    try std.testing.expectEqualStrings(overview.etag.slice(), operator_overview.etag.slice());
    try std.testing.expectEqualStrings(overview.etag.slice(), superuser_overview.etag.slice());
    try std.testing.expectError(error.InvalidTimestamp, service.getOverview(viewer, -1));

    var topology = try service.getTopology(viewer, 100);
    defer topology.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), topology.value.vnrs.len);
    try std.testing.expectEqual(@as(usize, 205), topology.value.nodes.len);
    try std.testing.expectEqual(@as(usize, 1), topology.value.routes.len);
    try std.testing.expectEqual(topology.value.nodes.len, topology.value.runtime.len);
    try std.testing.expectEqual(EnrollmentState.credential_issued, topology.value.nodes[1].enrollment_state);
    for (topology.value.nodes[1..], topology.value.nodes[0 .. topology.value.nodes.len - 1]) |current, previous| {
        try std.testing.expect(compareIds(previous.id, current.id) == .lt);
    }
    for (topology.value.nodes, topology.value.runtime) |node, runtime| {
        try std.testing.expect(node.id.eql(runtime.node_id));
        try std.testing.expectEqual(@as(i64, 100), runtime.observed_at);
    }

    const node_runtime = try service.getRuntimeNode(viewer, testNodeId(4), 101);
    try std.testing.expect(node_runtime.node_id.eql(testNodeId(4)));
    try std.testing.expectEqual(LivenessState.online, node_runtime.liveness);
    try std.testing.expectEqual(RuntimeSessionState.established, node_runtime.session_state);
    try std.testing.expectEqual(TrafficState.warm, node_runtime.traffic_state);
    try std.testing.expectEqual(@as(i64, 101), node_runtime.observed_at);
    try std.testing.expectEqualStrings(
        "198.51.100.4:51900",
        node_runtime.observed_endpoint.?.slice(),
    );
    try std.testing.expectError(
        error.NodeNotFound,
        service.getRuntimeNode(viewer, testNodeId(999), 101),
    );
    try std.testing.expectError(
        error.InvalidTimestamp,
        service.getRuntimeNode(viewer, testNodeId(4), -1),
    );

    var topology_again = try service.getTopology(viewer, 100);
    defer topology_again.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(topology.etag.slice(), topology_again.etag.slice());

    var after_expiry = try service.getTopology(viewer, 1_000);
    defer after_expiry.deinit(std.testing.allocator);
    try std.testing.expectEqual(EnrollmentState.unenrolled, after_expiry.value.nodes[1].enrollment_state);
    try std.testing.expect(!std.mem.eql(u8, topology.etag.slice(), after_expiry.etag.slice()));

    var first = try service.listRuntimeNodes(
        viewer,
        null,
        2,
        .{ .liveness = .online },
        100,
    );
    defer first.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), first.items.len);
    try std.testing.expect(first.next_cursor != null);
    try std.testing.expectEqual(LivenessState.online, first.items[0].liveness);
    try std.testing.expectEqual(LivenessState.online, first.items[1].liveness);

    var second = try service.listRuntimeNodes(
        viewer,
        first.next_cursor,
        2,
        .{ .liveness = .online },
        100,
    );
    defer second.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), second.items.len);
    try std.testing.expect(compareIds(first.items[1].node_id, second.items[0].node_id) == .lt);
    try std.testing.expectError(
        error.InvalidPageLimit,
        service.listRuntimeNodes(viewer, null, maximum_page_size + 1, .{}, 100),
    );
}

test "runtime callback failures and malformed observations fail closed" {
    const Callbacks = struct {
        fn unavailable(_: ?*anyopaque, _: model.NodeId, _: i64) !?RuntimeObservation {
            return error.RuntimeUnavailable;
        }

        fn malformed(_: ?*anyopaque, _: model.NodeId, _: i64) !?RuntimeObservation {
            return .{ .authenticated_rx_at = -1 };
        }
    };
    const unavailable: RuntimeSource = .{ .observe_fn = Callbacks.unavailable };
    try std.testing.expectError(error.RuntimeUnavailable, unavailable.observe(testNodeId(1), 100));
    const malformed_source: RuntimeSource = .{ .observe_fn = Callbacks.malformed };
    const malformed = (try malformed_source.observe(testNodeId(1), 100)).?;
    try std.testing.expectError(error.InvalidTimestamp, validateObservation(malformed));
}
