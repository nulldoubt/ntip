//! Transport-independent operations, settings, and service-control boundary.
//!
//! The serialized operator worker is the sole production caller. Durable
//! mutations are delegated to `operations_repository` and
//! `settings_repository`; filtered read models use prepared statements through
//! those repositories' authoritative database handle. HTTP framing, Unix
//! socket authentication, and response-frame sequencing deliberately remain
//! outside this module.

const std = @import("std");
const auth = @import("auth.zig");
const api_error = @import("error.zig");
const api_response = @import("api_response.zig");
const security_policy = @import("security_policy.zig");
const service_ipc = @import("service_ipc.zig");
const settings_model = @import("settings.zig");
const ipv4 = @import("../domain/ipv4.zig");
const management_repository = @import("../state/management_repository.zig");
const operations_repository = @import("../state/operations_repository.zig");
const settings_repository = @import("../state/settings_repository.zig");
const sqlite = @import("../state/sqlite.zig");

pub const default_page_size: u16 = 50;
pub const maximum_page_size: u16 = 200;
pub const maximum_cursor_bytes: usize = 96;
pub const maximum_etag_bytes: usize = 112;
pub const export_checkpoint_interval: u16 = 64;
pub const restart_exit_status: u8 = 75;
pub const shutdown_exit_status: u8 = 0;

pub const ErrorCode = api_error.Code;
pub const OperationalSettings = settings_model.OperationalSettings;
pub const ConnectivityStatus = operations_repository.ConnectivityStatus;

pub const Principal = struct {
    user_id: [16]u8,
    session_id: [16]u8,
    role: auth.Role,
    user_agent: ?UserAgentText = null,
    proxy_peer: ?ProxyPeerText = null,
};

/// Preconditions have already crossed strict service-IPC decoding, but are
/// checked again at this application boundary so direct callers cannot bypass
/// authorization, concurrency, or POST replay policy.
///
/// The central API dispatcher owns idempotency reservation, request-hash
/// conflict detection, and response replay because those require the final
/// transport encoding. It must reserve before invoking a mutating method and
/// commit the encoded response afterward. This boundary still requires and
/// validates the key on every POST so a direct caller cannot omit that step.
pub const RequestContext = struct {
    request_id: [16]u8,
    now_unix_ms: i64,
    deadline_unix_ms: ?i64 = null,
    preconditions: service_ipc.Preconditions = .{},

    pub fn unixSeconds(self: RequestContext) !i64 {
        if (self.now_unix_ms < 0) return error.InvalidTimestamp;
        return @divFloor(self.now_unix_ms, 1000);
    }

    pub fn requireIdempotency(self: RequestContext) ![32]u8 {
        const key = self.preconditions.idempotency_key orelse return error.IdempotencyRequired;
        if (key.len == 0 or key.len > service_ipc.maximum_idempotency_key_bytes) {
            return error.InvalidIdempotencyKey;
        }
        for (key) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidIdempotencyKey;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(key, &digest, .{});
        return digest;
    }

    pub fn requireLiveDeadline(self: RequestContext) !i64 {
        const deadline = self.deadline_unix_ms orelse return error.DeadlineRequired;
        if (deadline <= 0) return error.InvalidDeadline;
        if (self.now_unix_ms >= deadline) return error.DeadlineExceeded;
        return deadline;
    }
};

fn BoundedText(comptime maximum: usize, comptime allow_empty: bool) type {
    return struct {
        const Self = @This();
        len: u16,
        bytes: [maximum]u8,

        pub fn parse(value: []const u8) !Self {
            if ((!allow_empty and value.len == 0) or value.len > maximum or
                !std.unicode.utf8ValidateSlice(value)) return error.InvalidText;
            for (value) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidText;
            var result: Self = .{ .len = @intCast(value.len), .bytes = [_]u8{0} ** maximum };
            @memcpy(result.bytes[0..value.len], value);
            return result;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

fn ContractCode(comptime maximum: usize, comptime allow_dot: bool) type {
    return struct {
        const Self = @This();
        len: u8,
        bytes: [maximum]u8,

        pub fn parse(value: []const u8) !Self {
            if (value.len == 0 or value.len > maximum or value[0] < 'a' or value[0] > 'z') {
                return error.InvalidText;
            }
            for (value) |byte| switch (byte) {
                'a'...'z', '0'...'9', '_' => {},
                '.' => if (!allow_dot) return error.InvalidText,
                else => return error.InvalidText,
            };
            var result: Self = .{ .len = @intCast(value.len), .bytes = [_]u8{0} ** maximum };
            @memcpy(result.bytes[0..value.len], value);
            return result;
        }

        pub fn slice(self: *const Self) []const u8 {
            return self.bytes[0..self.len];
        }
    };
}

pub const KindText = ContractCode(128, true);
pub const ResourceTypeText = BoundedText(64, false);
pub const ResourceIdText = BoundedText(128, false);
pub const AddressText = BoundedText(63, false);
pub const UsernameText = BoundedText(63, false);
pub const UserAgentText = BoundedText(512, true);
pub const ProxyPeerText = BoundedText(255, true);
pub const FailureText = ContractCode(64, false);

pub const EventSeverity = enum { info, warning, critical };

pub const Event = struct {
    id: [16]u8,
    kind: KindText,
    severity: EventSeverity,
    resource_type: ResourceTypeText,
    resource_id: ?ResourceIdText,
    occurred_at: i64,

    /// Summaries are intentionally derived from the bounded event kind. Raw
    /// details JSON may contain internal diagnostics and is never projected.
    pub fn summary(self: *const Event) []const u8 {
        return self.kind.slice();
    }
};

pub const EventCursor = struct { observed_at: i64, before_id: [16]u8 };

pub const EventFilter = struct {
    severity: ?EventSeverity = null,
    node_id: ?[16]u8 = null,
    since_unix_seconds: ?i64 = null,
};

pub const EventPage = struct {
    items: []Event,
    next_cursor: ?EventCursor,

    pub fn deinit(self: *EventPage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const AuditActorType = enum { web_user, local_cli, system };
pub const AuditOutcome = enum { succeeded };

pub const AuditEntry = struct {
    sequence: u64,
    id: [16]u8,
    actor_type: AuditActorType,
    actor_user_id: ?[16]u8,
    actor_username: ?UsernameText,
    action: KindText,
    resource_type: ResourceTypeText,
    resource_id: ?ResourceIdText,
    outcome: AuditOutcome = .succeeded,
    request_id: ?[16]u8,
    user_agent: ?UserAgentText,
    proxy_peer: ?ProxyPeerText,
    occurred_at: i64,
    redacted: bool,
};

pub const AuditCursor = struct { before_sequence: u64 };

pub const AuditFilter = struct {
    actor_user_id: ?[16]u8 = null,
    resource_type: ?ResourceTypeText = null,
    since_unix_seconds: ?i64 = null,
};

pub const AuditPage = struct {
    items: []AuditEntry,
    next_cursor: ?AuditCursor,

    pub fn deinit(self: *AuditPage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const ConnectivityCheck = struct {
    id: [16]u8,
    /// Historical results remain readable after their target Node is deleted;
    /// the schema intentionally clears the foreign key while retaining the
    /// immutable target-address snapshot.
    node_id: ?[16]u8,
    node_address: AddressText,
    status: ConnectivityStatus,
    timeout_milliseconds: u16,
    round_trip_milliseconds: ?f64,
    failure_code: ?FailureText,
    created_at: i64,
    started_at: ?i64,
    completed_at: ?i64,
};

pub const ConnectivityCursor = struct { requested_at: i64, before_id: [16]u8 };

pub const ConnectivityFilter = struct {
    node_id: ?[16]u8 = null,
    status: ?ConnectivityStatus = null,
};

pub const ConnectivityPage = struct {
    items: []ConnectivityCheck,
    next_cursor: ?ConnectivityCursor,

    pub fn deinit(self: *ConnectivityPage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const StartConnectivityInput = struct {
    node_id: [16]u8,
    timeout_milliseconds: u16 = 3_000,
};

pub const ConnectivityDispatcher = struct {
    context: ?*anyopaque = null,
    dispatch_fn: *const fn (
        ?*anyopaque,
        [16]u8,
        [16]u8,
        []const u8,
        u16,
    ) anyerror!void,

    pub fn dispatch(
        self: ConnectivityDispatcher,
        check_id: [16]u8,
        node_id: [16]u8,
        node_address: []const u8,
        timeout_milliseconds: u16,
    ) !void {
        return self.dispatch_fn(self.context, check_id, node_id, node_address, timeout_milliseconds);
    }
};

pub const SettingsRevision = struct {
    id: [16]u8,
    sequence: u64,
    status: settings_model.RevisionStatus,
    values: OperationalSettings,
    created_by_user_id: ?[16]u8,
    created_at: i64,
    applied_at: ?i64,
    failure_code: ?FailureText,
};

pub const SettingsState = struct {
    desired: SettingsRevision,
    effective: SettingsRevision,
    pending_restart: bool,
};

pub const SettingsCursor = struct { before_sequence: u64 };

pub const SettingsPage = struct {
    items: []SettingsRevision,
    next_cursor: ?SettingsCursor,

    pub fn deinit(self: *SettingsPage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

pub const SettingsPatch = struct {
    inner_mtu: ?u16 = null,
    heartbeat_idle_seconds: ?u16 = null,
    suspect_after_seconds: ?u16 = null,
    offline_after_seconds: ?u16 = null,
    default_enrollment_lifetime_seconds: ?u32 = null,
    maximum_nodes: ?u32 = null,
    traffic_cold_after_seconds: ?u32 = null,
    traffic_hot_packets_per_second: ?u64 = null,
    traffic_hot_bits_per_second: ?u64 = null,
    traffic_saturated_queue_percent: ?u8 = null,
    traffic_hysteresis_seconds: ?u32 = null,
    runtime_event_retention_days: ?u16 = null,
    connectivity_result_retention_days: ?u16 = null,

    pub fn apply(self: SettingsPatch, current: OperationalSettings) !OperationalSettings {
        if (!self.hasChanges()) return error.NoSettingsChanges;
        var result = current;
        if (self.inner_mtu) |value| result.inner_mtu = value;
        if (self.heartbeat_idle_seconds) |value| result.heartbeat_idle_seconds = value;
        if (self.suspect_after_seconds) |value| result.suspect_after_seconds = value;
        if (self.offline_after_seconds) |value| result.offline_after_seconds = value;
        if (self.default_enrollment_lifetime_seconds) |value| result.default_enrollment_lifetime_seconds = value;
        if (self.maximum_nodes) |value| result.maximum_nodes = value;
        if (self.traffic_cold_after_seconds) |value| result.traffic_cold_after_seconds = value;
        if (self.traffic_hot_packets_per_second) |value| result.traffic_hot_packets_per_second = value;
        if (self.traffic_hot_bits_per_second) |value| result.traffic_hot_bits_per_second = value;
        if (self.traffic_saturated_queue_percent) |value| result.traffic_saturated_queue_percent = value;
        if (self.traffic_hysteresis_seconds) |value| result.traffic_hysteresis_seconds = value;
        if (self.runtime_event_retention_days) |value| result.runtime_event_retention_days = value;
        if (self.connectivity_result_retention_days) |value| result.connectivity_result_retention_days = value;
        return result;
    }

    fn hasChanges(self: SettingsPatch) bool {
        return self.inner_mtu != null or self.heartbeat_idle_seconds != null or
            self.suspect_after_seconds != null or self.offline_after_seconds != null or
            self.default_enrollment_lifetime_seconds != null or self.maximum_nodes != null or
            self.traffic_cold_after_seconds != null or self.traffic_hot_packets_per_second != null or
            self.traffic_hot_bits_per_second != null or self.traffic_saturated_queue_percent != null or
            self.traffic_hysteresis_seconds != null or self.runtime_event_retention_days != null or
            self.connectivity_result_retention_days != null;
    }
};

pub const SettingsPublisher = struct {
    context: ?*anyopaque = null,
    publish_fn: *const fn (?*anyopaque, u64, OperationalSettings) void,

    pub fn publish(self: SettingsPublisher, sequence: u64, values: OperationalSettings) void {
        self.publish_fn(self.context, sequence, values);
    }
};

pub const ControlKind = enum { restart, shutdown };

pub const ControlDecision = struct {
    id: [16]u8,
    kind: ControlKind,
    accepted_at: i64,
    exit_status: u8,
};

pub const ControlState = struct {
    instance_id: [16]u8,
    revision: u64 = 1,
    managed_restart_supported: bool,
    /// A durable audit entry exists, but the central API dispatcher has not
    /// yet committed the matching idempotency response. Runtime code must
    /// never treat this as executable.
    staged: ?ControlDecision = null,
    /// An exact staged decision moves here only after the accepted response
    /// has a durable completion marker. The serialized runtime loop observes
    /// this only after the response write succeeds or fails, preserving both
    /// normal flush-before-exit ordering and peer-disconnect at-most-once
    /// execution.
    pending: ?ControlDecision = null,
};

pub const ControlStageCheckpoint = struct {
    revision: u64,
    staged_id: ?[16]u8,
    pending_id: ?[16]u8,
};

pub const StrongEtag = struct {
    bytes: [maximum_etag_bytes]u8,
    len: u8,

    pub fn slice(self: *const StrongEtag) []const u8 {
        return self.bytes[0..self.len];
    }
};

/// A sink used by audit export. `write` must not retain the borrowed bytes.
/// The service calls `flush` before committing the matching export receipt.
pub const ExportWriter = struct {
    context: *anyopaque,
    begin_fn: *const fn (*anyopaque, [16]u8, [16]u8) anyerror!void,
    write_fn: *const fn (*anyopaque, []const u8) anyerror!void,
    flush_fn: *const fn (*anyopaque) anyerror!void,

    /// Stages the response header metadata before the first body frame. The
    /// sink must not flush headers from this callback.
    pub fn begin(self: ExportWriter, export_id: [16]u8, through_audit_id: [16]u8) !void {
        return self.begin_fn(self.context, export_id, through_audit_id);
    }

    pub fn write(self: ExportWriter, bytes: []const u8) !void {
        return self.write_fn(self.context, bytes);
    }

    pub fn flush(self: ExportWriter) !void {
        return self.flush_fn(self.context);
    }
};

/// Production installs a checkpoint that tests the live service-IPC deadline
/// and yields to higher-priority protocol persistence. It is invoked before
/// export begins and after each bounded batch; it must not retain the database
/// statement or call this Service recursively.
pub const ExportCheckpoint = struct {
    context: ?*anyopaque = null,
    checkpoint_fn: *const fn (?*anyopaque, i64) anyerror!void,

    pub fn run(self: ExportCheckpoint, deadline_unix_ms: i64) !void {
        return self.checkpoint_fn(self.context, deadline_unix_ms);
    }
};

pub const ExportResult = struct {
    receipt: operations_repository.ExportReceipt,
    exported_through_audit_id: [16]u8,
    etag: StrongEtag,
};

pub const PruneResult = struct {
    export_id: [16]u8,
    through_audit_id: [16]u8,
    pruned_entries: u64,
    pruned_at: i64,
    etag: StrongEtag,
};

pub const Service = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    operations: *operations_repository.Repository,
    settings: *settings_repository.Repository,
    control: *ControlState,
    connectivity_dispatcher: ?ConnectivityDispatcher = null,
    settings_publisher: ?SettingsPublisher = null,
    export_checkpoint: ?ExportCheckpoint = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        operations: *operations_repository.Repository,
        settings: *settings_repository.Repository,
        control: *ControlState,
        connectivity_dispatcher: ?ConnectivityDispatcher,
        settings_publisher: ?SettingsPublisher,
    ) Service {
        return .{
            .allocator = allocator,
            .io = io,
            .operations = operations,
            .settings = settings,
            .control = control,
            .connectivity_dispatcher = connectivity_dispatcher,
            .settings_publisher = settings_publisher,
        };
    }

    pub fn listEvents(
        self: *Service,
        principal: Principal,
        cursor: ?EventCursor,
        requested_limit: ?u16,
        filter: EventFilter,
    ) !EventPage {
        try authorize(principal, .read);
        try validateEventFilter(filter);
        const limit = try normalizePageLimit(requested_limit);
        var statement = try self.operations.db.prepare(
            "SELECT id,kind,severity,node_id,observed_at FROM runtime_events " ++
                "WHERE (?1 = 0 OR observed_at < ?2 OR (observed_at = ?2 AND id < ?3)) " ++
                "AND (?4 = 0 OR severity = ?5) AND (?6 = 0 OR node_id = ?7) " ++
                "AND (?8 = 0 OR observed_at >= ?9) " ++
                "ORDER BY observed_at DESC,id DESC LIMIT ?10;",
        );
        defer statement.deinit();
        try bindCompositeCursor(&statement, cursor != null, if (cursor) |value| value.observed_at else 0, if (cursor) |value| value.before_id else zero_id);
        try statement.bindInt64(4, @intFromBool(filter.severity != null));
        try statement.bindText(5, if (filter.severity) |value| eventSeverityStorage(value) else "");
        try statement.bindInt64(6, @intFromBool(filter.node_id != null));
        try statement.bindBlob(7, if (filter.node_id) |*value| value else &zero_id);
        try statement.bindInt64(8, @intFromBool(filter.since_unix_seconds != null));
        try statement.bindInt64(9, filter.since_unix_seconds orelse 0);
        try statement.bindInt64(10, @as(u32, limit) + 1);

        var items: std.ArrayList(Event) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            items.appendAssumeCapacity(try decodeEvent(&statement));
        }
        const next: ?EventCursor = if (saw_more) .{
            .observed_at = items.items[items.items.len - 1].occurred_at,
            .before_id = items.items[items.items.len - 1].id,
        } else null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next };
    }

    pub fn listAudit(
        self: *Service,
        principal: Principal,
        cursor: ?AuditCursor,
        requested_limit: ?u16,
        filter: AuditFilter,
    ) !AuditPage {
        try authorize(principal, .read);
        if (filter.actor_user_id != null and principal.role != .superuser) return error.Forbidden;
        try validateAuditFilter(filter);
        const limit = try normalizePageLimit(requested_limit);
        var statement = try self.operations.db.prepare(
            "SELECT a.sequence,a.id,a.occurred_at,a.actor_kind,a.actor_id,a.action," ++
                "a.resource_type,a.resource_id,a.request_id," ++
                "coalesce((SELECT username FROM users WHERE id = a.actor_id)," ++
                "(SELECT username FROM user_tombstones WHERE former_user_id = a.actor_id))," ++
                "CASE WHEN json_type(a.details_json,'$.userAgent') = 'text' " ++
                "THEN json_extract(a.details_json,'$.userAgent') END," ++
                "CASE WHEN json_type(a.details_json,'$.proxyPeer') = 'text' " ++
                "THEN json_extract(a.details_json,'$.proxyPeer') END " ++
                "FROM audit_entries AS a " ++
                "WHERE (?1 = 0 OR a.sequence < ?2) AND (?3 = 0 OR a.actor_id = ?4) " ++
                "AND (?5 = 0 OR a.resource_type = ?6) AND (?7 = 0 OR a.occurred_at >= ?8) " ++
                "ORDER BY a.sequence DESC LIMIT ?9;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, @intFromBool(cursor != null));
        try statement.bindInt64(2, if (cursor) |value| try validPositiveSequence(value.before_sequence) else 0);
        try statement.bindInt64(3, @intFromBool(filter.actor_user_id != null));
        try statement.bindBlob(4, if (filter.actor_user_id) |*value| value else &zero_id);
        try statement.bindInt64(5, @intFromBool(filter.resource_type != null));
        try statement.bindText(6, if (filter.resource_type) |*value| value.slice() else "");
        try statement.bindInt64(7, @intFromBool(filter.since_unix_seconds != null));
        try statement.bindInt64(8, filter.since_unix_seconds orelse 0);
        try statement.bindInt64(9, @as(u32, limit) + 1);

        var items: std.ArrayList(AuditEntry) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            items.appendAssumeCapacity(try decodeAudit(&statement, principal.role == .superuser));
        }
        const next: ?AuditCursor = if (saw_more)
            .{ .before_sequence = items.items[items.items.len - 1].sequence }
        else
            null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next };
    }

    pub fn listConnectivityChecks(
        self: *Service,
        principal: Principal,
        cursor: ?ConnectivityCursor,
        requested_limit: ?u16,
        filter: ConnectivityFilter,
    ) !ConnectivityPage {
        try authorize(principal, .read);
        if (filter.node_id) |value| if (allZero(&value)) return error.InvalidNodeId;
        const limit = try normalizePageLimit(requested_limit);
        var statement = try self.operations.db.prepare(
            "SELECT id,node_id,node_name,status,timeout_ms,requested_at,started_at," ++
                "completed_at,rtt_microseconds,error_code FROM connectivity_checks " ++
                "WHERE (?1 = 0 OR requested_at < ?2 OR (requested_at = ?2 AND id < ?3)) " ++
                "AND (?4 = 0 OR node_id = ?5) AND (?6 = 0 OR status = ?7) " ++
                "ORDER BY requested_at DESC,id DESC LIMIT ?8;",
        );
        defer statement.deinit();
        try bindCompositeCursor(&statement, cursor != null, if (cursor) |value| value.requested_at else 0, if (cursor) |value| value.before_id else zero_id);
        try statement.bindInt64(4, @intFromBool(filter.node_id != null));
        try statement.bindBlob(5, if (filter.node_id) |*value| value else &zero_id);
        try statement.bindInt64(6, @intFromBool(filter.status != null));
        try statement.bindText(7, if (filter.status) |value| @tagName(value) else "");
        try statement.bindInt64(8, @as(u32, limit) + 1);

        var items: std.ArrayList(ConnectivityCheck) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            items.appendAssumeCapacity(try decodeConnectivity(&statement));
        }
        const next: ?ConnectivityCursor = if (saw_more) .{
            .requested_at = items.items[items.items.len - 1].created_at,
            .before_id = items.items[items.items.len - 1].id,
        } else null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next };
    }

    pub fn getConnectivityCheck(self: *Service, principal: Principal, id: [16]u8) !ConnectivityCheck {
        try authorize(principal, .read);
        return self.readConnectivity(id);
    }

    pub fn startConnectivityCheck(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        input: StartConnectivityInput,
    ) !ConnectivityCheck {
        try authorize(principal, .run_connectivity_check);
        try validatePrincipalAndContext(principal, context);
        _ = try context.requireIdempotency();
        if (input.timeout_milliseconds < operations_repository.minimum_check_timeout_ms or
            input.timeout_milliseconds > operations_repository.maximum_check_timeout_ms)
        {
            return error.InvalidConnectivityTimeout;
        }
        const now = try context.unixSeconds();
        const address = try self.readNodeAddress(input.node_id);
        const check_id = randomId(self.io);
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        var check_text: [32]u8 = undefined;
        try self.operations.createConnectivityCheck(.{
            .id = check_id,
            .node_id = input.node_id,
            // The v0.2 schema's historical `node_name` column stores the
            // immutable target-address snapshot used by the public DTO.
            .node_name = address.slice(),
            .requested_by_kind = .web,
            .requested_by_id = principal.user_id,
            .timeout_ms = input.timeout_milliseconds,
            .requested_at = now,
        }, makeAudit(
            randomId(self.io),
            principal,
            context.request_id,
            now,
            "connectivity_check.create",
            "connectivity_check",
            encodeId(check_id, &check_text),
            audit_details,
        ));

        if (self.connectivity_dispatcher) |dispatcher| {
            dispatcher.dispatch(check_id, input.node_id, address.slice(), input.timeout_milliseconds) catch {
                try self.operations.transitionConnectivityCheck(check_id, .failed, now, null, "dispatch_unavailable");
                return error.ConnectivityDispatchUnavailable;
            };
            // Admission reserves a terminal-result slot before returning, so
            // the durable state may enter `running` without a lost-completion
            // race. DATA-path failures are reported asynchronously through the
            // matching completion seam.
            try self.operations.transitionConnectivityCheck(check_id, .running, now, null, null);
        } else {
            try self.operations.transitionConnectivityCheck(check_id, .failed, now, null, "dispatch_unavailable");
            return error.ConnectivityDispatchUnavailable;
        }
        return self.readConnectivity(check_id);
    }

    pub fn auditEtag(self: *Service, principal: Principal) !StrongEtag {
        try authorize(principal, .read);
        return makeAuditEtag(try latestAuditSequence(self.operations.db));
    }

    pub fn exportAudit(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        through_audit_id: [16]u8,
        writer: ExportWriter,
    ) !ExportResult {
        try authorize(principal, .manage_audit);
        try validatePrincipalAndContext(principal, context);
        const current_etag = makeAuditEtag(try latestAuditSequence(self.operations.db));
        try validateDangerous(principal, context, &current_etag, "export audit");
        _ = try context.requireIdempotency();
        const deadline = try context.requireLiveDeadline();
        if (self.export_checkpoint) |checkpoint| try checkpoint.run(deadline);
        const now = try context.unixSeconds();
        const through_sequence = try auditSequenceForId(self.operations.db, through_audit_id);
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        const export_id = randomId(self.io);
        try writer.begin(export_id, through_audit_id);

        var accumulator: operations_repository.ExportAccumulator = .{};
        var exported_through_sequence: u64 = 0;
        while (true) {
            const batch = try self.writeAuditExportBatch(
                exported_through_sequence,
                through_sequence,
                writer,
                &accumulator,
            );
            if (batch.entry_count == 0) break;
            exported_through_sequence = batch.last_sequence;
            // `writeAuditExportBatch` has finalized its SELECT before this
            // checkpoint. The production callback may therefore advance
            // higher-priority protocol persistence on the same SQLite owner
            // without re-entering the service API or retaining an audit read.
            if (self.export_checkpoint) |checkpoint| try checkpoint.run(deadline);
            if (exported_through_sequence == through_sequence) break;
        }
        const receipt = try accumulator.finish(export_id, .web, principal.user_id, now);
        try writer.flush();
        var receipt_text: [32]u8 = undefined;
        try self.operations.commitExportReceipt(receipt, makeAudit(
            randomId(self.io),
            principal,
            context.request_id,
            now,
            "audit.export",
            "audit_export",
            encodeId(receipt.id, &receipt_text),
            audit_details,
        ));
        // The terminal receipt record is never exposed until the matching
        // receipt and immutable audit action are durable. If this final write
        // fails, the conservative extra receipt is harmless; a client can
        // retry through the central idempotency dispatcher.
        const receipt_line = try encodeAuditExportReceiptLine(
            self.allocator,
            receipt,
            through_audit_id,
        );
        defer self.allocator.free(receipt_line);
        try writer.write(receipt_line);
        try writer.flush();
        return .{
            .receipt = receipt,
            .exported_through_audit_id = through_audit_id,
            .etag = makeAuditEtag(try latestAuditSequence(self.operations.db)),
        };
    }

    const AuditExportBatch = struct {
        entry_count: u16,
        last_sequence: u64,
    };

    /// Writes at most one bounded audit prefix batch. The statement lifetime
    /// is deliberately contained in this function so callers can checkpoint
    /// protocol-critical work only after `deinit` has run.
    fn writeAuditExportBatch(
        self: *Service,
        after_sequence: u64,
        through_sequence: u64,
        writer: ExportWriter,
        accumulator: *operations_repository.ExportAccumulator,
    ) !AuditExportBatch {
        if (after_sequence >= through_sequence) return .{
            .entry_count = 0,
            .last_sequence = after_sequence,
        };
        const through_sql = try validPositiveSequence(through_sequence);
        if (after_sequence > std.math.maxInt(i64)) return error.CorruptAuditEntry;

        var query = try self.operations.db.prepare(
            "SELECT a.sequence,a.id,a.occurred_at,a.actor_kind,a.actor_id,a.action," ++
                "a.resource_type,a.resource_id,a.request_id," ++
                "coalesce((SELECT username FROM users WHERE id = a.actor_id)," ++
                "(SELECT username FROM user_tombstones WHERE former_user_id = a.actor_id))," ++
                "CASE WHEN json_type(a.details_json,'$.userAgent') = 'text' " ++
                "THEN json_extract(a.details_json,'$.userAgent') END," ++
                "CASE WHEN json_type(a.details_json,'$.proxyPeer') = 'text' " ++
                "THEN json_extract(a.details_json,'$.proxyPeer') END " ++
                "FROM audit_entries AS a " ++
                "WHERE a.sequence > ?1 AND a.sequence <= ?2 " ++
                "ORDER BY a.sequence ASC LIMIT ?3;",
        );
        defer query.deinit();
        try query.bindInt64(1, @as(i64, @intCast(after_sequence)));
        try query.bindInt64(2, through_sql);
        try query.bindInt64(3, export_checkpoint_interval);

        var result: AuditExportBatch = .{
            .entry_count = 0,
            .last_sequence = after_sequence,
        };
        while (try query.step() == .row) {
            const entry = try decodeAudit(&query, true);
            const line = try encodeAuditExportLine(self.allocator, entry);
            defer self.allocator.free(line);
            try writer.write(line);
            try accumulator.appendEntry(entry.sequence, line);
            result.entry_count += 1;
            result.last_sequence = entry.sequence;
        }
        return result;
    }

    pub fn pruneAudit(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        export_id: [16]u8,
        through_audit_id: [16]u8,
    ) !PruneResult {
        try authorize(principal, .manage_audit);
        try validatePrincipalAndContext(principal, context);
        const current_etag = makeAuditEtag(try latestAuditSequence(self.operations.db));
        try validateDangerous(principal, context, &current_etag, "prune audit");
        _ = try context.requireIdempotency();
        const now = try context.unixSeconds();
        const receipt = try loadExportReceipt(self.operations.db, export_id);
        const through_sequence = try auditSequenceForId(self.operations.db, through_audit_id);
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        var export_text: [32]u8 = undefined;
        const deleted = try self.operations.pruneAuditPrefix(.{
            .receipt = receipt,
            .prune_through_sequence = through_sequence,
            .recent_reauthentication = true,
            .typed_confirmation_matches = true,
        }, makeAudit(
            randomId(self.io),
            principal,
            context.request_id,
            now,
            "audit.prune",
            "audit_export",
            encodeId(export_id, &export_text),
            audit_details,
        ));
        return .{
            .export_id = export_id,
            .through_audit_id = through_audit_id,
            .pruned_entries = deleted,
            .pruned_at = now,
            .etag = makeAuditEtag(try latestAuditSequence(self.operations.db)),
        };
    }

    pub fn getSettings(self: *Service, principal: Principal) !SettingsState {
        try authorize(principal, .read);
        return try projectSettingsState(try self.settings.loadState());
    }

    pub fn settingsEtag(self: *Service, principal: Principal) !StrongEtag {
        try authorize(principal, .read);
        return makeSettingsEtag(try self.settings.loadState());
    }

    pub fn listSettingsRevisions(
        self: *Service,
        principal: Principal,
        cursor: ?SettingsCursor,
        requested_limit: ?u16,
    ) !SettingsPage {
        try authorize(principal, .read);
        const limit = try normalizePageLimit(requested_limit);
        var statement = try self.settings.db.prepare(
            "SELECT revision FROM settings_revisions WHERE (?1 = 0 OR revision < ?2) " ++
                "ORDER BY revision DESC LIMIT ?3;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, @intFromBool(cursor != null));
        try statement.bindInt64(2, if (cursor) |value| try validPositiveSequence(value.before_sequence) else 0);
        try statement.bindInt64(3, @as(u32, limit) + 1);
        var items: std.ArrayList(SettingsRevision) = .empty;
        errdefer items.deinit(self.allocator);
        try items.ensureTotalCapacity(self.allocator, limit);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            const raw = statement.columnInt64(0);
            if (raw <= 0) return error.CorruptSettingsState;
            items.appendAssumeCapacity(try projectSettingsRevision(try self.settings.loadRevision(@intCast(raw))));
        }
        const next: ?SettingsCursor = if (saw_more)
            .{ .before_sequence = items.items[items.items.len - 1].sequence }
        else
            null;
        return .{ .items = try items.toOwnedSlice(self.allocator), .next_cursor = next };
    }

    pub fn updateSettings(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        patch: SettingsPatch,
    ) !SettingsRevision {
        try authorize(principal, .manage_settings);
        try validatePrincipalAndContext(principal, context);
        const current = try self.settings.loadState();
        const current_etag = makeSettingsEtag(current);
        try validateDangerous(principal, context, &current_etag, "settings");
        const desired = try patch.apply(current.desired.values);
        const now = try context.unixSeconds();
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        var resource_text: [32]u8 = undefined;
        const id = randomId(self.io);
        const revision = try self.settings.createRevision(
            id,
            desired,
            try currentNodeCount(self.settings.db),
            current.desired.sequence,
            now,
            .web,
            principal.user_id,
            makeAudit(
                randomId(self.io),
                principal,
                context.request_id,
                now,
                "settings.update",
                "settings_revision",
                encodeId(id, &resource_text),
                audit_details,
            ),
        );
        if (revision.status == .pending_apply) if (self.settings_publisher) |publisher| {
            publisher.publish(revision.sequence, revision.values);
        };
        return try projectSettingsRevision(revision);
    }

    pub fn rollbackSettings(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        target_id: [16]u8,
    ) !SettingsRevision {
        try authorize(principal, .manage_settings);
        try validatePrincipalAndContext(principal, context);
        const current = try self.settings.loadState();
        const current_etag = makeSettingsEtag(current);
        var target_text: [32]u8 = undefined;
        try validateDangerous(principal, context, &current_etag, encodeId(target_id, &target_text));
        _ = try context.requireIdempotency();
        const target_sequence = try settingsSequenceForId(self.settings.db, target_id);
        const target = try self.settings.loadRevision(target_sequence);
        const now = try context.unixSeconds();
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        const id = randomId(self.io);
        var new_text: [32]u8 = undefined;
        const revision = try self.settings.createRollbackRevision(
            id,
            target.values,
            try currentNodeCount(self.settings.db),
            current.desired.sequence,
            now,
            .web,
            principal.user_id,
            makeAudit(
                randomId(self.io),
                principal,
                context.request_id,
                now,
                "settings.rollback",
                "settings_revision",
                encodeId(id, &new_text),
                audit_details,
            ),
        );
        if (revision.status == .pending_apply) if (self.settings_publisher) |publisher| {
            publisher.publish(revision.sequence, revision.values);
        };
        return try projectSettingsRevision(revision);
    }

    pub fn controlEtag(self: *Service, principal: Principal) !StrongEtag {
        try authorize(principal, .read);
        return makeControlEtag(self.control.*);
    }

    /// Captures the serialized control-state boundary before dispatching a
    /// request. The central dispatcher uses the checkpoint to prove that a
    /// later stage belongs to that request rather than clearing an older one.
    pub fn controlStageCheckpoint(self: *const Service) ControlStageCheckpoint {
        return .{
            .revision = self.control.revision,
            .staged_id = if (self.control.staged) |decision| decision.id else null,
            .pending_id = if (self.control.pending) |decision| decision.id else null,
        };
    }

    /// Returns only a stage created from a previously idle control state and
    /// the immediately following revision. Production dispatch is serialized,
    /// so this is an exact ownership proof for the current request.
    pub fn stagedControlSince(
        self: *const Service,
        checkpoint: ControlStageCheckpoint,
        kind: ControlKind,
    ) ?ControlDecision {
        if (checkpoint.staged_id != null or checkpoint.pending_id != null) return null;
        const expected_revision = std.math.add(u64, checkpoint.revision, 1) catch return null;
        if (self.control.revision != expected_revision or self.control.pending != null) return null;
        const decision = self.control.staged orelse return null;
        if (decision.kind != kind) return null;
        return decision;
    }

    /// Makes one exact staged decision executable. A stale or unrelated token
    /// cannot replace an armed operation or consume another request's stage.
    pub fn armStagedControl(self: *Service, decision_id: [16]u8) !void {
        if (self.control.pending != null) return error.ServiceOperationInProgress;
        const staged = self.control.staged orelse return error.ControlDecisionNotStaged;
        if (!std.mem.eql(u8, &staged.id, &decision_id)) return error.ControlDecisionMismatch;
        self.control.staged = null;
        self.control.pending = staged;
    }

    /// Drops only the exact non-executable stage owned by the caller. The
    /// revision remains advanced because its immutable audit record committed;
    /// stale preconditions therefore remain stale after a pre-completion
    /// failure.
    pub fn discardStagedControl(self: *Service, decision_id: [16]u8) bool {
        const staged = self.control.staged orelse return false;
        if (!std.mem.eql(u8, &staged.id, &decision_id)) return false;
        self.control.staged = null;
        return true;
    }

    pub fn requestRestart(
        self: *Service,
        principal: Principal,
        context: RequestContext,
    ) !ControlDecision {
        if (!self.control.managed_restart_supported) {
            try authorize(principal, .control_service);
            return error.OperationUnavailable;
        }
        return self.requestControl(principal, context, .restart);
    }

    pub fn requestShutdown(
        self: *Service,
        principal: Principal,
        context: RequestContext,
    ) !ControlDecision {
        return self.requestControl(principal, context, .shutdown);
    }

    fn requestControl(
        self: *Service,
        principal: Principal,
        context: RequestContext,
        kind: ControlKind,
    ) !ControlDecision {
        try authorize(principal, .control_service);
        try validatePrincipalAndContext(principal, context);
        if (self.control.staged != null or self.control.pending != null) {
            return error.ServiceOperationInProgress;
        }
        const etag = makeControlEtag(self.control.*);
        try validateDangerous(principal, context, &etag, @tagName(kind));
        _ = try context.requireIdempotency();
        const next_revision = std.math.add(u64, self.control.revision, 1) catch return error.RevisionOverflow;
        const now = try context.unixSeconds();
        const decision: ControlDecision = .{
            .id = randomId(self.io),
            .kind = kind,
            .accepted_at = now,
            .exit_status = if (kind == .restart) restart_exit_status else shutdown_exit_status,
        };
        const audit_details = try encodeAuditDetails(self.allocator, principal);
        defer self.allocator.free(audit_details);
        var operation_text: [32]u8 = undefined;
        _ = try self.operations.appendAudit(makeAudit(
            randomId(self.io),
            principal,
            context.request_id,
            now,
            if (kind == .restart) "service.restart" else "service.shutdown",
            "service_operation",
            encodeId(decision.id, &operation_text),
            audit_details,
        ));
        self.control.revision = next_revision;
        self.control.staged = decision;
        return decision;
    }

    fn readConnectivity(self: *Service, id: [16]u8) !ConnectivityCheck {
        var statement = try self.operations.db.prepare(
            "SELECT id,node_id,node_name,status,timeout_ms,requested_at,started_at," ++
                "completed_at,rtt_microseconds,error_code FROM connectivity_checks WHERE id = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id);
        if (try statement.step() != .row) return error.ConnectivityCheckNotFound;
        const result = try decodeConnectivity(&statement);
        if (try statement.step() != .done) return error.CorruptConnectivityCheck;
        return result;
    }

    fn readNodeAddress(self: *Service, id: [16]u8) !AddressText {
        var statement = try self.operations.db.prepare("SELECT address FROM nodes WHERE id = ?1;");
        defer statement.deinit();
        try statement.bindBlob(1, &id);
        if (try statement.step() != .row) return error.NodeNotFound;
        const raw = statement.columnInt64(0);
        if (raw < 0 or raw > std.math.maxInt(u32)) return error.CorruptInventory;
        var buffer: [15]u8 = undefined;
        const value: u32 = @intCast(raw);
        const rendered = std.fmt.bufPrint(
            &buffer,
            "{d}.{d}.{d}.{d}",
            .{ value >> 24, value >> 16 & 0xff, value >> 8 & 0xff, value & 0xff },
        ) catch unreachable;
        if (try statement.step() != .done) return error.CorruptInventory;
        return AddressText.parse(rendered);
    }
};

const zero_id = [_]u8{0} ** 16;

fn authorize(principal: Principal, permission: auth.Permission) !void {
    if (allZero(&principal.user_id) or allZero(&principal.session_id)) return error.InvalidPrincipal;
    if (!auth.allows(principal.role, permission)) return error.Forbidden;
}

fn validatePrincipalAndContext(principal: Principal, context: RequestContext) !void {
    try authorize(principal, .read);
    if (allZero(&context.request_id)) return error.InvalidRequestId;
    _ = try context.unixSeconds();
}

fn validateDangerous(
    principal: Principal,
    context: RequestContext,
    current_etag: *const StrongEtag,
    required_confirmation: []const u8,
) !void {
    const now = try context.unixSeconds();
    const reauthenticated_at: ?u64 = if (context.preconditions.reauthenticated_at_unix_ms) |value| blk: {
        if (value < 0) return error.InvalidTimestamp;
        break :blk @intCast(@divFloor(value, 1000));
    } else null;
    try security_policy.validateDangerous(.{
        .role = principal.role,
        .reauthenticated_at = reauthenticated_at,
        .now = @intCast(now),
        .supplied_etag = context.preconditions.etag,
        .current_etag = current_etag.slice(),
        .supplied_confirmation = context.preconditions.confirmation,
        .required_confirmation = required_confirmation,
    });
}

fn normalizePageLimit(requested: ?u16) !u16 {
    const limit = requested orelse default_page_size;
    if (limit == 0 or limit > maximum_page_size) return error.InvalidPageLimit;
    return limit;
}

fn validateEventFilter(filter: EventFilter) !void {
    if (filter.since_unix_seconds) |value| if (value < 0) return error.InvalidTimestamp;
    if (filter.node_id) |value| if (allZero(&value)) return error.InvalidNodeId;
}

fn validateAuditFilter(filter: AuditFilter) !void {
    if (filter.since_unix_seconds) |value| if (value < 0) return error.InvalidTimestamp;
    if (filter.actor_user_id) |value| if (allZero(&value)) return error.InvalidUserId;
}

fn validPositiveSequence(value: u64) !i64 {
    if (value == 0 or value > std.math.maxInt(i64)) return error.InvalidCursor;
    return @intCast(value);
}

fn bindCompositeCursor(
    statement: *sqlite.Statement,
    present: bool,
    timestamp: i64,
    before_id: [16]u8,
) !void {
    if (present and (timestamp < 0 or allZero(&before_id))) return error.InvalidCursor;
    try statement.bindInt64(1, @intFromBool(present));
    try statement.bindInt64(2, timestamp);
    try statement.bindBlob(3, &before_id);
}

fn eventSeverityStorage(value: EventSeverity) []const u8 {
    return switch (value) {
        .info => "info",
        .warning => "warning",
        .critical => "error",
    };
}

fn parseEventSeverity(value: []const u8) !EventSeverity {
    if (std.mem.eql(u8, value, "info")) return .info;
    if (std.mem.eql(u8, value, "warning")) return .warning;
    if (std.mem.eql(u8, value, "error")) return .critical;
    return error.CorruptRuntimeEvent;
}

fn parseAuditActor(value: []const u8) !AuditActorType {
    if (std.mem.eql(u8, value, "web")) return .web_user;
    if (std.mem.eql(u8, value, "local_cli")) return .local_cli;
    if (std.mem.eql(u8, value, "system")) return .system;
    return error.CorruptAuditEntry;
}

fn parseRepositoryActor(value: []const u8) !management_repository.ActorKind {
    if (std.mem.eql(u8, value, "web")) return .web;
    if (std.mem.eql(u8, value, "local_cli")) return .local_cli;
    if (std.mem.eql(u8, value, "system")) return .system;
    return error.CorruptExportReceipt;
}

fn parseConnectivityStatus(value: []const u8) !ConnectivityStatus {
    return std.meta.stringToEnum(ConnectivityStatus, value) orelse error.CorruptConnectivityCheck;
}

fn copyRequiredId(blob: ?[]const u8, comptime corrupt: anyerror) ![16]u8 {
    const bytes = blob orelse return corrupt;
    if (bytes.len != 16) return corrupt;
    var result: [16]u8 = undefined;
    @memcpy(&result, bytes);
    return result;
}

fn copyOptionalId(statement: *const sqlite.Statement, column: c_int, comptime corrupt: anyerror) !?[16]u8 {
    const blob = statement.columnBlob(column) orelse return null;
    return try copyRequiredId(blob, corrupt);
}

fn decodeEvent(statement: *const sqlite.Statement) !Event {
    const occurred_at = statement.columnInt64(4);
    if (occurred_at < 0) return error.CorruptRuntimeEvent;
    const node_id = try copyOptionalId(statement, 3, error.CorruptRuntimeEvent);
    var resource_id_text: [32]u8 = undefined;
    return .{
        .id = try copyRequiredId(statement.columnBlob(0), error.CorruptRuntimeEvent),
        .kind = KindText.parse(statement.columnText(1) orelse return error.CorruptRuntimeEvent) catch
            return error.CorruptRuntimeEvent,
        .severity = try parseEventSeverity(statement.columnText(2) orelse return error.CorruptRuntimeEvent),
        .resource_type = ResourceTypeText.parse(if (node_id != null) "node" else "system") catch unreachable,
        .resource_id = if (node_id) |id|
            ResourceIdText.parse(encodeId(id, &resource_id_text)) catch unreachable
        else
            null,
        .occurred_at = occurred_at,
    };
}

fn decodeAudit(statement: *const sqlite.Statement, full: bool) !AuditEntry {
    const raw_sequence = statement.columnInt64(0);
    const occurred_at = statement.columnInt64(2);
    if (raw_sequence <= 0 or occurred_at < 0) return error.CorruptAuditEntry;
    const actor_id = try copyOptionalId(statement, 4, error.CorruptAuditEntry);
    const request_id = try copyOptionalId(statement, 8, error.CorruptAuditEntry);
    const resource_id_text = statement.columnText(7) orelse return error.CorruptAuditEntry;
    const actor_username = if (statement.columnText(9)) |value|
        UsernameText.parse(value) catch return error.CorruptAuditEntry
    else
        null;
    const user_agent = if (statement.columnText(10)) |value|
        UserAgentText.parse(value) catch return error.CorruptAuditEntry
    else
        null;
    const proxy_peer = if (statement.columnText(11)) |value|
        ProxyPeerText.parse(value) catch return error.CorruptAuditEntry
    else
        null;
    return .{
        .sequence = @intCast(raw_sequence),
        .id = try copyRequiredId(statement.columnBlob(1), error.CorruptAuditEntry),
        .actor_type = try parseAuditActor(statement.columnText(3) orelse return error.CorruptAuditEntry),
        .actor_user_id = if (full) actor_id else null,
        .actor_username = if (full) actor_username else null,
        .action = KindText.parse(statement.columnText(5) orelse return error.CorruptAuditEntry) catch
            return error.CorruptAuditEntry,
        .resource_type = ResourceTypeText.parse(statement.columnText(6) orelse return error.CorruptAuditEntry) catch
            return error.CorruptAuditEntry,
        .resource_id = if (resource_id_text.len == 0)
            null
        else
            ResourceIdText.parse(resource_id_text) catch return error.CorruptAuditEntry,
        .request_id = if (full) request_id else null,
        .user_agent = if (full) user_agent else null,
        .proxy_peer = if (full) proxy_peer else null,
        .occurred_at = occurred_at,
        .redacted = !full,
    };
}

fn decodeConnectivity(statement: *const sqlite.Statement) !ConnectivityCheck {
    const timeout = statement.columnInt64(4);
    const requested_at = statement.columnInt64(5);
    if (timeout < operations_repository.minimum_check_timeout_ms or
        timeout > operations_repository.maximum_check_timeout_ms or requested_at < 0)
    {
        return error.CorruptConnectivityCheck;
    }
    const started_at = if (statement.columnIsNull(6)) null else statement.columnInt64(6);
    const completed_at = if (statement.columnIsNull(7)) null else statement.columnInt64(7);
    if ((started_at != null and started_at.? < requested_at) or
        (completed_at != null and completed_at.? < requested_at)) return error.CorruptConnectivityCheck;
    const rtt: ?u64 = if (statement.columnIsNull(8)) null else blk: {
        const value = statement.columnInt64(8);
        if (value < 0) return error.CorruptConnectivityCheck;
        break :blk @intCast(value);
    };
    const failure = if (statement.columnText(9)) |value|
        FailureText.parse(value) catch return error.CorruptConnectivityCheck
    else
        null;
    const status = try parseConnectivityStatus(statement.columnText(3) orelse return error.CorruptConnectivityCheck);
    if ((status == .succeeded) != (rtt != null) or
        (status == .succeeded and failure != null) or
        (status.isTerminal() != (completed_at != null))) return error.CorruptConnectivityCheck;
    const address_text = statement.columnText(2) orelse return error.CorruptConnectivityCheck;
    _ = ipv4.Ipv4.parse(address_text) catch return error.CorruptConnectivityCheck;
    return .{
        .id = try copyRequiredId(statement.columnBlob(0), error.CorruptConnectivityCheck),
        .node_id = try copyOptionalId(statement, 1, error.CorruptConnectivityCheck),
        .node_address = AddressText.parse(address_text) catch
            return error.CorruptConnectivityCheck,
        .status = status,
        .timeout_milliseconds = @intCast(timeout),
        .round_trip_milliseconds = if (rtt) |value| @as(f64, @floatFromInt(value)) / 1000.0 else null,
        .failure_code = failure,
        .created_at = requested_at,
        .started_at = started_at,
        .completed_at = completed_at,
    };
}

fn projectSettingsRevision(revision: settings_repository.Revision) !SettingsRevision {
    return .{
        .id = revision.id,
        .sequence = revision.sequence,
        .status = revision.status,
        .values = revision.values,
        .created_by_user_id = if (revision.actor_kind == .web) revision.actor_id else null,
        .created_at = revision.created_at,
        .applied_at = revision.applied_at,
        .failure_code = if (revision.failure_code) |value|
            FailureText.parse(value.slice()) catch return error.CorruptSettingsState
        else
            null,
    };
}

fn projectSettingsState(state: settings_repository.State) !SettingsState {
    return .{
        .desired = try projectSettingsRevision(state.desired),
        .effective = try projectSettingsRevision(state.effective),
        .pending_restart = state.pendingRestart(),
    };
}

fn latestAuditSequence(db: *sqlite.Database) !u64 {
    var statement = try db.prepare("SELECT coalesce(max(sequence), 0) FROM audit_entries;");
    defer statement.deinit();
    if (try statement.step() != .row) return error.CorruptAuditEntry;
    const raw = statement.columnInt64(0);
    if (raw < 0) return error.CorruptAuditEntry;
    if (try statement.step() != .done) return error.CorruptAuditEntry;
    return @intCast(raw);
}

fn auditSequenceForId(db: *sqlite.Database, id: [16]u8) !u64 {
    if (allZero(&id)) return error.AuditEntryNotFound;
    var statement = try db.prepare("SELECT sequence FROM audit_entries WHERE id = ?1;");
    defer statement.deinit();
    try statement.bindBlob(1, &id);
    if (try statement.step() != .row) return error.AuditEntryNotFound;
    const raw = statement.columnInt64(0);
    if (raw <= 0) return error.CorruptAuditEntry;
    if (try statement.step() != .done) return error.CorruptAuditEntry;
    return @intCast(raw);
}

fn settingsSequenceForId(db: *sqlite.Database, id: [16]u8) !u64 {
    if (allZero(&id)) return error.SettingsRevisionNotFound;
    var statement = try db.prepare("SELECT revision FROM settings_revisions WHERE id = ?1;");
    defer statement.deinit();
    try statement.bindBlob(1, &id);
    if (try statement.step() != .row) return error.SettingsRevisionNotFound;
    const raw = statement.columnInt64(0);
    if (raw <= 0) return error.CorruptSettingsState;
    if (try statement.step() != .done) return error.CorruptSettingsState;
    return @intCast(raw);
}

fn currentNodeCount(db: *sqlite.Database) !usize {
    var statement = try db.prepare("SELECT count(*) FROM nodes;");
    defer statement.deinit();
    if (try statement.step() != .row) return error.CorruptInventory;
    const raw = statement.columnInt64(0);
    if (raw < 0) return error.CorruptInventory;
    if (try statement.step() != .done) return error.CorruptInventory;
    return @intCast(raw);
}

fn loadExportReceipt(db: *sqlite.Database, id: [16]u8) !operations_repository.ExportReceipt {
    if (allZero(&id)) return error.ExportReceiptNotFound;
    var statement = try db.prepare(
        "SELECT exported_through_sequence,entry_count,content_sha256," ++
            "actor_kind,actor_id,exported_at FROM audit_export_receipts WHERE id = ?1;",
    );
    defer statement.deinit();
    try statement.bindBlob(1, &id);
    if (try statement.step() != .row) return error.ExportReceiptNotFound;
    const through = statement.columnInt64(0);
    const count = statement.columnInt64(1);
    if (through <= 0 or count <= 0) return error.CorruptExportReceipt;
    const digest_blob = statement.columnBlob(2) orelse return error.CorruptExportReceipt;
    if (digest_blob.len != 32) return error.CorruptExportReceipt;
    var digest: [32]u8 = undefined;
    @memcpy(&digest, digest_blob);
    const actor_kind = try parseRepositoryActor(statement.columnText(3) orelse return error.CorruptExportReceipt);
    if (actor_kind == .system) return error.CorruptExportReceipt;
    const actor_id = try copyOptionalId(&statement, 4, error.CorruptExportReceipt);
    const exported_at = statement.columnInt64(5);
    if (exported_at < 0) return error.CorruptExportReceipt;
    if (try statement.step() != .done) return error.CorruptExportReceipt;
    return .{
        .id = id,
        .exported_through_sequence = @intCast(through),
        .entry_count = @intCast(count),
        .content_sha256 = digest,
        .actor_kind = actor_kind,
        .actor_id = actor_id,
        .exported_at = exported_at,
    };
}

fn makeAudit(
    id: [16]u8,
    principal: Principal,
    request_id: [16]u8,
    now: i64,
    action: []const u8,
    resource_type: []const u8,
    resource_id: []const u8,
    details_json: []const u8,
) management_repository.AuditEntry {
    return .{
        .id = id,
        .occurred_at = now,
        .actor_kind = .web,
        .actor_id = principal.user_id,
        .action = action,
        .resource_type = resource_type,
        .resource_id = resource_id,
        .request_id = request_id,
        .details_json = details_json,
    };
}

fn encodeAuditDetails(allocator: std.mem.Allocator, principal: Principal) ![]u8 {
    const Details = struct {
        userAgent: ?[]const u8 = null,
        proxyPeer: ?[]const u8 = null,
    };
    return std.json.Stringify.valueAlloc(allocator, Details{
        .userAgent = if (principal.user_agent) |*value| value.slice() else null,
        .proxyPeer = if (principal.proxy_peer) |*value| value.slice() else null,
    }, .{ .emit_null_optional_fields = false });
}

fn makeStrongEtag(comptime format: []const u8, arguments: anytype) StrongEtag {
    var result: StrongEtag = .{ .bytes = [_]u8{0} ** maximum_etag_bytes, .len = 0 };
    const rendered = std.fmt.bufPrint(&result.bytes, format, arguments) catch unreachable;
    result.len = @intCast(rendered.len);
    return result;
}

fn makeAuditEtag(sequence: u64) StrongEtag {
    return makeStrongEtag("\"audit:{d}\"", .{sequence});
}

fn makeSettingsEtag(state: settings_repository.State) StrongEtag {
    return makeStrongEtag(
        "\"settings:{d}:{s}:{d}:{s}\"",
        .{
            state.desired.sequence,
            @tagName(state.desired.status),
            state.effective.sequence,
            @tagName(state.effective.status),
        },
    );
}

fn makeControlEtag(state: ControlState) StrongEtag {
    var id_text: [32]u8 = undefined;
    return makeStrongEtag(
        "\"service:{s}:{d}:{d}\"",
        .{ encodeId(state.instance_id, &id_text), state.revision, @intFromBool(state.managed_restart_supported) },
    );
}

fn randomId(io: std.Io) [16]u8 {
    var id: [16]u8 = undefined;
    while (true) {
        io.random(&id);
        if (!allZero(&id)) return id;
    }
}

fn allZero(bytes: []const u8) bool {
    var accumulator: u8 = 0;
    for (bytes) |byte| accumulator |= byte;
    return accumulator == 0;
}

fn encodeId(id: [16]u8, output: *[32]u8) []const u8 {
    return encodeLowerHex(&id, output);
}

fn encodeLowerHex(bytes: []const u8, output: []u8) []const u8 {
    std.debug.assert(output.len == bytes.len * 2);
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn decodeId(text: []const u8) ![16]u8 {
    if (text.len != 32) return error.InvalidCursor;
    var id: [16]u8 = undefined;
    for (&id, 0..) |*byte, index| {
        const high = decodeNibble(text[index * 2]) orelse return error.InvalidCursor;
        const low = decodeNibble(text[index * 2 + 1]) orelse return error.InvalidCursor;
        byte.* = high << 4 | low;
    }
    if (allZero(&id)) return error.InvalidCursor;
    return id;
}

fn decodeNibble(value: u8) ?u8 {
    return switch (value) {
        '0'...'9' => value - '0',
        'a'...'f' => value - 'a' + 10,
        else => null,
    };
}

fn parseCanonicalUnsigned(comptime T: type, text: []const u8, allow_zero: bool) !T {
    if (text.len == 0 or (text.len > 1 and text[0] == '0')) return error.InvalidCursor;
    for (text) |byte| if (byte < '0' or byte > '9') return error.InvalidCursor;
    const result = std.fmt.parseInt(T, text, 10) catch return error.InvalidCursor;
    if (!allow_zero and result == 0) return error.InvalidCursor;
    return result;
}

fn splitCursor(text: []const u8, expected_kind: []const u8, expected_fields: usize) !std.mem.SplitIterator(u8, .scalar) {
    if (text.len == 0 or text.len > maximum_cursor_bytes) return error.InvalidCursor;
    var iterator = std.mem.splitScalar(u8, text, ':');
    if (!std.mem.eql(u8, iterator.next() orelse return error.InvalidCursor, "v1")) return error.InvalidCursor;
    if (!std.mem.eql(u8, iterator.next() orelse return error.InvalidCursor, expected_kind)) return error.InvalidCursor;
    _ = expected_fields;
    return iterator;
}

pub fn encodeEventCursor(cursor: EventCursor, output: *[maximum_cursor_bytes]u8) ![]const u8 {
    if (cursor.observed_at < 0 or allZero(&cursor.before_id)) return error.InvalidCursor;
    var id_text: [32]u8 = undefined;
    return std.fmt.bufPrint(output, "v1:e:{d}:{s}", .{ cursor.observed_at, encodeId(cursor.before_id, &id_text) });
}

pub fn decodeEventCursor(text: []const u8) !EventCursor {
    var fields = try splitCursor(text, "e", 2);
    const timestamp = try parseCanonicalUnsigned(i64, fields.next() orelse return error.InvalidCursor, true);
    const id = try decodeId(fields.next() orelse return error.InvalidCursor);
    if (fields.next() != null) return error.InvalidCursor;
    return .{ .observed_at = timestamp, .before_id = id };
}

pub fn encodeAuditCursor(cursor: AuditCursor, output: *[maximum_cursor_bytes]u8) ![]const u8 {
    _ = try validPositiveSequence(cursor.before_sequence);
    return std.fmt.bufPrint(output, "v1:a:{d}", .{cursor.before_sequence});
}

pub fn decodeAuditCursor(text: []const u8) !AuditCursor {
    var fields = try splitCursor(text, "a", 1);
    const sequence = try parseCanonicalUnsigned(u64, fields.next() orelse return error.InvalidCursor, false);
    _ = try validPositiveSequence(sequence);
    if (fields.next() != null) return error.InvalidCursor;
    return .{ .before_sequence = sequence };
}

pub fn encodeConnectivityCursor(cursor: ConnectivityCursor, output: *[maximum_cursor_bytes]u8) ![]const u8 {
    if (cursor.requested_at < 0 or allZero(&cursor.before_id)) return error.InvalidCursor;
    var id_text: [32]u8 = undefined;
    return std.fmt.bufPrint(output, "v1:c:{d}:{s}", .{ cursor.requested_at, encodeId(cursor.before_id, &id_text) });
}

pub fn decodeConnectivityCursor(text: []const u8) !ConnectivityCursor {
    var fields = try splitCursor(text, "c", 2);
    const timestamp = try parseCanonicalUnsigned(i64, fields.next() orelse return error.InvalidCursor, true);
    const id = try decodeId(fields.next() orelse return error.InvalidCursor);
    if (fields.next() != null) return error.InvalidCursor;
    return .{ .requested_at = timestamp, .before_id = id };
}

pub fn encodeSettingsCursor(cursor: SettingsCursor, output: *[maximum_cursor_bytes]u8) ![]const u8 {
    _ = try validPositiveSequence(cursor.before_sequence);
    return std.fmt.bufPrint(output, "v1:s:{d}", .{cursor.before_sequence});
}

pub fn decodeSettingsCursor(text: []const u8) !SettingsCursor {
    var fields = try splitCursor(text, "s", 1);
    const sequence = try parseCanonicalUnsigned(u64, fields.next() orelse return error.InvalidCursor, false);
    _ = try validPositiveSequence(sequence);
    if (fields.next() != null) return error.InvalidCursor;
    return .{ .before_sequence = sequence };
}

fn encodeAuditExportLine(allocator: std.mem.Allocator, entry: AuditEntry) ![]u8 {
    var id_text: [32]u8 = undefined;
    var actor_text: [32]u8 = undefined;
    var request_text: [32]u8 = undefined;
    var occurred_at_text: [api_response.timestamp_text_len]u8 = undefined;
    const Payload = struct {
        recordType: []const u8,
        sequence: u64,
        id: []const u8,
        occurredAt: []const u8,
        actorType: []const u8,
        actorUserId: ?[]const u8,
        actorUsername: ?[]const u8,
        action: []const u8,
        resourceType: []const u8,
        resourceId: ?[]const u8,
        outcome: []const u8,
        requestId: ?[]const u8,
        userAgent: ?[]const u8,
        proxyPeer: ?[]const u8,
    };
    var bytes = try std.json.Stringify.valueAlloc(allocator, Payload{
        .recordType = "auditEntry",
        .sequence = entry.sequence,
        .id = encodeId(entry.id, &id_text),
        .occurredAt = api_response.formatTimestamp(entry.occurred_at, &occurred_at_text) catch
            return error.CorruptAuditEntry,
        .actorType = @tagName(entry.actor_type),
        .actorUserId = if (entry.actor_user_id) |id| encodeId(id, &actor_text) else null,
        .actorUsername = if (entry.actor_username) |*value| value.slice() else null,
        .action = entry.action.slice(),
        .resourceType = entry.resource_type.slice(),
        .resourceId = if (entry.resource_id) |*value| value.slice() else null,
        .outcome = @tagName(entry.outcome),
        .requestId = if (entry.request_id) |id| encodeId(id, &request_text) else null,
        .userAgent = if (entry.user_agent) |*value| value.slice() else null,
        .proxyPeer = if (entry.proxy_peer) |*value| value.slice() else null,
    }, .{ .emit_null_optional_fields = false });
    errdefer allocator.free(bytes);
    if (bytes.len >= service_ipc.maximum_frame_bytes) return error.ExportEntryTooLarge;
    bytes = try allocator.realloc(bytes, bytes.len + 1);
    bytes[bytes.len - 1] = '\n';
    return bytes;
}

fn encodeAuditExportReceiptLine(
    allocator: std.mem.Allocator,
    receipt: operations_repository.ExportReceipt,
    through_audit_id: [16]u8,
) ![]u8 {
    var id_text: [32]u8 = undefined;
    var audit_text: [32]u8 = undefined;
    var digest_text: [64]u8 = undefined;
    var exported_at_text: [api_response.timestamp_text_len]u8 = undefined;
    const Payload = struct {
        recordType: []const u8,
        id: []const u8,
        exportedThroughSequence: u64,
        exportedThroughAuditId: []const u8,
        entryCount: u64,
        contentSha256: []const u8,
        exportedAt: []const u8,
    };
    var bytes = try std.json.Stringify.valueAlloc(allocator, Payload{
        .recordType = "auditExportReceipt",
        .id = encodeId(receipt.id, &id_text),
        .exportedThroughSequence = receipt.exported_through_sequence,
        .exportedThroughAuditId = encodeId(through_audit_id, &audit_text),
        .entryCount = receipt.entry_count,
        .contentSha256 = encodeLowerHex(&receipt.content_sha256, &digest_text),
        .exportedAt = api_response.formatTimestamp(receipt.exported_at, &exported_at_text) catch
            return error.CorruptExportReceipt,
    }, .{});
    errdefer allocator.free(bytes);
    if (bytes.len >= service_ipc.maximum_frame_bytes) return error.ExportEntryTooLarge;
    bytes = try allocator.realloc(bytes, bytes.len + 1);
    bytes[bytes.len - 1] = '\n';
    return bytes;
}

/// Maps internal application and repository failures onto the stable private
/// IPC vocabulary without leaking SQLite or invariant implementation detail.
pub fn failureForError(err: anyerror) service_ipc.ErrorBody {
    return switch (err) {
        error.Forbidden => .{ .code = .forbidden, .message = "operation is not permitted" },
        error.ReauthenticationRequired => .{ .code = .reauthentication_required, .message = "recent password reauthentication is required" },
        error.PreconditionRequired => .{ .code = .precondition_required, .message = "If-Match precondition is required" },
        error.PreconditionFailed => .{ .code = .precondition_failed, .message = "resource generation changed" },
        error.IdempotencyRequired => .{ .code = .idempotency_required, .message = "Idempotency-Key is required" },
        error.DeadlineRequired,
        error.InvalidDeadline,
        => .{ .code = .invalid_request, .message = "request deadline is invalid" },
        error.NodeNotFound,
        error.ConnectivityCheckNotFound,
        error.AuditEntryNotFound,
        error.ExportReceiptNotFound,
        error.SettingsRevisionNotFound,
        => .{ .code = .not_found, .message = "resource was not found" },
        error.ConnectivityDispatchUnavailable => .{ .code = .service_unavailable, .message = "connectivity worker is unavailable", .retryable = true },
        error.DeadlineExceeded => .{ .code = .service_unavailable, .message = "request deadline expired", .retryable = true },
        error.OperationUnavailable => .{ .code = .operation_unavailable, .message = "operation is unavailable in this launch mode" },
        error.ServiceOperationInProgress,
        error.SettingsApplicationInProgress,
        error.NoSettingsChanges,
        error.ExportSnapshotMismatch,
        error.ExportReceiptMismatch,
        error.ExportReceiptDoesNotCoverPrefix,
        error.ConnectivityCheckStateChanged,
        => .{ .code = .conflict, .message = "operation conflicts with current state" },
        error.InvalidTimestamp,
        error.InvalidPageLimit,
        error.InvalidCursor,
        error.InvalidNodeId,
        error.InvalidUserId,
        error.InvalidText,
        error.InvalidConnectivityTimeout,
        error.InvalidIdempotencyKey,
        error.InvalidSettings,
        error.ConfirmationRequired,
        error.ConfirmationFailed,
        => .{ .code = .validation_failed, .message = "request validation failed" },
        else => .{ .code = .internal_error, .message = "internal management service failure" },
    };
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testPrincipal(role: auth.Role, byte: u8) Principal {
    return .{
        .user_id = [_]u8{byte} ** 16,
        .session_id = [_]u8{byte +% 0x40} ** 16,
        .role = role,
    };
}

fn testContext(now_seconds: i64, request_byte: u8, preconditions: service_ipc.Preconditions) RequestContext {
    return .{
        .request_id = [_]u8{request_byte} ** 16,
        .now_unix_ms = now_seconds * 1000,
        .deadline_unix_ms = (now_seconds + 60) * 1000,
        .preconditions = preconditions,
    };
}

fn testDangerousContext(
    now_seconds: i64,
    request_byte: u8,
    etag: []const u8,
    confirmation: []const u8,
    idempotency_key: ?[]const u8,
) RequestContext {
    return testContext(now_seconds, request_byte, .{
        .etag = etag,
        .confirmation = confirmation,
        .reauthenticated_at_unix_ms = (now_seconds - 10) * 1000,
        .idempotency_key = idempotency_key,
    });
}

fn testAudit(id_byte: u8, now: i64, action: []const u8) management_repository.AuditEntry {
    return .{
        .id = [_]u8{id_byte} ** 16,
        .occurred_at = now,
        .actor_kind = .web,
        .actor_id = [_]u8{0xa1} ** 16,
        .action = action,
        .resource_type = "operation",
        .resource_id = "target",
        .request_id = [_]u8{0xb1} ** 16,
        .details_json = "{\"secret\":\"must-not-export\",\"userAgent\":\"test-agent\",\"proxyPeer\":\"127.0.0.1:4321\"}",
    };
}

fn insertTestNode(db: *sqlite.Database) ![16]u8 {
    var vnr = try db.prepare(
        "INSERT INTO vnrs (name,network,prefix,revision,created_at,updated_at) " ++
            "VALUES ('core',167772160,24,1,1,1);",
    );
    defer vnr.deinit();
    if (try vnr.step() != .done) return error.UnexpectedRow;
    const node_id = [_]u8{0x44} ** 16;
    var node = try db.prepare(
        "INSERT INTO nodes (id,name,vnr_name,address,created_at,updated_at) " ++
            "VALUES (?1,'edge-a','core',167772162,1,1);",
    );
    defer node.deinit();
    try node.bindBlob(1, &node_id);
    if (try node.step() != .done) return error.UnexpectedRow;
    return node_id;
}

fn scalarInt(db: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try db.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const value = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return value;
}

const TestDispatcher = struct {
    calls: usize = 0,
    fail: bool = false,
    last_check_id: [16]u8 = zero_id,
    last_node_id: [16]u8 = zero_id,
    last_timeout: u16 = 0,
    last_address: AddressText = .{ .len = 0, .bytes = [_]u8{0} ** 63 },

    fn callback(
        context: ?*anyopaque,
        check_id: [16]u8,
        node_id: [16]u8,
        address: []const u8,
        timeout: u16,
    ) anyerror!void {
        const self: *TestDispatcher = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.last_check_id = check_id;
        self.last_node_id = node_id;
        self.last_timeout = timeout;
        self.last_address = try AddressText.parse(address);
        if (self.fail) return error.TestDispatchFailure;
    }

    fn dispatcher(self: *TestDispatcher) ConnectivityDispatcher {
        return .{ .context = self, .dispatch_fn = callback };
    }
};

const TestSettingsPublisher = struct {
    calls: usize = 0,
    last_sequence: u64 = 0,
    last_values: OperationalSettings = .{},

    fn callback(context: ?*anyopaque, sequence: u64, values: OperationalSettings) void {
        const self: *TestSettingsPublisher = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.last_sequence = sequence;
        self.last_values = values;
    }

    fn publisher(self: *TestSettingsPublisher) SettingsPublisher {
        return .{ .context = self, .publish_fn = callback };
    }
};

const TestExportSink = struct {
    bytes: std.ArrayList(u8) = .empty,
    began: bool = false,
    export_id: [16]u8 = zero_id,
    through_audit_id: [16]u8 = zero_id,
    flushed: bool = false,
    fail_write: bool = false,

    fn deinit(self: *TestExportSink) void {
        self.bytes.deinit(std.testing.allocator);
    }

    fn write(context: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *TestExportSink = @ptrCast(@alignCast(context));
        if (self.fail_write) return error.TestExportWriteFailure;
        try self.bytes.appendSlice(std.testing.allocator, bytes);
    }

    fn begin(context: *anyopaque, export_id: [16]u8, through_audit_id: [16]u8) anyerror!void {
        const self: *TestExportSink = @ptrCast(@alignCast(context));
        self.began = true;
        self.export_id = export_id;
        self.through_audit_id = through_audit_id;
    }

    fn flush(context: *anyopaque) anyerror!void {
        const self: *TestExportSink = @ptrCast(@alignCast(context));
        self.flushed = true;
    }

    fn writer(self: *TestExportSink) ExportWriter {
        return .{ .context = self, .begin_fn = begin, .write_fn = write, .flush_fn = flush };
    }
};

const TestExportCheckpoint = struct {
    calls: usize = 0,
    last_deadline: i64 = 0,
    fail_on_call: ?usize = null,

    fn callback(context: ?*anyopaque, deadline_unix_ms: i64) anyerror!void {
        const self: *TestExportCheckpoint = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        self.last_deadline = deadline_unix_ms;
        if (self.fail_on_call == self.calls) return error.DeadlineExceeded;
    }

    fn checkpoint(self: *TestExportCheckpoint) ExportCheckpoint {
        return .{ .context = self, .checkpoint_fn = callback };
    }
};

test "cursor codecs are versioned canonical and bounded" {
    const id = [_]u8{0xab} ** 16;
    var buffer: [maximum_cursor_bytes]u8 = undefined;

    const event_text = try encodeEventCursor(.{ .observed_at = 123, .before_id = id }, &buffer);
    const event = try decodeEventCursor(event_text);
    try std.testing.expectEqual(@as(i64, 123), event.observed_at);
    try std.testing.expectEqualSlices(u8, &id, &event.before_id);

    const connectivity_text = try encodeConnectivityCursor(.{ .requested_at = 456, .before_id = id }, &buffer);
    const connectivity = try decodeConnectivityCursor(connectivity_text);
    try std.testing.expectEqual(@as(i64, 456), connectivity.requested_at);
    try std.testing.expectEqualSlices(u8, &id, &connectivity.before_id);

    const audit_text = try encodeAuditCursor(.{ .before_sequence = 42 }, &buffer);
    try std.testing.expectEqual(@as(u64, 42), (try decodeAuditCursor(audit_text)).before_sequence);
    const settings_text = try encodeSettingsCursor(.{ .before_sequence = 7 }, &buffer);
    try std.testing.expectEqual(@as(u64, 7), (try decodeSettingsCursor(settings_text)).before_sequence);

    try std.testing.expectError(error.InvalidCursor, decodeEventCursor("v1:e:01:abababababababababababababababab"));
    try std.testing.expectError(error.InvalidCursor, decodeEventCursor("v1:e:-1:abababababababababababababababab"));
    try std.testing.expectError(error.InvalidCursor, decodeEventCursor("v1:e:-0:abababababababababababababababab"));
    try std.testing.expectError(error.InvalidCursor, decodeEventCursor("v2:e:1:abababababababababababababababab"));
    try std.testing.expectError(error.InvalidCursor, decodeAuditCursor("v1:a:0"));
    try std.testing.expectError(error.InvalidCursor, decodeSettingsCursor("v1:s:2:extra"));
    try std.testing.expectError(error.InvalidPageLimit, normalizePageLimit(maximum_page_size + 1));

    try std.testing.expectEqual(ErrorCode.service_unavailable, failureForError(error.ConnectivityDispatchUnavailable).code);
    try std.testing.expect(failureForError(error.ConnectivityDispatchUnavailable).retryable);
    try std.testing.expectEqual(ErrorCode.precondition_failed, failureForError(error.PreconditionFailed).code);
    try std.testing.expectEqual(ErrorCode.invalid_request, failureForError(error.DeadlineRequired).code);
    try std.testing.expectEqual(ErrorCode.service_unavailable, failureForError(error.DeadlineExceeded).code);
    try std.testing.expectEqual(ErrorCode.internal_error, failureForError(error.SqliteFailure).code);
}

test "events and audit listings enforce filters paging and redaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    var control: ControlState = .{ .instance_id = [_]u8{0x70} ** 16, .managed_restart_supported = true };
    var service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &control, null, null);
    const viewer = testPrincipal(.viewer, 1);
    const superuser = testPrincipal(.superuser, 2);

    try operations.appendRuntimeEvent(.{
        .id = [_]u8{0x11} ** 16,
        .kind = "node.online",
        .severity = .info,
        .observed_at = 10,
        .details_json = "{\"endpoint\":\"secret\"}",
    });
    try operations.appendRuntimeEvent(.{
        .id = [_]u8{0x12} ** 16,
        .kind = "node.offline",
        .severity = .@"error",
        .observed_at = 20,
        .details_json = "{\"key\":\"secret\"}",
    });
    _ = try operations.appendAudit(testAudit(0x21, 10, "inventory.create"));
    _ = try operations.appendAudit(testAudit(0x22, 20, "settings.update"));

    var first_events = try service.listEvents(viewer, null, 1, .{});
    defer first_events.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), first_events.items.len);
    try std.testing.expect(first_events.next_cursor != null);
    try std.testing.expectEqual(EventSeverity.critical, first_events.items[0].severity);
    try std.testing.expectEqualStrings("node.offline", first_events.items[0].summary());

    var critical = try service.listEvents(viewer, null, null, .{ .severity = .critical, .since_unix_seconds = 15 });
    defer critical.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), critical.items.len);

    var redacted = try service.listAudit(viewer, null, null, .{});
    defer redacted.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), redacted.items.len);
    try std.testing.expect(redacted.items[0].redacted);
    try std.testing.expect(redacted.items[0].actor_user_id == null);
    try std.testing.expect(redacted.items[0].request_id == null);
    try std.testing.expect(redacted.items[0].user_agent == null);
    try std.testing.expect(redacted.items[0].proxy_peer == null);
    try std.testing.expectError(
        error.Forbidden,
        service.listAudit(viewer, null, null, .{ .actor_user_id = [_]u8{0xa1} ** 16 }),
    );

    const resource_type = try ResourceTypeText.parse("operation");
    var full = try service.listAudit(superuser, null, null, .{
        .actor_user_id = [_]u8{0xa1} ** 16,
        .resource_type = resource_type,
    });
    defer full.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), full.items.len);
    try std.testing.expect(!full.items[0].redacted);
    try std.testing.expect(full.items[0].actor_user_id != null);
    try std.testing.expect(full.items[0].request_id != null);
    try std.testing.expectEqualStrings("test-agent", full.items[0].user_agent.?.slice());
    try std.testing.expectEqualStrings("127.0.0.1:4321", full.items[0].proxy_peer.?.slice());
}

test "connectivity checks require operator idempotency and dispatch a bounded address target" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const node_id = try insertTestNode(&db);
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    var control: ControlState = .{ .instance_id = [_]u8{0x70} ** 16, .managed_restart_supported = true };
    var dispatcher: TestDispatcher = .{};
    var service = Service.init(
        std.testing.allocator,
        std.testing.io,
        &operations,
        &settings,
        &control,
        dispatcher.dispatcher(),
        null,
    );
    const viewer = testPrincipal(.viewer, 1);
    const operator = testPrincipal(.operator, 2);

    try std.testing.expectError(
        error.Forbidden,
        service.startConnectivityCheck(viewer, testContext(100, 1, .{ .idempotency_key = "viewer-1" }), .{ .node_id = node_id }),
    );
    try std.testing.expectError(
        error.IdempotencyRequired,
        service.startConnectivityCheck(operator, testContext(100, 2, .{}), .{ .node_id = node_id }),
    );
    const created = try service.startConnectivityCheck(
        operator,
        testContext(100, 3, .{ .idempotency_key = "check-1" }),
        .{ .node_id = node_id, .timeout_milliseconds = 750 },
    );
    try std.testing.expectEqual(ConnectivityStatus.running, created.status);
    try std.testing.expectEqualStrings("10.0.0.2", created.node_address.slice());
    try std.testing.expectEqual(@as(usize, 1), dispatcher.calls);
    try std.testing.expectEqualSlices(u8, &created.id, &dispatcher.last_check_id);
    try std.testing.expectEqualSlices(u8, &node_id, &dispatcher.last_node_id);
    try std.testing.expectEqual(@as(u16, 750), dispatcher.last_timeout);
    try std.testing.expectEqualStrings("10.0.0.2", dispatcher.last_address.slice());

    var page = try service.listConnectivityChecks(viewer, null, null, .{ .node_id = node_id, .status = .running });
    defer page.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), page.items.len);
    try std.testing.expectEqualSlices(u8, &created.id, &page.items[0].id);

    dispatcher.fail = true;
    try std.testing.expectError(
        error.ConnectivityDispatchUnavailable,
        service.startConnectivityCheck(
            operator,
            testContext(101, 4, .{ .idempotency_key = "check-2" }),
            .{ .node_id = node_id },
        ),
    );
    var failed = try service.listConnectivityChecks(viewer, null, null, .{ .status = .failed });
    defer failed.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), failed.items.len);
    try std.testing.expectEqualStrings("dispatch_unavailable", failed.items[0].failure_code.?.slice());
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));

    try db.exec("DELETE FROM nodes WHERE name = 'edge-a';");
    const historical = try service.getConnectivityCheck(viewer, created.id);
    try std.testing.expect(historical.node_id == null);
    try std.testing.expectEqualStrings("10.0.0.2", historical.node_address.slice());
}

test "audit export streams a canonical redacted-safe prefix before receipt and prune" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    var control: ControlState = .{ .instance_id = [_]u8{0x70} ** 16, .managed_restart_supported = true };
    var service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &control, null, null);
    var checkpoint: TestExportCheckpoint = .{};
    service.export_checkpoint = checkpoint.checkpoint();
    const superuser = testPrincipal(.superuser, 3);
    _ = try operations.appendAudit(testAudit(0x31, 10, "inventory.create"));
    _ = try operations.appendAudit(testAudit(0x32, 20, "settings.update"));
    const through_id = [_]u8{0x32} ** 16;
    const before = try service.auditEtag(superuser);

    var no_deadline = testDangerousContext(100, 1, before.slice(), "export audit", "export-no-deadline");
    no_deadline.deadline_unix_ms = null;
    var unused_sink: TestExportSink = .{};
    defer unused_sink.deinit();
    try std.testing.expectError(
        error.DeadlineRequired,
        service.exportAudit(superuser, no_deadline, through_id, unused_sink.writer()),
    );
    var expired = testDangerousContext(100, 1, before.slice(), "export audit", "export-expired");
    expired.deadline_unix_ms = expired.now_unix_ms;
    try std.testing.expectError(
        error.DeadlineExceeded,
        service.exportAudit(superuser, expired, through_id, unused_sink.writer()),
    );

    var failed_sink: TestExportSink = .{ .fail_write = true };
    defer failed_sink.deinit();
    try std.testing.expectError(
        error.TestExportWriteFailure,
        service.exportAudit(
            superuser,
            testDangerousContext(100, 1, before.slice(), "export audit", "export-fail"),
            through_id,
            failed_sink.writer(),
        ),
    );
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM audit_export_receipts;"));

    checkpoint.calls = 0;
    var sink: TestExportSink = .{};
    defer sink.deinit();
    const exported = try service.exportAudit(
        superuser,
        testDangerousContext(100, 2, before.slice(), "export audit", "export-1"),
        through_id,
        sink.writer(),
    );
    try std.testing.expect(sink.began);
    try std.testing.expectEqualSlices(u8, &sink.export_id, &exported.receipt.id);
    try std.testing.expectEqualSlices(u8, &through_id, &sink.through_audit_id);
    try std.testing.expect(sink.flushed);
    try std.testing.expectEqual(@as(usize, 2), checkpoint.calls);
    try std.testing.expectEqual(@as(i64, 160_000), checkpoint.last_deadline);
    try std.testing.expectEqual(@as(u64, 2), exported.receipt.entry_count);
    try std.testing.expectEqualSlices(u8, &through_id, &exported.exported_through_audit_id);
    try std.testing.expect(std.mem.indexOf(u8, sink.bytes.items, "\"recordType\":\"auditEntry\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sink.bytes.items, "\"occurredAt\":\"1970-01-01T00:00:10Z\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, sink.bytes.items, "must-not-export") == null);
    try std.testing.expect(std.mem.indexOf(u8, sink.bytes.items, "details") == null);
    try std.testing.expect(std.mem.indexOf(u8, sink.bytes.items, "\"recordType\":\"auditExportReceipt\"") != null);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, sink.bytes.items, "\n"));

    try std.testing.expectError(
        error.PreconditionFailed,
        service.pruneAudit(
            superuser,
            testDangerousContext(101, 3, before.slice(), "prune audit", "prune-stale"),
            exported.receipt.id,
            through_id,
        ),
    );
    const pruned = try service.pruneAudit(
        superuser,
        testDangerousContext(101, 4, exported.etag.slice(), "prune audit", "prune-1"),
        exported.receipt.id,
        through_id,
    );
    try std.testing.expectEqual(@as(u64, 2), pruned.pruned_entries);
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_export_receipts;"));
}

test "audit export checkpoints finalized 64-row batches without gaps or duplicates" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    var control: ControlState = .{ .instance_id = [_]u8{0x70} ** 16, .managed_restart_supported = true };
    var service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &control, null, null);
    var checkpoint: TestExportCheckpoint = .{};
    service.export_checkpoint = checkpoint.checkpoint();
    const superuser = testPrincipal(.superuser, 3);

    const audit_count: u16 = export_checkpoint_interval * 2 + 2;
    var through_id: [16]u8 = undefined;
    for (1..@as(usize, audit_count) + 1) |raw_sequence| {
        var audit = testAudit(0x31, @intCast(raw_sequence), "inventory.create");
        audit.id = [_]u8{0} ** 16;
        audit.id[0] = 0xc7;
        audit.id[14] = @intCast(raw_sequence >> 8);
        audit.id[15] = @intCast(raw_sequence & 0xff);
        through_id = audit.id;
        _ = try operations.appendAudit(audit);
    }
    const before = try service.auditEtag(superuser);
    var sink: TestExportSink = .{};
    defer sink.deinit();
    const exported = try service.exportAudit(
        superuser,
        testDangerousContext(200, 1, before.slice(), "export audit", "export-batches"),
        through_id,
        sink.writer(),
    );

    try std.testing.expectEqual(@as(u64, audit_count), exported.receipt.entry_count);
    try std.testing.expectEqual(@as(usize, 4), checkpoint.calls); // admission + three batches
    var lines = std.mem.splitScalar(u8, sink.bytes.items, '\n');
    for (1..@as(usize, audit_count) + 1) |expected_sequence| {
        const line = lines.next() orelse return error.MissingAuditExportLine;
        var expected_buffer: [48]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buffer, "\"sequence\":{d},", .{expected_sequence});
        try std.testing.expect(std.mem.indexOf(u8, line, expected) != null);
        try std.testing.expect(std.mem.indexOf(u8, line, "\"recordType\":\"auditEntry\"") != null);
    }
    const receipt_line = lines.next() orelse return error.MissingAuditExportReceipt;
    try std.testing.expect(std.mem.indexOf(u8, receipt_line, "\"recordType\":\"auditExportReceipt\"") != null);
    try std.testing.expectEqualStrings("", lines.next() orelse return error.MissingAuditExportTerminator);
    try std.testing.expect(lines.next() == null);
}

test "audit export stops at an expired between-batch checkpoint" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    var control: ControlState = .{ .instance_id = [_]u8{0x70} ** 16, .managed_restart_supported = true };
    var service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &control, null, null);
    var checkpoint: TestExportCheckpoint = .{ .fail_on_call = 2 };
    service.export_checkpoint = checkpoint.checkpoint();
    const superuser = testPrincipal(.superuser, 3);

    var through_id: [16]u8 = undefined;
    for (1..@as(usize, export_checkpoint_interval) + 2) |raw_sequence| {
        var audit = testAudit(0x31, @intCast(raw_sequence), "inventory.create");
        audit.id = [_]u8{0} ** 16;
        audit.id[0] = 0xd8;
        audit.id[15] = @intCast(raw_sequence);
        through_id = audit.id;
        _ = try operations.appendAudit(audit);
    }
    const before = try service.auditEtag(superuser);
    var sink: TestExportSink = .{};
    defer sink.deinit();
    try std.testing.expectError(
        error.DeadlineExceeded,
        service.exportAudit(
            superuser,
            testDangerousContext(300, 1, before.slice(), "export audit", "export-deadline"),
            through_id,
            sink.writer(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), checkpoint.calls);
    try std.testing.expectEqual(@as(usize, export_checkpoint_interval), std.mem.count(u8, sink.bytes.items, "\n"));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM audit_export_receipts;"));
}

test "settings update rollback and revision paging enforce strong policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    var control: ControlState = .{ .instance_id = [_]u8{0x70} ** 16, .managed_restart_supported = true };
    var publisher: TestSettingsPublisher = .{};
    var service = Service.init(
        std.testing.allocator,
        std.testing.io,
        &operations,
        &settings,
        &control,
        null,
        publisher.publisher(),
    );
    const viewer = testPrincipal(.viewer, 1);
    const superuser = testPrincipal(.superuser, 3);
    const initial = try service.getSettings(viewer);
    try std.testing.expectEqual(@as(u64, 1), initial.desired.sequence);
    const initial_etag = try service.settingsEtag(viewer);

    try std.testing.expectError(
        error.Forbidden,
        service.updateSettings(
            viewer,
            testDangerousContext(100, 1, initial_etag.slice(), "settings", null),
            .{ .inner_mtu = 1400 },
        ),
    );
    const updated = try service.updateSettings(
        superuser,
        testDangerousContext(100, 2, initial_etag.slice(), "settings", null),
        .{ .inner_mtu = 1400 },
    );
    try std.testing.expectEqual(@as(u64, 2), updated.sequence);
    try std.testing.expectEqual(settings_model.RevisionStatus.pending_apply, updated.status);
    try std.testing.expectEqual(@as(usize, 1), publisher.calls);
    try std.testing.expectEqual(@as(u64, 2), publisher.last_sequence);
    try std.testing.expectEqual(@as(u16, 1400), publisher.last_values.inner_mtu);
    const pending_etag = try service.settingsEtag(superuser);
    _ = try settings.acknowledgeFailed(
        updated.sequence,
        try settings_repository.FailureCode.parse("mtu_apply_failed"),
        101,
        testAudit(0x91, 101, "settings.apply_failed"),
    );
    const failed_etag = try service.settingsEtag(superuser);
    try std.testing.expect(!std.mem.eql(u8, pending_etag.slice(), failed_etag.slice()));
    try std.testing.expectError(
        error.PreconditionFailed,
        service.updateSettings(
            superuser,
            testDangerousContext(102, 9, pending_etag.slice(), "settings", null),
            .{ .inner_mtu = 1410 },
        ),
    );

    var revisions = try service.listSettingsRevisions(viewer, null, 1);
    defer revisions.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), revisions.items.len);
    try std.testing.expectEqual(@as(u64, 2), revisions.items[0].sequence);
    try std.testing.expect(revisions.next_cursor != null);

    const after_update = failed_etag;
    const initial_id = [_]u8{0} ** 15 ++ [_]u8{1};
    var initial_id_text: [32]u8 = undefined;
    const rolled_back = try service.rollbackSettings(
        superuser,
        testDangerousContext(101, 3, after_update.slice(), encodeId(initial_id, &initial_id_text), "rollback-1"),
        initial_id,
    );
    try std.testing.expectEqual(@as(u64, 3), rolled_back.sequence);
    try std.testing.expectEqual(@as(u16, 1380), rolled_back.values.inner_mtu);
    try std.testing.expectEqual(settings_model.RevisionStatus.active, rolled_back.status);
    try std.testing.expectEqual(@as(usize, 1), publisher.calls);

    const after_rollback = try service.settingsEtag(superuser);
    const restart_only = try service.updateSettings(
        superuser,
        testDangerousContext(102, 4, after_rollback.slice(), "settings", null),
        .{ .maximum_nodes = 8192 },
    );
    try std.testing.expectEqual(settings_model.RevisionStatus.pending_restart, restart_only.status);
    try std.testing.expectEqual(@as(usize, 1), publisher.calls);
    try std.testing.expect((try service.getSettings(viewer)).pending_restart);
}

test "restart and shutdown decisions are audited after exact authorization" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    var operations = operations_repository.Repository.init(&db);
    var settings = settings_repository.Repository.init(&db);
    const viewer = testPrincipal(.viewer, 1);
    var superuser = testPrincipal(.superuser, 3);
    superuser.user_agent = try UserAgentText.parse("ntip-dashboard-test");
    superuser.proxy_peer = try ProxyPeerText.parse("127.0.0.1:4444");

    var unmanaged: ControlState = .{ .instance_id = [_]u8{0x71} ** 16, .managed_restart_supported = false };
    var unmanaged_service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &unmanaged, null, null);
    try std.testing.expectError(error.Forbidden, unmanaged_service.requestRestart(viewer, testContext(100, 1, .{})));
    try std.testing.expectError(error.OperationUnavailable, unmanaged_service.requestRestart(superuser, testContext(100, 2, .{})));

    var managed: ControlState = .{ .instance_id = [_]u8{0x72} ** 16, .managed_restart_supported = true };
    var service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &managed, null, null);
    const etag = try service.controlEtag(superuser);
    try std.testing.expectError(
        error.IdempotencyRequired,
        service.requestRestart(superuser, testDangerousContext(100, 3, etag.slice(), "restart", null)),
    );
    try std.testing.expectError(
        error.PreconditionFailed,
        service.requestRestart(superuser, testDangerousContext(100, 4, "\"service:stale:1:1\"", "restart", "restart-stale")),
    );
    const restart_checkpoint = service.controlStageCheckpoint();
    const restart = try service.requestRestart(
        superuser,
        testDangerousContext(100, 5, etag.slice(), "restart", "restart-1"),
    );
    try std.testing.expectEqual(ControlKind.restart, restart.kind);
    try std.testing.expectEqual(restart_exit_status, restart.exit_status);
    try std.testing.expectEqual(@as(u64, 2), managed.revision);
    try std.testing.expect(managed.staged != null);
    try std.testing.expect(managed.pending == null);
    const owned_restart = service.stagedControlSince(restart_checkpoint, .restart) orelse
        return error.MissingStagedControlDecision;
    try std.testing.expectEqualSlices(u8, &restart.id, &owned_restart.id);
    var unrelated_id = restart.id;
    unrelated_id[0] ^= 0xff;
    try std.testing.expect(!service.discardStagedControl(unrelated_id));
    try std.testing.expect(managed.staged != null);
    try std.testing.expectError(error.ControlDecisionMismatch, service.armStagedControl(unrelated_id));
    try service.armStagedControl(restart.id);
    try std.testing.expect(managed.staged == null);
    try std.testing.expect(managed.pending != null);
    try std.testing.expect(!service.discardStagedControl(restart.id));
    try std.testing.expectEqualSlices(u8, &restart.id, &managed.pending.?.id);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE action = 'service.restart';"));
    try std.testing.expectEqual(
        @as(i64, 1),
        try scalarInt(
            &db,
            "SELECT count(*) FROM audit_entries WHERE " ++
                "json_extract(details_json,'$.userAgent') = 'ntip-dashboard-test' AND " ++
                "json_extract(details_json,'$.proxyPeer') = '127.0.0.1:4444';",
        ),
    );
    try std.testing.expectError(
        error.Forbidden,
        service.requestShutdown(viewer, testDangerousContext(101, 6, etag.slice(), "shutdown", "viewer-shutdown")),
    );
    try std.testing.expectError(
        error.ServiceOperationInProgress,
        service.requestShutdown(superuser, testDangerousContext(101, 7, etag.slice(), "shutdown", "shutdown-1")),
    );

    var shutdown_state: ControlState = .{ .instance_id = [_]u8{0x73} ** 16, .managed_restart_supported = true };
    var shutdown_service = Service.init(std.testing.allocator, std.testing.io, &operations, &settings, &shutdown_state, null, null);
    const shutdown_etag = try shutdown_service.controlEtag(superuser);
    const shutdown = try shutdown_service.requestShutdown(
        superuser,
        testDangerousContext(102, 8, shutdown_etag.slice(), "shutdown", "shutdown-2"),
    );
    try std.testing.expectEqual(ControlKind.shutdown, shutdown.kind);
    try std.testing.expectEqual(shutdown_exit_status, shutdown.exit_status);
    try std.testing.expect(shutdown_state.staged != null);
    try std.testing.expect(shutdown_state.pending == null);
    try std.testing.expect(shutdown_service.discardStagedControl(shutdown.id));
    try std.testing.expect(shutdown_state.staged == null);
    try std.testing.expectEqual(@as(u64, 2), shutdown_state.revision);
    const after_discard = try shutdown_service.controlEtag(superuser);
    try std.testing.expect(!std.mem.eql(u8, shutdown_etag.slice(), after_discard.slice()));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries WHERE action = 'service.shutdown';"));
}
