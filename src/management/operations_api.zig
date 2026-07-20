//! HTTP-contract adapter for operations, diagnostics, settings, and service control.
//!
//! Authentication and CSRF verification happen in the central authoritative
//! dispatcher. This layer receives that authenticated session, revalidates the
//! forwarded route/body/query contract, derives all actor and reauthentication
//! context from authoritative state, and delegates durable work to
//! `operations_service.Service`.

const std = @import("std");
const api_request = @import("api_request.zig");
const api_response = @import("api_response.zig");
const http = @import("http.zig");
const operations_service = @import("operations_service.zig");
const service_ipc = @import("service_ipc.zig");
const service_server = @import("service_server.zig");
const access_repository = @import("../state/access_repository.zig");

const export_chunk_bytes: usize = 32 * 1024;
const cursor_buffer_bytes: usize = 112;

pub const Adapter = struct {
    service: *operations_service.Service,

    pub fn init(service: *operations_service.Service) Adapter {
        return .{ .service = service };
    }

    /// Dispatches one already-authenticated canonical operation. `session`
    /// must be the session authenticated from `forwarded.session_token` by the
    /// central application in the same synchronous request.
    pub fn handle(
        self: *Adapter,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        session: access_repository.Session,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (session.password_change_required) return error.PasswordChangeRequired;
        if (forwarded.session_token == null) return error.SessionNotFound;
        if (request.actor.kind != .service) return error.InvalidActor;

        const now_ms = std.Io.Clock.real.now(self.service.io).toMilliseconds();
        if (now_ms < 0) return error.InvalidTimestamp;
        if (request.deadline_unix_ms <= now_ms) return error.DeadlineExceeded;
        const request_id = try api_response.decodeId(request.request_id);
        const principal = try makePrincipal(session, forwarded.user_agent);

        if (std.mem.eql(u8, request.operation, "diagnostics.checks.list")) {
            return self.listConnectivity(forwarded, principal, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "diagnostics.check.create")) {
            return self.createConnectivity(
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        if (std.mem.eql(u8, request.operation, "diagnostics.check.read")) {
            return self.readConnectivity(forwarded, principal, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "operations.events.list")) {
            return self.listEvents(forwarded, principal, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "operations.audit.list")) {
            return self.listAudit(forwarded, principal, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "operations.audit.export")) {
            return self.exportAudit(
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        if (std.mem.eql(u8, request.operation, "operations.audit.prune")) {
            return self.pruneAudit(
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        if (std.mem.eql(u8, request.operation, "settings.read")) {
            return self.readSettings(forwarded, principal, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "settings.revisions.list")) {
            return self.listSettingsRevisions(forwarded, principal, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "settings.update")) {
            return self.updateSettings(
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        if (std.mem.eql(u8, request.operation, "settings.rollback")) {
            return self.rollbackSettings(
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        if (std.mem.eql(u8, request.operation, "service.restart")) {
            return self.control(
                .restart,
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        if (std.mem.eql(u8, request.operation, "service.shutdown")) {
            return self.control(
                .shutdown,
                request,
                forwarded,
                principal,
                session,
                request_id,
                now_ms,
                allocator,
                response,
            );
        }
        return error.OperationUnavailable;
    }

    fn listConnectivity(
        self: *Adapter,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireCollectionRead(forwarded, "/api/v1/connectivity-checks");
        var query_scratch: [http.maximum_target_bytes]u8 = undefined;
        const query = try parseQuery(forwarded.query(), .connectivity, &query_scratch);
        const cursor = if (query.cursor) |text| try decodeCompositeCursor(.connectivity, text) else null;
        var page = try self.service.listConnectivityChecks(
            principal,
            if (cursor) |value| .{ .requested_at = value.timestamp, .before_id = value.id } else null,
            query.limit,
            .{
                .node_id = if (query.node_id) |text| try api_response.decodeId(text) else null,
                .status = if (query.status) |text|
                    std.meta.stringToEnum(operations_service.ConnectivityStatus, text) orelse
                        return error.InvalidConnectivityStatus
                else
                    null,
            },
        );
        // Page storage is owned by the long-lived operations service, not the
        // per-request serialization arena.
        defer page.deinit(self.service.allocator);
        return finishConnectivityPage(response, allocator, page);
    }

    fn createConnectivity(
        self: *Adapter,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        session: access_repository.Session,
        request_id: [16]u8,
        now_ms: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireExact(forwarded, .POST, "/api/v1/connectivity-checks");
        try validatePreconditionShape(request.preconditions, false, true, false);
        const Body = struct {
            nodeId: []const u8,
            timeoutMilliseconds: u16 = 3_000,
        };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        const check = try self.service.startConnectivityCheck(principal, try makeContext(
            request,
            session,
            request_id,
            now_ms,
            null,
        ), .{
            .node_id = try api_response.decodeId(parsed.value.nodeId),
            .timeout_milliseconds = parsed.value.timeoutMilliseconds,
        });
        var id_text: [32]u8 = undefined;
        var location_buffer: [96]u8 = undefined;
        const id = api_response.encodeId(check.id, &id_text);
        const location = try std.fmt.bufPrint(
            &location_buffer,
            "/api/v1/connectivity-checks/{s}",
            .{id},
        );
        return finishConnectivity(response, allocator, 202, check, .{ .location = location });
    }

    fn readConnectivity(
        self: *Adapter,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireParameterizedRead(forwarded);
        const id_text = try api_request.pathParameter(
            forwarded.target,
            "/api/v1/connectivity-checks/",
            "",
        );
        const check = try self.service.getConnectivityCheck(principal, try api_response.decodeId(id_text));
        return finishConnectivity(response, allocator, 200, check, .{});
    }

    fn listEvents(
        self: *Adapter,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireCollectionRead(forwarded, "/api/v1/events");
        var query_scratch: [http.maximum_target_bytes]u8 = undefined;
        const query = try parseQuery(forwarded.query(), .events, &query_scratch);
        const cursor = if (query.cursor) |text| try decodeCompositeCursor(.event, text) else null;
        const severity: ?operations_service.EventSeverity = if (query.severity) |text|
            std.meta.stringToEnum(operations_service.EventSeverity, text) orelse return error.InvalidEventSeverity
        else
            null;
        var page = try self.service.listEvents(
            principal,
            if (cursor) |value| .{ .observed_at = value.timestamp, .before_id = value.id } else null,
            query.limit,
            .{
                .severity = severity,
                .node_id = if (query.node_id) |text| try api_response.decodeId(text) else null,
                .since_unix_seconds = if (query.since) |text| try parseTimestamp(text) else null,
            },
        );
        defer page.deinit(self.service.allocator);
        return finishEventPage(response, allocator, page);
    }

    fn listAudit(
        self: *Adapter,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireCollectionRead(forwarded, "/api/v1/audit");
        var query_scratch: [http.maximum_target_bytes]u8 = undefined;
        const query = try parseQuery(forwarded.query(), .audit, &query_scratch);
        const cursor = if (query.cursor) |text| try decodeSequenceCursor(.audit, text) else null;
        var page = try self.service.listAudit(
            principal,
            if (cursor) |sequence| .{ .before_sequence = sequence } else null,
            query.limit,
            .{
                .actor_user_id = if (query.actor_user_id) |text| try api_response.decodeId(text) else null,
                .resource_type = if (query.resource_type) |text|
                    operations_service.ResourceTypeText.parse(text) catch return error.InvalidResourceType
                else
                    null,
                .since_unix_seconds = if (query.since) |text| try parseTimestamp(text) else null,
            },
        );
        defer page.deinit(self.service.allocator);
        const etag = try self.service.auditEtag(principal);
        return finishAuditPage(response, allocator, page, .{ .etag = etag.slice() });
    }

    fn exportAudit(
        self: *Adapter,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        session: access_repository.Session,
        request_id: [16]u8,
        now_ms: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireExact(forwarded, .POST, "/api/v1/audit/export");
        try validatePreconditionShape(request.preconditions, true, true, true);
        const Body = struct { throughAuditId: []const u8, confirmation: []const u8 };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        try requireConfirmation(request.preconditions.confirmation, parsed.value.confirmation);

        var stream = ExportStream.init(allocator, response);
        defer stream.deinit();
        const result = try self.service.exportAudit(
            principal,
            try makeContext(request, session, request_id, now_ms, parsed.value.confirmation),
            try api_response.decodeId(parsed.value.throughAuditId),
            stream.writer(),
        );
        try stream.flush();
        if (stream.export_id == null or !std.mem.eql(u8, &stream.export_id.?, &result.receipt.id)) {
            return error.InvalidExportStream;
        }
        // The central idempotency dispatcher owns the terminal frame. It
        // durably commits the consumed marker after this adapter returns and
        // only then terminates the private stream, so public HTTP success
        // cannot precede idempotency durability.
    }

    fn pruneAudit(
        self: *Adapter,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        session: access_repository.Session,
        request_id: [16]u8,
        now_ms: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireExact(forwarded, .POST, "/api/v1/audit/prune");
        try validatePreconditionShape(request.preconditions, true, true, true);
        const Body = struct {
            exportId: []const u8,
            throughAuditId: []const u8,
            confirmation: []const u8,
        };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        try requireConfirmation(request.preconditions.confirmation, parsed.value.confirmation);
        const result = try self.service.pruneAudit(
            principal,
            try makeContext(request, session, request_id, now_ms, parsed.value.confirmation),
            try api_response.decodeId(parsed.value.exportId),
            try api_response.decodeId(parsed.value.throughAuditId),
        );
        return finishPruneResult(response, allocator, result);
    }

    fn readSettings(
        self: *Adapter,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireExact(forwarded, .GET, "/api/v1/settings");
        try requireNoBody(forwarded);
        const state = try self.service.getSettings(principal);
        const etag = try self.service.settingsEtag(principal);
        return finishSettingsState(response, allocator, state, .{ .etag = etag.slice() });
    }

    fn listSettingsRevisions(
        self: *Adapter,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireCollectionRead(forwarded, "/api/v1/settings/revisions");
        var query_scratch: [http.maximum_target_bytes]u8 = undefined;
        const query = try parseQuery(forwarded.query(), .settings_revisions, &query_scratch);
        const cursor = if (query.cursor) |text| try decodeSequenceCursor(.settings, text) else null;
        var page = try self.service.listSettingsRevisions(
            principal,
            if (cursor) |sequence| .{ .before_sequence = sequence } else null,
            query.limit,
        );
        defer page.deinit(self.service.allocator);
        return finishSettingsPage(response, allocator, page);
    }

    fn updateSettings(
        self: *Adapter,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        session: access_repository.Session,
        request_id: [16]u8,
        now_ms: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try requireExact(forwarded, .PATCH, "/api/v1/settings");
        try validatePreconditionShape(request.preconditions, true, false, true);
        const Body = struct {
            confirmation: []const u8,
            innerMtu: ?u16 = null,
            heartbeatIntervalSeconds: ?u16 = null,
            suspectAfterSeconds: ?u16 = null,
            offlineAfterSeconds: ?u16 = null,
            defaultEnrollmentLifetimeSeconds: ?u32 = null,
            trafficColdAfterSeconds: ?u32 = null,
            trafficHotPacketsPerSecond: ?u64 = null,
            trafficHotBitsPerSecond: ?u64 = null,
            trafficSaturatedQueuePercent: ?u8 = null,
            trafficHysteresisSeconds: ?u32 = null,
            runtimeEventRetentionDays: ?u16 = null,
            connectivityRetentionDays: ?u16 = null,
            maximumNodes: ?u32 = null,
        };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        try requireConfirmation(request.preconditions.confirmation, parsed.value.confirmation);
        const revision = try self.service.updateSettings(
            principal,
            try makeContext(request, session, request_id, now_ms, parsed.value.confirmation),
            .{
                .inner_mtu = parsed.value.innerMtu,
                .heartbeat_idle_seconds = parsed.value.heartbeatIntervalSeconds,
                .suspect_after_seconds = parsed.value.suspectAfterSeconds,
                .offline_after_seconds = parsed.value.offlineAfterSeconds,
                .default_enrollment_lifetime_seconds = parsed.value.defaultEnrollmentLifetimeSeconds,
                .maximum_nodes = parsed.value.maximumNodes,
                .traffic_cold_after_seconds = parsed.value.trafficColdAfterSeconds,
                .traffic_hot_packets_per_second = parsed.value.trafficHotPacketsPerSecond,
                .traffic_hot_bits_per_second = parsed.value.trafficHotBitsPerSecond,
                .traffic_saturated_queue_percent = parsed.value.trafficSaturatedQueuePercent,
                .traffic_hysteresis_seconds = parsed.value.trafficHysteresisSeconds,
                .runtime_event_retention_days = parsed.value.runtimeEventRetentionDays,
                .connectivity_result_retention_days = parsed.value.connectivityRetentionDays,
            },
        );
        const etag = try self.service.settingsEtag(principal);
        return finishSettingsRevisionCreated(response, allocator, revision, etag);
    }

    fn rollbackSettings(
        self: *Adapter,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        session: access_repository.Session,
        request_id: [16]u8,
        now_ms: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (forwarded.method != .POST or forwarded.query().len != 0) return error.InvalidTarget;
        const id_text = try api_request.pathParameter(
            forwarded.target,
            "/api/v1/settings/revisions/",
            "/rollback",
        );
        try validatePreconditionShape(request.preconditions, true, true, true);
        const Body = struct { confirmation: []const u8 };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        try requireConfirmation(request.preconditions.confirmation, parsed.value.confirmation);
        if (!std.mem.eql(u8, parsed.value.confirmation, id_text)) return error.ConfirmationFailed;
        const revision = try self.service.rollbackSettings(
            principal,
            try makeContext(request, session, request_id, now_ms, parsed.value.confirmation),
            try api_response.decodeId(id_text),
        );
        const etag = try self.service.settingsEtag(principal);
        return finishSettingsRevisionCreated(response, allocator, revision, etag);
    }

    fn control(
        self: *Adapter,
        kind: operations_service.ControlKind,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: operations_service.Principal,
        session: access_repository.Session,
        request_id: [16]u8,
        now_ms: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const target = if (kind == .restart)
            "/api/v1/operations/restart"
        else
            "/api/v1/operations/shutdown";
        try requireExact(forwarded, .POST, target);
        try validatePreconditionShape(request.preconditions, true, true, true);
        const Body = struct { confirmation: []const u8 };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        try requireConfirmation(request.preconditions.confirmation, parsed.value.confirmation);
        if (!std.mem.eql(u8, parsed.value.confirmation, @tagName(kind))) return error.ConfirmationFailed;
        const context = try makeContext(request, session, request_id, now_ms, parsed.value.confirmation);
        const decision = if (kind == .restart)
            try self.service.requestRestart(principal, context)
        else
            try self.service.requestShutdown(principal, context);
        return finishControlDecision(response, allocator, decision);
    }
};

fn makePrincipal(
    session: access_repository.Session,
    user_agent_text: ?[]const u8,
) !operations_service.Principal {
    const user_agent = if (user_agent_text) |text|
        operations_service.UserAgentText.parse(text) catch return error.InvalidUserAgent
    else
        null;
    return .{
        .user_id = session.user_id,
        .session_id = session.id,
        .role = session.role,
        .user_agent = user_agent,
        .proxy_peer = operations_service.ProxyPeerText.parse("loopback") catch unreachable,
    };
}

fn makeContext(
    request: service_ipc.Request,
    session: access_repository.Session,
    request_id: [16]u8,
    now_ms: i64,
    confirmation: ?[]const u8,
) !operations_service.RequestContext {
    const reauthenticated_ms: ?i64 = if (session.reauthenticated_at) |seconds|
        std.math.mul(i64, seconds, 1000) catch return error.InvalidTimestamp
    else
        null;
    return .{
        .request_id = request_id,
        .now_unix_ms = now_ms,
        .deadline_unix_ms = request.deadline_unix_ms,
        .preconditions = .{
            .etag = request.preconditions.etag,
            .idempotency_key = request.preconditions.idempotency_key,
            // Never trust a reauthentication timestamp forwarded by the
            // DB-free HTTP tier; derive it from the authenticated session.
            .reauthenticated_at_unix_ms = reauthenticated_ms,
            .confirmation = confirmation,
        },
    };
}

fn validatePreconditionShape(
    preconditions: service_ipc.Preconditions,
    etag: bool,
    idempotency: bool,
    confirmation: bool,
) !void {
    if ((preconditions.etag != null) != etag) {
        return if (etag) error.PreconditionRequired else error.InvalidPrecondition;
    }
    if ((preconditions.idempotency_key != null) != idempotency) {
        return if (idempotency) error.IdempotencyRequired else error.InvalidPrecondition;
    }
    if ((preconditions.confirmation != null) != confirmation) return error.InvalidPrecondition;
    if (preconditions.reauthenticated_at_unix_ms != null) return error.InvalidPrecondition;
}

fn requireConfirmation(forwarded: ?[]const u8, body: []const u8) !void {
    const value = forwarded orelse return error.InvalidPrecondition;
    if (!std.mem.eql(u8, value, body)) return error.InvalidPrecondition;
}

fn requireExact(forwarded: api_request.Forwarded, method: http.Method, path: []const u8) !void {
    if (forwarded.method != method or forwarded.query().len != 0 or
        !std.mem.eql(u8, forwarded.path(), path)) return error.InvalidTarget;
}

fn requireCollectionRead(forwarded: api_request.Forwarded, path: []const u8) !void {
    if (forwarded.method != .GET or !std.mem.eql(u8, forwarded.path(), path)) {
        return error.InvalidTarget;
    }
    try requireNoBody(forwarded);
}

fn requireParameterizedRead(forwarded: api_request.Forwarded) !void {
    if (forwarded.method != .GET or forwarded.query().len != 0) return error.InvalidTarget;
    try requireNoBody(forwarded);
}

fn requireNoBody(forwarded: api_request.Forwarded) !void {
    if (forwarded.body != null) return error.InvalidRequestBody;
}

const QueryKind = enum { connectivity, events, audit, settings_revisions };

const Query = struct {
    cursor: ?[]const u8 = null,
    limit: ?u16 = null,
    node_id: ?[]const u8 = null,
    status: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    since: ?[]const u8 = null,
    actor_user_id: ?[]const u8 = null,
    resource_type: ?[]const u8 = null,
};

fn parseQuery(text: []const u8, kind: QueryKind, scratch: []u8) !Query {
    if (text.len == 0) return .{};
    var result: Query = .{};
    var scratch_used: usize = 0;
    var pairs = std.mem.splitScalar(u8, text, '&');
    while (pairs.next()) |pair| {
        if (pair.len == 0) return error.InvalidQuery;
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse return error.InvalidQuery;
        if (std.mem.indexOfScalarPos(u8, pair, equals + 1, '=') != null) return error.InvalidQuery;
        const name = pair[0..equals];
        const encoded_value = pair[equals + 1 ..];
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '%') != null or
            std.mem.indexOfScalar(u8, name, '+') != null or encoded_value.len == 0)
        {
            return error.InvalidQuery;
        }
        const value = try api_request.decodeQueryComponent(encoded_value, scratch[scratch_used..]);
        scratch_used += value.len;
        if (std.mem.eql(u8, name, "cursor")) {
            if (result.cursor != null or value.len > operations_service.maximum_cursor_bytes) {
                return error.InvalidQuery;
            }
            result.cursor = value;
        } else if (std.mem.eql(u8, name, "limit")) {
            if (result.limit != null) return error.InvalidQuery;
            result.limit = std.fmt.parseInt(u16, value, 10) catch return error.InvalidQuery;
            if (result.limit.? == 0 or result.limit.? > operations_service.maximum_page_size) {
                return error.InvalidQuery;
            }
        } else if (kind == .connectivity and std.mem.eql(u8, name, "nodeId")) {
            if (result.node_id != null) return error.InvalidQuery;
            result.node_id = value;
        } else if (kind == .connectivity and std.mem.eql(u8, name, "status")) {
            if (result.status != null) return error.InvalidQuery;
            result.status = value;
        } else if (kind == .events and std.mem.eql(u8, name, "severity")) {
            if (result.severity != null) return error.InvalidQuery;
            result.severity = value;
        } else if (kind == .events and std.mem.eql(u8, name, "nodeId")) {
            if (result.node_id != null) return error.InvalidQuery;
            result.node_id = value;
        } else if ((kind == .events or kind == .audit) and std.mem.eql(u8, name, "since")) {
            if (result.since != null) return error.InvalidQuery;
            result.since = value;
        } else if (kind == .audit and std.mem.eql(u8, name, "actorUserId")) {
            if (result.actor_user_id != null) return error.InvalidQuery;
            result.actor_user_id = value;
        } else if (kind == .audit and std.mem.eql(u8, name, "resourceType")) {
            if (result.resource_type != null) return error.InvalidQuery;
            result.resource_type = value;
        } else {
            return error.InvalidQuery;
        }
    }
    return result;
}

const CompositeCursorKind = enum { connectivity, event };
const SequenceCursorKind = enum { audit, settings };
const CompositeCursor = struct { timestamp: i64, id: [16]u8 };

fn encodeCompositeCursor(
    kind: CompositeCursorKind,
    cursor: CompositeCursor,
    output: *[cursor_buffer_bytes]u8,
) []const u8 {
    var id_text: [32]u8 = undefined;
    return std.fmt.bufPrint(output, "v1:{c}:{d}:{s}", .{
        if (kind == .connectivity) @as(u8, 'c') else @as(u8, 'e'),
        cursor.timestamp,
        api_response.encodeId(cursor.id, &id_text),
    }) catch unreachable;
}

fn decodeCompositeCursor(kind: CompositeCursorKind, text: []const u8) !CompositeCursor {
    const prefix = if (kind == .connectivity) "v1:c:" else "v1:e:";
    if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidCursor;
    const rest = text[prefix.len..];
    const separator = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidCursor;
    const timestamp_text = rest[0..separator];
    const id_text = rest[separator + 1 ..];
    if (timestamp_text.len == 0 or timestamp_text.len > 19 or id_text.len != 32) {
        return error.InvalidCursor;
    }
    const timestamp = std.fmt.parseInt(i64, timestamp_text, 10) catch return error.InvalidCursor;
    if (timestamp < 0) return error.InvalidCursor;
    const cursor: CompositeCursor = .{
        .timestamp = timestamp,
        .id = api_response.decodeId(id_text) catch return error.InvalidCursor,
    };
    var canonical: [cursor_buffer_bytes]u8 = undefined;
    if (!std.mem.eql(u8, text, encodeCompositeCursor(kind, cursor, &canonical))) {
        return error.InvalidCursor;
    }
    return cursor;
}

fn encodeSequenceCursor(
    kind: SequenceCursorKind,
    sequence: u64,
    output: *[cursor_buffer_bytes]u8,
) []const u8 {
    return std.fmt.bufPrint(output, "v1:{c}:{d}", .{
        if (kind == .audit) @as(u8, 'a') else @as(u8, 's'),
        sequence,
    }) catch unreachable;
}

fn decodeSequenceCursor(kind: SequenceCursorKind, text: []const u8) !u64 {
    const prefix = if (kind == .audit) "v1:a:" else "v1:s:";
    if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidCursor;
    const number = text[prefix.len..];
    if (number.len == 0 or number.len > 20) return error.InvalidCursor;
    const sequence = std.fmt.parseInt(u64, number, 10) catch return error.InvalidCursor;
    if (sequence == 0 or sequence > std.math.maxInt(i64)) return error.InvalidCursor;
    var canonical: [cursor_buffer_bytes]u8 = undefined;
    if (!std.mem.eql(u8, text, encodeSequenceCursor(kind, sequence, &canonical))) {
        return error.InvalidCursor;
    }
    return sequence;
}

fn parseTimestamp(text: []const u8) !i64 {
    if (text.len != api_response.timestamp_text_len or text[4] != '-' or text[7] != '-' or
        text[10] != 'T' or text[13] != ':' or text[16] != ':' or text[19] != 'Z')
    {
        return error.InvalidTimestamp;
    }
    const year = try parseDecimal(u16, text[0..4]);
    const month = try parseDecimal(u8, text[5..7]);
    const day = try parseDecimal(u8, text[8..10]);
    const hour = try parseDecimal(u8, text[11..13]);
    const minute = try parseDecimal(u8, text[14..16]);
    const second = try parseDecimal(u8, text[17..19]);
    if (year < 1970 or month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59) {
        return error.InvalidTimestamp;
    }
    const month_days = [_]u8{ 31, if (isLeapYear(year)) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    if (day < 1 or day > month_days[month - 1]) return error.InvalidTimestamp;
    const days = daysFromCivil(year, month, day);
    const day_seconds = std.math.mul(i64, days, 86_400) catch return error.InvalidTimestamp;
    const seconds = day_seconds + @as(i64, hour) * 3_600 + @as(i64, minute) * 60 + second;
    if (seconds > api_response.maximum_timestamp_seconds) return error.InvalidTimestamp;
    return seconds;
}

fn parseDecimal(comptime T: type, text: []const u8) !T {
    for (text) |byte| if (byte < '0' or byte > '9') return error.InvalidTimestamp;
    return std.fmt.parseInt(T, text, 10) catch return error.InvalidTimestamp;
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

fn daysFromCivil(year_value: u16, month_value: u8, day_value: u8) i64 {
    var year: i64 = year_value;
    const month: i64 = month_value;
    if (month <= 2) year -= 1;
    const era = @divFloor(year, 400);
    const year_of_era = year - era * 400;
    const adjusted_month = month + (if (month > 2) @as(i64, -3) else 9);
    const day_of_year = @divFloor(153 * adjusted_month + 2, 5) + day_value - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) -
        @divFloor(year_of_era, 100) + day_of_year;
    return era * 146_097 + day_of_era - 719_468;
}

fn finishConnectivity(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    check: operations_service.ConnectivityCheck,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeConnectivity(&json, check);
    return api_response.finishBody(
        response,
        allocator,
        status,
        api_response.json_content_type,
        output.written(),
        metadata,
    );
}

fn finishConnectivityPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: operations_service.ConnectivityPage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |item| try writeConnectivity(&json, item);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [cursor_buffer_bytes]u8 = undefined;
        try json.write(encodeCompositeCursor(.connectivity, .{
            .timestamp = cursor.requested_at,
            .id = cursor.before_id,
        }, &cursor_buffer));
    } else try json.write(null);
    try json.endObject();
    return api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn writeConnectivity(json: *std.json.Stringify, check: operations_service.ConnectivityCheck) !void {
    var id_text: [32]u8 = undefined;
    var node_text: [32]u8 = undefined;
    var created_text: [api_response.timestamp_text_len]u8 = undefined;
    var started_text: [api_response.timestamp_text_len]u8 = undefined;
    var completed_text: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(check.id, &id_text));
    try json.objectField("nodeId");
    if (check.node_id) |id| try json.write(api_response.encodeId(id, &node_text)) else try json.write(null);
    try json.objectField("nodeAddress");
    try json.write(check.node_address.slice());
    try json.objectField("status");
    try json.write(@tagName(check.status));
    try json.objectField("timeoutMilliseconds");
    try json.write(check.timeout_milliseconds);
    try json.objectField("roundTripMilliseconds");
    if (check.round_trip_milliseconds) |value| try json.write(value) else try json.write(null);
    try json.objectField("failureCode");
    if (check.failure_code) |*value| try json.write(value.slice()) else try json.write(null);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(check.created_at, &created_text));
    try json.objectField("startedAt");
    if (check.started_at) |value| try json.write(try api_response.formatTimestamp(value, &started_text)) else try json.write(null);
    try json.objectField("completedAt");
    if (check.completed_at) |value| try json.write(try api_response.formatTimestamp(value, &completed_text)) else try json.write(null);
    try json.endObject();
}

fn finishEventPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: operations_service.EventPage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |*item| try writeEvent(&json, item);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [cursor_buffer_bytes]u8 = undefined;
        try json.write(encodeCompositeCursor(.event, .{
            .timestamp = cursor.observed_at,
            .id = cursor.before_id,
        }, &cursor_buffer));
    } else try json.write(null);
    try json.endObject();
    return api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn writeEvent(json: *std.json.Stringify, event: *const operations_service.Event) !void {
    var id_text: [32]u8 = undefined;
    var occurred_text: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(event.id, &id_text));
    try json.objectField("kind");
    try json.write(event.kind.slice());
    try json.objectField("severity");
    try json.write(@tagName(event.severity));
    try json.objectField("resourceType");
    try json.write(event.resource_type.slice());
    try json.objectField("resourceId");
    if (event.resource_id) |*value| try json.write(value.slice()) else try json.write(null);
    try json.objectField("summary");
    try json.write(event.summary());
    try json.objectField("occurredAt");
    try json.write(try api_response.formatTimestamp(event.occurred_at, &occurred_text));
    try json.endObject();
}

fn finishAuditPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: operations_service.AuditPage,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |*item| try writeAudit(&json, item);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [cursor_buffer_bytes]u8 = undefined;
        try json.write(encodeSequenceCursor(.audit, cursor.before_sequence, &cursor_buffer));
    } else try json.write(null);
    try json.endObject();
    return api_response.finishBody(
        response,
        allocator,
        200,
        api_response.json_content_type,
        output.written(),
        metadata,
    );
}

fn writeAudit(json: *std.json.Stringify, entry: *const operations_service.AuditEntry) !void {
    var id_text: [32]u8 = undefined;
    var actor_text: [32]u8 = undefined;
    var request_text: [32]u8 = undefined;
    var occurred_text: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(entry.id, &id_text));
    try json.objectField("actorType");
    try json.write(@tagName(entry.actor_type));
    try json.objectField("actorUserId");
    if (entry.actor_user_id) |id| try json.write(api_response.encodeId(id, &actor_text)) else try json.write(null);
    try json.objectField("actorUsername");
    if (entry.actor_username) |*value| try json.write(value.slice()) else try json.write(null);
    try json.objectField("action");
    try json.write(entry.action.slice());
    try json.objectField("resourceType");
    try json.write(entry.resource_type.slice());
    try json.objectField("resourceId");
    if (entry.resource_id) |*value| try json.write(value.slice()) else try json.write(null);
    try json.objectField("outcome");
    try json.write(@tagName(entry.outcome));
    try json.objectField("requestId");
    if (entry.request_id) |id| try json.write(api_response.encodeId(id, &request_text)) else try json.write(null);
    try json.objectField("userAgent");
    if (entry.user_agent) |*value| try json.write(value.slice()) else try json.write(null);
    try json.objectField("proxyPeer");
    if (entry.proxy_peer) |*value| try json.write(value.slice()) else try json.write(null);
    try json.objectField("occurredAt");
    try json.write(try api_response.formatTimestamp(entry.occurred_at, &occurred_text));
    try json.endObject();
}

fn finishPruneResult(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    result: operations_service.PruneResult,
) !void {
    var export_text: [32]u8 = undefined;
    var through_text: [32]u8 = undefined;
    var pruned_text: [api_response.timestamp_text_len]u8 = undefined;
    return api_response.finishJson(response, allocator, 200, .{
        .exportId = api_response.encodeId(result.export_id, &export_text),
        .throughAuditId = api_response.encodeId(result.through_audit_id, &through_text),
        .prunedEntries = result.pruned_entries,
        .prunedAt = try api_response.formatTimestamp(result.pruned_at, &pruned_text),
    }, .{ .etag = result.etag.slice() });
}

fn finishSettingsState(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    state: operations_service.SettingsState,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("desired");
    try writeSettingsRevision(&json, state.desired);
    try json.objectField("effective");
    try writeSettingsRevision(&json, state.effective);
    try json.objectField("pendingRestart");
    try json.write(state.pending_restart);
    try json.endObject();
    return api_response.finishBody(
        response,
        allocator,
        200,
        api_response.json_content_type,
        output.written(),
        metadata,
    );
}

fn finishSettingsPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: operations_service.SettingsPage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |item| try writeSettingsRevision(&json, item);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [cursor_buffer_bytes]u8 = undefined;
        try json.write(encodeSequenceCursor(.settings, cursor.before_sequence, &cursor_buffer));
    } else try json.write(null);
    try json.endObject();
    return api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn finishSettingsRevisionCreated(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    revision: operations_service.SettingsRevision,
    etag: operations_service.StrongEtag,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeSettingsRevision(&json, revision);
    var id_text: [32]u8 = undefined;
    var location_buffer: [112]u8 = undefined;
    const location = try std.fmt.bufPrint(
        &location_buffer,
        "/api/v1/settings/revisions/{s}",
        .{api_response.encodeId(revision.id, &id_text)},
    );
    return api_response.finishBody(response, allocator, 202, api_response.json_content_type, output.written(), .{
        .etag = etag.slice(),
        .location = location,
    });
}

fn writeSettingsRevision(
    json: *std.json.Stringify,
    revision: operations_service.SettingsRevision,
) !void {
    var id_text: [32]u8 = undefined;
    var actor_text: [32]u8 = undefined;
    var created_text: [api_response.timestamp_text_len]u8 = undefined;
    var applied_text: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(revision.id, &id_text));
    try json.objectField("sequence");
    try json.write(revision.sequence);
    try json.objectField("status");
    try json.write(@tagName(revision.status));
    try json.objectField("settings");
    try writeSettings(json, revision.values);
    try json.objectField("createdByUserId");
    if (revision.created_by_user_id) |id| try json.write(api_response.encodeId(id, &actor_text)) else try json.write(null);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(revision.created_at, &created_text));
    try json.objectField("appliedAt");
    if (revision.applied_at) |value| try json.write(try api_response.formatTimestamp(value, &applied_text)) else try json.write(null);
    try json.objectField("failureCode");
    if (revision.failure_code) |*value| try json.write(value.slice()) else try json.write(null);
    try json.endObject();
}

fn writeSettings(json: *std.json.Stringify, settings: operations_service.OperationalSettings) !void {
    try json.beginObject();
    try json.objectField("innerMtu");
    try json.write(settings.inner_mtu);
    try json.objectField("heartbeatIntervalSeconds");
    try json.write(settings.heartbeat_idle_seconds);
    try json.objectField("suspectAfterSeconds");
    try json.write(settings.suspect_after_seconds);
    try json.objectField("offlineAfterSeconds");
    try json.write(settings.offline_after_seconds);
    try json.objectField("defaultEnrollmentLifetimeSeconds");
    try json.write(settings.default_enrollment_lifetime_seconds);
    try json.objectField("trafficColdAfterSeconds");
    try json.write(settings.traffic_cold_after_seconds);
    try json.objectField("trafficHotPacketsPerSecond");
    try json.write(settings.traffic_hot_packets_per_second);
    try json.objectField("trafficHotBitsPerSecond");
    try json.write(settings.traffic_hot_bits_per_second);
    try json.objectField("trafficSaturatedQueuePercent");
    try json.write(settings.traffic_saturated_queue_percent);
    try json.objectField("trafficHysteresisSeconds");
    try json.write(settings.traffic_hysteresis_seconds);
    try json.objectField("runtimeEventRetentionDays");
    try json.write(settings.runtime_event_retention_days);
    try json.objectField("connectivityRetentionDays");
    try json.write(settings.connectivity_result_retention_days);
    try json.objectField("maximumNodes");
    try json.write(settings.maximum_nodes);
    try json.endObject();
}

fn finishControlDecision(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    decision: operations_service.ControlDecision,
) !void {
    var id_text: [32]u8 = undefined;
    var accepted_text: [api_response.timestamp_text_len]u8 = undefined;
    return api_response.finishJson(response, allocator, 202, .{
        .id = api_response.encodeId(decision.id, &id_text),
        .kind = @tagName(decision.kind),
        .acceptedAt = try api_response.formatTimestamp(decision.accepted_at, &accepted_text),
    }, .{});
}

const ExportStream = struct {
    allocator: std.mem.Allocator,
    response: *service_server.ResponseSink,
    buffer: std.ArrayList(u8) = .empty,
    export_id: ?[16]u8 = null,
    through_audit_id: ?[16]u8 = null,
    metadata_sent: bool = false,

    fn init(allocator: std.mem.Allocator, response: *service_server.ResponseSink) ExportStream {
        return .{ .allocator = allocator, .response = response };
    }

    fn deinit(self: *ExportStream) void {
        std.crypto.secureZero(u8, self.buffer.items);
        self.buffer.deinit(self.allocator);
        self.* = undefined;
    }

    fn writer(self: *ExportStream) operations_service.ExportWriter {
        return .{
            .context = self,
            .begin_fn = beginOpaque,
            .write_fn = writeOpaque,
            .flush_fn = flushOpaque,
        };
    }

    fn beginOpaque(raw: *anyopaque, export_id: [16]u8, through_audit_id: [16]u8) !void {
        const self: *ExportStream = @ptrCast(@alignCast(raw));
        if (self.export_id != null) return error.ExportAlreadyBegun;
        self.export_id = export_id;
        self.through_audit_id = through_audit_id;
    }

    fn writeOpaque(raw: *anyopaque, bytes: []const u8) !void {
        const self: *ExportStream = @ptrCast(@alignCast(raw));
        if (self.export_id == null) return error.ExportNotBegun;
        if (bytes.len > export_chunk_bytes) {
            return error.ExportChunkTooLarge;
        }
        if (self.buffer.items.len + bytes.len > export_chunk_bytes) try self.flush();
        try self.buffer.appendSlice(self.allocator, bytes);
    }

    fn flushOpaque(raw: *anyopaque) !void {
        const self: *ExportStream = @ptrCast(@alignCast(raw));
        return self.flush();
    }

    fn flush(self: *ExportStream) !void {
        if (self.export_id == null) return error.ExportNotBegun;
        if (self.buffer.items.len == 0) {
            if (!self.metadata_sent) try self.sendChunk("");
            return;
        }
        try self.sendChunk(self.buffer.items);
        std.crypto.secureZero(u8, self.buffer.items);
        self.buffer.clearRetainingCapacity();
    }

    fn sendChunk(self: *ExportStream, bytes: []const u8) !void {
        var object: std.json.ObjectMap = .empty;
        defer object.deinit(self.allocator);
        if (!self.metadata_sent) {
            var export_text: [32]u8 = undefined;
            var filename_buffer: [96]u8 = undefined;
            const id = api_response.encodeId(self.export_id.?, &export_text);
            const disposition = try std.fmt.bufPrint(
                &filename_buffer,
                "attachment; filename=\"ntip-audit-{s}.ndjson\"",
                .{id},
            );
            try object.put(self.allocator, "status", .{ .integer = 200 });
            try object.put(self.allocator, "contentType", .{ .string = "application/x-ndjson" });
            // These private metadata fields are serialized by ntip-api as
            // Content-Disposition and X-NTIP-Audit-Export-ID respectively.
            try object.put(self.allocator, "contentDisposition", .{ .string = disposition });
            try object.put(self.allocator, "auditExportId", .{ .string = id });
            self.metadata_sent = true;
        }
        if (bytes.len != 0) try object.put(self.allocator, "bodyChunk", .{ .string = bytes });
        try self.response.send(.{ .object = object }, false);
    }
};

test "operations cursors are typed, lowercase, and round trip" {
    const id = [_]u8{0xab} ** 16;
    var buffer: [cursor_buffer_bytes]u8 = undefined;
    const composite_text = encodeCompositeCursor(.event, .{ .timestamp = 1_625_159_473, .id = id }, &buffer);
    const composite = try decodeCompositeCursor(.event, composite_text);
    try std.testing.expectEqual(@as(i64, 1_625_159_473), composite.timestamp);
    try std.testing.expectEqualSlices(u8, &id, &composite.id);
    try std.testing.expectError(error.InvalidCursor, decodeCompositeCursor(.connectivity, composite_text));

    const sequence_text = encodeSequenceCursor(.audit, 42, &buffer);
    try std.testing.expectEqual(@as(u64, 42), try decodeSequenceCursor(.audit, sequence_text));
    try std.testing.expectError(error.InvalidCursor, decodeSequenceCursor(.settings, sequence_text));
    try std.testing.expectError(
        error.InvalidCursor,
        decodeCompositeCursor(.event, "v1:e:01625159473:abababababababababababababababab"),
    );
    try std.testing.expectError(error.InvalidCursor, decodeSequenceCursor(.audit, "v1:a:042"));
}

test "operations queries reject unknown and duplicate parameters" {
    var scratch: [http.maximum_target_bytes]u8 = undefined;
    const query = try parseQuery(
        "nodeId=abababababababababababababababab&status=queued&limit=50",
        .connectivity,
        &scratch,
    );
    try std.testing.expectEqualStrings("queued", query.status.?);
    try std.testing.expectError(error.InvalidQuery, parseQuery("limit=50&limit=51", .events, &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("scope=all", .audit, &scratch));
    try std.testing.expectError(
        error.InvalidQuery,
        parseQuery("resourceType=node%20record", .audit, &scratch),
    );
}

test "operations queries accept URLSearchParams cursors and timestamps" {
    var scratch: [http.maximum_target_bytes]u8 = undefined;
    const query = try parseQuery(
        "cursor=v1%3Ae%3A1625159473%3Aabababababababababababababababab&" ++
            "since=2021-07-01T17%3A11%3A13Z",
        .events,
        &scratch,
    );
    const cursor = try decodeCompositeCursor(.event, query.cursor.?);
    try std.testing.expectEqual(@as(i64, 1_625_159_473), cursor.timestamp);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xab} ** 16), &cursor.id);
    try std.testing.expectEqual(@as(i64, 1_625_159_473), try parseTimestamp(query.since.?));
}

test "canonical UTC parser validates leap days and exact normalization" {
    try std.testing.expectEqual(@as(i64, 0), try parseTimestamp("1970-01-01T00:00:00Z"));
    try std.testing.expectEqual(@as(i64, 1_625_159_473), try parseTimestamp("2021-07-01T17:11:13Z"));
    _ = try parseTimestamp("2000-02-29T23:59:59Z");
    try std.testing.expectError(error.InvalidTimestamp, parseTimestamp("2100-02-29T00:00:00Z"));
    try std.testing.expectError(error.InvalidTimestamp, parseTimestamp("2021-07-01T17:11:13+00:00"));
}

test "audit export leaves the terminal frame for durable idempotency completion" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var response = try service_server.ResponseSink.init(
        std.testing.allocator,
        &output.writer,
        "0123456789abcdef0123456789abcdef",
    );
    var export_stream = ExportStream.init(std.testing.allocator, &response);
    defer export_stream.deinit();
    const export_id = [_]u8{0xaa} ** 16;
    const through_id = [_]u8{0xbb} ** 16;
    const sink = export_stream.writer();
    try sink.begin(export_id, through_id);
    var oversized = [_]u8{'x'} ** (export_chunk_bytes + 1);
    try std.testing.expectError(error.ExportChunkTooLarge, sink.write(&oversized));
    try sink.write("{\"sequence\":1}\n");
    try sink.flush();

    try std.testing.expectEqual(@as(u32, 1), response.frame_count);
    try std.testing.expect(!response.terminal);
    var terminal: std.json.ObjectMap = .empty;
    defer terminal.deinit(std.testing.allocator);
    try response.finish(.{ .object = terminal });
    try std.testing.expect(response.terminal);
}
