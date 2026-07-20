//! Authoritative management API dispatcher owned by `ntsrv`.
//!
//! The loopback HTTP process is deliberately DB-free. Every forwarded request
//! is decoded again here, authenticated against hash-only SQLite sessions, and
//! converted to the bounded private HTTP-response frame convention.

const std = @import("std");
const api_request = @import("api_request.zig");
const api_response = @import("api_response.zig");
const http = @import("http.zig");
const auth = @import("auth.zig");
const auth_application = @import("auth_application.zig");
const enrollment_service = @import("enrollment_service.zig");
const inventory_service = @import("inventory_service.zig");
const operations_api = @import("operations_api.zig");
const operations_service = @import("operations_service.zig");
const read_models_service = @import("read_models_service.zig");
const service_ipc = @import("service_ipc.zig");
const service_server = @import("service_server.zig");
const access_repository = @import("../state/access_repository.zig");
const idempotency_repository = @import("../state/idempotency_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const model = @import("../domain/model.zig");

const idempotency_retention_seconds: i64 = 24 * 60 * 60;

const IdempotencyMutationHook = struct {
    repository: idempotency_repository.Repository,
    input: idempotency_repository.MutationCommitInput,

    fn hook(self: *IdempotencyMutationHook) sqlite.CommitHook {
        return .{ .context = self, .before_commit_fn = beforeCommit };
    }

    fn beforeCommit(raw: *anyopaque, db: *sqlite.Database) !void {
        const self: *IdempotencyMutationHook = @ptrCast(@alignCast(raw));
        if (self.repository.db != db) return error.IdempotencyDatabaseMismatch;
        try self.repository.markMutationCommitted(self.input);
    }
};

pub const Application = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    authentication: *auth_application.Application,
    inventory: *inventory_service.Service,
    enrollment: ?*enrollment_service.Service = null,
    read_models: ?*read_models_service.Service = null,
    operations: *operations_service.Service,
    idempotency: idempotency_repository.Repository,
    idempotency_request_hash_key: *const idempotency_repository.RequestHashKey,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        authentication: *auth_application.Application,
        inventory: *inventory_service.Service,
        operations: *operations_service.Service,
        idempotency: idempotency_repository.Repository,
        idempotency_request_hash_key: *const idempotency_repository.RequestHashKey,
    ) Application {
        return .{
            .allocator = allocator,
            .io = io,
            .authentication = authentication,
            .inventory = inventory,
            .operations = operations,
            .idempotency = idempotency,
            .idempotency_request_hash_key = idempotency_request_hash_key,
        };
    }

    pub fn handler(self: *Application) service_server.Handler {
        return service_server.adaptHandler(Application, self, handle);
    }

    pub fn setEnrollmentService(self: *Application, enrollment: *enrollment_service.Service) void {
        self.enrollment = enrollment;
    }

    pub fn setReadModelsService(self: *Application, read_models: *read_models_service.Service) void {
        self.read_models = read_models;
    }

    fn handle(
        self: *Application,
        _: service_server.PeerCredentials,
        request: service_ipc.Request,
        request_allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        self.handleRequest(request, request_allocator, response) catch |failure| {
            if (response.terminal or response.poisoned) return failure;
            const public = publicError(failure);
            try api_response.fail(response, public.code, public.message, public.retryable);
        };
    }

    fn handleRequest(
        self: *Application,
        request: service_ipc.Request,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const forwarded = try api_request.decode(request.payload);
        if (forwarded.method == .POST and request.preconditions.idempotency_key != null) {
            return self.dispatchIdempotent(request, forwarded, allocator, response);
        }
        return self.dispatch(request, allocator, response);
    }

    fn executeMapped(
        self: *Application,
        request: service_ipc.Request,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        self.dispatch(request, allocator, response) catch |failure| {
            if (response.terminal or response.poisoned) return failure;
            const public = publicError(failure);
            try api_response.fail(response, public.code, public.message, public.retryable);
        };
    }

    fn dispatchIdempotent(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const raw_key = request.preconditions.idempotency_key.?;
        const now = try wallSeconds(self.io);
        const canonical = try canonicalIdempotencyRequest(
            allocator,
            request.operation,
            forwarded,
            request.preconditions.etag,
        );
        defer {
            std.crypto.secureZero(u8, canonical);
            allocator.free(canonical);
        }
        const request_hash = try idempotency_repository.requestHash(
            self.idempotency_request_hash_key,
            raw_key,
            request.operation,
            canonical,
        );
        const actor_id = try idempotencyActor(forwarded, request.operation, allocator);

        if (!std.mem.eql(u8, request.operation, "auth.login")) {
            const token = forwarded.session_token orelse return error.SessionNotFound;
            // A completed idempotency row is not an authorization capability.
            // Revoked and expired sessions must fail before lookup so their
            // former token cannot retrieve mutation responses for the 24-hour
            // replay-retention window.
            var preauthenticated = try self.authentication.authenticate(token, now);
            preauthenticated.clear();
        }

        var reservation = try self.idempotency.reserve(allocator, .{
            .actor_id = actor_id,
            .raw_key = raw_key,
            .request_hash = request_hash,
            .now = now,
            .expires_at = std.math.add(i64, now, idempotency_retention_seconds) catch
                return error.InvalidTimestamp,
        });
        defer reservation.deinit(allocator);
        switch (reservation) {
            .replay => |replay| return finishIdempotencyReplay(
                response,
                allocator,
                request.operation,
                replay,
            ),
            .in_progress => return error.IdempotencyInProgress,
            .committed_without_response => return error.IdempotencyResultUnavailable,
            .reserved => {},
        }

        var mutation_hook: IdempotencyMutationHook = .{
            .repository = self.idempotency,
            .input = .{
                .actor_id = actor_id,
                .raw_key = raw_key,
                .request_hash = request_hash,
                .now = now,
            },
        };
        self.idempotency.db.installCommitHook(mutation_hook.hook()) catch |failure| {
            try self.idempotency.cancel(actor_id, raw_key, request_hash);
            return failure;
        };
        defer self.idempotency.db.clearCommitHook();
        var reservation_active = true;
        defer if (reservation_active and !self.idempotency.db.commitHookCompleted()) {
            // This predicate can remove only the exact still-reserved row. If
            // the audited mutation committed, its atomic consumed marker is
            // retained even when exact response completion later fails. This
            // defer runs before the hook is cleared, so the completion state
            // remains observable here.
            self.idempotency.cancel(actor_id, raw_key, request_hash) catch {};
        };

        if (std.mem.eql(u8, request.operation, "operations.audit.export")) {
            return self.dispatchIdempotentAuditExport(
                request,
                allocator,
                response,
                actor_id,
                raw_key,
                request_hash,
                now,
            );
        }

        const control_kind = controlOperationKind(request.operation);
        const control_checkpoint = if (control_kind != null)
            self.operations.controlStageCheckpoint()
        else
            null;
        var staged_control: ?operations_service.ControlDecision = null;
        defer {
            const owned = staged_control orelse if (control_kind) |kind|
                self.operations.stagedControlSince(control_checkpoint.?, kind)
            else
                null;
            if (owned) |decision| {
                // Never clear a pre-existing or subsequently staged decision:
                // the exact random decision ID is the rollback capability.
                _ = self.operations.discardStagedControl(decision.id);
            }
        }

        var captured: std.Io.Writer.Allocating = .init(allocator);
        defer {
            std.crypto.secureZero(u8, captured.written());
            captured.deinit();
        }
        var capture_sink = try service_server.ResponseSink.init(
            allocator,
            &captured.writer,
            request.request_id,
        );
        try self.executeMapped(request, allocator, &capture_sink);
        const summary = try inspectCapturedResponse(allocator, captured.written());
        defer if (summary.replay_payload) |payload| {
            std.crypto.secureZero(u8, payload);
            allocator.free(payload);
        };
        staged_control = if (control_kind) |kind|
            self.operations.stagedControlSince(control_checkpoint.?, kind)
        else
            null;

        if (summary.failed) {
            if (self.idempotency.db.commitHookCompleted()) {
                _ = try self.idempotency.commit(.{
                    .actor_id = actor_id,
                    .raw_key = raw_key,
                    .request_hash = request_hash,
                    .status = summary.status,
                    .response_body = summary.replay_payload orelse
                        return error.IdempotencyResponseNotReplayable,
                    .now = now,
                });
                reservation_active = false;
            } else {
                try self.idempotency.cancel(actor_id, raw_key, request_hash);
                reservation_active = false;
            }
            return forwardCapturedResponse(allocator, captured.written(), response);
        }
        if (!self.idempotency.db.commitHookCompleted()) {
            return error.IdempotencyMutationNotCommitted;
        }
        if (control_kind != null and staged_control == null) {
            return error.ControlDecisionNotStaged;
        }
        if (staged_control != null and summary.status != 202) {
            return error.InvalidCapturedResponse;
        }

        const stored_payload = if (nonReplayableOperation(request.operation))
            "{\"oneTimeResponse\":true}"
        else
            summary.replay_payload orelse return error.IdempotencyResponseNotReplayable;
        _ = try self.idempotency.commit(.{
            .actor_id = actor_id,
            .raw_key = raw_key,
            .request_hash = request_hash,
            .status = summary.status,
            .response_body = stored_payload,
            .now = now,
        });
        reservation_active = false;
        if (staged_control) |decision| {
            // The serialized runtime loop cannot observe this arm until
            // service response handling returns. Arm immediately after the
            // durable completion marker so a peer disconnect during the
            // following write still executes the accepted operation exactly
            // once; a successful path remains audit -> marker -> flush -> exit.
            try self.operations.armStagedControl(decision.id);
            staged_control = null;
        }
        try forwardCapturedResponse(allocator, captured.written(), response);
    }

    fn dispatchIdempotentAuditExport(
        self: *Application,
        request: service_ipc.Request,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
        actor_id: idempotency_repository.ActorId,
        raw_key: []const u8,
        request_hash: idempotency_repository.Digest,
        now: i64,
    ) !void {
        self.dispatch(request, allocator, response) catch |failure| {
            // A partial export is deliberately retryable. If private frames
            // already crossed the socket, ntip-api closes the public chunked
            // response after observing this terminal failure.
            if (!self.idempotency.db.commitHookCompleted()) {
                try self.idempotency.cancel(actor_id, raw_key, request_hash);
            }
            if (response.terminal or response.poisoned) return failure;
            const public = operations_service.failureForError(failure);
            try response.fail(public.code, public.message, public.retryable);
            return;
        };
        if (response.poisoned or response.frame_count == 0) {
            return error.InvalidCapturedResponse;
        }
        if (response.terminal) {
            // A precondition can terminate before export headers begin. It is
            // not a replayable body and did not commit a mutation, so release
            // the reservation while preserving the already-framed 412.
            if (!self.idempotency.db.commitHookCompleted()) {
                try self.idempotency.cancel(actor_id, raw_key, request_hash);
            }
            return;
        }
        if (!self.idempotency.db.commitHookCompleted()) {
            return error.IdempotencyMutationNotCommitted;
        }

        // Audit exports are not replay bodies. Store only a durable consumed
        // marker after the authoritative export completed and its receipt was
        // committed. The NDJSON bytes never enter the idempotency table.
        _ = self.idempotency.commit(.{
            .actor_id = actor_id,
            .raw_key = raw_key,
            .request_hash = request_hash,
            .status = 200,
            .response_body = "{\"oneTimeResponse\":true}",
            .now = now,
        }) catch {
            // The receipt transaction already committed the consumed marker.
            // Never delete it merely because attaching the exact terminal
            // response failed; a retry must not create a second export.
            try response.fail(.internal_error, "internal service error", false);
            return;
        };

        var terminal: std.json.ObjectMap = .empty;
        defer terminal.deinit(allocator);
        try response.finish(.{ .object = terminal });
    }

    fn dispatch(
        self: *Application,
        request: service_ipc.Request,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const forwarded = try api_request.decode(request.payload);
        const request_id = try api_response.decodeId(request.request_id);
        const now = try wallSeconds(self.io);

        if (std.mem.eql(u8, request.operation, "health.ready")) {
            try requireTarget(forwarded, .GET, "/api/v1/health/ready");
            return api_response.finishJson(response, allocator, 200, .{
                .status = "ready",
                .ntsrv = "ready",
                .databaseSchemaVersion = @as(u32, 1),
            }, .{});
        }
        if (std.mem.eql(u8, request.operation, "auth.login")) {
            try requireTarget(forwarded, .POST, "/api/v1/auth/login");
            try requireIdempotency(request.preconditions);
            return self.login(forwarded, request_id, now, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "auth.me")) {
            try requireTarget(forwarded, .GET, "/api/v1/auth/me");
            return self.me(forwarded, now, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "auth.reauthenticate")) {
            try requireTarget(forwarded, .POST, "/api/v1/auth/reauth");
            try requireIdempotency(request.preconditions);
            return self.reauthenticate(forwarded, request_id, now, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "auth.password.change")) {
            try requireTarget(forwarded, .POST, "/api/v1/auth/change-password");
            try requireIdempotency(request.preconditions);
            return self.changePassword(forwarded, request_id, now, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "auth.logout")) {
            try requireTarget(forwarded, .POST, "/api/v1/auth/logout");
            try requireIdempotency(request.preconditions);
            return self.logout(forwarded, request_id, now, allocator, response);
        }
        if (std.mem.eql(u8, request.operation, "overview.read") or
            std.mem.eql(u8, request.operation, "topology.read") or
            std.mem.eql(u8, request.operation, "runtime.nodes.list"))
        {
            return self.readModelOperation(request, forwarded, now, allocator, response);
        }
        if (std.mem.startsWith(u8, request.operation, "inventory.")) {
            return self.inventoryOperation(request, forwarded, request_id, now, allocator, response);
        }
        if (std.mem.startsWith(u8, request.operation, "enrollment.")) {
            return self.enrollmentOperation(request, forwarded, request_id, now, allocator, response);
        }
        if (std.mem.startsWith(u8, request.operation, "diagnostics.") or
            std.mem.startsWith(u8, request.operation, "operations.") or
            std.mem.startsWith(u8, request.operation, "settings.") or
            std.mem.startsWith(u8, request.operation, "service."))
        {
            return self.operationsOperation(request, forwarded, now, allocator, response);
        }
        if (std.mem.startsWith(u8, request.operation, "security.")) {
            return self.securityOperation(request, forwarded, request_id, now, allocator, response);
        }
        return error.OperationUnavailable;
    }

    fn readModelOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const service = self.read_models orelse return error.OperationUnavailable;
        const token = forwarded.session_token orelse return error.SessionNotFound;
        var authenticated = try self.authentication.authenticate(token, now);
        defer authenticated.clear();
        if (authenticated.session.password_change_required) return error.PasswordChangeRequired;
        const principal: read_models_service.Principal = .{
            .id = authenticated.session.user_id,
            .role = authenticated.session.role,
        };

        if (std.mem.eql(u8, request.operation, "overview.read")) {
            try requireTarget(forwarded, .GET, "/api/v1/overview");
            if (forwarded.query().len != 0 or forwarded.body != null) return error.InvalidTarget;
            const result = try service.getOverview(principal, now);
            const control_etag = try self.operations.controlEtag(.{
                .user_id = authenticated.session.user_id,
                .session_id = authenticated.session.id,
                .role = authenticated.session.role,
            });
            return finishOverview(response, allocator, result, control_etag);
        }
        if (std.mem.eql(u8, request.operation, "topology.read")) {
            try requireTarget(forwarded, .GET, "/api/v1/topology");
            if (forwarded.query().len != 0 or forwarded.body != null) return error.InvalidTarget;
            var result = try service.getTopology(principal, now);
            defer result.deinit(service.allocator);
            return finishTopology(response, allocator, result);
        }
        if (std.mem.eql(u8, request.operation, "runtime.nodes.list")) {
            try requireTargetPath(forwarded, .GET, "/api/v1/runtime/nodes");
            if (forwarded.body != null) return error.InvalidRequestBody;
            var query_scratch: [http.maximum_target_bytes]u8 = undefined;
            const query = try api_request.parseQuery(forwarded.query(), &query_scratch);
            if (queryHasInventoryFields(query) or query.scope != null or query.status != null or
                query.severity != null or query.since != null or query.actor_user_id != null or
                query.resource_type != null)
            {
                return error.InvalidQuery;
            }
            const cursor = if (query.cursor) |value|
                try read_models_service.decodeRuntimeCursor(value)
            else
                null;
            const liveness: ?read_models_service.LivenessState = if (query.liveness) |value|
                parseLiveness(value) orelse return error.InvalidLivenessState
            else
                null;
            var page = try service.listRuntimeNodes(
                principal,
                cursor,
                query.limit,
                .{ .liveness = liveness },
                now,
            );
            defer page.deinit(service.allocator);
            return finishRuntimePage(response, allocator, page);
        }
        return error.OperationUnavailable;
    }

    fn enrollmentOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const service = self.enrollment orelse return error.OperationUnavailable;
        const token = forwarded.session_token orelse return error.SessionNotFound;
        var authenticated = try self.authentication.authenticateMutation(token, forwarded.csrf_token, now);
        defer authenticated.clear();
        if (authenticated.session.password_change_required) return error.PasswordChangeRequired;

        const principal: enrollment_service.Principal = .{
            .user_id = authenticated.session.user_id,
            .session_id = authenticated.session.id,
            .role = authenticated.session.role,
            .reauthenticated_at = authenticated.session.reauthenticated_at,
            .user_agent = forwarded.user_agent,
            .proxy_peer = "loopback",
        };
        const inventory_principal: inventory_service.Principal = .{
            .id = authenticated.session.user_id,
            .role = authenticated.session.role,
        };
        const context: enrollment_service.RequestContext = .{
            .request_id = request_id,
            .occurred_at = now,
            .preconditions = request.preconditions,
        };

        if (std.mem.eql(u8, request.operation, "enrollment.credential.issue")) {
            if (forwarded.method != .POST or forwarded.query().len != 0) return error.InvalidTarget;
            const id_text = try api_request.pathParameter(
                forwarded.target,
                "/api/v1/nodes/",
                "/enrollment-credentials",
            );
            const Body = struct {
                expiresInSeconds: u64,
                confirmation: []const u8,
            };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const node_id = model.NodeId.parse(id_text) catch return error.InvalidIdentifier;
            var issued = service.issueCredential(
                principal,
                context,
                node_id,
                body.value.expiresInSeconds,
            ) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current = try self.inventory.getNode(inventory_principal, node_id);
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            defer issued.clear();
            return api_response.finishBody(
                response,
                allocator,
                200,
                "application/vnd.ntip.enrollment-credential",
                issued.slice(),
                .{ .content_disposition = "attachment; filename=\"ntip-enrollment-credential.txt\"" },
            );
        }

        if (std.mem.eql(u8, request.operation, "enrollment.reset")) {
            if (forwarded.method != .POST or forwarded.query().len != 0) return error.InvalidTarget;
            const id_text = try api_request.pathParameter(
                forwarded.target,
                "/api/v1/nodes/",
                "/actions/reset-enrollment",
            );
            const Body = struct { confirmation: []const u8 };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const node_id = model.NodeId.parse(id_text) catch return error.InvalidIdentifier;
            const record = service.resetEnrollment(
                principal,
                context,
                node_id,
            ) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current = try self.inventory.getNode(inventory_principal, node_id);
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return self.finishNodeDetail(response, allocator, inventory_principal, record, now);
        }
        return error.OperationUnavailable;
    }

    fn operationsOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const token = forwarded.session_token orelse return error.SessionNotFound;
        var authenticated = if (forwarded.method == .GET)
            try self.authentication.authenticate(token, now)
        else
            try self.authentication.authenticateMutation(token, forwarded.csrf_token, now);
        defer authenticated.clear();
        if (authenticated.session.password_change_required) return error.PasswordChangeRequired;
        const principal: operations_service.Principal = .{
            .user_id = authenticated.session.user_id,
            .session_id = authenticated.session.id,
            .role = authenticated.session.role,
        };
        var adapter = operations_api.Adapter.init(self.operations);
        if (std.mem.eql(u8, request.operation, "operations.audit.export")) {
            adapter.handle(request, forwarded, authenticated.session, allocator, response) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current_etag = (try currentOperationsEtag(
                    self.operations,
                    principal,
                    request.operation,
                )) orelse return failure;
                return failPrecondition(response, current_etag.slice());
            };
            return;
        }
        adapter.handle(request, forwarded, authenticated.session, allocator, response) catch |failure| {
            if (failure == error.PreconditionFailed) {
                const current_etag = (try currentOperationsEtag(
                    self.operations,
                    principal,
                    request.operation,
                )) orelse return failure;
                return failPrecondition(response, current_etag.slice());
            }
            const public = operations_service.failureForError(failure);
            return response.fail(public.code, public.message, public.retryable);
        };
    }

    fn login(
        self: *Application,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (forwarded.session_token != null or forwarded.csrf_token != null) {
            return error.InvalidRequest;
        }
        const LoginBody = struct {
            username: []const u8,
            password: []const u8,
        };
        const parsed = try api_request.decodeBody(LoginBody, allocator, forwarded.body);
        defer parsed.deinit();
        var issued = self.authentication.login(.{
            .username = parsed.value.username,
            .password = parsed.value.password,
            .now = now,
            .audit = authAuditMetadata(forwarded, request_id),
        }) catch |failure| {
            if (failure == error.LoginThrottled) {
                const retry_after = try self.authentication.loginRetryAfter(parsed.value.username, now);
                const public = publicError(failure);
                return api_response.failWithMetadata(
                    response,
                    public.code,
                    public.message,
                    public.retryable,
                    .{ .retry_after_seconds = boundedRetryAfter(retry_after) },
                );
            }
            return failure;
        };
        defer issued.clear();
        const user = try self.authentication.repository.loadUser(issued.session.user_id);
        var cookie_buffer: [auth_application.session_cookie_buffer_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &cookie_buffer);
        const cookie = auth_application.writeSessionCookie(issued.token, &cookie_buffer);
        try finishAuthContext(
            response,
            allocator,
            user,
            issued.session,
            issued.csrf_token,
            if (forwarded.user_agent) |value| if (value.len == 0) null else value else null,
            .{ .set_cookie = cookie },
        );
    }

    fn me(
        self: *Application,
        forwarded: api_request.Forwarded,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const token = forwarded.session_token orelse return error.SessionNotFound;
        var authenticated = try self.authentication.authenticate(token, now);
        defer authenticated.clear();
        const user = try self.authentication.repository.loadUser(authenticated.session.user_id);
        var view = try self.authentication.repository.loadSessionView(
            allocator,
            authenticated.session.id,
            authenticated.session.id,
            now,
        );
        defer view.deinit(allocator);
        try finishAuthContext(
            response,
            allocator,
            user,
            authenticated.session,
            authenticated.csrf_token,
            view.user_agent,
            .{},
        );
    }

    fn reauthenticate(
        self: *Application,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const token = forwarded.session_token orelse return error.SessionNotFound;
        const Body = struct { password: []const u8 };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        const session = try self.authentication.reauthenticate(
            token,
            forwarded.csrf_token,
            parsed.value.password,
            now,
            authAuditMetadata(forwarded, request_id),
        );
        const valid_until = std.math.add(i64, session.reauthenticated_at.?, auth.reauthentication_window_seconds) catch
            return error.InvalidTimestamp;
        var timestamp_buffer: [api_response.timestamp_text_len]u8 = undefined;
        try api_response.finishJson(response, allocator, 200, .{
            .validUntil = try api_response.formatTimestamp(valid_until, &timestamp_buffer),
        }, .{});
    }

    fn changePassword(
        self: *Application,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const token = forwarded.session_token orelse return error.SessionNotFound;
        const Body = struct {
            currentPassword: []const u8,
            newPassword: []const u8,
        };
        const parsed = try api_request.decodeBody(Body, allocator, forwarded.body);
        defer parsed.deinit();
        _ = try self.authentication.changePassword(
            token,
            forwarded.csrf_token,
            parsed.value.currentPassword,
            parsed.value.newPassword,
            now,
            authAuditMetadata(forwarded, request_id),
        );
        try api_response.finishNoContent(response, allocator, .{});
    }

    fn logout(
        self: *Application,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (forwarded.body != null) return error.InvalidRequestBody;
        const token = forwarded.session_token orelse return error.SessionNotFound;
        try self.authentication.logout(
            token,
            forwarded.csrf_token,
            now,
            authAuditMetadata(forwarded, request_id),
        );
        try api_response.finishNoContent(response, allocator, .{
            .set_cookie = auth_application.clearing_session_cookie,
        });
    }

    fn securityOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const token = forwarded.session_token orelse return error.SessionNotFound;
        var authenticated = if (forwarded.method == .GET)
            try self.authentication.authenticate(token, now)
        else
            try self.authentication.authenticateMutation(token, forwarded.csrf_token, now);
        defer authenticated.clear();
        if (authenticated.session.password_change_required) return error.PasswordChangeRequired;

        if (std.mem.startsWith(u8, request.operation, "security.user")) {
            return self.userOperation(
                request,
                forwarded,
                authenticated.session,
                request_id,
                now,
                allocator,
                response,
            );
        }
        if (std.mem.startsWith(u8, request.operation, "security.session")) {
            return self.sessionOperation(
                request,
                forwarded,
                authenticated.session,
                request_id,
                now,
                allocator,
                response,
            );
        }
        return error.OperationUnavailable;
    }

    fn userOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        session: access_repository.Session,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try auth_application.Application.authorize(session, .manage_users);

        if (std.mem.eql(u8, request.operation, "security.users.list")) {
            try requireTargetPath(forwarded, .GET, "/api/v1/users");
            if (forwarded.body != null) return error.InvalidRequestBody;
            var query_scratch: [http.maximum_target_bytes]u8 = undefined;
            const query = try api_request.parseQuery(forwarded.query(), &query_scratch);
            if (queryHasInventoryFields(query) or queryHasOperationsFields(query) or
                query.scope != null)
            {
                return error.InvalidQuery;
            }
            const cursor = if (query.cursor) |value| try decodeAccessCursor(.user, value) else null;
            var page = try self.authentication.repository.listUsers(
                allocator,
                if (cursor) |value| .{ .created_at = value.created_at, .before_id = value.before_id } else null,
                query.limit orelse access_repository.default_page_size,
            );
            defer page.deinit(allocator);
            return finishUserPage(response, allocator, page);
        }
        if (std.mem.eql(u8, request.operation, "security.user.create")) {
            try requireTarget(forwarded, .POST, "/api/v1/users");
            try requireIdempotency(request.preconditions);
            const Body = struct { username: []const u8, role: []const u8 };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            var credential = try self.authentication.provisionUser(
                session,
                body.value.username,
                try parseRole(body.value.role),
                now,
                authAuditMetadata(forwarded, request_id),
            );
            defer credential.clear();
            var id_text: [32]u8 = undefined;
            var location_buffer: [96]u8 = undefined;
            const location = try std.fmt.bufPrint(
                &location_buffer,
                "/api/v1/users/{s}",
                .{api_response.encodeId(credential.user.id, &id_text)},
            );
            return finishUserCredential(response, allocator, 201, &credential, .{ .location = location });
        }

        if (std.mem.eql(u8, request.operation, "security.user.password_reset")) {
            if (forwarded.method != .POST or forwarded.query().len != 0) return error.InvalidTarget;
            try requireIdempotency(request.preconditions);
            const id_text = try api_request.pathParameter(
                forwarded.target,
                "/api/v1/users/",
                "/password-reset",
            );
            const id = try api_response.decodeId(id_text);
            const current = try self.authentication.repository.loadUser(id);
            if (!try requireAccessEtagOrRespond(
                response,
                request.preconditions.etag,
                .user,
                current.id,
                current.revision,
            )) return;
            const confirmation = try dangerousConfirmation(allocator, forwarded.body);
            try auth_application.Application.requireRecentReauthentication(session, now);
            if (!std.mem.eql(u8, confirmation, current.username.slice())) return error.ConfirmationFailed;
            var credential = try self.authentication.resetPassword(
                session,
                id,
                now,
                authAuditMetadata(forwarded, request_id),
            );
            defer credential.clear();
            return finishUserCredential(response, allocator, 200, &credential, .{});
        }

        const id_text = try api_request.pathParameter(forwarded.target, "/api/v1/users/", "");
        const id = try api_response.decodeId(id_text);
        const current = try self.authentication.repository.loadUser(id);
        if (std.mem.eql(u8, request.operation, "security.user.read")) {
            if (forwarded.method != .GET or forwarded.query().len != 0 or forwarded.body != null) {
                return error.InvalidTarget;
            }
            return finishUser(response, allocator, 200, current, .{});
        }
        if (!try requireAccessEtagOrRespond(
            response,
            request.preconditions.etag,
            .user,
            current.id,
            current.revision,
        )) return;
        if (std.mem.eql(u8, request.operation, "security.user.update")) {
            if (forwarded.method != .PATCH or forwarded.query().len != 0) return error.InvalidTarget;
            const Body = struct {
                role: ?[]const u8 = null,
                enabled: ?bool = null,
                confirmation: []const u8,
            };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            if (body.value.role == null and body.value.enabled == null) return error.NoChanges;
            try auth_application.Application.requireRecentReauthentication(session, now);
            if (!std.mem.eql(u8, body.value.confirmation, current.username.slice())) {
                return error.ConfirmationFailed;
            }
            const role = if (body.value.role) |value| try parseRole(value) else current.role;
            const enabled = body.value.enabled orelse current.enabled;
            if (role == current.role and enabled == current.enabled) return error.NoChanges;
            const updated = (try self.authentication.mutateUser(session, .{
                .user_id = id,
                .role = role,
                .enabled = enabled,
                .now = now,
            }, authAuditMetadata(forwarded, request_id))).?;
            return finishUser(response, allocator, 200, updated, .{});
        }
        if (std.mem.eql(u8, request.operation, "security.user.tombstone")) {
            if (forwarded.method != .DELETE or forwarded.query().len != 0) return error.InvalidTarget;
            const confirmation = try dangerousConfirmation(allocator, forwarded.body);
            try auth_application.Application.requireRecentReauthentication(session, now);
            if (!std.mem.eql(u8, confirmation, current.username.slice())) return error.ConfirmationFailed;
            _ = try self.authentication.mutateUser(session, .{
                .user_id = id,
                .role = current.role,
                .enabled = current.enabled,
                .tombstone = true,
                .now = now,
            }, authAuditMetadata(forwarded, request_id));
            return api_response.finishNoContent(response, allocator, .{});
        }
        return error.OperationUnavailable;
    }

    fn sessionOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        session: access_repository.Session,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        try auth_application.Application.authorize(session, .read);
        if (std.mem.eql(u8, request.operation, "security.sessions.list")) {
            try requireTargetPath(forwarded, .GET, "/api/v1/sessions");
            if (forwarded.body != null) return error.InvalidRequestBody;
            var query_scratch: [http.maximum_target_bytes]u8 = undefined;
            const query = try api_request.parseQuery(forwarded.query(), &query_scratch);
            if (queryHasInventoryFields(query) or queryHasOperationsFields(query)) {
                return error.InvalidQuery;
            }
            const all = if (query.scope) |value| std.mem.eql(u8, value, "all") else false;
            if (all) try auth_application.Application.authorize(session, .manage_all_sessions);
            const cursor = if (query.cursor) |value| try decodeAccessCursor(.session, value) else null;
            var page = try self.authentication.repository.listSessions(
                allocator,
                if (all) null else session.user_id,
                session.id,
                now,
                if (cursor) |value| .{ .created_at = value.created_at, .before_id = value.before_id } else null,
                query.limit orelse access_repository.default_page_size,
            );
            defer page.deinit(allocator);
            return finishSessionPage(response, allocator, page);
        }
        if (std.mem.eql(u8, request.operation, "security.session.revoke")) {
            if (forwarded.method != .DELETE or forwarded.query().len != 0 or forwarded.body != null) {
                return error.InvalidTarget;
            }
            const id_text = try api_request.pathParameter(forwarded.target, "/api/v1/sessions/", "");
            const id = try api_response.decodeId(id_text);
            var target = self.authentication.repository.loadSessionView(allocator, id, session.id, now) catch |failure|
                return if (failure == error.SessionNotFound) error.TargetSessionNotFound else failure;
            defer target.deinit(allocator);
            if (session.role != .superuser and !std.mem.eql(u8, &target.user_id, &session.user_id)) {
                return error.TargetSessionNotFound;
            }
            if (!try requireAccessEtagOrRespond(
                response,
                request.preconditions.etag,
                .session,
                target.id,
                target.generation,
            )) return;
            self.authentication.revokeSession(
                session,
                id,
                now,
                authAuditMetadata(forwarded, request_id),
            ) catch |failure|
                return if (failure == error.SessionNotFound) error.TargetSessionNotFound else failure;
            return api_response.finishNoContent(response, allocator, .{
                .set_cookie = if (target.current) auth_application.clearing_session_cookie else null,
            });
        }
        return error.OperationUnavailable;
    }

    fn inventoryOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        request_id: [16]u8,
        now: i64,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        const mutation = forwarded.method != .GET;
        const token = forwarded.session_token orelse return error.SessionNotFound;
        var authenticated = if (mutation)
            try self.authentication.authenticateMutation(token, forwarded.csrf_token, now)
        else
            try self.authentication.authenticate(token, now);
        defer authenticated.clear();
        if (authenticated.session.password_change_required) return error.PasswordChangeRequired;
        const principal: inventory_service.Principal = .{
            .id = authenticated.session.user_id,
            .role = authenticated.session.role,
        };
        const context: inventory_service.MutationContext = .{
            .request_id = request_id,
            .occurred_at = now,
            .user_agent = forwarded.user_agent,
            .proxy_peer = forwarded.proxy_peer,
        };

        if (std.mem.startsWith(u8, request.operation, "inventory.vnr") or
            std.mem.eql(u8, request.operation, "inventory.vnrs.list"))
        {
            return self.vnrOperation(
                request,
                forwarded,
                principal,
                authenticated.session,
                context,
                allocator,
                response,
            );
        }
        if (std.mem.startsWith(u8, request.operation, "inventory.node") or
            std.mem.eql(u8, request.operation, "inventory.nodes.list"))
        {
            return self.nodeOperation(
                request,
                forwarded,
                principal,
                authenticated.session,
                context,
                allocator,
                response,
            );
        }
        if (std.mem.startsWith(u8, request.operation, "inventory.route") or
            std.mem.eql(u8, request.operation, "inventory.routes.list"))
        {
            return self.routeOperation(
                request,
                forwarded,
                principal,
                authenticated.session,
                context,
                allocator,
                response,
            );
        }
        return error.OperationUnavailable;
    }

    fn vnrOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: inventory_service.Principal,
        session: access_repository.Session,
        context: inventory_service.MutationContext,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (std.mem.eql(u8, request.operation, "inventory.vnrs.list")) {
            try requireTargetPath(forwarded, .GET, "/api/v1/vnrs");
            if (forwarded.body != null) return error.InvalidRequestBody;
            var query_scratch: [http.maximum_target_bytes]u8 = undefined;
            const query = try api_request.parseQuery(forwarded.query(), &query_scratch);
            if (queryHasInventoryFields(query) or queryHasOperationsFields(query) or query.scope != null) {
                return error.InvalidQuery;
            }
            const cursor = if (query.cursor) |value| try inventory_service.decodeVnrCursor(value) else null;
            var page = try self.inventory.listVnrs(principal, cursor, query.limit);
            defer page.deinit(self.inventory.allocator);
            return finishVnrPage(response, allocator, page);
        }
        if (std.mem.eql(u8, request.operation, "inventory.vnr.create")) {
            try requireTarget(forwarded, .POST, "/api/v1/vnrs");
            try requireIdempotency(request.preconditions);
            const Body = struct { name: []const u8, cidr: []const u8 };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const record = try self.inventory.createVnr(principal, context, .{
                .name = body.value.name,
                .range = model.Cidr.parse(body.value.cidr) catch return error.InvalidCidr,
            });
            var location_buffer: [96]u8 = undefined;
            const location = try std.fmt.bufPrint(&location_buffer, "/api/v1/vnrs/{s}", .{record.name.slice()});
            return finishVnr(response, allocator, 201, record, .{ .location = location });
        }

        const name = try api_request.pathParameter(forwarded.target, "/api/v1/vnrs/", "");
        if (std.mem.eql(u8, request.operation, "inventory.vnr.read")) {
            if (forwarded.method != .GET or forwarded.query().len != 0 or forwarded.body != null) {
                return error.InvalidTarget;
            }
            const record = try self.inventory.getVnr(principal, name);
            return finishVnr(response, allocator, 200, record, .{});
        }
        if (std.mem.eql(u8, request.operation, "inventory.vnr.update")) {
            if (forwarded.method != .PATCH or forwarded.query().len != 0) return error.InvalidTarget;
            const Body = struct { cidr: []const u8 };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const record = self.inventory.updateVnr(
                principal,
                context,
                name,
                request.preconditions.etag,
                .{ .range = model.Cidr.parse(body.value.cidr) catch return error.InvalidCidr },
            ) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current = try self.inventory.getVnr(principal, name);
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return finishVnr(response, allocator, 200, record, .{});
        }
        if (std.mem.eql(u8, request.operation, "inventory.vnr.delete")) {
            if (forwarded.method != .DELETE or forwarded.query().len != 0) return error.InvalidTarget;
            const confirmation = try dangerousConfirmation(allocator, forwarded.body);
            try auth_application.Application.requireRecentReauthentication(session, context.occurred_at);
            if (!std.mem.eql(u8, confirmation, name)) return error.ConfirmationFailed;
            self.inventory.deleteVnr(principal, context, name, request.preconditions.etag) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current = try self.inventory.getVnr(principal, name);
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return api_response.finishNoContent(response, allocator, .{});
        }
        return error.OperationUnavailable;
    }

    fn nodeOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: inventory_service.Principal,
        session: access_repository.Session,
        context: inventory_service.MutationContext,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (std.mem.eql(u8, request.operation, "inventory.nodes.list")) {
            try requireTargetPath(forwarded, .GET, "/api/v1/nodes");
            if (forwarded.body != null) return error.InvalidRequestBody;
            var query_scratch: [http.maximum_target_bytes]u8 = undefined;
            const query = try api_request.parseQuery(forwarded.query(), &query_scratch);
            if (query.node_id != null or query.scope != null or queryHasOperationsFields(query)) {
                return error.InvalidQuery;
            }
            const cursor = if (query.cursor) |value| try inventory_service.decodeNodeCursor(value) else null;
            const vnr = if (query.vnr_name) |value| model.Name.parse(value) catch return error.InvalidName else null;
            const enrollment_state: ?inventory_service.EnrollmentState = if (query.enrollment_state) |value|
                try parseEnrollmentState(value)
            else
                null;
            var page = try self.inventory.listNodes(principal, cursor, query.limit, .{
                .vnr = vnr,
                .enrollment_state = enrollment_state,
            });
            defer page.deinit(self.inventory.allocator);
            return finishNodePage(response, allocator, page);
        }
        if (std.mem.eql(u8, request.operation, "inventory.node.create")) {
            try requireTarget(forwarded, .POST, "/api/v1/nodes");
            try requireIdempotency(request.preconditions);
            const Body = struct {
                name: []const u8,
                vnrName: []const u8,
                address: []const u8,
            };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const record = try self.inventory.createNode(principal, context, .{
                .name = body.value.name,
                .vnr = body.value.vnrName,
                .address = model.Ipv4.parse(body.value.address) catch return error.InvalidAddress,
            });
            var id_text: [32]u8 = undefined;
            var location_buffer: [96]u8 = undefined;
            const location = try std.fmt.bufPrint(
                &location_buffer,
                "/api/v1/nodes/{s}",
                .{record.id.write(&id_text)},
            );
            return finishNode(response, allocator, 201, record, .{ .location = location });
        }

        const id_text = try api_request.pathParameter(forwarded.target, "/api/v1/nodes/", "");
        const id = model.NodeId.parse(id_text) catch return error.InvalidIdentifier;
        if (std.mem.eql(u8, request.operation, "inventory.node.read")) {
            if (forwarded.method != .GET or forwarded.query().len != 0 or forwarded.body != null) {
                return error.InvalidTarget;
            }
            const record = try self.inventory.getNode(principal, id);
            return self.finishNodeDetail(response, allocator, principal, record, context.occurred_at);
        }
        if (std.mem.eql(u8, request.operation, "inventory.node.update")) {
            if (forwarded.method != .PATCH or forwarded.query().len != 0) return error.InvalidTarget;
            const Body = struct {
                name: ?[]const u8 = null,
                vnrName: ?[]const u8 = null,
                address: ?[]const u8 = null,
            };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const address = if (body.value.address) |value|
                model.Ipv4.parse(value) catch return error.InvalidAddress
            else
                null;
            const record = self.inventory.updateNode(
                principal,
                context,
                id,
                request.preconditions.etag,
                .{ .name = body.value.name, .vnr = body.value.vnrName, .address = address },
            ) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current = try self.inventory.getNode(principal, id);
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return self.finishNodeDetail(response, allocator, principal, record, context.occurred_at);
        }
        if (std.mem.eql(u8, request.operation, "inventory.node.delete")) {
            if (forwarded.method != .DELETE or forwarded.query().len != 0) return error.InvalidTarget;
            const confirmation = try dangerousConfirmation(allocator, forwarded.body);
            try auth_application.Application.requireRecentReauthentication(session, context.occurred_at);
            const current = try self.inventory.getNode(principal, id);
            if (!std.mem.eql(u8, confirmation, current.name.slice())) return error.ConfirmationFailed;
            self.inventory.deleteNode(principal, context, id, request.preconditions.etag) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return api_response.finishNoContent(response, allocator, .{});
        }
        return error.OperationUnavailable;
    }

    fn finishNodeDetail(
        self: *Application,
        response: *service_server.ResponseSink,
        allocator: std.mem.Allocator,
        principal: inventory_service.Principal,
        record: inventory_service.NodeRecord,
        observed_at: i64,
    ) !void {
        var output: std.Io.Writer.Allocating = .init(allocator);
        defer output.deinit();
        var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
        try json.beginObject();
        try json.objectField("node");
        try writeNode(&json, record);
        try json.objectField("runtime");
        if (self.read_models) |read_models| {
            // Runtime observations are explicitly ephemeral. A transient
            // observation failure must not turn an already-committed Node
            // mutation into an apparent HTTP failure that a client retries.
            if (read_models.getRuntimeNode(principal, record.id, observed_at)) |runtime| {
                try writeRuntimeNode(&json, runtime);
            } else |_| {
                try json.write(null);
            }
        } else {
            try json.write(null);
        }
        try json.objectField("routes");
        try json.beginArray();
        var cursor: ?inventory_service.RouteCursor = null;
        while (true) {
            var page = try self.inventory.listRoutes(principal, cursor, inventory_service.maximum_page_size, .{
                .node_id = record.id,
            });
            const next = page.next_cursor;
            for (page.items) |route| try writeRoute(&json, route);
            page.deinit(self.inventory.allocator);
            cursor = next;
            if (cursor == null) break;
        }
        try json.endArray();
        try json.endObject();
        const etag = record.etag();
        try api_response.finishBody(
            response,
            allocator,
            200,
            api_response.json_content_type,
            output.written(),
            .{ .etag = etag.slice() },
        );
    }

    fn routeOperation(
        self: *Application,
        request: service_ipc.Request,
        forwarded: api_request.Forwarded,
        principal: inventory_service.Principal,
        session: access_repository.Session,
        context: inventory_service.MutationContext,
        allocator: std.mem.Allocator,
        response: *service_server.ResponseSink,
    ) !void {
        if (std.mem.eql(u8, request.operation, "inventory.routes.list")) {
            try requireTargetPath(forwarded, .GET, "/api/v1/routes");
            if (forwarded.body != null) return error.InvalidRequestBody;
            var query_scratch: [http.maximum_target_bytes]u8 = undefined;
            const query = try api_request.parseQuery(forwarded.query(), &query_scratch);
            if (query.vnr_name != null or query.enrollment_state != null or query.scope != null or
                queryHasOperationsFields(query))
            {
                return error.InvalidQuery;
            }
            const cursor = if (query.cursor) |value| try inventory_service.decodeRouteCursor(value) else null;
            const node_id = if (query.node_id) |value| model.NodeId.parse(value) catch return error.InvalidIdentifier else null;
            var page = try self.inventory.listRoutes(principal, cursor, query.limit, .{ .node_id = node_id });
            defer page.deinit(self.inventory.allocator);
            return finishRoutePage(response, allocator, page);
        }
        if (std.mem.eql(u8, request.operation, "inventory.route.create")) {
            try requireTarget(forwarded, .POST, "/api/v1/routes");
            try requireIdempotency(request.preconditions);
            const Body = struct { prefix: []const u8, nodeId: []const u8 };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const record = try self.inventory.createRoute(principal, context, .{
                .prefix = model.Cidr.parse(body.value.prefix) catch return error.InvalidCidr,
                .node_id = model.NodeId.parse(body.value.nodeId) catch return error.InvalidIdentifier,
            });
            var id_text: [32]u8 = undefined;
            var location_buffer: [96]u8 = undefined;
            const location = try std.fmt.bufPrint(
                &location_buffer,
                "/api/v1/routes/{s}",
                .{record.id.write(&id_text)},
            );
            return finishRoute(response, allocator, 201, record, .{ .location = location });
        }

        const id_text = try api_request.pathParameter(forwarded.target, "/api/v1/routes/", "");
        const id = model.RouteId.parse(id_text) catch return error.InvalidIdentifier;
        if (std.mem.eql(u8, request.operation, "inventory.route.read")) {
            if (forwarded.method != .GET or forwarded.query().len != 0 or forwarded.body != null) {
                return error.InvalidTarget;
            }
            const record = try self.inventory.getRoute(principal, id);
            return finishRoute(response, allocator, 200, record, .{});
        }
        if (std.mem.eql(u8, request.operation, "inventory.route.update")) {
            if (forwarded.method != .PATCH or forwarded.query().len != 0) return error.InvalidTarget;
            const Body = struct {
                prefix: ?[]const u8 = null,
                nodeId: ?[]const u8 = null,
            };
            const body = try api_request.decodeBody(Body, allocator, forwarded.body);
            defer body.deinit();
            const prefix = if (body.value.prefix) |value|
                model.Cidr.parse(value) catch return error.InvalidCidr
            else
                null;
            const node_id = if (body.value.nodeId) |value|
                model.NodeId.parse(value) catch return error.InvalidIdentifier
            else
                null;
            const record = self.inventory.updateRoute(
                principal,
                context,
                id,
                request.preconditions.etag,
                .{ .prefix = prefix, .node_id = node_id },
            ) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current = try self.inventory.getRoute(principal, id);
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return finishRoute(response, allocator, 200, record, .{});
        }
        if (std.mem.eql(u8, request.operation, "inventory.route.delete")) {
            if (forwarded.method != .DELETE or forwarded.query().len != 0) return error.InvalidTarget;
            const confirmation = try dangerousConfirmation(allocator, forwarded.body);
            try auth_application.Application.requireRecentReauthentication(session, context.occurred_at);
            const current = try self.inventory.getRoute(principal, id);
            var prefix_buffer: [18]u8 = undefined;
            if (!std.mem.eql(u8, confirmation, try current.prefix.write(&prefix_buffer))) {
                return error.ConfirmationFailed;
            }
            self.inventory.deleteRoute(principal, context, id, request.preconditions.etag) catch |failure| {
                if (failure != error.PreconditionFailed) return failure;
                const current_etag = current.etag();
                return failPrecondition(response, current_etag.slice());
            };
            return api_response.finishNoContent(response, allocator, .{});
        }
        return error.OperationUnavailable;
    }
};

fn authAuditMetadata(
    forwarded: api_request.Forwarded,
    request_id: [16]u8,
) auth_application.AuditMetadata {
    return .{
        .request_id = request_id,
        .user_agent = forwarded.user_agent,
        .proxy_peer = forwarded.proxy_peer,
    };
}

fn canonicalIdempotencyRequest(
    allocator: std.mem.Allocator,
    operation: []const u8,
    forwarded: api_request.Forwarded,
    etag: ?[]const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer {
        std.crypto.secureZero(u8, output.written());
        output.deinit();
    }
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("body");
    if (forwarded.body) |body|
        try writeCanonicalBody(&json, allocator, operation, body)
    else
        try json.write(null);
    try json.objectField("etag");
    if (etag) |value| try json.write(value) else try json.write(null);
    try json.objectField("method");
    try json.write(@tagName(forwarded.method));
    try json.objectField("target");
    try json.write(forwarded.target);
    try json.endObject();
    if (output.written().len > idempotency_repository.maximum_canonical_request_bytes) {
        return error.RequestTooLarge;
    }
    return output.toOwnedSlice();
}

/// Authentication secrets deliberately do not participate in idempotency
/// equality. A caller that learns a previously used Idempotency-Key must not
/// be able to distinguish a matching password from a different guess by
/// observing replay versus conflict behavior. The safe identity fields remain
/// part of the canonical request, and the authoritative request decoder still
/// applies strict operation-specific schemas before any mutation succeeds.
fn writeCanonicalBody(
    json: *std.json.Stringify,
    allocator: std.mem.Allocator,
    operation: []const u8,
    value: std.json.Value,
) !void {
    if (value != .object) return writeCanonicalValue(json, allocator, value);

    const object = value.object;
    const keys = try allocator.alloc([]const u8, object.count());
    defer allocator.free(keys);
    var iterator = object.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) keys[index] = entry.key_ptr.*;
    std.mem.sort([]const u8, keys, {}, lessThanText);
    try json.beginObject();
    for (keys) |key| {
        try json.objectField(key);
        if (isIdempotencySecretField(operation, key)) {
            try json.write("[secret]");
        } else {
            try writeCanonicalValue(json, allocator, object.get(key).?);
        }
    }
    try json.endObject();
}

fn isIdempotencySecretField(operation: []const u8, field: []const u8) bool {
    if (std.mem.eql(u8, operation, "auth.login") or
        std.mem.eql(u8, operation, "auth.reauthenticate"))
    {
        return std.mem.eql(u8, field, "password");
    }
    if (std.mem.eql(u8, operation, "auth.password.change")) {
        return std.mem.eql(u8, field, "currentPassword") or
            std.mem.eql(u8, field, "newPassword");
    }
    return false;
}

fn writeCanonicalValue(
    json: *std.json.Stringify,
    allocator: std.mem.Allocator,
    value: std.json.Value,
) !void {
    switch (value) {
        .object => |object| {
            const keys = try allocator.alloc([]const u8, object.count());
            defer allocator.free(keys);
            var iterator = object.iterator();
            var index: usize = 0;
            while (iterator.next()) |entry| : (index += 1) keys[index] = entry.key_ptr.*;
            std.mem.sort([]const u8, keys, {}, lessThanText);
            try json.beginObject();
            for (keys) |key| {
                try json.objectField(key);
                try writeCanonicalValue(json, allocator, object.get(key).?);
            }
            try json.endObject();
        },
        .array => |array| {
            try json.beginArray();
            for (array.items) |item| try writeCanonicalValue(json, allocator, item);
            try json.endArray();
        },
        else => try json.write(value),
    }
}

fn lessThanText(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn idempotencyActor(
    forwarded: api_request.Forwarded,
    operation: []const u8,
    allocator: std.mem.Allocator,
) !idempotency_repository.ActorId {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    if (std.mem.eql(u8, operation, "auth.login")) {
        const LoginBody = struct { username: []const u8, password: []const u8 };
        const body = try api_request.decodeBody(LoginBody, allocator, forwarded.body);
        defer body.deinit();
        const username = try auth.Username.parse(body.value.username);
        hasher.update("ntip-login-idempotency-actor-v0.2\x00");
        hasher.update(username.slice());
    } else {
        const token = forwarded.session_token orelse return error.SessionNotFound;
        hasher.update("ntip-session-idempotency-actor-v0.2\x00");
        hasher.update(&token.bytes);
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var actor: idempotency_repository.ActorId = undefined;
    @memcpy(&actor, digest[0..actor.len]);
    std.crypto.secureZero(u8, &digest);
    return actor;
}

fn nonReplayableOperation(operation: []const u8) bool {
    return std.mem.eql(u8, operation, "auth.login") or
        std.mem.eql(u8, operation, "enrollment.credential.issue") or
        std.mem.eql(u8, operation, "operations.audit.export") or
        std.mem.eql(u8, operation, "security.user.create") or
        std.mem.eql(u8, operation, "security.user.password_reset");
}

fn controlOperationKind(operation: []const u8) ?operations_service.ControlKind {
    if (std.mem.eql(u8, operation, "service.restart")) return .restart;
    if (std.mem.eql(u8, operation, "service.shutdown")) return .shutdown;
    return null;
}

const CapturedSummary = struct {
    status: u16,
    failed: bool,
    replay_payload: ?[]u8,
};

fn inspectCapturedResponse(allocator: std.mem.Allocator, bytes: []const u8) !CapturedSummary {
    var offset: usize = 0;
    var frames: usize = 0;
    var terminal = false;
    var failed = false;
    var status: u16 = 0;
    var replay_payload: ?[]u8 = null;
    errdefer if (replay_payload) |payload| {
        std.crypto.secureZero(u8, payload);
        allocator.free(payload);
    };

    while (offset < bytes.len) {
        const parsed = try decodeCapturedFrame(allocator, bytes, &offset);
        defer parsed.deinit();
        const frame = parsed.value;
        if (terminal) return error.InvalidCapturedResponse;
        terminal = frame.final;
        frames += 1;
        if (frame.@"error" != null) {
            const failure = frame.@"error".?;
            failed = true;
            if (!frame.final or frame.payload != null) return error.InvalidCapturedResponse;
            status = @intFromEnum(http.statusForError(failure.code));
            if (frames == 1) {
                replay_payload = try std.json.Stringify.valueAlloc(allocator, failure, .{
                    .emit_null_optional_fields = false,
                });
            } else if (replay_payload) |candidate| {
                std.crypto.secureZero(u8, candidate);
                allocator.free(candidate);
                replay_payload = null;
            }
            continue;
        }
        const payload = frame.payload orelse return error.InvalidCapturedResponse;
        if (frames == 1) {
            status = try responseStatus(payload);
            replay_payload = try std.json.Stringify.valueAlloc(allocator, payload, .{});
        } else if (replay_payload) |candidate| {
            std.crypto.secureZero(u8, candidate);
            allocator.free(candidate);
            replay_payload = null;
        }
    }
    if (frames == 0 or !terminal) return error.InvalidCapturedResponse;
    return .{ .status = status, .failed = failed, .replay_payload = replay_payload };
}

fn decodeCapturedFrame(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    offset: *usize,
) !std.json.Parsed(service_ipc.ResponseFrame) {
    if (bytes.len - offset.* < service_ipc.frame_prefix_bytes) return error.InvalidCapturedResponse;
    var prefix: [service_ipc.frame_prefix_bytes]u8 = undefined;
    @memcpy(&prefix, bytes[offset.* .. offset.* + prefix.len]);
    const length = service_ipc.decodeLength(&prefix) catch return error.InvalidCapturedResponse;
    offset.* += prefix.len;
    if (length > bytes.len - offset.*) return error.InvalidCapturedResponse;
    const body = bytes[offset.* .. offset.* + length];
    offset.* += length;
    return service_ipc.decodeResponseFrame(allocator, body) catch return error.InvalidCapturedResponse;
}

fn responseStatus(payload: std.json.Value) !u16 {
    if (payload != .object) return error.InvalidCapturedResponse;
    const raw = payload.object.get("status") orelse return error.InvalidCapturedResponse;
    if (raw != .integer or raw.integer < 200 or raw.integer > 599) return error.InvalidCapturedResponse;
    return @intCast(raw.integer);
}

fn forwardCapturedResponse(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    response: *service_server.ResponseSink,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const parsed = try decodeCapturedFrame(allocator, bytes, &offset);
        defer parsed.deinit();
        const frame = parsed.value;
        if (frame.@"error") |failure| {
            try response.failWithMetadata(
                failure.code,
                failure.message,
                failure.retryable,
                failure.metadata orelse .{},
            );
        } else {
            try response.send(frame.payload, frame.final);
        }
    }
}

fn finishIdempotencyReplay(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    operation: []const u8,
    replay: idempotency_repository.Replay,
) !void {
    if (replay.status >= 400) {
        const parsed_failure = std.json.parseFromSlice(
            service_ipc.ErrorBody,
            allocator,
            replay.body,
            .{
                .duplicate_field_behavior = .@"error",
                .ignore_unknown_fields = false,
                .allocate = .alloc_always,
            },
        ) catch return error.CorruptIdempotencyState;
        defer parsed_failure.deinit();
        const failure = parsed_failure.value;
        if (@intFromEnum(http.statusForError(failure.code)) != replay.status) {
            return error.CorruptIdempotencyState;
        }
        try response.failWithMetadata(
            failure.code,
            failure.message,
            failure.retryable,
            failure.metadata orelse .{},
        );
        return;
    }
    if (nonReplayableOperation(operation)) return error.OneTimeResponseAlreadyIssued;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, replay.body, .{
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
    }) catch return error.CorruptIdempotencyState;
    defer parsed.deinit();
    if (try responseStatus(parsed.value) != replay.status) return error.CorruptIdempotencyState;
    try response.finish(parsed.value);
}

const PublicError = struct {
    code: service_ipc.ErrorCode,
    message: []const u8,
    retryable: bool = false,
};

fn failPrecondition(response: *service_server.ResponseSink, etag: []const u8) !void {
    const public = publicError(error.PreconditionFailed);
    return api_response.failWithMetadata(
        response,
        public.code,
        public.message,
        public.retryable,
        .{ .etag = etag },
    );
}

fn boundedRetryAfter(value: u64) u32 {
    return @intCast(@min(
        @max(value, 1),
        @as(u64, service_ipc.maximum_error_retry_after_seconds),
    ));
}

fn currentOperationsEtag(
    service: *operations_service.Service,
    principal: operations_service.Principal,
    operation: []const u8,
) !?operations_service.StrongEtag {
    if (std.mem.startsWith(u8, operation, "operations.audit.")) {
        return try service.auditEtag(principal);
    }
    if (std.mem.startsWith(u8, operation, "settings.")) {
        return try service.settingsEtag(principal);
    }
    if (std.mem.startsWith(u8, operation, "service.")) {
        return try service.controlEtag(principal);
    }
    return null;
}

fn publicError(failure: anyerror) PublicError {
    return switch (failure) {
        error.InvalidCredentials, error.UserDisabled => .{
            .code = .invalid_credentials,
            .message = "invalid username or password",
        },
        error.SessionNotFound, error.SessionExpired, error.InvalidSessionToken => .{
            .code = .authentication_required,
            .message = "authentication is required",
        },
        error.PasswordChangeRequired => .{
            .code = .password_change_required,
            .message = "password change is required",
        },
        error.CsrfRequired, error.CsrfFailed => .{
            .code = .csrf_failed,
            .message = "CSRF validation failed",
        },
        error.Forbidden, error.RootRequired => .{
            .code = .forbidden,
            .message = "operation is not permitted",
        },
        error.ReauthenticationRequired => .{
            .code = .reauthentication_required,
            .message = "recent password reauthentication is required",
        },
        error.PasswordQueueSaturated, error.LoginThrottled => .{
            .code = .rate_limited,
            .message = "authentication is temporarily rate limited",
            .retryable = true,
        },
        error.IdempotencyRequired => .{
            .code = .idempotency_required,
            .message = "Idempotency-Key is required",
        },
        error.PreconditionRequired => .{
            .code = .precondition_required,
            .message = "If-Match is required",
        },
        error.PreconditionFailed => .{
            .code = .precondition_failed,
            .message = "resource precondition failed",
        },
        error.UserNotFound,
        error.TargetSessionNotFound,
        error.VnrNotFound,
        error.NodeNotFound,
        error.RouteNotFound,
        => .{
            .code = .not_found,
            .message = "resource was not found",
        },
        error.UsernameReserved,
        error.AlreadyBootstrapped,
        error.UserConstraintViolation,
        error.OneTimeResponseAlreadyIssued,
        error.VnrExists,
        error.NodeExists,
        error.RouteExists,
        error.NodeAlreadyEnrolled,
        error.MaximumNodesExceeded,
        error.NoChanges,
        => .{ .code = .conflict, .message = "resource conflicts with current state" },
        error.IdempotencyConflict => .{
            .code = .idempotency_conflict,
            .message = "Idempotency-Key conflicts with an earlier request",
        },
        error.IdempotencyResultUnavailable => .{
            .code = .idempotency_conflict,
            .message = "operation committed but its original response is unavailable",
        },
        error.FinalSuperuserRequired,
        error.VnrOverlap,
        error.RouteOverlap,
        error.RouteOverlapsVnr,
        error.NodeAddressReserved,
        error.NodeAddressOutsideVnr,
        => .{ .code = .invariant_violation, .message = "domain invariant would be violated" },
        error.OperationUnavailable => .{
            .code = .operation_unavailable,
            .message = "operation is not available",
        },
        error.InvalidForwardedRequest,
        error.InvalidRequest,
        error.InvalidRequestBody,
        error.RequestBodyRequired,
        error.InvalidTarget,
        error.InvalidQuery,
        error.InvalidIdentifier,
        error.InvalidUsername,
        error.InvalidPassword,
        error.InvalidTimestamp,
        error.InvalidUserAgent,
        error.InvalidEtag,
        error.InvalidCidr,
        error.InvalidAddress,
        error.InvalidName,
        error.InvalidEnrollmentState,
        error.InvalidLivenessState,
        error.InvalidRole,
        error.InvalidCursor,
        error.InvalidPageLimit,
        error.InvalidIdempotencyKey,
        error.InvalidCredentialLifetime,
        error.ConfirmationFailed,
        => .{ .code = .validation_failed, .message = "request validation failed" },
        error.DatabaseBusy,
        error.DatabaseLocked,
        error.IdempotencyInProgress,
        error.IdempotencyRace,
        error.ProjectionMismatch,
        error.ProjectionChanged,
        => .{
            .code = .service_unavailable,
            .message = "authoritative service is temporarily unavailable",
            .retryable = true,
        },
        else => .{ .code = .internal_error, .message = "internal service error" },
    };
}

fn queryHasInventoryFields(query: api_request.Query) bool {
    return query.vnr_name != null or
        query.enrollment_state != null or
        query.node_id != null;
}

fn queryHasOperationsFields(query: api_request.Query) bool {
    return query.liveness != null or
        query.status != null or
        query.severity != null or
        query.since != null or
        query.actor_user_id != null or
        query.resource_type != null;
}

fn requireTarget(forwarded: api_request.Forwarded, method: @import("http.zig").Method, path: []const u8) !void {
    if (forwarded.method != method or !std.mem.eql(u8, forwarded.path(), path)) {
        return error.InvalidTarget;
    }
}

fn requireTargetPath(forwarded: api_request.Forwarded, method: @import("http.zig").Method, path: []const u8) !void {
    if (forwarded.method != method or !std.mem.eql(u8, forwarded.path(), path)) {
        return error.InvalidTarget;
    }
}

fn requireIdempotency(preconditions: service_ipc.Preconditions) !void {
    if (preconditions.idempotency_key == null) return error.IdempotencyRequired;
}

fn dangerousConfirmation(allocator: std.mem.Allocator, body_value: ?std.json.Value) ![]const u8 {
    const Body = struct { confirmation: []const u8 };
    const parsed = try api_request.decodeBody(Body, allocator, body_value);
    // `allocator` is the request arena, so returning this borrowed slice is
    // valid through the complete synchronous dispatch.
    return parsed.value.confirmation;
}

const AccessResourceKind = enum { user, session };
const access_etag_buffer_len: usize = 80;

fn writeAccessEtag(
    kind: AccessResourceKind,
    id: [16]u8,
    generation: u64,
    output: *[access_etag_buffer_len]u8,
) ![]const u8 {
    if (generation == 0) return error.InvalidAccessGeneration;
    var id_text: [32]u8 = undefined;
    return std.fmt.bufPrint(output, "\"{s}:{s}:{d}\"", .{
        @tagName(kind),
        api_response.encodeId(id, &id_text),
        generation,
    });
}

fn requireAccessEtag(
    supplied: ?[]const u8,
    kind: AccessResourceKind,
    id: [16]u8,
    generation: u64,
) !void {
    const actual = supplied orelse return error.PreconditionRequired;
    var expected_buffer: [access_etag_buffer_len]u8 = undefined;
    const expected = try writeAccessEtag(kind, id, generation, &expected_buffer);
    if (!std.mem.eql(u8, actual, expected)) return error.PreconditionFailed;
}

fn requireAccessEtagOrRespond(
    response: *service_server.ResponseSink,
    supplied: ?[]const u8,
    kind: AccessResourceKind,
    id: [16]u8,
    generation: u64,
) !bool {
    const actual = supplied orelse return error.PreconditionRequired;
    var expected_buffer: [access_etag_buffer_len]u8 = undefined;
    const expected = try writeAccessEtag(kind, id, generation, &expected_buffer);
    if (std.mem.eql(u8, actual, expected)) return true;
    try failPrecondition(response, expected);
    return false;
}

const AccessCursor = struct {
    created_at: i64,
    before_id: [16]u8,
};

fn encodeAccessCursor(
    kind: AccessResourceKind,
    cursor: AccessCursor,
    output: *[96]u8,
) []const u8 {
    var id_text: [32]u8 = undefined;
    return std.fmt.bufPrint(output, "v1:{c}:{d}:{s}", .{
        if (kind == .user) @as(u8, 'u') else @as(u8, 's'),
        cursor.created_at,
        api_response.encodeId(cursor.before_id, &id_text),
    }) catch unreachable;
}

fn decodeAccessCursor(kind: AccessResourceKind, text: []const u8) !AccessCursor {
    const prefix = if (kind == .user) "v1:u:" else "v1:s:";
    if (!std.mem.startsWith(u8, text, prefix)) return error.InvalidCursor;
    const rest = text[prefix.len..];
    const separator = std.mem.indexOfScalar(u8, rest, ':') orelse return error.InvalidCursor;
    const created_text = rest[0..separator];
    const id_text = rest[separator + 1 ..];
    if (created_text.len == 0 or created_text.len > 20 or id_text.len != 32) {
        return error.InvalidCursor;
    }
    const created_at = std.fmt.parseInt(i64, created_text, 10) catch return error.InvalidCursor;
    if (created_at < 0) return error.InvalidCursor;
    const cursor: AccessCursor = .{
        .created_at = created_at,
        .before_id = api_response.decodeId(id_text) catch return error.InvalidCursor,
    };
    var canonical: [96]u8 = undefined;
    if (!std.mem.eql(u8, text, encodeAccessCursor(kind, cursor, &canonical))) {
        return error.InvalidCursor;
    }
    return cursor;
}

fn parseRole(text: []const u8) !auth.Role {
    if (std.mem.eql(u8, text, "viewer")) return .viewer;
    if (std.mem.eql(u8, text, "operator")) return .operator;
    if (std.mem.eql(u8, text, "superuser")) return .superuser;
    return error.InvalidRole;
}

fn parseLiveness(text: []const u8) ?read_models_service.LivenessState {
    if (std.mem.eql(u8, text, "unknown")) return .unknown;
    if (std.mem.eql(u8, text, "online")) return .online;
    if (std.mem.eql(u8, text, "suspect")) return .suspect;
    if (std.mem.eql(u8, text, "offline")) return .offline;
    return null;
}

fn parseEnrollmentState(text: []const u8) !inventory_service.EnrollmentState {
    if (std.mem.eql(u8, text, "unenrolled")) return .unenrolled;
    if (std.mem.eql(u8, text, "credential_issued")) return .credential_issued;
    if (std.mem.eql(u8, text, "enrolled")) return .enrolled;
    return error.InvalidEnrollmentState;
}

fn wallSeconds(io: std.Io) !i64 {
    const seconds = std.Io.Clock.real.now(io).toSeconds();
    if (seconds < 0) return error.InvalidTimestamp;
    return seconds;
}

fn finishAuthContext(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    user: access_repository.User,
    session: access_repository.Session,
    csrf_token: auth.SecretToken,
    user_agent: ?[]const u8,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer {
        std.crypto.secureZero(u8, output.written());
        output.deinit();
    }
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("user");
    try writeUser(&json, user);
    try json.objectField("session");
    try writeSession(&json, session, user_agent);
    try json.objectField("csrfToken");
    var csrf_text: [auth.session_token_text_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &csrf_text);
    try json.write(csrf_token.encode(&csrf_text));
    try json.endObject();
    try api_response.finishBody(
        response,
        allocator,
        200,
        api_response.json_content_type,
        output.written(),
        metadata,
    );
}

fn writeUser(json: *std.json.Stringify, user: access_repository.User) !void {
    var id: [32]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var updated: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(user.id, &id));
    try json.objectField("username");
    try json.write(user.username.slice());
    try json.objectField("role");
    try json.write(@tagName(user.role));
    try json.objectField("status");
    try json.write(if (user.enabled) "active" else "disabled");
    try json.objectField("mustChangePassword");
    try json.write(user.password_change_required);
    try json.objectField("generation");
    try json.write(user.revision);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(user.created_at, &created));
    try json.objectField("updatedAt");
    try json.write(try api_response.formatTimestamp(user.updated_at, &updated));
    try json.endObject();
}

fn writeSession(
    json: *std.json.Stringify,
    session: access_repository.Session,
    user_agent: ?[]const u8,
) !void {
    var id: [32]u8 = undefined;
    var user_id: [32]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var last_seen: [api_response.timestamp_text_len]u8 = undefined;
    var idle: [api_response.timestamp_text_len]u8 = undefined;
    var absolute: [api_response.timestamp_text_len]u8 = undefined;
    const generation = std.math.add(u64, @as(u64, @intCast(session.last_seen_at)), 1) catch
        return error.InvalidTimestamp;
    var etag_buffer: [access_etag_buffer_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(session.id, &id));
    try json.objectField("userId");
    try json.write(api_response.encodeId(session.user_id, &user_id));
    try json.objectField("username");
    try json.write(session.username.slice());
    try json.objectField("current");
    try json.write(true);
    try json.objectField("userAgent");
    if (user_agent) |value| try json.write(value) else try json.write(null);
    try json.objectField("proxyPeer");
    try json.write("loopback");
    try json.objectField("generation");
    try json.write(generation);
    try json.objectField("etag");
    try json.write(try writeAccessEtag(.session, session.id, generation, &etag_buffer));
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(session.created_at, &created));
    try json.objectField("lastSeenAt");
    try json.write(try api_response.formatTimestamp(session.last_seen_at, &last_seen));
    try json.objectField("idleExpiresAt");
    try json.write(try api_response.formatTimestamp(session.idle_expires_at, &idle));
    try json.objectField("absoluteExpiresAt");
    try json.write(try api_response.formatTimestamp(session.absolute_expires_at, &absolute));
    try json.endObject();
}

fn writeSessionView(json: *std.json.Stringify, session: access_repository.SessionView) !void {
    var id: [32]u8 = undefined;
    var user_id: [32]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var last_seen: [api_response.timestamp_text_len]u8 = undefined;
    var idle: [api_response.timestamp_text_len]u8 = undefined;
    var absolute: [api_response.timestamp_text_len]u8 = undefined;
    var etag_buffer: [access_etag_buffer_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(api_response.encodeId(session.id, &id));
    try json.objectField("userId");
    try json.write(api_response.encodeId(session.user_id, &user_id));
    try json.objectField("username");
    try json.write(session.username.slice());
    try json.objectField("current");
    try json.write(session.current);
    try json.objectField("userAgent");
    if (session.user_agent) |value| try json.write(value) else try json.write(null);
    try json.objectField("proxyPeer");
    if (session.proxy_peer) |value| try json.write(value) else try json.write(null);
    try json.objectField("generation");
    try json.write(session.generation);
    try json.objectField("etag");
    try json.write(try writeAccessEtag(.session, session.id, session.generation, &etag_buffer));
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(session.created_at, &created));
    try json.objectField("lastSeenAt");
    try json.write(try api_response.formatTimestamp(session.last_seen_at, &last_seen));
    try json.objectField("idleExpiresAt");
    try json.write(try api_response.formatTimestamp(session.idle_expires_at, &idle));
    try json.objectField("absoluteExpiresAt");
    try json.write(try api_response.formatTimestamp(session.absolute_expires_at, &absolute));
    try json.endObject();
}

fn finishUser(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    user: access_repository.User,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeUser(&json, user);
    var etag_buffer: [access_etag_buffer_len]u8 = undefined;
    var completed = metadata;
    completed.etag = try writeAccessEtag(.user, user.id, user.revision, &etag_buffer);
    try api_response.finishBody(
        response,
        allocator,
        status,
        api_response.json_content_type,
        output.written(),
        completed,
    );
}

fn finishUserCredential(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    credential: *const auth_application.TemporaryCredential,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer {
        std.crypto.secureZero(u8, output.written());
        output.deinit();
    }
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("user");
    try writeUser(&json, credential.user);
    try json.objectField("temporaryPassword");
    try json.write(credential.password[0..]);
    try json.endObject();
    var etag_buffer: [access_etag_buffer_len]u8 = undefined;
    var completed = metadata;
    completed.etag = try writeAccessEtag(.user, credential.user.id, credential.user.revision, &etag_buffer);
    try api_response.finishBody(
        response,
        allocator,
        status,
        api_response.json_content_type,
        output.written(),
        completed,
    );
}

fn finishUserPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: access_repository.UserPage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |user| try writeUser(&json, user);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [96]u8 = undefined;
        try json.write(encodeAccessCursor(.user, .{
            .created_at = cursor.created_at,
            .before_id = cursor.before_id,
        }, &cursor_buffer));
    } else try json.write(null);
    try json.endObject();
    try api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn finishSessionPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: access_repository.SessionPage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |session| try writeSessionView(&json, session);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [96]u8 = undefined;
        try json.write(encodeAccessCursor(.session, .{
            .created_at = cursor.created_at,
            .before_id = cursor.before_id,
        }, &cursor_buffer));
    } else try json.write(null);
    try json.endObject();
    try api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn finishOverview(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    result: read_models_service.OverviewResult,
    control_etag: operations_service.StrongEtag,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    var desired_id: [32]u8 = undefined;
    var effective_id: [32]u8 = undefined;
    var observed: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("generation");
    try json.write(result.value.generation);
    try json.objectField("inventory");
    try json.write(.{
        .vnrs = result.value.inventory.vnrs,
        .nodes = result.value.inventory.nodes,
        .routes = result.value.inventory.routes,
    });
    try json.objectField("runtime");
    try json.write(.{
        .online = result.value.runtime.online,
        .suspect = result.value.runtime.suspect,
        .offline = result.value.runtime.offline,
        .unknown = result.value.runtime.unknown,
    });
    try json.objectField("desiredSettingsRevisionId");
    try json.write(api_response.encodeId(result.value.desired_settings_revision_id, &desired_id));
    try json.objectField("effectiveSettingsRevisionId");
    try json.write(api_response.encodeId(result.value.effective_settings_revision_id, &effective_id));
    try json.objectField("pendingRestart");
    try json.write(result.value.pending_restart);
    try json.objectField("serviceControlEtag");
    try json.write(control_etag.slice());
    try json.objectField("observedAt");
    try json.write(try api_response.formatTimestamp(result.value.observed_at, &observed));
    try json.endObject();
    try api_response.finishBody(
        response,
        allocator,
        200,
        api_response.json_content_type,
        output.written(),
        .{ .etag = result.etag.slice() },
    );
}

fn finishTopology(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    result: read_models_service.TopologyResult,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    var observed: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("generation");
    try json.write(result.value.generation);
    try json.objectField("vnrs");
    try json.beginArray();
    for (result.value.vnrs) |record| try writeVnr(&json, record);
    try json.endArray();
    try json.objectField("nodes");
    try json.beginArray();
    for (result.value.nodes) |record| try writeReadModelNode(&json, record);
    try json.endArray();
    try json.objectField("routes");
    try json.beginArray();
    for (result.value.routes) |record| try writeRoute(&json, record);
    try json.endArray();
    try json.objectField("runtime");
    try json.beginArray();
    for (result.value.runtime) |record| try writeRuntimeNode(&json, record);
    try json.endArray();
    try json.objectField("observedAt");
    try json.write(try api_response.formatTimestamp(result.value.observed_at, &observed));
    try json.endObject();
    try api_response.finishBody(
        response,
        allocator,
        200,
        api_response.json_content_type,
        output.written(),
        .{ .etag = result.etag.slice() },
    );
}

fn finishRuntimePage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: read_models_service.RuntimePage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    var observed: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |record| try writeRuntimeNode(&json, record);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var cursor_buffer: [read_models_service.maximum_cursor_bytes]u8 = undefined;
        try json.write(read_models_service.encodeRuntimeCursor(cursor, &cursor_buffer));
    } else try json.write(null);
    try json.objectField("observedAt");
    try json.write(try api_response.formatTimestamp(page.observed_at, &observed));
    try json.endObject();
    try api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn writeReadModelNode(json: *std.json.Stringify, record: read_models_service.Node) !void {
    var id: [32]u8 = undefined;
    var address: [15]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var updated: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(record.id.write(&id));
    try json.objectField("name");
    try json.write(record.name.slice());
    try json.objectField("vnrName");
    try json.write(record.vnr.slice());
    try json.objectField("address");
    try json.write(try record.address.write(&address));
    try json.objectField("enrollmentState");
    try json.write(@tagName(record.enrollment_state));
    try json.objectField("generation");
    try json.write(record.revision);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(record.created_at, &created));
    try json.objectField("updatedAt");
    try json.write(try api_response.formatTimestamp(record.updated_at, &updated));
    try json.endObject();
}

fn writeRuntimeNode(json: *std.json.Stringify, record: read_models_service.RuntimeNode) !void {
    var id: [32]u8 = undefined;
    var rx: [api_response.timestamp_text_len]u8 = undefined;
    var tx: [api_response.timestamp_text_len]u8 = undefined;
    var observed: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("nodeId");
    try json.write(record.node_id.write(&id));
    try json.objectField("liveness");
    try json.write(@tagName(record.liveness));
    try json.objectField("sessionState");
    try json.write(@tagName(record.session_state));
    try json.objectField("observedEndpoint");
    if (record.observed_endpoint) |endpoint| try json.write(endpoint.slice()) else try json.write(null);
    try json.objectField("trafficState");
    try json.write(@tagName(record.traffic_state));
    try json.objectField("authenticatedRxAt");
    if (record.authenticated_rx_at) |timestamp| {
        try json.write(try api_response.formatTimestamp(timestamp, &rx));
    } else try json.write(null);
    try json.objectField("authenticatedTxAt");
    if (record.authenticated_tx_at) |timestamp| {
        try json.write(try api_response.formatTimestamp(timestamp, &tx));
    } else try json.write(null);
    try json.objectField("observedAt");
    try json.write(try api_response.formatTimestamp(record.observed_at, &observed));
    try json.endObject();
}

fn finishVnr(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    record: inventory_service.VnrRecord,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeVnr(&json, record);
    const etag = record.etag();
    var completed = metadata;
    completed.etag = etag.slice();
    try api_response.finishBody(response, allocator, status, api_response.json_content_type, output.written(), completed);
}

fn finishNode(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    record: inventory_service.NodeRecord,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeNode(&json, record);
    const etag = record.etag();
    var completed = metadata;
    completed.etag = etag.slice();
    try api_response.finishBody(response, allocator, status, api_response.json_content_type, output.written(), completed);
}

fn finishRoute(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    record: inventory_service.RouteRecord,
    metadata: api_response.Metadata,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeRoute(&json, record);
    const etag = record.etag();
    var completed = metadata;
    completed.etag = etag.slice();
    try api_response.finishBody(response, allocator, status, api_response.json_content_type, output.written(), completed);
}

fn finishVnrPage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: inventory_service.VnrPage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |record| try writeVnr(&json, record);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var buffer: [inventory_service.maximum_cursor_token_bytes]u8 = undefined;
        try json.write(inventory_service.encodeVnrCursor(cursor, &buffer));
    } else try json.write(null);
    try json.endObject();
    try api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn finishNodePage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: inventory_service.NodePage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |record| try writeNode(&json, record);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var buffer: [inventory_service.maximum_cursor_token_bytes]u8 = undefined;
        try json.write(inventory_service.encodeNodeCursor(cursor, &buffer));
    } else try json.write(null);
    try json.endObject();
    try api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn finishRoutePage(
    response: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    page: inventory_service.RoutePage,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("items");
    try json.beginArray();
    for (page.items) |record| try writeRoute(&json, record);
    try json.endArray();
    try json.objectField("nextCursor");
    if (page.next_cursor) |cursor| {
        var buffer: [inventory_service.maximum_cursor_token_bytes]u8 = undefined;
        try json.write(inventory_service.encodeRouteCursor(cursor, &buffer));
    } else try json.write(null);
    try json.endObject();
    try api_response.finishBody(response, allocator, 200, api_response.json_content_type, output.written(), .{});
}

fn canonicalBodyForTest(operation: []const u8, source: []const u8) ![]u8 {
    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, source, .{});
    defer parsed.deinit();
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer {
        std.crypto.secureZero(u8, output.written());
        output.deinit();
    }
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeCanonicalBody(&json, allocator, operation, parsed.value);
    return output.toOwnedSlice();
}

test "authentication secrets do not create an idempotency equality oracle" {
    const allocator = std.testing.allocator;
    const login_a = try canonicalBodyForTest(
        "auth.login",
        "{\"password\":\"correct horse battery staple\",\"username\":\"root\"}",
    );
    defer {
        std.crypto.secureZero(u8, login_a);
        allocator.free(login_a);
    }
    const login_b = try canonicalBodyForTest(
        "auth.login",
        "{\"username\":\"root\",\"password\":\"an entirely different guess\"}",
    );
    defer {
        std.crypto.secureZero(u8, login_b);
        allocator.free(login_b);
    }
    try std.testing.expectEqualStrings(login_a, login_b);

    const other_actor = try canonicalBodyForTest(
        "auth.login",
        "{\"username\":\"operator\",\"password\":\"correct horse battery staple\"}",
    );
    defer {
        std.crypto.secureZero(u8, other_actor);
        allocator.free(other_actor);
    }
    try std.testing.expect(!std.mem.eql(u8, login_a, other_actor));

    const reauth_a = try canonicalBodyForTest("auth.reauthenticate", "{\"password\":\"first value\"}");
    defer {
        std.crypto.secureZero(u8, reauth_a);
        allocator.free(reauth_a);
    }
    const reauth_b = try canonicalBodyForTest("auth.reauthenticate", "{\"password\":\"second value\"}");
    defer {
        std.crypto.secureZero(u8, reauth_b);
        allocator.free(reauth_b);
    }
    try std.testing.expectEqualStrings(reauth_a, reauth_b);

    const change_a = try canonicalBodyForTest(
        "auth.password.change",
        "{\"currentPassword\":\"old secret\",\"newPassword\":\"new secret one\"}",
    );
    defer {
        std.crypto.secureZero(u8, change_a);
        allocator.free(change_a);
    }
    const change_b = try canonicalBodyForTest(
        "auth.password.change",
        "{\"newPassword\":\"new secret two\",\"currentPassword\":\"wrong guess\"}",
    );
    defer {
        std.crypto.secureZero(u8, change_b);
        allocator.free(change_b);
    }
    try std.testing.expectEqualStrings(change_a, change_b);

    const mutation_a = try canonicalBodyForTest("inventory.vnr.create", "{\"name\":\"core\",\"cidr\":\"10.0.0.0/24\"}");
    defer allocator.free(mutation_a);
    const mutation_b = try canonicalBodyForTest("inventory.vnr.create", "{\"name\":\"core\",\"cidr\":\"10.1.0.0/24\"}");
    defer allocator.free(mutation_b);
    try std.testing.expect(!std.mem.eql(u8, mutation_a, mutation_b));
}

fn writeVnr(json: *std.json.Stringify, record: inventory_service.VnrRecord) !void {
    var cidr: [18]u8 = undefined;
    var address: [15]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var updated: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("name");
    try json.write(record.name.slice());
    try json.objectField("cidr");
    try json.write(try record.range.write(&cidr));
    try json.objectField("masterAddress");
    try json.write(try record.masterAddress().write(&address));
    try json.objectField("publicRangeWarning");
    try json.write(record.public_range_warning);
    try json.objectField("generation");
    try json.write(record.revision);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(record.created_at, &created));
    try json.objectField("updatedAt");
    try json.write(try api_response.formatTimestamp(record.updated_at, &updated));
    try json.endObject();
}

fn writeNode(json: *std.json.Stringify, record: inventory_service.NodeRecord) !void {
    var id: [32]u8 = undefined;
    var address: [15]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var updated: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(record.id.write(&id));
    try json.objectField("name");
    try json.write(record.name.slice());
    try json.objectField("vnrName");
    try json.write(record.vnr.slice());
    try json.objectField("address");
    try json.write(try record.address.write(&address));
    try json.objectField("enrollmentState");
    try json.write(@tagName(record.enrollment_state));
    try json.objectField("generation");
    try json.write(record.revision);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(record.created_at, &created));
    try json.objectField("updatedAt");
    try json.write(try api_response.formatTimestamp(record.updated_at, &updated));
    try json.endObject();
}

fn writeRoute(json: *std.json.Stringify, record: inventory_service.RouteRecord) !void {
    var id: [32]u8 = undefined;
    var node_id: [32]u8 = undefined;
    var prefix: [18]u8 = undefined;
    var created: [api_response.timestamp_text_len]u8 = undefined;
    var updated: [api_response.timestamp_text_len]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(record.id.write(&id));
    try json.objectField("prefix");
    try json.write(try record.prefix.write(&prefix));
    try json.objectField("nodeId");
    try json.write(record.node_id.write(&node_id));
    try json.objectField("nodeName");
    try json.write(record.node_name.slice());
    try json.objectField("generation");
    try json.write(record.revision);
    try json.objectField("createdAt");
    try json.write(try api_response.formatTimestamp(record.created_at, &created));
    try json.objectField("updatedAt");
    try json.write(try api_response.formatTimestamp(record.updated_at, &updated));
    try json.endObject();
}

test "public error mapping never exposes internal error names" {
    try std.testing.expectEqual(service_ipc.ErrorCode.invalid_credentials, publicError(error.InvalidCredentials).code);
    try std.testing.expectEqual(service_ipc.ErrorCode.authentication_required, publicError(error.SessionExpired).code);
    try std.testing.expectEqual(service_ipc.ErrorCode.conflict, publicError(error.MaximumNodesExceeded).code);
    try std.testing.expectEqual(service_ipc.ErrorCode.internal_error, publicError(error.SecretInternalFailure).code);
    try std.testing.expectEqualStrings("internal service error", publicError(error.SecretInternalFailure).message);
}

test "access resource ETags are strong exact preconditions" {
    const id = [_]u8{0x5a} ** 16;
    var buffer: [access_etag_buffer_len]u8 = undefined;
    const tag = try writeAccessEtag(.session, id, 42, &buffer);
    try std.testing.expectEqualStrings(
        "\"session:5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a:42\"",
        tag,
    );
    try requireAccessEtag(tag, .session, id, 42);
    try std.testing.expectError(error.PreconditionRequired, requireAccessEtag(null, .session, id, 42));
    try std.testing.expectError(error.PreconditionFailed, requireAccessEtag(tag, .session, id, 43));
}

test "access cursors round trip their timestamp and opaque ID" {
    const cursor: AccessCursor = .{ .created_at = 1_721_478_400, .before_id = [_]u8{0xab} ** 16 };
    var buffer: [96]u8 = undefined;
    const encoded = encodeAccessCursor(.user, cursor, &buffer);
    const decoded = try decodeAccessCursor(.user, encoded);
    try std.testing.expectEqual(cursor.created_at, decoded.created_at);
    try std.testing.expectEqualSlices(u8, &cursor.before_id, &decoded.before_id);
    try std.testing.expectError(error.InvalidCursor, decodeAccessCursor(.session, encoded));
    try std.testing.expectError(error.InvalidCursor, decodeAccessCursor(.user, "v1:u:-1:abab"));
    try std.testing.expectError(
        error.InvalidCursor,
        decodeAccessCursor(.user, "v1:u:01721478400:abababababababababababababababab"),
    );
}

test "Node API accepts filters and serializes the credential-issued projection" {
    try std.testing.expectEqual(
        inventory_service.EnrollmentState.credential_issued,
        try parseEnrollmentState("credential_issued"),
    );
    try std.testing.expectError(error.InvalidEnrollmentState, parseEnrollmentState("credential-issued"));

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeNode(&json, .{
        .id = .{ .bytes = [_]u8{0x11} ** 16 },
        .name = try model.Name.parse("edge-issued"),
        .vnr = try model.Name.parse("core"),
        .address = try model.Ipv4.parse("10.42.0.2"),
        .enrollment_state = .credential_issued,
        .revision = 1,
        .created_at = 100,
        .updated_at = 100,
    });
    try std.testing.expect(std.mem.indexOf(
        u8,
        output.written(),
        "\"enrollmentState\":\"credential_issued\"",
    ) != null);
}

test "Node runtime serialization exposes only the bounded public observation" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try writeRuntimeNode(&json, .{
        .node_id = .{ .bytes = [_]u8{0x22} ** 16 },
        .liveness = .online,
        .session_state = .established,
        .observed_endpoint = try read_models_service.EndpointText.parse("198.51.100.4:51900"),
        .traffic_state = .warm,
        .authenticated_rx_at = 98,
        .authenticated_tx_at = 99,
        .observed_at = 100,
    });
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"liveness\":\"online\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"sessionState\":\"established\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "\"trafficState\":\"warm\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "198.51.100.4:51900") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "sessionId") == null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "publicKey") == null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "softwareVersion") == null);
}
