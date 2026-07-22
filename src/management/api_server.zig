//! Bounded loopback HTTP service and typed bridge to the authoritative
//! `ntsrv` application worker.
//!
//! This module intentionally has no QAWS dependency. Its admission queue,
//! fixed worker model, absolute read deadlines, capped keep-alive loop, and
//! resumable response cursor follow the same defensive shape while retaining
//! NTIP's own parser and service protocol.

const std = @import("std");
const builtin = @import("builtin");
const api_config = @import("api_config.zig");
const bootstrap_assets = @import("bootstrap_assets.zig");
const api_error = @import("error.zig");
const auth = @import("auth.zig");
const http = @import("http.zig");
const service_ipc = @import("service_ipc.zig");
const bootstrap_installer_template = @embedFile("node-bootstrap-installer.sh.in");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const maximum_requests_per_connection: u32 = 100;
pub const request_timeout_ms: i64 = 10_000;
pub const service_timeout_ms: i64 = 5_000;
pub const maximum_bootstrap_redeem_body_bytes: usize = 128;
pub const maximum_anonymous_redemptions: u32 = 2;
pub const maximum_service_response_frames: u32 = 1024;
pub const maximum_streamed_audit_body_bytes: usize =
    http.maximum_streaming_response_chunk_bytes * @as(usize, maximum_service_response_frames - 1);
pub const worker_stack_bytes: usize = 1024 * 1024;
pub const connection_buffer_bytes: usize = http.maximum_request_head_bytes + http.maximum_body_bytes;

/// The socket listener in `ntsrv` must obtain Linux `SO_PEERCRED` and compare
/// the accepted UID before decoding a frame. Keeping the requirement typed
/// here prevents a future integration from treating pathname permissions as
/// sufficient authentication.
pub const ServicePeerRequirement = struct {
    expected_api_uid: std.Io.File.Uid,

    pub fn accepts(self: ServicePeerRequirement, actual_uid: std.Io.File.Uid) bool {
        return self.expected_api_uid == actual_uid;
    }
};

pub const OpenApiProvider = struct {
    context: *const anyopaque,
    getFn: *const fn (context: *const anyopaque) []const u8,

    pub fn get(self: OpenApiProvider) []const u8 {
        return self.getFn(self.context);
    }

    pub fn fromFixedDocument(document: *const FixedDocument) OpenApiProvider {
        return .{ .context = document, .getFn = FixedDocument.getOpaque };
    }
};

pub const FixedDocument = struct {
    bytes: []const u8,

    fn getOpaque(context: *const anyopaque) []const u8 {
        const self: *const FixedDocument = @ptrCast(@alignCast(context));
        return self.bytes;
    }
};

/// HTTP response convention carried inside a service response frame. The
/// first frame supplies status and headers. Every frame may append one UTF-8
/// body fragment; later frames must not repeat response metadata.
pub const ServiceHttpResponseFrame = struct {
    status: ?u16 = null,
    contentType: ?[]const u8 = null,
    bodyChunk: ?[]const u8 = null,
    etag: ?[]const u8 = null,
    location: ?[]const u8 = null,
    contentDisposition: ?[]const u8 = null,
    auditExportId: ?[]const u8 = null,
    retryAfterSeconds: ?u32 = null,
    setCookie: ?[]const u8 = null,
};

pub const OwnedHttpResponse = struct {
    allocator: Allocator,
    status: http.Status,
    body: []u8,
    content_type: []u8,
    etag: ?[]u8 = null,
    location: ?[]u8 = null,
    content_disposition: ?[]u8 = null,
    audit_export_id: ?[]u8 = null,
    retry_after_seconds: ?u32 = null,
    set_cookie: ?[]u8 = null,
    allow: ?[]u8 = null,

    pub fn deinit(self: *OwnedHttpResponse) void {
        std.crypto.secureZero(u8, self.body);
        self.allocator.free(self.body);
        self.allocator.free(self.content_type);
        if (self.etag) |value| self.allocator.free(value);
        if (self.location) |value| self.allocator.free(value);
        if (self.content_disposition) |value| self.allocator.free(value);
        if (self.audit_export_id) |value| self.allocator.free(value);
        if (self.set_cookie) |value| {
            std.crypto.secureZero(u8, value);
            self.allocator.free(value);
        }
        if (self.allow) |value| self.allocator.free(value);
        self.* = undefined;
    }

    fn fromStatic(allocator: Allocator, status: http.Status, body: []const u8, content_type: []const u8) !OwnedHttpResponse {
        const owned_body = try allocator.dupe(u8, body);
        errdefer allocator.free(owned_body);
        return .{
            .allocator = allocator,
            .status = status,
            .body = owned_body,
            .content_type = try allocator.dupe(u8, content_type),
        };
    }
};

pub const Backend = struct {
    context: *anyopaque,
    exchangeFn: *const fn (
        context: *anyopaque,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
    ) anyerror!OwnedHttpResponse,
    streamExchangeFn: ?*const fn (
        context: *anyopaque,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
        http_writer: *std.Io.Writer,
    ) anyerror!StreamingExchangeResult = null,

    pub fn exchange(
        self: Backend,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
    ) !OwnedHttpResponse {
        return self.exchangeFn(self.context, allocator, io, request);
    }

    pub fn streamExchange(
        self: Backend,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
        http_writer: *std.Io.Writer,
    ) !?StreamingExchangeResult {
        const function = self.streamExchangeFn orelse return null;
        return try function(self.context, allocator, io, request, http_writer);
    }
};

/// `fallback` is only returned before an HTTP streaming head has been sent.
/// Once `aborted` is returned the caller must close the client connection and
/// must not attempt to append a second HTTP response.
pub const StreamingExchangeResult = union(enum) {
    completed,
    aborted,
    fallback: OwnedHttpResponse,
};

pub const UnixBackend = struct {
    socket_path: []const u8,

    pub fn backend(self: *UnixBackend) Backend {
        return .{
            .context = self,
            .exchangeFn = exchangeOpaque,
            .streamExchangeFn = streamExchangeOpaque,
        };
    }

    fn exchangeOpaque(
        context: *anyopaque,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
    ) !OwnedHttpResponse {
        const self: *UnixBackend = @ptrCast(@alignCast(context));
        return self.exchange(allocator, io, request);
    }

    fn streamExchangeOpaque(
        context: *anyopaque,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
        http_writer: *std.Io.Writer,
    ) !StreamingExchangeResult {
        const self: *UnixBackend = @ptrCast(@alignCast(context));
        return self.streamAuditExport(allocator, io, request, http_writer);
    }

    pub fn exchange(
        self: UnixBackend,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
    ) !OwnedHttpResponse {
        var wiping_allocator: WipingAllocator = .{ .child = allocator };
        const secret_allocator = wiping_allocator.allocator();
        if (self.socket_path.len > std.Io.net.UnixAddress.max_len) return error.ServiceUnavailable;
        const address = std.Io.net.UnixAddress.init(self.socket_path) catch return error.ServiceUnavailable;
        const stream = address.connect(io) catch return error.ServiceUnavailable;
        defer stream.close(io);
        installSocketDeadlines(stream.socket.handle, 5) catch return error.ServiceUnavailable;

        const encoded = try service_ipc.encodeRequest(secret_allocator, request);
        defer secret_allocator.free(encoded);
        var writer_buffer: [8192]u8 = undefined;
        defer std.crypto.secureZero(u8, &writer_buffer);
        var stream_writer = stream.writer(io, &writer_buffer);
        service_ipc.writeFrame(&stream_writer.interface, encoded) catch return error.ServiceUnavailable;

        const io_deadline = Io.Clock.Timestamp.fromNow(io, .{
            .raw = Io.Duration.fromMilliseconds(service_timeout_ms),
            .clock = .awake,
        });
        const timeout: Io.Timeout = .{ .deadline = io_deadline };
        const frame_storage = try allocator.alloc(u8, service_ipc.maximum_frame_bytes);
        defer {
            std.crypto.secureZero(u8, frame_storage);
            allocator.free(frame_storage);
        }

        var body: std.ArrayList(u8) = .empty;
        errdefer {
            std.crypto.secureZero(u8, body.items);
            body.deinit(secret_allocator);
        }
        var response_status: ?http.Status = null;
        var content_type: ?[]u8 = null;
        errdefer if (content_type) |value| allocator.free(value);
        var etag: ?[]u8 = null;
        errdefer if (etag) |value| allocator.free(value);
        var location: ?[]u8 = null;
        errdefer if (location) |value| allocator.free(value);
        var content_disposition: ?[]u8 = null;
        errdefer if (content_disposition) |value| allocator.free(value);
        var audit_export_id: ?[]u8 = null;
        errdefer if (audit_export_id) |value| allocator.free(value);
        var set_cookie: ?[]u8 = null;
        errdefer if (set_cookie) |value| {
            std.crypto.secureZero(u8, value);
            allocator.free(value);
        };
        var retry_after_seconds: ?u32 = null;

        var sequence = ResponseSequence.init(request.request_id);
        while (sequence.next_sequence < maximum_service_response_frames) {
            if (Io.Clock.real.now(io).toMilliseconds() > request.deadline_unix_ms) return error.ServiceDeadlineExceeded;
            const frame_bytes = readFrameTimeout(io, stream, frame_storage, timeout) catch return error.ServiceUnavailable;
            var parsed = service_ipc.decodeResponseFrame(secret_allocator, frame_bytes) catch return error.InvalidServiceResponse;
            defer {
                wipeDecodedResponseFrame(&parsed.value);
                parsed.deinit();
            }
            const frame = parsed.value;
            try sequence.accept(frame);

            if (frame.@"error") |failure| {
                // A streamed operation may discover a terminal failure after
                // sending one or more body frames. The HTTP bridge buffers the
                // private response until finality, so discard the incomplete
                // success safely and surface the stable terminal error.
                std.crypto.secureZero(u8, body.items);
                body.deinit(secret_allocator);
                body = .empty;
                if (content_type) |value| allocator.free(value);
                content_type = null;
                if (etag) |value| allocator.free(value);
                etag = null;
                if (location) |value| allocator.free(value);
                location = null;
                if (content_disposition) |value| allocator.free(value);
                content_disposition = null;
                if (audit_export_id) |value| allocator.free(value);
                audit_export_id = null;
                if (set_cookie) |value| {
                    std.crypto.secureZero(u8, value);
                    allocator.free(value);
                }
                set_cookie = null;
                const metadata = failure.metadata orelse service_ipc.ErrorMetadata{};
                if (metadata.etag) |value| etag = try allocator.dupe(u8, value);
                retry_after_seconds = metadata.retry_after_seconds;
                const error_body = try encodeServiceError(
                    allocator,
                    request.request_id,
                    failure,
                );
                errdefer allocator.free(error_body);
                return .{
                    .allocator = allocator,
                    .status = http.statusForError(failure.code),
                    .body = error_body,
                    .content_type = try allocator.dupe(u8, "application/json; charset=utf-8"),
                    .etag = etag,
                    .retry_after_seconds = retry_after_seconds,
                };
            }

            const payload_value = frame.payload orelse return error.InvalidServiceResponse;
            const payload_bytes = try std.json.Stringify.valueAlloc(secret_allocator, payload_value, .{});
            defer secret_allocator.free(payload_bytes);
            var payload = std.json.parseFromSlice(ServiceHttpResponseFrame, secret_allocator, payload_bytes, .{
                .duplicate_field_behavior = .@"error",
                .ignore_unknown_fields = false,
                .allocate = .alloc_always,
            }) catch return error.InvalidServiceResponse;
            defer {
                wipeDecodedHttpResponseFrame(&payload.value);
                payload.deinit();
            }

            if (frame.sequence == 0) {
                response_status = statusFromInt(payload.value.status orelse return error.InvalidServiceResponse) orelse
                    return error.InvalidServiceResponse;
                try validateServiceResponseMetadata(payload.value);
                content_type = try allocator.dupe(u8, payload.value.contentType orelse "application/json; charset=utf-8");
                if (payload.value.etag) |value| etag = try allocator.dupe(u8, value);
                if (payload.value.location) |value| location = try allocator.dupe(u8, value);
                if (payload.value.contentDisposition) |value| content_disposition = try allocator.dupe(u8, value);
                if (payload.value.auditExportId) |value| audit_export_id = try allocator.dupe(u8, value);
                if (payload.value.setCookie) |value| set_cookie = try allocator.dupe(u8, value);
                retry_after_seconds = payload.value.retryAfterSeconds;
            } else if (payload.value.status != null or payload.value.contentType != null or
                payload.value.etag != null or payload.value.location != null or
                payload.value.contentDisposition != null or payload.value.auditExportId != null or
                payload.value.setCookie != null or payload.value.retryAfterSeconds != null)
            {
                return error.InvalidServiceResponse;
            }

            if (payload.value.bodyChunk) |chunk| {
                if (body.items.len + chunk.len > http.maximum_buffered_response_body_bytes) {
                    return error.ServiceResponseTooLarge;
                }
                try body.appendSlice(secret_allocator, chunk);
            }
            if (!frame.final) continue;

            return .{
                .allocator = allocator,
                .status = response_status.?,
                .body = try body.toOwnedSlice(secret_allocator),
                .content_type = content_type.?,
                .etag = etag,
                .location = location,
                .content_disposition = content_disposition,
                .audit_export_id = audit_export_id,
                .retry_after_seconds = retry_after_seconds,
                .set_cookie = set_cookie,
            };
        }
        return error.TooManyServiceFrames;
    }

    /// Relays the one intentionally streaming public operation without ever
    /// accumulating its body. Before the first valid success frame, failures
    /// can still be represented as a normal JSON response. After the HTTP head
    /// is visible, any malformed frame, deadline, IPC failure, or terminal
    /// service error aborts the chunked response by closing the connection.
    pub fn streamAuditExport(
        self: UnixBackend,
        allocator: Allocator,
        io: Io,
        request: service_ipc.Request,
        http_writer: *std.Io.Writer,
    ) !StreamingExchangeResult {
        var wiping_allocator: WipingAllocator = .{ .child = allocator };
        const secret_allocator = wiping_allocator.allocator();
        if (!std.mem.eql(u8, request.operation, "operations.audit.export")) {
            return error.InvalidRoutePolicy;
        }
        if (self.socket_path.len > std.Io.net.UnixAddress.max_len) return error.ServiceUnavailable;
        const address = std.Io.net.UnixAddress.init(self.socket_path) catch return error.ServiceUnavailable;
        const stream = address.connect(io) catch return error.ServiceUnavailable;
        defer stream.close(io);
        installSocketDeadlines(stream.socket.handle, 5) catch return error.ServiceUnavailable;

        const encoded = try service_ipc.encodeRequest(secret_allocator, request);
        defer secret_allocator.free(encoded);
        var service_writer_buffer: [8192]u8 = undefined;
        defer std.crypto.secureZero(u8, &service_writer_buffer);
        var service_writer = stream.writer(io, &service_writer_buffer);
        service_ipc.writeFrame(&service_writer.interface, encoded) catch return error.ServiceUnavailable;

        const io_deadline = Io.Clock.Timestamp.fromNow(io, .{
            .raw = Io.Duration.fromMilliseconds(service_timeout_ms),
            .clock = .awake,
        });
        const timeout: Io.Timeout = .{ .deadline = io_deadline };
        const frame_storage = try allocator.alloc(u8, service_ipc.maximum_frame_bytes);
        defer {
            std.crypto.secureZero(u8, frame_storage);
            allocator.free(frame_storage);
        }

        var sequence = ResponseSequence.init(request.request_id);
        var headers_started = false;
        var streamed_bytes: usize = 0;
        while (sequence.next_sequence < maximum_service_response_frames) {
            if (Io.Clock.real.now(io).toMilliseconds() >= request.deadline_unix_ms) {
                if (headers_started) return .aborted;
                return error.ServiceDeadlineExceeded;
            }
            const frame_bytes = readFrameTimeout(io, stream, frame_storage, timeout) catch {
                if (headers_started) return .aborted;
                return error.ServiceUnavailable;
            };
            var parsed = service_ipc.decodeResponseFrame(secret_allocator, frame_bytes) catch {
                if (headers_started) return .aborted;
                return error.InvalidServiceResponse;
            };
            defer {
                wipeDecodedResponseFrame(&parsed.value);
                parsed.deinit();
            }
            const frame = parsed.value;
            sequence.accept(frame) catch {
                if (headers_started) return .aborted;
                return error.InvalidServiceResponse;
            };

            if (frame.@"error") |failure| {
                if (headers_started) return .aborted;
                const error_body = try encodeServiceError(
                    allocator,
                    request.request_id,
                    failure,
                );
                errdefer allocator.free(error_body);
                const metadata = failure.metadata orelse service_ipc.ErrorMetadata{};
                const error_etag = if (metadata.etag) |value| try allocator.dupe(u8, value) else null;
                errdefer if (error_etag) |value| allocator.free(value);
                const content_type = try allocator.dupe(u8, "application/json; charset=utf-8");
                return .{ .fallback = .{
                    .allocator = allocator,
                    .status = http.statusForError(failure.code),
                    .body = error_body,
                    .content_type = content_type,
                    .etag = error_etag,
                    .retry_after_seconds = metadata.retry_after_seconds,
                } };
            }

            const payload_value = frame.payload orelse {
                if (headers_started) return .aborted;
                return error.InvalidServiceResponse;
            };
            const payload_bytes = std.json.Stringify.valueAlloc(secret_allocator, payload_value, .{}) catch |failure| {
                if (headers_started) return .aborted;
                return failure;
            };
            defer secret_allocator.free(payload_bytes);
            var payload = std.json.parseFromSlice(ServiceHttpResponseFrame, secret_allocator, payload_bytes, .{
                .duplicate_field_behavior = .@"error",
                .ignore_unknown_fields = false,
                .allocate = .alloc_always,
            }) catch {
                if (headers_started) return .aborted;
                return error.InvalidServiceResponse;
            };
            defer {
                wipeDecodedHttpResponseFrame(&payload.value);
                payload.deinit();
            }

            if (frame.sequence == 0) {
                validateAuditStreamingMetadata(payload.value) catch return error.InvalidServiceResponse;
                if (payload.value.bodyChunk) |chunk| {
                    if (chunk.len == 0 or chunk.len > http.maximum_streaming_response_chunk_bytes) {
                        return error.InvalidServiceResponse;
                    }
                }
                var head_storage: [http.maximum_response_head_bytes]u8 = undefined;
                defer std.crypto.secureZero(u8, &head_storage);
                const prepared = http.prepareResponse(&head_storage, .{
                    .status = .ok,
                    .content_type = payload.value.contentType.?,
                    .close = true,
                    .request_id = request.request_id,
                    .content_disposition = payload.value.contentDisposition.?,
                    .audit_export_id = payload.value.auditExportId.?,
                    .body_framing = .chunked,
                }) catch return error.InvalidServiceResponse;
                // Treat any write error from this point as an indeterminate,
                // already-started response; a partial head cannot be replaced.
                headers_started = true;
                http.writePrepared(http_writer, prepared) catch return .aborted;
            } else if (payload.value.status != null or payload.value.contentType != null or
                payload.value.etag != null or payload.value.location != null or
                payload.value.contentDisposition != null or payload.value.auditExportId != null or
                payload.value.setCookie != null or payload.value.retryAfterSeconds != null)
            {
                return .aborted;
            }

            if (payload.value.bodyChunk) |chunk| {
                if (chunk.len == 0 or chunk.len > http.maximum_streaming_response_chunk_bytes) {
                    return .aborted;
                }
                streamed_bytes = std.math.add(usize, streamed_bytes, chunk.len) catch return .aborted;
                if (streamed_bytes > maximum_streamed_audit_body_bytes) return .aborted;
                http.writeChunkedResponseChunk(http_writer, chunk) catch return .aborted;
            }
            if (!frame.final) continue;
            if (!headers_started) return error.InvalidServiceResponse;
            http.finishChunkedResponse(http_writer) catch return .aborted;
            return .completed;
        }
        return if (headers_started) .aborted else error.TooManyServiceFrames;
    }
};

pub const Handler = struct {
    public_https_origin: []const u8,
    bootstrap_spki_pin: []const u8 = "",
    bootstrap_manifest: ?bootstrap_assets.Manifest = null,
    anonymous_redemptions: ?*std.atomic.Value(u32) = null,
    openapi: OpenApiProvider,
    backend: Backend,

    pub fn dispatch(
        self: Handler,
        allocator: Allocator,
        io: Io,
        request: *const http.Request,
        request_id: []const u8,
    ) !OwnedHttpResponse {
        if (publicBootstrapRoute(request)) |public_route| {
            return switch (public_route) {
                .installer => |bootstrap_id| self.renderBootstrapInstaller(allocator, request, bootstrap_id),
                .redeem => self.forwardBootstrapRedemption(allocator, io, request, request_id),
            };
        }
        const resolution = try router.resolve(request.method, request.target);
        switch (resolution) {
            .not_found => return error.RouteNotFound,
            .method_not_allowed => return error.MethodNotAllowed,
            .matched => |match| {
                if (std.mem.eql(u8, match.route.operation, "health.live")) {
                    return OwnedHttpResponse.fromStatic(
                        allocator,
                        .ok,
                        "{\"status\":\"live\"}",
                        "application/json; charset=utf-8",
                    );
                }
                if (std.mem.eql(u8, match.route.operation, "contract.openapi")) {
                    const document = self.openapi.get();
                    if (document.len == 0 or document.len > http.maximum_buffered_response_body_bytes) {
                        return error.InvalidOpenApiDocument;
                    }
                    return OwnedHttpResponse.fromStatic(allocator, .ok, document, "application/json; charset=utf-8");
                }
                var result = try self.forward(allocator, io, request, request_id, match.route.operation);
                errdefer result.deinit();
                if (std.mem.eql(u8, match.route.operation, "enrollment.bootstrap.config") and
                    result.status == .ok)
                {
                    try self.replaceBootstrapConfigBody(allocator, &result);
                }
                return result;
            },
        }
    }

    fn renderBootstrapInstaller(
        self: Handler,
        allocator: Allocator,
        request: *const http.Request,
        bootstrap_id: []const u8,
    ) !OwnedHttpResponse {
        if (request.method != .GET) return error.MethodNotAllowed;
        if (request.body.len != 0) return error.UnexpectedRequestBody;
        if (request.header("Origin") != null) return error.InvalidBootstrapRequest;
        const manifest = self.bootstrap_manifest orelse return error.ServiceUnavailable;
        const body = try renderInstallerScript(
            allocator,
            bootstrap_id,
            self.public_https_origin,
            self.bootstrap_spki_pin,
            manifest,
        );
        errdefer allocator.free(body);
        return .{
            .allocator = allocator,
            .status = .ok,
            .body = body,
            .content_type = try allocator.dupe(u8, "text/x-shellscript; charset=utf-8"),
        };
    }

    fn forwardBootstrapRedemption(
        self: Handler,
        allocator: Allocator,
        io: Io,
        request: *const http.Request,
        request_id: []const u8,
    ) !OwnedHttpResponse {
        if (request.method != .POST) return error.MethodNotAllowed;
        if (request.header("Origin") != null) return error.InvalidBootstrapRequest;
        if (request.body.len == 0 or request.body.len > maximum_bootstrap_redeem_body_bytes) {
            return error.InvalidBootstrapRequest;
        }
        const content_type = request.header("Content-Type") orelse return error.UnsupportedMediaType;
        if (!std.ascii.eqlIgnoreCase(content_type, "application/json")) {
            return error.UnsupportedMediaType;
        }
        const admission = self.anonymous_redemptions;
        if (admission) |active| {
            if (!tryAcquireConnection(active, maximum_anonymous_redemptions)) {
                return error.BootstrapRedemptionBusy;
            }
        }
        defer if (admission) |active| releaseConnection(active);

        var prepared = try prepareBootstrapRedemption(allocator, io, request, request_id);
        defer prepared.deinit();
        var result = try self.backend.exchange(allocator, io, prepared.request);
        errdefer result.deinit();
        if (result.status == .ok) {
            if (result.etag != null or result.location != null or result.content_disposition != null or
                result.audit_export_id != null or result.retry_after_seconds != null or
                result.set_cookie != null or result.allow != null or
                !isJsonContentType(result.content_type))
            {
                return error.InvalidServiceResponse;
            }
            const manifest = self.bootstrap_manifest orelse return error.ServiceUnavailable;
            try attachBootstrapArchives(allocator, &result, manifest);
        } else {
            try replaceBootstrapPublicFailure(allocator, request_id, &result);
        }
        return result;
    }

    fn replaceBootstrapConfigBody(
        self: Handler,
        allocator: Allocator,
        response: *OwnedHttpResponse,
    ) !void {
        var parsed = std.json.parseFromSlice(
            struct { authorized: bool },
            allocator,
            response.body,
            .{ .duplicate_field_behavior = .@"error", .ignore_unknown_fields = false },
        ) catch return error.InvalidServiceResponse;
        defer parsed.deinit();
        if (!parsed.value.authorized) return error.InvalidServiceResponse;
        const replacement = try std.json.Stringify.valueAlloc(allocator, .{
            .installerOrigin = self.public_https_origin,
            .spkiPin = self.bootstrap_spki_pin,
        }, .{});
        std.crypto.secureZero(u8, response.body);
        allocator.free(response.body);
        response.body = replacement;
    }

    fn forward(
        self: Handler,
        allocator: Allocator,
        io: Io,
        request: *const http.Request,
        request_id: []const u8,
        operation: []const u8,
    ) !OwnedHttpResponse {
        var prepared = try self.prepareForward(allocator, io, request, request_id, operation);
        defer prepared.deinit();
        return self.backend.exchange(allocator, io, prepared.request);
    }

    fn forwardStreaming(
        self: Handler,
        allocator: Allocator,
        io: Io,
        request: *const http.Request,
        request_id: []const u8,
        operation: []const u8,
        http_writer: *std.Io.Writer,
    ) !StreamingExchangeResult {
        if (!std.mem.eql(u8, operation, "operations.audit.export")) {
            return error.InvalidRoutePolicy;
        }
        var prepared = try self.prepareForward(allocator, io, request, request_id, operation);
        defer prepared.deinit();
        if (try self.backend.streamExchange(allocator, io, prepared.request, http_writer)) |result| {
            return result;
        }
        return .{ .fallback = try self.backend.exchange(allocator, io, prepared.request) };
    }

    fn prepareForward(
        self: Handler,
        allocator: Allocator,
        io: Io,
        request: *const http.Request,
        request_id: []const u8,
        operation: []const u8,
    ) !PreparedForward {
        const policy = policyFor(operation) orelse return error.InvalidRoutePolicy;
        if (policy.origin) {
            const supplied = request.header("Origin") orelse return error.OriginRequired;
            if (!std.mem.eql(u8, supplied, self.public_https_origin)) return error.OriginForbidden;
        }
        if (policy.csrf and request.header("X-CSRF-Token") == null) return error.CsrfRequired;
        if (policy.idempotency and request.header("Idempotency-Key") == null) return error.IdempotencyRequired;
        if (policy.if_match and request.header("If-Match") == null) return error.PreconditionRequired;

        if ((request.method == .GET or request.method == .HEAD) and request.body.len != 0) {
            return error.UnexpectedRequestBody;
        }
        if (request.body.len != 0 and !isJsonContentType(request.header("Content-Type") orelse
            return error.UnsupportedMediaType)) return error.UnsupportedMediaType;

        var body_parsed: ?std.json.Parsed(std.json.Value) = null;
        errdefer if (body_parsed) |*parsed| {
            wipeJsonValue(&parsed.value);
            parsed.deinit();
        };
        if (request.body.len != 0) {
            body_parsed = std.json.parseFromSlice(std.json.Value, allocator, request.body, .{
                .duplicate_field_behavior = .@"error",
                .allocate = .alloc_always,
            }) catch return error.InvalidJsonBody;
            if (body_parsed.?.value != .object) return error.InvalidJsonBody;
        }

        const session_token = try extractSessionToken(request.header("Cookie"));
        const user_agent = request.header("User-Agent");
        if (user_agent) |value| if (value.len > service_ipc.maximum_user_agent_bytes) {
            return error.InvalidUserAgent;
        };

        var payload_object: std.json.ObjectMap = .{};
        errdefer payload_object.deinit(allocator);
        try payload_object.put(allocator, "method", .{ .string = request.method.text() });
        try payload_object.put(allocator, "target", .{ .string = request.target });
        try payload_object.put(allocator, "proxyPeer", .{ .string = "loopback" });
        try payload_object.put(allocator, "body", if (body_parsed) |parsed| parsed.value else .null);
        if (session_token) |value| try payload_object.put(allocator, "sessionToken", .{ .string = value });
        if (request.header("Origin")) |value| try payload_object.put(allocator, "origin", .{ .string = value });
        if (request.header("X-CSRF-Token")) |value| try payload_object.put(allocator, "csrfToken", .{ .string = value });
        if (user_agent) |value| try payload_object.put(allocator, "userAgent", .{ .string = value });

        const now_ms = Io.Clock.real.now(io).toMilliseconds();
        const deadline_ms = std.math.add(i64, now_ms, service_timeout_ms) catch std.math.maxInt(i64);
        const service_request: service_ipc.Request = .{
            .version = service_ipc.protocol_version,
            .request_id = request_id,
            .deadline_unix_ms = deadline_ms,
            .operation = operation,
            // The socket peer is the service. `sessionToken` remains untrusted
            // until ntsrv authenticates it and derives the user/audit actor.
            .actor = .{ .kind = .service, .user_agent = user_agent },
            .preconditions = .{
                .etag = request.header("If-Match"),
                .idempotency_key = request.header("Idempotency-Key"),
                .confirmation = confirmationFromBody(if (body_parsed) |parsed| parsed.value else null),
            },
            .payload = .{ .object = payload_object },
        };
        service_ipc.validateRequest(service_request) catch |failure| switch (failure) {
            error.InvalidPrecondition, error.InvalidActor => return error.InvalidHttpMetadata,
            else => return error.InvalidRoutePolicy,
        };
        return .{
            .allocator = allocator,
            .body_parsed = body_parsed,
            .payload_object = payload_object,
            .request = service_request,
        };
    }
};

const PreparedForward = struct {
    allocator: Allocator,
    body_parsed: ?std.json.Parsed(std.json.Value),
    payload_object: std.json.ObjectMap,
    request: service_ipc.Request,

    fn deinit(self: *PreparedForward) void {
        if (self.body_parsed) |*parsed| {
            wipeJsonValue(&parsed.value);
            parsed.deinit();
        }
        self.payload_object.deinit(self.allocator);
        self.* = undefined;
    }
};

fn prepareBootstrapRedemption(
    allocator: Allocator,
    io: Io,
    request: *const http.Request,
    request_id: []const u8,
) !PreparedForward {
    var body_parsed = std.json.parseFromSlice(std.json.Value, allocator, request.body, .{
        .duplicate_field_behavior = .@"error",
        .allocate = .alloc_always,
    }) catch return error.InvalidBootstrapRequest;
    errdefer {
        wipeJsonValue(&body_parsed.value);
        body_parsed.deinit();
    }
    if (body_parsed.value != .object or body_parsed.value.object.count() != 2) {
        return error.InvalidBootstrapRequest;
    }
    const bootstrap_id = body_parsed.value.object.get("bootstrapId") orelse
        return error.InvalidBootstrapRequest;
    const secret_code = body_parsed.value.object.get("secretCode") orelse
        return error.InvalidBootstrapRequest;
    if (bootstrap_id != .string or !isBootstrapId(bootstrap_id.string) or
        secret_code != .string or !isBootstrapSecretCode(secret_code.string))
    {
        return error.InvalidBootstrapRequest;
    }
    const user_agent = request.header("User-Agent");
    if (user_agent) |value| if (value.len > service_ipc.maximum_user_agent_bytes) {
        return error.InvalidBootstrapRequest;
    };

    var payload_object: std.json.ObjectMap = .{};
    errdefer payload_object.deinit(allocator);
    try payload_object.put(allocator, "method", .{ .string = request.method.text() });
    try payload_object.put(allocator, "target", .{ .string = request.target });
    try payload_object.put(allocator, "proxyPeer", .{ .string = "loopback" });
    try payload_object.put(allocator, "body", body_parsed.value);
    if (user_agent) |value| try payload_object.put(allocator, "userAgent", .{ .string = value });

    const now_ms = Io.Clock.real.now(io).toMilliseconds();
    const deadline_ms = std.math.add(i64, now_ms, service_timeout_ms) catch std.math.maxInt(i64);
    const service_request: service_ipc.Request = .{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .deadline_unix_ms = deadline_ms,
        .operation = "enrollment.bootstrap.redeem",
        .actor = .{ .kind = .service, .user_agent = user_agent },
        .preconditions = .{},
        .payload = .{ .object = payload_object },
    };
    service_ipc.validateRequest(service_request) catch return error.InvalidBootstrapRequest;
    return .{
        .allocator = allocator,
        .body_parsed = body_parsed,
        .payload_object = payload_object,
        .request = service_request,
    };
}

const PartialBootstrapRedemption = struct {
    schemaVersion: u16,
    bootstrapId: []const u8,
    nodeName: []const u8,
    masterEndpoint: []const u8,
    expiresAt: []const u8,
    enrollmentCredential: []const u8,
};

fn attachBootstrapArchives(
    allocator: Allocator,
    response: *OwnedHttpResponse,
    manifest: bootstrap_assets.Manifest,
) !void {
    var wiping_allocator: WipingAllocator = .{ .child = allocator };
    const secret_allocator = wiping_allocator.allocator();
    var parsed = std.json.parseFromSlice(PartialBootstrapRedemption, secret_allocator, response.body, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidServiceResponse;
    defer parsed.deinit();
    const value = parsed.value;
    if (value.schemaVersion != 1 or !isBootstrapId(value.bootstrapId) or
        value.nodeName.len == 0 or value.nodeName.len > 63 or
        value.masterEndpoint.len == 0 or value.masterEndpoint.len > 272 or
        value.expiresAt.len != 20 or value.enrollmentCredential.len != 122 or
        !std.mem.startsWith(u8, value.enrollmentCredential, "ntip-enroll-v1."))
    {
        return error.InvalidServiceResponse;
    }

    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer {
        std.crypto.secureZero(u8, output.written());
        output.deinit();
    }
    var json: std.json.Stringify = .{ .writer = &output.writer, .options = .{} };
    try json.beginObject();
    try json.objectField("schemaVersion");
    try json.write(value.schemaVersion);
    try json.objectField("bootstrapId");
    try json.write(value.bootstrapId);
    try json.objectField("nodeName");
    try json.write(value.nodeName);
    try json.objectField("masterEndpoint");
    try json.write(value.masterEndpoint);
    try json.objectField("expiresAt");
    try json.write(value.expiresAt);
    try json.objectField("enrollmentCredential");
    try json.write(value.enrollmentCredential);
    try json.objectField("archives");
    try json.beginArray();
    for (manifest.archives) |archive| {
        var path_storage: [224]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_storage, "/enrollment/assets/{s}", .{archive.file});
        try json.beginObject();
        try json.objectField("version");
        try json.write(manifest.version);
        try json.objectField("target");
        try json.write(archive.target);
        try json.objectField("path");
        try json.write(path);
        try json.objectField("sha256");
        try json.write(archive.sha256);
        try json.objectField("sizeBytes");
        try json.write(archive.size_bytes);
        try json.endObject();
    }
    try json.endArray();
    try json.endObject();
    if (output.written().len > http.maximum_buffered_response_body_bytes) {
        return error.InvalidServiceResponse;
    }
    const replacement = try output.toOwnedSlice();
    std.crypto.secureZero(u8, response.body);
    allocator.free(response.body);
    response.body = replacement;
}

fn replaceBootstrapPublicFailure(
    allocator: Allocator,
    request_id: []const u8,
    response: *OwnedHttpResponse,
) !void {
    const details: struct { []const u8, []const u8, http.Status } = switch (response.status) {
        .bad_request, .payload_too_large, .unsupported_media_type => .{ "invalid_request", "Bootstrap request is invalid.", response.status },
        .not_found => .{ "bootstrap_unavailable", "Bootstrap invitation is unavailable.", .not_found },
        .too_many_requests => .{ "rate_limited", "Bootstrap redemption is temporarily rate limited.", .too_many_requests },
        else => .{ "service_unavailable", "Bootstrap service is unavailable.", .service_unavailable },
    };
    const replacement = try encodeBootstrapError(allocator, request_id, details[0], details[1]);
    errdefer allocator.free(replacement);
    const content_type = try allocator.dupe(u8, "application/json; charset=utf-8");
    std.crypto.secureZero(u8, response.body);
    allocator.free(response.body);
    response.body = replacement;
    allocator.free(response.content_type);
    response.content_type = content_type;
    clearBootstrapResponseMetadata(response);
    response.status = details[2];
    response.retry_after_seconds = switch (response.status) {
        .too_many_requests, .service_unavailable => 1,
        else => null,
    };
}

fn clearBootstrapResponseMetadata(response: *OwnedHttpResponse) void {
    if (response.etag) |value| response.allocator.free(value);
    response.etag = null;
    if (response.location) |value| response.allocator.free(value);
    response.location = null;
    if (response.content_disposition) |value| response.allocator.free(value);
    response.content_disposition = null;
    if (response.audit_export_id) |value| response.allocator.free(value);
    response.audit_export_id = null;
    if (response.set_cookie) |value| {
        std.crypto.secureZero(u8, value);
        response.allocator.free(value);
    }
    response.set_cookie = null;
    if (response.allow) |value| response.allocator.free(value);
    response.allow = null;
}

fn encodeBootstrapError(
    allocator: Allocator,
    request_id: []const u8,
    code: []const u8,
    message: []const u8,
) ![]u8 {
    if (!api_error.isIdentifier(request_id)) return error.InvalidRequestId;
    return std.json.Stringify.valueAlloc(allocator, .{
        .@"error" = .{ .code = code, .message = message },
        .requestId = request_id,
    }, .{});
}

fn renderInstallerScript(
    allocator: Allocator,
    bootstrap_id: []const u8,
    public_origin: []const u8,
    spki_pin: []const u8,
    manifest: bootstrap_assets.Manifest,
) ![]u8 {
    const x86 = bootstrap_assets.archiveFor(manifest, .x86_64_linux_musl);
    const arm = bootstrap_assets.archiveFor(manifest, .aarch64_linux_musl);
    var x86_path_storage: [224]u8 = undefined;
    var arm_path_storage: [224]u8 = undefined;
    var x86_size_storage: [32]u8 = undefined;
    var arm_size_storage: [32]u8 = undefined;
    const x86_path = try std.fmt.bufPrint(&x86_path_storage, "/enrollment/assets/{s}", .{x86.file});
    const arm_path = try std.fmt.bufPrint(&arm_path_storage, "/enrollment/assets/{s}", .{arm.file});
    const x86_size = try std.fmt.bufPrint(&x86_size_storage, "{d}", .{x86.size_bytes});
    const arm_size = try std.fmt.bufPrint(&arm_size_storage, "{d}", .{arm.size_bytes});

    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    var cursor: usize = 0;
    var replacements: usize = 0;
    while (std.mem.indexOf(u8, bootstrap_installer_template[cursor..], "@NTIP_")) |relative_start| {
        const start = cursor + relative_start;
        try output.writer.writeAll(bootstrap_installer_template[cursor..start]);
        const marker_tail = bootstrap_installer_template[start + 1 ..];
        const relative_end = std.mem.indexOfScalar(u8, marker_tail, '@') orelse
            return error.InvalidBootstrapManifest;
        const end = start + 1 + relative_end + 1;
        const marker = bootstrap_installer_template[start..end];
        const replacement = installerTemplateValue(
            marker,
            bootstrap_id,
            public_origin,
            spki_pin,
            manifest.version,
            x86_path,
            x86.sha256,
            x86_size,
            arm_path,
            arm.sha256,
            arm_size,
        ) orelse return error.InvalidBootstrapManifest;
        try output.writer.writeAll(replacement);
        replacements += 1;
        cursor = end;
    }
    try output.writer.writeAll(bootstrap_installer_template[cursor..]);
    if (replacements != 10 or output.written().len == 0 or output.written().len > 65_536 or
        std.mem.indexOf(u8, output.written(), "@NTIP_") != null or
        !std.mem.endsWith(u8, output.written(), "\nmain \"$@\"\n"))
    {
        return error.InvalidBootstrapManifest;
    }
    return output.toOwnedSlice();
}

fn installerTemplateValue(
    marker: []const u8,
    bootstrap_id: []const u8,
    public_origin: []const u8,
    spki_pin: []const u8,
    version: []const u8,
    x86_path: []const u8,
    x86_sha256: []const u8,
    x86_size: []const u8,
    arm_path: []const u8,
    arm_sha256: []const u8,
    arm_size: []const u8,
) ?[]const u8 {
    if (std.mem.eql(u8, marker, "@NTIP_BOOTSTRAP_ID@")) return bootstrap_id;
    if (std.mem.eql(u8, marker, "@NTIP_PUBLIC_HTTPS_ORIGIN@")) return public_origin;
    if (std.mem.eql(u8, marker, "@NTIP_BOOTSTRAP_SPKI_PIN@")) return spki_pin;
    if (std.mem.eql(u8, marker, "@NTIP_NODE_VERSION@")) return version;
    if (std.mem.eql(u8, marker, "@NTIP_X86_64_ARCHIVE_PATH@")) return x86_path;
    if (std.mem.eql(u8, marker, "@NTIP_X86_64_ARCHIVE_SHA256@")) return x86_sha256;
    if (std.mem.eql(u8, marker, "@NTIP_X86_64_ARCHIVE_SIZE@")) return x86_size;
    if (std.mem.eql(u8, marker, "@NTIP_AARCH64_ARCHIVE_PATH@")) return arm_path;
    if (std.mem.eql(u8, marker, "@NTIP_AARCH64_ARCHIVE_SHA256@")) return arm_sha256;
    if (std.mem.eql(u8, marker, "@NTIP_AARCH64_ARCHIVE_SIZE@")) return arm_size;
    return null;
}

/// `alloc_always` gives the HTTP edge an independent strict JSON tree, but it
/// may contain passwords and one-time credentials. Wipe every owned string
/// (including unknown-field names) before returning those allocations to the
/// general-purpose worker allocator.
fn wipeJsonValue(value: *std.json.Value) void {
    switch (value.*) {
        .number_string => |text| std.crypto.secureZero(u8, @constCast(text)),
        .string => |text| std.crypto.secureZero(u8, @constCast(text)),
        .array => |array| for (array.items) |*item| wipeJsonValue(item),
        .object => |object_value| {
            var object = object_value;
            var iterator = object.iterator();
            while (iterator.next()) |entry| {
                std.crypto.secureZero(u8, @constCast(entry.key_ptr.*));
                wipeJsonValue(entry.value_ptr);
            }
        },
        else => {},
    }
}

/// `service_ipc.decodeResponseFrame` uses `alloc_always`, so every text slice
/// in this frame is owned by its parsed arena. Response payloads can contain
/// login cookies and CSRF values, enrollment credentials, temporary
/// passwords, and session material; scrub the complete decoded tree before
/// releasing the arena.
fn wipeDecodedResponseFrame(frame: *service_ipc.ResponseFrame) void {
    std.crypto.secureZero(u8, @constCast(frame.request_id));
    if (frame.payload) |*payload| wipeJsonValue(payload);
    if (frame.@"error") |*failure| {
        std.crypto.secureZero(u8, @constCast(failure.message));
        if (failure.violations) |violations| for (violations) |violation| {
            std.crypto.secureZero(u8, @constCast(violation.field));
            std.crypto.secureZero(u8, @constCast(violation.code));
            std.crypto.secureZero(u8, @constCast(violation.message));
        };
        if (failure.metadata) |*metadata| {
            if (metadata.etag) |value| std.crypto.secureZero(u8, @constCast(value));
        }
    }
}

fn encodeServiceError(
    allocator: Allocator,
    request_id: []const u8,
    failure: service_ipc.ErrorBody,
) ![]u8 {
    if (failure.violations) |violations| {
        return api_error.encodeWithViolations(
            allocator,
            request_id,
            failure.code,
            failure.message,
            violations,
        );
    }
    return api_error.encode(allocator, request_id, failure.code, failure.message);
}

/// The strict second parse of a service HTTP payload also uses
/// `alloc_always`. These slices are therefore independent allocations rather
/// than borrowed literals and can be wiped safely before `Parsed.deinit`.
fn wipeDecodedHttpResponseFrame(frame: *ServiceHttpResponseFrame) void {
    inline for (&.{
        &frame.contentType,
        &frame.bodyChunk,
        &frame.etag,
        &frame.location,
        &frame.contentDisposition,
        &frame.auditExportId,
        &frame.setCookie,
    }) |field| {
        if (field.*) |text| std.crypto.secureZero(u8, @constCast(text));
    }
}

/// Ensures JSON scanners, partially constructed parsed arenas, response
/// chunks replaced during list growth, and successful parsed arenas are all
/// scrubbed even when decoding exits through an error path.
const WipingAllocator = struct {
    child: Allocator,

    fn allocator(self: *WipingAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocate,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn allocate(
        raw: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(raw));
        return self.child.rawAlloc(len, alignment, return_address);
    }

    fn resize(
        raw: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *WipingAllocator = @ptrCast(@alignCast(raw));
        if (new_len < memory.len) std.crypto.secureZero(u8, memory[new_len..]);
        return self.child.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(
        _: *anyopaque,
        _: []u8,
        _: std.mem.Alignment,
        _: usize,
        _: usize,
    ) ?[*]u8 {
        // Force Allocator's allocate/copy/free fallback so the old block is
        // scrubbed instead of being released by an opaque remap operation.
        return null;
    }

    fn free(
        raw: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(raw));
        std.crypto.secureZero(u8, memory);
        self.child.rawFree(memory, alignment, return_address);
    }
};

pub const RoutePolicy = struct {
    origin: bool = false,
    csrf: bool = false,
    idempotency: bool = false,
    if_match: bool = false,
};

const RouteDefinition = struct {
    route: http.Route,
    policy: RoutePolicy = .{},
};

const unsafe_post: RoutePolicy = .{ .origin = true, .csrf = true, .idempotency = true };
const unsafe_post_etag: RoutePolicy = .{ .origin = true, .csrf = true, .idempotency = true, .if_match = true };
const unsafe_etag: RoutePolicy = .{ .origin = true, .csrf = true, .if_match = true };

const route_definitions = [_]RouteDefinition{
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/health/live", .operation = "health.live" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/health/ready", .operation = "health.ready" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/openapi.json", .operation = "contract.openapi" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/auth/login", .operation = "auth.login" }, .policy = .{ .origin = true, .idempotency = true } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/auth/me", .operation = "auth.me" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/auth/reauth", .operation = "auth.reauthenticate" }, .policy = unsafe_post },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/auth/change-password", .operation = "auth.password.change" }, .policy = unsafe_post },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/auth/logout", .operation = "auth.logout" }, .policy = unsafe_post },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/overview", .operation = "overview.read" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/topology", .operation = "topology.read" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/runtime/nodes", .operation = "runtime.nodes.list" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/vnrs", .operation = "inventory.vnrs.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/vnrs", .operation = "inventory.vnr.create" }, .policy = unsafe_post },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/vnrs/{name}", .operation = "inventory.vnr.read" } },
    .{ .route = .{ .method = .PATCH, .pattern = "/api/v1/vnrs/{name}", .operation = "inventory.vnr.update" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .DELETE, .pattern = "/api/v1/vnrs/{name}", .operation = "inventory.vnr.delete" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/nodes", .operation = "inventory.nodes.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/nodes", .operation = "inventory.node.create" }, .policy = unsafe_post },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/nodes/actions/bootstrap", .operation = "enrollment.bootstrap.create_node" }, .policy = unsafe_post },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/nodes/{id}", .operation = "inventory.node.read" } },
    .{ .route = .{ .method = .PATCH, .pattern = "/api/v1/nodes/{id}", .operation = "inventory.node.update" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .DELETE, .pattern = "/api/v1/nodes/{id}", .operation = "inventory.node.delete" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/routes", .operation = "inventory.routes.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/routes", .operation = "inventory.route.create" }, .policy = unsafe_post },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/routes/{id}", .operation = "inventory.route.read" } },
    .{ .route = .{ .method = .PATCH, .pattern = "/api/v1/routes/{id}", .operation = "inventory.route.update" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .DELETE, .pattern = "/api/v1/routes/{id}", .operation = "inventory.route.delete" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/enrollment/bootstrap-config", .operation = "enrollment.bootstrap.config" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/nodes/{id}/enrollment-bootstrap", .operation = "enrollment.bootstrap.replace" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .DELETE, .pattern = "/api/v1/nodes/{id}/enrollment-bootstrap", .operation = "enrollment.bootstrap.revoke" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/nodes/{id}/actions/reset-enrollment", .operation = "enrollment.bootstrap.reset" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/connectivity-checks", .operation = "diagnostics.checks.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/connectivity-checks", .operation = "diagnostics.check.create" }, .policy = unsafe_post },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/connectivity-checks/{id}", .operation = "diagnostics.check.read" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/events", .operation = "operations.events.list" } },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/audit", .operation = "operations.audit.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/audit/export", .operation = "operations.audit.export" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/audit/prune", .operation = "operations.audit.prune" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/users", .operation = "security.users.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/users", .operation = "security.user.create" }, .policy = unsafe_post },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/users/{id}", .operation = "security.user.read" } },
    .{ .route = .{ .method = .PATCH, .pattern = "/api/v1/users/{id}", .operation = "security.user.update" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .DELETE, .pattern = "/api/v1/users/{id}", .operation = "security.user.tombstone" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/users/{id}/password-reset", .operation = "security.user.password_reset" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/sessions", .operation = "security.sessions.list" } },
    .{ .route = .{ .method = .DELETE, .pattern = "/api/v1/sessions/{id}", .operation = "security.session.revoke" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/settings", .operation = "settings.read" } },
    .{ .route = .{ .method = .PATCH, .pattern = "/api/v1/settings", .operation = "settings.update" }, .policy = unsafe_etag },
    .{ .route = .{ .method = .GET, .pattern = "/api/v1/settings/revisions", .operation = "settings.revisions.list" } },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/settings/revisions/{id}/rollback", .operation = "settings.rollback" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/operations/restart", .operation = "service.restart" }, .policy = unsafe_post_etag },
    .{ .route = .{ .method = .POST, .pattern = "/api/v1/operations/shutdown", .operation = "service.shutdown" }, .policy = unsafe_post_etag },
};

const routes = routeArray();
const router = blk: {
    @setEvalBranchQuota(1_000_000);
    break :blk http.Router.init(&routes) catch unreachable;
};

fn routeArray() [route_definitions.len]http.Route {
    var result: [route_definitions.len]http.Route = undefined;
    for (route_definitions, 0..) |definition, index| result[index] = definition.route;
    return result;
}

const PublicBootstrapRoute = union(enum) {
    installer: []const u8,
    redeem,
};

fn publicBootstrapRoute(request: *const http.Request) ?PublicBootstrapRoute {
    if (std.mem.eql(u8, request.target, "/enrollment/v1/redeem")) return .redeem;
    const prefix = "/enrollment/";
    if (!std.mem.startsWith(u8, request.target, prefix)) return null;
    const bootstrap_id = request.target[prefix.len..];
    if (!isBootstrapId(bootstrap_id)) return null;
    return .{ .installer = bootstrap_id };
}

fn isBootstrapId(value: []const u8) bool {
    if (value.len != 8) return false;
    for (value) |byte| if (std.mem.indexOfScalar(u8, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", byte) == null) {
        return false;
    };
    return true;
}

fn isBootstrapSecretCode(value: []const u8) bool {
    if (value.len != 11 or value[3] != '-' or value[7] != '-') return false;
    for (value, 0..) |byte, index| {
        if (index == 3 or index == 7) continue;
        if (std.mem.indexOfScalar(u8, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789", byte) == null) {
            return false;
        }
    }
    return true;
}

pub fn policyFor(operation: []const u8) ?RoutePolicy {
    for (route_definitions) |definition| {
        if (std.mem.eql(u8, definition.route.operation, operation)) return definition.policy;
    }
    return null;
}

pub fn canonicalRoutes() []const http.Route {
    return &routes;
}

fn confirmationFromBody(value: ?std.json.Value) ?[]const u8 {
    const body = value orelse return null;
    if (body != .object) return null;
    const confirmation = body.object.get("confirmation") orelse return null;
    return if (confirmation == .string) confirmation.string else null;
}

fn extractSessionToken(cookie_header: ?[]const u8) !?[]const u8 {
    const header = cookie_header orelse return null;
    var found: ?[]const u8 = null;
    var cookies = std.mem.splitScalar(u8, header, ';');
    while (cookies.next()) |raw| {
        const cookie = std.mem.trim(u8, raw, " \t");
        const equals = std.mem.indexOfScalar(u8, cookie, '=') orelse continue;
        const name = std.mem.trim(u8, cookie[0..equals], " \t");
        if (!std.mem.eql(u8, name, "__Host-ntip_session")) continue;
        if (found != null) return error.DuplicateSessionCookie;
        const value = cookie[equals + 1 ..];
        if (!isLowerHex(value, auth.session_token_text_len)) return error.InvalidSessionCookie;
        found = value;
    }
    return found;
}

fn isLowerHex(value: []const u8, exact_length: usize) bool {
    if (value.len != exact_length) return false;
    for (value) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn isJsonContentType(value: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(value, "application/json")) return true;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, value, " \t"), "application/json; charset=utf-8");
}

fn validateServiceResponseMetadata(payload: ServiceHttpResponseFrame) !void {
    if (payload.contentType) |value| {
        if (value.len == 0 or value.len > 256 or !isSafeHeaderValue(value)) return error.InvalidServiceResponse;
    }
    if (payload.etag) |value| {
        if (value.len == 0 or value.len > service_ipc.maximum_etag_bytes or !isSafeHeaderValue(value)) {
            return error.InvalidServiceResponse;
        }
    }
    if (payload.location) |value| {
        if (value.len == 0 or value.len > http.maximum_target_bytes or !isSafeHeaderValue(value)) {
            return error.InvalidServiceResponse;
        }
    }
    if (payload.contentDisposition) |value| {
        if (value.len == 0 or value.len > 512 or !isSafeHeaderValue(value)) {
            return error.InvalidServiceResponse;
        }
    }
    if (payload.auditExportId) |value| {
        if (!api_error.isIdentifier(value)) return error.InvalidServiceResponse;
    }
    if (payload.setCookie) |value| {
        if (value.len == 0 or value.len > 4096 or !isSafeHeaderValue(value) or
            !std.mem.startsWith(u8, value, "__Host-ntip_session=") or
            std.mem.indexOf(u8, value, "; Secure") == null or
            std.mem.indexOf(u8, value, "; HttpOnly") == null or
            std.mem.indexOf(u8, value, "; SameSite=Strict") == null or
            std.mem.indexOf(u8, value, "; Path=/") == null)
        {
            return error.InvalidServiceResponse;
        }
    }
}

fn validateAuditStreamingMetadata(payload: ServiceHttpResponseFrame) !void {
    try validateServiceResponseMetadata(payload);
    if (payload.status != 200 or
        payload.contentType == null or
        !std.mem.eql(u8, payload.contentType.?, "application/x-ndjson") or
        payload.contentDisposition == null or
        payload.auditExportId == null or
        payload.etag != null or
        payload.location != null or
        payload.retryAfterSeconds != null or
        payload.setCookie != null)
    {
        return error.InvalidServiceResponse;
    }
    var expected_storage: [96]u8 = undefined;
    const expected = std.fmt.bufPrint(
        &expected_storage,
        "attachment; filename=\"ntip-audit-{s}.ndjson\"",
        .{payload.auditExportId.?},
    ) catch return error.InvalidServiceResponse;
    if (!std.mem.eql(u8, payload.contentDisposition.?, expected)) {
        return error.InvalidServiceResponse;
    }
}

fn isSafeHeaderValue(value: []const u8) bool {
    for (value) |byte| if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return false;
    return true;
}

fn statusFromInt(value: u16) ?http.Status {
    return switch (value) {
        200 => .ok,
        201 => .created,
        202 => .accepted,
        204 => .no_content,
        400 => .bad_request,
        401 => .unauthorized,
        403 => .forbidden,
        404 => .not_found,
        405 => .method_not_allowed,
        409 => .conflict,
        412 => .precondition_failed,
        413 => .payload_too_large,
        415 => .unsupported_media_type,
        428 => .precondition_required,
        429 => .too_many_requests,
        500 => .internal_server_error,
        503 => .service_unavailable,
        else => null,
    };
}

pub const ResponseSequence = struct {
    request_id: []const u8,
    next_sequence: u32 = 0,
    terminal: bool = false,

    pub fn init(request_id: []const u8) ResponseSequence {
        return .{ .request_id = request_id };
    }

    pub fn accept(self: *ResponseSequence, frame: service_ipc.ResponseFrame) !void {
        if (self.terminal or !std.mem.eql(u8, frame.request_id, self.request_id) or
            frame.sequence != self.next_sequence)
        {
            return error.InvalidServiceResponse;
        }
        self.next_sequence = std.math.add(u32, self.next_sequence, 1) catch
            return error.InvalidServiceResponse;
        self.terminal = frame.final;
    }
};

fn readFrameTimeout(io: Io, stream: Io.net.Stream, storage: []u8, timeout: Io.Timeout) ![]u8 {
    var prefix: [service_ipc.frame_prefix_bytes]u8 = undefined;
    try readExactTimeout(io, stream, &prefix, timeout);
    const length = try service_ipc.decodeLength(&prefix);
    if (length > storage.len) return error.DestinationTooSmall;
    try readExactTimeout(io, stream, storage[0..length], timeout);
    return storage[0..length];
}

fn readExactTimeout(io: Io, stream: Io.net.Stream, destination: []u8, timeout: Io.Timeout) !void {
    var offset: usize = 0;
    while (offset < destination.len) {
        const message = try stream.socket.receiveTimeout(io, destination[offset..], timeout);
        if (message.data.len == 0) return error.EndOfStream;
        offset += message.data.len;
    }
}

fn installSocketDeadlines(handle: std.Io.net.Socket.Handle, seconds: i64) !void {
    if (comptime builtin.os.tag != .linux) return;
    const linux = std.os.linux;
    const timeout: linux.timeval = .{ .sec = seconds, .usec = 0 };
    try std.posix.setsockopt(handle, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try std.posix.setsockopt(handle, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&timeout));
}

pub const WorkerQueue = struct {
    allocator: Allocator,
    io: Io,
    buffer: []Io.net.Stream,
    head: usize = 0,
    tail: usize = 0,
    count: usize = 0,
    closed: bool = false,
    mutex: Io.Mutex = .init,
    condition: Io.Condition = .init,

    pub fn init(allocator: Allocator, io: Io, capacity: usize) !WorkerQueue {
        if (capacity == 0) return error.InvalidQueueCapacity;
        return .{
            .allocator = allocator,
            .io = io,
            .buffer = try allocator.alloc(Io.net.Stream, capacity),
        };
    }

    pub fn deinit(self: *WorkerQueue) void {
        self.allocator.free(self.buffer);
        self.* = undefined;
    }

    pub fn push(self: *WorkerQueue, stream: Io.net.Stream) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.closed or self.count == self.buffer.len) return false;
        self.buffer[self.tail] = stream;
        self.tail = (self.tail + 1) % self.buffer.len;
        self.count += 1;
        self.condition.signal(self.io);
        return true;
    }

    pub fn pop(self: *WorkerQueue) ?Io.net.Stream {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        while (self.count == 0 and !self.closed) {
            self.condition.waitUncancelable(self.io, &self.mutex);
        }
        if (self.count == 0) return null;
        const stream = self.buffer[self.head];
        self.head = (self.head + 1) % self.buffer.len;
        self.count -= 1;
        return stream;
    }

    pub fn close(self: *WorkerQueue) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.closed = true;
        self.condition.broadcast(self.io);
    }
};

const WorkerContext = struct {
    allocator: Allocator,
    io: Io,
    queue: *WorkerQueue,
    handler: *const Handler,
    active_connections: *std.atomic.Value(u32),
};

/// Starts the production listener. `config` must come from `api_config.decode`;
/// validation is repeated so direct callers cannot widen the bind. `allocator`
/// must support concurrent allocation and reclamation from every HTTP worker;
/// a process-lifetime arena is not suitable.
pub fn serve(
    allocator: Allocator,
    io: Io,
    config: api_config.Config,
    openapi: OpenApiProvider,
) !void {
    try api_config.validate(config);
    const manifest_bytes = try api_config.readManifestFile(
        allocator,
        io,
        config.bootstrap_manifest_path,
        bootstrap_assets.maximum_manifest_bytes,
    );
    defer allocator.free(manifest_bytes);
    const parsed_manifest = try bootstrap_assets.decode(allocator, manifest_bytes);
    defer parsed_manifest.deinit();
    var address = try Io.net.IpAddress.parse(config.bind_address, config.port);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var unix_backend: UnixBackend = .{ .socket_path = config.service_socket };
    var anonymous_redemptions = std.atomic.Value(u32).init(0);
    const handler: Handler = .{
        .public_https_origin = config.public_https_origin,
        .bootstrap_spki_pin = config.bootstrap_spki_pin,
        .bootstrap_manifest = parsed_manifest.value,
        .anonymous_redemptions = &anonymous_redemptions,
        .openapi = openapi,
        .backend = unix_backend.backend(),
    };
    return serveAccepted(allocator, io, config, &handler, &listener);
}

fn serveAccepted(
    allocator: Allocator,
    io: Io,
    config: api_config.Config,
    handler: *const Handler,
    listener: *Io.net.Server,
) !void {
    var queue = try WorkerQueue.init(allocator, io, config.maximum_connections);
    defer queue.deinit();
    var active_connections = std.atomic.Value(u32).init(0);
    const worker_count: usize = @intCast(config.workers);
    const threads = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(threads);
    const contexts = try allocator.alloc(WorkerContext, worker_count);
    defer allocator.free(contexts);

    var started: usize = 0;
    errdefer {
        queue.close();
        for (threads[0..started]) |thread| thread.join();
    }
    for (contexts, 0..) |*context, index| {
        context.* = .{
            .allocator = allocator,
            .io = io,
            .queue = &queue,
            .handler = handler,
            .active_connections = &active_connections,
        };
        threads[index] = try std.Thread.spawn(.{
            .allocator = allocator,
            .stack_size = worker_stack_bytes,
        }, workerLoop, .{context});
        started += 1;
    }
    defer {
        queue.close();
        for (threads[0..started]) |thread| thread.join();
    }

    while (true) {
        const stream = listener.accept(io) catch |failure| switch (failure) {
            error.ConnectionAborted => continue,
            else => return failure,
        };
        if (!tryAcquireConnection(&active_connections, config.maximum_connections)) {
            sendBusy(io, stream) catch {};
            continue;
        }
        if (!queue.push(stream)) {
            releaseConnection(&active_connections);
            sendBusy(io, stream) catch {};
        }
    }
}

fn workerLoop(context: *WorkerContext) void {
    while (context.queue.pop()) |stream| {
        handleConnection(context.allocator, context.io, stream, context.handler) catch {};
        releaseConnection(context.active_connections);
    }
}

pub fn tryAcquireConnection(active: *std.atomic.Value(u32), maximum: u32) bool {
    var current = active.load(.seq_cst);
    while (current < maximum) {
        if (active.cmpxchgWeak(current, current + 1, .seq_cst, .seq_cst)) |actual| {
            current = actual;
        } else return true;
    }
    return false;
}

pub fn releaseConnection(active: *std.atomic.Value(u32)) void {
    _ = active.fetchSub(1, .seq_cst);
}

const ConnectionReader = struct {
    bytes: [connection_buffer_bytes]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn next(self: *ConnectionReader, io: Io, stream: Io.net.Stream) !http.ParsedRequest {
        const deadline = Io.Clock.Timestamp.fromNow(io, .{
            .raw = Io.Duration.fromMilliseconds(request_timeout_ms),
            .clock = .awake,
        });
        while (true) {
            const parsed = http.parseRequest(self.bytes[self.start..self.end]) catch |failure| switch (failure) {
                error.Incomplete => null,
                else => return failure,
            };
            if (parsed) |value| return value;

            if (self.end == self.bytes.len and self.start != 0) self.compact();
            if (self.end == self.bytes.len) return error.RequestTooLarge;
            const message = try stream.socket.receiveTimeout(
                io,
                self.bytes[self.end..],
                .{ .deadline = deadline },
            );
            if (message.data.len == 0) return error.EndOfStream;
            self.end += message.data.len;
        }
    }

    fn consume(self: *ConnectionReader, count: usize) void {
        std.debug.assert(count <= self.end - self.start);
        // Parsed headers and bodies may contain passwords, cookies, CSRF
        // values, and one-time credentials. Their slices are dead once the
        // response is sent, so wipe the consumed request before retaining the
        // connection for another keep-alive request.
        std.crypto.secureZero(u8, self.bytes[self.start .. self.start + count]);
        self.start += count;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    fn compact(self: *ConnectionReader) void {
        const remaining = self.end - self.start;
        std.mem.copyForwards(u8, self.bytes[0..remaining], self.bytes[self.start..self.end]);
        self.start = 0;
        self.end = remaining;
    }
};

fn handleConnection(allocator: Allocator, io: Io, stream: Io.net.Stream, handler: *const Handler) !void {
    defer stream.close(io);
    try installSocketDeadlines(stream.socket.handle, 15);
    var reader: ConnectionReader = .{};
    defer std.crypto.secureZero(u8, &reader.bytes);
    var served_requests: u32 = 0;

    while (served_requests < maximum_requests_per_connection) {
        var request_id_buffer: [api_error.identifier_text_bytes]u8 = undefined;
        const request_id = generateRequestId(io, &request_id_buffer);
        const parsed = reader.next(io, stream) catch |failure| switch (failure) {
            error.Timeout, error.EndOfStream, error.ConnectionResetByPeer, error.SocketUnconnected => return,
            else => {
                try sendParseFailure(allocator, io, stream, request_id, failure);
                return;
            },
        };
        const current_count = served_requests + 1;
        const close = !parsed.request.wantsKeepAlive(current_count, maximum_requests_per_connection);
        if (isAuditExportRequest(&parsed.request)) {
            var writer_buffer: [8192]u8 = undefined;
            defer std.crypto.secureZero(u8, &writer_buffer);
            var stream_writer = stream.writer(io, &writer_buffer);
            const streamed = handler.forwardStreaming(
                allocator,
                io,
                &parsed.request,
                request_id,
                "operations.audit.export",
                &stream_writer.interface,
            ) catch |failure| {
                var failure_response = try responseForDispatchFailure(
                    allocator,
                    &parsed.request,
                    request_id,
                    failure,
                );
                defer failure_response.deinit();
                try sendOwnedResponse(io, stream, request_id, &failure_response, true);
                return;
            };
            switch (streamed) {
                .fallback => |owned| {
                    var fallback = owned;
                    defer fallback.deinit();
                    try sendOwnedResponse(io, stream, request_id, &fallback, true);
                },
                .completed, .aborted => {},
            }
            // Audit downloads are intentionally one request per connection.
            // This makes a terminal stream failure unambiguous: absence of the
            // zero chunk is observed as a truncated response by the proxy.
            return;
        }
        var response = handler.dispatch(allocator, io, &parsed.request, request_id) catch |failure|
            try responseForDispatchFailure(allocator, &parsed.request, request_id, failure);
        defer response.deinit();
        try sendOwnedResponse(io, stream, request_id, &response, close or response.status == .service_unavailable);
        reader.consume(parsed.consumed);
        served_requests = current_count;
        if (close or response.status == .service_unavailable) return;
    }
}

fn isAuditExportRequest(request: *const http.Request) bool {
    return request.method == .POST and
        std.mem.eql(u8, request.target, "/api/v1/audit/export");
}

fn sendOwnedResponse(
    io: Io,
    stream: Io.net.Stream,
    request_id: []const u8,
    response: *const OwnedHttpResponse,
    close: bool,
) !void {
    var head_storage: [http.maximum_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &head_storage);
    const prepared = try http.prepareResponse(&head_storage, .{
        .status = response.status,
        .body = response.body,
        .content_type = response.content_type,
        .close = close,
        .request_id = request_id,
        .etag = response.etag,
        .allow = response.allow,
        .location = response.location,
        .content_disposition = response.content_disposition,
        .audit_export_id = response.audit_export_id,
        .retry_after_seconds = response.retry_after_seconds,
        .set_cookie = response.set_cookie,
    });
    var cursor = prepared.cursor();
    var writer_buffer: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &writer_buffer);
    var stream_writer = stream.writer(io, &writer_buffer);
    while (!cursor.done()) {
        const part = cursor.next();
        try stream_writer.interface.writeAll(part);
        try cursor.advance(part.len);
    }
    try stream_writer.interface.flush();
}

fn sendBusy(io: Io, stream: Io.net.Stream) !void {
    defer stream.close(io);
    var request_id_buffer: [api_error.identifier_text_bytes]u8 = undefined;
    const request_id = generateRequestId(io, &request_id_buffer);
    var response = try makeErrorResponse(
        std.heap.smp_allocator,
        request_id,
        .service_unavailable,
        "connection limit reached",
        .service_unavailable,
        null,
    );
    defer response.deinit();
    try sendOwnedResponse(io, stream, request_id, &response, true);
}

fn sendParseFailure(
    allocator: Allocator,
    io: Io,
    stream: Io.net.Stream,
    request_id: []const u8,
    failure: anyerror,
) !void {
    var head_storage: [http.maximum_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &head_storage);
    var response = try http.prepareParseErrorResponse(
        allocator,
        &head_storage,
        request_id,
        failure,
        "invalid HTTP request",
    );
    defer response.deinit();
    var writer_buffer: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &writer_buffer);
    var stream_writer = stream.writer(io, &writer_buffer);
    try http.writePrepared(&stream_writer.interface, response.prepared);
}

fn responseForDispatchFailure(
    allocator: Allocator,
    request: *const http.Request,
    request_id: []const u8,
    failure: anyerror,
) !OwnedHttpResponse {
    if (std.mem.startsWith(u8, request.target, "/enrollment/")) {
        return bootstrapResponseForDispatchFailure(allocator, request_id, failure);
    }
    var allowed_storage: [128]u8 = undefined;
    const details: struct { api_error.Code, []const u8, http.Status } = switch (failure) {
        error.RouteNotFound => .{ .not_found, "API route not found", .not_found },
        error.MethodNotAllowed => .{ .invalid_request, "method not allowed", .method_not_allowed },
        error.OriginRequired, error.OriginForbidden => .{ .origin_forbidden, "request origin is not allowed", .forbidden },
        error.CsrfRequired => .{ .csrf_failed, "CSRF token is required", .forbidden },
        error.IdempotencyRequired => .{ .idempotency_required, "Idempotency-Key is required", .bad_request },
        error.PreconditionRequired => .{ .precondition_required, "If-Match is required", .precondition_required },
        error.UnsupportedMediaType => .{ .invalid_request, "application/json is required", .unsupported_media_type },
        error.InvalidJsonBody,
        error.UnexpectedRequestBody,
        error.InvalidSessionCookie,
        error.DuplicateSessionCookie,
        error.InvalidUserAgent,
        error.InvalidHttpMetadata,
        => .{ .invalid_request, "request validation failed", .bad_request },
        error.ServiceUnavailable,
        error.ServiceDeadlineExceeded,
        error.ServiceResponseTooLarge,
        error.TooManyServiceFrames,
        => .{ .service_unavailable, "management service is unavailable", .service_unavailable },
        error.InvalidServiceResponse,
        error.InvalidOpenApiDocument,
        error.InvalidRoutePolicy,
        => .{ .internal_error, "management service returned an invalid response", .internal_server_error },
        error.OutOfMemory => return error.OutOfMemory,
        else => .{ .internal_error, "internal server error", .internal_server_error },
    };
    var allow: ?[]const u8 = null;
    if (failure == error.MethodNotAllowed) {
        const resolution = try router.resolve(request.method, request.target);
        if (resolution == .method_not_allowed) allow = resolution.method_not_allowed.format(&allowed_storage);
    }
    return makeErrorResponse(allocator, request_id, details[0], details[1], details[2], allow);
}

fn bootstrapResponseForDispatchFailure(
    allocator: Allocator,
    request_id: []const u8,
    failure: anyerror,
) !OwnedHttpResponse {
    const details: struct { []const u8, []const u8, http.Status } = switch (failure) {
        error.BootstrapRedemptionBusy => .{ "rate_limited", "Bootstrap redemption is temporarily rate limited.", .too_many_requests },
        error.ServiceUnavailable,
        error.ServiceDeadlineExceeded,
        error.ServiceResponseTooLarge,
        error.TooManyServiceFrames,
        error.InvalidServiceResponse,
        error.InvalidBootstrapManifest,
        => .{ "service_unavailable", "Bootstrap service is unavailable.", .service_unavailable },
        error.RouteNotFound => .{ "bootstrap_unavailable", "Bootstrap invitation is unavailable.", .not_found },
        error.UnsupportedMediaType => .{ "invalid_request", "application/json is required.", .unsupported_media_type },
        error.MethodNotAllowed => .{ "invalid_request", "Method is not allowed.", .method_not_allowed },
        error.InvalidBootstrapRequest,
        error.UnexpectedRequestBody,
        => .{ "invalid_request", "Bootstrap request is invalid.", .bad_request },
        error.OutOfMemory => return error.OutOfMemory,
        else => .{ "service_unavailable", "Bootstrap service is unavailable.", .service_unavailable },
    };
    const body = try encodeBootstrapError(allocator, request_id, details[0], details[1]);
    errdefer allocator.free(body);
    return .{
        .allocator = allocator,
        .status = details[2],
        .body = body,
        .content_type = try allocator.dupe(u8, "application/json; charset=utf-8"),
        .retry_after_seconds = switch (details[2]) {
            .too_many_requests, .service_unavailable => 1,
            else => null,
        },
    };
}

fn makeErrorResponse(
    allocator: Allocator,
    request_id: []const u8,
    code: api_error.Code,
    message: []const u8,
    status: http.Status,
    allow: ?[]const u8,
) !OwnedHttpResponse {
    const body = try api_error.encode(allocator, request_id, code, message);
    errdefer allocator.free(body);
    const content_type = try allocator.dupe(u8, "application/json; charset=utf-8");
    errdefer allocator.free(content_type);
    return .{
        .allocator = allocator,
        .status = status,
        .body = body,
        .content_type = content_type,
        .allow = if (allow) |value| try allocator.dupe(u8, value) else null,
        .retry_after_seconds = switch (status) {
            .too_many_requests, .service_unavailable => 1,
            else => null,
        },
    };
}

pub fn generateRequestId(io: Io, output: *[api_error.identifier_text_bytes]u8) []const u8 {
    var random: [api_error.identifier_text_bytes / 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &random);
    io.random(&random);
    const alphabet = "0123456789abcdef";
    for (random, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

const FakeBackend = struct {
    called: bool = false,

    fn asBackend(self: *FakeBackend) Backend {
        return .{ .context = self, .exchangeFn = exchange };
    }

    fn exchange(
        context: *anyopaque,
        allocator: Allocator,
        _: Io,
        request: service_ipc.Request,
    ) !OwnedHttpResponse {
        const self: *FakeBackend = @ptrCast(@alignCast(context));
        self.called = true;
        try std.testing.expectEqualStrings("inventory.node.update", request.operation);
        try std.testing.expectEqual(service_ipc.ActorKind.service, request.actor.kind);
        try std.testing.expectEqualStrings("\"generation-4\"", request.preconditions.etag.?);
        try std.testing.expectEqualStrings("node-a", request.preconditions.confirmation.?);
        const session = request.payload.object.get("sessionToken") orelse return error.MissingSessionToken;
        try std.testing.expect(session == .string);
        try std.testing.expectEqual(@as(usize, auth.session_token_text_len), session.string.len);
        try std.testing.expectEqualStrings("loopback", request.payload.object.get("proxyPeer").?.string);
        return OwnedHttpResponse.fromStatic(
            allocator,
            .ok,
            "{\"id\":\"11111111111111111111111111111111\"}",
            "application/json; charset=utf-8",
        );
    }
};

const test_bootstrap_archives = [_]bootstrap_assets.Archive{
    .{
        .target = "x86_64-linux-musl",
        .file = "ntip-node-v0.2.0-x86_64-linux-musl.tar.gz",
        .sha256 = "a" ** 64,
        .size_bytes = 1_024,
    },
    .{
        .target = "aarch64-linux-musl",
        .file = "ntip-node-v0.2.0-aarch64-linux-musl.tar.gz",
        .sha256 = "b" ** 64,
        .size_bytes = 2_048,
    },
};

const test_bootstrap_manifest: bootstrap_assets.Manifest = .{
    .schema_version = 1,
    .version = "0.2.0",
    .archives = &test_bootstrap_archives,
};

const BootstrapFakeBackend = struct {
    called: bool = false,

    fn asBackend(self: *BootstrapFakeBackend) Backend {
        return .{ .context = self, .exchangeFn = exchange };
    }

    fn exchange(
        context: *anyopaque,
        allocator: Allocator,
        _: Io,
        request: service_ipc.Request,
    ) !OwnedHttpResponse {
        const self: *BootstrapFakeBackend = @ptrCast(@alignCast(context));
        self.called = true;
        try std.testing.expectEqualStrings("enrollment.bootstrap.redeem", request.operation);
        try std.testing.expect(request.payload.object.get("sessionToken") == null);
        try std.testing.expect(request.payload.object.get("origin") == null);
        const body = request.payload.object.get("body") orelse return error.InvalidBody;
        try std.testing.expectEqualStrings("ABCDEFGH", body.object.get("bootstrapId").?.string);
        try std.testing.expectEqualStrings("ABC-DEF-GHJ", body.object.get("secretCode").?.string);
        return OwnedHttpResponse.fromStatic(
            allocator,
            .ok,
            "{\"schemaVersion\":1,\"bootstrapId\":\"ABCDEFGH\",\"nodeName\":\"node-a\",\"masterEndpoint\":\"192.0.2.1:49152\",\"expiresAt\":\"2026-07-22T19:00:00Z\",\"enrollmentCredential\":\"ntip-enroll-v1." ++ ("A" ** 107) ++ "\"}",
            "application/json; charset=utf-8",
        );
    }
};

test "canonical API route table has all 52 contract operations" {
    try std.testing.expectEqual(@as(usize, 52), canonicalRoutes().len);
    const initialized = try http.Router.init(canonicalRoutes());
    const enrollment = try initialized.resolve(
        .POST,
        "/api/v1/nodes/11111111111111111111111111111111/enrollment-bootstrap",
    );
    try std.testing.expectEqualStrings("enrollment.bootstrap.replace", enrollment.matched.route.operation);
    const create = try initialized.resolve(.POST, "/api/v1/nodes/actions/bootstrap");
    try std.testing.expectEqualStrings("enrollment.bootstrap.create_node", create.matched.route.operation);
    try std.testing.expect(!policyFor("enrollment.bootstrap.create_node").?.if_match);
    try std.testing.expect(policyFor("enrollment.bootstrap.replace").?.if_match);
    const delete_vnr = try initialized.resolve(.DELETE, "/api/v1/vnrs/office");
    try std.testing.expectEqualStrings("inventory.vnr.delete", delete_vnr.matched.route.operation);
    try std.testing.expect(policyFor("operations.audit.prune").?.if_match);
    try std.testing.expect(!policyFor("auth.login").?.csrf);
}

test "handler serves liveness and OpenAPI locally" {
    var fake: FakeBackend = .{};
    const document = FixedDocument{ .bytes = "{\"openapi\":\"3.1.0\"}" };
    const handler: Handler = .{
        .public_https_origin = "https://ntip.example.test",
        .openapi = OpenApiProvider.fromFixedDocument(&document),
        .backend = fake.asBackend(),
    };

    const live_parsed = try http.parseRequest(
        "GET /api/v1/health/live HTTP/1.1\r\nHost: ntip.example.test\r\n\r\n",
    );
    var live = try handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &live_parsed.request,
        "0123456789abcdef0123456789abcdef",
    );
    defer live.deinit();
    try std.testing.expectEqualStrings("{\"status\":\"live\"}", live.body);

    const contract_parsed = try http.parseRequest(
        "GET /api/v1/openapi.json HTTP/1.1\r\nHost: ntip.example.test\r\n\r\n",
    );
    var contract = try handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &contract_parsed.request,
        "0123456789abcdef0123456789abcdef",
    );
    defer contract.deinit();
    try std.testing.expectEqualStrings(document.bytes, contract.body);
    try std.testing.expect(!fake.called);
}

test "handler validates proxy policy and forwards typed session context" {
    var fake: FakeBackend = .{};
    const document = FixedDocument{ .bytes = "{}" };
    const handler: Handler = .{
        .public_https_origin = "https://ntip.example.test",
        .openapi = OpenApiProvider.fromFixedDocument(&document),
        .backend = fake.asBackend(),
    };
    const token = "0000000000000000000000000000000000000000000000000000000000000000";
    const request_bytes =
        "PATCH /api/v1/nodes/11111111111111111111111111111111 HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Origin: https://ntip.example.test\r\n" ++
        "X-CSRF-Token: 1111111111111111111111111111111111111111111111111111111111111111\r\n" ++
        "If-Match: \"generation-4\"\r\n" ++
        "Cookie: other=value; __Host-ntip_session=" ++ token ++ "\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 41\r\n\r\n" ++
        "{\"confirmation\":\"node-a\",\"name\":\"node-b\"}";
    const parsed = try http.parseRequest(request_bytes);
    var response = try handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &parsed.request,
        "0123456789abcdef0123456789abcdef",
    );
    defer response.deinit();
    try std.testing.expect(fake.called);
    try std.testing.expectEqual(http.Status.ok, response.status);

    const wrong_origin_bytes =
        "PATCH /api/v1/nodes/11111111111111111111111111111111 HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Origin: https://evil.example.test\r\n" ++
        "X-CSRF-Token: token\r\n" ++
        "If-Match: \"generation-4\"\r\n" ++
        "Content-Length: 0\r\n\r\n";
    const wrong_origin = try http.parseRequest(wrong_origin_bytes);
    try std.testing.expectError(error.OriginForbidden, handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &wrong_origin.request,
        "0123456789abcdef0123456789abcdef",
    ));
}

test "service response sequence binds request id, order, and finality" {
    const request_id = "0123456789abcdef0123456789abcdef";
    var sequence = ResponseSequence.init(request_id);
    try sequence.accept(.{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .sequence = 0,
        .final = false,
    });
    try std.testing.expectError(error.InvalidServiceResponse, sequence.accept(.{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .sequence = 2,
        .final = true,
    }));
    try sequence.accept(.{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .sequence = 1,
        .final = true,
    });
    try std.testing.expectError(error.InvalidServiceResponse, sequence.accept(.{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .sequence = 2,
        .final = true,
    }));
}

test "admission counter is bounded under contention semantics" {
    var active = std.atomic.Value(u32).init(0);
    try std.testing.expect(tryAcquireConnection(&active, 2));
    try std.testing.expect(tryAcquireConnection(&active, 2));
    try std.testing.expect(!tryAcquireConnection(&active, 2));
    releaseConnection(&active);
    try std.testing.expect(tryAcquireConnection(&active, 2));
    try std.testing.expectEqual(@as(u32, 2), active.load(.seq_cst));
}

test "request identifiers and service peer requirements are exact" {
    var request_id: [api_error.identifier_text_bytes]u8 = undefined;
    try std.testing.expect(api_error.isIdentifier(generateRequestId(std.testing.io, &request_id)));
    const requirement = ServicePeerRequirement{ .expected_api_uid = 991 };
    try std.testing.expect(requirement.accepts(991));
    try std.testing.expect(!requirement.accepts(992));
}

test "audit stream metadata is exact and cannot inject public headers" {
    const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try validateAuditStreamingMetadata(.{
        .status = 200,
        .contentType = "application/x-ndjson",
        .contentDisposition = "attachment; filename=\"ntip-audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ndjson\"",
        .auditExportId = id,
    });
    try std.testing.expectError(error.InvalidServiceResponse, validateAuditStreamingMetadata(.{
        .status = 200,
        .contentType = "application/json",
        .contentDisposition = "attachment; filename=\"ntip-audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ndjson\"",
        .auditExportId = id,
    }));
    try std.testing.expectError(error.InvalidServiceResponse, validateAuditStreamingMetadata(.{
        .status = 200,
        .contentType = "application/x-ndjson",
        .contentDisposition = "attachment; filename=\"other.ndjson\"",
        .auditExportId = id,
    }));
    try std.testing.expectError(error.InvalidServiceResponse, validateAuditStreamingMetadata(.{
        .status = 200,
        .contentType = "application/x-ndjson",
        .contentDisposition = "attachment; filename=\"ntip-audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ndjson\"\r\nX-Evil: yes",
        .auditExportId = id,
    }));
}

test "only POST selects the exact audit export streaming path" {
    const exact = try http.parseRequest(
        "POST /api/v1/audit/export HTTP/1.1\r\nHost: ntip.test\r\nContent-Length: 0\r\n\r\n",
    );
    try std.testing.expect(isAuditExportRequest(&exact.request));
    const query = try http.parseRequest(
        "POST /api/v1/audit/export?unexpected=true HTTP/1.1\r\nHost: ntip.test\r\nContent-Length: 0\r\n\r\n",
    );
    try std.testing.expect(!isAuditExportRequest(&query.request));
    const read = try http.parseRequest(
        "GET /api/v1/audit/export HTTP/1.1\r\nHost: ntip.test\r\n\r\n",
    );
    try std.testing.expect(!isAuditExportRequest(&read.request));
}

test "production listener and Unix backend entry points typecheck" {
    const document = FixedDocument{ .bytes = "{}" };
    try std.testing.expectError(error.NonLoopbackBind, serve(
        std.testing.allocator,
        std.testing.io,
        .{
            .schema_version = api_config.schema_version,
            .bind_address = "192.0.2.1",
            .public_https_origin = "https://ntip.example.test",
            .bootstrap_spki_pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            .bootstrap_manifest_path = "/etc/ntip/bootstrap-assets.json",
        },
        OpenApiProvider.fromFixedDocument(&document),
    ));

    var object: std.json.ObjectMap = .{};
    defer object.deinit(std.testing.allocator);
    const unavailable: UnixBackend = .{ .socket_path = "/tmp/ntip-api-test-does-not-exist.sock" };
    try std.testing.expectError(error.ServiceUnavailable, unavailable.exchange(
        std.testing.allocator,
        std.testing.io,
        .{
            .version = service_ipc.protocol_version,
            .request_id = "0123456789abcdef0123456789abcdef",
            .deadline_unix_ms = std.math.maxInt(i64),
            .operation = "health.ready",
            .actor = .{ .kind = .service },
            .payload = .{ .object = object },
        },
    ));
}

test "edge preconditions and an unavailable ntsrv map to exact public 428 and 503 responses" {
    const UnavailableBackend = struct {
        fn backend(self: *@This()) Backend {
            return .{ .context = self, .exchangeFn = exchange };
        }

        fn exchange(
            _: *anyopaque,
            _: Allocator,
            _: Io,
            _: service_ipc.Request,
        ) !OwnedHttpResponse {
            return error.ServiceUnavailable;
        }
    };
    var unavailable: UnavailableBackend = .{};
    const document = FixedDocument{ .bytes = "{}" };
    const handler: Handler = .{
        .public_https_origin = "https://ntip.example.test",
        .openapi = OpenApiProvider.fromFixedDocument(&document),
        .backend = unavailable.backend(),
    };

    const missing_parsed = try http.parseRequest(
        "PATCH /api/v1/vnrs/Core HTTP/1.1\r\n" ++
            "Host: ntip.example.test\r\n" ++
            "Origin: https://ntip.example.test\r\n" ++
            "X-CSRF-Token: present\r\n" ++
            "Content-Type: application/json\r\n" ++
            "Content-Length: 23\r\n\r\n" ++
            "{\"cidr\":\"10.24.0.0/23\"}",
    );
    try std.testing.expectError(error.PreconditionRequired, handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &missing_parsed.request,
        "0123456789abcdef0123456789abcdef",
    ));
    var missing = try responseForDispatchFailure(
        std.testing.allocator,
        &missing_parsed.request,
        "0123456789abcdef0123456789abcdef",
        error.PreconditionRequired,
    );
    defer missing.deinit();
    try std.testing.expectEqual(http.Status.precondition_required, missing.status);
    try std.testing.expect(std.mem.indexOf(u8, missing.body, "\"code\":\"precondition_required\"") != null);

    const ready_parsed = try http.parseRequest(
        "GET /api/v1/health/ready HTTP/1.1\r\nHost: ntip.example.test\r\n\r\n",
    );
    try std.testing.expectError(error.ServiceUnavailable, handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &ready_parsed.request,
        "0123456789abcdef0123456789abcdef",
    ));
    var outage = try responseForDispatchFailure(
        std.testing.allocator,
        &ready_parsed.request,
        "0123456789abcdef0123456789abcdef",
        error.ServiceUnavailable,
    );
    defer outage.deinit();
    try std.testing.expectEqual(http.Status.service_unavailable, outage.status);
    try std.testing.expectEqual(@as(?u32, 1), outage.retry_after_seconds);
    try std.testing.expect(std.mem.indexOf(u8, outage.body, "\"code\":\"service_unavailable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, outage.body, "socket") == null);
}

test "keep-alive reader wipes each consumed request before retaining the connection" {
    var reader: ConnectionReader = .{};
    defer std.crypto.secureZero(u8, &reader.bytes);
    @memcpy(reader.bytes[0..10], "secretNEXT");
    reader.end = 10;

    reader.consume(6);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 6), reader.bytes[0..6]);
    try std.testing.expectEqualStrings("NEXT", reader.bytes[6..10]);
    try std.testing.expectEqual(@as(usize, 6), reader.start);
    try std.testing.expectEqual(@as(usize, 10), reader.end);
}

test "allocator-owned service response secrets are wiped before parsed arenas are released" {
    const encoded_frame =
        \\{"version":2,"request_id":"0123456789abcdef0123456789abcdef","sequence":0,"final":true,"payload":{"status":200,"contentType":"application/json; charset=utf-8","bodyChunk":"csrf-session-temporary-password","setCookie":"__Host-ntip_session=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; Secure; HttpOnly; SameSite=Strict; Path=/"}}
    ;
    var parsed = try service_ipc.decodeResponseFrame(std.testing.allocator, encoded_frame);
    defer parsed.deinit();
    const decoded_request_id = parsed.value.request_id;
    const decoded_payload = &parsed.value.payload.?.object;
    const decoded_chunk = decoded_payload.get("bodyChunk").?.string;
    const decoded_cookie = decoded_payload.get("setCookie").?.string;

    wipeDecodedResponseFrame(&parsed.value);
    try expectSecurelyZeroed(decoded_request_id);
    try expectSecurelyZeroed(decoded_chunk);
    try expectSecurelyZeroed(decoded_cookie);

    const encoded_http_payload =
        \\{"status":200,"contentType":"application/json; charset=utf-8","bodyChunk":"enrollment-and-csrf-secret","setCookie":"__Host-ntip_session=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; Secure; HttpOnly; SameSite=Strict; Path=/"}
    ;
    var payload = try std.json.parseFromSlice(
        ServiceHttpResponseFrame,
        std.testing.allocator,
        encoded_http_payload,
        .{ .allocate = .alloc_always },
    );
    defer payload.deinit();
    const reparsed_content_type = payload.value.contentType.?;
    const reparsed_chunk = payload.value.bodyChunk.?;
    const reparsed_cookie = payload.value.setCookie.?;

    wipeDecodedHttpResponseFrame(&payload.value);
    try expectSecurelyZeroed(reparsed_content_type);
    try expectSecurelyZeroed(reparsed_chunk);
    try expectSecurelyZeroed(reparsed_cookie);
}

test "buffered and streaming bridges preserve service field violations" {
    const violations = [_]service_ipc.FieldViolation{.{
        .field = "address",
        .code = "address_in_use",
        .message = "Address is already assigned.",
    }};
    const body = try encodeServiceError(
        std.testing.allocator,
        "0123456789abcdef0123456789abcdef",
        .{
            .code = .conflict,
            .message = "resource conflicts with current state",
            .violations = &violations,
        },
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"violations\":[") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "\"code\":\"address_in_use\"") != null);
}

test "public installer is locator specific pinned complete and mutation last" {
    var fake: FakeBackend = .{};
    const document = FixedDocument{ .bytes = "{}" };
    const handler: Handler = .{
        .public_https_origin = "https://10.2.40.49:8443",
        .bootstrap_spki_pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .bootstrap_manifest = test_bootstrap_manifest,
        .openapi = OpenApiProvider.fromFixedDocument(&document),
        .backend = fake.asBackend(),
    };
    const parsed = try http.parseRequest(
        "GET /enrollment/ABCDEFGH HTTP/1.1\r\nHost: 192.0.2.1\r\nCookie: ignored=yes\r\n\r\n",
    );
    var response = try handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &parsed.request,
        "0123456789abcdef0123456789abcdef",
    );
    defer response.deinit();
    try std.testing.expectEqual(http.Status.ok, response.status);
    try std.testing.expectEqualStrings("text/x-shellscript; charset=utf-8", response.content_type);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "readonly bootstrap_id='ABCDEFGH'") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.body,
        "readonly public_origin='https://10.2.40.49:8443'",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "readonly spki_pin='sha256//AAAAAAAA") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, test_bootstrap_archives[0].sha256) != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "@NTIP_") == null);
    try std.testing.expect(std.mem.endsWith(u8, response.body, "\nmain \"$@\"\n"));
    try std.testing.expect(!fake.called);

    const with_origin = try http.parseRequest(
        "GET /enrollment/ABCDEFGH HTTP/1.1\r\nHost: 192.0.2.1\r\nOrigin: https://192.0.2.1\r\n\r\n",
    );
    try std.testing.expectError(error.InvalidBootstrapRequest, handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &with_origin.request,
        "0123456789abcdef0123456789abcdef",
    ));
}

test "public redemption is strict anonymous bounded and receives immutable archives" {
    var fake: BootstrapFakeBackend = .{};
    var active = std.atomic.Value(u32).init(0);
    const document = FixedDocument{ .bytes = "{}" };
    const handler: Handler = .{
        .public_https_origin = "https://192.0.2.1",
        .bootstrap_spki_pin = "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        .bootstrap_manifest = test_bootstrap_manifest,
        .anonymous_redemptions = &active,
        .openapi = OpenApiProvider.fromFixedDocument(&document),
        .backend = fake.asBackend(),
    };
    const body = "{\"bootstrapId\":\"ABCDEFGH\",\"secretCode\":\"ABC-DEF-GHJ\"}";
    const request_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /enrollment/v1/redeem HTTP/1.1\r\nHost: 192.0.2.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ body.len, body },
    );
    defer std.testing.allocator.free(request_bytes);
    const parsed = try http.parseRequest(request_bytes);
    var response = try handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &parsed.request,
        "0123456789abcdef0123456789abcdef",
    );
    defer response.deinit();
    try std.testing.expect(fake.called);
    try std.testing.expectEqual(http.Status.ok, response.status);
    try std.testing.expectEqual(@as(u32, 0), active.load(.seq_cst));
    var bundle = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response.body, .{});
    defer bundle.deinit();
    try std.testing.expectEqual(@as(usize, 2), bundle.value.object.get("archives").?.array.items.len);
    try std.testing.expectEqualStrings(
        "/enrollment/assets/ntip-node-v0.2.0-x86_64-linux-musl.tar.gz",
        bundle.value.object.get("archives").?.array.items[0].object.get("path").?.string,
    );
    try std.testing.expectEqualStrings("ABCDEFGH", bundle.value.object.get("bootstrapId").?.string);

    const unknown_body = "{\"bootstrapId\":\"ABCDEFGH\",\"secretCode\":\"ABC-DEF-GHJ\",\"extra\":true}";
    const unknown_bytes = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /enrollment/v1/redeem HTTP/1.1\r\nHost: 192.0.2.1\r\nContent-Type: application/json\r\nContent-Length: {d}\r\n\r\n{s}",
        .{ unknown_body.len, unknown_body },
    );
    defer std.testing.allocator.free(unknown_bytes);
    const unknown = try http.parseRequest(unknown_bytes);
    try std.testing.expectError(error.InvalidBootstrapRequest, handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &unknown.request,
        "0123456789abcdef0123456789abcdef",
    ));

    active.store(maximum_anonymous_redemptions, .seq_cst);
    try std.testing.expectError(error.BootstrapRedemptionBusy, handler.dispatch(
        std.testing.allocator,
        std.testing.io,
        &parsed.request,
        "0123456789abcdef0123456789abcdef",
    ));
}

test "public bootstrap errors keep the separate stable envelope" {
    const parsed = try http.parseRequest(
        "POST /enrollment/v1/redeem HTTP/1.1\r\nHost: ntip.test\r\nContent-Length: 0\r\n\r\n",
    );
    var response = try responseForDispatchFailure(
        std.testing.allocator,
        &parsed.request,
        "0123456789abcdef0123456789abcdef",
        error.BootstrapRedemptionBusy,
    );
    defer response.deinit();
    try std.testing.expectEqual(http.Status.too_many_requests, response.status);
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"rate_limited\",\"message\":\"Bootstrap redemption is temporarily rate limited.\"},\"requestId\":\"0123456789abcdef0123456789abcdef\"}",
        response.body,
    );
    try std.testing.expectEqual(@as(?u32, 1), response.retry_after_seconds);
}

fn expectSecurelyZeroed(bytes: []const u8) !void {
    for (bytes) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

test {
    _ = api_config;
    _ = api_error;
    _ = http;
    _ = service_ipc;
}
