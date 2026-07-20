//! Allocation-free HTTP/1.1 parsing, deterministic routing, and resumable
//! response writing for the loopback management service.
//!
//! The parser consumes exactly one request from a byte slice. The caller owns
//! connection admission, read/write timeouts, and buffering; this module owns
//! the protocol ambiguity and size limits that must be identical for every
//! worker.

const std = @import("std");
const api_error = @import("error.zig");

pub const maximum_request_head_bytes: usize = 16 * 1024;
pub const maximum_request_line_bytes: usize = 4 * 1024;
pub const maximum_header_line_bytes: usize = 4 * 1024;
pub const maximum_header_count: usize = 64;
pub const maximum_target_bytes: usize = 4 * 1024;
pub const maximum_body_bytes: usize = 64 * 1024;
pub const maximum_buffered_response_body_bytes: usize = 1024 * 1024;
pub const maximum_streaming_response_chunk_bytes: usize = 32 * 1024;
pub const maximum_response_head_bytes: usize = 8 * 1024;
pub const maximum_route_parameters: usize = 8;

pub const Method = enum(u3) {
    GET,
    HEAD,
    POST,
    PUT,
    PATCH,
    DELETE,
    OPTIONS,

    pub fn text(self: Method) []const u8 {
        return @tagName(self);
    }
};

const all_methods = [_]Method{ .GET, .HEAD, .POST, .PUT, .PATCH, .DELETE, .OPTIONS };

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    method: Method,
    target: []const u8,
    headers: [maximum_header_count]Header,
    header_count: usize,
    body: []const u8,
    connection_close: bool,

    pub fn header(self: *const Request, name: []const u8) ?[]const u8 {
        for (self.headers[0..self.header_count]) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
        }
        return null;
    }

    pub fn path(self: *const Request) []const u8 {
        const query = std.mem.indexOfScalar(u8, self.target, '?') orelse self.target.len;
        return self.target[0..query];
    }

    pub fn wantsKeepAlive(self: *const Request, served_requests: u32, maximum_requests: u32) bool {
        return !self.connection_close and served_requests < maximum_requests;
    }
};

pub const ParsedRequest = struct {
    request: Request,
    consumed: usize,
};

/// Returns `error.Incomplete` until one entire head and declared body are
/// present. Bytes after `consumed` belong to the next pipelined request.
pub fn parseRequest(bytes: []const u8) !ParsedRequest {
    const terminator = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse {
        if (bytes.len > maximum_request_head_bytes) return error.RequestHeadTooLarge;
        return error.Incomplete;
    };
    const head_length = terminator + 4;
    if (head_length > maximum_request_head_bytes) return error.RequestHeadTooLarge;

    const request_line_end = std.mem.indexOf(u8, bytes[0..terminator], "\r\n") orelse return error.BadRequest;
    if (request_line_end == 0 or request_line_end > maximum_request_line_bytes) return error.BadRequest;
    const request_line = bytes[0..request_line_end];
    const first_space = std.mem.indexOfScalar(u8, request_line, ' ') orelse return error.BadRequest;
    const second_space_relative = std.mem.indexOfScalar(u8, request_line[first_space + 1 ..], ' ') orelse return error.BadRequest;
    const second_space = first_space + 1 + second_space_relative;
    if (std.mem.indexOfScalar(u8, request_line[second_space + 1 ..], ' ') != null) return error.BadRequest;

    const method_text = request_line[0..first_space];
    if (!isToken(method_text)) return error.BadRequest;
    const method = parseMethod(method_text) orelse return error.UnsupportedMethod;
    const target = request_line[first_space + 1 .. second_space];
    try validateTarget(target);
    if (!std.mem.eql(u8, request_line[second_space + 1 ..], "HTTP/1.1")) return error.UnsupportedHttpVersion;

    var headers: [maximum_header_count]Header = undefined;
    var header_count: usize = 0;
    var content_length: usize = 0;
    var host_seen = false;
    var transfer_encoding_seen = false;
    var connection_close = false;
    var cursor = request_line_end + 2;
    while (cursor < terminator) {
        const relative_end = std.mem.indexOf(u8, bytes[cursor..terminator], "\r\n") orelse terminator - cursor;
        const line_end = cursor + relative_end;
        if (line_end == cursor or line_end - cursor > maximum_header_line_bytes) return error.BadRequest;
        if (header_count == maximum_header_count) return error.TooManyHeaders;

        const line = bytes[cursor..line_end];
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadRequest;
        if (colon == 0) return error.BadRequest;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (!isToken(name) or !isHeaderValue(value)) return error.BadRequest;

        for (headers[0..header_count]) |existing| {
            if (!std.ascii.eqlIgnoreCase(existing.name, name)) continue;
            if (std.ascii.eqlIgnoreCase(name, "Content-Length")) return error.DuplicateContentLength;
            if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding")) return error.DuplicateTransferEncoding;
            return error.DuplicateHeader;
        }

        headers[header_count] = .{ .name = name, .value = value };
        header_count += 1;

        if (std.ascii.eqlIgnoreCase(name, "Host")) {
            if (value.len == 0) return error.BadRequest;
            host_seen = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Content-Length")) {
            if (value.len == 0) return error.BadRequest;
            for (value) |byte| if (!std.ascii.isDigit(byte)) return error.BadRequest;
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.BadRequest;
            if (content_length > maximum_body_bytes) return error.PayloadTooLarge;
        } else if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding")) {
            // Chunked and all extension codings are intentionally unsupported;
            // accepting both TE and CL creates request-smuggling ambiguity.
            transfer_encoding_seen = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Connection")) {
            connection_close = try connectionRequestsClose(value);
        } else if (std.ascii.eqlIgnoreCase(name, "Expect")) {
            // `100-continue` is not implemented. Rejecting it prevents a peer
            // from holding a worker while waiting for an interim response.
            return error.UnsupportedExpectation;
        }
        cursor = line_end + 2;
    }

    if (!host_seen) return error.MissingHost;
    if (transfer_encoding_seen) return error.UnsupportedTransferEncoding;
    const consumed = head_length + content_length;
    if (bytes.len < consumed) return error.Incomplete;
    return .{
        .request = .{
            .method = method,
            .target = target,
            .headers = headers,
            .header_count = header_count,
            .body = bytes[head_length..consumed],
            .connection_close = connection_close,
        },
        .consumed = consumed,
    };
}

fn parseMethod(value: []const u8) ?Method {
    inline for (std.meta.fields(Method)) |field| {
        if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
    }
    return null;
}

fn validateTarget(target: []const u8) !void {
    if (target.len == 0 or target.len > maximum_target_bytes or target[0] != '/') return error.BadRequest;
    const query = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    for (target, 0..) |byte, index| {
        if (byte < 0x21 or byte > 0x7e or byte == '#') return error.BadRequest;
        // Reverse proxies disagree on normalization of encoded separators and
        // backslashes. API route segments never require either spelling.
        if (index < query and (byte == '%' or byte == '\\')) return error.BadRequest;
    }
}

fn isToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| switch (byte) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => {},
        else => return false,
    };
    return true;
}

fn isHeaderValue(value: []const u8) bool {
    for (value) |byte| {
        if ((byte < 0x20 and byte != '\t') or byte == 0x7f) return false;
    }
    return true;
}

fn connectionRequestsClose(value: []const u8) !bool {
    var close = false;
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (!isToken(token)) return error.BadRequest;
        if (std.ascii.eqlIgnoreCase(token, "close")) close = true;
    }
    return close;
}

pub const Route = struct {
    method: Method,
    pattern: []const u8,
    operation: []const u8,
};

pub const RouteParameter = struct {
    name: []const u8,
    value: []const u8,
};

pub const Match = struct {
    route: *const Route,
    parameters: [maximum_route_parameters]RouteParameter,
    parameter_count: usize,

    pub fn parameter(self: *const Match, name: []const u8) ?[]const u8 {
        for (self.parameters[0..self.parameter_count]) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }
        return null;
    }
};

pub const AllowedMethods = struct {
    bits: u8 = 0,

    pub fn insert(self: *AllowedMethods, method: Method) void {
        self.bits |= @as(u8, 1) << @intCast(@intFromEnum(method));
    }

    pub fn contains(self: AllowedMethods, method: Method) bool {
        return self.bits & (@as(u8, 1) << @intCast(@intFromEnum(method))) != 0;
    }

    pub fn format(self: AllowedMethods, storage: []u8) []const u8 {
        var writer: std.Io.Writer = .fixed(storage);
        var first = true;
        for (all_methods) |method| {
            if (!self.contains(method)) continue;
            if (!first) writer.writeAll(", ") catch return "";
            writer.writeAll(method.text()) catch return "";
            first = false;
        }
        return writer.buffered();
    }
};

pub const Resolution = union(enum) {
    matched: Match,
    method_not_allowed: AllowedMethods,
    not_found,
};

pub const Router = struct {
    routes: []const Route,

    pub fn init(routes: []const Route) !Router {
        for (routes, 0..) |route, index| {
            try validateRoute(route);
            for (routes[0..index]) |existing| {
                if (existing.method == route.method and sameRouteShape(existing.pattern, route.pattern)) {
                    return error.DuplicateRoute;
                }
            }
        }
        return .{ .routes = routes };
    }

    pub fn resolve(self: Router, method: Method, target: []const u8) !Resolution {
        const query = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
        const path = target[0..query];
        var allowed: AllowedMethods = .{};
        var best: ?Match = null;
        var best_specificity: usize = 0;

        for (self.routes) |*route| {
            var parameters: [maximum_route_parameters]RouteParameter = undefined;
            const pattern_match = matchPattern(route.pattern, path, &parameters) orelse continue;
            allowed.insert(route.method);
            if (route.method != method) continue;
            const candidate: Match = .{
                .route = route,
                .parameters = parameters,
                .parameter_count = pattern_match.parameter_count,
            };
            if (best == null or pattern_match.static_segments > best_specificity) {
                best = candidate;
                best_specificity = pattern_match.static_segments;
            } else if (pattern_match.static_segments == best_specificity) {
                return error.AmbiguousRouteMatch;
            }
        }

        if (best) |value| return .{ .matched = value };
        if (allowed.bits != 0) return .{ .method_not_allowed = allowed };
        return .not_found;
    }
};

const PatternMatch = struct {
    parameter_count: usize,
    static_segments: usize,
};

fn validateRoute(route: Route) !void {
    if (route.pattern.len == 0 or route.pattern.len > maximum_target_bytes or route.pattern[0] != '/') {
        return error.InvalidRoute;
    }
    if (route.pattern.len > 1 and route.pattern[route.pattern.len - 1] == '/') return error.InvalidRoute;
    if (!isOperation(route.operation)) return error.InvalidRoute;

    if (route.pattern.len == 1) return;
    var parameter_count: usize = 0;
    var segments = std.mem.splitScalar(u8, route.pattern[1..], '/');
    while (segments.next()) |segment| {
        if (segment.len == 0) return error.InvalidRoute;
        if (parameterName(segment)) |name| {
            parameter_count += 1;
            if (parameter_count > maximum_route_parameters or !isParameterName(name)) return error.InvalidRoute;
        } else {
            for (segment) |byte| switch (byte) {
                'a'...'z', '0'...'9', '-', '_', '.' => {},
                else => return error.InvalidRoute,
            };
        }
    }
}

fn matchPattern(pattern: []const u8, path: []const u8, parameters: *[maximum_route_parameters]RouteParameter) ?PatternMatch {
    if (pattern.len == 1 or path.len == 1) {
        return if (std.mem.eql(u8, pattern, path)) .{ .parameter_count = 0, .static_segments = 0 } else null;
    }
    if (path.len == 0 or path[0] != '/' or path[path.len - 1] == '/') return null;

    var parameter_count: usize = 0;
    var static_segments: usize = 0;
    var pattern_segments = std.mem.splitScalar(u8, pattern[1..], '/');
    var path_segments = std.mem.splitScalar(u8, path[1..], '/');
    while (true) {
        const pattern_segment = pattern_segments.next();
        const path_segment = path_segments.next();
        if (pattern_segment == null or path_segment == null) {
            if (pattern_segment != null or path_segment != null) return null;
            break;
        }
        if (path_segment.?.len == 0) return null;
        if (parameterName(pattern_segment.?)) |name| {
            if (parameter_count == parameters.len) return null;
            parameters[parameter_count] = .{ .name = name, .value = path_segment.? };
            parameter_count += 1;
        } else {
            if (!std.mem.eql(u8, pattern_segment.?, path_segment.?)) return null;
            static_segments += 1;
        }
    }
    return .{ .parameter_count = parameter_count, .static_segments = static_segments };
}

fn sameRouteShape(left: []const u8, right: []const u8) bool {
    if (std.mem.eql(u8, left, "/") or std.mem.eql(u8, right, "/")) return std.mem.eql(u8, left, right);
    var left_segments = std.mem.splitScalar(u8, left[1..], '/');
    var right_segments = std.mem.splitScalar(u8, right[1..], '/');
    while (true) {
        const left_segment = left_segments.next();
        const right_segment = right_segments.next();
        if (left_segment == null or right_segment == null) return left_segment == null and right_segment == null;
        const left_parameter = parameterName(left_segment.?) != null;
        const right_parameter = parameterName(right_segment.?) != null;
        if (left_parameter != right_parameter) return false;
        if (!left_parameter and !std.mem.eql(u8, left_segment.?, right_segment.?)) return false;
    }
}

fn parameterName(segment: []const u8) ?[]const u8 {
    if (segment.len < 3 or segment[0] != '{' or segment[segment.len - 1] != '}') return null;
    return segment[1 .. segment.len - 1];
}

fn isParameterName(value: []const u8) bool {
    if (value.len == 0 or !(value[0] >= 'a' and value[0] <= 'z')) return false;
    for (value) |byte| switch (byte) {
        'a'...'z', '0'...'9', '_' => {},
        else => return false,
    };
    return true;
}

fn isOperation(value: []const u8) bool {
    if (value.len == 0 or value.len > 96 or value[0] == '.' or value[value.len - 1] == '.') return false;
    var previous_dot = false;
    for (value) |byte| {
        const dot = byte == '.';
        if (dot and previous_dot) return false;
        previous_dot = dot;
        switch (byte) {
            'a'...'z', '0'...'9', '.', '_', '-' => {},
            else => return false,
        }
    }
    return true;
}

pub const Status = enum(u16) {
    ok = 200,
    created = 201,
    accepted = 202,
    no_content = 204,
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    conflict = 409,
    payload_too_large = 413,
    unsupported_media_type = 415,
    precondition_failed = 412,
    precondition_required = 428,
    too_many_requests = 429,
    internal_server_error = 500,
    service_unavailable = 503,

    pub fn reason(self: Status) []const u8 {
        return switch (self) {
            .ok => "OK",
            .created => "Created",
            .accepted => "Accepted",
            .no_content => "No Content",
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .conflict => "Conflict",
            .payload_too_large => "Payload Too Large",
            .unsupported_media_type => "Unsupported Media Type",
            .precondition_failed => "Precondition Failed",
            .precondition_required => "Precondition Required",
            .too_many_requests => "Too Many Requests",
            .internal_server_error => "Internal Server Error",
            .service_unavailable => "Service Unavailable",
        };
    }
};

pub const ResponseOptions = struct {
    status: Status,
    body: []const u8 = "",
    content_type: []const u8 = "application/json; charset=utf-8",
    close: bool = false,
    request_id: ?[]const u8 = null,
    etag: ?[]const u8 = null,
    allow: ?[]const u8 = null,
    location: ?[]const u8 = null,
    content_disposition: ?[]const u8 = null,
    audit_export_id: ?[]const u8 = null,
    retry_after_seconds: ?u32 = null,
    set_cookie: ?[]const u8 = null,
    body_framing: BodyFraming = .content_length,
};

pub const BodyFraming = enum {
    content_length,
    chunked,
};

pub const PreparedResponse = struct {
    head: []const u8,
    body: []const u8,

    pub fn cursor(self: PreparedResponse) ResponseCursor {
        return .{ .response = self };
    }

    pub fn totalLength(self: PreparedResponse) usize {
        return self.head.len + self.body.len;
    }
};

/// Resumable state for nonblocking writes. `advance` accepts a partial write
/// spanning the head and body, so it can also be paired with `writev`.
pub const ResponseCursor = struct {
    response: PreparedResponse,
    head_offset: usize = 0,
    body_offset: usize = 0,

    pub fn done(self: ResponseCursor) bool {
        return self.head_offset == self.response.head.len and self.body_offset == self.response.body.len;
    }

    pub fn remaining(self: ResponseCursor) usize {
        return self.response.head.len - self.head_offset + self.response.body.len - self.body_offset;
    }

    pub fn next(self: ResponseCursor) []const u8 {
        if (self.head_offset < self.response.head.len) return self.response.head[self.head_offset..];
        return self.response.body[self.body_offset..];
    }

    pub fn advance(self: *ResponseCursor, written: usize) !void {
        if (written > self.remaining()) return error.AdvanceBeyondResponse;
        var rest = written;
        const remaining_head = self.response.head.len - self.head_offset;
        const head_written = @min(rest, remaining_head);
        self.head_offset += head_written;
        rest -= head_written;
        self.body_offset += rest;
    }
};

pub fn prepareResponse(storage: []u8, options: ResponseOptions) !PreparedResponse {
    const bounded_storage = storage[0..@min(storage.len, maximum_response_head_bytes)];
    try validateResponseOptions(options);
    var writer: std.Io.Writer = .fixed(bounded_storage);
    writeResponseHead(&writer, options) catch return error.ResponseHeadTooLarge;
    return .{ .head = writer.buffered(), .body = options.body };
}

pub fn writePrepared(writer: *std.Io.Writer, prepared: PreparedResponse) !void {
    try writer.writeAll(prepared.head);
    try writer.writeAll(prepared.body);
    try writer.flush();
}

fn validateResponseOptions(options: ResponseOptions) !void {
    if (options.body.len > maximum_buffered_response_body_bytes) return error.ResponseBodyTooLarge;
    if (options.body_framing == .chunked and options.body.len != 0) return error.InvalidResponse;
    if (options.status == .no_content and options.body.len != 0) return error.InvalidResponse;
    if (options.status == .no_content and options.body_framing == .chunked) return error.InvalidResponse;
    if (options.content_type.len == 0 or !isHeaderValue(options.content_type)) return error.InvalidResponseHeader;
    if (options.request_id) |value| if (!api_error.isIdentifier(value)) return error.InvalidResponseHeader;
    inline for (.{
        options.etag,
        options.allow,
        options.location,
        options.content_disposition,
        options.audit_export_id,
        options.set_cookie,
    }) |optional| {
        if (optional) |value| if (value.len == 0 or !isHeaderValue(value)) return error.InvalidResponseHeader;
    }
    if (options.audit_export_id) |value| {
        if (!api_error.isIdentifier(value)) return error.InvalidResponseHeader;
    }
    if (options.status == .precondition_failed and options.etag == null) {
        return error.InvalidResponseHeader;
    }
    if ((options.status == .too_many_requests or options.status == .service_unavailable) and
        options.retry_after_seconds == null)
    {
        return error.InvalidResponseHeader;
    }
    if (options.retry_after_seconds) |value| {
        if (value == 0) return error.InvalidResponseHeader;
    }
}

fn writeResponseHead(writer: *std.Io.Writer, options: ResponseOptions) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ @intFromEnum(options.status), options.status.reason() });
    try writer.writeAll("Server: ntip-api/0.2\r\n");
    try writer.print("Content-Type: {s}\r\n", .{options.content_type});
    switch (options.body_framing) {
        .content_length => try writer.print("Content-Length: {d}\r\n", .{options.body.len}),
        .chunked => try writer.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    try writer.print("Connection: {s}\r\n", .{if (options.close) "close" else "keep-alive"});
    try writer.writeAll("Cache-Control: no-store\r\n");
    try writer.writeAll("X-Content-Type-Options: nosniff\r\n");
    try writer.writeAll("X-Frame-Options: DENY\r\n");
    try writer.writeAll("Referrer-Policy: no-referrer\r\n");
    try writer.writeAll("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n");
    if (options.request_id) |value| try writer.print("X-Request-ID: {s}\r\n", .{value});
    if (options.etag) |value| try writer.print("ETag: {s}\r\n", .{value});
    if (options.allow) |value| try writer.print("Allow: {s}\r\n", .{value});
    if (options.location) |value| try writer.print("Location: {s}\r\n", .{value});
    if (options.content_disposition) |value| try writer.print("Content-Disposition: {s}\r\n", .{value});
    if (options.audit_export_id) |value| try writer.print("X-NTIP-Audit-Export-ID: {s}\r\n", .{value});
    if (options.retry_after_seconds) |value| try writer.print("Retry-After: {d}\r\n", .{value});
    if (options.set_cookie) |value| try writer.print("Set-Cookie: {s}\r\n", .{value});
    try writer.writeAll("\r\n");
}

/// Writes one bounded HTTP/1.1 response chunk. `writeAll` and `flush` retain
/// correct framing across partial socket writes. A zero-length data chunk is
/// reserved for `finishChunkedResponse` so callers cannot terminate a stream
/// accidentally.
pub fn writeChunkedResponseChunk(writer: *std.Io.Writer, bytes: []const u8) !void {
    if (bytes.len == 0 or bytes.len > maximum_streaming_response_chunk_bytes) {
        return error.InvalidResponseChunk;
    }
    try writer.print("{x}\r\n", .{bytes.len});
    try writer.writeAll(bytes);
    try writer.writeAll("\r\n");
    try writer.flush();
}

pub fn finishChunkedResponse(writer: *std.Io.Writer) !void {
    try writer.writeAll("0\r\n\r\n");
    try writer.flush();
}

pub const OwnedErrorResponse = struct {
    allocator: std.mem.Allocator,
    body: []u8,
    prepared: PreparedResponse,

    pub fn deinit(self: *OwnedErrorResponse) void {
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

pub fn prepareErrorResponse(
    allocator: std.mem.Allocator,
    head_storage: []u8,
    request_id: []const u8,
    code: api_error.Code,
    message: []const u8,
    close: bool,
) !OwnedErrorResponse {
    const body = try api_error.encode(allocator, request_id, code, message);
    errdefer allocator.free(body);
    return prepareEncodedErrorResponse(allocator, head_storage, body, request_id, statusForError(code), close);
}

pub fn prepareParseErrorResponse(
    allocator: std.mem.Allocator,
    head_storage: []u8,
    request_id: []const u8,
    failure: anyerror,
    message: []const u8,
) !OwnedErrorResponse {
    const body = try api_error.encode(allocator, request_id, errorCodeForParseFailure(failure), message);
    errdefer allocator.free(body);
    return prepareEncodedErrorResponse(allocator, head_storage, body, request_id, statusForParseFailure(failure), true);
}

fn prepareEncodedErrorResponse(
    allocator: std.mem.Allocator,
    head_storage: []u8,
    body: []u8,
    request_id: []const u8,
    status: Status,
    close: bool,
) !OwnedErrorResponse {
    const prepared = try prepareResponse(head_storage, .{
        .status = status,
        .body = body,
        .close = close,
        .request_id = request_id,
    });
    return .{ .allocator = allocator, .body = body, .prepared = prepared };
}

pub fn statusForError(code: api_error.Code) Status {
    return switch (code) {
        .invalid_request, .validation_failed, .idempotency_required => .bad_request,
        .authentication_required, .invalid_credentials => .unauthorized,
        .password_change_required,
        .csrf_failed,
        .origin_forbidden,
        .forbidden,
        .reauthentication_required,
        => .forbidden,
        .not_found => .not_found,
        .conflict, .invariant_violation, .idempotency_conflict => .conflict,
        .precondition_required => .precondition_required,
        .precondition_failed => .precondition_failed,
        .rate_limited => .too_many_requests,
        .operation_unavailable, .service_unavailable => .service_unavailable,
        .internal_error => .internal_server_error,
    };
}

pub fn errorCodeForParseFailure(failure: anyerror) api_error.Code {
    return switch (failure) {
        error.PayloadTooLarge,
        error.BadRequest,
        error.RequestHeadTooLarge,
        error.TooManyHeaders,
        error.DuplicateContentLength,
        error.DuplicateTransferEncoding,
        error.DuplicateHeader,
        error.UnsupportedTransferEncoding,
        error.UnsupportedExpectation,
        error.MissingHost,
        error.UnsupportedHttpVersion,
        error.UnsupportedMethod,
        => .invalid_request,
        else => .internal_error,
    };
}

pub fn statusForParseFailure(failure: anyerror) Status {
    return if (failure == error.PayloadTooLarge) .payload_too_large else .bad_request;
}

test "HTTP parser consumes one bounded request and preserves a pipeline" {
    const bytes =
        "POST /api/v1/nodes?view=full HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Content-Length: 7\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n" ++
        "{\"a\":1}" ++
        "GET /api/v1/overview HTTP/1.1\r\nHost: ntip.example.test\r\n\r\n";
    const parsed = try parseRequest(bytes);
    try std.testing.expectEqual(Method.POST, parsed.request.method);
    try std.testing.expectEqualStrings("/api/v1/nodes", parsed.request.path());
    try std.testing.expectEqualStrings("application/json", parsed.request.header("content-type").?);
    try std.testing.expectEqualStrings("{\"a\":1}", parsed.request.body);
    try std.testing.expect(parsed.request.wantsKeepAlive(1, 100));
    try std.testing.expect(std.mem.startsWith(u8, bytes[parsed.consumed..], "GET /api/v1/overview"));
}

test "HTTP parser rejects ambiguous framing and every transfer encoding" {
    const duplicate_length =
        "POST /api/v1/test HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Content-Length: 0\r\n" ++
        "Content-Length: 0\r\n\r\n";
    try std.testing.expectError(error.DuplicateContentLength, parseRequest(duplicate_length));

    const transfer_encoding =
        "POST /api/v1/test HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Transfer-Encoding: identity\r\n\r\n";
    try std.testing.expectError(error.DuplicateTransferEncoding, parseRequest(transfer_encoding));

    const single_transfer_encoding =
        "POST /api/v1/test HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectError(error.UnsupportedTransferEncoding, parseRequest(single_transfer_encoding));

    const duplicate_origin =
        "POST /api/v1/test HTTP/1.1\r\n" ++
        "Host: ntip.example.test\r\n" ++
        "Origin: https://ntip.example.test\r\n" ++
        "Origin: https://ntip.example.test\r\n\r\n";
    try std.testing.expectError(error.DuplicateHeader, parseRequest(duplicate_origin));
}

test "HTTP parser enforces host, body, head, and completeness limits" {
    try std.testing.expectError(
        error.MissingHost,
        parseRequest("GET /api/v1/overview HTTP/1.1\r\nConnection: close\r\n\r\n"),
    );
    try std.testing.expectError(
        error.PayloadTooLarge,
        parseRequest("POST /api/v1/test HTTP/1.1\r\nHost: ntip\r\nContent-Length: 65537\r\n\r\n"),
    );
    try std.testing.expectError(
        error.Incomplete,
        parseRequest("POST /api/v1/test HTTP/1.1\r\nHost: ntip\r\nContent-Length: 4\r\n\r\n{}"),
    );

    const oversized = try std.testing.allocator.alloc(u8, maximum_request_head_bytes + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 'a');
    try std.testing.expectError(error.RequestHeadTooLarge, parseRequest(oversized));
}

test "router extracts parameters, prefers static routes, and reports Allow" {
    const routes = [_]Route{
        .{ .method = .GET, .pattern = "/api/v1/nodes/{id}", .operation = "node.read" },
        .{ .method = .GET, .pattern = "/api/v1/nodes/special", .operation = "node.special" },
        .{ .method = .PATCH, .pattern = "/api/v1/nodes/{id}", .operation = "node.update" },
        .{ .method = .POST, .pattern = "/api/v1/nodes/{id}/actions/reset-enrollment", .operation = "node.enrollment.reset" },
    };
    const router = try Router.init(&routes);

    const dynamic = try router.resolve(.GET, "/api/v1/nodes/0123?runtime=true");
    try std.testing.expectEqualStrings("node.read", dynamic.matched.route.operation);
    try std.testing.expectEqualStrings("0123", dynamic.matched.parameter("id").?);

    const static = try router.resolve(.GET, "/api/v1/nodes/special");
    try std.testing.expectEqualStrings("node.special", static.matched.route.operation);

    const wrong_method = try router.resolve(.DELETE, "/api/v1/nodes/0123");
    try std.testing.expect(wrong_method.method_not_allowed.contains(.GET));
    try std.testing.expect(wrong_method.method_not_allowed.contains(.PATCH));
    var allow_storage: [64]u8 = undefined;
    try std.testing.expectEqualStrings("GET, PATCH", wrong_method.method_not_allowed.format(&allow_storage));

    const missing = try router.resolve(.GET, "/api/v1/vnrs");
    try std.testing.expect(missing == .not_found);
}

test "router rejects duplicate route shapes and ambiguous runtime matches" {
    const duplicate = [_]Route{
        .{ .method = .GET, .pattern = "/api/v1/nodes/{id}", .operation = "node.read" },
        .{ .method = .GET, .pattern = "/api/v1/nodes/{name}", .operation = "node.read_alias" },
    };
    try std.testing.expectError(error.DuplicateRoute, Router.init(&duplicate));

    const ambiguous = [_]Route{
        .{ .method = .GET, .pattern = "/{left}/fixed", .operation = "left.read" },
        .{ .method = .GET, .pattern = "/fixed/{right}", .operation = "right.read" },
    };
    const router = try Router.init(&ambiguous);
    try std.testing.expectError(error.AmbiguousRouteMatch, router.resolve(.GET, "/fixed/fixed"));
}

test "prepared responses carry security headers and resume partial writes" {
    var head_storage: [maximum_response_head_bytes]u8 = undefined;
    var owned = try prepareErrorResponse(
        std.testing.allocator,
        &head_storage,
        "0123456789abcdef0123456789abcdef",
        .conflict,
        "resource conflicts with current state",
        false,
    );
    defer owned.deinit();

    try std.testing.expect(std.mem.startsWith(u8, owned.prepared.head, "HTTP/1.1 409 Conflict\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, owned.prepared.head, "Cache-Control: no-store\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, owned.prepared.head, "X-Content-Type-Options: nosniff\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, owned.prepared.body, "\"code\":\"conflict\"") != null);

    var cursor = owned.prepared.cursor();
    const total = cursor.remaining();
    try cursor.advance(7);
    try std.testing.expectEqual(total - 7, cursor.remaining());
    try cursor.advance(cursor.remaining());
    try std.testing.expect(cursor.done());
    try std.testing.expectError(error.AdvanceBeyondResponse, cursor.advance(1));
}

test "response helpers reject header injection and map stable errors" {
    var storage: [maximum_response_head_bytes]u8 = undefined;
    try std.testing.expectError(error.InvalidResponseHeader, prepareResponse(&storage, .{
        .status = .ok,
        .request_id = "not-an-id",
    }));
    try std.testing.expectError(error.InvalidResponseHeader, prepareResponse(&storage, .{
        .status = .ok,
        .etag = "safe\r\nInjected: true",
    }));
    try std.testing.expectError(error.InvalidResponseHeader, prepareResponse(&storage, .{
        .status = .ok,
        .audit_export_id = "not-an-id",
    }));
    try std.testing.expectError(error.InvalidResponseHeader, prepareResponse(&storage, .{
        .status = .precondition_failed,
    }));
    try std.testing.expectError(error.InvalidResponseHeader, prepareResponse(&storage, .{
        .status = .service_unavailable,
    }));
    try std.testing.expectError(error.InvalidResponseHeader, prepareResponse(&storage, .{
        .status = .too_many_requests,
        .retry_after_seconds = 0,
    }));
    const stale = try prepareResponse(&storage, .{
        .status = .precondition_failed,
        .etag = "\"node:0123456789abcdef0123456789abcdef:4\"",
    });
    try std.testing.expect(std.mem.indexOf(
        u8,
        stale.head,
        "ETag: \"node:0123456789abcdef0123456789abcdef:4\"\r\n",
    ) != null);
    const unavailable = try prepareResponse(&storage, .{
        .status = .service_unavailable,
        .retry_after_seconds = 1,
    });
    try std.testing.expect(std.mem.indexOf(u8, unavailable.head, "Retry-After: 1\r\n") != null);
    const exported = try prepareResponse(&storage, .{
        .status = .ok,
        .content_type = "application/x-ndjson",
        .content_disposition = "attachment; filename=\"ntip-audit.ndjson\"",
        .audit_export_id = "0123456789abcdef0123456789abcdef",
    });
    try std.testing.expect(std.mem.indexOf(
        u8,
        exported.head,
        "Content-Disposition: attachment; filename=\"ntip-audit.ndjson\"\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        exported.head,
        "X-NTIP-Audit-Export-ID: 0123456789abcdef0123456789abcdef\r\n",
    ) != null);
    try std.testing.expectEqual(Status.conflict, statusForError(.idempotency_conflict));
    try std.testing.expectEqual(Status.payload_too_large, statusForParseFailure(error.PayloadTooLarge));
    try std.testing.expectEqual(api_error.Code.invalid_request, errorCodeForParseFailure(error.DuplicateContentLength));
}

test "chunked responses frame bounded chunks and terminate explicitly" {
    var head_storage: [maximum_response_head_bytes]u8 = undefined;
    const prepared = try prepareResponse(&head_storage, .{
        .status = .ok,
        .content_type = "application/x-ndjson",
        .close = true,
        .request_id = "0123456789abcdef0123456789abcdef",
        .content_disposition = "attachment; filename=\"ntip-audit-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.ndjson\"",
        .audit_export_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .body_framing = .chunked,
    });
    try std.testing.expect(std.mem.indexOf(
        u8,
        prepared.head,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, prepared.head, "Content-Length:") == null);
    try std.testing.expect(std.mem.indexOf(u8, prepared.head, "Connection: close\r\n") != null);

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writePrepared(&output.writer, prepared);
    try writeChunkedResponseChunk(&output.writer, "{\"sequence\":1}\n");
    try finishChunkedResponse(&output.writer);
    try std.testing.expect(std.mem.endsWith(
        u8,
        output.written(),
        "f\r\n{\"sequence\":1}\n\r\n0\r\n\r\n",
    ));

    try std.testing.expectError(error.InvalidResponseChunk, writeChunkedResponseChunk(&output.writer, ""));
    const oversized = try std.testing.allocator.alloc(u8, maximum_streaming_response_chunk_bytes + 1);
    defer std.testing.allocator.free(oversized);
    try std.testing.expectError(error.InvalidResponseChunk, writeChunkedResponseChunk(&output.writer, oversized));
    try std.testing.expectError(error.InvalidResponse, prepareResponse(&head_storage, .{
        .status = .ok,
        .body = "not allowed with chunked framing",
        .body_framing = .chunked,
    }));
}
