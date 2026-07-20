//! Strict decoding helpers for requests forwarded by the loopback HTTP tier.
//!
//! `SO_PEERCRED` authenticates the `ntip-api` process, not its payload. The
//! authoritative service therefore validates the fixed forwarding envelope,
//! target path, body shape, cookie token, and query bounds again.

const std = @import("std");
const auth = @import("auth.zig");
const http = @import("http.zig");
const service_ipc = @import("service_ipc.zig");

pub const Forwarded = struct {
    method: http.Method,
    target: []const u8,
    body: ?std.json.Value,
    session_token: ?auth.SecretToken,
    origin: ?[]const u8,
    csrf_token: ?[]const u8,
    user_agent: ?[]const u8,
    /// The HTTP tier may only describe its locally observed proxy peer. The
    /// authoritative service retains and revalidates this fixed claim so
    /// audit attribution cannot be supplied by an HTTP client.
    proxy_peer: []const u8,

    pub fn path(self: Forwarded) []const u8 {
        const query_start = std.mem.indexOfScalar(u8, self.target, '?') orelse self.target.len;
        return self.target[0..query_start];
    }

    pub fn query(self: Forwarded) []const u8 {
        const query_start = std.mem.indexOfScalar(u8, self.target, '?') orelse return "";
        return self.target[query_start + 1 ..];
    }
};

pub fn decode(value: std.json.Value) !Forwarded {
    if (value != .object) return error.InvalidForwardedRequest;
    const object = value.object;
    const allowed = [_][]const u8{
        "method",
        "target",
        "proxyPeer",
        "body",
        "sessionToken",
        "origin",
        "csrfToken",
        "userAgent",
    };
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        var known = false;
        for (allowed) |name| known = known or std.mem.eql(u8, entry.key_ptr.*, name);
        if (!known) return error.InvalidForwardedRequest;
    }

    const method_text = try requiredString(object, "method");
    const target = try requiredString(object, "target");
    const proxy_peer = try requiredString(object, "proxyPeer");
    if (!std.mem.eql(u8, proxy_peer, "loopback")) return error.InvalidForwardedRequest;
    try validateTarget(target);
    const body_value = object.get("body") orelse return error.InvalidForwardedRequest;
    const body: ?std.json.Value = switch (body_value) {
        .null => null,
        .object => body_value,
        else => return error.InvalidForwardedRequest,
    };

    const session_token = if (try optionalString(object, "sessionToken")) |text|
        auth.SecretToken.parse(text) catch return error.InvalidSessionToken
    else
        null;
    const user_agent = try optionalString(object, "userAgent");
    try validateAuditText(user_agent, service_ipc.maximum_user_agent_bytes);
    return .{
        .method = parseMethod(method_text) orelse return error.InvalidForwardedRequest,
        .target = target,
        .body = body,
        .session_token = session_token,
        .origin = try optionalString(object, "origin"),
        .csrf_token = try optionalString(object, "csrfToken"),
        .user_agent = user_agent,
        .proxy_peer = proxy_peer,
    };
}

fn validateAuditText(value: ?[]const u8, maximum: usize) !void {
    const text = value orelse return;
    if (text.len > maximum or !std.unicode.utf8ValidateSlice(text)) {
        return error.InvalidForwardedRequest;
    }
    for (text) |byte| if (byte < 0x20 or byte == 0x7f) {
        return error.InvalidForwardedRequest;
    };
}

pub fn decodeBody(
    comptime T: type,
    allocator: std.mem.Allocator,
    body: ?std.json.Value,
) !std.json.Parsed(T) {
    const value = body orelse return error.RequestBodyRequired;
    const encoded = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer {
        std.crypto.secureZero(u8, encoded);
        allocator.free(encoded);
    }
    return std.json.parseFromSlice(T, allocator, encoded, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidRequestBody;
}

pub fn pathParameter(target: []const u8, prefix: []const u8, suffix: []const u8) ![]const u8 {
    const query_start = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    const path = target[0..query_start];
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix)) {
        return error.InvalidTarget;
    }
    if (path.len < prefix.len + suffix.len) return error.InvalidTarget;
    const value = path[prefix.len .. path.len - suffix.len];
    if (value.len == 0 or std.mem.indexOfScalar(u8, value, '/') != null) return error.InvalidTarget;
    return value;
}

pub const Query = struct {
    cursor: ?[]const u8 = null,
    limit: ?u16 = null,
    vnr_name: ?[]const u8 = null,
    enrollment_state: ?[]const u8 = null,
    node_id: ?[]const u8 = null,
    scope: ?[]const u8 = null,
    liveness: ?[]const u8 = null,
    status: ?[]const u8 = null,
    severity: ?[]const u8 = null,
    since: ?[]const u8 = null,
    actor_user_id: ?[]const u8 = null,
    resource_type: ?[]const u8 = null,
};

/// Decodes one URI query component into caller-owned bounded storage.
///
/// The HTTP edge forwards the request-target verbatim, so the authoritative
/// service must perform this decoding itself. `+` is rejected instead of
/// being interpreted as a space because no NTIP query value admits spaces;
/// callers that need a literal plus must use `%2B`. Encoded delimiters,
/// controls, and non-ASCII bytes are rejected before typed validation.
pub fn decodeQueryComponent(encoded: []const u8, output: []u8) ![]const u8 {
    var read_index: usize = 0;
    var write_index: usize = 0;
    while (read_index < encoded.len) {
        const byte = encoded[read_index];
        const decoded = if (byte == '%') decoded: {
            if (read_index + 2 >= encoded.len) return error.InvalidQuery;
            const high = hexNibble(encoded[read_index + 1]) orelse return error.InvalidQuery;
            const low = hexNibble(encoded[read_index + 2]) orelse return error.InvalidQuery;
            read_index += 3;
            break :decoded (high << 4) | low;
        } else decoded: {
            if (byte == '+') return error.InvalidQuery;
            read_index += 1;
            break :decoded byte;
        };
        if (decoded < 0x21 or decoded > 0x7e or decoded == '&' or decoded == '=' or
            decoded == '%' or decoded == '#' or decoded == '\\')
        {
            return error.InvalidQuery;
        }
        if (write_index == output.len) return error.InvalidQuery;
        output[write_index] = decoded;
        write_index += 1;
    }
    return output[0..write_index];
}

fn hexNibble(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

pub fn parseQuery(text: []const u8, scratch: []u8) !Query {
    if (text.len == 0) return .{};
    var result: Query = .{};
    var scratch_used: usize = 0;
    var pairs = std.mem.splitScalar(u8, text, '&');
    while (pairs.next()) |pair| {
        if (pair.len == 0) return error.InvalidQuery;
        const equals = std.mem.indexOfScalar(u8, pair, '=') orelse return error.InvalidQuery;
        const name = pair[0..equals];
        const encoded_value = pair[equals + 1 ..];
        if (name.len == 0 or std.mem.indexOfScalar(u8, name, '%') != null or
            std.mem.indexOfScalar(u8, name, '+') != null or encoded_value.len == 0 or
            std.mem.indexOfScalar(u8, encoded_value, '=') != null)
        {
            return error.InvalidQuery;
        }
        const value = try decodeQueryComponent(encoded_value, scratch[scratch_used..]);
        scratch_used += value.len;
        if (std.mem.eql(u8, name, "cursor")) {
            if (result.cursor != null or value.len > 512) return error.InvalidQuery;
            result.cursor = value;
        } else if (std.mem.eql(u8, name, "limit")) {
            if (result.limit != null) return error.InvalidQuery;
            result.limit = std.fmt.parseInt(u16, value, 10) catch return error.InvalidQuery;
            if (result.limit.? == 0 or result.limit.? > 200) return error.InvalidQuery;
        } else if (std.mem.eql(u8, name, "vnrName")) {
            if (result.vnr_name != null) return error.InvalidQuery;
            result.vnr_name = value;
        } else if (std.mem.eql(u8, name, "enrollmentState")) {
            if (result.enrollment_state != null) return error.InvalidQuery;
            result.enrollment_state = value;
        } else if (std.mem.eql(u8, name, "nodeId")) {
            if (result.node_id != null) return error.InvalidQuery;
            result.node_id = value;
        } else if (std.mem.eql(u8, name, "scope")) {
            if (result.scope != null or
                !(std.mem.eql(u8, value, "own") or std.mem.eql(u8, value, "all")))
            {
                return error.InvalidQuery;
            }
            result.scope = value;
        } else if (std.mem.eql(u8, name, "liveness")) {
            if (result.liveness != null) return error.InvalidQuery;
            result.liveness = value;
        } else if (std.mem.eql(u8, name, "status")) {
            if (result.status != null) return error.InvalidQuery;
            result.status = value;
        } else if (std.mem.eql(u8, name, "severity")) {
            if (result.severity != null) return error.InvalidQuery;
            result.severity = value;
        } else if (std.mem.eql(u8, name, "since")) {
            if (result.since != null or value.len > 32) return error.InvalidQuery;
            result.since = value;
        } else if (std.mem.eql(u8, name, "actorUserId")) {
            if (result.actor_user_id != null) return error.InvalidQuery;
            result.actor_user_id = value;
        } else if (std.mem.eql(u8, name, "resourceType")) {
            if (result.resource_type != null or value.len > 64) return error.InvalidQuery;
            result.resource_type = value;
        } else {
            return error.InvalidQuery;
        }
    }
    return result;
}

fn requiredString(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidForwardedRequest;
    return if (value == .string) value.string else error.InvalidForwardedRequest;
}

fn optionalString(object: std.json.ObjectMap, name: []const u8) !?[]const u8 {
    const value = object.get(name) orelse return null;
    return switch (value) {
        .string => |text| text,
        else => error.InvalidForwardedRequest,
    };
}

fn parseMethod(value: []const u8) ?http.Method {
    inline for (std.meta.fields(http.Method)) |field| {
        if (std.mem.eql(u8, value, field.name)) return @enumFromInt(field.value);
    }
    return null;
}

fn validateTarget(target: []const u8) !void {
    if (target.len == 0 or target.len > http.maximum_target_bytes or target[0] != '/') {
        return error.InvalidForwardedRequest;
    }
    const query_start = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    for (target, 0..) |byte, index| {
        if (byte < 0x21 or byte > 0x7e or byte == '#') return error.InvalidForwardedRequest;
        if (index < query_start and (byte == '%' or byte == '\\')) return error.InvalidForwardedRequest;
    }
}

test "forwarded request decoder rejects unknown fields and non-loopback claims" {
    const valid =
        \\{"method":"GET","target":"/api/v1/vnrs?limit=50","proxyPeer":"loopback","body":null,"sessionToken":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, valid, .{});
    defer parsed.deinit();
    const request = try decode(parsed.value);
    try std.testing.expectEqual(http.Method.GET, request.method);
    try std.testing.expect(request.session_token != null);
    try std.testing.expectEqualStrings("limit=50", request.query());
    try std.testing.expectEqualStrings("loopback", request.proxy_peer);

    const unknown =
        \\{"method":"GET","target":"/api/v1/vnrs","proxyPeer":"loopback","body":null,"forwardedFor":"198.51.100.8"}
    ;
    const unknown_parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, unknown, .{});
    defer unknown_parsed.deinit();
    try std.testing.expectError(error.InvalidForwardedRequest, decode(unknown_parsed.value));

    const unsafe_agent =
        \\{"method":"GET","target":"/api/v1/vnrs","proxyPeer":"loopback","body":null,"userAgent":"bad\u000aagent"}
    ;
    const unsafe_agent_parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        unsafe_agent,
        .{},
    );
    defer unsafe_agent_parsed.deinit();
    try std.testing.expectError(error.InvalidForwardedRequest, decode(unsafe_agent_parsed.value));
}

test "body decoding is strict and query parsing rejects ambiguity" {
    const body_json = "{\"username\":\"admin\",\"password\":\"correct horse battery staple\"}";
    const value = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, body_json, .{});
    defer value.deinit();
    const Login = struct { username: []const u8, password: []const u8 };
    const body = try decodeBody(Login, std.testing.allocator, value.value);
    defer body.deinit();
    try std.testing.expectEqualStrings("admin", body.value.username);

    var scratch: [http.maximum_target_bytes]u8 = undefined;
    const query = try parseQuery("cursor=v1:n:abcd&limit=50&vnrName=edge", &scratch);
    try std.testing.expectEqual(@as(u16, 50), query.limit.?);
    try std.testing.expectError(error.InvalidQuery, parseQuery("limit=50&limit=51", &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("unknown=value", &scratch));
    try std.testing.expectEqualStrings("all", (try parseQuery("scope=all", &scratch)).scope.?);
    try std.testing.expectError(error.InvalidQuery, parseQuery("scope=other", &scratch));

    const operational = try parseQuery(
        "liveness=suspect&status=running&severity=warning&since=2026-07-20T00:00:00Z&" ++
            "actorUserId=abababababababababababababababab&resourceType=node",
        &scratch,
    );
    try std.testing.expectEqualStrings("suspect", operational.liveness.?);
    try std.testing.expectEqualStrings("running", operational.status.?);
    try std.testing.expectEqualStrings("warning", operational.severity.?);
    try std.testing.expectEqualStrings("2026-07-20T00:00:00Z", operational.since.?);
    try std.testing.expectEqualStrings("abababababababababababababababab", operational.actor_user_id.?);
    try std.testing.expectEqualStrings("node", operational.resource_type.?);
    try std.testing.expectError(error.InvalidQuery, parseQuery("status=running&status=failed", &scratch));
}

test "query decoding accepts URLSearchParams cursors and canonical timestamps" {
    var scratch: [http.maximum_target_bytes]u8 = undefined;
    const query = try parseQuery(
        "cursor=v1%3An%3Aabababababababababababababababab&" ++
            "since=2026-07-20T12%3A34%3A56Z",
        &scratch,
    );
    try std.testing.expectEqualStrings(
        "v1:n:abababababababababababababababab",
        query.cursor.?,
    );
    try std.testing.expectEqualStrings("2026-07-20T12:34:56Z", query.since.?);

    try std.testing.expectError(error.InvalidQuery, parseQuery("cursor=v1%3", &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("cursor=v1%GG", &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("cursor=v1%00", &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("cursor=v1%26next", &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("cursor=v1+next", &scratch));
    try std.testing.expectError(error.InvalidQuery, parseQuery("cur%73or=value", &scratch));

    var bounded: [2]u8 = undefined;
    try std.testing.expectError(error.InvalidQuery, decodeQueryComponent("abc", &bounded));
}

test "path parameters are one exact unescaped segment" {
    try std.testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef",
        try pathParameter(
            "/api/v1/nodes/0123456789abcdef0123456789abcdef/actions/reset-enrollment",
            "/api/v1/nodes/",
            "/actions/reset-enrollment",
        ),
    );
    try std.testing.expectError(error.InvalidTarget, pathParameter("/api/v1/nodes/a/b", "/api/v1/nodes/", ""));
}
