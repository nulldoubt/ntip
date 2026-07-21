//! Versioned framing and strict JSON contracts for the private
//! `ntip-api` -> `ntsrv` management socket.
//!
//! This protocol is deliberately separate from `runtime/ipc.zig`: that
//! module is the human CLI transport, while this one carries authenticated
//! web actor context, mutation preconditions, deadlines, and bounded
//! response streams. Authentication of the Unix peer belongs to the socket
//! server; every field in this module remains untrusted input.

const std = @import("std");
const api_error = @import("error.zig");

pub const protocol_version: u16 = 2;
pub const frame_prefix_bytes: usize = 4;
pub const maximum_frame_bytes: usize = 1024 * 1024;
pub const maximum_operation_bytes: usize = 96;
pub const maximum_user_agent_bytes: usize = 512;
pub const maximum_etag_bytes: usize = 128;
pub const maximum_idempotency_key_bytes: usize = 128;
pub const maximum_confirmation_bytes: usize = 256;
pub const maximum_error_retry_after_seconds: u32 = 24 * 60 * 60;
pub const identifier_text_bytes: usize = api_error.identifier_text_bytes;

pub const ActorKind = enum {
    /// Login and readiness requests that have no authenticated web session.
    anonymous,
    /// A request backed by an authenticated user and opaque web session.
    authenticated,
    /// A service-internal request such as a dependency readiness probe.
    service,
};

pub const ActorContext = struct {
    kind: ActorKind,
    user_id: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    user_agent: ?[]const u8 = null,
};

pub const Preconditions = struct {
    etag: ?[]const u8 = null,
    idempotency_key: ?[]const u8 = null,
    reauthenticated_at_unix_ms: ?i64 = null,
    confirmation: ?[]const u8 = null,
};

pub const Request = struct {
    version: u16,
    request_id: []const u8,
    deadline_unix_ms: i64,
    operation: []const u8,
    actor: ActorContext,
    preconditions: Preconditions = .{},
    payload: std.json.Value,
};

/// Stable machine-readable failures shared across the private service
/// boundary. New values may be appended, but existing spellings are API.
pub const ErrorCode = api_error.Code;
pub const FieldViolation = api_error.FieldViolation;

/// Bounded response metadata that is safe to expose as public HTTP headers.
/// Only metadata required by the stable error contract is accepted.
pub const ErrorMetadata = struct {
    etag: ?[]const u8 = null,
    retry_after_seconds: ?u32 = null,
};

pub const ErrorMetadataRequirements = struct {
    etag: bool = false,
    retry_after_seconds: bool = false,
};

pub const ErrorBody = struct {
    code: ErrorCode,
    message: []const u8,
    retryable: bool = false,
    metadata: ?ErrorMetadata = null,
    violations: ?[]const FieldViolation = null,
};

pub fn errorMetadataRequirements(code: ErrorCode) ErrorMetadataRequirements {
    return switch (code) {
        .precondition_failed => .{ .etag = true },
        .rate_limited, .operation_unavailable, .service_unavailable => .{
            .retry_after_seconds = true,
        },
        else => .{},
    };
}

/// One frame in a bounded response stream. Sequence numbers start at zero.
/// A terminal success may omit `payload`; an error is always terminal.
pub const ResponseFrame = struct {
    version: u16,
    request_id: []const u8,
    sequence: u32,
    final: bool,
    payload: ?std.json.Value = null,
    @"error": ?ErrorBody = null,
};

pub fn encodeLength(destination: *[frame_prefix_bytes]u8, length: usize) !void {
    if (length == 0 or length > maximum_frame_bytes) return error.InvalidFrameLength;
    std.mem.writeInt(u32, destination, @intCast(length), .big);
}

pub fn decodeLength(source: *const [frame_prefix_bytes]u8) !usize {
    const length = std.mem.readInt(u32, source, .big);
    if (length == 0 or length > maximum_frame_bytes) return error.InvalidFrameLength;
    return length;
}

pub fn readFrame(reader: *std.Io.Reader, destination: []u8) ![]u8 {
    var prefix: [frame_prefix_bytes]u8 = undefined;
    try reader.readSliceAll(&prefix);
    const length = try decodeLength(&prefix);
    if (length > destination.len) return error.DestinationTooSmall;
    try reader.readSliceAll(destination[0..length]);
    return destination[0..length];
}

pub fn writeFrame(writer: *std.Io.Writer, body: []const u8) !void {
    var prefix: [frame_prefix_bytes]u8 = undefined;
    try encodeLength(&prefix, body.len);
    try writer.writeAll(&prefix);
    try writer.writeAll(body);
    try writer.flush();
}

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Request) {
    if (bytes.len == 0 or bytes.len > maximum_frame_bytes) return error.InvalidRequest;
    const parsed = std.json.parseFromSlice(Request, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidRequestJson;
    errdefer parsed.deinit();
    try validateRequest(parsed.value);
    return parsed;
}

pub fn decodeResponseFrame(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(ResponseFrame) {
    if (bytes.len == 0 or bytes.len > maximum_frame_bytes) return error.InvalidResponseFrame;
    const parsed = std.json.parseFromSlice(ResponseFrame, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidResponseJson;
    errdefer parsed.deinit();
    try validateResponseFrame(parsed.value);
    return parsed;
}

pub fn encodeRequest(allocator: std.mem.Allocator, request: Request) ![]u8 {
    try validateRequest(request);
    return encodeBounded(allocator, request);
}

pub fn encodeResponseFrame(allocator: std.mem.Allocator, frame: ResponseFrame) ![]u8 {
    try validateResponseFrame(frame);
    return encodeBounded(allocator, frame);
}

pub fn validateRequest(request: Request) !void {
    if (request.version != protocol_version) return error.UnsupportedProtocolVersion;
    if (!isIdentifier(request.request_id)) return error.InvalidRequestId;
    if (request.deadline_unix_ms <= 0) return error.InvalidDeadline;
    if (!isOperation(request.operation)) return error.InvalidOperation;
    if (request.payload != .object) return error.InvalidPayload;
    try validateActor(request.actor);
    try validatePreconditions(request.preconditions);
}

pub fn validateResponseFrame(frame: ResponseFrame) !void {
    if (frame.version != protocol_version) return error.UnsupportedProtocolVersion;
    if (!isIdentifier(frame.request_id)) return error.InvalidRequestId;
    if (frame.@"error") |failure| {
        if (!frame.final or frame.payload != null) return error.InvalidResponseFrame;
        if (failure.message.len == 0 or failure.message.len > 512 or !isSafeText(failure.message)) {
            return error.InvalidResponseFrame;
        }
        api_error.validateEnvelopeBounds(
            frame.request_id,
            failure.code,
            failure.message,
            failure.violations,
        ) catch return error.InvalidResponseFrame;
        try validateErrorMetadata(failure);
    }
}

fn validateErrorMetadata(failure: ErrorBody) !void {
    const requirements = errorMetadataRequirements(failure.code);
    const metadata = failure.metadata orelse ErrorMetadata{};
    if ((metadata.etag != null) != requirements.etag or
        (metadata.retry_after_seconds != null) != requirements.retry_after_seconds)
    {
        return error.InvalidResponseFrame;
    }
    if (metadata.etag) |value| {
        if (!isStrongEntityTag(value)) return error.InvalidResponseFrame;
    }
    if (metadata.retry_after_seconds) |value| {
        if (value == 0 or value > maximum_error_retry_after_seconds) {
            return error.InvalidResponseFrame;
        }
    }
}

pub fn isIdentifier(value: []const u8) bool {
    return api_error.isIdentifier(value);
}

fn validateActor(actor: ActorContext) !void {
    switch (actor.kind) {
        .authenticated => {
            if (!isIdentifier(actor.user_id orelse return error.InvalidActor)) return error.InvalidActor;
            if (!isIdentifier(actor.session_id orelse return error.InvalidActor)) return error.InvalidActor;
        },
        .anonymous, .service => if (actor.user_id != null or actor.session_id != null) return error.InvalidActor,
    }
    if (actor.user_agent) |value| {
        if (value.len > maximum_user_agent_bytes or !isSafeText(value)) return error.InvalidActor;
    }
}

fn validatePreconditions(preconditions: Preconditions) !void {
    if (preconditions.etag) |value| {
        if (value.len == 0 or value.len > maximum_etag_bytes or !isSafeText(value)) return error.InvalidPrecondition;
    }
    if (preconditions.idempotency_key) |value| {
        if (value.len == 0 or value.len > maximum_idempotency_key_bytes or !isVisibleAscii(value)) {
            return error.InvalidPrecondition;
        }
    }
    if (preconditions.reauthenticated_at_unix_ms) |value| {
        if (value <= 0) return error.InvalidPrecondition;
    }
    if (preconditions.confirmation) |value| {
        if (value.len == 0 or value.len > maximum_confirmation_bytes or !isSafeText(value)) {
            return error.InvalidPrecondition;
        }
    }
}

fn isOperation(value: []const u8) bool {
    if (value.len == 0 or value.len > maximum_operation_bytes) return false;
    if (value[0] == '.' or value[value.len - 1] == '.') return false;
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

fn isSafeText(value: []const u8) bool {
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return std.unicode.utf8ValidateSlice(value);
}

fn isVisibleAscii(value: []const u8) bool {
    for (value) |byte| if (byte < 0x21 or byte > 0x7e) return false;
    return true;
}

fn isStrongEntityTag(value: []const u8) bool {
    if (value.len < 3 or value.len > maximum_etag_bytes or
        value[0] != '"' or value[value.len - 1] != '"') return false;
    const tag_value = value[1 .. value.len - 1];
    if (tag_value.len > 96) return false;
    for (tag_value) |byte| switch (byte) {
        'a'...'z', '0'...'9', '.', '_', ':', '-' => {},
        else => return false,
    };
    return true;
}

fn encodeBounded(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    errdefer allocator.free(bytes);
    if (bytes.len == 0 or bytes.len > maximum_frame_bytes) return error.FrameTooLarge;
    return bytes;
}

test "service IPC length prefix is big endian and strictly bounded" {
    var prefix: [frame_prefix_bytes]u8 = undefined;
    try encodeLength(&prefix, 0x010203);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x03 }, &prefix);
    try std.testing.expectEqual(@as(usize, 0x010203), try decodeLength(&prefix));
    try std.testing.expectError(error.InvalidFrameLength, encodeLength(&prefix, 0));
    try std.testing.expectError(error.InvalidFrameLength, encodeLength(&prefix, maximum_frame_bytes + 1));
}

test "service IPC request JSON is strict, versioned, and carries preconditions" {
    const bytes =
        \\{"version":2,"request_id":"0123456789abcdef0123456789abcdef","deadline_unix_ms":1784500000000,"operation":"inventory.node.update","actor":{"kind":"authenticated","user_id":"11111111111111111111111111111111","session_id":"22222222222222222222222222222222","user_agent":"browser"},"preconditions":{"etag":"\"generation-4\"","idempotency_key":"mutation-7","reauthenticated_at_unix_ms":1784499999000,"confirmation":"node-a"},"payload":{"name":"node-a"}}
    ;
    const parsed = try decodeRequest(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("inventory.node.update", parsed.value.operation);
    try std.testing.expectEqualStrings("mutation-7", parsed.value.preconditions.idempotency_key.?);

    const duplicate =
        \\{"version":2,"version":2,"request_id":"0123456789abcdef0123456789abcdef","deadline_unix_ms":1,"operation":"health.ready","actor":{"kind":"service"},"payload":{}}
    ;
    try std.testing.expectError(error.InvalidRequestJson, decodeRequest(std.testing.allocator, duplicate));

    const unknown =
        \\{"version":2,"request_id":"0123456789abcdef0123456789abcdef","deadline_unix_ms":1,"operation":"health.ready","actor":{"kind":"service"},"payload":{},"extra":true}
    ;
    try std.testing.expectError(error.InvalidRequestJson, decodeRequest(std.testing.allocator, unknown));

    const old_version =
        \\{"version":1,"request_id":"0123456789abcdef0123456789abcdef","deadline_unix_ms":1,"operation":"health.ready","actor":{"kind":"service"},"payload":{}}
    ;
    try std.testing.expectError(
        error.UnsupportedProtocolVersion,
        decodeRequest(std.testing.allocator, old_version),
    );
}

test "service IPC validates actors, identifiers, operations, and object payloads" {
    var object: std.json.ObjectMap = .{};
    defer object.deinit(std.testing.allocator);
    const payload: std.json.Value = .{ .object = object };
    const base: Request = .{
        .version = protocol_version,
        .request_id = "0123456789abcdef0123456789abcdef",
        .deadline_unix_ms = 1,
        .operation = "health.ready",
        .actor = .{ .kind = .service },
        .payload = payload,
    };
    try validateRequest(base);

    var invalid_id = base;
    invalid_id.request_id = "0123456789ABCDEF0123456789ABCDEF";
    try std.testing.expectError(error.InvalidRequestId, validateRequest(invalid_id));

    var invalid_actor = base;
    invalid_actor.actor = .{ .kind = .authenticated, .user_id = base.request_id };
    try std.testing.expectError(error.InvalidActor, validateRequest(invalid_actor));

    var invalid_operation = base;
    invalid_operation.operation = "inventory..read";
    try std.testing.expectError(error.InvalidOperation, validateRequest(invalid_operation));
}

test "service IPC response errors are stable and terminal" {
    const frame: ResponseFrame = .{
        .version = protocol_version,
        .request_id = "0123456789abcdef0123456789abcdef",
        .sequence = 0,
        .final = true,
        .@"error" = .{
            .code = .precondition_failed,
            .message = "resource generation changed",
            .metadata = .{ .etag = "\"node:0123456789abcdef0123456789abcdef:4\"" },
        },
    };
    const encoded = try encodeResponseFrame(std.testing.allocator, frame);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"code\":\"precondition_failed\"") != null);

    const parsed = try decodeResponseFrame(std.testing.allocator, encoded);
    defer parsed.deinit();
    try std.testing.expectEqual(ErrorCode.precondition_failed, parsed.value.@"error".?.code);

    var non_terminal = frame;
    non_terminal.final = false;
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(non_terminal));

    var missing_metadata = frame;
    missing_metadata.@"error".?.metadata = null;
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(missing_metadata));

    var injected = frame;
    injected.@"error".?.metadata.?.etag = "\"safe\"\r\nInjected: true";
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(injected));

    var retryable = frame;
    retryable.@"error" = .{
        .code = .service_unavailable,
        .message = "service unavailable",
        .retryable = true,
        .metadata = .{ .retry_after_seconds = 1 },
    };
    try validateResponseFrame(retryable);
    retryable.@"error".?.metadata.?.retry_after_seconds = 0;
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(retryable));
}

test "service IPC v2 errors carry strictly bounded field violations" {
    const valid = FieldViolation{
        .field = "address",
        .code = "address_in_use",
        .message = "Address is already assigned.",
    };
    const violations = [_]FieldViolation{valid};
    const frame: ResponseFrame = .{
        .version = protocol_version,
        .request_id = "0123456789abcdef0123456789abcdef",
        .sequence = 0,
        .final = true,
        .@"error" = .{
            .code = .conflict,
            .message = "resource conflicts with current state",
            .violations = &violations,
        },
    };
    const encoded = try encodeResponseFrame(std.testing.allocator, frame);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"version\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "\"code\":\"address_in_use\"") != null);

    const parsed = try decodeResponseFrame(std.testing.allocator, encoded);
    defer parsed.deinit();
    const decoded = parsed.value.@"error".?.violations.?;
    try std.testing.expectEqual(@as(usize, 1), decoded.len);
    try std.testing.expectEqualStrings("address", decoded[0].field);
    try std.testing.expectEqualStrings("address_in_use", decoded[0].code);

    var empty = frame;
    empty.@"error".?.violations = &.{};
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(empty));

    const too_many = [_]FieldViolation{valid} ** (api_error.maximum_violations + 1);
    var oversized = frame;
    oversized.@"error".?.violations = &too_many;
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(oversized));

    const malformed = [_]FieldViolation{.{
        .field = "address",
        .code = "Address-In-Use",
        .message = "Address is already assigned.",
    }};
    var invalid_code = frame;
    invalid_code.@"error".?.violations = &malformed;
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(invalid_code));

    const large = FieldViolation{
        .field = "\\" ** 256,
        .code = "bounded_violation",
        .message = "\\" ** api_error.maximum_message_bytes,
    };
    const aggregate = [_]FieldViolation{large} ** api_error.maximum_violations;
    var aggregate_oversized = frame;
    aggregate_oversized.@"error".?.violations = &aggregate;
    try std.testing.expectError(error.InvalidResponseFrame, validateResponseFrame(aggregate_oversized));
}
