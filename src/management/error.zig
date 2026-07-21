//! Stable error vocabulary and JSON envelope used by the management API.

const std = @import("std");

pub const maximum_encoded_bytes: usize = 64 * 1024;
pub const identifier_text_bytes: usize = 32;
pub const maximum_message_bytes: usize = 512;
pub const maximum_violations: usize = 64;

/// Existing names are part of the v1 contract and must not be renamed.
pub const Code = enum {
    invalid_request,
    validation_failed,
    authentication_required,
    invalid_credentials,
    password_change_required,
    csrf_failed,
    origin_forbidden,
    forbidden,
    reauthentication_required,
    not_found,
    conflict,
    invariant_violation,
    idempotency_required,
    idempotency_conflict,
    precondition_required,
    precondition_failed,
    rate_limited,
    service_unavailable,
    operation_unavailable,
    internal_error,
};

pub const FieldViolation = struct {
    field: []const u8,
    code: []const u8,
    message: []const u8,
};

pub const Body = struct {
    code: Code,
    message: []const u8,
    requestId: []const u8,
    violations: ?[]const FieldViolation = null,
};

pub const Envelope = struct {
    @"error": Body,
};

pub fn make(request_id: []const u8, code: Code, message: []const u8) !Envelope {
    if (!isIdentifier(request_id)) return error.InvalidRequestId;
    if (message.len == 0 or message.len > maximum_message_bytes or !isSafeText(message)) {
        return error.InvalidErrorMessage;
    }
    return .{ .@"error" = .{
        .code = code,
        .message = message,
        .requestId = request_id,
    } };
}

pub fn encode(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    code: Code,
    message: []const u8,
) ![]u8 {
    try validateEnvelopeBounds(request_id, code, message, null);
    const envelope = try make(request_id, code, message);
    return encodeEnvelope(allocator, envelope);
}

pub fn encodeWithViolations(
    allocator: std.mem.Allocator,
    request_id: []const u8,
    code: Code,
    message: []const u8,
    violations: []const FieldViolation,
) ![]u8 {
    try validateEnvelopeBounds(request_id, code, message, violations);
    var envelope = try make(request_id, code, message);
    envelope.@"error".violations = violations;
    return encodeEnvelope(allocator, envelope);
}

/// Validates the public field-violation shape independently of JSON
/// encoding so the typed ntsrv -> ntip-api protocol can enforce the exact
/// same bounds before accepting a response frame.
pub fn validateViolations(violations: []const FieldViolation) !void {
    if (violations.len == 0 or violations.len > maximum_violations) {
        return error.InvalidViolations;
    }
    for (violations) |violation| try validateViolation(violation);
}

/// Ensures a shape accepted across service IPC is also guaranteed to fit the
/// public HTTP error-envelope limit. The estimate deliberately assumes every
/// input byte may require a six-byte JSON escape, so accepted shapes cannot
/// fail later when the HTTP bridge performs exact serialization.
pub fn validateEnvelopeBounds(
    request_id: []const u8,
    code: Code,
    message: []const u8,
    violations: ?[]const FieldViolation,
) !void {
    _ = try make(request_id, code, message);
    var maximum_json_bytes: usize = 512 +
        6 * (request_id.len + @tagName(code).len + message.len);
    if (violations) |items| {
        try validateViolations(items);
        for (items) |violation| {
            maximum_json_bytes += 128 +
                6 * (violation.field.len + violation.code.len + violation.message.len);
            if (maximum_json_bytes > maximum_encoded_bytes) {
                return error.ErrorEnvelopeTooLarge;
            }
        }
    }
    if (maximum_json_bytes > maximum_encoded_bytes) return error.ErrorEnvelopeTooLarge;
}

fn encodeEnvelope(allocator: std.mem.Allocator, envelope: Envelope) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, envelope, .{ .emit_null_optional_fields = false });
    errdefer allocator.free(bytes);
    if (bytes.len > maximum_encoded_bytes) return error.ErrorEnvelopeTooLarge;
    return bytes;
}

fn validateViolation(violation: FieldViolation) !void {
    if (violation.field.len == 0 or violation.field.len > 256 or !isSafeText(violation.field)) {
        return error.InvalidViolations;
    }
    if (violation.code.len == 0 or violation.code.len > 64 or
        !(violation.code[0] >= 'a' and violation.code[0] <= 'z')) return error.InvalidViolations;
    for (violation.code) |byte| switch (byte) {
        'a'...'z', '0'...'9', '_' => {},
        else => return error.InvalidViolations,
    };
    if (violation.message.len == 0 or violation.message.len > maximum_message_bytes or
        !isSafeText(violation.message)) return error.InvalidViolations;
}

pub fn isIdentifier(value: []const u8) bool {
    if (value.len != identifier_text_bytes) return false;
    for (value) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn isSafeText(value: []const u8) bool {
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return std.unicode.utf8ValidateSlice(value);
}

test "management errors encode a stable camelCase envelope" {
    const request_id = "0123456789abcdef0123456789abcdef";
    const bytes = try encode(std.testing.allocator, request_id, .precondition_failed, "resource generation changed");
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(
        "{\"error\":{\"code\":\"precondition_failed\",\"message\":\"resource generation changed\",\"requestId\":\"0123456789abcdef0123456789abcdef\"}}",
        bytes,
    );
}

test "management validation errors use the canonical violations shape" {
    const violations = [_]FieldViolation{.{
        .field = "cidr",
        .code = "invalid_cidr",
        .message = "CIDR is not a canonical IPv4 prefix",
    }};
    const bytes = try encodeWithViolations(
        std.testing.allocator,
        "0123456789abcdef0123456789abcdef",
        .validation_failed,
        "request validation failed",
        &violations,
    );
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "\"violations\":[{\"field\":\"cidr\"") != null);
}

test "management errors reject unsafe public messages and request ids" {
    try std.testing.expectError(
        error.InvalidRequestId,
        make("ABCDEF", .invalid_request, "invalid request"),
    );
    try std.testing.expectError(
        error.InvalidErrorMessage,
        make("0123456789abcdef0123456789abcdef", .invalid_request, "line one\nline two"),
    );
}

test "management errors reject aggregate violation shapes that cannot fit HTTP" {
    const large = FieldViolation{
        .field = "\\" ** 256,
        .code = "bounded_violation",
        .message = "\\" ** maximum_message_bytes,
    };
    const violations = [_]FieldViolation{large} ** maximum_violations;
    try std.testing.expectError(
        error.ErrorEnvelopeTooLarge,
        validateEnvelopeBounds(
            "0123456789abcdef0123456789abcdef",
            .invariant_violation,
            "domain invariant would be violated",
            &violations,
        ),
    );
}
