//! Small, transport-facing response helpers shared by management API slices.
//!
//! The authoritative application writes the HTTP status/metadata and JSON
//! body as the private service protocol's `ServiceHttpResponseFrame` shape.
//! JSON bodies are wiped immediately after the response sink encodes them.

const std = @import("std");
const service_server = @import("service_server.zig");
const service_ipc = @import("service_ipc.zig");

pub const json_content_type = "application/json; charset=utf-8";
pub const maximum_timestamp_seconds: i64 = 253_402_300_799; // 9999-12-31T23:59:59Z
pub const timestamp_text_len: usize = 20;

pub const Metadata = struct {
    etag: ?[]const u8 = null,
    location: ?[]const u8 = null,
    content_disposition: ?[]const u8 = null,
    audit_export_id: ?[]const u8 = null,
    retry_after_seconds: ?u32 = null,
    set_cookie: ?[]const u8 = null,
};

pub fn finishJson(
    sink: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    value: anytype,
    metadata: Metadata,
) !void {
    const body = try std.json.Stringify.valueAlloc(allocator, value, .{
        .emit_null_optional_fields = false,
    });
    defer {
        std.crypto.secureZero(u8, body);
        allocator.free(body);
    }
    try finishBody(sink, allocator, status, json_content_type, body, metadata);
}

pub fn finishBody(
    sink: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    status: u16,
    content_type: []const u8,
    body: []const u8,
    metadata: Metadata,
) !void {
    if (status < 100 or status > 599) return error.InvalidHttpStatus;
    var object: std.json.ObjectMap = .empty;
    defer object.deinit(allocator);
    try object.put(allocator, "status", .{ .integer = status });
    try object.put(allocator, "contentType", .{ .string = content_type });
    if (body.len != 0) try object.put(allocator, "bodyChunk", .{ .string = body });
    if (metadata.etag) |value| try object.put(allocator, "etag", .{ .string = value });
    if (metadata.location) |value| try object.put(allocator, "location", .{ .string = value });
    if (metadata.content_disposition) |value| {
        try object.put(allocator, "contentDisposition", .{ .string = value });
    }
    if (metadata.audit_export_id) |value| {
        try object.put(allocator, "auditExportId", .{ .string = value });
    }
    if (metadata.retry_after_seconds) |value| {
        try object.put(allocator, "retryAfterSeconds", .{ .integer = value });
    }
    if (metadata.set_cookie) |value| try object.put(allocator, "setCookie", .{ .string = value });
    try sink.finish(.{ .object = object });
}

pub fn finishNoContent(
    sink: *service_server.ResponseSink,
    allocator: std.mem.Allocator,
    metadata: Metadata,
) !void {
    return finishBody(sink, allocator, 204, json_content_type, "", metadata);
}

pub fn fail(
    sink: *service_server.ResponseSink,
    code: service_ipc.ErrorCode,
    message: []const u8,
    retryable: bool,
) !void {
    return sink.fail(code, message, retryable);
}

pub fn failWithViolations(
    sink: *service_server.ResponseSink,
    code: service_ipc.ErrorCode,
    message: []const u8,
    retryable: bool,
    violations: []const service_ipc.FieldViolation,
) !void {
    return sink.failWithViolations(code, message, retryable, violations);
}

pub fn failWithMetadata(
    sink: *service_server.ResponseSink,
    code: service_ipc.ErrorCode,
    message: []const u8,
    retryable: bool,
    metadata: service_ipc.ErrorMetadata,
) !void {
    return sink.failWithMetadata(code, message, retryable, metadata);
}

pub fn formatTimestamp(seconds: i64, output: *[timestamp_text_len]u8) ![]const u8 {
    if (seconds < 0 or seconds > maximum_timestamp_seconds) return error.InvalidTimestamp;
    const epoch_seconds: std.time.epoch.EpochSeconds = .{ .secs = @intCast(seconds) };
    const year_day = epoch_seconds.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    return std.fmt.bufPrint(output, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        year_day.year,
        month_day.month.numeric(),
        @as(u8, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    });
}

pub fn decodeId(text: []const u8) ![16]u8 {
    if (text.len != 32) return error.InvalidIdentifier;
    var result: [16]u8 = undefined;
    for (&result, 0..) |*byte, index| {
        const high = decodeNibble(text[index * 2]) orelse return error.InvalidIdentifier;
        const low = decodeNibble(text[index * 2 + 1]) orelse return error.InvalidIdentifier;
        byte.* = high << 4 | low;
    }
    return result;
}

pub fn encodeId(id: [16]u8, output: *[32]u8) []const u8 {
    const alphabet = "0123456789abcdef";
    for (id, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

fn decodeNibble(value: u8) ?u8 {
    return switch (value) {
        '0'...'9' => value - '0',
        'a'...'f' => value - 'a' + 10,
        else => null,
    };
}

test "RFC 3339 UTC timestamps are canonical and bounded" {
    var output: [timestamp_text_len]u8 = undefined;
    try std.testing.expectEqualStrings("1970-01-01T00:00:00Z", try formatTimestamp(0, &output));
    try std.testing.expectEqualStrings("2021-07-01T17:11:13Z", try formatTimestamp(1_625_159_473, &output));
    try std.testing.expectEqualStrings("9999-12-31T23:59:59Z", try formatTimestamp(maximum_timestamp_seconds, &output));
    try std.testing.expectError(error.InvalidTimestamp, formatTimestamp(-1, &output));
    try std.testing.expectError(error.InvalidTimestamp, formatTimestamp(maximum_timestamp_seconds + 1, &output));
}

test "opaque identifiers use exact lowercase 32-character text" {
    const id = [_]u8{0xab} ** 16;
    var text: [32]u8 = undefined;
    try std.testing.expectEqualStrings("abababababababababababababababab", encodeId(id, &text));
    try std.testing.expectEqualSlices(u8, &id, &(try decodeId(&text)));
    try std.testing.expectError(error.InvalidIdentifier, decodeId("ABABABABABABABABABABABABABABABAB"));
}

test "JSON response helper emits private HTTP response metadata" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var sink = try service_server.ResponseSink.init(
        std.testing.allocator,
        &output.writer,
        "0123456789abcdef0123456789abcdef",
    );
    try finishJson(&sink, std.testing.allocator, 200, .{ .status = "ready" }, .{ .etag = "\"ready:1\"" });
    var framed = std.Io.Reader.fixed(output.written());
    var storage: [service_ipc.maximum_frame_bytes]u8 = undefined;
    const frame_bytes = try service_ipc.readFrame(&framed, &storage);
    const parsed = try service_ipc.decodeResponseFrame(std.testing.allocator, frame_bytes);
    defer parsed.deinit();
    const payload = parsed.value.payload.?.object;
    try std.testing.expectEqualStrings("{\"status\":\"ready\"}", payload.get("bodyChunk").?.string);
    try std.testing.expectEqualStrings("\"ready:1\"", payload.get("etag").?.string);
}
