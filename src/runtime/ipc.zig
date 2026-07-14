const std = @import("std");

pub const protocol_version: u16 = 1;
pub const maximum_message_bytes: usize = 1024 * 1024;
pub const prefix_bytes: usize = 4;

pub fn encodeLength(destination: *[prefix_bytes]u8, length: usize) !void {
    if (length == 0 or length > maximum_message_bytes) return error.InvalidMessageLength;
    std.mem.writeInt(u32, destination, @intCast(length), .big);
}

pub fn decodeLength(source: *const [prefix_bytes]u8) !usize {
    const length = std.mem.readInt(u32, source, .big);
    if (length == 0 or length > maximum_message_bytes) return error.InvalidMessageLength;
    return length;
}

pub const Request = struct {
    version: u16,
    request_id: u64,
    command: []const u8,
    arguments: std.json.Value,
};

pub const ErrorBody = struct {
    code: []const u8,
    message: []const u8,
};

pub const Response = struct {
    version: u16,
    request_id: u64,
    ok: bool,
    exit_code: u8,
    result: ?std.json.Value,
    @"error": ?ErrorBody,
};

pub fn validateRequest(request: Request) !void {
    if (request.version != protocol_version) return error.UnsupportedIpcVersion;
    if (request.request_id == 0) return error.InvalidRequest;
    if (request.command.len == 0 or request.command.len > 128) return error.InvalidRequest;
    for (request.command) |byte| switch (byte) {
        'a'...'z', '0'...'9', '.', '_', '-' => {},
        else => return error.InvalidRequest,
    };
    if (request.arguments != .object) return error.InvalidRequest;
}

pub fn validateResponse(response: Response) !void {
    if (response.version != protocol_version or response.request_id == 0) return error.InvalidResponse;
    if (response.ok) {
        if (response.exit_code != 0 or response.@"error" != null) return error.InvalidResponse;
    } else {
        if (response.exit_code == 0 or response.@"error" == null) return error.InvalidResponse;
    }
    if (response.result) |result| if (result != .object) return error.InvalidResponse;
}

pub fn decodeRequest(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Request) {
    if (bytes.len == 0 or bytes.len > maximum_message_bytes) return error.InvalidRequest;
    const parsed = std.json.parseFromSlice(Request, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidRequestJson;
    errdefer parsed.deinit();
    try validateRequest(parsed.value);
    return parsed;
}

pub fn decodeResponse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Response) {
    if (bytes.len == 0 or bytes.len > maximum_message_bytes) return error.InvalidResponse;
    const parsed = std.json.parseFromSlice(Response, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidResponseJson;
    errdefer parsed.deinit();
    try validateResponse(parsed.value);
    return parsed;
}

pub fn encodeResponse(allocator: std.mem.Allocator, response: Response) ![]u8 {
    try validateResponse(response);
    const bytes = try std.json.Stringify.valueAlloc(allocator, response, .{});
    if (bytes.len > maximum_message_bytes) {
        allocator.free(bytes);
        return error.ResponseTooLarge;
    }
    return bytes;
}

pub fn readFrame(reader: *std.Io.Reader, destination: []u8) ![]u8 {
    var prefix: [prefix_bytes]u8 = undefined;
    try reader.readSliceAll(&prefix);
    const length = try decodeLength(&prefix);
    if (length > destination.len) return error.DestinationTooSmall;
    try reader.readSliceAll(destination[0..length]);
    return destination[0..length];
}

pub fn writeFrame(writer: *std.Io.Writer, body: []const u8) !void {
    var prefix: [prefix_bytes]u8 = undefined;
    try encodeLength(&prefix, body.len);
    try writer.writeAll(&prefix);
    try writer.writeAll(body);
    try writer.flush();
}

test "IPC length prefix is network byte order and bounded" {
    var prefix: [4]u8 = undefined;
    try encodeLength(&prefix, 0x010203);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x01, 0x02, 0x03 }, &prefix);
    try std.testing.expectEqual(@as(usize, 0x010203), try decodeLength(&prefix));
    try std.testing.expectError(error.InvalidMessageLength, encodeLength(&prefix, 0));
}

test "IPC JSON contract is strict and versioned" {
    const request_bytes =
        \\{"version":1,"request_id":7,"command":"vnr.create","arguments":{"name":"vnr0","cidr":"10.1.0.0/24"}}
    ;
    const request = try decodeRequest(std.testing.allocator, request_bytes);
    defer request.deinit();
    try std.testing.expectEqualStrings("vnr.create", request.value.command);

    const unknown =
        \\{"version":1,"request_id":7,"command":"status","arguments":{},"extra":true}
    ;
    try std.testing.expectError(error.InvalidRequestJson, decodeRequest(std.testing.allocator, unknown));

    const response_bytes =
        \\{"version":1,"request_id":7,"ok":false,"exit_code":3,"result":null,"error":{"code":"not_found","message":"node not found"}}
    ;
    const response = try decodeResponse(std.testing.allocator, response_bytes);
    defer response.deinit();
    try std.testing.expectEqual(@as(u8, 3), response.value.exit_code);
}
