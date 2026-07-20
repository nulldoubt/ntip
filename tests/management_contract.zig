const std = @import("std");
const ntip = @import("ntip");
const openapi_document = @import("openapi_document");

const management = ntip.management;
const http = management.http;

const http_method_names = [_][]const u8{
    "get",
    "head",
    "post",
    "put",
    "patch",
    "delete",
    "options",
};

test "canonical Zig routes exactly match the OpenAPI method and path surface" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        openapi_document.bytes,
        .{ .duplicate_field_behavior = .@"error" },
    );
    defer parsed.deinit();

    const paths = try requiredObject(parsed.value, "paths");
    const routes = management.api_server.canonicalRoutes();
    var operation_count: usize = 0;

    var path_iterator = paths.iterator();
    while (path_iterator.next()) |path_entry| {
        const operations = switch (path_entry.value_ptr.*) {
            .object => |value| value,
            else => return error.InvalidOpenApiDocument,
        };
        for (http_method_names) |method_name| {
            if (operations.get(method_name) == null) continue;
            operation_count += 1;

            const method = methodFromOpenApi(method_name) orelse unreachable;
            var pattern_storage: [512]u8 = undefined;
            const pattern = try std.fmt.bufPrint(&pattern_storage, "/api/v1{s}", .{path_entry.key_ptr.*});
            try std.testing.expect(routeExists(routes, method, pattern));
        }
    }

    try std.testing.expectEqual(routes.len, operation_count);
    for (routes) |route| {
        try std.testing.expect(std.mem.startsWith(u8, route.pattern, "/api/v1/"));
        const openapi_path = route.pattern["/api/v1".len..];
        const path_value = paths.get(openapi_path) orelse return error.ZigRouteMissingFromOpenApi;
        const operations = switch (path_value) {
            .object => |value| value,
            else => return error.InvalidOpenApiDocument,
        };
        try std.testing.expect(operations.get(openApiName(route.method)) != null);
    }
}

test "public Zig enums exactly match their OpenAPI schemas" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        openapi_document.bytes,
        .{ .duplicate_field_behavior = .@"error" },
    );
    defer parsed.deinit();

    const components = try requiredObject(parsed.value, "components");
    const schemas_value = components.get("schemas") orelse return error.InvalidOpenApiDocument;
    const schemas = switch (schemas_value) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };

    try expectEnumSchema(management.auth.Role, schemas, "Role");
    try expectEnumSchema(management.read_models_service.EnrollmentState, schemas, "EnrollmentState");
    try expectEnumSchema(management.read_models_service.LivenessState, schemas, "LivenessState");
    try expectEnumSchema(management.read_models_service.RuntimeSessionState, schemas, "RuntimeSessionState");
    try expectEnumSchema(management.read_models_service.TrafficState, schemas, "TrafficState");
    try expectEnumSchema(management.settings.RevisionStatus, schemas, "SettingsRevisionStatus");
    try expectEnumSchema(management.errors.Code, schemas, "ErrorCode");
}

test "canonical error header promises exactly match runtime metadata requirements" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        openapi_document.bytes,
        .{ .duplicate_field_behavior = .@"error" },
    );
    defer parsed.deinit();

    const components = try requiredObject(parsed.value, "components");
    const responses = switch (components.get("responses") orelse return error.InvalidOpenApiDocument) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    const headers = switch (components.get("headers") orelse return error.InvalidOpenApiDocument) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };

    const Case = struct {
        response: []const u8,
        code: management.errors.Code,
        status: http.Status,
        etag: bool,
        retry_after_seconds: bool,
    };
    const cases = [_]Case{
        .{
            .response = "PreconditionFailed",
            .code = .precondition_failed,
            .status = .precondition_failed,
            .etag = true,
            .retry_after_seconds = false,
        },
        .{
            .response = "TooManyRequests",
            .code = .rate_limited,
            .status = .too_many_requests,
            .etag = false,
            .retry_after_seconds = true,
        },
        .{
            .response = "ServiceUnavailable",
            .code = .service_unavailable,
            .status = .service_unavailable,
            .etag = false,
            .retry_after_seconds = true,
        },
    };

    for (cases) |case| {
        const response = switch (responses.get(case.response) orelse return error.InvalidOpenApiDocument) {
            .object => |value| value,
            else => return error.InvalidOpenApiDocument,
        };
        const response_headers = switch (response.get("headers") orelse return error.InvalidOpenApiDocument) {
            .object => |value| value,
            else => return error.InvalidOpenApiDocument,
        };
        try std.testing.expectEqual(case.etag, response_headers.get("ETag") != null);
        try std.testing.expectEqual(case.retry_after_seconds, response_headers.get("Retry-After") != null);

        const requirements = management.service_ipc.errorMetadataRequirements(case.code);
        try std.testing.expectEqual(case.etag, requirements.etag);
        try std.testing.expectEqual(case.retry_after_seconds, requirements.retry_after_seconds);
        try std.testing.expectEqual(case.status, http.statusForError(case.code));
    }

    for ([_][]const u8{ "ETag", "RetryAfter" }) |name| {
        const header = switch (headers.get(name) orelse return error.InvalidOpenApiDocument) {
            .object => |value| value,
            else => return error.InvalidOpenApiDocument,
        };
        const required = header.get("required") orelse return error.InvalidOpenApiDocument;
        try std.testing.expect(required == .bool and required.bool);
    }
}

test "operational settings fields have an explicit complete contract mapping" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        openapi_document.bytes,
        .{ .duplicate_field_behavior = .@"error" },
    );
    defer parsed.deinit();

    const components = try requiredObject(parsed.value, "components");
    const schemas_value = components.get("schemas") orelse return error.InvalidOpenApiDocument;
    const schemas = switch (schemas_value) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    const settings_schema = schemas.get("OperationalSettings") orelse return error.InvalidOpenApiDocument;
    const settings_object = switch (settings_schema) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    const properties_value = settings_object.get("properties") orelse return error.InvalidOpenApiDocument;
    const properties = switch (properties_value) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };

    const FieldMapping = struct { zig: []const u8, json: []const u8 };
    const mappings = [_]FieldMapping{
        .{ .zig = "inner_mtu", .json = "innerMtu" },
        .{ .zig = "heartbeat_idle_seconds", .json = "heartbeatIntervalSeconds" },
        .{ .zig = "suspect_after_seconds", .json = "suspectAfterSeconds" },
        .{ .zig = "offline_after_seconds", .json = "offlineAfterSeconds" },
        .{ .zig = "default_enrollment_lifetime_seconds", .json = "defaultEnrollmentLifetimeSeconds" },
        .{ .zig = "maximum_nodes", .json = "maximumNodes" },
        .{ .zig = "traffic_cold_after_seconds", .json = "trafficColdAfterSeconds" },
        .{ .zig = "traffic_hot_packets_per_second", .json = "trafficHotPacketsPerSecond" },
        .{ .zig = "traffic_hot_bits_per_second", .json = "trafficHotBitsPerSecond" },
        .{ .zig = "traffic_saturated_queue_percent", .json = "trafficSaturatedQueuePercent" },
        .{ .zig = "traffic_hysteresis_seconds", .json = "trafficHysteresisSeconds" },
        .{ .zig = "runtime_event_retention_days", .json = "runtimeEventRetentionDays" },
        .{ .zig = "connectivity_result_retention_days", .json = "connectivityRetentionDays" },
    };
    const zig_fields = std.meta.fields(management.settings.OperationalSettings);

    try std.testing.expectEqual(zig_fields.len, mappings.len);
    try std.testing.expectEqual(zig_fields.len, properties.count());
    inline for (zig_fields) |field| {
        var found = false;
        for (mappings) |mapping| {
            if (std.mem.eql(u8, field.name, mapping.zig)) {
                found = true;
                try std.testing.expect(properties.get(mapping.json) != null);
            }
        }
        try std.testing.expect(found);
    }

    try expectIntegerConstraint(
        properties,
        "defaultEnrollmentLifetimeSeconds",
        "minimum",
        management.settings.minimum_enrollment_lifetime_seconds,
    );
    try expectIntegerConstraint(
        properties,
        "defaultEnrollmentLifetimeSeconds",
        "maximum",
        management.settings.maximum_enrollment_lifetime_seconds,
    );
    try expectIntegerConstraint(
        properties,
        "trafficHysteresisSeconds",
        "maximum",
        management.settings.maximum_traffic_hysteresis_seconds,
    );

    const update_schema = schemas.get("SettingsUpdate") orelse return error.InvalidOpenApiDocument;
    const update_object = switch (update_schema) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    const update_properties_value = update_object.get("properties") orelse return error.InvalidOpenApiDocument;
    const update_properties = switch (update_properties_value) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    try expectIntegerConstraint(
        update_properties,
        "defaultEnrollmentLifetimeSeconds",
        "minimum",
        management.settings.minimum_enrollment_lifetime_seconds,
    );
    try expectIntegerConstraint(
        update_properties,
        "defaultEnrollmentLifetimeSeconds",
        "maximum",
        management.settings.maximum_enrollment_lifetime_seconds,
    );
    try expectIntegerConstraint(
        update_properties,
        "trafficHysteresisSeconds",
        "maximum",
        management.settings.maximum_traffic_hysteresis_seconds,
    );
}

fn requiredObject(value: std.json.Value, key: []const u8) !std.json.ObjectMap {
    const child = switch (value) {
        .object => |object| object.get(key) orelse return error.InvalidOpenApiDocument,
        else => return error.InvalidOpenApiDocument,
    };
    return switch (child) {
        .object => |object| object,
        else => error.InvalidOpenApiDocument,
    };
}

fn methodFromOpenApi(name: []const u8) ?http.Method {
    if (std.mem.eql(u8, name, "get")) return .GET;
    if (std.mem.eql(u8, name, "head")) return .HEAD;
    if (std.mem.eql(u8, name, "post")) return .POST;
    if (std.mem.eql(u8, name, "put")) return .PUT;
    if (std.mem.eql(u8, name, "patch")) return .PATCH;
    if (std.mem.eql(u8, name, "delete")) return .DELETE;
    if (std.mem.eql(u8, name, "options")) return .OPTIONS;
    return null;
}

fn openApiName(method: http.Method) []const u8 {
    return switch (method) {
        .GET => "get",
        .HEAD => "head",
        .POST => "post",
        .PUT => "put",
        .PATCH => "patch",
        .DELETE => "delete",
        .OPTIONS => "options",
    };
}

fn routeExists(routes: []const http.Route, method: http.Method, pattern: []const u8) bool {
    for (routes) |route| {
        if (route.method == method and std.mem.eql(u8, route.pattern, pattern)) return true;
    }
    return false;
}

fn expectEnumSchema(comptime Enum: type, schemas: std.json.ObjectMap, schema_name: []const u8) !void {
    const schema = schemas.get(schema_name) orelse return error.InvalidOpenApiDocument;
    const schema_object = switch (schema) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    const enum_value = schema_object.get("enum") orelse return error.InvalidOpenApiDocument;
    const values = switch (enum_value) {
        .array => |value| value.items,
        else => return error.InvalidOpenApiDocument,
    };
    const fields = std.meta.fields(Enum);

    try std.testing.expectEqual(fields.len, values.len);
    inline for (fields) |field| {
        var found = false;
        for (values) |value| {
            const text = switch (value) {
                .string => |string| string,
                else => return error.InvalidOpenApiDocument,
            };
            if (std.mem.eql(u8, field.name, text)) found = true;
        }
        try std.testing.expect(found);
    }
}

fn expectIntegerConstraint(
    properties: std.json.ObjectMap,
    property_name: []const u8,
    constraint_name: []const u8,
    expected: anytype,
) !void {
    const property = properties.get(property_name) orelse return error.InvalidOpenApiDocument;
    const property_object = switch (property) {
        .object => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    const constraint = property_object.get(constraint_name) orelse return error.InvalidOpenApiDocument;
    const actual = switch (constraint) {
        .integer => |value| value,
        else => return error.InvalidOpenApiDocument,
    };
    try std.testing.expectEqual(@as(i64, @intCast(expected)), actual);
}
