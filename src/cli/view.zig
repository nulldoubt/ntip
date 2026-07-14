const std = @import("std");
const common = @import("common.zig");
const model = @import("../domain/model.zig");

pub const json_schema_version: u32 = 1;

pub const RuntimeNode = struct {
    state: []const u8,
    online: bool,
    traffic_state: ?[]const u8 = null,
    endpoint: ?[]const u8 = null,
};

pub const RuntimeLookup = struct {
    context: *anyopaque,
    lookup_fn: *const fn (*anyopaque, model.Node, []u8) RuntimeNode,

    pub fn lookup(self: RuntimeLookup, node: model.Node, endpoint_buffer: []u8) RuntimeNode {
        return self.lookup_fn(self.context, node, endpoint_buffer);
    }
};

pub fn writeServerStatus(
    writer: *std.Io.Writer,
    store: *const model.Store,
    state: []const u8,
    format: common.OutputFormat,
) !void {
    switch (format) {
        .text => try writer.print("ntsrv {s}\ngeneration: {d}\nnodes: {d}\n", .{
            state,
            store.generation,
            store.nodes.items.len,
        }),
        .json => try writer.print("{{\"schema_version\":1,\"state\":\"{s}\",\"generation\":{d},\"nodes\":{d}}}\n", .{
            state,
            store.generation,
            store.nodes.items.len,
        }),
    }
}

pub fn writeClientStatus(writer: *std.Io.Writer, state: []const u8, format: common.OutputFormat) !void {
    switch (format) {
        .text => try writer.print("ntcl {s}\n", .{state}),
        .json => try writer.print("{{\"schema_version\":1,\"state\":\"{s}\"}}\n", .{state}),
    }
}

pub fn writeVnrList(writer: *std.Io.Writer, store: *const model.Store, format: common.OutputFormat) !void {
    switch (format) {
        .json => {
            var json: std.json.Stringify = .{ .writer = writer, .options = .{} };
            try json.beginObject();
            try json.objectField("schema_version");
            try json.write(json_schema_version);
            try json.objectField("generation");
            try json.write(store.generation);
            try json.objectField("vnrs");
            try json.beginArray();
            for (store.vnrs.items) |vnr| try writeVnrJson(&json, vnr);
            try json.endArray();
            try json.endObject();
            try writer.writeByte('\n');
        },
        .text => {
            try writer.writeAll("NAME\tRANGE\tMASTER\n");
            for (store.vnrs.items) |vnr| {
                var range_buffer: [18]u8 = undefined;
                var address_buffer: [15]u8 = undefined;
                try writer.print("{s}\t{s}\t{s}\n", .{
                    vnr.name.slice(),
                    try vnr.range.write(&range_buffer),
                    try vnr.masterAddress().write(&address_buffer),
                });
            }
        },
    }
}

pub fn writeVnrShow(writer: *std.Io.Writer, store: *const model.Store, name: []const u8, format: common.OutputFormat) !void {
    const vnr = store.findVnr(name) orelse return error.VnrNotFound;
    switch (format) {
        .json => {
            var json: std.json.Stringify = .{ .writer = writer, .options = .{} };
            try json.beginObject();
            try json.objectField("schema_version");
            try json.write(json_schema_version);
            try json.objectField("vnr");
            try writeVnrJson(&json, vnr.*);
            try json.endObject();
            try writer.writeByte('\n');
        },
        .text => {
            var range_buffer: [18]u8 = undefined;
            var address_buffer: [15]u8 = undefined;
            try writer.print("Name:           {s}\nRange:          {s}\nMaster address: {s}\n", .{
                vnr.name.slice(),
                try vnr.range.write(&range_buffer),
                try vnr.masterAddress().write(&address_buffer),
            });
        },
    }
}

pub fn writeNodeList(writer: *std.Io.Writer, store: *const model.Store, format: common.OutputFormat) !void {
    return writeNodeListRuntime(writer, store, format, null);
}

pub fn writeNodeListRuntime(
    writer: *std.Io.Writer,
    store: *const model.Store,
    format: common.OutputFormat,
    runtime: ?RuntimeLookup,
) !void {
    switch (format) {
        .json => {
            var json: std.json.Stringify = .{ .writer = writer, .options = .{} };
            try json.beginObject();
            try json.objectField("schema_version");
            try json.write(json_schema_version);
            try json.objectField("generation");
            try json.write(store.generation);
            try json.objectField("nodes");
            try json.beginArray();
            for (store.nodes.items) |node| {
                var endpoint_buffer: [64]u8 = undefined;
                try writeNodeJson(&json, node, if (runtime) |lookup| lookup.lookup(node, &endpoint_buffer) else null);
            }
            try json.endArray();
            try json.endObject();
            try writer.writeByte('\n');
        },
        .text => {
            try writer.writeAll("NAME\tVNR\tADDRESS\tSTATE\tTRAFFIC\tENDPOINT\n");
            for (store.nodes.items) |node| {
                var address_buffer: [15]u8 = undefined;
                var endpoint_buffer: [64]u8 = undefined;
                const current = if (runtime) |lookup| lookup.lookup(node, &endpoint_buffer) else RuntimeNode{
                    .state = @tagName(node.enrollment_state),
                    .online = false,
                };
                try writer.print("{s}\t{s}\t{s}\t{s}\t{s}\t{s}\n", .{
                    node.name.slice(),
                    node.vnr.slice(),
                    try node.address.write(&address_buffer),
                    current.state,
                    current.traffic_state orelse "-",
                    current.endpoint orelse "-",
                });
            }
        },
    }
}

pub fn writeNodeShow(writer: *std.Io.Writer, store: *const model.Store, name: []const u8, format: common.OutputFormat) !void {
    return writeNodeShowRuntime(writer, store, name, format, null);
}

pub fn writeNodeShowRuntime(
    writer: *std.Io.Writer,
    store: *const model.Store,
    name: []const u8,
    format: common.OutputFormat,
    runtime: ?RuntimeLookup,
) !void {
    const node = store.findNode(name) orelse return error.NodeNotFound;
    var endpoint_buffer: [64]u8 = undefined;
    const current = if (runtime) |lookup| lookup.lookup(node.*, &endpoint_buffer) else null;
    switch (format) {
        .json => {
            var json: std.json.Stringify = .{ .writer = writer, .options = .{} };
            try json.beginObject();
            try json.objectField("schema_version");
            try json.write(json_schema_version);
            try json.objectField("node");
            try writeNodeJson(&json, node.*, current);
            try json.endObject();
            try writer.writeByte('\n');
        },
        .text => {
            var id_buffer: [32]u8 = undefined;
            var address_buffer: [15]u8 = undefined;
            try writer.print("Name:       {s}\nID:         {s}\nVNR:        {s}\nAddress:    {s}\nEnrollment: {s}\nState:      {s}\nTraffic:    {s}\nEndpoint:   {s}\n", .{
                node.name.slice(),
                node.id.write(&id_buffer),
                node.vnr.slice(),
                try node.address.write(&address_buffer),
                @tagName(node.enrollment_state),
                if (current) |value| value.state else @tagName(node.enrollment_state),
                if (current) |value| value.traffic_state orelse "-" else "-",
                if (current) |value| value.endpoint orelse "-" else "-",
            });
        },
    }
}

pub fn writeRouteList(writer: *std.Io.Writer, store: *const model.Store, format: common.OutputFormat) !void {
    switch (format) {
        .json => {
            var json: std.json.Stringify = .{ .writer = writer, .options = .{} };
            try json.beginObject();
            try json.objectField("schema_version");
            try json.write(json_schema_version);
            try json.objectField("generation");
            try json.write(store.generation);
            try json.objectField("routes");
            try json.beginArray();
            for (store.routes.items) |route| try writeRouteJson(&json, route);
            try json.endArray();
            try json.endObject();
            try writer.writeByte('\n');
        },
        .text => {
            try writer.writeAll("PREFIX\tNODE\n");
            for (store.routes.items) |route| {
                var prefix_buffer: [18]u8 = undefined;
                try writer.print("{s}\t{s}\n", .{ try route.prefix.write(&prefix_buffer), route.node.slice() });
            }
        },
    }
}

pub fn writeRouteShow(writer: *std.Io.Writer, store: *const model.Store, prefix: model.Cidr, format: common.OutputFormat) !void {
    const route = store.findRoute(prefix) orelse return error.RouteNotFound;
    switch (format) {
        .json => {
            var json: std.json.Stringify = .{ .writer = writer, .options = .{} };
            try json.beginObject();
            try json.objectField("schema_version");
            try json.write(json_schema_version);
            try json.objectField("route");
            try writeRouteJson(&json, route.*);
            try json.endObject();
            try writer.writeByte('\n');
        },
        .text => {
            var prefix_buffer: [18]u8 = undefined;
            try writer.print("Prefix: {s}\nNode:   {s}\n", .{ try route.prefix.write(&prefix_buffer), route.node.slice() });
        },
    }
}

fn writeVnrJson(json: *std.json.Stringify, vnr: model.Vnr) !void {
    var range_buffer: [18]u8 = undefined;
    var address_buffer: [15]u8 = undefined;
    try json.beginObject();
    try json.objectField("name");
    try json.write(vnr.name.slice());
    try json.objectField("range");
    try json.write(try vnr.range.write(&range_buffer));
    try json.objectField("master_address");
    try json.write(try vnr.masterAddress().write(&address_buffer));
    try json.endObject();
}

fn writeNodeJson(json: *std.json.Stringify, node: model.Node, runtime: ?RuntimeNode) !void {
    var id_buffer: [32]u8 = undefined;
    var address_buffer: [15]u8 = undefined;
    try json.beginObject();
    try json.objectField("id");
    try json.write(node.id.write(&id_buffer));
    try json.objectField("name");
    try json.write(node.name.slice());
    try json.objectField("vnr");
    try json.write(node.vnr.slice());
    try json.objectField("address");
    try json.write(try node.address.write(&address_buffer));
    try json.objectField("enrollment_state");
    try json.write(@tagName(node.enrollment_state));
    try json.objectField("state");
    try json.write(if (runtime) |current| current.state else @tagName(node.enrollment_state));
    // Runtime reachability is deliberately ephemeral and therefore null in an
    // offline state view. Daemon-backed views replace these values live.
    try json.objectField("online");
    if (runtime) |current| try json.write(current.online) else try json.write(null);
    try json.objectField("traffic_state");
    if (runtime) |current| {
        if (current.traffic_state) |traffic_state| try json.write(traffic_state) else try json.write(null);
    } else try json.write(null);
    try json.objectField("endpoint");
    if (runtime) |current| {
        if (current.endpoint) |endpoint| try json.write(endpoint) else try json.write(null);
    } else try json.write(null);
    try json.endObject();
}

fn writeRouteJson(json: *std.json.Stringify, route: model.Route) !void {
    var prefix_buffer: [18]u8 = undefined;
    try json.beginObject();
    try json.objectField("prefix");
    try json.write(try route.prefix.write(&prefix_buffer));
    try json.objectField("node");
    try json.write(route.node.slice());
    try json.endObject();
}

test "JSON views have a stable schema envelope" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeVnrList(&output.writer, &store, .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"generation\":1,\"vnrs\":[{\"name\":\"vnr0\",\"range\":\"10.1.0.0/24\",\"master_address\":\"10.1.0.1\"}]}\n",
        output.written(),
    );
}

test "all v0.1 read commands have exact stable JSON" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
    try store.createNode(.{ .bytes = .{1} ** 16 }, "node01", "vnr0", try model.Ipv4.parse("10.1.0.2"));
    try store.addRoute(try model.Cidr.parse("192.168.50.0/24"), "node01");

    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();

    try writeServerStatus(&output.writer, &store, "stopped", .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"state\":\"stopped\",\"generation\":3,\"nodes\":1}\n",
        output.written(),
    );
    output.clearRetainingCapacity();
    try writeClientStatus(&output.writer, "stopped", .json);
    try std.testing.expectEqualStrings("{\"schema_version\":1,\"state\":\"stopped\"}\n", output.written());

    output.clearRetainingCapacity();
    try writeVnrShow(&output.writer, &store, "vnr0", .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"vnr\":{\"name\":\"vnr0\",\"range\":\"10.1.0.0/24\",\"master_address\":\"10.1.0.1\"}}\n",
        output.written(),
    );

    const node_json = "{\"id\":\"01010101010101010101010101010101\",\"name\":\"node01\",\"vnr\":\"vnr0\",\"address\":\"10.1.0.2\",\"enrollment_state\":\"unenrolled\",\"state\":\"unenrolled\",\"online\":null,\"traffic_state\":null,\"endpoint\":null}";
    output.clearRetainingCapacity();
    try writeNodeList(&output.writer, &store, .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"generation\":3,\"nodes\":[" ++ node_json ++ "]}\n",
        output.written(),
    );
    output.clearRetainingCapacity();
    try writeNodeShow(&output.writer, &store, "node01", .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"node\":" ++ node_json ++ "}\n",
        output.written(),
    );

    const route_json = "{\"prefix\":\"192.168.50.0/24\",\"node\":\"node01\"}";
    output.clearRetainingCapacity();
    try writeRouteList(&output.writer, &store, .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"generation\":3,\"routes\":[" ++ route_json ++ "]}\n",
        output.written(),
    );
    output.clearRetainingCapacity();
    try writeRouteShow(&output.writer, &store, try model.Cidr.parse("192.168.50.0/24"), .json);
    try std.testing.expectEqualStrings(
        "{\"schema_version\":1,\"route\":" ++ route_json ++ "}\n",
        output.written(),
    );
}
