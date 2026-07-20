const std = @import("std");
const framing = @import("ipc.zig");
const socket = @import("../platform/linux/ipc_socket.zig");
const socket_deadline = @import("../platform/linux/socket_deadline.zig");
const lifecycle = @import("../platform/linux/lifecycle.zig");

pub const Handler = struct {
    context: *anyopaque,
    handle_fn: *const fn (
        *anyopaque,
        socket.PeerCredentials,
        framing.Request,
        std.mem.Allocator,
    ) anyerror!framing.Response,

    pub fn handle(
        self: Handler,
        credentials: socket.PeerCredentials,
        request: framing.Request,
        allocator: std.mem.Allocator,
    ) !framing.Response {
        return self.handle_fn(self.context, credentials, request, allocator);
    }
};

/// One-request/one-response local control server. Its 1 MiB request buffer is
/// allocated once before serving; per-request JSON allocations occur only on
/// the control worker, never on the packet path.
pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: socket.Listener,
    handler: Handler,
    request_storage: []u8,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        path: []const u8,
        admin_gid: std.Io.File.Gid,
        handler: Handler,
    ) !Server {
        var listener = try socket.Listener.listen(io, path, admin_gid);
        errdefer listener.close();
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .handler = handler,
            .request_storage = try allocator.alloc(u8, framing.maximum_message_bytes),
        };
    }

    pub fn deinit(self: *Server) void {
        self.allocator.free(self.request_storage);
        self.listener.close();
        self.* = undefined;
    }

    pub fn run(self: *Server) !void {
        while (!lifecycle.shouldStop()) try self.serveOne();
    }

    pub fn serveOne(self: *Server) !void {
        var connection = try self.listener.accept();
        defer connection.close(self.io);
        std.log.info("local IPC peer pid={d} uid={d} gid={d}", .{
            connection.credentials.pid,
            connection.credentials.uid,
            connection.credentials.gid,
        });

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const request_allocator = arena.allocator();

        const read_deadline = socket_deadline.Deadline.start(self.io);
        var prefix: [framing.prefix_bytes]u8 = undefined;
        try socket_deadline.readExact(self.io, connection.stream, &prefix, read_deadline);
        const request_length = try framing.decodeLength(&prefix);
        if (request_length > self.request_storage.len) return error.DestinationTooSmall;
        try socket_deadline.readExact(
            self.io,
            connection.stream,
            self.request_storage[0..request_length],
            read_deadline,
        );
        const body = self.request_storage[0..request_length];
        const parsed = try framing.decodeRequest(request_allocator, body);
        defer parsed.deinit();

        const response = self.handler.handle(connection.credentials, parsed.value, request_allocator) catch |err| framing.Response{
            .version = framing.protocol_version,
            .request_id = parsed.value.request_id,
            .ok = false,
            .exit_code = 1,
            .result = null,
            .@"error" = .{ .code = "internal_failure", .message = @errorName(err) },
        };
        const encoded = try framing.encodeResponse(request_allocator, response);

        var response_prefix: [framing.prefix_bytes]u8 = undefined;
        try framing.encodeLength(&response_prefix, encoded.len);
        const write_deadline = socket_deadline.Deadline.start(self.io);
        try socket_deadline.writeAll(
            self.io,
            connection.stream.socket,
            &response_prefix,
            write_deadline,
        );
        try socket_deadline.writeAll(
            self.io,
            connection.stream.socket,
            encoded,
            write_deadline,
        );
    }
};

test "IPC server handler contract preserves peer credentials" {
    const Context = struct {
        seen_uid: u32 = 0,

        fn handle(
            raw: *anyopaque,
            credentials: socket.PeerCredentials,
            request: framing.Request,
            _: std.mem.Allocator,
        ) !framing.Response {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.seen_uid = credentials.uid;
            return .{
                .version = framing.protocol_version,
                .request_id = request.request_id,
                .ok = true,
                .exit_code = 0,
                .result = null,
                .@"error" = null,
            };
        }
    };
    var context: Context = .{};
    const handler: Handler = .{ .context = &context, .handle_fn = Context.handle };
    var arguments: std.json.ObjectMap = .{};
    defer arguments.deinit(std.testing.allocator);
    const request: framing.Request = .{
        .version = 1,
        .request_id = 4,
        .command = "status",
        .arguments = .{ .object = arguments },
    };
    const response = try handler.handle(.{ .pid = 1, .uid = 42, .gid = 7 }, request, std.testing.allocator);
    try std.testing.expect(response.ok);
    try std.testing.expectEqual(@as(u32, 42), context.seen_uid);
}
