const std = @import("std");
const framing = @import("ipc.zig");
const socket = @import("../platform/linux/ipc_socket.zig");
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

        var reader_buffer: [4096]u8 = undefined;
        var stream_reader = std.Io.net.Stream.Reader.init(connection.stream, self.io, &reader_buffer);
        const body = try framing.readFrame(&stream_reader.interface, self.request_storage);
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

        var writer_buffer: [4096]u8 = undefined;
        var stream_writer = std.Io.net.Stream.Writer.init(connection.stream, self.io, &writer_buffer);
        try framing.writeFrame(&stream_writer.interface, encoded);
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
