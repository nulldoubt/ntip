//! Linux-only `ntsrv` endpoint for the private `ntip-api` service protocol.
//!
//! This listener is intentionally independent from the human CLI socket.  A
//! pathname permission check is not treated as authentication: every accepted
//! connection is authenticated with `SO_PEERCRED` before a byte is read.  The
//! server handles one request per connection and is designed to be called by
//! the serialized operator worker (or from that worker's epoll loop).

const std = @import("std");
const builtin = @import("builtin");
const service_ipc = @import("service_ipc.zig");
const socket_deadline = @import("../platform/linux/socket_deadline.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const socket_mode: std.posix.mode_t = 0o660;
/// A connected peer gets one short, bounded I/O slice. The serialized owner
/// closes an incomplete request instead of waiting across multiple slices, so
/// a slow or abandoned local connection cannot hold protocol persistence for
/// seconds. The outer owner loop drains runtime work before admitting the next
/// connection.
pub const socket_io_timeout_milliseconds: i64 = socket_deadline.phase_timeout_milliseconds;
pub const maximum_response_frames: u32 = 1024;

test "service peer I/O slice preserves protocol progress bound" {
    try std.testing.expect(socket_io_timeout_milliseconds > 0);
    try std.testing.expect(socket_io_timeout_milliseconds <= 250);
}

/// Layout of Linux's `struct ucred`, returned by `SO_PEERCRED`.
pub const PeerCredentials = extern struct {
    pid: i32,
    uid: u32,
    gid: u32,
};

/// Numeric ownership and peer-authentication policy supplied by the service
/// launcher after resolving the `ntip` and `ntip-api` accounts.
pub const SocketPolicy = struct {
    owner_uid: std.Io.File.Uid,
    group_gid: std.Io.File.Gid,
    expected_api_uid: std.Io.File.Uid,

    pub fn authorize(self: SocketPolicy, credentials: PeerCredentials) !void {
        if (credentials.uid != self.expected_api_uid) return error.UnauthorizedServicePeer;
    }

    pub fn acceptsMetadata(
        self: SocketPolicy,
        uid: std.Io.File.Uid,
        gid: std.Io.File.Gid,
        mode: std.posix.mode_t,
        is_socket: bool,
    ) bool {
        return is_socket and uid == self.owner_uid and gid == self.group_gid and
            mode & 0o777 == socket_mode;
    }
};

/// Type-erased streaming application handler. Values referenced by `request`
/// remain valid for the duration of this call. The handler must finish the
/// supplied sink with either a final success frame or an error frame.
pub const Handler = struct {
    context: *anyopaque,
    handle_fn: *const fn (
        context: *anyopaque,
        credentials: PeerCredentials,
        request: service_ipc.Request,
        request_allocator: Allocator,
        response: *ResponseSink,
    ) anyerror!void,

    pub fn handle(
        self: Handler,
        credentials: PeerCredentials,
        request: service_ipc.Request,
        request_allocator: Allocator,
        response: *ResponseSink,
    ) !void {
        return self.handle_fn(self.context, credentials, request, request_allocator, response);
    }
};

/// Adapts a type-safe handler method to the stable type-erased contract.
pub fn adaptHandler(
    comptime Context: type,
    context: *Context,
    comptime function: *const fn (
        context: *Context,
        credentials: PeerCredentials,
        request: service_ipc.Request,
        request_allocator: Allocator,
        response: *ResponseSink,
    ) anyerror!void,
) Handler {
    const Adapter = struct {
        fn invoke(
            raw: *anyopaque,
            credentials: PeerCredentials,
            request: service_ipc.Request,
            request_allocator: Allocator,
            response: *ResponseSink,
        ) anyerror!void {
            const typed: *Context = @ptrCast(@alignCast(raw));
            return function(typed, credentials, request, request_allocator, response);
        }
    };
    return .{ .context = context, .handle_fn = Adapter.invoke };
}

/// Ordered response stream. JSON is encoded before attempting a write and the
/// underlying framing helper uses `writeAll`; after any write failure the sink
/// is poisoned so the server never appends another frame to a partial frame.
pub const ResponseSink = struct {
    allocator: Allocator,
    writer: ?*std.Io.Writer = null,
    socket_output: ?SocketOutput = null,
    request_id: []const u8,
    next_sequence: u32 = 0,
    frame_count: u32 = 0,
    frame_limit: u32 = maximum_response_frames,
    terminal: bool = false,
    poisoned: bool = false,

    pub fn init(
        allocator: Allocator,
        writer: *std.Io.Writer,
        request_id: []const u8,
    ) !ResponseSink {
        return initLimited(allocator, writer, request_id, maximum_response_frames);
    }

    fn initLimited(
        allocator: Allocator,
        writer: *std.Io.Writer,
        request_id: []const u8,
        frame_limit: u32,
    ) !ResponseSink {
        if (!service_ipc.isIdentifier(request_id)) return error.InvalidRequestId;
        if (frame_limit == 0 or frame_limit > maximum_response_frames) return error.InvalidFrameLimit;
        return .{
            .allocator = allocator,
            .writer = writer,
            .request_id = request_id,
            .frame_limit = frame_limit,
        };
    }

    fn initSocket(
        allocator: Allocator,
        io: Io,
        socket: std.Io.net.Socket,
        request_id: []const u8,
    ) !ResponseSink {
        if (!service_ipc.isIdentifier(request_id)) return error.InvalidRequestId;
        return .{
            .allocator = allocator,
            .socket_output = .{ .io = io, .socket = socket },
            .request_id = request_id,
        };
    }

    /// Sends a success frame. A non-terminal frame always leaves one slot for
    /// a terminal frame, including the server's fail-closed fallback.
    pub fn send(
        self: *ResponseSink,
        payload: ?std.json.Value,
        final: bool,
    ) !void {
        try self.write(.{
            .version = service_ipc.protocol_version,
            .request_id = self.request_id,
            .sequence = self.next_sequence,
            .final = final,
            .payload = payload,
        });
    }

    pub fn finish(self: *ResponseSink, payload: ?std.json.Value) !void {
        return self.send(payload, true);
    }

    /// Sends a public, stable failure. The service server itself only calls
    /// this with fixed messages and never serializes `@errorName`.
    pub fn fail(
        self: *ResponseSink,
        code: service_ipc.ErrorCode,
        message: []const u8,
        retryable: bool,
    ) !void {
        const requirements = service_ipc.errorMetadataRequirements(code);
        if (requirements.etag) return error.ErrorMetadataRequired;
        return self.failWithMetadata(code, message, retryable, .{
            .retry_after_seconds = if (requirements.retry_after_seconds) 1 else null,
        });
    }

    /// Sends a stable failure with validated public-header metadata. Callers
    /// must supply the current strong ETag for stale-precondition failures;
    /// retryable status families use `fail` when a one-second default is
    /// sufficient.
    pub fn failWithMetadata(
        self: *ResponseSink,
        code: service_ipc.ErrorCode,
        message: []const u8,
        retryable: bool,
        metadata: service_ipc.ErrorMetadata,
    ) !void {
        try self.write(.{
            .version = service_ipc.protocol_version,
            .request_id = self.request_id,
            .sequence = self.next_sequence,
            .final = true,
            .@"error" = .{
                .code = code,
                .message = message,
                .retryable = retryable,
                .metadata = metadata,
            },
        });
    }

    fn internalFailure(self: *ResponseSink) !void {
        return self.fail(.internal_error, "internal service error", false);
    }

    fn write(self: *ResponseSink, frame: service_ipc.ResponseFrame) !void {
        if (self.poisoned) return error.ResponseStreamPoisoned;
        if (self.terminal) return error.ResponseAlreadyTerminal;
        if (!std.mem.eql(u8, frame.request_id, self.request_id) or
            frame.sequence != self.next_sequence)
        {
            return error.InvalidResponseSequence;
        }
        if (self.frame_count >= self.frame_limit) return error.ResponseFrameLimitExceeded;
        if (!frame.final and self.frame_count + 1 >= self.frame_limit) {
            return error.ResponseFrameLimitExceeded;
        }

        const encoded = try service_ipc.encodeResponseFrame(self.allocator, frame);
        defer {
            std.crypto.secureZero(u8, encoded);
            self.allocator.free(encoded);
        }
        self.writeEncodedFrame(encoded) catch |err| {
            self.poisoned = true;
            return err;
        };

        self.frame_count += 1;
        self.next_sequence += 1;
        self.terminal = frame.final;
    }

    fn writeEncodedFrame(self: *ResponseSink, encoded: []const u8) !void {
        if (self.socket_output) |output| {
            var prefix: [service_ipc.frame_prefix_bytes]u8 = undefined;
            try service_ipc.encodeLength(&prefix, encoded.len);
            const deadline = socket_deadline.Deadline.start(output.io);
            try socket_deadline.writeAll(output.io, output.socket, &prefix, deadline);
            try socket_deadline.writeAll(output.io, output.socket, encoded, deadline);
            return;
        }
        return service_ipc.writeFrame(self.writer orelse return error.MissingResponseWriter, encoded);
    }
};

const SocketOutput = struct {
    io: Io,
    socket: std.Io.net.Socket,
};

const SocketIdentity = struct {
    inode: u64,
    device_major: u32,
    device_minor: u32,

    fn eql(a: SocketIdentity, b: SocketIdentity) bool {
        return a.inode == b.inode and a.device_major == b.device_major and
            a.device_minor == b.device_minor;
    }
};

const SocketMetadata = struct {
    identity: SocketIdentity,
    uid: std.Io.File.Uid,
    gid: std.Io.File.Gid,
    mode: std.posix.mode_t,
    is_socket: bool,
};

/// One-request-per-connection listener owned by the serialized operator
/// worker. `serveOne` is intentionally exposed so the listener handle can be
/// registered in the worker's epoll set.
pub const Server = struct {
    allocator: Allocator,
    io: Io,
    listener: std.Io.net.Server,
    path: []u8,
    owned_identity: SocketIdentity,
    policy: SocketPolicy,
    handler: Handler,
    request_storage: []u8,

    pub fn init(
        allocator: Allocator,
        io: Io,
        path: []const u8,
        owner_uid: std.Io.File.Uid,
        group_gid: std.Io.File.Gid,
        expected_api_uid: std.Io.File.Uid,
        handler: Handler,
    ) !Server {
        return initWithPolicy(allocator, io, path, .{
            .owner_uid = owner_uid,
            .group_gid = group_gid,
            .expected_api_uid = expected_api_uid,
        }, handler);
    }

    pub fn initWithPolicy(
        allocator: Allocator,
        io: Io,
        path: []const u8,
        policy: SocketPolicy,
        handler: Handler,
    ) !Server {
        if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
        try validateSocketPath(path);

        const owned_path = try allocator.dupe(u8, path);
        errdefer allocator.free(owned_path);
        const address = try std.Io.net.UnixAddress.init(owned_path);
        var listener = try address.listen(io, .{});

        var created_identity: ?SocketIdentity = null;
        errdefer {
            listener.deinit(io);
            if (created_identity) |identity| removeIfIdentityMatches(io, owned_path, identity);
        }

        const initial_metadata = try socketMetadata(owned_path);
        if (!initial_metadata.is_socket) return error.InvalidSocketPath;
        created_identity = initial_metadata.identity;
        try secureSocketPath(owned_path, policy);
        const secured_metadata = try socketMetadata(owned_path);
        if (!created_identity.?.eql(secured_metadata.identity) or
            !policy.acceptsMetadata(
                secured_metadata.uid,
                secured_metadata.gid,
                secured_metadata.mode,
                secured_metadata.is_socket,
            ))
        {
            return error.SocketMetadataMismatch;
        }

        const request_storage = try allocator.alloc(u8, service_ipc.maximum_frame_bytes);
        errdefer allocator.free(request_storage);
        return .{
            .allocator = allocator,
            .io = io,
            .listener = listener,
            .path = owned_path,
            .owned_identity = secured_metadata.identity,
            .policy = policy,
            .handler = handler,
            .request_storage = request_storage,
        };
    }

    /// File descriptor suitable for registration with epoll.
    pub fn listenerHandle(self: *const Server) std.Io.net.Socket.Handle {
        return self.listener.socket.handle;
    }

    pub fn handle(self: *const Server) std.Io.net.Socket.Handle {
        return self.listenerHandle();
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        removeIfIdentityMatches(self.io, self.path, self.owned_identity);
        std.crypto.secureZero(u8, self.request_storage);
        self.allocator.free(self.request_storage);
        self.allocator.free(self.path);
        self.* = undefined;
    }

    /// Accepts exactly one connection. Peer credentials are obtained and
    /// authorized before reader construction, frame reads, or JSON decoding.
    pub fn serveOne(self: *Server) !void {
        const stream = try self.listener.accept(self.io);
        defer stream.close(self.io);

        const credentials = try peerCredentials(stream.socket.handle);
        try self.policy.authorize(credentials);
        try installSocketDeadlines(stream.socket.handle);

        // Parsed request objects can contain passwords, session cookies, CSRF
        // values, or one-time credentials. Back the request arena with an
        // allocator that wipes every complete arena block on release.
        var wiping_allocator: WipingAllocator = .{ .child = self.allocator };
        var arena = std.heap.ArenaAllocator.init(wiping_allocator.allocator());
        defer arena.deinit();
        const request_allocator = arena.allocator();

        // The fixed buffer can contain login credentials or session tokens.
        // Clear prior contents before reuse and clear partial/full reads on
        // every exit path.
        std.crypto.secureZero(u8, self.request_storage);
        defer std.crypto.secureZero(u8, self.request_storage);
        const parsed = try readAuthorizedSocketRequest(
            self.policy,
            credentials,
            request_allocator,
            self.io,
            stream,
            self.request_storage,
        );
        defer parsed.deinit();

        var sink = try ResponseSink.initSocket(
            self.allocator,
            self.io,
            stream.socket,
            parsed.value.request_id,
        );

        const now_ms = Io.Clock.real.now(self.io).toMilliseconds();
        if (deadlineExpired(parsed.value.deadline_unix_ms, now_ms)) {
            try sink.fail(.invalid_request, "request deadline has expired", false);
            return;
        }

        self.handler.handle(credentials, parsed.value, request_allocator, &sink) catch {
            if (!sink.terminal and !sink.poisoned) try sink.internalFailure();
            if (sink.poisoned) return error.ResponseStreamPoisoned;
            return;
        };
        if (!sink.terminal and !sink.poisoned) try sink.internalFailure();
        if (sink.poisoned) return error.ResponseStreamPoisoned;
    }
};

const WipingAllocator = struct {
    child: Allocator,

    fn allocator(self: *WipingAllocator) Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocate,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn allocate(
        raw: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) ?[*]u8 {
        const self: *WipingAllocator = @ptrCast(@alignCast(raw));
        return self.child.rawAlloc(len, alignment, return_address);
    }

    fn resize(
        raw: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        return_address: usize,
    ) bool {
        const self: *WipingAllocator = @ptrCast(@alignCast(raw));
        if (new_len < memory.len) std.crypto.secureZero(u8, memory[new_len..]);
        return self.child.rawResize(memory, alignment, new_len, return_address);
    }

    fn remap(
        _: *anyopaque,
        _: []u8,
        _: std.mem.Alignment,
        _: usize,
        _: usize,
    ) ?[*]u8 {
        // Let Allocator's fallback allocate/copy/free path wipe the old block.
        return null;
    }

    fn free(
        raw: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        return_address: usize,
    ) void {
        const self: *WipingAllocator = @ptrCast(@alignCast(raw));
        std.crypto.secureZero(u8, memory);
        self.child.rawFree(memory, alignment, return_address);
    }
};

fn validateSocketPath(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path) or path.len <= 1) return error.SocketPathMustBeAbsolute;
    if (path.len > std.Io.net.UnixAddress.max_len) return error.NameTooLong;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidSocketPath;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidSocketPath;
        }
    }
}

fn readAuthorizedRequest(
    policy: SocketPolicy,
    credentials: PeerCredentials,
    allocator: Allocator,
    reader: *std.Io.Reader,
    storage: []u8,
) !std.json.Parsed(service_ipc.Request) {
    // This check deliberately remains in the same helper as the first read,
    // making the authorization-before-decode ordering independently testable.
    try policy.authorize(credentials);
    const body = try service_ipc.readFrame(reader, storage);
    return service_ipc.decodeRequest(allocator, body);
}

fn readAuthorizedSocketRequest(
    policy: SocketPolicy,
    credentials: PeerCredentials,
    allocator: Allocator,
    io: Io,
    stream: std.Io.net.Stream,
    storage: []u8,
) !std.json.Parsed(service_ipc.Request) {
    try policy.authorize(credentials);
    const deadline = socket_deadline.Deadline.start(io);
    var prefix: [service_ipc.frame_prefix_bytes]u8 = undefined;
    try socket_deadline.readExact(io, stream, &prefix, deadline);
    const length = try service_ipc.decodeLength(&prefix);
    if (length > storage.len) return error.DestinationTooSmall;
    try socket_deadline.readExact(io, stream, storage[0..length], deadline);
    return service_ipc.decodeRequest(allocator, storage[0..length]);
}

pub fn deadlineExpired(deadline_unix_ms: i64, now_unix_ms: i64) bool {
    return deadline_unix_ms <= 0 or now_unix_ms >= deadline_unix_ms;
}

fn peerCredentials(handle: std.Io.net.Socket.Handle) !PeerCredentials {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    var credentials: PeerCredentials = undefined;
    var length: linux.socklen_t = @sizeOf(PeerCredentials);
    switch (linux.errno(linux.getsockopt(
        handle,
        linux.SOL.SOCKET,
        linux.SO.PEERCRED,
        @ptrCast(&credentials),
        &length,
    ))) {
        .SUCCESS => {},
        else => return error.PeerCredentialLookupFailed,
    }
    if (length != @sizeOf(PeerCredentials)) return error.PeerCredentialLookupFailed;
    return credentials;
}

fn installSocketDeadlines(handle: std.Io.net.Socket.Handle) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    const timeout: linux.timeval = .{
        .sec = 0,
        .usec = socket_io_timeout_milliseconds * std.time.us_per_ms,
    };
    try std.posix.setsockopt(handle, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&timeout));
    try std.posix.setsockopt(handle, linux.SOL.SOCKET, linux.SO.SNDTIMEO, std.mem.asBytes(&timeout));
}

fn secureSocketPath(path: []const u8, policy: SocketPolicy) !void {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    var path_z = try nulTerminatedPath(path);
    switch (linux.errno(linux.chmod(&path_z, socket_mode))) {
        .SUCCESS => {},
        else => return error.SocketPermissionSetupFailed,
    }
    switch (linux.errno(linux.fchownat(
        linux.AT.FDCWD,
        &path_z,
        policy.owner_uid,
        policy.group_gid,
        linux.AT.SYMLINK_NOFOLLOW,
    ))) {
        .SUCCESS => {},
        else => return error.SocketOwnershipSetupFailed,
    }
}

fn socketMetadata(path: []const u8) !SocketMetadata {
    if (comptime builtin.os.tag != .linux) return error.UnsupportedPlatform;
    const linux = std.os.linux;
    var path_z = try nulTerminatedPath(path);
    const request: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .UID = true,
        .GID = true,
        .INO = true,
    };
    var metadata = std.mem.zeroes(linux.Statx);
    switch (linux.errno(linux.statx(
        linux.AT.FDCWD,
        &path_z,
        linux.AT.SYMLINK_NOFOLLOW,
        request,
        &metadata,
    ))) {
        .SUCCESS => {},
        else => return error.SocketMetadataLookupFailed,
    }
    if (!metadata.mask.TYPE or !metadata.mask.MODE or !metadata.mask.UID or
        !metadata.mask.GID or !metadata.mask.INO)
    {
        return error.SocketMetadataLookupFailed;
    }
    return .{
        .identity = .{
            .inode = metadata.ino,
            .device_major = metadata.dev_major,
            .device_minor = metadata.dev_minor,
        },
        .uid = metadata.uid,
        .gid = metadata.gid,
        .mode = metadata.mode,
        .is_socket = linux.S.ISSOCK(metadata.mode),
    };
}

fn removeIfIdentityMatches(io: Io, path: []const u8, expected: SocketIdentity) void {
    const current = socketMetadata(path) catch return;
    if (!current.is_socket or !current.identity.eql(expected)) return;
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

fn nulTerminatedPath(path: []const u8) ![std.Io.net.UnixAddress.max_len + 1:0]u8 {
    if (path.len > std.Io.net.UnixAddress.max_len or
        std.mem.indexOfScalar(u8, path, 0) != null)
    {
        return error.InvalidSocketPath;
    }
    var result: [std.Io.net.UnixAddress.max_len + 1:0]u8 =
        [_:0]u8{0} ** (std.Io.net.UnixAddress.max_len + 1);
    @memcpy(result[0..path.len], path);
    return result;
}

test "socket ownership and exact peer UID policies are independent" {
    const policy: SocketPolicy = .{
        .owner_uid = 901,
        .group_gid = 902,
        .expected_api_uid = 903,
    };
    try policy.authorize(.{ .pid = 7, .uid = 903, .gid = 999 });
    try std.testing.expectError(
        error.UnauthorizedServicePeer,
        policy.authorize(.{ .pid = 7, .uid = 904, .gid = 902 }),
    );
    try std.testing.expect(policy.acceptsMetadata(901, 902, 0o660, true));
    try std.testing.expect(!policy.acceptsMetadata(901, 902, 0o666, true));
    try std.testing.expect(!policy.acceptsMetadata(901, 902, 0o660, false));
    try std.testing.expect(!policy.acceptsMetadata(903, 902, 0o660, true));
}

test "peer authorization happens before frame read or JSON decode" {
    const policy: SocketPolicy = .{
        .owner_uid = 1,
        .group_gid = 2,
        .expected_api_uid = 3,
    };
    var empty_reader = std.Io.Reader.fixed("");
    var storage: [service_ipc.maximum_frame_bytes]u8 = undefined;
    try std.testing.expectError(
        error.UnauthorizedServicePeer,
        readAuthorizedRequest(
            policy,
            .{ .pid = 9, .uid = 4, .gid = 2 },
            std.testing.allocator,
            &empty_reader,
            &storage,
        ),
    );
}

test "wall-clock deadline rejects the boundary instant" {
    try std.testing.expect(deadlineExpired(0, 0));
    try std.testing.expect(deadlineExpired(1000, 1000));
    try std.testing.expect(deadlineExpired(1000, 1001));
    try std.testing.expect(!deadlineExpired(1001, 1000));
}

test "response sink enforces sequence finality and a reserved terminal slot" {
    const request_id = "0123456789abcdef0123456789abcdef";
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var sink = try ResponseSink.initLimited(std.testing.allocator, &output.writer, request_id, 3);

    try sink.send(null, false);
    try sink.send(null, false);
    try std.testing.expectError(error.ResponseFrameLimitExceeded, sink.send(null, false));
    try sink.finish(null);
    try std.testing.expect(sink.terminal);
    try std.testing.expectEqual(@as(u32, 3), sink.frame_count);
    try std.testing.expectError(error.ResponseAlreadyTerminal, sink.finish(null));

    var framed = std.Io.Reader.fixed(output.written());
    var body_storage: [service_ipc.maximum_frame_bytes]u8 = undefined;
    for (0..3) |expected_sequence| {
        const body = try service_ipc.readFrame(&framed, &body_storage);
        const parsed = try service_ipc.decodeResponseFrame(std.testing.allocator, body);
        defer parsed.deinit();
        try std.testing.expectEqual(@as(u32, @intCast(expected_sequence)), parsed.value.sequence);
        try std.testing.expectEqual(expected_sequence == 2, parsed.value.final);
        try std.testing.expectEqualStrings(request_id, parsed.value.request_id);
    }
}

test "typed handler adapter receives peer and can terminate the response" {
    const Context = struct {
        seen_uid: u32 = 0,
        seen_operation: bool = false,

        fn handle(
            self: *@This(),
            credentials: PeerCredentials,
            request: service_ipc.Request,
            _: Allocator,
            response: *ResponseSink,
        ) !void {
            self.seen_uid = credentials.uid;
            self.seen_operation = std.mem.eql(u8, request.operation, "health.ready");
            try response.finish(null);
        }
    };

    var context: Context = .{};
    const handler = adaptHandler(Context, &context, Context.handle);
    var object: std.json.ObjectMap = .{};
    defer object.deinit(std.testing.allocator);
    const request: service_ipc.Request = .{
        .version = service_ipc.protocol_version,
        .request_id = "0123456789abcdef0123456789abcdef",
        .deadline_unix_ms = 100,
        .operation = "health.ready",
        .actor = .{ .kind = .service },
        .payload = .{ .object = object },
    };
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var sink = try ResponseSink.init(std.testing.allocator, &output.writer, request.request_id);
    try handler.handle(.{ .pid = 10, .uid = 44, .gid = 45 }, request, std.testing.allocator, &sink);
    try std.testing.expectEqual(@as(u32, 44), context.seen_uid);
    try std.testing.expect(context.seen_operation);
    try std.testing.expect(sink.terminal);
}

test "handler failures use a fixed terminal message rather than an error name" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var sink = try ResponseSink.init(
        std.testing.allocator,
        &output.writer,
        "0123456789abcdef0123456789abcdef",
    );
    try sink.internalFailure();
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "internal service error") != null);
    try std.testing.expect(std.mem.indexOf(u8, output.written(), "InternalFailure") == null);
}

test "service socket path is absolute and Linux ucred layout is stable" {
    try std.testing.expectError(error.SocketPathMustBeAbsolute, validateSocketPath("relative.sock"));
    try std.testing.expectError(error.InvalidSocketPath, validateSocketPath("/run//ntsrv-api.sock"));
    try std.testing.expectError(error.InvalidSocketPath, validateSocketPath("/run/../ntsrv-api.sock"));
    try std.testing.expectError(error.InvalidSocketPath, validateSocketPath("/run/./ntsrv-api.sock"));
    try validateSocketPath("/run/ntip-api/ntsrv-api.sock");
    try std.testing.expectEqual(@as(usize, 12), @sizeOf(PeerCredentials));
}

test "request arena backing memory is wiped on release" {
    var backing = [_]u8{0} ** 2048;
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    var wiping: WipingAllocator = .{ .child = fixed.allocator() };
    var arena = std.heap.ArenaAllocator.init(wiping.allocator());
    const secret = try arena.allocator().alloc(u8, 128);
    @memset(secret, 0xa5);
    arena.deinit();
    for (backing) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}
