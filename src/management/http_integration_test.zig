//! Cross-layer management-plane tests.
//!
//! The production `ntip-api` Unix backend is connected to a one-request test
//! responder. The responder performs the same strict frame/request decoding,
//! invokes the authoritative SQLite-backed application, and emits responses
//! through `ResponseSink`. Only Linux `SO_PEERCRED` admission is omitted so
//! this seam remains runnable on every native development platform.

const std = @import("std");
const api_application = @import("api_application.zig");
const api_error = @import("error.zig");
const api_server = @import("api_server.zig");
const auth = @import("auth.zig");
const auth_application = @import("auth_application.zig");
const http = @import("http.zig");
const inventory_service = @import("inventory_service.zig");
const operations_service = @import("operations_service.zig");
const security_policy = @import("security_policy.zig");
const service_ipc = @import("service_ipc.zig");
const service_server = @import("service_server.zig");
const access_repository = @import("../state/access_repository.zig");
const idempotency_repository = @import("../state/idempotency_repository.zig");
const management_repository = @import("../state/management_repository.zig");
const operations_repository = @import("../state/operations_repository.zig");
const settings_repository = @import("../state/settings_repository.zig");
const sqlite = @import("../state/sqlite.zig");
const model = @import("../domain/model.zig");

const allocator = std.testing.allocator;
const request_id = "0123456789abcdef0123456789abcdef";
const origin = "https://ntip.example.test";
const root_password = "correct horse battery staple";
const replacement_password = "a completely new safe passphrase";
const test_phc = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$dmVyaWZpZXI";
const test_dummy_phc = "$argon2id$v=19$m=32768,t=2,p=1$ZHVtbXk$dmVyaWZpZXI";

const FakePasswords = struct {
    accepted: []const u8 = root_password,

    fn engine(self: *FakePasswords) auth_application.PasswordEngine {
        return .{
            .context = self,
            .hash_fn = hash,
            .verify_fn = verify,
            .needs_rehash_fn = needsRehash,
        };
    }

    fn hash(
        _: ?*anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        _: []const u8,
    ) !auth.PasswordHash {
        return auth.PasswordHash.parse(test_phc);
    }

    fn verify(
        raw: ?*anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        _: *const auth.PasswordHash,
        password: []const u8,
    ) !bool {
        const self: *FakePasswords = @ptrCast(@alignCast(raw.?));
        return std.mem.eql(u8, self.accepted, password);
    }

    fn needsRehash(_: ?*anyopaque, _: *const auth.PasswordHash) bool {
        return false;
    }
};

const Fixture = struct {
    tmp: std.testing.TmpDir,
    database_path: [:0]u8,
    socket_path: []u8,
    database: sqlite.Database,
    management: management_repository.Repository,
    live: model.Store,
    passwords: FakePasswords,
    admission: auth_application.PasswordAdmission,
    authentication: auth_application.Application,
    inventory: inventory_service.Service,
    operations_repository: operations_repository.Repository,
    settings_repository: settings_repository.Repository,
    control: operations_service.ControlState,
    operations: operations_service.Service,
    idempotency_request_hash_key: idempotency_repository.RequestHashKey,
    application: api_application.Application,
    listener: std.Io.net.Server,
    unix_backend: api_server.UnixBackend,
    document: api_server.FixedDocument,
    http_handler: api_server.Handler,

    fn init(self: *Fixture) !void {
        self.tmp = std.testing.tmpDir(.{});
        errdefer self.tmp.cleanup();
        self.database_path = try std.fmt.allocPrintSentinel(
            allocator,
            ".zig-cache/tmp/{s}/ntip.sqlite3",
            .{&self.tmp.sub_path},
            0,
        );
        errdefer allocator.free(self.database_path);
        self.socket_path = try std.fmt.allocPrint(
            allocator,
            ".zig-cache/tmp/{s}/service.sock",
            .{&self.tmp.sub_path},
        );
        errdefer allocator.free(self.socket_path);

        self.database = try sqlite.Database.openInitialized(self.database_path);
        errdefer self.database.close();
        self.management = management_repository.Repository.init(&self.database);
        self.live = try self.management.loadInventory(allocator);
        errdefer self.live.deinit();
        self.passwords = .{};
        self.admission = .{};
        self.authentication = auth_application.Application.init(
            allocator,
            std.testing.io,
            access_repository.Repository.init(&self.database),
            self.passwords.engine(),
            &self.admission,
            try auth.PasswordHash.parse(test_dummy_phc),
        );
        errdefer self.authentication.deinit();
        const now = try wallSeconds();
        _ = try self.authentication.bootstrapFirstUser(.{
            .caller_uid = 0,
            .username = "root",
            .password = root_password,
            .now = now,
        });

        self.inventory = inventory_service.Service.init(
            &self.management,
            &self.live,
            allocator,
            std.testing.io,
            .{},
        );
        self.operations_repository = operations_repository.Repository.init(&self.database);
        self.settings_repository = settings_repository.Repository.init(&self.database);
        self.control = .{
            .instance_id = [_]u8{0xa7} ** 16,
            .managed_restart_supported = true,
        };
        self.operations = operations_service.Service.init(
            allocator,
            std.testing.io,
            &self.operations_repository,
            &self.settings_repository,
            &self.control,
            null,
            null,
        );
        const fixture_identity_secret = [_]u8{0x5a} ** 32;
        self.idempotency_request_hash_key = idempotency_repository.deriveRequestHashKey(
            &fixture_identity_secret,
        );
        self.application = api_application.Application.init(
            allocator,
            std.testing.io,
            &self.authentication,
            &self.inventory,
            &self.operations,
            idempotency_repository.Repository.init(&self.database),
            &self.idempotency_request_hash_key,
        );

        const address = try std.Io.net.UnixAddress.init(self.socket_path);
        self.listener = try address.listen(std.testing.io, .{});
        errdefer {
            self.listener.deinit(std.testing.io);
            std.Io.Dir.cwd().deleteFile(std.testing.io, self.socket_path) catch {};
        }
        self.unix_backend = .{ .socket_path = self.socket_path };
        self.document = .{ .bytes = "{\"openapi\":\"3.1.0\"}" };
        self.http_handler = .{
            .public_https_origin = origin,
            .openapi = api_server.OpenApiProvider.fromFixedDocument(&self.document),
            .backend = self.unix_backend.backend(),
        };
    }

    fn deinit(self: *Fixture) void {
        self.listener.deinit(std.testing.io);
        std.Io.Dir.cwd().deleteFile(std.testing.io, self.socket_path) catch {};
        self.authentication.deinit();
        std.crypto.secureZero(u8, &self.idempotency_request_hash_key);
        self.live.deinit();
        self.database.close();
        allocator.free(self.socket_path);
        allocator.free(self.database_path);
        self.tmp.cleanup();
        self.* = undefined;
    }

    fn dispatch(self: *Fixture, raw_request: []const u8) !api_server.OwnedHttpResponse {
        const parsed = try http.parseRequest(raw_request);
        var responder: ApplicationResponder = .{
            .listener = &self.listener,
            .handler = self.application.handler(),
        };
        const thread = try std.Thread.spawn(.{}, ApplicationResponder.run, .{&responder});
        const result = self.http_handler.dispatch(
            allocator,
            std.testing.io,
            &parsed.request,
            request_id,
        );
        thread.join();
        if (responder.failure) |failure| return failure;
        return result;
    }

    fn dispatchWithFailedServiceWrite(
        self: *Fixture,
        raw_request: []const u8,
    ) !api_server.OwnedHttpResponse {
        const parsed = try http.parseRequest(raw_request);
        var responder: ApplicationResponder = .{
            .listener = &self.listener,
            .handler = self.application.handler(),
            .fail_response_write = true,
        };
        const thread = try std.Thread.spawn(.{}, ApplicationResponder.run, .{&responder});
        const result = self.http_handler.dispatch(
            allocator,
            std.testing.io,
            &parsed.request,
            request_id,
        );
        thread.join();
        if (responder.failure) |failure| return failure;
        return result;
    }
};

const ApplicationResponder = struct {
    listener: *std.Io.net.Server,
    handler: service_server.Handler,
    fail_response_write: bool = false,
    failure: ?anyerror = null,

    fn run(self: *ApplicationResponder) void {
        self.respond() catch |failure| {
            self.failure = failure;
        };
    }

    fn respond(self: *ApplicationResponder) !void {
        const stream = try self.listener.accept(std.testing.io);
        defer stream.close(std.testing.io);

        const request_storage = try std.heap.smp_allocator.alloc(u8, service_ipc.maximum_frame_bytes);
        defer {
            std.crypto.secureZero(u8, request_storage);
            std.heap.smp_allocator.free(request_storage);
        }
        var reader_buffer: [8192]u8 = undefined;
        defer std.crypto.secureZero(u8, &reader_buffer);
        var stream_reader = stream.reader(std.testing.io, &reader_buffer);
        const frame = try service_ipc.readFrame(&stream_reader.interface, request_storage);

        var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
        defer arena.deinit();
        const parsed = try service_ipc.decodeRequest(arena.allocator(), frame);
        defer parsed.deinit();

        if (self.fail_response_write) {
            var failing: FailingResponseWriter = .{};
            var sink = try service_server.ResponseSink.init(
                std.heap.smp_allocator,
                &failing.interface,
                parsed.value.request_id,
            );
            self.handler.handle(
                .{ .pid = 1, .uid = 2, .gid = 3 },
                parsed.value,
                arena.allocator(),
                &sink,
            ) catch {
                if (!sink.poisoned) return error.UnexpectedApplicationFailure;
                return;
            };
            return error.ExpectedResponseWriteFailure;
        } else {
            var writer_buffer: [8192]u8 = undefined;
            defer std.crypto.secureZero(u8, &writer_buffer);
            var stream_writer = stream.writer(std.testing.io, &writer_buffer);
            var sink = try service_server.ResponseSink.init(
                std.heap.smp_allocator,
                &stream_writer.interface,
                parsed.value.request_id,
            );
            try self.handler.handle(
                .{ .pid = 1, .uid = 2, .gid = 3 },
                parsed.value,
                arena.allocator(),
                &sink,
            );
            if (!sink.terminal) return error.UnterminatedServiceResponse;
        }
    }
};

const FailingResponseWriter = struct {
    interface: std.Io.Writer = .{
        .vtable = &.{ .drain = drain },
        .buffer = &.{},
    },

    fn drain(
        _: *std.Io.Writer,
        _: []const []const u8,
        _: usize,
    ) std.Io.Writer.Error!usize {
        return error.WriteFailed;
    }
};

const RequestOptions = struct {
    method: http.Method,
    target: []const u8,
    body: []const u8 = "",
    origin_header: ?[]const u8 = null,
    cookie: ?[]const u8 = null,
    csrf: ?[]const u8 = null,
    idempotency_key: ?[]const u8 = null,
    if_match: ?[]const u8 = null,
};

fn makeRequest(options: RequestOptions) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try output.writer.print("{s} {s} HTTP/1.1\r\n", .{ options.method.text(), options.target });
    try output.writer.writeAll("Host: ntip.example.test\r\nUser-Agent: ntip-integration-test\r\n");
    if (options.origin_header) |value| try output.writer.print("Origin: {s}\r\n", .{value});
    if (options.cookie) |value| try output.writer.print("Cookie: {s}\r\n", .{value});
    if (options.csrf) |value| try output.writer.print("X-CSRF-Token: {s}\r\n", .{value});
    if (options.idempotency_key) |value| try output.writer.print("Idempotency-Key: {s}\r\n", .{value});
    if (options.if_match) |value| try output.writer.print("If-Match: {s}\r\n", .{value});
    if (options.body.len != 0) try output.writer.writeAll("Content-Type: application/json\r\n");
    if (options.body.len != 0 or options.method == .POST or options.method == .PATCH or
        options.method == .DELETE)
    {
        try output.writer.print("Content-Length: {d}\r\n", .{options.body.len});
    }
    try output.writer.writeAll("\r\n");
    try output.writer.writeAll(options.body);
    return output.toOwnedSlice();
}

fn dispatch(self: *Fixture, options: RequestOptions) !api_server.OwnedHttpResponse {
    const raw = try makeRequest(options);
    defer allocator.free(raw);
    return self.dispatch(raw);
}

fn dispatchWithFailedServiceWrite(
    self: *Fixture,
    options: RequestOptions,
) !api_server.OwnedHttpResponse {
    const raw = try makeRequest(options);
    defer allocator.free(raw);
    return self.dispatchWithFailedServiceWrite(raw);
}

const AuthContext = struct {
    response: api_server.OwnedHttpResponse,
    cookie_pair: [96]u8,
    cookie_pair_len: usize,
    csrf: [auth.session_token_text_len]u8,

    fn cookie(self: *const AuthContext) []const u8 {
        return self.cookie_pair[0..self.cookie_pair_len];
    }

    fn deinit(self: *AuthContext) void {
        self.response.deinit();
        std.crypto.secureZero(u8, &self.cookie_pair);
        std.crypto.secureZero(u8, &self.csrf);
        self.* = undefined;
    }
};

fn login(self: *Fixture, username: []const u8, password: []const u8, key: []const u8) !AuthContext {
    const body = try std.fmt.allocPrint(
        allocator,
        "{{\"username\":\"{s}\",\"password\":\"{s}\"}}",
        .{ username, password },
    );
    defer allocator.free(body);
    var response = try dispatch(self, .{
        .method = .POST,
        .target = "/api/v1/auth/login",
        .body = body,
        .origin_header = origin,
        .idempotency_key = key,
    });
    errdefer response.deinit();
    try std.testing.expectEqual(http.Status.ok, response.status);
    const set_cookie = response.set_cookie orelse return error.MissingSessionCookie;
    const separator = std.mem.indexOfScalar(u8, set_cookie, ';') orelse return error.InvalidSessionCookie;
    var result: AuthContext = .{
        .response = response,
        .cookie_pair = undefined,
        .cookie_pair_len = separator,
        .csrf = undefined,
    };
    if (separator > result.cookie_pair.len) return error.InvalidSessionCookie;
    @memcpy(result.cookie_pair[0..separator], set_cookie[0..separator]);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.body, .{});
    defer parsed.deinit();
    const csrf = parsed.value.object.get("csrfToken") orelse return error.MissingCsrfToken;
    if (csrf != .string or csrf.string.len != result.csrf.len) return error.InvalidCsrfToken;
    @memcpy(&result.csrf, csrf.string);
    return result;
}

fn errorCode(response: *const api_server.OwnedHttpResponse) !api_error.Code {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.body, .{});
    defer parsed.deinit();
    const error_value = parsed.value.object.get("error") orelse return error.InvalidErrorResponse;
    if (error_value != .object) return error.InvalidErrorResponse;
    const code = error_value.object.get("code") orelse return error.InvalidErrorResponse;
    if (code != .string) return error.InvalidErrorResponse;
    return std.meta.stringToEnum(api_error.Code, code.string) orelse error.InvalidErrorResponse;
}

fn temporaryPassword(response: *const api_server.OwnedHttpResponse) ![security_policy.temporary_password_bytes]u8 {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.body, .{});
    defer parsed.deinit();
    const value = parsed.value.object.get("temporaryPassword") orelse return error.MissingTemporaryPassword;
    if (value != .string or value.string.len != security_policy.temporary_password_bytes) {
        return error.InvalidTemporaryPassword;
    }
    var password: [security_policy.temporary_password_bytes]u8 = undefined;
    @memcpy(&password, value.string);
    return password;
}

const SessionResource = struct {
    id: [32]u8,
    etag: [128]u8,
    etag_len: usize,

    fn etagSlice(self: *const SessionResource) []const u8 {
        return self.etag[0..self.etag_len];
    }
};

fn sessionResource(response: *const api_server.OwnedHttpResponse) !SessionResource {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response.body, .{});
    defer parsed.deinit();
    const session = parsed.value.object.get("session") orelse return error.MissingSession;
    if (session != .object) return error.InvalidSession;
    const id = session.object.get("id") orelse return error.MissingSession;
    const etag = session.object.get("etag") orelse return error.MissingSession;
    if (id != .string or id.string.len != 32 or etag != .string or etag.string.len > 128) {
        return error.InvalidSession;
    }
    var result: SessionResource = .{
        .id = undefined,
        .etag = undefined,
        .etag_len = etag.string.len,
    };
    @memcpy(&result.id, id.string);
    @memcpy(result.etag[0..etag.string.len], etag.string);
    return result;
}

fn scalarInt(database: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try database.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const value = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return value;
}

fn wallSeconds() !i64 {
    const seconds = std.Io.Clock.real.now(std.testing.io).toSeconds();
    if (seconds < 0) return error.InvalidTimestamp;
    return seconds;
}

test "HTTP policy, typed IPC, auth application, logout replay, and revocation stay coherent" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const bad_origin_raw = try makeRequest(.{
        .method = .POST,
        .target = "/api/v1/auth/login",
        .body = "{\"username\":\"root\",\"password\":\"correct horse battery staple\"}",
        .origin_header = "https://evil.example.test",
        .idempotency_key = "login-origin-check-0001",
    });
    defer allocator.free(bad_origin_raw);
    const bad_origin = try http.parseRequest(bad_origin_raw);
    try std.testing.expectError(error.OriginForbidden, fixture.http_handler.dispatch(
        allocator,
        std.testing.io,
        &bad_origin.request,
        request_id,
    ));

    var root = try login(&fixture, "root", root_password, "login-root-session-0001");
    defer root.deinit();
    try std.testing.expect(std.mem.endsWith(
        u8,
        root.response.set_cookie.?,
        "; Secure; HttpOnly; SameSite=Strict; Path=/",
    ));

    var me = try dispatch(&fixture, .{
        .method = .GET,
        .target = "/api/v1/auth/me",
        .cookie = root.cookie(),
    });
    defer me.deinit();
    try std.testing.expectEqual(http.Status.ok, me.status);
    try std.testing.expect(std.mem.indexOf(u8, me.body, "\"username\":\"root\"") != null);

    // These four reads return page storage owned by OperationsService while
    // serialization uses the short-lived request arena. The testing allocator
    // makes an owner mismatch a deterministic leak regression.
    const operations_reads = [_][]const u8{
        "/api/v1/connectivity-checks",
        "/api/v1/events",
        "/api/v1/audit",
        "/api/v1/settings/revisions",
    };
    for (operations_reads) |target| {
        var page = try dispatch(&fixture, .{
            .method = .GET,
            .target = target,
            .cookie = root.cookie(),
        });
        defer page.deinit();
        try std.testing.expectEqual(http.Status.ok, page.status);
        if (std.mem.eql(u8, target, "/api/v1/audit")) {
            try std.testing.expect(std.mem.indexOf(u8, page.body, root_password) == null);
            const equals = std.mem.indexOfScalar(u8, root.cookie(), '=') orelse
                return error.InvalidSessionCookie;
            try std.testing.expect(std.mem.indexOf(u8, page.body, root.cookie()[equals + 1 ..]) == null);
        }
    }

    const missing_csrf_raw = try makeRequest(.{
        .method = .POST,
        .target = "/api/v1/auth/logout",
        .origin_header = origin,
        .cookie = root.cookie(),
        .idempotency_key = "logout-missing-csrf-01",
    });
    defer allocator.free(missing_csrf_raw);
    const missing_csrf = try http.parseRequest(missing_csrf_raw);
    try std.testing.expectError(error.CsrfRequired, fixture.http_handler.dispatch(
        allocator,
        std.testing.io,
        &missing_csrf.request,
        request_id,
    ));

    var wrong_csrf = [_]u8{'0'} ** auth.session_token_text_len;
    var rejected = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/logout",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &wrong_csrf,
        .idempotency_key = "logout-wrong-csrf-0001",
    });
    defer rejected.deinit();
    try std.testing.expectEqual(http.Status.forbidden, rejected.status);
    try std.testing.expectEqual(api_error.Code.csrf_failed, try errorCode(&rejected));

    var logout = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/logout",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "logout-root-session-001",
    });
    defer logout.deinit();
    try std.testing.expectEqual(http.Status.no_content, logout.status);
    try std.testing.expectEqualStrings(auth_application.clearing_session_cookie, logout.set_cookie.?);

    // Idempotency is not an authorization capability: once logout revokes the
    // session, even the exact completed key cannot replay its response.
    var logout_replay = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/logout",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "logout-root-session-001",
    });
    defer logout_replay.deinit();
    try std.testing.expectEqual(http.Status.unauthorized, logout_replay.status);
    try std.testing.expectEqual(api_error.Code.authentication_required, try errorCode(&logout_replay));
    try std.testing.expect(logout_replay.set_cookie == null);

    var revoked = try dispatch(&fixture, .{
        .method = .GET,
        .target = "/api/v1/auth/me",
        .cookie = root.cookie(),
    });
    defer revoked.deinit();
    try std.testing.expectEqual(http.Status.unauthorized, revoked.status);
    try std.testing.expectEqual(api_error.Code.authentication_required, try errorCode(&revoked));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM web_sessions;",
    ));
}

test "inventory ETags, idempotency, one-time secrets, forced password change, and RBAC cross every boundary" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var root = try login(&fixture, "root", root_password, "login-root-session-0002");
    defer root.deinit();

    const create_vnr = RequestOptions{
        .method = .POST,
        .target = "/api/v1/vnrs",
        .body = "{\"name\":\"Core\",\"cidr\":\"10.24.0.0/24\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "create-vnr-core-00001",
    };
    var created = try dispatch(&fixture, create_vnr);
    defer created.deinit();
    try std.testing.expectEqual(http.Status.created, created.status);
    try std.testing.expect(created.etag != null);
    try std.testing.expect(std.mem.indexOf(u8, created.body, "password") == null);

    var replayed = try dispatch(&fixture, create_vnr);
    defer replayed.deinit();
    try std.testing.expectEqual(http.Status.created, replayed.status);
    try std.testing.expectEqualSlices(u8, created.body, replayed.body);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM vnrs;",
    ));

    var conflict = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/vnrs",
        .body = "{\"name\":\"Other\",\"cidr\":\"10.25.0.0/24\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "create-vnr-core-00001",
    });
    defer conflict.deinit();
    try std.testing.expectEqual(http.Status.conflict, conflict.status);
    try std.testing.expectEqual(api_error.Code.idempotency_conflict, try errorCode(&conflict));

    var stale = try dispatch(&fixture, .{
        .method = .PATCH,
        .target = "/api/v1/vnrs/Core",
        .body = "{\"cidr\":\"10.24.0.0/23\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .if_match = "\"vnr:0000000000000000000000000000000000000000000000000000000000000000:1\"",
    });
    defer stale.deinit();
    try std.testing.expectEqual(http.Status.precondition_failed, stale.status);
    try std.testing.expectEqual(api_error.Code.precondition_failed, try errorCode(&stale));
    try std.testing.expectEqualStrings(created.etag.?, stale.etag.?);

    var updated = try dispatch(&fixture, .{
        .method = .PATCH,
        .target = "/api/v1/vnrs/Core",
        .body = "{\"cidr\":\"10.24.0.0/23\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .if_match = created.etag.?,
    });
    defer updated.deinit();
    try std.testing.expectEqual(http.Status.ok, updated.status);

    const create_user = RequestOptions{
        .method = .POST,
        .target = "/api/v1/users",
        .body = "{\"username\":\"viewer\",\"role\":\"viewer\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "create-viewer-user-001",
    };
    var provisioned = try dispatch(&fixture, create_user);
    defer provisioned.deinit();
    try std.testing.expectEqual(http.Status.created, provisioned.status);
    var temporary = try temporaryPassword(&provisioned);
    defer std.crypto.secureZero(u8, &temporary);

    var one_time_replay = try dispatch(&fixture, create_user);
    defer one_time_replay.deinit();
    try std.testing.expectEqual(http.Status.conflict, one_time_replay.status);
    try std.testing.expectEqual(api_error.Code.conflict, try errorCode(&one_time_replay));
    try std.testing.expect(std.mem.indexOf(u8, one_time_replay.body, &temporary) == null);
    try std.testing.expect(std.mem.indexOf(u8, one_time_replay.body, "temporaryPassword") == null);
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM users;",
    ));

    fixture.passwords.accepted = &temporary;
    var viewer = try login(&fixture, "viewer", &temporary, "login-viewer-session-01");
    defer viewer.deinit();
    try std.testing.expect(std.mem.indexOf(u8, viewer.response.body, "\"mustChangePassword\":true") != null);

    var forced = try dispatch(&fixture, .{
        .method = .GET,
        .target = "/api/v1/vnrs",
        .cookie = viewer.cookie(),
    });
    defer forced.deinit();
    try std.testing.expectEqual(http.Status.forbidden, forced.status);
    try std.testing.expectEqual(api_error.Code.password_change_required, try errorCode(&forced));

    const password_body = try std.fmt.allocPrint(
        allocator,
        "{{\"currentPassword\":\"{s}\",\"newPassword\":\"{s}\"}}",
        .{ &temporary, replacement_password },
    );
    defer allocator.free(password_body);
    var changed = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/change-password",
        .body = password_body,
        .origin_header = origin,
        .cookie = viewer.cookie(),
        .csrf = &viewer.csrf,
        .idempotency_key = "change-viewer-pass-0001",
    });
    defer changed.deinit();
    try std.testing.expectEqual(http.Status.no_content, changed.status);

    var viewer_read = try dispatch(&fixture, .{
        .method = .GET,
        .target = "/api/v1/vnrs",
        .cookie = viewer.cookie(),
    });
    defer viewer_read.deinit();
    try std.testing.expectEqual(http.Status.ok, viewer_read.status);

    var forbidden = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/vnrs",
        .body = "{\"name\":\"Denied\",\"cidr\":\"10.26.0.0/24\"}",
        .origin_header = origin,
        .cookie = viewer.cookie(),
        .csrf = &viewer.csrf,
        .idempotency_key = "viewer-forbidden-vnr-1",
    });
    defer forbidden.deinit();
    try std.testing.expectEqual(http.Status.forbidden, forbidden.status);
    try std.testing.expectEqual(api_error.Code.forbidden, try errorCode(&forbidden));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM vnrs;",
    ));

    const viewer_session = try sessionResource(&viewer.response);
    const session_target = try std.fmt.allocPrint(
        allocator,
        "/api/v1/sessions/{s}",
        .{&viewer_session.id},
    );
    defer allocator.free(session_target);
    var stale_revoke = try dispatch(&fixture, .{
        .method = .DELETE,
        .target = session_target,
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .if_match = "\"session:00000000000000000000000000000000:1\"",
    });
    defer stale_revoke.deinit();
    try std.testing.expectEqual(http.Status.precondition_failed, stale_revoke.status);
    try std.testing.expectEqualStrings(viewer_session.etagSlice(), stale_revoke.etag.?);

    var revoke = try dispatch(&fixture, .{
        .method = .DELETE,
        .target = session_target,
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .if_match = viewer_session.etagSlice(),
    });
    defer revoke.deinit();
    try std.testing.expectEqual(http.Status.no_content, revoke.status);
    var revoked_viewer = try dispatch(&fixture, .{
        .method = .GET,
        .target = "/api/v1/auth/me",
        .cookie = viewer.cookie(),
    });
    defer revoked_viewer.deinit();
    try std.testing.expectEqual(http.Status.unauthorized, revoked_viewer.status);
    try std.testing.expectEqual(api_error.Code.authentication_required, try errorCode(&revoked_viewer));

    // A completed idempotency record is never an authentication capability.
    // Expire the still-live root session, then prove the earlier VNR response
    // cannot be replayed even with the original cookie, CSRF token, and key.
    try fixture.database.exec(
        "UPDATE web_sessions SET created_at=0,last_seen_at=0," ++
            "idle_expires_at=1,absolute_expires_at=1,reauthenticated_at=NULL;",
    );
    var expired_replay = try dispatch(&fixture, create_vnr);
    defer expired_replay.deinit();
    try std.testing.expectEqual(http.Status.unauthorized, expired_replay.status);
    try std.testing.expectEqual(
        api_error.Code.authentication_required,
        try errorCode(&expired_replay),
    );
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM vnrs;",
    ));
}

test "idempotency mutation marker is atomic and prevents reexecution after response commit failure" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var root = try login(&fixture, "root", root_password, "login-idempotency-atomic-1");
    defer root.deinit();

    const rollback_request = RequestOptions{
        .method = .POST,
        .target = "/api/v1/users",
        .body = "{\"username\":\"atomicfail\",\"role\":\"viewer\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "atomic-marker-failure-001",
    };
    try fixture.database.exec(
        "CREATE TRIGGER fail_atomic_mutation_marker " ++
            "BEFORE UPDATE OF response_status ON idempotency_records " ++
            "WHEN OLD.response_status = 102 AND NEW.response_status = 103 BEGIN " ++
            "SELECT RAISE(ABORT, 'injected atomic marker failure'); END;",
    );
    var rolled_back = try dispatch(&fixture, rollback_request);
    defer rolled_back.deinit();
    try std.testing.expectEqual(http.Status.internal_server_error, rolled_back.status);
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM users WHERE username = 'atomicfail';",
    ));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM audit_entries WHERE resource_id = 'atomicfail';",
    ));
    try fixture.database.exec("DROP TRIGGER fail_atomic_mutation_marker;");

    var retried_after_rollback = try dispatch(&fixture, rollback_request);
    defer retried_after_rollback.deinit();
    try std.testing.expectEqual(http.Status.created, retried_after_rollback.status);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM users WHERE username = 'atomicfail';",
    ));

    const consumed_request = RequestOptions{
        .method = .POST,
        .target = "/api/v1/users",
        .body = "{\"username\":\"responsefail\",\"role\":\"viewer\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "exact-response-failure-001",
    };
    try fixture.database.exec(
        "CREATE TRIGGER fail_exact_response_completion " ++
            "BEFORE UPDATE OF response_status ON idempotency_records " ++
            "WHEN OLD.response_status = 103 AND NEW.response_status >= 200 BEGIN " ++
            "SELECT RAISE(ABORT, 'injected exact response failure'); END;",
    );
    var response_failed = try dispatch(&fixture, consumed_request);
    defer response_failed.deinit();
    try std.testing.expectEqual(http.Status.internal_server_error, response_failed.status);
    try std.testing.expect(std.mem.indexOf(u8, response_failed.body, "temporaryPassword") == null);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM users WHERE username = 'responsefail';",
    ));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM idempotency_records WHERE response_status = 103;",
    ));
    try fixture.database.exec("DROP TRIGGER fail_exact_response_completion;");

    var consumed_retry = try dispatch(&fixture, consumed_request);
    defer consumed_retry.deinit();
    try std.testing.expectEqual(http.Status.conflict, consumed_retry.status);
    try std.testing.expectEqual(api_error.Code.idempotency_conflict, try errorCode(&consumed_retry));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM users WHERE username = 'responsefail';",
    ));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM audit_entries WHERE resource_id = 'responsefail';",
    ));
}

test "authentication throttles cross the service boundary with bounded Retry-After metadata" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();

    const body = "{\"username\":\"root\",\"password\":\"wrong password\"}";
    for (0..security_policy.failures_before_lockout) |attempt| {
        var key_storage: [64]u8 = undefined;
        const key = try std.fmt.bufPrint(&key_storage, "login-throttle-attempt-{d:0>2}", .{attempt});
        var response = try dispatch(&fixture, .{
            .method = .POST,
            .target = "/api/v1/auth/login",
            .body = body,
            .origin_header = origin,
            .idempotency_key = key,
        });
        defer response.deinit();
        try std.testing.expectEqual(http.Status.unauthorized, response.status);
        try std.testing.expect(response.retry_after_seconds == null);
        if (attempt == 0) {
            var replay = try dispatch(&fixture, .{
                .method = .POST,
                .target = "/api/v1/auth/login",
                .body = body,
                .origin_header = origin,
                .idempotency_key = key,
            });
            defer replay.deinit();
            try std.testing.expectEqual(http.Status.unauthorized, replay.status);
            try std.testing.expectEqual(api_error.Code.invalid_credentials, try errorCode(&replay));
        }
    }
    try std.testing.expectEqual(@as(i64, security_policy.failures_before_lockout), try scalarInt(
        &fixture.database,
        "SELECT max(failure_count) FROM login_throttles;",
    ));

    var throttled = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/login",
        .body = "{\"username\":\"root\",\"password\":\"correct horse battery staple\"}",
        .origin_header = origin,
        .idempotency_key = "login-throttle-valid-01",
    });
    defer throttled.deinit();
    try std.testing.expectEqual(http.Status.too_many_requests, throttled.status);
    try std.testing.expectEqual(api_error.Code.rate_limited, try errorCode(&throttled));
    const retry_after = throttled.retry_after_seconds orelse return error.MissingRetryAfter;
    try std.testing.expect(retry_after > 1);
    try std.testing.expect(@as(u64, retry_after) <= security_policy.initial_lockout_seconds);

    fixture.admission.active = security_policy.argon2_parallel_verifications;
    fixture.admission.waiting = security_policy.argon2_wait_queue_entries;
    defer {
        fixture.admission.active = 0;
        fixture.admission.waiting = 0;
    }
    var saturated = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/login",
        .body = "{\"username\":\"queue-test\",\"password\":\"wrong password\"}",
        .origin_header = origin,
        .idempotency_key = "login-queue-saturated-01",
    });
    defer saturated.deinit();
    try std.testing.expectEqual(http.Status.too_many_requests, saturated.status);
    try std.testing.expectEqual(api_error.Code.rate_limited, try errorCode(&saturated));
    try std.testing.expectEqual(@as(?u32, 1), saturated.retry_after_seconds);
}

test "service control rolls back before completion but failed delivery remains armed once" {
    var fixture: Fixture = undefined;
    try fixture.init();
    defer fixture.deinit();
    var root = try login(&fixture, "root", root_password, "login-control-session-001");
    defer root.deinit();

    var reauthenticated = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/auth/reauth",
        .body = "{\"password\":\"correct horse battery staple\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "reauth-control-session-01",
    });
    defer reauthenticated.deinit();
    try std.testing.expectEqual(http.Status.ok, reauthenticated.status);

    const control_principal: operations_service.Principal = .{
        .user_id = [_]u8{0x11} ** 16,
        .session_id = [_]u8{0x22} ** 16,
        .role = .superuser,
    };
    const initial_etag_value = try fixture.operations.controlEtag(control_principal);
    const initial_etag = initial_etag_value.slice();

    // Fail exactly the central reserved->202 transition after the service
    // audit has committed and the response has been captured. The staged
    // decision must be rolled back without ever becoming runtime-executable.
    try fixture.database.exec(
        "CREATE TRIGGER fail_control_idempotency_completion " ++
            "BEFORE UPDATE OF response_status ON idempotency_records " ++
            "WHEN NEW.response_status = 202 BEGIN " ++
            "SELECT RAISE(ABORT, 'injected idempotency completion failure'); END;",
    );
    var failed = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/operations/restart",
        .body = "{\"confirmation\":\"restart\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "restart-injected-failure-01",
        .if_match = initial_etag,
    });
    defer failed.deinit();
    try std.testing.expectEqual(http.Status.internal_server_error, failed.status);
    try std.testing.expect(fixture.control.staged == null);
    try std.testing.expect(fixture.control.pending == null);
    try std.testing.expectEqual(@as(u64, 2), fixture.control.revision);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM audit_entries WHERE action = 'service.restart';",
    ));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM idempotency_records WHERE response_status = 202;",
    ));
    try fixture.database.exec("DROP TRIGGER fail_control_idempotency_completion;");

    const refreshed_etag_value = try fixture.operations.controlEtag(control_principal);
    const refreshed_etag = refreshed_etag_value.slice();
    try std.testing.expect(!std.mem.eql(u8, initial_etag, refreshed_etag));

    var stale_control = try dispatch(&fixture, .{
        .method = .POST,
        .target = "/api/v1/operations/restart",
        .body = "{\"confirmation\":\"restart\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "restart-stale-control-001",
        .if_match = initial_etag,
    });
    defer stale_control.deinit();
    try std.testing.expectEqual(http.Status.precondition_failed, stale_control.status);
    try std.testing.expectEqual(api_error.Code.precondition_failed, try errorCode(&stale_control));
    try std.testing.expectEqualStrings(refreshed_etag, stale_control.etag.?);

    const accepted_request: RequestOptions = .{
        .method = .POST,
        .target = "/api/v1/operations/restart",
        .body = "{\"confirmation\":\"restart\"}",
        .origin_header = origin,
        .cookie = root.cookie(),
        .csrf = &root.csrf,
        .idempotency_key = "restart-success-and-replay-1",
        .if_match = refreshed_etag,
    };
    try std.testing.expectError(
        error.ServiceUnavailable,
        dispatchWithFailedServiceWrite(&fixture, accepted_request),
    );
    try std.testing.expect(fixture.control.staged == null);
    const armed = fixture.control.pending orelse return error.MissingArmedControlDecision;
    try std.testing.expectEqual(operations_service.ControlKind.restart, armed.kind);
    try std.testing.expectEqual(@as(u64, 3), fixture.control.revision);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM idempotency_records WHERE response_status = 202;",
    ));

    // Model the runtime consuming the decision armed despite the peer's failed
    // read. Replaying its completed key returns the recorded 202 directly and
    // must not stage or arm another restart, append another audit row, or
    // change the control revision.
    fixture.control.pending = null;
    var replayed = try dispatch(&fixture, accepted_request);
    defer replayed.deinit();
    try std.testing.expectEqual(http.Status.accepted, replayed.status);
    try std.testing.expect(std.mem.indexOf(u8, replayed.body, "\"kind\":\"restart\"") != null);
    try std.testing.expect(fixture.control.staged == null);
    try std.testing.expect(fixture.control.pending == null);
    try std.testing.expectEqual(@as(u64, 3), fixture.control.revision);
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(
        &fixture.database,
        "SELECT count(*) FROM audit_entries WHERE action = 'service.restart';",
    ));
}

test "production Unix backend rejects oversized and malformed service response frames" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const socket_path = try std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/malformed.sock",
        .{&tmp.sub_path},
    );
    defer allocator.free(socket_path);
    const address = try std.Io.net.UnixAddress.init(socket_path);
    var listener = try address.listen(std.testing.io, .{});
    defer {
        listener.deinit(std.testing.io);
        std.Io.Dir.cwd().deleteFile(std.testing.io, socket_path) catch {};
    }

    const MalformedResponder = struct {
        listener: *std.Io.net.Server,
        kind: enum { oversized, invalid_json },
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.respond() catch |failure| {
                self.failure = failure;
            };
        }

        fn respond(self: *@This()) !void {
            const stream = try self.listener.accept(std.testing.io);
            defer stream.close(std.testing.io);
            var reader_buffer: [8192]u8 = undefined;
            var stream_reader = stream.reader(std.testing.io, &reader_buffer);
            const storage = try std.heap.smp_allocator.alloc(u8, service_ipc.maximum_frame_bytes);
            defer std.heap.smp_allocator.free(storage);
            _ = try service_ipc.readFrame(&stream_reader.interface, storage);
            var writer_buffer: [16]u8 = undefined;
            var stream_writer = stream.writer(std.testing.io, &writer_buffer);
            switch (self.kind) {
                .oversized => {
                    var prefix: [service_ipc.frame_prefix_bytes]u8 = undefined;
                    std.mem.writeInt(u32, &prefix, service_ipc.maximum_frame_bytes + 1, .big);
                    try stream_writer.interface.writeAll(&prefix);
                    try stream_writer.interface.flush();
                },
                .invalid_json => try service_ipc.writeFrame(&stream_writer.interface, "not-json"),
            }
        }
    };
    var responder: MalformedResponder = .{ .listener = &listener, .kind = .oversized };
    const thread = try std.Thread.spawn(.{}, MalformedResponder.run, .{&responder});

    var payload_object: std.json.ObjectMap = .empty;
    defer payload_object.deinit(allocator);
    try payload_object.put(allocator, "method", .{ .string = "GET" });
    try payload_object.put(allocator, "target", .{ .string = "/api/v1/health/ready" });
    try payload_object.put(allocator, "proxyPeer", .{ .string = "loopback" });
    try payload_object.put(allocator, "body", .null);
    const backend: api_server.UnixBackend = .{ .socket_path = socket_path };
    const result = backend.exchange(allocator, std.testing.io, .{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .deadline_unix_ms = std.math.maxInt(i64),
        .operation = "health.ready",
        .actor = .{ .kind = .service },
        .payload = .{ .object = payload_object },
    });
    thread.join();
    if (responder.failure) |failure| return failure;
    try std.testing.expectError(error.ServiceUnavailable, result);

    var invalid_json: MalformedResponder = .{ .listener = &listener, .kind = .invalid_json };
    const invalid_thread = try std.Thread.spawn(.{}, MalformedResponder.run, .{&invalid_json});
    const invalid_result = backend.exchange(allocator, std.testing.io, .{
        .version = service_ipc.protocol_version,
        .request_id = request_id,
        .deadline_unix_ms = std.math.maxInt(i64),
        .operation = "health.ready",
        .actor = .{ .kind = .service },
        .payload = .{ .object = payload_object },
    });
    invalid_thread.join();
    if (invalid_json.failure) |failure| return failure;
    try std.testing.expectError(error.InvalidServiceResponse, invalid_result);
}
