//! Transport-independent authentication and access-control application layer.
//!
//! HTTP and CLI transports supply bounded byte slices and timestamps. This
//! module owns authentication policy, fixed Argon2 admission, raw credential
//! issuance, and authorization; `access_repository` remains the transactional
//! owner of users, session hashes, throttle transitions, and immutable audit
//! rows.

const std = @import("std");
const auth = @import("auth.zig");
const security_policy = @import("security_policy.zig");
const service_ipc = @import("service_ipc.zig");
const access_repository = @import("../state/access_repository.zig");
const sqlite = @import("../state/sqlite.zig");

pub const UserId = access_repository.UserId;
pub const SessionId = access_repository.SessionId;
pub const User = access_repository.User;
pub const Session = access_repository.Session;
pub const Permission = auth.Permission;

const dummy_password = "ntip constant work dummy password";
const csrf_domain = "ntip-csrf-v0.2\x00";
pub const auth_progress_wait_slice_milliseconds: i64 = 100;

/// Optional production hook used while an admitted Argon2 worker is running.
/// The owner invokes it between waits of at most 100 ms, allowing the service
/// runtime to advance protocol work without recursively admitting another
/// management request.
pub const AuthProgressCheckpoint = struct {
    context: ?*anyopaque,
    checkpoint_fn: *const fn (?*anyopaque) anyerror!void,

    pub fn run(self: AuthProgressCheckpoint) !void {
        return self.checkpoint_fn(self.context);
    }
};

pub const PasswordEngine = struct {
    context: ?*anyopaque,
    hash_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        []const u8,
    ) anyerror!auth.PasswordHash,
    verify_fn: *const fn (
        ?*anyopaque,
        std.mem.Allocator,
        std.Io,
        *const auth.PasswordHash,
        []const u8,
    ) anyerror!bool,
    needs_rehash_fn: *const fn (?*anyopaque, *const auth.PasswordHash) bool,
    /// Production Argon2 must not occupy the serialized service owner. Test
    /// engines default to inline execution for cheap deterministic fixtures.
    off_thread: bool = false,

    pub fn production() PasswordEngine {
        return .{
            .context = null,
            .hash_fn = productionHash,
            .verify_fn = productionVerify,
            .needs_rehash_fn = productionNeedsRehash,
            .off_thread = true,
        };
    }

    pub fn hash(
        self: PasswordEngine,
        allocator: std.mem.Allocator,
        io: std.Io,
        password: []const u8,
    ) !auth.PasswordHash {
        return self.hash_fn(self.context, allocator, io, password);
    }

    pub fn verify(
        self: PasswordEngine,
        allocator: std.mem.Allocator,
        io: std.Io,
        password_hash: *const auth.PasswordHash,
        password: []const u8,
    ) !bool {
        return self.verify_fn(self.context, allocator, io, password_hash, password);
    }

    pub fn needsRehash(self: PasswordEngine, password_hash: *const auth.PasswordHash) bool {
        return self.needs_rehash_fn(self.context, password_hash);
    }

    fn productionHash(
        _: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        password: []const u8,
    ) !auth.PasswordHash {
        return auth.PasswordHash.create(allocator, io, password);
    }

    fn productionVerify(
        _: ?*anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        password_hash: *const auth.PasswordHash,
        password: []const u8,
    ) !bool {
        // Deliberately do not apply the creation-time 14-codepoint minimum
        // before Argon2. A short incorrect login password must still perform
        // the same expensive verification as any other bounded candidate.
        if (password.len > auth.password_max_bytes) return false;
        std.crypto.pwhash.argon2.strVerify(
            password_hash.slice(),
            password,
            .{ .allocator = allocator },
            io,
        ) catch |err| switch (err) {
            error.PasswordVerificationFailed => return false,
            else => return err,
        };
        return true;
    }

    fn productionNeedsRehash(_: ?*anyopaque, password_hash: *const auth.PasswordHash) bool {
        return password_hash.needsRehash();
    }
};

/// The process-wide production instance is intentionally shared by every
/// authentication application. At most one Argon2 operation runs at once;
/// eight callers may wait and the ninth is rejected before allocating hash
/// memory. Tests normally inject an isolated admission object.
pub var global_password_admission: PasswordAdmission = .{};

pub const PasswordAdmission = struct {
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    active: u8 = 0,
    waiting: u8 = 0,

    pub const Lease = struct {
        admission: *PasswordAdmission,
        io: std.Io,
        held: bool = true,

        pub fn release(self: *Lease) void {
            if (!self.held) return;
            self.held = false;
            self.admission.releaseOne(self.io);
        }
    };

    pub fn acquire(self: *PasswordAdmission, io: std.Io) !Lease {
        try self.mutex.lock(io);
        var locked = true;
        defer if (locked) self.mutex.unlock(io);

        if (self.active >= security_policy.argon2_parallel_verifications) {
            if (self.waiting >= security_policy.argon2_wait_queue_entries) {
                return error.PasswordQueueSaturated;
            }
            self.waiting += 1;
            errdefer self.waiting -= 1;
            while (self.active >= security_policy.argon2_parallel_verifications) {
                try self.condition.wait(io, &self.mutex);
            }
            self.waiting -= 1;
        }
        self.active += 1;
        self.mutex.unlock(io);
        locked = false;
        return .{ .admission = self, .io = io };
    }

    fn releaseOne(self: *PasswordAdmission, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        std.debug.assert(self.active > 0);
        self.active -= 1;
        self.condition.signal(io);
    }
};

pub const AuditContext = struct {
    actor_kind: access_repository.ActorKind,
    actor_id: ?UserId = null,
    request_id: ?[16]u8 = null,
};

/// Bounded transport attribution supplied by a trusted application adapter.
/// Direct callers may omit it, which preserves the empty CLI/system audit
/// details used outside the HTTP management plane.
pub const AuditMetadata = struct {
    request_id: ?[16]u8 = null,
    user_agent: ?[]const u8 = null,
    proxy_peer: ?[]const u8 = null,
};

pub const RehashStatus = enum {
    not_needed,
    updated,
};

pub const IssuedSession = struct {
    session: Session,
    token: auth.SecretToken,
    csrf_token: auth.SecretToken,
    rehash_status: RehashStatus,

    /// Call after the response has copied the one-time raw values.
    pub fn clear(self: *IssuedSession) void {
        std.crypto.secureZero(u8, &self.token.bytes);
        std.crypto.secureZero(u8, &self.csrf_token.bytes);
    }
};

pub const AuthenticatedSession = struct {
    session: Session,
    csrf_token: auth.SecretToken,

    pub fn clear(self: *AuthenticatedSession) void {
        std.crypto.secureZero(u8, &self.csrf_token.bytes);
    }
};

pub const MeProjection = struct {
    id: UserId,
    username: auth.Username,
    role: auth.Role,
    password_change_required: bool,
    csrf_token: auth.SecretToken,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    reauthenticated_at: ?i64,

    pub fn clear(self: *MeProjection) void {
        std.crypto.secureZero(u8, &self.csrf_token.bytes);
    }
};

pub const TemporaryCredential = struct {
    user: User,
    password: [security_policy.temporary_password_bytes]u8,

    /// The transport must call this immediately after the one-time response
    /// or download has been completed.
    pub fn clear(self: *TemporaryCredential) void {
        std.crypto.secureZero(u8, &self.password);
    }
};

pub const LoginInput = struct {
    username: []const u8,
    password: []const u8,
    now: i64,
    audit: AuditMetadata = .{},
};

pub const BootstrapInput = struct {
    caller_uid: u32,
    username: []const u8,
    password: []const u8,
    now: i64,
};

pub const session_cookie_buffer_len = security_policy.session_cookie_name.len +
    1 + auth.session_token_text_len + 2 + security_policy.session_cookie_attributes.len;

pub fn writeSessionCookie(
    token: auth.SecretToken,
    output: *[session_cookie_buffer_len]u8,
) []const u8 {
    var encoded: [auth.session_token_text_len]u8 = undefined;
    return std.fmt.bufPrint(
        output,
        "{s}={s}; {s}",
        .{
            security_policy.session_cookie_name,
            token.encode(&encoded),
            security_policy.session_cookie_attributes,
        },
    ) catch unreachable;
}

pub const clearing_session_cookie =
    "__Host-ntip_session=; Max-Age=0; Secure; HttpOnly; SameSite=Strict; Path=/";

pub const Application = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: access_repository.Repository,
    passwords: PasswordEngine,
    admission: *PasswordAdmission,
    dummy_hash: auth.PasswordHash,
    unknown_throttle_selection_key: [32]u8,
    auth_progress_checkpoint: ?AuthProgressCheckpoint = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository: access_repository.Repository,
        passwords: PasswordEngine,
        admission: *PasswordAdmission,
        dummy_hash: auth.PasswordHash,
    ) Application {
        var unknown_throttle_selection_key: [32]u8 = undefined;
        io.random(&unknown_throttle_selection_key);
        return .{
            .allocator = allocator,
            .io = io,
            .repository = repository,
            .passwords = passwords,
            .admission = admission,
            .dummy_hash = dummy_hash,
            .unknown_throttle_selection_key = unknown_throttle_selection_key,
        };
    }

    pub fn initProduction(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository: access_repository.Repository,
    ) !Application {
        const passwords = PasswordEngine.production();
        var lease = try global_password_admission.acquire(io);
        defer lease.release();
        const dummy_hash = try runPasswordHashWorker(
            io,
            passwords,
            null,
            dummy_password,
        );
        return init(
            allocator,
            io,
            repository,
            passwords,
            &global_password_admission,
            dummy_hash,
        );
    }

    pub fn deinit(self: *Application) void {
        std.crypto.secureZero(u8, &self.dummy_hash.bytes);
        std.crypto.secureZero(u8, &self.unknown_throttle_selection_key);
    }

    pub fn setAuthProgressCheckpoint(
        self: *Application,
        checkpoint: ?AuthProgressCheckpoint,
    ) void {
        self.auth_progress_checkpoint = checkpoint;
    }

    pub fn bootstrapFirstUser(self: *Application, input: BootstrapInput) !User {
        if (input.caller_uid != 0) return error.RootRequired;
        const username = try auth.Username.parse(input.username);
        var password_hash = try self.hashPassword(input.password);
        defer std.crypto.secureZero(u8, &password_hash.bytes);
        const user_id = randomId(self.io);
        return self.repository.bootstrapFirstSuperuser(.{
            .id = user_id,
            .username = username.slice(),
            .role = .superuser,
            .password_phc = password_hash.slice(),
            .password_change_required = false,
            .now = input.now,
        }, self.audit(.{
            .actor_kind = .local_cli,
        }, "user.bootstrap", "user", username.slice(), input.now, "{}"));
    }

    pub fn login(self: *Application, input: LoginInput) !IssuedSession {
        const audit_details = try encodeAuditDetails(self.allocator, input.audit);
        defer self.allocator.free(audit_details);
        const username = try auth.Username.parse(input.username);
        if (input.now < 0) return error.InvalidTimestamp;
        const principal_hash = try access_repository.principalHash(username.slice());
        const principal: ?access_repository.LoginPrincipal =
            self.repository.loadLoginPrincipal(username.slice()) catch |err| switch (err) {
                error.UserNotFound => null,
                else => return err,
            };
        const throttle_hash = if (principal != null)
            principal_hash
        else
            try self.unknownThrottleHash(username.slice());
        const throttle = try self.repository.loadLoginThrottle(throttle_hash);

        const selected_hash = if (principal) |*known| &known.password_hash else &self.dummy_hash;
        const verified = try self.verifyPassword(selected_hash, input.password);
        // A guessed password never exposes whether this exact principal or an
        // anonymous bucket was already blocked. Both paths perform Argon2 and
        // return InvalidCredentials. A caller that actually knows a valid
        // password still observes the account lockout.
        if (throttle.isBlocked(@intCast(input.now)) and
            verified and principal != null and principal.?.user.enabled)
        {
            return error.LoginThrottled;
        }
        if (!verified or principal == null or !principal.?.user.enabled) {
            // A failed login still mutates durable throttle state. When this
            // call is inside the central idempotent dispatcher, consume the
            // reservation in the same transaction so a lost 401 response can
            // be replayed without counting the attempt twice.
            self.repository.db.armCommitHook();
            const failure = try self.repository.recordLoginFailure(
                throttle_hash,
                input.now,
                randomId(self.io),
                self.audit(
                    .{ .actor_kind = .system, .request_id = input.audit.request_id },
                    "auth.lockout",
                    "login_principal",
                    if (principal == null) "unknown" else username.slice(),
                    input.now,
                    audit_details,
                ),
            );
            // The transition is intentionally not observable to a caller
            // presenting invalid credentials. Already-blocked candidates take
            // this same transaction path, so the post-Argon database work does
            // not disclose whether the canonical username resolved.
            _ = failure;
            return error.InvalidCredentials;
        }

        const known = principal.?;
        var rehash_status: RehashStatus = .not_needed;
        var replacement_hash: ?auth.PasswordHash = null;
        defer if (replacement_hash) |*replacement| {
            std.crypto.secureZero(u8, &replacement.bytes);
        };
        if (self.passwords.needsRehash(&known.password_hash)) {
            replacement_hash = try self.hashPassword(input.password);
            rehash_status = .updated;
        }

        var token = auth.SecretToken.generate(self.io);
        errdefer std.crypto.secureZero(u8, &token.bytes);
        var csrf_token = deriveCsrfToken(token);
        errdefer std.crypto.secureZero(u8, &csrf_token.bytes);
        const session_id = randomId(self.io);
        const create_input = access_repository.CreateSessionInput{
            .id = session_id,
            .user_id = known.user.id,
            .principal_hash = principal_hash,
            .token = token,
            .csrf_token = csrf_token,
            .user_agent = input.audit.user_agent orelse "",
            .now = input.now,
        };
        var session_id_text: [32]u8 = undefined;
        const login_audit = self.audit(.{
            .actor_kind = .web,
            .actor_id = known.user.id,
            .request_id = input.audit.request_id,
        }, "auth.login", "session", encodeId(session_id, &session_id_text), input.now, audit_details);
        const replacement_phc: ?[]const u8 = if (replacement_hash) |*replacement|
            replacement.slice()
        else
            null;
        const session = try self.repository.completeSuccessfulLogin(.{
            .session = create_input,
            .expected_user_revision = known.user.revision,
            .replacement_password_phc = replacement_phc,
        }, login_audit);
        return .{
            .session = session,
            .token = token,
            .csrf_token = csrf_token,
            .rehash_status = rehash_status,
        };
    }

    pub fn loginRetryAfter(
        self: *Application,
        username_text: []const u8,
        now: i64,
    ) !u64 {
        if (now < 0) return error.InvalidTimestamp;
        const username = try auth.Username.parse(username_text);
        const known: bool = known: {
            _ = self.repository.loadLoginPrincipal(username.slice()) catch |err| switch (err) {
                error.UserNotFound => break :known false,
                else => return err,
            };
            break :known true;
        };
        const principal_hash = if (!known)
            try self.unknownThrottleHash(username.slice())
        else
            try access_repository.principalHash(username.slice());
        const throttle = try self.repository.loadLoginThrottle(principal_hash);
        return throttle.retryAfter(@intCast(now));
    }

    fn unknownThrottleHash(self: *const Application, username_text: []const u8) ![32]u8 {
        return access_repository.unknownPrincipalThrottleHash(
            username_text,
            &self.unknown_throttle_selection_key,
        );
    }

    pub fn authenticate(
        self: *Application,
        token: auth.SecretToken,
        now: i64,
    ) !AuthenticatedSession {
        const session = try self.repository.authenticateSession(token, now);
        const csrf_token = deriveCsrfToken(token);
        if (!std.crypto.timing_safe.eql([32]u8, csrf_token.hash(), session.csrf_token_hash)) {
            return error.CorruptSession;
        }
        return .{ .session = session, .csrf_token = csrf_token };
    }

    pub fn authenticateMutation(
        self: *Application,
        token: auth.SecretToken,
        supplied_csrf: ?[]const u8,
        now: i64,
    ) !AuthenticatedSession {
        var authenticated = try self.authenticate(token, now);
        errdefer authenticated.clear();
        try security_policy.validateCsrf(authenticated.session.csrf_token_hash, supplied_csrf);
        return authenticated;
    }

    pub fn me(self: *Application, token: auth.SecretToken, now: i64) !MeProjection {
        var authenticated = try self.authenticate(token, now);
        const projection = MeProjection{
            .id = authenticated.session.user_id,
            .username = authenticated.session.username,
            .role = authenticated.session.role,
            .password_change_required = authenticated.session.password_change_required,
            .csrf_token = authenticated.csrf_token,
            .idle_expires_at = authenticated.session.idle_expires_at,
            .absolute_expires_at = authenticated.session.absolute_expires_at,
            .reauthenticated_at = authenticated.session.reauthenticated_at,
        };
        authenticated.clear();
        return projection;
    }

    pub fn authorize(session: Session, permission: Permission) !void {
        if (session.password_change_required) return error.PasswordChangeRequired;
        if (!auth.allows(session.role, permission)) return error.Forbidden;
    }

    pub fn requireRecentReauthentication(session: Session, now: i64) !void {
        if (!session.recentlyReauthenticated(now)) return error.ReauthenticationRequired;
    }

    pub fn reauthenticate(
        self: *Application,
        token: auth.SecretToken,
        supplied_csrf: ?[]const u8,
        password: []const u8,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !Session {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        var authenticated = try self.authenticateMutation(token, supplied_csrf, now);
        defer authenticated.clear();
        const principal = try self.repository.loadLoginPrincipal(authenticated.session.username.slice());
        if (!try self.verifyPassword(&principal.password_hash, password)) {
            return error.InvalidCredentials;
        }
        var session_id_text: [32]u8 = undefined;
        return self.repository.markReauthenticated(token, now, self.audit(.{
            .actor_kind = .web,
            .actor_id = authenticated.session.user_id,
            .request_id = audit_metadata.request_id,
        }, "auth.reauthenticate", "session", encodeId(authenticated.session.id, &session_id_text), now, audit_details));
    }

    pub fn changePassword(
        self: *Application,
        token: auth.SecretToken,
        supplied_csrf: ?[]const u8,
        current_password: []const u8,
        new_password: []const u8,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !User {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        var authenticated = try self.authenticateMutation(token, supplied_csrf, now);
        defer authenticated.clear();
        const principal = try self.repository.loadLoginPrincipal(authenticated.session.username.slice());
        if (!try self.verifyPassword(&principal.password_hash, current_password)) {
            return error.InvalidCredentials;
        }
        var replacement = try self.hashPassword(new_password);
        defer std.crypto.secureZero(u8, &replacement.bytes);
        return self.repository.changePassword(
            authenticated.session.user_id,
            authenticated.session.id,
            replacement.slice(),
            now,
            self.audit(.{
                .actor_kind = .web,
                .actor_id = authenticated.session.user_id,
                .request_id = audit_metadata.request_id,
            }, "auth.change_password", "user", authenticated.session.username.slice(), now, audit_details),
        );
    }

    pub fn logout(
        self: *Application,
        token: auth.SecretToken,
        supplied_csrf: ?[]const u8,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !void {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        var authenticated = try self.authenticateMutation(token, supplied_csrf, now);
        defer authenticated.clear();
        var session_id_text: [32]u8 = undefined;
        try self.repository.revokeOwnSession(
            authenticated.session.user_id,
            authenticated.session.id,
            self.audit(.{
                .actor_kind = .web,
                .actor_id = authenticated.session.user_id,
                .request_id = audit_metadata.request_id,
            }, "auth.logout", "session", encodeId(authenticated.session.id, &session_id_text), now, audit_details),
        );
    }

    pub fn provisionUser(
        self: *Application,
        actor: Session,
        username_text: []const u8,
        role: auth.Role,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !TemporaryCredential {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        try authorize(actor, .manage_users);
        const username = try auth.Username.parse(username_text);
        var temporary_password = security_policy.generateTemporaryPassword(self.io);
        errdefer std.crypto.secureZero(u8, &temporary_password);
        var password_hash = try self.hashPassword(&temporary_password);
        defer std.crypto.secureZero(u8, &password_hash.bytes);
        const user = try self.repository.createUser(.{
            .id = randomId(self.io),
            .username = username.slice(),
            .role = role,
            .password_phc = password_hash.slice(),
            .password_change_required = true,
            .now = now,
        }, self.audit(.{
            .actor_kind = .web,
            .actor_id = actor.user_id,
            .request_id = audit_metadata.request_id,
        }, "user.create", "user", username.slice(), now, audit_details));
        return .{ .user = user, .password = temporary_password };
    }

    pub fn resetPassword(
        self: *Application,
        actor: Session,
        user_id: UserId,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !TemporaryCredential {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        try authorize(actor, .manage_users);
        try requireRecentReauthentication(actor, now);
        var temporary_password = security_policy.generateTemporaryPassword(self.io);
        errdefer std.crypto.secureZero(u8, &temporary_password);
        var password_hash = try self.hashPassword(&temporary_password);
        defer std.crypto.secureZero(u8, &password_hash.bytes);
        var id_text: [32]u8 = undefined;
        const user = try self.repository.resetPassword(.{
            .user_id = user_id,
            .password_phc = password_hash.slice(),
            .password_change_required = true,
            .now = now,
        }, self.audit(.{
            .actor_kind = .web,
            .actor_id = actor.user_id,
            .request_id = audit_metadata.request_id,
        }, "user.password_reset", "user", encodeId(user_id, &id_text), now, audit_details));
        return .{ .user = user, .password = temporary_password };
    }

    pub fn mutateUser(
        self: *Application,
        actor: Session,
        mutation: access_repository.UserMutation,
        audit_metadata: AuditMetadata,
    ) !?User {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        try authorize(actor, .manage_users);
        try requireRecentReauthentication(actor, mutation.now);
        var id_text: [32]u8 = undefined;
        return self.repository.mutateUser(mutation, self.audit(.{
            .actor_kind = .web,
            .actor_id = actor.user_id,
            .request_id = audit_metadata.request_id,
        }, "user.update", "user", encodeId(mutation.user_id, &id_text), mutation.now, audit_details));
    }

    pub fn revokeSession(
        self: *Application,
        actor: Session,
        target_session_id: SessionId,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !void {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        var id_text: [32]u8 = undefined;
        const audit_entry = self.audit(.{
            .actor_kind = .web,
            .actor_id = actor.user_id,
            .request_id = audit_metadata.request_id,
        }, "session.revoke", "session", encodeId(target_session_id, &id_text), now, audit_details);
        if (actor.role == .superuser and !actor.password_change_required) {
            return self.repository.revokeSession(target_session_id, audit_entry);
        }
        try authorize(actor, .read);
        return self.repository.revokeOwnSession(actor.user_id, target_session_id, audit_entry);
    }

    pub fn revokeSessionsForUser(
        self: *Application,
        actor: Session,
        target_user_id: UserId,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !u64 {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        if (!std.crypto.timing_safe.eql(UserId, actor.user_id, target_user_id)) {
            try authorize(actor, .manage_all_sessions);
        } else {
            try authorize(actor, .read);
        }
        var id_text: [32]u8 = undefined;
        return self.repository.revokeAllSessionsForUser(target_user_id, self.audit(.{
            .actor_kind = .web,
            .actor_id = actor.user_id,
            .request_id = audit_metadata.request_id,
        }, "sessions.revoke_user", "user", encodeId(target_user_id, &id_text), now, audit_details));
    }

    pub fn revokeEverySession(
        self: *Application,
        actor: Session,
        now: i64,
        audit_metadata: AuditMetadata,
    ) !u64 {
        const audit_details = try encodeAuditDetails(self.allocator, audit_metadata);
        defer self.allocator.free(audit_details);
        try authorize(actor, .manage_all_sessions);
        return self.repository.revokeEverySession(self.audit(.{
            .actor_kind = .web,
            .actor_id = actor.user_id,
            .request_id = audit_metadata.request_id,
        }, "sessions.revoke_all", "session", "*", now, audit_details));
    }

    fn hashPassword(self: *Application, password: []const u8) !auth.PasswordHash {
        try auth.validatePassword(password);
        var lease = try self.admission.acquire(self.io);
        defer lease.release();
        if (self.passwords.off_thread) return runPasswordHashWorker(
            self.io,
            self.passwords,
            self.auth_progress_checkpoint,
            password,
        );
        return self.passwords.hash(self.allocator, self.io, password);
    }

    fn verifyPassword(
        self: *Application,
        password_hash: *const auth.PasswordHash,
        password: []const u8,
    ) !bool {
        // Bound memory retained by a request before it enters the expensive
        // queue. Creation policy is intentionally not applied here.
        if (password.len > auth.password_max_bytes) return false;
        var lease = try self.admission.acquire(self.io);
        defer lease.release();
        if (self.passwords.off_thread) return runPasswordVerifyWorker(
            self.io,
            self.passwords,
            self.auth_progress_checkpoint,
            password_hash,
            password,
        );
        return self.passwords.verify(self.allocator, self.io, password_hash, password);
    }

    fn audit(
        self: *Application,
        context: AuditContext,
        action: []const u8,
        resource_type: []const u8,
        resource_id: []const u8,
        now: i64,
        details_json: []const u8,
    ) access_repository.AuditEntry {
        return .{
            .id = randomId(self.io),
            .occurred_at = now,
            .actor_kind = context.actor_kind,
            .actor_id = context.actor_id,
            .action = action,
            .resource_type = resource_type,
            .resource_id = resource_id,
            .request_id = context.request_id,
            .details_json = details_json,
        };
    }
};

const password_worker_wait_slice: std.Io.Timeout = .{ .duration = .{
    .raw = .fromMilliseconds(auth_progress_wait_slice_milliseconds),
    .clock = .awake,
} };

const PasswordHashJob = struct {
    engine: PasswordEngine,
    io: std.Io,
    password_len: usize,
    password: [auth.password_max_bytes]u8 = [_]u8{0} ** auth.password_max_bytes,
    result: auth.PasswordHash = .{ .len = 0, .bytes = [_]u8{0} ** 128 },
    failure: ?anyerror = null,
    completed: std.Io.Event = .unset,

    fn init(engine: PasswordEngine, io: std.Io, password: []const u8) PasswordHashJob {
        var job = PasswordHashJob{
            .engine = engine,
            .io = io,
            .password_len = password.len,
        };
        @memcpy(job.password[0..password.len], password);
        return job;
    }

    fn run(self: *PasswordHashJob) void {
        defer {
            std.crypto.secureZero(u8, &self.password);
            self.completed.set(self.io);
        }
        self.result = self.engine.hash(
            std.heap.page_allocator,
            self.io,
            self.password[0..self.password_len],
        ) catch |err| {
            self.failure = err;
            return;
        };
    }

    fn clear(self: *PasswordHashJob) void {
        std.crypto.secureZero(u8, &self.password);
        std.crypto.secureZero(u8, &self.result.bytes);
    }
};

const PasswordVerifyJob = struct {
    engine: PasswordEngine,
    io: std.Io,
    password_hash: auth.PasswordHash,
    password_len: usize,
    password: [auth.password_max_bytes]u8 = [_]u8{0} ** auth.password_max_bytes,
    result: bool = false,
    failure: ?anyerror = null,
    completed: std.Io.Event = .unset,

    fn init(
        engine: PasswordEngine,
        io: std.Io,
        password_hash: *const auth.PasswordHash,
        password: []const u8,
    ) PasswordVerifyJob {
        var job = PasswordVerifyJob{
            .engine = engine,
            .io = io,
            .password_hash = password_hash.*,
            .password_len = password.len,
        };
        @memcpy(job.password[0..password.len], password);
        return job;
    }

    fn run(self: *PasswordVerifyJob) void {
        defer {
            std.crypto.secureZero(u8, &self.password);
            std.crypto.secureZero(u8, &self.password_hash.bytes);
            self.completed.set(self.io);
        }
        self.result = self.engine.verify(
            std.heap.page_allocator,
            self.io,
            &self.password_hash,
            self.password[0..self.password_len],
        ) catch |err| {
            self.failure = err;
            return;
        };
    }

    fn clear(self: *PasswordVerifyJob) void {
        std.crypto.secureZero(u8, &self.password);
        std.crypto.secureZero(u8, &self.password_hash.bytes);
    }
};

fn runPasswordHashWorker(
    io: std.Io,
    engine: PasswordEngine,
    checkpoint: ?AuthProgressCheckpoint,
    password: []const u8,
) !auth.PasswordHash {
    std.debug.assert(password.len <= auth.password_max_bytes);
    var job = PasswordHashJob.init(engine, io, password);
    defer job.clear();
    const thread = try std.Thread.spawn(.{}, PasswordHashJob.run, .{&job});
    defer thread.join();
    try waitForPasswordWorker(io, checkpoint, &job.completed);
    if (job.failure) |failure| return failure;
    return job.result;
}

fn runPasswordVerifyWorker(
    io: std.Io,
    engine: PasswordEngine,
    checkpoint: ?AuthProgressCheckpoint,
    password_hash: *const auth.PasswordHash,
    password: []const u8,
) !bool {
    std.debug.assert(password.len <= auth.password_max_bytes);
    var job = PasswordVerifyJob.init(engine, io, password_hash, password);
    defer job.clear();
    const thread = try std.Thread.spawn(.{}, PasswordVerifyJob.run, .{&job});
    defer thread.join();
    try waitForPasswordWorker(io, checkpoint, &job.completed);
    if (job.failure) |failure| return failure;
    return job.result;
}

fn waitForPasswordWorker(
    io: std.Io,
    checkpoint: ?AuthProgressCheckpoint,
    completed: *std.Io.Event,
) !void {
    const progress = checkpoint orelse return completed.wait(io);
    var pending_failure: ?anyerror = null;
    while (!completed.isSet()) {
        progress.run() catch |failure| {
            pending_failure = failure;
            completed.waitUncancelable(io);
            break;
        };
        if (completed.isSet()) break;
        completed.waitTimeout(io, password_worker_wait_slice) catch |failure| switch (failure) {
            error.Timeout => continue,
            else => {
                pending_failure = failure;
                completed.waitUncancelable(io);
                break;
            },
        };
    }
    if (pending_failure) |failure| return failure;
}

fn encodeAuditDetails(allocator: std.mem.Allocator, metadata: AuditMetadata) ![]u8 {
    try validateAuditText(metadata.user_agent, service_ipc.maximum_user_agent_bytes);
    try validateAuditText(metadata.proxy_peer, 255);
    if (metadata.proxy_peer) |peer| if (!std.mem.eql(u8, peer, "loopback")) {
        return error.InvalidAuditMetadata;
    };
    const Details = struct {
        userAgent: ?[]const u8 = null,
        proxyPeer: ?[]const u8 = null,
    };
    return std.json.Stringify.valueAlloc(allocator, Details{
        .userAgent = metadata.user_agent,
        .proxyPeer = metadata.proxy_peer,
    }, .{ .emit_null_optional_fields = false });
}

fn validateAuditText(value: ?[]const u8, maximum: usize) !void {
    const text = value orelse return;
    if (text.len > maximum or !std.unicode.utf8ValidateSlice(text)) {
        return error.InvalidAuditMetadata;
    }
    for (text) |byte| if (byte < 0x20 or byte == 0x7f) {
        return error.InvalidAuditMetadata;
    };
}

pub fn deriveCsrfToken(token: auth.SecretToken) auth.SecretToken {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(csrf_domain);
    hasher.update(&token.bytes);
    var csrf: auth.SecretToken = undefined;
    hasher.final(&csrf.bytes);
    return csrf;
}

fn randomId(io: std.Io) [16]u8 {
    var id: [16]u8 = undefined;
    io.random(&id);
    return id;
}

fn encodeId(id: [16]u8, output: *[32]u8) []const u8 {
    const alphabet = "0123456789abcdef";
    for (id, 0..) |byte, index| {
        output[index * 2] = alphabet[byte >> 4];
        output[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return output;
}

const test_phc = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$dmVyaWZpZXI";
const test_dummy_phc = "$argon2id$v=19$m=32768,t=2,p=1$ZHVtbXk$dmVyaWZpZXI";

const FakePasswords = struct {
    accepted: []const u8,
    verify_calls: usize = 0,
    hash_calls: usize = 0,
    last_verified: auth.PasswordHash = undefined,
    force_rehash: bool = false,
    off_thread: bool = false,

    fn engine(self: *FakePasswords) PasswordEngine {
        return .{
            .context = self,
            .hash_fn = hash,
            .verify_fn = verify,
            .needs_rehash_fn = needsRehash,
            .off_thread = self.off_thread,
        };
    }

    fn hash(
        raw: ?*anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        _: []const u8,
    ) !auth.PasswordHash {
        const self: *FakePasswords = @ptrCast(@alignCast(raw.?));
        self.hash_calls += 1;
        return auth.PasswordHash.parse(test_phc);
    }

    fn verify(
        raw: ?*anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        password_hash: *const auth.PasswordHash,
        password: []const u8,
    ) !bool {
        const self: *FakePasswords = @ptrCast(@alignCast(raw.?));
        self.verify_calls += 1;
        self.last_verified = password_hash.*;
        return std.mem.eql(u8, self.accepted, password);
    }

    fn needsRehash(raw: ?*anyopaque, _: *const auth.PasswordHash) bool {
        const self: *FakePasswords = @ptrCast(@alignCast(raw.?));
        return self.force_rehash;
    }
};

const CountingAuthCheckpoint = struct {
    calls: usize = 0,

    fn checkpoint(self: *CountingAuthCheckpoint) AuthProgressCheckpoint {
        return .{ .context = self, .checkpoint_fn = run };
    }

    fn run(raw: ?*anyopaque) !void {
        const self: *CountingAuthCheckpoint = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
    }
};

const BlockingPasswords = struct {
    original_hash_password: [*]const u8,
    original_verify_password: [*]const u8 = undefined,
    hash_worker_thread: std.Thread.Id = undefined,
    verify_worker_thread: std.Thread.Id = undefined,
    hash_password_was_copied: bool = false,
    verify_password_was_copied: bool = false,
    verify_started: std.Io.Event = .unset,
    verify_release: std.Io.Event = .unset,

    fn engine(self: *BlockingPasswords) PasswordEngine {
        return .{
            .context = self,
            .hash_fn = hash,
            .verify_fn = verify,
            .needs_rehash_fn = needsRehash,
            .off_thread = true,
        };
    }

    fn hash(
        raw: ?*anyopaque,
        _: std.mem.Allocator,
        _: std.Io,
        password: []const u8,
    ) !auth.PasswordHash {
        const self: *BlockingPasswords = @ptrCast(@alignCast(raw.?));
        self.hash_worker_thread = std.Thread.getCurrentId();
        self.hash_password_was_copied = password.ptr != self.original_hash_password;
        return auth.PasswordHash.parse(test_phc);
    }

    fn verify(
        raw: ?*anyopaque,
        _: std.mem.Allocator,
        io: std.Io,
        _: *const auth.PasswordHash,
        password: []const u8,
    ) !bool {
        const self: *BlockingPasswords = @ptrCast(@alignCast(raw.?));
        self.verify_worker_thread = std.Thread.getCurrentId();
        self.verify_password_was_copied = password.ptr != self.original_verify_password;
        self.verify_started.set(io);
        self.verify_release.waitUncancelable(io);
        return false;
    }

    fn needsRehash(_: ?*anyopaque, _: *const auth.PasswordHash) bool {
        return false;
    }
};

const ReleasingAuthCheckpoint = struct {
    io: std.Io,
    database: *sqlite.Database,
    passwords: *BlockingPasswords,
    calls: usize = 0,

    fn checkpoint(self: *ReleasingAuthCheckpoint) AuthProgressCheckpoint {
        return .{ .context = self, .checkpoint_fn = run };
    }

    fn run(raw: ?*anyopaque) !void {
        const self: *ReleasingAuthCheckpoint = @ptrCast(@alignCast(raw.?));
        self.calls += 1;
        self.passwords.verify_started.waitUncancelable(self.io);
        // A nested BEGIN proves login retained neither a repository
        // transaction nor a borrowed SQLite column while Argon was running.
        var transaction = try self.database.begin(.immediate);
        try transaction.rollback();
        self.passwords.verify_release.set(self.io);
    }
};

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

fn testApplication(
    database: *sqlite.Database,
    passwords: *FakePasswords,
    admission: *PasswordAdmission,
) !Application {
    return Application.init(
        std.testing.allocator,
        std.testing.io,
        access_repository.Repository.init(database),
        passwords.engine(),
        admission,
        try auth.PasswordHash.parse(test_dummy_phc),
    );
}

fn bootstrap(app: *Application, username: []const u8, now: i64) !User {
    return app.bootstrapFirstUser(.{
        .caller_uid = 0,
        .username = username,
        .password = "correct horse battery staple",
        .now = now,
    });
}

fn csrfText(token: auth.SecretToken, output: *[auth.session_token_text_len]u8) []const u8 {
    return token.encode(output);
}

fn scalarInt(database: *sqlite.Database, sql: [:0]const u8) !i64 {
    var statement = try database.prepare(sql);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const result = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return result;
}

fn expectAuditAttribution(
    database: *sqlite.Database,
    action: []const u8,
    user_agent: []const u8,
) !void {
    var statement = try database.prepare(
        "SELECT count(*) FROM audit_entries WHERE action = ?1 " ++
            "AND json_extract(details_json, '$.userAgent') = ?2 " ++
            "AND json_extract(details_json, '$.proxyPeer') = 'loopback' " ++
            "AND instr(details_json, 'password') = 0 " ++
            "AND instr(details_json, 'token') = 0;",
    );
    defer statement.deinit();
    try statement.bindText(1, action);
    try statement.bindText(2, user_agent);
    try std.testing.expectEqual(sqlite.Step.row, try statement.step());
    try std.testing.expectEqual(@as(i64, 1), statement.columnInt64(0));
    try std.testing.expectEqual(sqlite.Step.done, try statement.step());
}

test "password admission rejects a ninth waiter without performing work" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    var passwords = FakePasswords{
        .accepted = "correct horse battery staple",
        .off_thread = true,
    };
    var admission = PasswordAdmission{
        .active = security_policy.argon2_parallel_verifications,
        .waiting = security_policy.argon2_wait_queue_entries,
    };
    var app = try testApplication(&database, &passwords, &admission);
    defer app.deinit();
    var checkpoint: CountingAuthCheckpoint = .{};
    app.setAuthProgressCheckpoint(checkpoint.checkpoint());

    try std.testing.expectError(error.PasswordQueueSaturated, app.bootstrapFirstUser(.{
        .caller_uid = 0,
        .username = "root",
        .password = "correct horse battery staple",
        .now = 1,
    }));
    try std.testing.expectEqual(@as(usize, 0), passwords.hash_calls);
    try std.testing.expectEqual(@as(usize, 0), checkpoint.calls);
}

test "primed unknown traffic cannot enumerate a known username and stays bounded" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    var passwords = FakePasswords{ .accepted = "correct horse battery staple" };
    var admission: PasswordAdmission = .{};
    var app = try testApplication(&database, &passwords, &admission);
    defer app.deinit();
    _ = try bootstrap(&app, "root", 1);

    var attempt: u16 = 1;
    while (attempt <= security_policy.failures_before_lockout) : (attempt += 1) {
        try std.testing.expectError(error.InvalidCredentials, app.login(.{
            .username = "missing-primer",
            .password = "incorrect horse battery staple",
            .now = 9 + attempt,
        }));
    }

    const primed_bucket = try app.unknownThrottleHash("missing-primer");
    var collision_buffer: [64]u8 = undefined;
    var collision: ?[]const u8 = null;
    var candidate_index: usize = 0;
    while (candidate_index < 4096) : (candidate_index += 1) {
        const candidate = try std.fmt.bufPrint(
            &collision_buffer,
            "missing-collision-{d}",
            .{candidate_index},
        );
        const candidate_bucket = try app.unknownThrottleHash(candidate);
        if (std.mem.eql(u8, &primed_bucket, &candidate_bucket)) {
            collision = candidate;
            break;
        }
    }
    const colliding_unknown = collision orelse return error.ExpectedBucketCollision;
    const verifier_calls_at_lockout = passwords.verify_calls;
    try std.testing.expectError(error.InvalidCredentials, app.login(.{
        .username = "root",
        .password = "incorrect horse battery staple",
        .now = 9 + security_policy.failures_before_lockout,
    }));
    try std.testing.expectError(error.InvalidCredentials, app.login(.{
        .username = colliding_unknown,
        .password = "incorrect horse battery staple",
        .now = 9 + security_policy.failures_before_lockout,
    }));
    try std.testing.expectEqual(
        verifier_calls_at_lockout + 2,
        passwords.verify_calls,
    );
    try std.testing.expectEqualStrings(test_dummy_phc, passwords.last_verified.slice());
    try std.testing.expectEqual(
        security_policy.failures_before_lockout + 1,
        (try app.repository.loadLoginThrottle(primed_bucket)).failure_count,
    );
    try std.testing.expectEqual(
        security_policy.initial_lockout_seconds * 2,
        try app.loginRetryAfter("missing-primer", 9 + security_policy.failures_before_lockout),
    );

    var spray_index: usize = 0;
    while (spray_index < 1024) : (spray_index += 1) {
        var username_buffer: [48]u8 = undefined;
        const username = try std.fmt.bufPrint(&username_buffer, "rotated-missing-{d}", .{spray_index});
        try std.testing.expectError(error.InvalidCredentials, app.login(.{
            .username = username,
            .password = "incorrect horse battery staple",
            .now = 20,
        }));
    }
    const maximum_throttle_rows: i64 =
        @as(i64, security_policy.unknown_login_throttle_buckets) + 1;
    try std.testing.expect((try scalarInt(
        &database,
        "SELECT count(*) FROM login_throttles;",
    )) <= maximum_throttle_rows);

    // Anonymous bucket saturation never touches the known principal's row.
    var issued = try app.login(.{
        .username = "root",
        .password = passwords.accepted,
        .now = 21,
    });
    defer issued.clear();
}

test "off-thread password work checkpoints with copied inputs and no SQLite borrow" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    const owner_thread = std.Thread.getCurrentId();
    const root_password = "correct horse battery staple";
    var passwords = BlockingPasswords{ .original_hash_password = root_password.ptr };
    var admission: PasswordAdmission = .{};
    var app = Application.init(
        std.testing.allocator,
        std.testing.io,
        access_repository.Repository.init(&database),
        passwords.engine(),
        &admission,
        try auth.PasswordHash.parse(test_dummy_phc),
    );
    defer app.deinit();
    _ = try app.bootstrapFirstUser(.{
        .caller_uid = 0,
        .username = "root",
        .password = root_password,
        .now = 1,
    });
    try std.testing.expect(passwords.hash_password_was_copied);
    try std.testing.expect(passwords.hash_worker_thread != owner_thread);

    var wrong_password = [_]u8{'x'} ** 32;
    passwords.original_verify_password = wrong_password[0..].ptr;
    var checkpoint = ReleasingAuthCheckpoint{
        .io = std.testing.io,
        .database = &database,
        .passwords = &passwords,
    };
    app.setAuthProgressCheckpoint(checkpoint.checkpoint());
    try std.testing.expectError(error.InvalidCredentials, app.login(.{
        .username = "root",
        .password = &wrong_password,
        .now = 2,
    }));
    try std.testing.expectEqual(@as(usize, 1), checkpoint.calls);
    try std.testing.expect(passwords.verify_password_was_copied);
    try std.testing.expect(passwords.verify_worker_thread != owner_thread);
}

test "successful login opportunistically rehashes in the session transaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    var passwords = FakePasswords{
        .accepted = "correct horse battery staple",
        .force_rehash = true,
    };
    var admission: PasswordAdmission = .{};
    var app = try testApplication(&database, &passwords, &admission);
    defer app.deinit();
    const initial = try bootstrap(&app, "root", 1);

    var issued = try app.login(.{
        .username = "root",
        .password = passwords.accepted,
        .now = 2,
        .audit = .{
            .request_id = [_]u8{0x42} ** 16,
            .user_agent = "ntip-dashboard-auth-test/1",
            .proxy_peer = "loopback",
        },
    });
    defer issued.clear();
    try std.testing.expectEqual(RehashStatus.updated, issued.rehash_status);
    const rehashed = try app.repository.loadLoginPrincipal("root");
    try std.testing.expectEqual(initial.revision + 1, rehashed.user.revision);
    try std.testing.expectEqual(initial.password_changed_at, rehashed.user.password_changed_at);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &database,
        "SELECT count(*) FROM web_sessions;",
    ));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &database,
        "SELECT count(*) FROM audit_entries WHERE action = 'auth.login';",
    ));
    try expectAuditAttribution(&database, "auth.login", "ntip-dashboard-auth-test/1");
}

test "temporary password flow is forced and raw credentials never enter SQLite" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    var passwords = FakePasswords{ .accepted = "correct horse battery staple" };
    var admission: PasswordAdmission = .{};
    var app = try testApplication(&database, &passwords, &admission);
    defer app.deinit();
    _ = try bootstrap(&app, "root", 1);
    var root_login = try app.login(.{
        .username = "root",
        .password = passwords.accepted,
        .now = 2,
    });
    defer root_login.clear();

    var temporary = try app.provisionUser(root_login.session, "Viewer.One", .viewer, 3, .{
        .request_id = [_]u8{0x43} ** 16,
        .user_agent = "ntip-dashboard-user-test/1",
        .proxy_peer = "loopback",
    });
    defer temporary.clear();
    try std.testing.expect(temporary.user.password_change_required);
    try auth.validatePassword(&temporary.password);
    passwords.accepted = &temporary.password;
    var viewer_login = try app.login(.{
        .username = "viewer.one",
        .password = &temporary.password,
        .now = 4,
    });
    defer viewer_login.clear();
    try std.testing.expect(viewer_login.session.password_change_required);
    try std.testing.expectError(
        error.PasswordChangeRequired,
        Application.authorize(viewer_login.session, .read),
    );

    var csrf_buffer: [auth.session_token_text_len]u8 = undefined;
    const changed = try app.changePassword(
        viewer_login.token,
        csrfText(viewer_login.csrf_token, &csrf_buffer),
        &temporary.password,
        "a completely new safe passphrase",
        5,
        .{},
    );
    try std.testing.expect(!changed.password_change_required);
    var refreshed = try app.authenticate(viewer_login.token, 6);
    defer refreshed.clear();
    try Application.authorize(refreshed.session, .read);

    var secrets = try database.prepare(
        "SELECT count(*) FROM web_sessions WHERE token_hash = ?1 OR csrf_token_hash = ?2;",
    );
    defer secrets.deinit();
    try secrets.bindBlob(1, &viewer_login.token.bytes);
    try secrets.bindBlob(2, &viewer_login.csrf_token.bytes);
    try std.testing.expectEqual(sqlite.Step.row, try secrets.step());
    try std.testing.expectEqual(@as(i64, 0), secrets.columnInt64(0));
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(
        &database,
        "SELECT count(*) FROM users WHERE password_phc NOT LIKE '$argon2id$%';",
    ));
    var temporary_search = try database.prepare(
        "SELECT count(*) FROM users WHERE password_phc = ?1;",
    );
    defer temporary_search.deinit();
    try temporary_search.bindText(1, &temporary.password);
    try std.testing.expectEqual(sqlite.Step.row, try temporary_search.step());
    try std.testing.expectEqual(@as(i64, 0), temporary_search.columnInt64(0));
    try expectAuditAttribution(&database, "user.create", "ntip-dashboard-user-test/1");
}

test "cookie flags CSRF sliding expiry and reauthentication are exact" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    var passwords = FakePasswords{ .accepted = "correct horse battery staple" };
    var admission: PasswordAdmission = .{};
    var app = try testApplication(&database, &passwords, &admission);
    defer app.deinit();
    _ = try bootstrap(&app, "root", 1);
    var issued = try app.login(.{
        .username = "root",
        .password = passwords.accepted,
        .now = 10,
    });
    defer issued.clear();

    var cookie_buffer: [session_cookie_buffer_len]u8 = undefined;
    const cookie = writeSessionCookie(issued.token, &cookie_buffer);
    try std.testing.expect(std.mem.startsWith(u8, cookie, "__Host-ntip_session="));
    try std.testing.expect(std.mem.endsWith(u8, cookie, "; Secure; HttpOnly; SameSite=Strict; Path=/"));
    try std.testing.expectEqualStrings(
        "__Host-ntip_session=; Max-Age=0; Secure; HttpOnly; SameSite=Strict; Path=/",
        clearing_session_cookie,
    );

    var csrf_buffer: [auth.session_token_text_len]u8 = undefined;
    const csrf = csrfText(issued.csrf_token, &csrf_buffer);
    var mutation = try app.authenticateMutation(issued.token, csrf, 10);
    mutation.clear();
    csrf_buffer[0] = if (csrf_buffer[0] == '0') '1' else '0';
    try std.testing.expectError(
        error.CsrfFailed,
        app.authenticateMutation(issued.token, &csrf_buffer, 10),
    );

    var touched = try app.me(
        issued.token,
        10 + access_repository.session_touch_interval_seconds,
    );
    defer touched.clear();
    try std.testing.expectEqual(
        @as(i64, 10 + access_repository.session_touch_interval_seconds),
        touched.idle_expires_at - @as(i64, @intCast(auth.idle_timeout_seconds)),
    );
    var csrf_buffer_again: [auth.session_token_text_len]u8 = undefined;
    const valid_csrf = csrfText(issued.csrf_token, &csrf_buffer_again);
    const reauthenticated = try app.reauthenticate(
        issued.token,
        valid_csrf,
        passwords.accepted,
        80,
        .{},
    );
    try std.testing.expect(reauthenticated.recentlyReauthenticated(80));
    try Application.requireRecentReauthentication(
        reauthenticated,
        80 + @as(i64, @intCast(auth.reauthentication_window_seconds)),
    );
    try std.testing.expectError(
        error.ReauthenticationRequired,
        Application.requireRecentReauthentication(
            reauthenticated,
            81 + @as(i64, @intCast(auth.reauthentication_window_seconds)),
        ),
    );
    try std.testing.expectError(
        error.SessionExpired,
        app.authenticate(issued.token, issued.session.absolute_expires_at),
    );
}

test "role checks and own versus global revocation are enforced" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var database = try sqlite.Database.openInitialized(
        try testDatabasePath(&tmp, &path_buffer),
    );
    defer database.close();
    var passwords = FakePasswords{ .accepted = "correct horse battery staple" };
    var admission: PasswordAdmission = .{};
    var app = try testApplication(&database, &passwords, &admission);
    defer app.deinit();
    _ = try bootstrap(&app, "root", 1);
    var root_login = try app.login(.{
        .username = "root",
        .password = passwords.accepted,
        .now = 2,
    });
    defer root_login.clear();
    var viewer_credential = try app.provisionUser(root_login.session, "viewer", .viewer, 3, .{});
    defer viewer_credential.clear();
    passwords.accepted = &viewer_credential.password;
    var viewer_login = try app.login(.{
        .username = "viewer",
        .password = &viewer_credential.password,
        .now = 4,
    });
    defer viewer_login.clear();

    // Clear the forced-change bit through the repository to focus this test
    // on role and ownership policy.
    _ = try app.repository.changePassword(
        viewer_login.session.user_id,
        viewer_login.session.id,
        test_phc,
        5,
        .{
            .id = [_]u8{0xa5} ** 16,
            .occurred_at = 5,
            .actor_kind = .system,
            .action = "test.password_change",
            .resource_type = "user",
        },
    );
    viewer_login.session.password_change_required = false;
    try std.testing.expectError(
        error.Forbidden,
        Application.authorize(viewer_login.session, .manage_users),
    );
    try std.testing.expectError(
        error.SessionNotFound,
        app.revokeSession(viewer_login.session, root_login.session.id, 6, .{}),
    );
    var root_still_active = try app.authenticate(root_login.token, 6);
    root_still_active.clear();
    try app.revokeSession(root_login.session, viewer_login.session.id, 7, .{
        .request_id = [_]u8{0x44} ** 16,
        .user_agent = "ntip-dashboard-session-test/1",
        .proxy_peer = "loopback",
    });
    try expectAuditAttribution(&database, "session.revoke", "ntip-dashboard-session-test/1");
    try std.testing.expectError(
        error.SessionNotFound,
        app.authenticate(viewer_login.token, 8),
    );
}
