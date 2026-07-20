//! Transactional access-control repository for the v0.2 management plane.
//!
//! The serialized `ntsrv` application worker owns the supplied SQLite
//! connection. Every persisted value is bound through a prepared statement;
//! user/session mutations and their immutable audit entries commit together.
//! Password hashing and verification remain outside this database-owning
//! layer so the caller can enforce the bounded Argon2 admission queue.

const std = @import("std");
const auth = @import("../management/auth.zig");
const security_policy = @import("../management/security_policy.zig");
const management_repository = @import("management_repository.zig");
const sqlite = @import("sqlite.zig");

pub const UserId = [16]u8;
pub const SessionId = [16]u8;
pub const AuditEntry = management_repository.AuditEntry;
pub const ActorKind = management_repository.ActorKind;

/// Avoids a durable write for every authenticated request while still
/// extending a live session well before its 30-minute idle deadline.
pub const session_touch_interval_seconds: i64 = 60;
pub const default_page_size: u16 = 50;
pub const maximum_page_size: u16 = 200;
pub const maximum_maintenance_batch: u16 = 1_000;
const seconds_per_day: i64 = 24 * 60 * 60;

pub const UserCursor = struct {
    /// Stable newest-first composite cursor. IDs break timestamp ties.
    created_at: i64,
    before_id: UserId,
};

pub const SessionCursor = struct {
    /// Stable newest-first composite cursor. IDs break timestamp ties.
    created_at: i64,
    before_id: SessionId,
};

pub const User = struct {
    id: UserId,
    username: auth.Username,
    role: auth.Role,
    enabled: bool,
    password_change_required: bool,
    revision: u64,
    created_at: i64,
    updated_at: i64,
    password_changed_at: i64,
};

pub const UserPage = struct {
    items: []User,
    next_cursor: ?UserCursor,

    pub fn deinit(self: *UserPage, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
        self.* = undefined;
    }
};

/// Secret-free administrative projection of a web session. `generation` is
/// derived from the durable `last_seen_at` value, so an ETag becomes stale
/// when the sliding-session touch is persisted. The current schema has no
/// proxy-peer column; the HTTP application serializes that contract field as
/// null until a future migration introduces durable peer observations.
pub const SessionView = struct {
    id: SessionId,
    user_id: UserId,
    username: auth.Username,
    current: bool,
    user_agent: ?[]u8,
    proxy_peer: ?[]u8,
    generation: u64,
    created_at: i64,
    last_seen_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,

    pub fn deinit(self: *SessionView, allocator: std.mem.Allocator) void {
        if (self.user_agent) |value| allocator.free(value);
        if (self.proxy_peer) |value| allocator.free(value);
        self.* = undefined;
    }
};

pub const SessionPage = struct {
    items: []SessionView,
    next_cursor: ?SessionCursor,

    pub fn deinit(self: *SessionPage, allocator: std.mem.Allocator) void {
        for (self.items) |*item| item.deinit(allocator);
        allocator.free(self.items);
        self.* = undefined;
    }
};

/// The PHC verifier is derived password material, not a browser credential.
/// Callers must send verification work through the fixed bounded Argon2
/// queue; this repository never accepts or returns plaintext passwords.
pub const LoginPrincipal = struct {
    user: User,
    password_hash: auth.PasswordHash,
};

pub const Session = struct {
    id: SessionId,
    user_id: UserId,
    username: auth.Username,
    role: auth.Role,
    password_change_required: bool,
    csrf_token_hash: [32]u8,
    created_at: i64,
    last_seen_at: i64,
    idle_expires_at: i64,
    absolute_expires_at: i64,
    reauthenticated_at: ?i64,

    pub fn recentlyReauthenticated(self: Session, now: i64) bool {
        if (now < 0) return false;
        const at = self.reauthenticated_at orelse return false;
        if (at < 0) return false;
        return auth.recentlyReauthenticated(@intCast(at), @intCast(now));
    }
};

pub const CreateUserInput = struct {
    id: UserId,
    username: []const u8,
    role: auth.Role,
    password_phc: []const u8,
    password_change_required: bool,
    now: i64,
};

pub const ResetPasswordInput = struct {
    user_id: UserId,
    password_phc: []const u8,
    password_change_required: bool = true,
    now: i64,
};

pub const UserMutation = struct {
    user_id: UserId,
    role: auth.Role,
    enabled: bool,
    tombstone: bool = false,
    now: i64,
};

pub const CreateSessionInput = struct {
    id: SessionId,
    user_id: UserId,
    principal_hash: [32]u8,
    token: auth.SecretToken,
    csrf_token: auth.SecretToken,
    user_agent: []const u8 = "",
    now: i64,
};

/// Successful password verification output supplied by the bounded Argon2
/// worker. A replacement PHC value is present only when policy requires an
/// opportunistic rehash. The expected revision prevents overwriting a
/// concurrent reset/disable/role mutation between principal load and commit.
pub const SuccessfulLoginInput = struct {
    session: CreateSessionInput,
    expected_user_revision: u64,
    replacement_password_phc: ?[]const u8 = null,
};

pub const ThrottleFailure = struct {
    state: security_policy.ThrottleState,
    security_event_recorded: bool,
};

pub const Repository = struct {
    db: *sqlite.Database,

    pub fn init(db: *sqlite.Database) Repository {
        return .{ .db = db };
    }

    /// Root-only CLI bootstrap calls this operation. The database check and
    /// insertion are in one immediate transaction, so concurrent attempts
    /// cannot create two initial administrators.
    pub fn bootstrapFirstSuperuser(
        self: Repository,
        input: CreateUserInput,
        audit: AuditEntry,
    ) !User {
        if (input.role != .superuser) return error.BootstrapRequiresSuperuser;
        try validateTimestamp(input.now);
        const username = try auth.Username.parse(input.username);
        _ = try auth.PasswordHash.parse(input.password_phc);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        if (try self.userCount() != 0) return error.AlreadyBootstrapped;
        try self.ensureUsernameAvailable(username.slice());
        const user = try self.insertUser(input, username);
        try self.insertAudit(audit);
        try transaction.commit();
        return user;
    }

    pub fn createUser(self: Repository, input: CreateUserInput, audit: AuditEntry) !User {
        try validateTimestamp(input.now);
        const username = try auth.Username.parse(input.username);
        _ = try auth.PasswordHash.parse(input.password_phc);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.ensureUsernameAvailable(username.slice());
        const user = self.insertUser(input, username) catch |err| return switch (err) {
            error.ConstraintViolation => error.UserConstraintViolation,
            else => err,
        };
        self.insertAudit(audit) catch |err| return switch (err) {
            error.ConstraintViolation => error.InvalidAuditEntry,
            else => err,
        };
        try transaction.commit();
        return user;
    }

    pub fn loadUser(self: Repository, id: UserId) !User {
        var statement = try self.db.prepare(
            "SELECT id, username, role, enabled, password_change_required, " ++
                "revision, created_at, updated_at, password_changed_at " ++
                "FROM users WHERE id = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id);
        if (try statement.step() != .row) return error.UserNotFound;
        const user = try decodeUser(&statement, 0);
        if (try statement.step() != .done) return error.CorruptAccessState;
        return user;
    }

    pub fn listUsers(
        self: Repository,
        allocator: std.mem.Allocator,
        cursor: ?UserCursor,
        requested_limit: u16,
    ) !UserPage {
        const limit = try pageLimit(requested_limit);
        var statement = try self.db.prepare(
            "SELECT id, username, role, enabled, password_change_required, " ++
                "revision, created_at, updated_at, password_changed_at " ++
                "FROM users WHERE (?1 = 0 OR created_at < ?2 OR " ++
                "(created_at = ?2 AND id < ?3)) " ++
                "ORDER BY created_at DESC, id DESC LIMIT ?4;",
        );
        defer statement.deinit();
        try bindPageCursor(
            &statement,
            cursor != null,
            if (cursor) |value| value.created_at else 0,
            if (cursor) |value| value.before_id else [_]u8{0} ** 16,
        );
        try statement.bindInt64(4, @as(i64, @intCast(limit + 1)));

        var items: std.ArrayListUnmanaged(User) = .empty;
        errdefer items.deinit(allocator);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            try items.append(allocator, try decodeUser(&statement, 0));
        }
        const next_cursor: ?UserCursor = if (saw_more) .{
            .created_at = items.items[items.items.len - 1].created_at,
            .before_id = items.items[items.items.len - 1].id,
        } else null;
        return .{ .items = try items.toOwnedSlice(allocator), .next_cursor = next_cursor };
    }

    pub fn loadSessionView(
        self: Repository,
        allocator: std.mem.Allocator,
        id: SessionId,
        current_session_id: ?SessionId,
        now: i64,
    ) !SessionView {
        try validateTimestamp(now);
        var statement = try self.db.prepare(
            "SELECT web_sessions.id, web_sessions.user_id, users.username, " ++
                "web_sessions.user_agent, web_sessions.created_at, " ++
                "web_sessions.last_seen_at, web_sessions.idle_expires_at, " ++
                "web_sessions.absolute_expires_at " ++
                "FROM web_sessions JOIN users ON users.id = web_sessions.user_id " ++
                "WHERE web_sessions.id = ?1 AND web_sessions.idle_expires_at > ?2 " ++
                "AND web_sessions.absolute_expires_at > ?2;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id);
        try statement.bindInt64(2, now);
        if (try statement.step() != .row) return error.SessionNotFound;
        const view = try decodeSessionView(allocator, &statement, current_session_id);
        errdefer {
            var owned = view;
            owned.deinit(allocator);
        }
        if (try statement.step() != .done) return error.CorruptAccessState;
        return view;
    }

    /// `owner_id == null` selects the superuser all-session scope. Supplying a
    /// user ID enforces the ordinary own-session scope in SQL, rather than
    /// filtering a privileged result in application memory.
    pub fn listSessions(
        self: Repository,
        allocator: std.mem.Allocator,
        owner_id: ?UserId,
        current_session_id: ?SessionId,
        now: i64,
        cursor: ?SessionCursor,
        requested_limit: u16,
    ) !SessionPage {
        try validateTimestamp(now);
        const limit = try pageLimit(requested_limit);
        var statement = try self.db.prepare(
            "SELECT web_sessions.id, web_sessions.user_id, users.username, " ++
                "web_sessions.user_agent, web_sessions.created_at, " ++
                "web_sessions.last_seen_at, web_sessions.idle_expires_at, " ++
                "web_sessions.absolute_expires_at " ++
                "FROM web_sessions JOIN users ON users.id = web_sessions.user_id " ++
                "WHERE (?1 = 0 OR web_sessions.user_id = ?2) " ++
                "AND web_sessions.idle_expires_at > ?3 " ++
                "AND web_sessions.absolute_expires_at > ?3 AND " ++
                "(?4 = 0 OR web_sessions.created_at < ?5 OR " ++
                "(web_sessions.created_at = ?5 AND web_sessions.id < ?6)) " ++
                "ORDER BY web_sessions.created_at DESC, web_sessions.id DESC LIMIT ?7;",
        );
        defer statement.deinit();
        try statement.bindInt64(1, @intFromBool(owner_id != null));
        if (owner_id) |id| try statement.bindBlob(2, &id) else try statement.bindNull(2);
        try statement.bindInt64(3, now);
        try statement.bindInt64(4, @intFromBool(cursor != null));
        if (cursor) |value| {
            if (value.created_at < 0) return error.InvalidCursor;
            try statement.bindInt64(5, value.created_at);
            try statement.bindBlob(6, &value.before_id);
        } else {
            const zero_id = [_]u8{0} ** 16;
            try statement.bindInt64(5, 0);
            try statement.bindBlob(6, &zero_id);
        }
        try statement.bindInt64(7, @as(i64, @intCast(limit + 1)));

        var items: std.ArrayListUnmanaged(SessionView) = .empty;
        errdefer deinitSessionViewList(&items, allocator);
        var saw_more = false;
        while (try statement.step() == .row) {
            if (items.items.len == limit) {
                saw_more = true;
                break;
            }
            var item = try decodeSessionView(allocator, &statement, current_session_id);
            errdefer item.deinit(allocator);
            try items.append(allocator, item);
        }
        const next_cursor: ?SessionCursor = if (saw_more) .{
            .created_at = items.items[items.items.len - 1].created_at,
            .before_id = items.items[items.items.len - 1].id,
        } else null;
        return .{ .items = try items.toOwnedSlice(allocator), .next_cursor = next_cursor };
    }

    /// Supplies the derived PHC verifier to the authentication worker. No
    /// plaintext password, session token, or CSRF token crosses this API.
    pub fn loadLoginPrincipal(self: Repository, username_text: []const u8) !LoginPrincipal {
        const username = try auth.Username.parse(username_text);
        var statement = try self.db.prepare(
            "SELECT id, username, role, enabled, password_change_required, " ++
                "revision, created_at, updated_at, password_changed_at, password_phc " ++
                "FROM users WHERE username = ?1;",
        );
        defer statement.deinit();
        try statement.bindText(1, username.slice());
        if (try statement.step() != .row) return error.UserNotFound;
        const user = try decodeUser(&statement, 0);
        const phc = statement.columnText(9) orelse return error.CorruptAccessState;
        const password_hash = auth.PasswordHash.parse(phc) catch return error.CorruptAccessState;
        if (try statement.step() != .done) return error.CorruptAccessState;
        return .{ .user = user, .password_hash = password_hash };
    }

    /// Administrative password provisioning/reset. Reset credentials may be
    /// marked temporary, and every existing session is revoked atomically.
    pub fn resetPassword(
        self: Repository,
        input: ResetPasswordInput,
        audit: AuditEntry,
    ) !User {
        try validateTimestamp(input.now);
        _ = try auth.PasswordHash.parse(input.password_phc);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        _ = try self.loadUser(input.user_id);

        var update = try self.db.prepare(
            "UPDATE users SET password_phc = ?1, password_change_required = ?2, " ++
                "password_changed_at = ?3, updated_at = ?3, revision = revision + 1 " ++
                "WHERE id = ?4;",
        );
        defer update.deinit();
        try update.bindText(1, input.password_phc);
        try update.bindInt64(2, @intFromBool(input.password_change_required));
        try update.bindInt64(3, input.now);
        try update.bindBlob(4, &input.user_id);
        if (try update.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.UserNotFound;
        try self.deleteSessionsForUser(input.user_id, null);
        try self.insertAudit(audit);
        const user = try self.loadUser(input.user_id);
        try transaction.commit();
        return user;
    }

    /// A user-driven password change clears the forced-change state and keeps
    /// only the authenticated session used for the change. Passing null is
    /// valid for OS-authorized CLI changes and revokes every web session.
    pub fn changePassword(
        self: Repository,
        user_id: UserId,
        keep_session_id: ?SessionId,
        password_phc: []const u8,
        now: i64,
        audit: AuditEntry,
    ) !User {
        try validateTimestamp(now);
        _ = try auth.PasswordHash.parse(password_phc);

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        _ = try self.loadUser(user_id);
        if (keep_session_id) |session_id| try self.requireSessionOwner(session_id, user_id);

        var update = try self.db.prepare(
            "UPDATE users SET password_phc = ?1, password_change_required = 0, " ++
                "password_changed_at = ?2, updated_at = ?2, revision = revision + 1 " ++
                "WHERE id = ?3;",
        );
        defer update.deinit();
        try update.bindText(1, password_phc);
        try update.bindInt64(2, now);
        try update.bindBlob(3, &user_id);
        if (try update.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.UserNotFound;
        try self.deleteSessionsForUser(user_id, keep_session_id);
        try self.insertAudit(audit);
        const user = try self.loadUser(user_id);
        try transaction.commit();
        return user;
    }

    /// Role, enabled-state, and tombstone changes always revoke all target
    /// sessions. The final active superuser invariant is checked while the
    /// immediate transaction excludes a competing mutation.
    pub fn mutateUser(
        self: Repository,
        mutation: UserMutation,
        audit: AuditEntry,
    ) !?User {
        try validateTimestamp(mutation.now);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        const current = try self.loadUser(mutation.user_id);
        const active_superusers = try self.activeSuperuserCount();
        try security_policy.validateUserMutation(active_superusers, .{
            .target_is_active_superuser = current.enabled and current.role == .superuser,
            .desired_role = mutation.role,
            .desired_enabled = mutation.enabled,
            .tombstone = mutation.tombstone,
        });

        try self.deleteSessionsForUser(mutation.user_id, null);
        if (mutation.tombstone) {
            var tombstone = try self.db.prepare(
                "INSERT INTO user_tombstones " ++
                    "(username, former_user_id, tombstoned_at, actor_kind, actor_id) " ++
                    "VALUES (?1, ?2, ?3, ?4, ?5);",
            );
            defer tombstone.deinit();
            try tombstone.bindText(1, current.username.slice());
            try tombstone.bindBlob(2, &current.id);
            try tombstone.bindInt64(3, mutation.now);
            try tombstone.bindText(4, actorKindText(audit.actor_kind));
            if (audit.actor_id) |actor_id| try tombstone.bindBlob(5, &actor_id) else try tombstone.bindNull(5);
            if (try tombstone.step() != .done) return error.UnexpectedRow;

            var remove = try self.db.prepare("DELETE FROM users WHERE id = ?1;");
            defer remove.deinit();
            try remove.bindBlob(1, &mutation.user_id);
            if (try remove.step() != .done) return error.UnexpectedRow;
            if (self.db.changes() != 1) return error.UserNotFound;
            try self.insertAudit(audit);
            try transaction.commit();
            return null;
        }

        var update = try self.db.prepare(
            "UPDATE users SET role = ?1, enabled = ?2, updated_at = ?3, " ++
                "revision = revision + 1 WHERE id = ?4;",
        );
        defer update.deinit();
        try update.bindText(1, roleText(mutation.role));
        try update.bindInt64(2, @intFromBool(mutation.enabled));
        try update.bindInt64(3, mutation.now);
        try update.bindBlob(4, &mutation.user_id);
        if (try update.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.UserNotFound;
        try self.insertAudit(audit);
        const user = try self.loadUser(mutation.user_id);
        try transaction.commit();
        return user;
    }

    /// Completes a successful browser login: reset principal throttling,
    /// persist only token hashes, and append the successful-auth audit row in
    /// one commit. The caller retains the one-time raw tokens for the response.
    pub fn createSession(
        self: Repository,
        input: CreateSessionInput,
        audit: AuditEntry,
    ) !Session {
        try validateTimestamp(input.now);
        if (input.user_agent.len > 1024) return error.UserAgentTooLong;

        const absolute_expires_at = try checkedAddTimestamp(input.now, auth.absolute_timeout_seconds);
        const idle_candidate = try checkedAddTimestamp(input.now, auth.idle_timeout_seconds);
        const idle_expires_at = @min(idle_candidate, absolute_expires_at);
        const token_hash = input.token.hash();
        const csrf_hash = input.csrf_token.hash();

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        const user = try self.loadUser(input.user_id);
        if (!user.enabled) return error.UserDisabled;

        var insert = try self.db.prepare(
            "INSERT INTO web_sessions " ++
                "(id, user_id, token_hash, csrf_token_hash, created_at, last_seen_at, " ++
                "idle_expires_at, absolute_expires_at, reauthenticated_at, user_agent) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, NULL, ?8);",
        );
        defer insert.deinit();
        try insert.bindBlob(1, &input.id);
        try insert.bindBlob(2, &input.user_id);
        try insert.bindBlob(3, &token_hash);
        try insert.bindBlob(4, &csrf_hash);
        try insert.bindInt64(5, input.now);
        try insert.bindInt64(6, idle_expires_at);
        try insert.bindInt64(7, absolute_expires_at);
        try insert.bindText(8, input.user_agent);
        if (try insert.step() != .done) return error.UnexpectedRow;

        var throttle = try self.loadThrottle(input.principal_hash);
        throttle.recordSuccess(@intCast(input.now));
        try self.saveThrottle(input.principal_hash, throttle);
        try self.insertAudit(audit);

        const session = Session{
            .id = input.id,
            .user_id = input.user_id,
            .username = user.username,
            .role = user.role,
            .password_change_required = user.password_change_required,
            .csrf_token_hash = csrf_hash,
            .created_at = input.now,
            .last_seen_at = input.now,
            .idle_expires_at = idle_expires_at,
            .absolute_expires_at = absolute_expires_at,
            .reauthenticated_at = null,
        };
        try transaction.commit();
        return session;
    }

    /// Commits every durable side effect of a verified browser login in one
    /// transaction. If Argon2 policy requested a PHC rehash, the compare-and-
    /// swap update, session creation, throttle reset, and audit entry either
    /// all commit or all roll back.
    pub fn completeSuccessfulLogin(
        self: Repository,
        input: SuccessfulLoginInput,
        audit: AuditEntry,
    ) !Session {
        try validateTimestamp(input.session.now);
        if (input.session.user_agent.len > 1024) return error.UserAgentTooLong;
        if (input.expected_user_revision == 0) return error.InvalidUserRevision;
        if (input.replacement_password_phc) |phc| _ = try auth.PasswordHash.parse(phc);

        const absolute_expires_at = try checkedAddTimestamp(
            input.session.now,
            auth.absolute_timeout_seconds,
        );
        const idle_candidate = try checkedAddTimestamp(input.session.now, auth.idle_timeout_seconds);
        const idle_expires_at = @min(idle_candidate, absolute_expires_at);
        const token_hash = input.session.token.hash();
        const csrf_hash = input.session.csrf_token.hash();

        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var user = try self.loadUser(input.session.user_id);
        if (!user.enabled) return error.UserDisabled;
        if (user.revision != input.expected_user_revision) return error.StaleUserRevision;

        if (input.replacement_password_phc) |phc| {
            if (input.session.now < user.updated_at) return error.InvalidTimestamp;
            var rehash = try self.db.prepare(
                "UPDATE users SET password_phc = ?1, updated_at = ?2, " ++
                    "revision = revision + 1 WHERE id = ?3 AND revision = ?4;",
            );
            defer rehash.deinit();
            try rehash.bindText(1, phc);
            try rehash.bindInt64(2, input.session.now);
            try rehash.bindBlob(3, &input.session.user_id);
            if (input.expected_user_revision >= std.math.maxInt(i64)) return error.InvalidUserRevision;
            try rehash.bindInt64(4, @as(i64, @intCast(input.expected_user_revision)));
            if (try rehash.step() != .done) return error.UnexpectedRow;
            if (self.db.changes() != 1) return error.StaleUserRevision;
            user.revision += 1;
            user.updated_at = input.session.now;
        }

        try self.insertSessionRow(
            input.session,
            token_hash,
            csrf_hash,
            idle_expires_at,
            absolute_expires_at,
        );
        var throttle = try self.loadThrottle(input.session.principal_hash);
        throttle.recordSuccess(@intCast(input.session.now));
        try self.saveThrottle(input.session.principal_hash, throttle);
        try self.insertAudit(audit);

        const session = makeSession(
            input.session,
            user,
            csrf_hash,
            idle_expires_at,
            absolute_expires_at,
        );
        try transaction.commit();
        return session;
    }

    /// Authenticates by a constant-size token digest. Expired rows are removed;
    /// active rows are touched no more than once per bounded touch interval.
    pub fn authenticateSession(
        self: Repository,
        token: auth.SecretToken,
        now: i64,
    ) !Session {
        try validateTimestamp(now);
        const token_hash = token.hash();
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};

        var session = try self.loadSessionByTokenHash(token_hash);
        if (now >= session.idle_expires_at or now >= session.absolute_expires_at) {
            try self.deleteSessionById(session.id);
            try transaction.commit();
            return error.SessionExpired;
        }
        if (now >= session.last_seen_at +| session_touch_interval_seconds) {
            const idle_candidate = try checkedAddTimestamp(now, auth.idle_timeout_seconds);
            const idle_expires_at = @min(idle_candidate, session.absolute_expires_at);
            var touch = try self.db.prepare(
                "UPDATE web_sessions SET last_seen_at = ?1, idle_expires_at = ?2 " ++
                    "WHERE id = ?3;",
            );
            defer touch.deinit();
            try touch.bindInt64(1, now);
            try touch.bindInt64(2, idle_expires_at);
            try touch.bindBlob(3, &session.id);
            if (try touch.step() != .done) return error.UnexpectedRow;
            if (self.db.changes() != 1) return error.SessionNotFound;
            session.last_seen_at = now;
            session.idle_expires_at = idle_expires_at;
        }
        try transaction.commit();
        return session;
    }

    /// Bounded maintenance for rows that can no longer authenticate. Public
    /// session reads also exclude these rows immediately, so cleanup cadence
    /// affects storage only, never authorization semantics.
    pub fn pruneExpiredSessions(
        self: Repository,
        now: i64,
        requested_limit: u16,
    ) !u64 {
        try validateTimestamp(now);
        try validateMaintenanceLimit(requested_limit);
        var statement = try self.db.prepare(
            "DELETE FROM web_sessions WHERE id IN (" ++
                "SELECT id FROM web_sessions WHERE idle_expires_at <= ?1 " ++
                "OR absolute_expires_at <= ?1 " ++
                "ORDER BY min(idle_expires_at,absolute_expires_at),id LIMIT ?2);",
        );
        defer statement.deinit();
        try statement.bindInt64(1, now);
        try statement.bindInt64(2, requested_limit);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    /// Principal throttle rows are useful only for the fixed security window.
    /// Keep them for the same 90-day forensic horizon as aggregate lockout
    /// events, then delete only rows whose active block has also elapsed.
    pub fn pruneStaleLoginThrottles(
        self: Repository,
        now: i64,
        requested_limit: u16,
    ) !u64 {
        try validateTimestamp(now);
        try validateMaintenanceLimit(requested_limit);
        const duration = @as(i64, security_policy.security_event_retention_days) * seconds_per_day;
        const cutoff = if (now > duration) now - duration else 0;
        var statement = try self.db.prepare(
            "DELETE FROM login_throttles WHERE principal_hash IN (" ++
                "SELECT principal_hash FROM login_throttles " ++
                "WHERE updated_at < ?1 AND blocked_until <= ?2 " ++
                "ORDER BY updated_at,principal_hash LIMIT ?3);",
        );
        defer statement.deinit();
        try statement.bindInt64(1, cutoff);
        try statement.bindInt64(2, now);
        try statement.bindInt64(3, requested_limit);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    /// Called only after password verification has succeeded through the
    /// bounded Argon2 queue. It sets the five-minute dangerous-operation gate
    /// and immutably audits the reauthentication.
    pub fn markReauthenticated(
        self: Repository,
        token: auth.SecretToken,
        now: i64,
        audit: AuditEntry,
    ) !Session {
        try validateTimestamp(now);
        const token_hash = token.hash();
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var session = try self.loadSessionByTokenHash(token_hash);
        if (now >= session.idle_expires_at or now >= session.absolute_expires_at) {
            try self.deleteSessionById(session.id);
            try transaction.commit();
            return error.SessionExpired;
        }

        const idle_candidate = try checkedAddTimestamp(now, auth.idle_timeout_seconds);
        const idle_expires_at = @min(idle_candidate, session.absolute_expires_at);
        var update = try self.db.prepare(
            "UPDATE web_sessions SET reauthenticated_at = ?1, last_seen_at = ?1, " ++
                "idle_expires_at = ?2 WHERE id = ?3;",
        );
        defer update.deinit();
        try update.bindInt64(1, now);
        try update.bindInt64(2, idle_expires_at);
        try update.bindBlob(3, &session.id);
        if (try update.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.SessionNotFound;
        try self.insertAudit(audit);
        session.last_seen_at = now;
        session.idle_expires_at = idle_expires_at;
        session.reauthenticated_at = now;
        try transaction.commit();
        return session;
    }

    pub fn revokeOwnSession(
        self: Repository,
        owner_id: UserId,
        session_id: SessionId,
        audit: AuditEntry,
    ) !void {
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var remove = try self.db.prepare(
            "DELETE FROM web_sessions WHERE id = ?1 AND user_id = ?2;",
        );
        defer remove.deinit();
        try remove.bindBlob(1, &session_id);
        try remove.bindBlob(2, &owner_id);
        if (try remove.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.SessionNotFound;
        try self.insertAudit(audit);
        try transaction.commit();
    }

    /// Superuser-facing single-session revocation. Authorization is enforced
    /// by the application service before entering the serialized repository.
    pub fn revokeSession(self: Repository, session_id: SessionId, audit: AuditEntry) !void {
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        try self.deleteSessionById(session_id);
        try self.insertAudit(audit);
        try transaction.commit();
    }

    pub fn revokeAllSessionsForUser(
        self: Repository,
        user_id: UserId,
        audit: AuditEntry,
    ) !u64 {
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        _ = try self.loadUser(user_id);
        const removed = try self.deleteSessionsForUserCount(user_id, null);
        try self.insertAudit(audit);
        try transaction.commit();
        return removed;
    }

    pub fn revokeEverySession(self: Repository, audit: AuditEntry) !u64 {
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var remove = try self.db.prepare("DELETE FROM web_sessions;");
        defer remove.deinit();
        if (try remove.step() != .done) return error.UnexpectedRow;
        const removed = self.db.changes();
        try self.insertAudit(audit);
        try transaction.commit();
        return removed;
    }

    pub fn loadLoginThrottle(
        self: Repository,
        principal_hash: [32]u8,
    ) !security_policy.ThrottleState {
        return self.loadThrottle(principal_hash);
    }

    /// Persists each bounded throttle transition. Only the first transition
    /// into lockout creates one aggregate 90-day security event and immutable
    /// audit row; individual guesses are deliberately not audited.
    pub fn recordLoginFailure(
        self: Repository,
        principal_hash: [32]u8,
        now: i64,
        security_event_id: [16]u8,
        lockout_audit: AuditEntry,
    ) !ThrottleFailure {
        try validateTimestamp(now);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var state = try self.loadThrottle(principal_hash);
        const outcome = state.recordFailure(@intCast(now));
        try self.saveThrottle(principal_hash, state);

        var recorded = false;
        switch (outcome) {
            .failed => {},
            .locked => |locked| if (locked.record_security_event) {
                try self.insertLockoutEvent(security_event_id, state.failure_count, now);
                try self.insertAudit(lockout_audit);
                recorded = true;
            },
        }
        try transaction.commit();
        return .{ .state = state, .security_event_recorded = recorded };
    }

    /// Alternate success transition for a non-browser authentication. Browser
    /// login normally uses `createSession`, which performs this transition and
    /// its audit in the session-creation transaction.
    pub fn recordLoginSuccess(
        self: Repository,
        principal_hash: [32]u8,
        now: i64,
        audit: AuditEntry,
    ) !security_policy.ThrottleState {
        try validateTimestamp(now);
        var transaction = try self.db.begin(.immediate);
        errdefer transaction.rollback() catch {};
        var state = try self.loadThrottle(principal_hash);
        state.recordSuccess(@intCast(now));
        try self.saveThrottle(principal_hash, state);
        try self.insertAudit(audit);
        try transaction.commit();
        return state;
    }

    fn insertSessionRow(
        self: Repository,
        input: CreateSessionInput,
        token_hash: [32]u8,
        csrf_hash: [32]u8,
        idle_expires_at: i64,
        absolute_expires_at: i64,
    ) !void {
        var insert = try self.db.prepare(
            "INSERT INTO web_sessions " ++
                "(id, user_id, token_hash, csrf_token_hash, created_at, last_seen_at, " ++
                "idle_expires_at, absolute_expires_at, reauthenticated_at, user_agent) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6, ?7, NULL, ?8);",
        );
        defer insert.deinit();
        try insert.bindBlob(1, &input.id);
        try insert.bindBlob(2, &input.user_id);
        try insert.bindBlob(3, &token_hash);
        try insert.bindBlob(4, &csrf_hash);
        try insert.bindInt64(5, input.now);
        try insert.bindInt64(6, idle_expires_at);
        try insert.bindInt64(7, absolute_expires_at);
        try insert.bindText(8, input.user_agent);
        if (try insert.step() != .done) return error.UnexpectedRow;
    }

    fn insertUser(self: Repository, input: CreateUserInput, username: auth.Username) !User {
        var statement = try self.db.prepare(
            "INSERT INTO users " ++
                "(id, username, role, password_phc, enabled, password_change_required, " ++
                "revision, created_at, updated_at, password_changed_at) " ++
                "VALUES (?1, ?2, ?3, ?4, 1, ?5, 1, ?6, ?6, ?6);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &input.id);
        try statement.bindText(2, username.slice());
        try statement.bindText(3, roleText(input.role));
        try statement.bindText(4, input.password_phc);
        try statement.bindInt64(5, @intFromBool(input.password_change_required));
        try statement.bindInt64(6, input.now);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return .{
            .id = input.id,
            .username = username,
            .role = input.role,
            .enabled = true,
            .password_change_required = input.password_change_required,
            .revision = 1,
            .created_at = input.now,
            .updated_at = input.now,
            .password_changed_at = input.now,
        };
    }

    fn ensureUsernameAvailable(self: Repository, username: []const u8) !void {
        var statement = try self.db.prepare(
            "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1) OR " ++
                "EXISTS(SELECT 1 FROM user_tombstones WHERE username = ?1);",
        );
        defer statement.deinit();
        try statement.bindText(1, username);
        if (try statement.step() != .row) return error.UnexpectedDone;
        const reserved = statement.columnInt64(0) != 0;
        if (try statement.step() != .done) return error.UnexpectedRow;
        if (reserved) return error.UsernameReserved;
    }

    fn userCount(self: Repository) !u64 {
        return self.scalarCount("SELECT count(*) FROM users;");
    }

    fn activeSuperuserCount(self: Repository) !usize {
        const count = try self.scalarCount(
            "SELECT count(*) FROM users WHERE role = 'superuser' AND enabled = 1;",
        );
        if (count > std.math.maxInt(usize)) return error.CorruptAccessState;
        return @intCast(count);
    }

    fn scalarCount(self: Repository, sql_text: [:0]const u8) !u64 {
        var statement = try self.db.prepare(sql_text);
        defer statement.deinit();
        if (try statement.step() != .row) return error.UnexpectedDone;
        const value = statement.columnInt64(0);
        if (value < 0) return error.CorruptAccessState;
        if (try statement.step() != .done) return error.UnexpectedRow;
        return @intCast(value);
    }

    fn loadSessionByTokenHash(self: Repository, token_hash: [32]u8) !Session {
        var statement = try self.db.prepare(
            "SELECT web_sessions.id, web_sessions.user_id, users.username, users.role, " ++
                "users.password_change_required, web_sessions.csrf_token_hash, " ++
                "web_sessions.created_at, web_sessions.last_seen_at, " ++
                "web_sessions.idle_expires_at, web_sessions.absolute_expires_at, " ++
                "web_sessions.reauthenticated_at " ++
                "FROM web_sessions JOIN users ON users.id = web_sessions.user_id " ++
                "WHERE web_sessions.token_hash = ?1 AND users.enabled = 1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &token_hash);
        if (try statement.step() != .row) return error.SessionNotFound;
        const session = try decodeSession(&statement);
        if (try statement.step() != .done) return error.CorruptAccessState;
        return session;
    }

    fn requireSessionOwner(self: Repository, session_id: SessionId, user_id: UserId) !void {
        var statement = try self.db.prepare(
            "SELECT 1 FROM web_sessions WHERE id = ?1 AND user_id = ?2;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &session_id);
        try statement.bindBlob(2, &user_id);
        if (try statement.step() != .row) return error.SessionNotFound;
        if (try statement.step() != .done) return error.CorruptAccessState;
    }

    fn deleteSessionById(self: Repository, session_id: SessionId) !void {
        var statement = try self.db.prepare("DELETE FROM web_sessions WHERE id = ?1;");
        defer statement.deinit();
        try statement.bindBlob(1, &session_id);
        if (try statement.step() != .done) return error.UnexpectedRow;
        if (self.db.changes() != 1) return error.SessionNotFound;
    }

    fn deleteSessionsForUser(
        self: Repository,
        user_id: UserId,
        keep_session_id: ?SessionId,
    ) !void {
        _ = try self.deleteSessionsForUserCount(user_id, keep_session_id);
    }

    fn deleteSessionsForUserCount(
        self: Repository,
        user_id: UserId,
        keep_session_id: ?SessionId,
    ) !u64 {
        var statement = if (keep_session_id == null)
            try self.db.prepare("DELETE FROM web_sessions WHERE user_id = ?1;")
        else
            try self.db.prepare("DELETE FROM web_sessions WHERE user_id = ?1 AND id != ?2;");
        defer statement.deinit();
        try statement.bindBlob(1, &user_id);
        if (keep_session_id) |session_id| try statement.bindBlob(2, &session_id);
        if (try statement.step() != .done) return error.UnexpectedRow;
        return self.db.changes();
    }

    fn loadThrottle(
        self: Repository,
        principal_hash: [32]u8,
    ) !security_policy.ThrottleState {
        var statement = try self.db.prepare(
            "SELECT failure_count, window_started_at, blocked_until, updated_at " ++
                "FROM login_throttles WHERE principal_hash = ?1;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &principal_hash);
        if (try statement.step() == .done) return .{};
        const failure_count = try unsignedColumn(u16, &statement, 0);
        const window_started_at = try unsignedColumn(u64, &statement, 1);
        const blocked_until = try unsignedColumn(u64, &statement, 2);
        const updated_at = try unsignedColumn(u64, &statement, 3);
        if (try statement.step() != .done) return error.CorruptAccessState;
        return .{
            .failure_count = failure_count,
            .window_started_at = window_started_at,
            .blocked_until = blocked_until,
            .updated_at = updated_at,
        };
    }

    fn saveThrottle(
        self: Repository,
        principal_hash: [32]u8,
        state: security_policy.ThrottleState,
    ) !void {
        if (state.window_started_at > std.math.maxInt(i64) or
            state.blocked_until > std.math.maxInt(i64) or
            state.updated_at > std.math.maxInt(i64)) return error.TimestampOverflow;
        var statement = try self.db.prepare(
            "INSERT INTO login_throttles " ++
                "(principal_hash, failure_count, window_started_at, blocked_until, updated_at) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5) " ++
                "ON CONFLICT(principal_hash) DO UPDATE SET " ++
                "failure_count = excluded.failure_count, " ++
                "window_started_at = excluded.window_started_at, " ++
                "blocked_until = excluded.blocked_until, updated_at = excluded.updated_at;",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &principal_hash);
        try statement.bindInt64(2, state.failure_count);
        try statement.bindInt64(3, state.window_started_at);
        try statement.bindInt64(4, state.blocked_until);
        try statement.bindInt64(5, state.updated_at);
        if (try statement.step() != .done) return error.UnexpectedRow;
    }

    fn insertLockoutEvent(
        self: Repository,
        id: [16]u8,
        failure_count: u16,
        now: i64,
    ) !void {
        var details_buffer: [96]u8 = undefined;
        const details = try std.fmt.bufPrint(
            &details_buffer,
            "{{\"aggregated\":true,\"failureCount\":{d}}}",
            .{failure_count},
        );
        var statement = try self.db.prepare(
            "INSERT INTO runtime_events " ++
                "(id, kind, severity, node_id, observed_at, details_json) " ++
                "VALUES (?1, 'security.login_lockout', 'warning', NULL, ?2, ?3);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &id);
        try statement.bindInt64(2, now);
        try statement.bindText(3, details);
        if (try statement.step() != .done) return error.UnexpectedRow;
    }

    fn insertAudit(self: Repository, audit: AuditEntry) !void {
        if (audit.occurred_at < 0) return error.InvalidAuditEntry;
        if (audit.actor_kind == .web) self.db.armCommitHook();
        var statement = try self.db.prepare(
            "INSERT INTO audit_entries " ++
                "(id, occurred_at, actor_kind, actor_id, action, resource_type, " ++
                "resource_id, request_id, details_json) " ++
                "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9);",
        );
        defer statement.deinit();
        try statement.bindBlob(1, &audit.id);
        try statement.bindInt64(2, audit.occurred_at);
        try statement.bindText(3, actorKindText(audit.actor_kind));
        if (audit.actor_id) |actor_id| try statement.bindBlob(4, &actor_id) else try statement.bindNull(4);
        try statement.bindText(5, audit.action);
        try statement.bindText(6, audit.resource_type);
        try statement.bindText(7, audit.resource_id);
        if (audit.request_id) |request_id| try statement.bindBlob(8, &request_id) else try statement.bindNull(8);
        try statement.bindText(9, audit.details_json);
        if (try statement.step() != .done) return error.UnexpectedRow;
    }
};

/// Principal-based throttling uses a canonical, domain-separated digest and
/// therefore never stores a supplied username or address in throttle state.
pub fn principalHash(username_text: []const u8) ![32]u8 {
    const username = try auth.Username.parse(username_text);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("ntip-login-principal-v0.2\x00");
    hasher.update(username.slice());
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

/// Maps every canonical username that does not resolve to a stored principal
/// into a fixed durable set. The row key reveals neither the username nor its
/// selection digest, and the number of rows is bounded by policy regardless
/// of attacker-controlled username rotation.
pub fn unknownPrincipalThrottleHash(
    username_text: []const u8,
    selection_key: *const [32]u8,
) ![32]u8 {
    const username = try auth.Username.parse(username_text);
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var selector = HmacSha256.init(selection_key);
    selector.update("ntip-login-unknown-selector-v0.2\x00");
    selector.update(username.slice());
    var selection: [HmacSha256.mac_length]u8 = undefined;
    selector.final(&selection);
    defer std.crypto.secureZero(u8, &selection);
    const bucket: u8 = selection[0] % security_policy.unknown_login_throttle_buckets;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("ntip-login-unknown-bucket-v0.2\x00");
    hasher.update(&.{bucket});
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn decodeUser(statement: *const sqlite.Statement, first: c_int) !User {
    const id_blob = statement.columnBlob(first) orelse return error.CorruptAccessState;
    if (id_blob.len != 16) return error.CorruptAccessState;
    var id: UserId = undefined;
    @memcpy(&id, id_blob);
    const username_text = statement.columnText(first + 1) orelse return error.CorruptAccessState;
    const username = auth.Username.parse(username_text) catch return error.CorruptAccessState;
    const role = try parseRole(statement.columnText(first + 2) orelse return error.CorruptAccessState);
    const enabled = try boolColumn(statement, first + 3);
    const password_change_required = try boolColumn(statement, first + 4);
    const revision = try unsignedColumn(u64, statement, first + 5);
    const created_at = statement.columnInt64(first + 6);
    const updated_at = statement.columnInt64(first + 7);
    const password_changed_at = statement.columnInt64(first + 8);
    if (created_at < 0 or updated_at < created_at or password_changed_at < created_at) {
        return error.CorruptAccessState;
    }
    return .{
        .id = id,
        .username = username,
        .role = role,
        .enabled = enabled,
        .password_change_required = password_change_required,
        .revision = revision,
        .created_at = created_at,
        .updated_at = updated_at,
        .password_changed_at = password_changed_at,
    };
}

fn decodeSession(statement: *const sqlite.Statement) !Session {
    const id_blob = statement.columnBlob(0) orelse return error.CorruptAccessState;
    const user_id_blob = statement.columnBlob(1) orelse return error.CorruptAccessState;
    const csrf_blob = statement.columnBlob(5) orelse return error.CorruptAccessState;
    if (id_blob.len != 16 or user_id_blob.len != 16 or csrf_blob.len != 32) {
        return error.CorruptAccessState;
    }
    var id: SessionId = undefined;
    var user_id: UserId = undefined;
    var csrf_hash: [32]u8 = undefined;
    @memcpy(&id, id_blob);
    @memcpy(&user_id, user_id_blob);
    @memcpy(&csrf_hash, csrf_blob);
    const username_text = statement.columnText(2) orelse return error.CorruptAccessState;
    const username = auth.Username.parse(username_text) catch return error.CorruptAccessState;
    const role = try parseRole(statement.columnText(3) orelse return error.CorruptAccessState);
    const password_change_required = try boolColumn(statement, 4);
    const created_at = statement.columnInt64(6);
    const last_seen_at = statement.columnInt64(7);
    const idle_expires_at = statement.columnInt64(8);
    const absolute_expires_at = statement.columnInt64(9);
    const reauthenticated_at: ?i64 = if (statement.columnIsNull(10)) null else statement.columnInt64(10);
    if (created_at < 0 or last_seen_at < created_at or idle_expires_at <= last_seen_at or
        absolute_expires_at <= created_at or idle_expires_at > absolute_expires_at or
        (reauthenticated_at != null and reauthenticated_at.? < created_at))
    {
        return error.CorruptAccessState;
    }
    return .{
        .id = id,
        .user_id = user_id,
        .username = username,
        .role = role,
        .password_change_required = password_change_required,
        .csrf_token_hash = csrf_hash,
        .created_at = created_at,
        .last_seen_at = last_seen_at,
        .idle_expires_at = idle_expires_at,
        .absolute_expires_at = absolute_expires_at,
        .reauthenticated_at = reauthenticated_at,
    };
}

fn decodeSessionView(
    allocator: std.mem.Allocator,
    statement: *const sqlite.Statement,
    current_session_id: ?SessionId,
) !SessionView {
    const id_blob = statement.columnBlob(0) orelse return error.CorruptAccessState;
    const user_id_blob = statement.columnBlob(1) orelse return error.CorruptAccessState;
    if (id_blob.len != 16 or user_id_blob.len != 16) return error.CorruptAccessState;
    var id: SessionId = undefined;
    var user_id: UserId = undefined;
    @memcpy(&id, id_blob);
    @memcpy(&user_id, user_id_blob);
    const username_text = statement.columnText(2) orelse return error.CorruptAccessState;
    const username = auth.Username.parse(username_text) catch return error.CorruptAccessState;
    const user_agent_text = statement.columnText(3) orelse return error.CorruptAccessState;
    const created_at = statement.columnInt64(4);
    const last_seen_at = statement.columnInt64(5);
    const idle_expires_at = statement.columnInt64(6);
    const absolute_expires_at = statement.columnInt64(7);
    if (created_at < 0 or last_seen_at < created_at or idle_expires_at <= last_seen_at or
        absolute_expires_at <= created_at or idle_expires_at > absolute_expires_at)
    {
        return error.CorruptAccessState;
    }
    const generation = std.math.add(u64, @as(u64, @intCast(last_seen_at)), 1) catch
        return error.CorruptAccessState;
    const user_agent: ?[]u8 = if (user_agent_text.len == 0)
        null
    else
        try allocator.dupe(u8, user_agent_text);
    return .{
        .id = id,
        .user_id = user_id,
        .username = username,
        .current = if (current_session_id) |current| std.mem.eql(u8, &current, &id) else false,
        .user_agent = user_agent,
        .proxy_peer = null,
        .generation = generation,
        .created_at = created_at,
        .last_seen_at = last_seen_at,
        .idle_expires_at = idle_expires_at,
        .absolute_expires_at = absolute_expires_at,
    };
}

fn makeSession(
    input: CreateSessionInput,
    user: User,
    csrf_hash: [32]u8,
    idle_expires_at: i64,
    absolute_expires_at: i64,
) Session {
    return .{
        .id = input.id,
        .user_id = input.user_id,
        .username = user.username,
        .role = user.role,
        .password_change_required = user.password_change_required,
        .csrf_token_hash = csrf_hash,
        .created_at = input.now,
        .last_seen_at = input.now,
        .idle_expires_at = idle_expires_at,
        .absolute_expires_at = absolute_expires_at,
        .reauthenticated_at = null,
    };
}

fn pageLimit(requested: u16) !usize {
    if (requested == 0 or requested > maximum_page_size) return error.InvalidPageLimit;
    return requested;
}

fn bindPageCursor(
    statement: *sqlite.Statement,
    present: bool,
    timestamp: i64,
    before_id: [16]u8,
) !void {
    if (present and timestamp < 0) return error.InvalidCursor;
    try statement.bindInt64(1, @intFromBool(present));
    try statement.bindInt64(2, timestamp);
    try statement.bindBlob(3, &before_id);
}

fn deinitSessionViewList(
    items: *std.ArrayListUnmanaged(SessionView),
    allocator: std.mem.Allocator,
) void {
    for (items.items) |*item| item.deinit(allocator);
    items.deinit(allocator);
}

fn roleText(role: auth.Role) []const u8 {
    return switch (role) {
        .viewer => "viewer",
        .operator => "operator",
        .superuser => "superuser",
    };
}

fn parseRole(text: []const u8) !auth.Role {
    if (std.mem.eql(u8, text, "viewer")) return .viewer;
    if (std.mem.eql(u8, text, "operator")) return .operator;
    if (std.mem.eql(u8, text, "superuser")) return .superuser;
    return error.CorruptAccessState;
}

fn actorKindText(kind: ActorKind) []const u8 {
    return switch (kind) {
        .local_cli => "local_cli",
        .web => "web",
        .system => "system",
    };
}

fn boolColumn(statement: *const sqlite.Statement, index: c_int) !bool {
    return switch (statement.columnInt64(index)) {
        0 => false,
        1 => true,
        else => error.CorruptAccessState,
    };
}

fn unsignedColumn(comptime T: type, statement: *const sqlite.Statement, index: c_int) !T {
    const value = statement.columnInt64(index);
    if (value < 0 or value > std.math.maxInt(T)) return error.CorruptAccessState;
    return @intCast(value);
}

fn validateTimestamp(now: i64) !void {
    if (now < 0) return error.InvalidTimestamp;
}

fn validateMaintenanceLimit(limit: u16) !void {
    if (limit == 0 or limit > maximum_maintenance_batch) return error.InvalidMaintenanceLimit;
}

fn checkedAddTimestamp(now: i64, seconds: u64) !i64 {
    try validateTimestamp(now);
    if (seconds > std.math.maxInt(i64)) return error.TimestampOverflow;
    return std.math.add(i64, now, @intCast(seconds)) catch error.TimestampOverflow;
}

fn testDatabasePath(tmp: *const std.testing.TmpDir, buffer: []u8) ![:0]u8 {
    return std.fmt.bufPrintZ(buffer, ".zig-cache/tmp/{s}/ntip.sqlite3", .{&tmp.sub_path});
}

const test_phc = "$argon2id$v=19$m=65536,t=3,p=1$c2FsdA$dmVyaWZpZXI";

fn testAudit(byte: u8, action: []const u8, now: i64) AuditEntry {
    return .{
        .id = [_]u8{byte} ** 16,
        .occurred_at = now,
        .actor_kind = .system,
        .action = action,
        .resource_type = "access",
    };
}

fn testCreateUser(id_byte: u8, username: []const u8, role: auth.Role, now: i64) CreateUserInput {
    return .{
        .id = [_]u8{id_byte} ** 16,
        .username = username,
        .role = role,
        .password_phc = test_phc,
        .password_change_required = false,
        .now = now,
    };
}

fn testToken(byte: u8) auth.SecretToken {
    return .{ .bytes = [_]u8{byte} ** auth.session_token_len };
}

fn scalarInt(db: *sqlite.Database, sql_text: [:0]const u8) !i64 {
    var statement = try db.prepare(sql_text);
    defer statement.deinit();
    if (try statement.step() != .row) return error.UnexpectedDone;
    const value = statement.columnInt64(0);
    if (try statement.step() != .done) return error.UnexpectedRow;
    return value;
}

test "temporary-password flow and canonical username are durable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    _ = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "Root.Admin", .superuser, 100),
        testAudit(1, "user.bootstrap", 100),
    );
    var provision = testCreateUser(2, "Operator.One", .operator, 101);
    provision.password_change_required = true;
    const temporary = try repository.createUser(provision, testAudit(2, "user.create", 101));
    try std.testing.expectEqualStrings("operator.one", temporary.username.slice());
    try std.testing.expect(temporary.password_change_required);

    const changed = try repository.changePassword(
        temporary.id,
        null,
        "$argon2id$v=19$m=65536,t=3,p=1$bmV3c2FsdA$bmV3dmVyaWZpZXI",
        102,
        testAudit(3, "auth.change_password", 102),
    );
    try std.testing.expect(!changed.password_change_required);
    try std.testing.expectEqual(@as(u64, 2), changed.revision);
    const login = try repository.loadLoginPrincipal("OPERATOR.ONE");
    try std.testing.expectEqualStrings("operator.one", login.user.username.slice());
}

test "tombstones reserve usernames and the final superuser cannot be changed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    const root = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        testAudit(10, "user.bootstrap", 100),
    );
    try std.testing.expectError(error.FinalSuperuserRequired, repository.mutateUser(.{
        .user_id = root.id,
        .role = .viewer,
        .enabled = true,
        .now = 101,
    }, testAudit(11, "user.role", 101)));
    try std.testing.expectError(error.FinalSuperuserRequired, repository.mutateUser(.{
        .user_id = root.id,
        .role = .superuser,
        .enabled = false,
        .now = 101,
    }, testAudit(12, "user.disable", 101)));
    try std.testing.expectError(error.FinalSuperuserRequired, repository.mutateUser(.{
        .user_id = root.id,
        .role = .superuser,
        .enabled = false,
        .tombstone = true,
        .now = 101,
    }, testAudit(16, "user.tombstone", 101)));

    const user = try repository.createUser(
        testCreateUser(2, "retired", .viewer, 102),
        testAudit(13, "user.create", 102),
    );
    try std.testing.expect((try repository.mutateUser(.{
        .user_id = user.id,
        .role = .viewer,
        .enabled = false,
        .tombstone = true,
        .now = 103,
    }, testAudit(14, "user.tombstone", 103))) == null);
    try std.testing.expectError(error.UsernameReserved, repository.createUser(
        testCreateUser(3, "RETIRED", .viewer, 104),
        testAudit(15, "user.create", 104),
    ));
}

test "sessions persist only hashes, slide sparingly, reauthenticate, and expire" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    const user = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        testAudit(20, "user.bootstrap", 100),
    );
    const token = testToken(0x41);
    const csrf = testToken(0x42);
    const session = try repository.createSession(.{
        .id = [_]u8{3} ** 16,
        .user_id = user.id,
        .principal_hash = try principalHash("root"),
        .token = token,
        .csrf_token = csrf,
        .now = 200,
    }, testAudit(21, "auth.login", 200));
    try std.testing.expectEqualSlices(u8, &csrf.hash(), &session.csrf_token_hash);

    var hashes = try db.prepare("SELECT token_hash, csrf_token_hash FROM web_sessions;");
    defer hashes.deinit();
    try std.testing.expectEqual(sqlite.Step.row, try hashes.step());
    try std.testing.expectEqualSlices(u8, &token.hash(), hashes.columnBlob(0).?);
    try std.testing.expectEqualSlices(u8, &csrf.hash(), hashes.columnBlob(1).?);
    try std.testing.expect(!std.mem.eql(u8, &token.bytes, hashes.columnBlob(0).?));
    try std.testing.expect(!std.mem.eql(u8, &csrf.bytes, hashes.columnBlob(1).?));

    const not_touched = try repository.authenticateSession(token, 200 + session_touch_interval_seconds - 1);
    try std.testing.expectEqual(@as(i64, 200), not_touched.last_seen_at);
    const touched = try repository.authenticateSession(token, 200 + session_touch_interval_seconds);
    try std.testing.expectEqual(@as(i64, 260), touched.last_seen_at);
    const reauthenticated = try repository.markReauthenticated(
        token,
        261,
        testAudit(22, "auth.reauthenticate", 261),
    );
    try std.testing.expect(reauthenticated.recentlyReauthenticated(262));
    try std.testing.expectError(
        error.SessionExpired,
        repository.authenticateSession(token, session.absolute_expires_at),
    );
    try std.testing.expectEqual(@as(i64, 0), try scalarInt(&db, "SELECT count(*) FROM web_sessions;"));
}

test "password and user mutations revoke the required session set" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    _ = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        testAudit(30, "user.bootstrap", 100),
    );
    const user = try repository.createUser(
        testCreateUser(2, "operator", .operator, 101),
        testAudit(31, "user.create", 101),
    );
    const principal = try principalHash("operator");
    _ = try repository.createSession(.{
        .id = [_]u8{4} ** 16,
        .user_id = user.id,
        .principal_hash = principal,
        .token = testToken(4),
        .csrf_token = testToken(14),
        .now = 200,
    }, testAudit(32, "auth.login", 200));
    _ = try repository.createSession(.{
        .id = [_]u8{5} ** 16,
        .user_id = user.id,
        .principal_hash = principal,
        .token = testToken(5),
        .csrf_token = testToken(15),
        .now = 201,
    }, testAudit(33, "auth.login", 201));

    _ = try repository.changePassword(
        user.id,
        [_]u8{4} ** 16,
        test_phc,
        202,
        testAudit(34, "auth.change_password", 202),
    );
    _ = try repository.authenticateSession(testToken(4), 203);
    try std.testing.expectError(error.SessionNotFound, repository.authenticateSession(testToken(5), 203));

    _ = try repository.mutateUser(.{
        .user_id = user.id,
        .role = .viewer,
        .enabled = true,
        .now = 204,
    }, testAudit(35, "user.role", 204));
    try std.testing.expectError(error.SessionNotFound, repository.authenticateSession(testToken(4), 205));
}

test "own all-user and password-reset revocations are scoped and audited" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    const root = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        testAudit(50, "user.bootstrap", 100),
    );
    const viewer = try repository.createUser(
        testCreateUser(2, "viewer", .viewer, 101),
        testAudit(51, "user.create", 101),
    );
    const principal = try principalHash("viewer");
    _ = try repository.createSession(.{
        .id = [_]u8{6} ** 16,
        .user_id = viewer.id,
        .principal_hash = principal,
        .token = testToken(6),
        .csrf_token = testToken(16),
        .now = 200,
    }, testAudit(52, "auth.login", 200));
    _ = try repository.createSession(.{
        .id = [_]u8{7} ** 16,
        .user_id = viewer.id,
        .principal_hash = principal,
        .token = testToken(7),
        .csrf_token = testToken(17),
        .now = 201,
    }, testAudit(53, "auth.login", 201));

    try std.testing.expectError(
        error.SessionNotFound,
        repository.revokeOwnSession(root.id, [_]u8{6} ** 16, testAudit(54, "session.revoke", 202)),
    );
    _ = try repository.authenticateSession(testToken(6), 202);
    try repository.revokeOwnSession(viewer.id, [_]u8{6} ** 16, testAudit(55, "session.revoke", 202));
    try std.testing.expectError(error.SessionNotFound, repository.authenticateSession(testToken(6), 203));
    try std.testing.expectEqual(
        @as(u64, 1),
        try repository.revokeAllSessionsForUser(viewer.id, testAudit(56, "sessions.revoke_all", 203)),
    );

    _ = try repository.createSession(.{
        .id = [_]u8{8} ** 16,
        .user_id = viewer.id,
        .principal_hash = principal,
        .token = testToken(8),
        .csrf_token = testToken(18),
        .now = 204,
    }, testAudit(57, "auth.login", 204));
    const reset = try repository.resetPassword(.{
        .user_id = viewer.id,
        .password_phc = "$argon2id$v=19$m=65536,t=3,p=1$cmVzZXQ$dmVyaWZpZXI",
        .password_change_required = true,
        .now = 205,
    }, testAudit(58, "user.password_reset", 205));
    try std.testing.expect(reset.password_change_required);
    try std.testing.expectError(error.SessionNotFound, repository.authenticateSession(testToken(8), 206));
}

test "an audit failure rolls an access mutation back" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    const duplicate_audit = testAudit(60, "user.bootstrap", 100);
    _ = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        duplicate_audit,
    );
    try std.testing.expectError(error.InvalidAuditEntry, repository.createUser(
        testCreateUser(2, "rolled-back", .viewer, 101),
        duplicate_audit,
    ));
    try std.testing.expectError(error.UserNotFound, repository.loadUser([_]u8{2} ** 16));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(&db, "SELECT count(*) FROM audit_entries;"));
}

test "throttle transitions persist and aggregate only the first lockout" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const principal = try principalHash("missing-user");

    var attempt: u16 = 1;
    while (attempt <= security_policy.failures_before_lockout) : (attempt += 1) {
        const outcome = try repository.recordLoginFailure(
            principal,
            100 + attempt,
            [_]u8{@intCast(attempt)} ** 16,
            testAudit(40, "auth.lockout", 100 + attempt),
        );
        try std.testing.expectEqual(
            attempt == security_policy.failures_before_lockout,
            outcome.security_event_recorded,
        );
    }
    const after_lock = try repository.recordLoginFailure(
        principal,
        200,
        [_]u8{9} ** 16,
        testAudit(41, "auth.lockout", 200),
    );
    try std.testing.expect(!after_lock.security_event_recorded);
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &db,
        "SELECT count(*) FROM runtime_events WHERE kind = 'security.login_lockout';",
    ));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &db,
        "SELECT count(*) FROM audit_entries WHERE action = 'auth.lockout';",
    ));

    const reset = try repository.recordLoginSuccess(
        principal,
        300,
        testAudit(42, "auth.login", 300),
    );
    try std.testing.expectEqual(@as(u16, 0), reset.failure_count);
    try std.testing.expectEqual(@as(u64, 0), reset.blocked_until);
    try std.testing.expectEqual(@as(u16, 0), (try repository.loadLoginThrottle(principal)).failure_count);
}

test "user and session read models paginate stably and enforce owner scope" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const allocator = std.testing.allocator;

    const root = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        testAudit(70, "user.bootstrap", 100),
    );
    const first = try repository.createUser(
        testCreateUser(2, "first", .viewer, 101),
        testAudit(71, "user.create", 101),
    );
    const second = try repository.createUser(
        testCreateUser(3, "second", .operator, 101),
        testAudit(72, "user.create", 101),
    );

    var users_one = try repository.listUsers(allocator, null, 2);
    defer users_one.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), users_one.items.len);
    try std.testing.expectEqualSlices(u8, &second.id, &users_one.items[0].id);
    try std.testing.expectEqualSlices(u8, &first.id, &users_one.items[1].id);
    try std.testing.expect(users_one.next_cursor != null);
    var users_two = try repository.listUsers(allocator, users_one.next_cursor, 2);
    defer users_two.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), users_two.items.len);
    try std.testing.expectEqualSlices(u8, &root.id, &users_two.items[0].id);
    try std.testing.expect(users_two.next_cursor == null);
    try std.testing.expectError(error.InvalidPageLimit, repository.listUsers(allocator, null, 0));
    try std.testing.expectError(
        error.InvalidPageLimit,
        repository.listUsers(allocator, null, maximum_page_size + 1),
    );

    _ = try repository.createSession(.{
        .id = [_]u8{8} ** 16,
        .user_id = first.id,
        .principal_hash = try principalHash("first"),
        .token = testToken(80),
        .csrf_token = testToken(81),
        .user_agent = "ntip-test/one",
        .now = 200,
    }, testAudit(73, "auth.login", 200));
    _ = try repository.createSession(.{
        .id = [_]u8{9} ** 16,
        .user_id = first.id,
        .principal_hash = try principalHash("first"),
        .token = testToken(82),
        .csrf_token = testToken(83),
        .now = 201,
    }, testAudit(74, "auth.login", 201));
    _ = try repository.createSession(.{
        .id = [_]u8{10} ** 16,
        .user_id = second.id,
        .principal_hash = try principalHash("second"),
        .token = testToken(84),
        .csrf_token = testToken(85),
        .user_agent = "ntip-test/two",
        .now = 202,
    }, testAudit(75, "auth.login", 202));

    const current_id = [_]u8{9} ** 16;
    var own_one = try repository.listSessions(allocator, first.id, current_id, 203, null, 1);
    defer own_one.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), own_one.items.len);
    try std.testing.expect(own_one.items[0].current);
    try std.testing.expect(own_one.items[0].user_agent == null);
    try std.testing.expectEqual(@as(u64, 202), own_one.items[0].generation);
    try std.testing.expect(own_one.next_cursor != null);
    var own_two = try repository.listSessions(
        allocator,
        first.id,
        current_id,
        203,
        own_one.next_cursor,
        1,
    );
    defer own_two.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), own_two.items.len);
    try std.testing.expect(!own_two.items[0].current);
    try std.testing.expectEqualStrings("ntip-test/one", own_two.items[0].user_agent.?);
    try std.testing.expect(own_two.next_cursor == null);

    var all = try repository.listSessions(allocator, null, current_id, 203, null, 10);
    defer all.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), all.items.len);
    var loaded = try repository.loadSessionView(allocator, [_]u8{8} ** 16, current_id, 203);
    defer loaded.deinit(allocator);
    try std.testing.expectEqualStrings("first", loaded.username.slice());
    try std.testing.expectEqualStrings("ntip-test/one", loaded.user_agent.?);
    try std.testing.expect(!loaded.current);
}

test "expired sessions are hidden and bounded access maintenance removes stale rows" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);
    const allocator = std.testing.allocator;
    const user = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 0),
        testAudit(100, "user.bootstrap", 0),
    );

    _ = try repository.createSession(.{
        .id = [_]u8{1} ** 16,
        .user_id = user.id,
        .principal_hash = try principalHash("root"),
        .token = testToken(101),
        .csrf_token = testToken(102),
        .now = 0,
    }, testAudit(101, "auth.login", 0));
    _ = try repository.createSession(.{
        .id = [_]u8{2} ** 16,
        .user_id = user.id,
        .principal_hash = try principalHash("root"),
        .token = testToken(103),
        .csrf_token = testToken(104),
        .now = 1_000,
    }, testAudit(102, "auth.login", 1_000));

    var active = try repository.listSessions(allocator, user.id, null, 2_000, null, 10);
    defer active.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), active.items.len);
    try std.testing.expectEqualSlices(u8, &([_]u8{2} ** 16), &active.items[0].id);
    try std.testing.expectError(
        error.SessionNotFound,
        repository.loadSessionView(allocator, [_]u8{1} ** 16, null, 2_000),
    );
    try std.testing.expectError(
        error.InvalidMaintenanceLimit,
        repository.pruneExpiredSessions(2_000, 0),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.pruneExpiredSessions(2_000, 1));

    const maintenance_now = 91 * seconds_per_day;
    _ = try repository.recordLoginFailure(
        try principalHash("stale-principal"),
        1,
        [_]u8{3} ** 16,
        testAudit(103, "auth.lockout", 1),
    );
    _ = try repository.recordLoginFailure(
        try principalHash("recent-principal"),
        maintenance_now - 1,
        [_]u8{4} ** 16,
        testAudit(104, "auth.lockout", maintenance_now - 1),
    );
    try std.testing.expectEqual(@as(u64, 1), try repository.pruneStaleLoginThrottles(
        maintenance_now,
        1,
    ));
    // The successful root login above retains its current principal throttle
    // record, as does the deliberately recent principal. Only the stale row
    // is eligible for this bounded maintenance pass.
    try std.testing.expectEqual(@as(i64, 2), try scalarInt(&db, "SELECT count(*) FROM login_throttles;"));
}

test "successful login atomically rehashes with revision guard and rolls back on audit failure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var db = try sqlite.Database.openInitialized(try testDatabasePath(&tmp, &path_buffer));
    defer db.close();
    const repository = Repository.init(&db);

    const user = try repository.bootstrapFirstSuperuser(
        testCreateUser(1, "root", .superuser, 100),
        testAudit(90, "user.bootstrap", 100),
    );
    const principal = try principalHash("root");
    _ = try repository.recordLoginFailure(
        principal,
        150,
        [_]u8{91} ** 16,
        testAudit(91, "auth.lockout", 150),
    );
    const replacement = "$argon2id$v=19$m=65536,t=3,p=1$cmVoYXNo$bmV3dmVyaWZpZXI";
    const session = try repository.completeSuccessfulLogin(.{
        .session = .{
            .id = [_]u8{11} ** 16,
            .user_id = user.id,
            .principal_hash = principal,
            .token = testToken(90),
            .csrf_token = testToken(91),
            .user_agent = "rehash-test",
            .now = 200,
        },
        .expected_user_revision = user.revision,
        .replacement_password_phc = replacement,
    }, testAudit(92, "auth.login", 200));
    try std.testing.expectEqualSlices(u8, &user.id, &session.user_id);
    try std.testing.expectEqual(@as(u64, 0), (try repository.loadLoginThrottle(principal)).failure_count);
    const rehashed = try repository.loadLoginPrincipal("root");
    try std.testing.expectEqual(@as(u64, 2), rehashed.user.revision);
    try std.testing.expectEqualStrings(replacement, rehashed.password_hash.slice());
    try std.testing.expectEqual(@as(i64, 100), rehashed.user.password_changed_at);

    try std.testing.expectError(error.StaleUserRevision, repository.completeSuccessfulLogin(.{
        .session = .{
            .id = [_]u8{12} ** 16,
            .user_id = user.id,
            .principal_hash = principal,
            .token = testToken(92),
            .csrf_token = testToken(93),
            .now = 201,
        },
        .expected_user_revision = 1,
        .replacement_password_phc = test_phc,
    }, testAudit(93, "auth.login", 201)));
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &db,
        "SELECT count(*) FROM web_sessions WHERE user_id = x'01010101010101010101010101010101';",
    ));

    try std.testing.expectError(error.ConstraintViolation, repository.completeSuccessfulLogin(.{
        .session = .{
            .id = [_]u8{13} ** 16,
            .user_id = user.id,
            .principal_hash = principal,
            .token = testToken(94),
            .csrf_token = testToken(95),
            .now = 202,
        },
        .expected_user_revision = 2,
        .replacement_password_phc = test_phc,
    }, testAudit(92, "auth.login", 202)));
    const rolled_back = try repository.loadLoginPrincipal("root");
    try std.testing.expectEqual(@as(u64, 2), rolled_back.user.revision);
    try std.testing.expectEqualStrings(replacement, rolled_back.password_hash.slice());
    try std.testing.expectEqual(@as(i64, 1), try scalarInt(
        &db,
        "SELECT count(*) FROM web_sessions WHERE user_id = x'01010101010101010101010101010101';",
    ));
}
