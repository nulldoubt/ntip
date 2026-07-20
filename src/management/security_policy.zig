//! Fixed v0.2 browser-security policy.
//!
//! These values are deliberately not settings revisions. The application
//! worker persists throttle/session state, while this module supplies the
//! deterministic transition and authorization rules used by CLI and HTTP
//! operations.

const std = @import("std");
const auth = @import("auth.zig");

pub const argon2_parallel_verifications: u8 = 1;
pub const argon2_wait_queue_entries: u8 = 8;
/// Unknown principals are distributed across this fixed durable set. Known
/// principals retain independent throttles, so exhausting every anonymous
/// bucket cannot lock a valid account or grow SQLite without bound.
pub const unknown_login_throttle_buckets: u8 = 64;
pub const throttle_window_seconds: u64 = 15 * 60;
pub const failures_before_lockout: u16 = 5;
pub const initial_lockout_seconds: u64 = 30;
pub const maximum_lockout_seconds: u64 = 15 * 60;
pub const security_event_retention_days: u16 = 90;
pub const temporary_password_bytes: usize = 24;

pub const session_cookie_name = "__Host-ntip_session";
pub const session_cookie_attributes = "Secure; HttpOnly; SameSite=Strict; Path=/";

pub const ThrottleState = struct {
    failure_count: u16 = 0,
    window_started_at: u64 = 0,
    blocked_until: u64 = 0,
    updated_at: u64 = 0,

    pub fn isBlocked(self: ThrottleState, now: u64) bool {
        return now < self.blocked_until;
    }

    pub fn retryAfter(self: ThrottleState, now: u64) u64 {
        return if (self.isBlocked(now)) self.blocked_until - now else 0;
    }

    pub fn recordFailure(self: *ThrottleState, now: u64) FailureOutcome {
        if (self.window_started_at == 0 or now < self.window_started_at or
            now - self.window_started_at >= throttle_window_seconds)
        {
            self.failure_count = 0;
            self.window_started_at = now;
            self.blocked_until = 0;
        }
        self.failure_count +|= 1;
        self.updated_at = now;
        if (self.failure_count < failures_before_lockout) return .failed;

        const excess = @min(self.failure_count - failures_before_lockout, 15);
        const multiplier = @as(u64, 1) << @intCast(excess);
        const duration = @min(initial_lockout_seconds * multiplier, maximum_lockout_seconds);
        self.blocked_until = std.math.add(u64, now, duration) catch std.math.maxInt(u64);
        return .{ .locked = .{
            .retry_after_seconds = duration,
            .record_security_event = self.failure_count == failures_before_lockout,
        } };
    }

    pub fn recordSuccess(self: *ThrottleState, now: u64) void {
        self.* = .{ .updated_at = now };
    }
};

pub const FailureOutcome = union(enum) {
    failed,
    locked: struct {
        retry_after_seconds: u64,
        /// Failed attempts are aggregated; emit one transition event rather
        /// than an immutable audit row per guessed password.
        record_security_event: bool,
    },
};

pub const UserMutation = struct {
    target_is_active_superuser: bool,
    desired_role: auth.Role,
    desired_enabled: bool,
    tombstone: bool = false,
};

pub fn validateUserMutation(active_superusers: usize, mutation: UserMutation) !void {
    if (active_superusers == 0) return error.InvalidUserState;
    if (!mutation.target_is_active_superuser) return;
    const remains_active_superuser = !mutation.tombstone and mutation.desired_enabled and
        mutation.desired_role == .superuser;
    if (!remains_active_superuser and active_superusers == 1) return error.FinalSuperuserRequired;
}

pub fn validateExactOrigin(configured_origin: []const u8, supplied_origin: ?[]const u8) !void {
    const supplied = supplied_origin orelse return error.OriginRequired;
    if (!std.mem.eql(u8, configured_origin, supplied)) return error.OriginForbidden;
}

pub fn validateCsrf(expected_hash: [32]u8, supplied_token: ?[]const u8) !void {
    const token = auth.SecretToken.parse(supplied_token orelse return error.CsrfRequired) catch
        return error.CsrfFailed;
    if (!std.crypto.timing_safe.eql([32]u8, expected_hash, token.hash())) return error.CsrfFailed;
}

pub const DangerousPreconditions = struct {
    role: auth.Role,
    reauthenticated_at: ?u64,
    now: u64,
    supplied_etag: ?[]const u8,
    current_etag: []const u8,
    supplied_confirmation: ?[]const u8,
    required_confirmation: []const u8,
};

pub fn validateDangerous(preconditions: DangerousPreconditions) !void {
    if (preconditions.role != .superuser) return error.Forbidden;
    if (!auth.recentlyReauthenticated(preconditions.reauthenticated_at, preconditions.now)) {
        return error.ReauthenticationRequired;
    }
    const etag = preconditions.supplied_etag orelse return error.PreconditionRequired;
    if (!std.mem.eql(u8, etag, preconditions.current_etag)) return error.PreconditionFailed;
    const confirmation = preconditions.supplied_confirmation orelse return error.ConfirmationRequired;
    if (!std.mem.eql(u8, confirmation, preconditions.required_confirmation)) {
        return error.ConfirmationFailed;
    }
}

/// Generates a high-entropy, one-time-displayed temporary password. The
/// 64-character alphabet maps each random byte without modulo bias.
pub fn generateTemporaryPassword(io: std.Io) [temporary_password_bytes]u8 {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    comptime std.debug.assert(alphabet.len == 64);
    var random: [temporary_password_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &random);
    io.random(&random);
    var password: [temporary_password_bytes]u8 = undefined;
    for (random, 0..) |byte, index| password[index] = alphabet[byte & 0x3f];
    return password;
}

test "login throttling is bounded, exponential, and emits one transition event" {
    var state: ThrottleState = .{};
    var attempt: u16 = 1;
    while (attempt < failures_before_lockout) : (attempt += 1) {
        try std.testing.expect(state.recordFailure(attempt) == .failed);
    }
    const first = state.recordFailure(failures_before_lockout).locked;
    try std.testing.expectEqual(initial_lockout_seconds, first.retry_after_seconds);
    try std.testing.expect(first.record_security_event);
    try std.testing.expect(state.isBlocked(failures_before_lockout));

    const second = state.recordFailure(failures_before_lockout + 1).locked;
    try std.testing.expectEqual(initial_lockout_seconds * 2, second.retry_after_seconds);
    try std.testing.expect(!second.record_security_event);
    state.recordSuccess(1000);
    try std.testing.expectEqual(@as(u16, 0), state.failure_count);
}

test "the final active superuser is preserved" {
    try std.testing.expectError(error.FinalSuperuserRequired, validateUserMutation(1, .{
        .target_is_active_superuser = true,
        .desired_role = .viewer,
        .desired_enabled = true,
    }));
    try validateUserMutation(2, .{
        .target_is_active_superuser = true,
        .desired_role = .viewer,
        .desired_enabled = true,
    });
    try validateUserMutation(1, .{
        .target_is_active_superuser = false,
        .desired_role = .viewer,
        .desired_enabled = false,
    });
}

test "origin CSRF and dangerous-operation checks are exact" {
    try validateExactOrigin("https://ntip.example.test", "https://ntip.example.test");
    try std.testing.expectError(
        error.OriginForbidden,
        validateExactOrigin("https://ntip.example.test", "https://evil.example.test"),
    );

    const token = auth.SecretToken.generate(std.testing.io);
    var encoded: [auth.session_token_text_len]u8 = undefined;
    try validateCsrf(token.hash(), token.encode(&encoded));
    encoded[0] = if (encoded[0] == '0') '1' else '0';
    try std.testing.expectError(error.CsrfFailed, validateCsrf(token.hash(), &encoded));

    try validateDangerous(.{
        .role = .superuser,
        .reauthenticated_at = 100,
        .now = 101,
        .supplied_etag = "\"revision-7\"",
        .current_etag = "\"revision-7\"",
        .supplied_confirmation = "node01",
        .required_confirmation = "node01",
    });
    try std.testing.expectError(error.PreconditionFailed, validateDangerous(.{
        .role = .superuser,
        .reauthenticated_at = 100,
        .now = 101,
        .supplied_etag = "\"revision-6\"",
        .current_etag = "\"revision-7\"",
        .supplied_confirmation = "node01",
        .required_confirmation = "node01",
    }));
}

test "temporary passwords satisfy the password policy" {
    var password = generateTemporaryPassword(std.testing.io);
    defer std.crypto.secureZero(u8, &password);
    try auth.validatePassword(&password);
}
