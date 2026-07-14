const std = @import("std");

pub const challenge_len = 16;
pub const challenge_timeout: u64 = 10 * std.time.ns_per_s;

pub const Family = enum(u8) { ipv4 = 4, ipv6 = 6 };

pub const Endpoint = struct {
    family: Family,
    address: [16]u8,
    port: u16,

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        if (a.family != b.family or a.port != b.port) return false;
        return switch (a.family) {
            .ipv4 => std.mem.eql(u8, a.address[0..4], b.address[0..4]),
            .ipv6 => std.mem.eql(u8, &a.address, &b.address),
        };
    }

    pub fn cookieBinding(self: Endpoint) [19]u8 {
        var out: [19]u8 = undefined;
        out[0] = @intFromEnum(self.family);
        @memset(out[1..17], 0);
        switch (self.family) {
            .ipv4 => @memcpy(out[1..5], self.address[0..4]),
            .ipv6 => @memcpy(out[1..17], &self.address),
        }
        std.mem.writeInt(u16, out[17..19], self.port, .big);
        return out;
    }
};

pub const Candidate = struct {
    endpoint: Endpoint,
    challenge: [challenge_len]u8,
    expires_at: u64,
};

/// Endpoint changes are staged only after the caller has authenticated a
/// packet. They become current only after an encrypted path response echoes
/// the challenge from that same candidate endpoint.
pub const Validator = struct {
    current: ?Endpoint = null,
    candidate: ?Candidate = null,

    pub fn setInitial(self: *Validator, endpoint: Endpoint) void {
        self.current = endpoint;
        self.candidate = null;
    }

    pub fn observeAuthenticated(self: *Validator, endpoint: Endpoint, challenge: [challenge_len]u8, now: u64) bool {
        if (self.current) |current| {
            if (Endpoint.eql(current, endpoint)) return false;
        }
        if (self.candidate) |candidate| {
            if (now <= candidate.expires_at and Endpoint.eql(candidate.endpoint, endpoint)) return false;
        }
        self.candidate = .{
            .endpoint = endpoint,
            .challenge = challenge,
            .expires_at = now +| challenge_timeout,
        };
        return true;
    }

    pub fn acceptResponse(self: *Validator, endpoint: Endpoint, response: [challenge_len]u8, now: u64) bool {
        if (!self.responseValid(endpoint, response, now)) {
            if (self.candidate) |candidate| {
                if (now > candidate.expires_at) self.candidate = null;
            }
            return false;
        }
        self.current = self.candidate.?.endpoint;
        self.candidate = null;
        return true;
    }

    /// Validates without committing. The control plane uses this before a
    /// bounded data-worker endpoint update is known to have been accepted.
    pub fn responseValid(self: *const Validator, endpoint: Endpoint, response: [challenge_len]u8, now: u64) bool {
        const candidate = self.candidate orelse return false;
        if (now > candidate.expires_at) return false;
        if (!Endpoint.eql(candidate.endpoint, endpoint)) return false;
        if (!std.crypto.timing_safe.eql([challenge_len]u8, candidate.challenge, response)) return false;
        return true;
    }
};

fn v4(a: u8, b: u8, c: u8, d: u8, port: u16) Endpoint {
    return .{ .family = .ipv4, .address = .{ a, b, c, d } ++ ([_]u8{0} ** 12), .port = port };
}

test "endpoint changes require an authenticated challenge response" {
    const old = v4(203, 0, 113, 1, 5000);
    const new = v4(198, 51, 100, 2, 6000);
    var validator = Validator{};
    validator.setInitial(old);
    const challenge = [_]u8{7} ** challenge_len;
    try std.testing.expect(validator.observeAuthenticated(new, challenge, 0));
    try std.testing.expect(!validator.observeAuthenticated(new, [_]u8{8} ** challenge_len, 1));
    try std.testing.expect(!validator.acceptResponse(old, challenge, 1));
    var wrong = challenge;
    wrong[0] ^= 1;
    try std.testing.expect(!validator.acceptResponse(new, wrong, 1));
    try std.testing.expect(validator.responseValid(new, challenge, 1));
    try std.testing.expect(Endpoint.eql(old, validator.current.?));
    try std.testing.expect(validator.acceptResponse(new, challenge, 1));
    try std.testing.expect(Endpoint.eql(new, validator.current.?));
}
