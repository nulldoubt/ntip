//! Strict bootstrap configuration for the unprivileged management HTTP
//! service. Operational and security-policy settings intentionally do not
//! live here.

const std = @import("std");
const builtin = @import("builtin");

pub const schema_version: u16 = 2;
pub const maximum_config_bytes: usize = 16 * 1024;
pub const default_bind_address = "127.0.0.1";
pub const default_port: u16 = 8787;
pub const default_service_socket = "/run/ntip-api/ntsrv-api.sock";

pub const Config = struct {
    schema_version: u16,
    bind_address: []const u8 = default_bind_address,
    port: u16 = default_port,
    service_socket: []const u8 = default_service_socket,
    public_https_origin: []const u8,
    bootstrap_spki_pin: []const u8,
    bootstrap_manifest_path: []const u8,
    workers: u16 = 4,
    maximum_connections: u32 = 256,
};

pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Config) {
    if (bytes.len == 0 or bytes.len > maximum_config_bytes) return error.InvalidApiConfig;
    const parsed = std.json.parseFromSlice(Config, allocator, bytes, .{
        .duplicate_field_behavior = .@"error",
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    }) catch return error.InvalidApiConfigJson;
    errdefer parsed.deinit();
    try validate(parsed.value);
    return parsed;
}

pub fn validate(config: Config) !void {
    if (config.schema_version != schema_version) return error.UnsupportedApiConfigVersion;
    try validateLoopbackBind(config.bind_address);
    if (config.port == 0) return error.InvalidBindPort;
    try validateServiceSocket(config.service_socket);
    try validatePublicHttpsOrigin(config.public_https_origin);
    try validateSpkiPin(config.bootstrap_spki_pin);
    try validateManifestPath(config.bootstrap_manifest_path);
    if (config.workers == 0 or config.workers > 64) return error.InvalidWorkerCount;
    if (config.maximum_connections == 0 or config.maximum_connections > 65_535 or
        config.maximum_connections < config.workers)
    {
        return error.InvalidConnectionLimit;
    }
}

pub fn validateSpkiPin(pin: []const u8) !void {
    const prefix = "sha256//";
    if (!std.mem.startsWith(u8, pin, prefix)) return error.InvalidBootstrapSpkiPin;
    const encoded = pin[prefix.len..];
    if (encoded.len != std.base64.standard.Encoder.calcSize(32)) {
        return error.InvalidBootstrapSpkiPin;
    }
    const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch
        return error.InvalidBootstrapSpkiPin;
    if (decoded_size != 32) return error.InvalidBootstrapSpkiPin;
    var digest: [32]u8 = undefined;
    std.base64.standard.Decoder.decode(&digest, encoded) catch
        return error.InvalidBootstrapSpkiPin;
    var canonical: [std.base64.standard.Encoder.calcSize(32)]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&canonical, &digest);
    if (!std.mem.eql(u8, &canonical, encoded)) return error.InvalidBootstrapSpkiPin;
}

pub fn validateManifestPath(path: []const u8) !void {
    if (path.len < 2 or path.len > 4095 or path[0] != '/' or
        !std.mem.endsWith(u8, path, ".json"))
    {
        return error.InvalidBootstrapManifestPath;
    }
    for (path) |byte| {
        if (byte == 0 or byte == '\n' or byte == '\r' or byte < 0x20) {
            return error.InvalidBootstrapManifestPath;
        }
    }
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidBootstrapManifestPath;
        }
    }
}

/// Reads the configured manifest from the same no-follow handle whose owner
/// and mode are validated, closing the check/use race at the API boundary.
pub fn readManifestFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    maximum_bytes: usize,
) ![]u8 {
    try validateManifestPath(path);
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    const metadata = try file.stat(io);
    if (metadata.kind != .file or metadata.permissions.toMode() & 0o022 != 0) {
        return error.InsecureBootstrapManifest;
    }
    if (comptime builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const request: linux.STATX = .{ .UID = true };
        var statx = std.mem.zeroes(linux.Statx);
        switch (linux.errno(linux.statx(file.handle, "", linux.AT.EMPTY_PATH, request, &statx))) {
            .SUCCESS => {},
            else => return error.BootstrapManifestMetadataLookupFailed,
        }
        if (statx.uid != 0) return error.InsecureBootstrapManifest;
    }
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(maximum_bytes)) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |other| return other,
    };
}

/// Accepts canonical IPv4 addresses inside 127/8 and the IPv6 loopback
/// literal. Hostnames are deliberately rejected so DNS cannot widen the bind.
pub fn validateLoopbackBind(address: []const u8) !void {
    if (std.mem.eql(u8, address, "::1")) return;

    var octets: [4]u8 = undefined;
    var count: usize = 0;
    var parts = std.mem.splitScalar(u8, address, '.');
    while (parts.next()) |part| {
        if (count == octets.len or part.len == 0 or part.len > 3) return error.NonLoopbackBind;
        if (part.len > 1 and part[0] == '0') return error.NonLoopbackBind;
        for (part) |byte| if (!std.ascii.isDigit(byte)) return error.NonLoopbackBind;
        octets[count] = std.fmt.parseInt(u8, part, 10) catch return error.NonLoopbackBind;
        count += 1;
    }
    if (count != octets.len or octets[0] != 127) return error.NonLoopbackBind;
}

pub fn validatePublicHttpsOrigin(origin: []const u8) !void {
    const prefix = "https://";
    if (!std.mem.startsWith(u8, origin, prefix)) return error.InvalidPublicOrigin;
    const authority = origin[prefix.len..];
    if (authority.len == 0 or authority.len > 253) return error.InvalidPublicOrigin;
    if (std.mem.indexOfAny(u8, authority, "/?#@") != null) return error.InvalidPublicOrigin;
    for (authority) |byte| {
        if (byte < 0x21 or byte > 0x7e or std.ascii.isUpper(byte)) return error.InvalidPublicOrigin;
    }

    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidPublicOrigin;
        if (close == 1) return error.InvalidPublicOrigin;
        for (authority[1..close]) |byte| switch (byte) {
            '0'...'9', 'a'...'f', ':', '.' => {},
            else => return error.InvalidPublicOrigin,
        };
        if (close + 1 == authority.len) return;
        if (authority[close + 1] != ':') return error.InvalidPublicOrigin;
        try validateOriginPort(authority[close + 2 ..]);
        return;
    }

    const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host = if (colon) |index| authority[0..index] else authority;
    if (host.len == 0 or std.mem.indexOfScalar(u8, host, ':') != null) return error.InvalidPublicOrigin;
    for (host) |byte| switch (byte) {
        'a'...'z', '0'...'9', '.', '-' => {},
        else => return error.InvalidPublicOrigin,
    };
    var labels = std.mem.splitScalar(u8, host, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') {
            return error.InvalidPublicOrigin;
        }
    }
    if (colon) |index| try validateOriginPort(authority[index + 1 ..]);
}

fn validateOriginPort(value: []const u8) !void {
    if (value.len == 0 or value.len > 5) return error.InvalidPublicOrigin;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidPublicOrigin;
    const port = std.fmt.parseInt(u16, value, 10) catch return error.InvalidPublicOrigin;
    if (port == 0) return error.InvalidPublicOrigin;
}

fn validateServiceSocket(path: []const u8) !void {
    // Linux sockaddr_un.sun_path is 108 bytes including its terminating NUL.
    if (path.len < 2 or path.len > 107 or path[0] != '/' or !std.mem.endsWith(u8, path, ".sock")) {
        return error.InvalidServiceSocket;
    }
    for (path) |byte| if (byte == 0 or byte == '\n' or byte == '\r') return error.InvalidServiceSocket;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.InvalidServiceSocket;
        }
    }
}

test "API bootstrap config defaults are strict and loopback-only" {
    const bytes =
        \\{"schema_version":2,"public_https_origin":"https://ntip.example.test","bootstrap_spki_pin":"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","bootstrap_manifest_path":"/etc/ntip/bootstrap-assets.json"}
    ;
    const parsed = try decode(std.testing.allocator, bytes);
    defer parsed.deinit();
    try std.testing.expectEqualStrings(default_bind_address, parsed.value.bind_address);
    try std.testing.expectEqual(default_port, parsed.value.port);
    try std.testing.expectEqual(@as(u32, 256), parsed.value.maximum_connections);

    const unknown =
        \\{"schema_version":2,"public_https_origin":"https://ntip.example.test","bootstrap_spki_pin":"sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","bootstrap_manifest_path":"/etc/ntip/bootstrap-assets.json","unexpected":true}
    ;
    try std.testing.expectError(error.InvalidApiConfigJson, decode(std.testing.allocator, unknown));
}

test "bootstrap SPKI pin and manifest path are canonical" {
    try validateSpkiPin("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
    try std.testing.expectError(error.InvalidBootstrapSpkiPin, validateSpkiPin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="));
    try std.testing.expectError(error.InvalidBootstrapSpkiPin, validateSpkiPin("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
    try std.testing.expectError(error.InvalidBootstrapSpkiPin, validateSpkiPin("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));

    try validateManifestPath("/etc/ntip/bootstrap-assets.json");
    try std.testing.expectError(error.InvalidBootstrapManifestPath, validateManifestPath("etc/ntip/bootstrap-assets.json"));
    try std.testing.expectError(error.InvalidBootstrapManifestPath, validateManifestPath("/etc/../bootstrap-assets.json"));
    try std.testing.expectError(error.InvalidBootstrapManifestPath, validateManifestPath("/etc/ntip/bootstrap-assets.txt"));
}

test "loopback bind validation rejects hostnames and routable addresses" {
    try validateLoopbackBind("127.0.0.1");
    try validateLoopbackBind("127.24.0.9");
    try validateLoopbackBind("::1");
    try std.testing.expectError(error.NonLoopbackBind, validateLoopbackBind("localhost"));
    try std.testing.expectError(error.NonLoopbackBind, validateLoopbackBind("0.0.0.0"));
    try std.testing.expectError(error.NonLoopbackBind, validateLoopbackBind("192.0.2.10"));
    try std.testing.expectError(error.NonLoopbackBind, validateLoopbackBind("127.000.0.1"));
}

test "service socket path rejects ambiguous components" {
    try validateServiceSocket("/run/ntip-api/ntsrv-api.sock");
    try std.testing.expectError(error.InvalidServiceSocket, validateServiceSocket("/run//ntsrv-api.sock"));
    try std.testing.expectError(error.InvalidServiceSocket, validateServiceSocket("/run/./ntsrv-api.sock"));
    try std.testing.expectError(error.InvalidServiceSocket, validateServiceSocket("/run/../ntsrv-api.sock"));
}

test "public origin is an exact lowercase HTTPS origin without a path" {
    try validatePublicHttpsOrigin("https://ntip.example.test");
    try validatePublicHttpsOrigin("https://ntip.example.test:8443");
    try validatePublicHttpsOrigin("https://10.2.40.49:8443");
    try validatePublicHttpsOrigin("https://[::1]:8443");
    try std.testing.expectError(error.InvalidPublicOrigin, validatePublicHttpsOrigin("http://ntip.example.test"));
    try std.testing.expectError(error.InvalidPublicOrigin, validatePublicHttpsOrigin("https://NTIP.example.test"));
    try std.testing.expectError(error.InvalidPublicOrigin, validatePublicHttpsOrigin("https://ntip.example.test/"));
    try std.testing.expectError(error.InvalidPublicOrigin, validatePublicHttpsOrigin("https://user@ntip.example.test"));
    try std.testing.expectError(error.InvalidPublicOrigin, validatePublicHttpsOrigin("https://ntip..example.test"));
    try std.testing.expectError(error.InvalidPublicOrigin, validatePublicHttpsOrigin("https://ntip.-example.test"));
}
