const std = @import("std");

/// An IPv4 address stored in network-significant order. The most significant
/// byte is the first dotted-decimal octet.
pub const Ipv4 = struct {
    value: u32,

    pub const ParseError = error{
        InvalidIpv4,
        NonCanonicalIpv4,
    };

    pub fn parse(text: []const u8) ParseError!Ipv4 {
        var parsed_octets: [4]u8 = undefined;
        var octet_index: usize = 0;
        var start: usize = 0;

        while (start <= text.len) {
            if (octet_index == parsed_octets.len) return error.InvalidIpv4;
            const end = std.mem.indexOfScalarPos(u8, text, start, '.') orelse text.len;
            const part = text[start..end];
            if (part.len == 0 or part.len > 3) return error.InvalidIpv4;
            if (part.len > 1 and part[0] == '0') return error.NonCanonicalIpv4;

            var value: u16 = 0;
            for (part) |c| {
                if (c < '0' or c > '9') return error.InvalidIpv4;
                value = value * 10 + (c - '0');
                if (value > 255) return error.InvalidIpv4;
            }
            parsed_octets[octet_index] = @intCast(value);
            octet_index += 1;
            if (end == text.len) break;
            start = end + 1;
        }
        if (octet_index != 4) return error.InvalidIpv4;

        return .{ .value = (@as(u32, parsed_octets[0]) << 24) |
            (@as(u32, parsed_octets[1]) << 16) |
            (@as(u32, parsed_octets[2]) << 8) |
            parsed_octets[3] };
    }

    pub fn octets(self: Ipv4) [4]u8 {
        return .{
            @truncate(self.value >> 24),
            @truncate(self.value >> 16),
            @truncate(self.value >> 8),
            @truncate(self.value),
        };
    }

    pub fn write(self: Ipv4, buffer: []u8) error{NoSpaceLeft}![]const u8 {
        const parts = self.octets();
        return std.fmt.bufPrint(buffer, "{d}.{d}.{d}.{d}", .{ parts[0], parts[1], parts[2], parts[3] }) catch
            return error.NoSpaceLeft;
    }

    pub fn isPrivate(self: Ipv4) bool {
        return Cidr.fromAddress(.{ .value = 0x0a00_0000 }, 8).contains(self) or
            Cidr.fromAddress(.{ .value = 0xac10_0000 }, 12).contains(self) or
            Cidr.fromAddress(.{ .value = 0xc0a8_0000 }, 16).contains(self);
    }

    pub fn isLoopback(self: Ipv4) bool {
        return self.value >> 24 == 127;
    }

    pub fn isLinkLocal(self: Ipv4) bool {
        return self.value & 0xffff_0000 == 0xa9fe_0000;
    }

    pub fn isMulticast(self: Ipv4) bool {
        return self.value & 0xf000_0000 == 0xe000_0000;
    }

    pub fn isUnspecified(self: Ipv4) bool {
        return self.value == 0;
    }
};

pub const Cidr = struct {
    network: Ipv4,
    prefix: u8,

    pub const ParseError = Ipv4.ParseError || error{
        InvalidCidr,
        InvalidPrefix,
        NonCanonicalCidr,
    };

    pub fn parse(text: []const u8) ParseError!Cidr {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidCidr;
        if (slash == 0 or slash + 1 >= text.len) return error.InvalidCidr;
        if (std.mem.indexOfScalarPos(u8, text, slash + 1, '/') != null) return error.InvalidCidr;

        const address = try Ipv4.parse(text[0..slash]);
        const prefix_text = text[slash + 1 ..];
        if (prefix_text.len > 1 and prefix_text[0] == '0') return error.NonCanonicalCidr;
        var prefix_value: u16 = 0;
        for (prefix_text) |c| {
            if (c < '0' or c > '9') return error.InvalidPrefix;
            prefix_value = prefix_value * 10 + (c - '0');
            if (prefix_value > 32) return error.InvalidPrefix;
        }
        const prefix: u8 = @intCast(prefix_value);
        if (address.value & ~mask(prefix) != 0) return error.NonCanonicalCidr;
        return .{ .network = address, .prefix = prefix };
    }

    pub fn fromAddress(address: Ipv4, prefix: u8) Cidr {
        std.debug.assert(prefix <= 32);
        return .{ .network = .{ .value = address.value & mask(prefix) }, .prefix = prefix };
    }

    pub fn mask(prefix: u8) u32 {
        std.debug.assert(prefix <= 32);
        if (prefix == 0) return 0;
        return @as(u32, 0xffff_ffff) << @intCast(32 - prefix);
    }

    pub fn contains(self: Cidr, address: Ipv4) bool {
        return address.value & mask(self.prefix) == self.network.value;
    }

    pub fn containsCidr(self: Cidr, other: Cidr) bool {
        return self.prefix <= other.prefix and self.contains(other.network);
    }

    pub fn overlaps(self: Cidr, other: Cidr) bool {
        return self.contains(other.network) or other.contains(self.network);
    }

    pub fn isPrivateRange(self: Cidr) bool {
        return Cidr.fromAddress(.{ .value = 0x0a00_0000 }, 8).containsCidr(self) or
            Cidr.fromAddress(.{ .value = 0xac10_0000 }, 12).containsCidr(self) or
            Cidr.fromAddress(.{ .value = 0xc0a8_0000 }, 16).containsCidr(self);
    }

    pub fn broadcast(self: Cidr) Ipv4 {
        return .{ .value = self.network.value | ~mask(self.prefix) };
    }

    pub fn firstUsable(self: Cidr) ?Ipv4 {
        if (self.prefix >= 31) return null;
        return .{ .value = self.network.value + 1 };
    }

    pub fn isUsableHost(self: Cidr, address: Ipv4) bool {
        return self.prefix <= 30 and self.contains(address) and
            address.value != self.network.value and address.value != self.broadcast().value;
    }

    pub fn write(self: Cidr, buffer: []u8) error{NoSpaceLeft}![]const u8 {
        var ip_buffer: [15]u8 = undefined;
        const ip = try self.network.write(&ip_buffer);
        return std.fmt.bufPrint(buffer, "{s}/{d}", .{ ip, self.prefix }) catch return error.NoSpaceLeft;
    }

    pub fn validateVnr(self: Cidr) error{ InvalidVnrPrefix, InvalidVnrRange }!void {
        if (self.prefix < 1 or self.prefix > 30) return error.InvalidVnrPrefix;
        if (overlapsReserved(self)) return error.InvalidVnrRange;
    }

    pub fn validateRouted(self: Cidr) error{ InvalidRoutePrefix, InvalidRouteRange }!void {
        if (self.prefix == 0) return error.InvalidRoutePrefix;
        if (overlapsReserved(self)) return error.InvalidRouteRange;
    }
};

fn overlapsReserved(cidr: Cidr) bool {
    const reserved = [_]Cidr{
        Cidr.fromAddress(.{ .value = 0x0000_0000 }, 8), // "this" network and unspecified
        Cidr.fromAddress(.{ .value = 0x7f00_0000 }, 8), // loopback
        Cidr.fromAddress(.{ .value = 0xa9fe_0000 }, 16), // link-local
        Cidr.fromAddress(.{ .value = 0xe000_0000 }, 4), // multicast
        Cidr.fromAddress(.{ .value = 0xf000_0000 }, 4), // reserved/broadcast
    };
    for (reserved) |range| if (cidr.overlaps(range)) return true;
    return false;
}

test "IPv4 parser accepts only canonical dotted decimal" {
    try std.testing.expectEqual(@as(u32, 0x0a01_0203), (try Ipv4.parse("10.1.2.3")).value);
    try std.testing.expectError(error.NonCanonicalIpv4, Ipv4.parse("10.01.2.3"));
    try std.testing.expectError(error.InvalidIpv4, Ipv4.parse("10.1.2.256"));
    try std.testing.expectError(error.InvalidIpv4, Ipv4.parse("10.1.2"));
    try std.testing.expectError(error.InvalidIpv4, Ipv4.parse("10.1.2.3.4"));
}

test "CIDR parser enforces canonical networks" {
    const cidr = try Cidr.parse("10.1.0.0/24");
    try std.testing.expect(cidr.contains(try Ipv4.parse("10.1.0.42")));
    try std.testing.expect(!cidr.contains(try Ipv4.parse("10.1.1.1")));
    try std.testing.expectError(error.NonCanonicalCidr, Cidr.parse("10.1.0.1/24"));
    try std.testing.expectError(error.InvalidPrefix, Cidr.parse("10.1.0.0/33"));
}

test "CIDR overlap and host semantics" {
    const a = try Cidr.parse("10.1.0.0/24");
    const b = try Cidr.parse("10.1.0.128/25");
    const c = try Cidr.parse("10.1.1.0/24");
    try std.testing.expect(a.overlaps(b));
    try std.testing.expect(!a.overlaps(c));
    try std.testing.expect(a.isUsableHost(try Ipv4.parse("10.1.0.2")));
    try std.testing.expect(!a.isUsableHost(try Ipv4.parse("10.1.0.255")));
}

test "VNR and routed ranges reject overlap with reserved address space" {
    try std.testing.expectError(error.InvalidVnrRange, (try Cidr.parse("126.0.0.0/7")).validateVnr());
    try std.testing.expectError(error.InvalidRouteRange, (try Cidr.parse("192.0.0.0/2")).validateRouted());
    try (try Cidr.parse("8.8.8.0/24")).validateVnr();
}
