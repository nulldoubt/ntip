const std = @import("std");
const secrets = @import("secret_store.zig");
const noise = @import("../protocol/noise.zig");

pub const file_name = "identity.key";

pub fn loadOrCreate(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
) !noise.KeyPair {
    const store: secrets.FileSecretStore = .{ .dir = dir };
    const loaded = store.load(allocator, io, file_name, .identity_key) catch |err| switch (err) {
        error.FileNotFound => return generateAndStore(allocator, io, store),
        else => return err,
    };
    defer {
        std.crypto.secureZero(u8, loaded);
        allocator.free(loaded);
    }
    if (loaded.len != 32) return error.InvalidSecretLength;
    return noise.KeyPair.fromSecret(loaded[0..32].*);
}

fn generateAndStore(
    allocator: std.mem.Allocator,
    io: std.Io,
    store: secrets.FileSecretStore,
) !noise.KeyPair {
    while (true) {
        var secret: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &secret);
        io.random(&secret);
        const pair = noise.KeyPair.fromSecret(secret) catch continue;
        try store.write(allocator, io, file_name, .identity_key, &secret);
        return pair;
    }
}

test "identity generation persists the same public key" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var first = try loadOrCreate(std.testing.allocator, std.testing.io, tmp.dir);
    defer std.crypto.secureZero(u8, &first.secret);
    var second = try loadOrCreate(std.testing.allocator, std.testing.io, tmp.dir);
    defer std.crypto.secureZero(u8, &second.secret);
    try std.testing.expectEqualSlices(u8, &first.public, &second.public);
}
