const std = @import("std");
const model = @import("../domain/model.zig");
const state_json = @import("json.zig");
const atomic = @import("atomic_file.zig");
const server_transaction = @import("server_transaction.zig");

pub const Repository = struct {
    dir: std.Io.Dir,
    state_file: []const u8 = "state.json",
    lock_file: []const u8 = "state.lock",

    pub fn load(self: Repository, allocator: std.mem.Allocator, io: std.Io) !model.Store {
        const stat = try self.dir.statFile(io, self.state_file, .{ .follow_symlinks = false });
        if (stat.kind != .file) return error.InvalidStateFileType;
        if (stat.permissions.toMode() & 0o077 != 0) return error.InsecurePermissions;
        const bytes = try atomic.readAlloc(self.dir, io, self.state_file, allocator, state_json.max_state_bytes);
        defer allocator.free(bytes);
        return state_json.decode(allocator, bytes);
    }

    pub fn loadOrEmpty(self: Repository, allocator: std.mem.Allocator, io: std.Io) !model.Store {
        return self.load(allocator, io) catch |err| switch (err) {
            error.FileNotFound => model.Store.init(allocator),
            else => return err,
        };
    }

    pub fn save(self: Repository, allocator: std.mem.Allocator, io: std.Io, store: *const model.Store) !void {
        try store.validate();
        const bytes = try state_json.encode(allocator, store);
        defer allocator.free(bytes);
        try atomic.replace(self.dir, io, self.state_file, bytes, atomic.private_file_permissions);
    }

    pub fn begin(self: *const Repository, allocator: std.mem.Allocator, io: std.Io, nonblocking: bool) !Transaction {
        var lock = try atomic.LifetimeLock.acquire(self.dir, io, self.lock_file, nonblocking);
        errdefer lock.release(io);
        _ = try server_transaction.recover(allocator, io, self.dir);
        const store = try self.loadOrEmpty(allocator, io);
        return .{
            .repository = self,
            .allocator = allocator,
            .io = io,
            .lock = lock,
            .store = store,
        };
    }
};

/// Offline administrative commands hold this transaction for the complete
/// read-modify-durable-write sequence, preventing lost updates.
pub const Transaction = struct {
    repository: *const Repository,
    allocator: std.mem.Allocator,
    io: std.Io,
    lock: atomic.LifetimeLock,
    store: model.Store,
    committed: bool = false,

    pub fn commit(self: *Transaction) !void {
        try self.repository.save(self.allocator, self.io, &self.store);
        self.committed = true;
    }

    pub fn deinit(self: *Transaction) void {
        self.store.deinit();
        self.lock.release(self.io);
        self.* = undefined;
    }
};

test "repository transactions are durable" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const repository: Repository = .{ .dir = tmp.dir };

    {
        var transaction = try repository.begin(std.testing.allocator, io, true);
        defer transaction.deinit();
        _ = try transaction.store.createVnr("vnr0", try model.Cidr.parse("10.1.0.0/24"));
        try transaction.commit();
    }

    var loaded = try repository.load(std.testing.allocator, io);
    defer loaded.deinit();
    try std.testing.expect(loaded.findVnr("vnr0") != null);
}

test "corrupt repository state is never replaced with an empty store" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try atomic.replace(tmp.dir, io, "state.json", "not json", atomic.private_file_permissions);
    const repository: Repository = .{ .dir = tmp.dir };
    try std.testing.expectError(error.InvalidJson, repository.loadOrEmpty(std.testing.allocator, io));
}
