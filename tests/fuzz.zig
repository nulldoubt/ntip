const std = @import("std");
const ntip = @import("ntip");

const protocol = ntip.protocol;

const fuzz_corpus = [_][]const u8{
    "",
    "{}",
    "{\"schema_version\":1}",
    "ntip-enroll-v1.",
    "\x01\x11\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00",
};

test "coverage-guided boundary parsers and replay model" {
    try std.testing.fuzz({}, fuzzBoundaryParsers, .{ .corpus = &fuzz_corpus });
}

fn fuzzBoundaryParsers(_: void, smith: *std.testing.Smith) !void {
    var storage: [4096]u8 = undefined;
    const length = smith.slice(&storage);
    const input = storage[0..length];
    exercisePacketParsers(input);
    exerciseStateParsers(input);
    exerciseIpcParsers(input);
    try fuzzReplayModel({}, smith);
}

fn fuzzReplayModel(_: void, smith: *std.testing.Smith) !void {
    var window = protocol.replay.Window{};
    var seen = [_]bool{false} ** (@as(usize, std.math.maxInt(u16)) + 1);
    var initialized = false;
    var highest: u16 = 0;
    const operation_count = smith.valueRangeAtMost(u16, 1, 512);
    for (0..operation_count) |_| {
        const sequence = smith.value(u16);
        const expected: enum { accept, duplicate, too_old } = if (!initialized or sequence > highest)
            .accept
        else if (@as(u32, highest) - sequence >= protocol.replay.window_size)
            .too_old
        else if (seen[sequence])
            .duplicate
        else
            .accept;

        const result = window.commit(sequence);
        switch (expected) {
            .accept => {
                try result;
                seen[sequence] = true;
                if (!initialized or sequence > highest) highest = sequence;
                initialized = true;
            },
            .duplicate => try std.testing.expectError(error.Duplicate, result),
            .too_old => try std.testing.expectError(error.TooOld, result),
        }
    }
    try std.testing.expectEqual(initialized, window.initialized);
    if (initialized) try std.testing.expectEqual(@as(u64, highest), window.highest);
}

test "deterministic bounded corpus exercises every portable boundary parser" {
    var corpus: [768]u8 = undefined;
    var state: u64 = 0x6e74_6970_2d76_3031;
    for (&corpus) |*byte| byte.* = nextByte(&state);

    var length: usize = 0;
    while (length <= corpus.len) : (length += 1) {
        const input = corpus[0..length];
        exercisePacketParsers(input);
        exerciseStateParsers(input);
        exerciseIpcParsers(input);
    }
}

test "structured packet control configuration and credential mutations are fail-closed" {
    const key = [_]u8{0x91} ** protocol.transport.key_len;
    const packet = ipv4Packet(.{ 10, 1, 0, 2 }, .{ 10, 2, 0, 2 });
    var sealed_storage: [256]u8 = undefined;
    const sealed = try protocol.transport.seal(.{
        .packet_type = .data,
        .context = 0x1122_3344,
        .sequence = 17,
    }, &packet, key, &sealed_storage);
    for (0..sealed.len) |index| {
        var mutated: [256]u8 = undefined;
        @memcpy(mutated[0..sealed.len], sealed);
        mutated[index] ^= @as(u8, 1) << @as(u3, @intCast(index % 8));
        var replay = protocol.replay.Window{};
        var plaintext: [256]u8 = undefined;
        if (protocol.transport.open(mutated[0..sealed.len], key, &replay, &plaintext)) |_| {
            return error.MutatedTransportAccepted;
        } else |_| {}
        try std.testing.expect(!replay.initialized);
    }

    var frame_storage: [protocol.control.max_frame_len]u8 = undefined;
    const frame = try (protocol.control.Frame{
        .frame_type = .heartbeat,
        .request_id = 0x0102_0304,
        .generation = 0,
        .payload = &([_]u8{0x6a} ** 8),
    }).encode(&frame_storage);
    for (0..frame.len) |index| {
        var mutated: [protocol.control.max_frame_len]u8 = undefined;
        @memcpy(mutated[0..frame.len], frame);
        mutated[index] ^= 0x20;
        if (protocol.control.Frame.decode(mutated[0..frame.len])) |decoded| {
            var canonical_storage: [protocol.control.max_frame_len]u8 = undefined;
            const canonical = try decoded.encode(&canonical_storage);
            try std.testing.expectEqualSlices(u8, mutated[0..frame.len], canonical);
        } else |_| {}
    }

    const route = [_]protocol.configuration.Route{.{
        .network = .{ 10, 9, 0, 0 },
        .prefix_len = 24,
        .kind = .vnr,
    }};
    var snapshot_storage: [protocol.configuration.maximum_snapshot_len]u8 = undefined;
    const snapshot = try (protocol.configuration.Snapshot{
        .node_uuid = [_]u8{0x44} ** 16,
        .own_address = .{ 10, 9, 0, 2 },
        .own_vnr_network = .{ 10, 9, 0, 0 },
        .own_vnr_prefix_len = 24,
        .master_address = .{ 10, 9, 0, 1 },
        .inner_mtu = 1380,
        .heartbeat_seconds = 15,
        .suspect_seconds = 30,
        .offline_seconds = 45,
        .cold_seconds = 30,
        .hysteresis_seconds = 5,
        .hot_packets_per_second = 100_000,
        .hot_bits_per_second = 1_000_000_000,
        .saturated_queue_percent = 80,
        .routes = &route,
    }).encode(&snapshot_storage);
    const snapshot_hash = protocol.control.hashConfiguration(snapshot);
    for (0..snapshot.len) |index| {
        var mutated: [protocol.configuration.header_len + protocol.configuration.entry_len]u8 = undefined;
        @memcpy(&mutated, snapshot);
        mutated[index] ^= 0x01;
        try std.testing.expect(!std.mem.eql(u8, &snapshot_hash, &protocol.control.hashConfiguration(&mutated)));
        if (protocol.configuration.View.decode(&mutated)) |view| {
            var route_index: usize = 0;
            while (route_index < view.route_count) : (route_index += 1) _ = try view.route(route_index);
        } else |_| {}
    }

    const original = protocol.credential.Credential{
        .handle = [_]u8{0x15} ** protocol.credential.handle_len,
        .secret = [_]u8{0x26} ** protocol.credential.secret_len,
        .master_public = [_]u8{0x37} ** protocol.credential.master_public_len,
    };
    var credential_text: [protocol.credential.text_len]u8 = undefined;
    _ = original.encode(&credential_text);
    for (0..credential_text.len) |index| {
        var mutated = credential_text;
        mutated[index] ^= 0x01;
        if (protocol.credential.Credential.decode(&mutated)) |candidate_value| {
            var candidate = candidate_value;
            defer candidate.deinit();
            try std.testing.expect(!std.meta.eql(original, candidate));
        } else |_| {}
    }
}

test "replay mutations include reorder duplicate stale and forged-future cases" {
    var window = protocol.replay.Window{};
    try window.commit(2048);
    try window.commit(2046);
    try window.commit(2047);
    try std.testing.expectError(error.Duplicate, window.check(2046));
    try std.testing.expectError(error.TooOld, window.check(0));

    try window.check(1_000_000);
    try std.testing.expectEqual(@as(u64, 2048), window.highest);
    try window.commit(4095);
    try std.testing.expectError(error.Duplicate, window.check(2048));
    try window.commit(4096);
    try std.testing.expectError(error.TooOld, window.check(2048));
}

test "strict state JSON mutations preserve invariants or reject" {
    var store = ntip.domain.model.Store.init(std.testing.allocator);
    defer store.deinit();
    _ = try store.createVnr("vnr0", try ntip.domain.model.Cidr.parse("10.8.0.0/24"));
    try store.createNode(.{ .bytes = [_]u8{0x48} ** 16 }, "node01", "vnr0", try ntip.domain.model.Ipv4.parse("10.8.0.2"));
    const encoded = try ntip.state.json.encode(std.testing.allocator, &store);
    defer std.testing.allocator.free(encoded);

    const mutations = @min(encoded.len, 384);
    for (0..mutations) |index| {
        const mutated = try std.testing.allocator.dupe(u8, encoded);
        defer std.testing.allocator.free(mutated);
        mutated[index] ^= 0x01;
        if (ntip.state.json.decode(std.testing.allocator, mutated)) |decoded_value| {
            var decoded = decoded_value;
            defer decoded.deinit();
            try decoded.validate();
            const canonical = try ntip.state.json.encode(std.testing.allocator, &decoded);
            defer std.testing.allocator.free(canonical);
            var reparsed = try ntip.state.json.decode(std.testing.allocator, canonical);
            reparsed.deinit();
        } else |_| {}
    }

    const duplicate =
        \\{"schema_version":1,"schema_version":1,"generation":0,"vnrs":[],"nodes":[],"routes":[]}
    ;
    try std.testing.expectError(error.InvalidJson, ntip.state.json.decode(std.testing.allocator, duplicate));
    const newer =
        \\{"schema_version":99,"generation":0,"vnrs":[],"nodes":[],"routes":[]}
    ;
    try std.testing.expectError(error.UnsupportedSchemaVersion, ntip.state.json.decode(std.testing.allocator, newer));
}

test "binary secret mutations are rejected before secret exposure" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const secret_store: ntip.state.secret_store.FileSecretStore = .{ .dir = tmp.dir };
    const key = [_]u8{0x39} ** 32;
    try secret_store.write(std.testing.allocator, std.testing.io, "identity.key", .identity_key, &key);
    const encoded = try ntip.state.atomic_file.readAlloc(tmp.dir, std.testing.io, "identity.key", std.testing.allocator, 256);
    defer std.testing.allocator.free(encoded);
    const positions = [_]usize{ 0, 8, 9, 10, 12, 43, 75 };
    for (positions) |position| {
        try std.testing.expect(position < encoded.len);
        const mutated = try std.testing.allocator.dupe(u8, encoded);
        defer std.testing.allocator.free(mutated);
        mutated[position] ^= 0x01;
        try ntip.state.atomic_file.replace(tmp.dir, std.testing.io, "identity.key", mutated, ntip.state.atomic_file.private_file_permissions);
        if (secret_store.load(std.testing.allocator, std.testing.io, "identity.key", .identity_key)) |loaded| {
            defer std.testing.allocator.free(loaded);
            return error.MutatedSecretAccepted;
        } else |_| {}
    }
}

fn exercisePacketParsers(input: []const u8) void {
    _ = protocol.header.Header.decode(input) catch {};
    _ = protocol.handshake.Envelope.decode(input) catch {};
    _ = protocol.handshake.EnrollmentMessage0.decode(input) catch {};
    _ = protocol.handshake.EnrollmentMessage1.decode(input) catch {};
    _ = protocol.handshake.EnrollmentMessage2.decode(input) catch {};
    _ = protocol.handshake.SessionMessage0.decode(input) catch {};
    _ = protocol.handshake.SessionMessage1.decode(input) catch {};
    _ = protocol.handshake.SessionConfirm.decode(input) catch {};
    _ = protocol.control.Frame.decode(input) catch {};
    _ = protocol.control.ConfigurationBegin.decode(input) catch {};
    _ = protocol.control.ConfigurationChunk.decode(input) catch {};
    if (protocol.configuration.View.decode(input)) |view| {
        var index: usize = 0;
        while (index < view.route_count) : (index += 1) _ = view.route(index) catch {};
    } else |_| {}
    _ = protocol.credential.Credential.decode(input) catch {};
    _ = protocol.cookie.RetryPayload.decode(input) catch {};
    _ = protocol.ipv4.Packet.parse(input) catch {};
    var replay = protocol.replay.Window{};
    var plaintext: [768]u8 = undefined;
    _ = protocol.transport.open(input, [_]u8{0x5c} ** protocol.transport.key_len, &replay, &plaintext) catch {};
}

fn exerciseStateParsers(input: []const u8) void {
    exerciseServerState(input);
    exerciseClientState(input);
    exerciseServerConfig(input);
    exerciseClientConfig(input);
}

fn exerciseServerState(input: []const u8) void {
    var storage: [16 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    if (ntip.state.json.decode(fixed.allocator(), input)) |decoded_value| {
        var decoded = decoded_value;
        decoded.deinit();
    } else |_| {}
}

fn exerciseClientState(input: []const u8) void {
    var storage: [16 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    _ = ntip.state.client.decode(fixed.allocator(), input) catch {};
}

fn exerciseServerConfig(input: []const u8) void {
    var storage: [16 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    if (ntip.state.config.decodeServer(fixed.allocator(), input)) |parsed| {
        parsed.deinit();
    } else |_| {}
}

fn exerciseClientConfig(input: []const u8) void {
    var storage: [16 * 1024]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    if (ntip.state.config.decodeClient(fixed.allocator(), input)) |parsed| {
        parsed.deinit();
    } else |_| {}
}

fn exerciseIpcParsers(input: []const u8) void {
    if (input.len >= ntip.runtime.ipc.prefix_bytes) {
        const prefix = input[0..ntip.runtime.ipc.prefix_bytes].*;
        _ = ntip.runtime.ipc.decodeLength(&prefix) catch {};
    }

    var request_storage: [16 * 1024]u8 = undefined;
    var request_fixed = std.heap.FixedBufferAllocator.init(&request_storage);
    if (ntip.runtime.ipc.decodeRequest(request_fixed.allocator(), input)) |parsed| {
        parsed.deinit();
    } else |_| {}

    var response_storage: [16 * 1024]u8 = undefined;
    var response_fixed = std.heap.FixedBufferAllocator.init(&response_storage);
    if (ntip.runtime.ipc.decodeResponse(response_fixed.allocator(), input)) |parsed| {
        parsed.deinit();
    } else |_| {}
}

fn nextByte(state: *u64) u8 {
    state.* ^= state.* << 13;
    state.* ^= state.* >> 7;
    state.* ^= state.* << 17;
    return @truncate(state.*);
}

fn ipv4Packet(source: [4]u8, destination: [4]u8) [24]u8 {
    return .{
        0x45,           0x00,           0x00,           0x18,           0,         1,         0x40,      0,
        64,             17,             0,              0,              source[0], source[1], source[2], source[3],
        destination[0], destination[1], destination[2], destination[3], 1,         2,         3,         4,
    };
}
