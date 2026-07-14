const std = @import("std");
const ntip = @import("ntip");

const model = ntip.domain.model;
const protocol = ntip.protocol;
const runtime = ntip.runtime;

test "persisted topology drives configuration sync and encrypted forwarding" {
    var store = model.Store.init(std.testing.allocator);
    defer store.deinit();

    _ = try store.createVnr("edge", try model.Cidr.parse("10.1.0.0/24"));
    _ = try store.createVnr("compute", try model.Cidr.parse("10.2.0.0/24"));
    const edge_id: model.NodeId = .{ .bytes = [_]u8{0x11} ** 16 };
    const compute_id: model.NodeId = .{ .bytes = [_]u8{0x22} ** 16 };
    try store.createNode(edge_id, "edge01", "edge", try model.Ipv4.parse("10.1.0.2"));
    try store.createNode(compute_id, "compute01", "compute", try model.Ipv4.parse("10.2.0.2"));
    try store.addRoute(try model.Cidr.parse("192.168.178.0/24"), "edge01");

    // Cross a real persistence boundary before materializing hot-path policy.
    const state_bytes = try ntip.state.json.encode(std.testing.allocator, &store);
    defer std.testing.allocator.free(state_bytes);
    var recovered = try ntip.state.json.decode(std.testing.allocator, state_bytes);
    defer recovered.deinit();
    try std.testing.expectEqual(store.generation, recovered.generation);

    var master = try runtime.topology.buildMaster(std.testing.allocator, &recovered, &.{
        .{ .node_id = edge_id, .receiver_session_id = 501 },
        .{ .node_id = compute_id, .receiver_session_id = 502 },
    });
    defer master.deinit();
    const edge_owner = runtime.topology.ownerForNode(edge_id);
    const compute_owner = runtime.topology.ownerForNode(compute_id);
    try std.testing.expectEqual(@as(u64, 501), master.forwarding.lookup((try model.Ipv4.parse("192.168.178.20")).value).?.receiver_session_id);
    try std.testing.expectEqual(@as(u64, 502), master.forwarding.lookup((try model.Ipv4.parse("10.2.0.2")).value).?.receiver_session_id);
    try std.testing.expect(master.sources.permits(edge_owner, (try model.Ipv4.parse("10.1.0.2")).value));
    try std.testing.expect(!master.sources.permits(edge_owner, (try model.Ipv4.parse("10.2.0.2")).value));

    // Make the snapshot large enough to require multiple bounded control frames.
    var routes: [151]protocol.configuration.Route = undefined;
    routes[0] = .{ .network = .{ 10, 2, 0, 0 }, .prefix_len = 24, .kind = .vnr };
    for (routes[1..], 0..) |*route, index| {
        var address: [4]u8 = undefined;
        std.mem.writeInt(u32, &address, 0x6440_0000 + @as(u32, @intCast(index)), .big);
        route.* = .{ .network = address, .prefix_len = 32, .kind = .routed_prefix };
    }
    var snapshot_storage: [protocol.configuration.maximum_snapshot_len]u8 = undefined;
    const snapshot = try (protocol.configuration.Snapshot{
        .node_uuid = compute_id.bytes,
        .own_address = .{ 10, 2, 0, 2 },
        .own_vnr_network = .{ 10, 2, 0, 0 },
        .own_vnr_prefix_len = 24,
        .master_address = .{ 10, 2, 0, 1 },
        .inner_mtu = 1380,
        .heartbeat_seconds = 15,
        .suspect_seconds = 30,
        .offline_seconds = 45,
        .cold_seconds = 30,
        .hysteresis_seconds = 5,
        .hot_packets_per_second = 100_000,
        .hot_bits_per_second = 1_000_000_000,
        .saturated_queue_percent = 80,
        .routes = &routes,
    }).encode(&snapshot_storage);
    const sender = try runtime.config_sync.Sender.init(snapshot);
    try std.testing.expect(sender.chunk_count > 1);

    var receiver = runtime.config_sync.Receiver.init(std.testing.allocator);
    defer receiver.deinit();
    const begin_payload = sender.begin().encode();
    var frame_storage: [protocol.control.max_frame_len]u8 = undefined;
    const begin_frame = try (protocol.control.Frame{
        .frame_type = .configuration_begin,
        .request_id = 41,
        .generation = recovered.generation,
        .payload = &begin_payload,
    }).encode(&frame_storage);
    const decoded_begin_frame = try protocol.control.Frame.decode(begin_frame);
    try receiver.start(decoded_begin_frame.generation, try protocol.control.ConfigurationBegin.decode(decoded_begin_frame.payload));

    var reverse_index: usize = sender.chunk_count;
    while (reverse_index > 0) {
        reverse_index -= 1;
        var chunk_storage: [protocol.control.max_payload_len]u8 = undefined;
        const chunk_payload = try (try sender.chunk(@intCast(reverse_index))).encode(&chunk_storage);
        const encoded_frame = try (protocol.control.Frame{
            .frame_type = .configuration_chunk,
            .request_id = @intCast(42 + reverse_index),
            .generation = recovered.generation,
            .payload = chunk_payload,
        }).encode(&frame_storage);
        const decoded_frame = try protocol.control.Frame.decode(encoded_frame);
        const decoded_chunk = try protocol.control.ConfigurationChunk.decode(decoded_frame.payload);
        try std.testing.expect(try receiver.accept(decoded_chunk));
        try std.testing.expect(!(try receiver.accept(decoded_chunk)));
    }
    const installed = try receiver.finish();
    try std.testing.expectEqual(compute_id.bytes, installed.node_uuid);
    try std.testing.expectEqual(@as(u16, routes.len), installed.route_count);

    // DATA crosses the encrypted association, replay window, IPv4 parser,
    // anti-spoof policy, and longest-prefix forwarding decision.
    const inner = ipv4Packet(.{ 10, 1, 0, 2 }, .{ 10, 2, 0, 2 });
    const key = [_]u8{0x5a} ** protocol.transport.key_len;
    var node_tx = protocol.transport.SendState{ .receiver_session_id = 9001, .key = key };
    var datagram_storage: [1600]u8 = undefined;
    const datagram = try node_tx.seal(.data, &inner, &datagram_storage);
    var master_rx = protocol.transport.ReceiveState{ .key = key };
    var plaintext: [1600]u8 = undefined;
    const opened = try master_rx.open(datagram, &plaintext);
    const packet = try protocol.ipv4.Packet.parse(opened.plaintext);
    const source = std.mem.readInt(u32, &packet.source, .big);
    const destination = std.mem.readInt(u32, &packet.destination, .big);
    try std.testing.expect(master.sources.permits(edge_owner, source));
    try std.testing.expect(!master.sources.permits(compute_owner, source));
    try std.testing.expectEqual(@as(u64, 502), master.forwarding.lookup(destination).?.receiver_session_id);
    try std.testing.expectError(error.Duplicate, master_rx.open(datagram, &plaintext));

    // A forged far-future clear sequence cannot advance a fresh replay window.
    var forged_storage: [1600]u8 = undefined;
    @memcpy(forged_storage[0..datagram.len], datagram);
    const forged_header = try (protocol.header.Header{
        .packet_type = .data,
        .context = 9001,
        .sequence = 1_000_000,
    }).encode();
    @memcpy(forged_storage[0..protocol.header.encoded_len], &forged_header);
    var fresh_rx = protocol.transport.ReceiveState{ .key = key };
    try std.testing.expectError(error.AuthenticationFailed, fresh_rx.open(forged_storage[0..datagram.len], &plaintext));
    try std.testing.expect(!fresh_rx.replay_window.initialized);
}

test "enrollment material becomes durable identity without persisting bearer secrets" {
    var credential = protocol.credential.Credential{
        .handle = [_]u8{0x31} ** protocol.credential.handle_len,
        .secret = [_]u8{0x42} ** protocol.credential.secret_len,
        .master_public = [_]u8{0x53} ** protocol.credential.master_public_len,
    };
    defer credential.deinit();
    var credential_text: [protocol.credential.text_len]u8 = undefined;
    const encoded_credential = credential.encode(&credential_text);
    var parsed_credential = try protocol.credential.Credential.decode(encoded_credential);
    defer parsed_credential.deinit();
    try std.testing.expectEqualSlices(u8, &credential.derivePsk(), &parsed_credential.derivePsk());

    const node_id: model.NodeId = .{ .bytes = [_]u8{0x64} ** 16 };
    const pending: ntip.state.client.PersistentState = .{
        .generation = 7,
        .enrollment_state = .unenrolled,
        .node_id = node_id,
        .assigned_address = try model.Ipv4.parse("10.9.0.2"),
        .vnr_range = try model.Cidr.parse("10.9.0.0/24"),
    };
    const pending_json = try ntip.state.client.encode(std.testing.allocator, pending);
    defer std.testing.allocator.free(pending_json);
    const recovered_pending = try ntip.state.client.decode(std.testing.allocator, pending_json);
    try std.testing.expectEqual(model.EnrollmentState.unenrolled, recovered_pending.enrollment_state);

    var control_storage: [protocol.control.max_frame_len]u8 = undefined;
    const completion_frame = try (protocol.control.Frame{
        .frame_type = .enrollment_complete,
        .request_id = 77,
        .generation = 0,
        .payload = &node_id.bytes,
    }).encode(&control_storage);
    var wire_storage: [protocol.control.max_frame_len + protocol.transport.overhead]u8 = undefined;
    const psk = parsed_credential.derivePsk();
    var sender = protocol.transport.SendState{ .receiver_session_id = 701, .key = psk };
    const encrypted = try sender.seal(.control, completion_frame, &wire_storage);
    var receiver = protocol.transport.ReceiveState{ .key = psk };
    var opened_storage: [protocol.control.max_frame_len]u8 = undefined;
    const opened = try receiver.open(encrypted, &opened_storage);
    const completion = try protocol.control.Frame.decode(opened.plaintext);
    try std.testing.expectEqual(protocol.control.Type.enrollment_complete, completion.frame_type);
    try std.testing.expectEqualSlices(u8, &node_id.bytes, completion.payload);

    var enrolled = recovered_pending;
    enrolled.generation += 1;
    enrolled.enrollment_state = .enrolled;
    const enrolled_json = try ntip.state.client.encode(std.testing.allocator, enrolled);
    defer std.testing.allocator.free(enrolled_json);
    _ = try ntip.state.client.decode(std.testing.allocator, enrolled_json);
    try std.testing.expect(std.mem.indexOf(u8, enrolled_json, protocol.credential.prefix) == null);
    try std.testing.expect(std.mem.indexOf(u8, enrolled_json, "secret") == null);
}

test "versioned IPC and client configuration reject identity ambiguity" {
    const request_bytes =
        \\{"version":1,"request_id":19,"command":"node.list","arguments":{}}
    ;
    const request = try runtime.ipc.decodeRequest(std.testing.allocator, request_bytes);
    defer request.deinit();
    try std.testing.expectEqual(@as(u64, 19), request.value.request_id);

    const response_bytes =
        \\{"version":1,"request_id":19,"ok":false,"exit_code":4,"result":null,"error":{"code":"daemon_unavailable","message":"not running"}}
    ;
    const response = try runtime.ipc.decodeResponse(std.testing.allocator, response_bytes);
    defer response.deinit();
    try std.testing.expectEqual(request.value.request_id, response.value.request_id);
    try std.testing.expectEqual(@as(u8, 4), response.value.exit_code);

    const config = try ntip.state.config.encodeClient(
        std.testing.allocator,
        "[2001:db8::1]:49152",
        "compute01",
        [_]u8{0x7b} ** 32,
    );
    defer std.testing.allocator.free(config);
    const decoded = try ntip.state.config.decodeClient(std.testing.allocator, config);
    defer decoded.deinit();
    try std.testing.expectEqualStrings("[2001:db8::1]:49152", decoded.value.master);
    try std.testing.expectEqualStrings("7b" ** 32, decoded.value.master_public_key);

    const ambiguous =
        \\{"schema_version":1,"master":"master.example:49152","node":"compute01","master_public_key":"0000000000000000000000000000000000000000000000000000000000000000"}
    ;
    try std.testing.expectError(error.InvalidConfig, ntip.state.config.decodeClient(std.testing.allocator, ambiguous));
}

fn ipv4Packet(source: [4]u8, destination: [4]u8) [24]u8 {
    return .{
        0x45,           0x00,           0x00,           0x18,           0,         1,         0x40,      0,
        64,             17,             0,              0,              source[0], source[1], source[2], source[3],
        destination[0], destination[1], destination[2], destination[3], 1,         2,         3,         4,
    };
}
