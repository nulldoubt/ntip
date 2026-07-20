const std = @import("std");
const ntip = @import("ntip");

const api_config = ntip.management.api_config;
const api_server = ntip.management.api_server;

const default_config_path = "/etc/ntip/api.json";
const openapi_json = @import("openapi_document").bytes;

const usage =
    \\NTIP management HTTP service
    \\usage: ntip-api [--config PATH]
    \\       ntip-api --version
    \\       ntip-api --help
    \\
;

pub fn main(init: std.process.Init) !void {
    const process_args = try init.minimal.args.toSlice(init.arena.allocator());
    const args = if (process_args.len > 0) process_args[1..] else process_args;
    var stdout_buffer: [4096]u8 = undefined;
    var stderr_buffer: [4096]u8 = undefined;
    var stdout_file = std.Io.File.Writer.init(.stdout(), init.io, &stdout_buffer);
    var stderr_file = std.Io.File.Writer.init(.stderr(), init.io, &stderr_buffer);
    const exit_code = run(
        // HTTP workers outlive startup and allocate concurrently. The process
        // arena is permanent storage, so using it here would retain every
        // non-LIFO request allocation until exit. Init's GPA is thread-safe
        // and honors the request/response deinitializers.
        init.gpa,
        init.io,
        args,
        &stdout_file.interface,
        &stderr_file.interface,
    ) catch |failure| {
        try stderr_file.interface.print("ntip-api: {s}\n", .{@errorName(failure)});
        try stderr_file.interface.flush();
        std.process.exit(1);
    };
    try stdout_file.interface.flush();
    try stderr_file.interface.flush();
    if (exit_code != 0) std.process.exit(exit_code);
}

fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) !u8 {
    if (args.len == 1 and (std.mem.eql(u8, args[0], "--help") or std.mem.eql(u8, args[0], "-h"))) {
        try stdout.writeAll(usage);
        return 0;
    }
    if (args.len == 1 and std.mem.eql(u8, args[0], "--version")) {
        try stdout.print("ntip-api {s}\n", .{ntip.version});
        return 0;
    }

    const config_path = if (args.len == 0)
        default_config_path
    else if (args.len == 2 and std.mem.eql(u8, args[0], "--config"))
        args[1]
    else {
        try stderr.writeAll("ntip-api: invalid arguments\n");
        try stderr.writeAll(usage);
        return 2;
    };

    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        config_path,
        allocator,
        .limited(api_config.maximum_config_bytes),
    );
    defer allocator.free(bytes);
    const parsed = try api_config.decode(allocator, bytes);
    defer parsed.deinit();

    const document = api_server.FixedDocument{ .bytes = openapi_json };
    try api_server.serve(
        allocator,
        io,
        parsed.value,
        api_server.OpenApiProvider.fromFixedDocument(&document),
    );
    return 0;
}

test "CLI rejects ambiguous startup arguments before reading config" {
    var stdout_buffer: [2048]u8 = undefined;
    var stderr_buffer: [2048]u8 = undefined;
    var stdout: std.Io.Writer = .fixed(&stdout_buffer);
    var stderr: std.Io.Writer = .fixed(&stderr_buffer);
    try std.testing.expectEqual(@as(u8, 2), try run(
        std.testing.allocator,
        std.testing.io,
        &.{ "--config", "one", "two" },
        &stdout,
        &stderr,
    ));
    try std.testing.expect(std.mem.indexOf(u8, stderr.buffered(), "invalid arguments") != null);
}
