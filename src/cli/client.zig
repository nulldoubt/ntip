const std = @import("std");
const common = @import("common.zig");

pub const CredentialSource = union(enum) {
    hidden_tty_prompt,
    positional: []const u8,
    file: []const u8,
    stdin,

    pub fn exposesProcessWarning(self: CredentialSource) bool {
        return self == .positional;
    }
};

pub const Config = struct {
    master_endpoint: []const u8,
    node: []const u8,
    credential: CredentialSource,
};

pub const Command = union(enum) {
    config: Config,
    up: struct { daemonize: bool },
    down,
    status: common.OutputFormat,
    version,

    pub fn isMutation(self: Command) bool {
        return self == .config;
    }

    pub fn connectsNetwork(self: Command) bool {
        return self == .up;
    }
};

pub const Parsed = struct {
    paths: common.Paths,
    command: Command,
};

pub fn parse(args: []const []const u8) !Parsed {
    var paths = common.Paths.client_defaults;
    var index: usize = 0;
    while (try common.consumeGlobal(args, &index, &paths)) {}
    if (index >= args.len) return error.MissingCommand;

    const primary = args[index];
    const rest = args[index + 1 ..];
    const command: Command = if (std.mem.eql(u8, primary, "config"))
        .{ .config = try parseConfig(rest) }
    else if (std.mem.eql(u8, primary, "up"))
        try parseUp(rest)
    else if (std.mem.eql(u8, primary, "down"))
        try exactNoArgs(rest, .down)
    else if (std.mem.eql(u8, primary, "status"))
        .{ .status = try common.parseOutputFlag(rest) }
    else if (std.mem.eql(u8, primary, "version"))
        try exactNoArgs(rest, .version)
    else
        return error.UnknownCommand;
    return .{ .paths = paths, .command = command };
}

fn parseConfig(args: []const []const u8) !Config {
    if (args.len < 2) return error.InvalidArguments;
    try common.validateEndpoint(args[0]);
    if (args[1].len == 0) return error.InvalidArguments;

    var source: CredentialSource = .hidden_tty_prompt;
    if (args.len == 3) {
        if (std.mem.eql(u8, args[2], "--credential-stdin")) {
            source = .stdin;
        } else if (std.mem.startsWith(u8, args[2], "--")) {
            return error.MissingOptionValue;
        } else {
            if (args[2].len == 0) return error.InvalidArguments;
            source = .{ .positional = args[2] };
        }
    } else if (args.len == 4 and std.mem.eql(u8, args[2], "--credential-file")) {
        if (args[3].len == 0) return error.InvalidArguments;
        source = .{ .file = args[3] };
    } else if (args.len != 2) {
        return error.InvalidArguments;
    }
    return .{ .master_endpoint = args[0], .node = args[1], .credential = source };
}

fn parseUp(args: []const []const u8) !Command {
    if (args.len == 0) return .{ .up = .{ .daemonize = false } };
    if (args.len == 1 and std.mem.eql(u8, args[0], "-d")) return .{ .up = .{ .daemonize = true } };
    return error.InvalidArguments;
}

fn exactNoArgs(args: []const []const u8, command: Command) !Command {
    if (args.len != 0) return error.InvalidArguments;
    return command;
}

test "client config supports every credential input mode without connecting" {
    const prompt_args = [_][]const u8{ "config", "master.example:49152", "node01" };
    const prompt = try parse(&prompt_args);
    try std.testing.expect(!prompt.command.connectsNetwork());
    try std.testing.expect(prompt.command.config.credential == .hidden_tty_prompt);

    const file_args = [_][]const u8{ "config", "[2001:db8::1]:49152", "node01", "--credential-file", "/secure/token" };
    const file = try parse(&file_args);
    try std.testing.expectEqualStrings("/secure/token", file.command.config.credential.file);

    const stdin_args = [_][]const u8{ "config", "203.0.113.10:49152", "node01", "--credential-stdin" };
    const stdin = try parse(&stdin_args);
    try std.testing.expect(stdin.command.config.credential == .stdin);
}

test "positional enrollment credential remains compatible but is warning-marked" {
    const args = [_][]const u8{ "config", "203.0.113.10:49152", "node01", "ntip-enroll-v1.example" };
    const parsed = try parse(&args);
    try std.testing.expect(parsed.command.config.credential.exposesProcessWarning());
}

test "credential sources are mutually exclusive" {
    const args = [_][]const u8{ "config", "203.0.113.10:49152", "node01", "--credential-stdin", "extra" };
    try std.testing.expectError(error.InvalidArguments, parse(&args));
}
