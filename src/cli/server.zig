const std = @import("std");
const common = @import("common.zig");

pub const Parsed = struct {
    paths: common.Paths,
    command: Command,
};

pub const Command = union(enum) {
    up: struct { daemonize: bool },
    down,
    status: common.OutputFormat,
    vnr_create: struct { name: []const u8, cidr: []const u8 },
    vnr_delete: []const u8,
    vnr_list: common.OutputFormat,
    vnr_show: struct { name: []const u8, output: common.OutputFormat },
    node_create: NodeCreate,
    node_delete: []const u8,
    node_list: common.OutputFormat,
    node_show: struct { name: []const u8, output: common.OutputFormat },
    node_enrollment_renew: EnrollmentBootstrap,
    node_enrollment_reset: EnrollmentBootstrap,
    route_add: struct { cidr: []const u8, node: []const u8 },
    route_delete: []const u8,
    route_list: common.OutputFormat,
    route_show: struct { cidr: []const u8, output: common.OutputFormat },
    user_bootstrap: struct { username: []const u8, password_stdin: bool },
    backup: struct { output_dir: []const u8 },
    restore: struct { input: []const u8 },
    version,

    pub fn isMutation(self: Command) bool {
        return switch (self) {
            .vnr_create,
            .vnr_delete,
            .node_create,
            .node_delete,
            .node_enrollment_renew,
            .node_enrollment_reset,
            .route_add,
            .route_delete,
            .user_bootstrap,
            .backup,
            .restore,
            => true,
            else => false,
        };
    }

    pub fn requiresDaemon(self: Command) bool {
        return switch (self) {
            .down, .status => true,
            .up, .version => false,
            else => false,
        };
    }
};

pub const NodeCreate = struct {
    name: []const u8,
    vnr: []const u8,
    address: []const u8,
    /// Null means use `server.json`'s default enrollment lifetime.
    expires_seconds: ?u64 = null,
    /// A protected, exclusively-created JSON disclosure file. Exactly one of
    /// this field and `no_bootstrap` must be selected by the human CLI.
    bootstrap_out: ?[]const u8 = null,
    no_bootstrap: bool = false,
};

pub const EnrollmentBootstrap = struct {
    name: []const u8,
    bootstrap_out: []const u8,
};

pub fn parse(args: []const []const u8) !Parsed {
    var paths = common.Paths.server_defaults;
    var index: usize = 0;
    while (try common.consumeGlobal(args, &index, &paths)) {}
    if (index >= args.len) return error.MissingCommand;

    const primary = args[index];
    index += 1;
    const rest = args[index..];
    const command: Command = if (std.mem.eql(u8, primary, "up"))
        try parseUp(rest)
    else if (std.mem.eql(u8, primary, "down"))
        try exactNoArgs(rest, .down)
    else if (std.mem.eql(u8, primary, "status"))
        .{ .status = try common.parseOutputFlag(rest) }
    else if (std.mem.eql(u8, primary, "vnr"))
        try parseVnr(rest)
    else if (std.mem.eql(u8, primary, "node"))
        try parseNode(rest)
    else if (std.mem.eql(u8, primary, "route"))
        try parseRoute(rest)
    else if (std.mem.eql(u8, primary, "user"))
        try parseUser(rest)
    else if (std.mem.eql(u8, primary, "backup"))
        try parseBackup(rest)
    else if (std.mem.eql(u8, primary, "restore"))
        try parseRestore(rest)
    else if (std.mem.eql(u8, primary, "version"))
        try exactNoArgs(rest, .version)
    else
        return error.UnknownCommand;

    return .{ .paths = paths, .command = command };
}

fn parseUp(args: []const []const u8) !Command {
    if (args.len == 0) return .{ .up = .{ .daemonize = false } };
    if (args.len == 1 and std.mem.eql(u8, args[0], "-d")) return .{ .up = .{ .daemonize = true } };
    return error.InvalidArguments;
}

fn parseVnr(args: []const []const u8) !Command {
    if (args.len == 0) return error.MissingSubcommand;
    if (std.mem.eql(u8, args[0], "create")) {
        if (args.len != 3) return error.InvalidArguments;
        return .{ .vnr_create = .{ .name = args[1], .cidr = args[2] } };
    }
    if (std.mem.eql(u8, args[0], "delete")) {
        if (args.len != 2) return error.InvalidArguments;
        return .{ .vnr_delete = args[1] };
    }
    if (std.mem.eql(u8, args[0], "list")) return .{ .vnr_list = try common.parseOutputFlag(args[1..]) };
    if (std.mem.eql(u8, args[0], "show")) {
        if (args.len < 2 or args.len > 3) return error.InvalidArguments;
        return .{ .vnr_show = .{ .name = args[1], .output = try common.parseOutputFlag(args[2..]) } };
    }
    return error.UnknownSubcommand;
}

fn parseNode(args: []const []const u8) !Command {
    if (args.len == 0) return error.MissingSubcommand;
    if (std.mem.eql(u8, args[0], "create")) return .{ .node_create = try parseNodeCreate(args[1..]) };
    if (std.mem.eql(u8, args[0], "delete")) {
        if (args.len != 2) return error.InvalidArguments;
        return .{ .node_delete = args[1] };
    }
    if (std.mem.eql(u8, args[0], "list")) return .{ .node_list = try common.parseOutputFlag(args[1..]) };
    if (std.mem.eql(u8, args[0], "show")) {
        if (args.len < 2 or args.len > 3) return error.InvalidArguments;
        return .{ .node_show = .{ .name = args[1], .output = try common.parseOutputFlag(args[2..]) } };
    }
    if (std.mem.eql(u8, args[0], "enrollment")) {
        if (args.len < 2) return error.InvalidArguments;
        if (std.mem.eql(u8, args[1], "renew")) {
            return .{ .node_enrollment_renew = try parseEnrollmentBootstrap(args[2..]) };
        }
        if (std.mem.eql(u8, args[1], "reset")) {
            return .{ .node_enrollment_reset = try parseEnrollmentBootstrap(args[2..]) };
        }
        return error.UnknownSubcommand;
    }
    return error.UnknownSubcommand;
}

fn parseNodeCreate(args: []const []const u8) !NodeCreate {
    if (args.len == 0) return error.InvalidArguments;
    var result: NodeCreate = .{ .name = args[0], .vnr = "", .address = "" };
    var have_vnr = false;
    var have_address = false;
    var have_expires = false;
    var i: usize = 1;
    while (i < args.len) {
        const option = args[i];
        i += 1;
        if (std.mem.eql(u8, option, "--no-bootstrap")) {
            if (result.no_bootstrap) return error.DuplicateOption;
            result.no_bootstrap = true;
            continue;
        }
        if (i >= args.len) return error.MissingOptionValue;
        const value = args[i];
        i += 1;
        if (std.mem.eql(u8, option, "--vnr")) {
            if (have_vnr) return error.DuplicateOption;
            result.vnr = value;
            have_vnr = true;
        } else if (std.mem.eql(u8, option, "--addr")) {
            if (have_address) return error.DuplicateOption;
            result.address = value;
            have_address = true;
        } else if (std.mem.eql(u8, option, "--expires")) {
            if (have_expires) return error.DuplicateOption;
            result.expires_seconds = try common.parseDuration(value);
            have_expires = true;
        } else if (std.mem.eql(u8, option, "--bootstrap-out")) {
            if (result.bootstrap_out != null) return error.DuplicateOption;
            if (value.len == 0) return error.InvalidArguments;
            result.bootstrap_out = value;
        } else {
            return error.UnknownOption;
        }
    }
    if (!have_vnr or !have_address) return error.MissingRequiredOption;
    if (have_expires and result.no_bootstrap) return error.InvalidArguments;
    if ((result.bootstrap_out == null) == !result.no_bootstrap) {
        return error.MissingRequiredOption;
    }
    return result;
}

fn parseEnrollmentBootstrap(args: []const []const u8) !EnrollmentBootstrap {
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--bootstrap-out") or
        args[0].len == 0 or args[2].len == 0)
    {
        return error.InvalidArguments;
    }
    return .{ .name = args[0], .bootstrap_out = args[2] };
}

fn parseRoute(args: []const []const u8) !Command {
    if (args.len == 0) return error.MissingSubcommand;
    if (std.mem.eql(u8, args[0], "add")) {
        if (args.len != 3) return error.InvalidArguments;
        return .{ .route_add = .{ .cidr = args[1], .node = args[2] } };
    }
    if (std.mem.eql(u8, args[0], "delete")) {
        if (args.len != 2) return error.InvalidArguments;
        return .{ .route_delete = args[1] };
    }
    if (std.mem.eql(u8, args[0], "list")) return .{ .route_list = try common.parseOutputFlag(args[1..]) };
    if (std.mem.eql(u8, args[0], "show")) {
        if (args.len < 2 or args.len > 3) return error.InvalidArguments;
        return .{ .route_show = .{ .cidr = args[1], .output = try common.parseOutputFlag(args[2..]) } };
    }
    return error.UnknownSubcommand;
}

fn parseUser(args: []const []const u8) !Command {
    if (args.len == 0) return error.MissingSubcommand;
    if (!std.mem.eql(u8, args[0], "bootstrap")) return error.UnknownSubcommand;
    if (args.len != 3 or !std.mem.eql(u8, args[2], "--password-stdin")) {
        return error.InvalidArguments;
    }
    if (args[1].len == 0) return error.InvalidArguments;
    return .{ .user_bootstrap = .{ .username = args[1], .password_stdin = true } };
}

fn parseBackup(args: []const []const u8) !Command {
    if (args.len != 2 or !std.mem.eql(u8, args[0], "--output-dir") or args[1].len == 0) {
        return error.InvalidArguments;
    }
    return .{ .backup = .{ .output_dir = args[1] } };
}

fn parseRestore(args: []const []const u8) !Command {
    if (args.len != 2 or !std.mem.eql(u8, args[0], "--input") or args[1].len == 0) {
        return error.InvalidArguments;
    }
    return .{ .restore = .{ .input = args[1] } };
}

fn exactNoArgs(args: []const []const u8, command: Command) !Command {
    if (args.len != 0) return error.InvalidArguments;
    return command;
}

test "server parser covers global overrides and typed command shape" {
    const args = [_][]const u8{
        "--state-dir", "/tmp/ntip-state", "node",                "create", "node01",
        "--addr",      "10.1.0.2",        "--vnr",               "vnr0",   "--expires",
        "2d",          "--bootstrap-out", "/tmp/bootstrap.json",
    };
    const parsed = try parse(&args);
    try std.testing.expectEqualStrings("/tmp/ntip-state", parsed.paths.state_dir);
    switch (parsed.command) {
        .node_create => |command| {
            try std.testing.expectEqualStrings("node01", command.name);
            try std.testing.expectEqualStrings("vnr0", command.vnr);
            try std.testing.expectEqual(@as(?u64, 172_800), command.expires_seconds);
            try std.testing.expectEqualStrings("/tmp/bootstrap.json", command.bootstrap_out.?);
        },
        else => return error.UnexpectedCommand,
    }
}

test "server parser rejects incomplete and destructive implicit forms" {
    const missing = [_][]const u8{ "node", "create", "node01", "--vnr", "vnr0" };
    try std.testing.expectError(error.MissingRequiredOption, parse(&missing));
    const force = [_][]const u8{ "vnr", "delete", "vnr0", "--force" };
    try std.testing.expectError(error.InvalidArguments, parse(&force));
    const duplicate = [_][]const u8{ "node", "create", "node01", "--vnr", "v0", "--vnr", "v1", "--addr", "10.1.0.2" };
    try std.testing.expectError(error.DuplicateOption, parse(&duplicate));
    try std.testing.expectError(error.MissingRequiredOption, parse(&.{
        "node", "create", "node01", "--vnr", "v0", "--addr", "10.1.0.2",
    }));
    try std.testing.expectError(error.MissingRequiredOption, parse(&.{
        "node",            "create", "node01",         "--vnr", "v0", "--addr", "10.1.0.2",
        "--bootstrap-out", "/tmp/a", "--no-bootstrap",
    }));
    const inventory_only = try parse(&.{
        "node", "create", "node01", "--vnr", "v0", "--addr", "10.1.0.2", "--no-bootstrap",
    });
    try std.testing.expect(inventory_only.command.node_create.no_bootstrap);

    const reset = try parse(&.{
        "node", "enrollment", "reset", "node01", "--bootstrap-out", "/tmp/node01.json",
    });
    try std.testing.expectEqualStrings("node01", reset.command.node_enrollment_reset.name);
    try std.testing.expectEqualStrings("/tmp/node01.json", reset.command.node_enrollment_reset.bootstrap_out);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "node", "enrollment", "renew", "node01" }));
}

test "server parser keeps bootstrap and maintenance commands explicit" {
    const bootstrap = try parse(&.{ "user", "bootstrap", "Root.Admin", "--password-stdin" });
    try std.testing.expectEqualStrings("Root.Admin", bootstrap.command.user_bootstrap.username);
    const backup = try parse(&.{ "backup", "--output-dir", "/var/backups/ntip" });
    try std.testing.expectEqualStrings("/var/backups/ntip", backup.command.backup.output_dir);
    const restore = try parse(&.{ "restore", "--input", "/var/backups/ntip/ntip.sqlite3" });
    try std.testing.expectEqualStrings("/var/backups/ntip/ntip.sqlite3", restore.command.restore.input);
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "user", "bootstrap", "root" }));
    try std.testing.expectError(error.InvalidArguments, parse(&.{ "restore", "/tmp/backup" }));
}
