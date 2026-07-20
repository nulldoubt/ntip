const std = @import("std");

pub const version = "0.2.0-dev";

const sqlite_flags = &.{
    "-DSQLITE_THREADSAFE=1",
    "-DSQLITE_DQS=0",
    "-DSQLITE_DEFAULT_MEMSTATUS=0",
    "-DSQLITE_DEFAULT_WAL_SYNCHRONOUS=2",
    "-DSQLITE_OMIT_DEPRECATED",
    "-DSQLITE_OMIT_LOAD_EXTENSION",
    "-DSQLITE_USE_URI=0",
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const expected_version = b.option([]const u8, "expected-version", "Version expected by release automation");

    const options = b.addOptions();
    options.addOption([]const u8, "version", version);

    const ntip = b.addModule("ntip", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    ntip.addOptions("build_options", options);
    addSqlite(ntip, b);

    // `ntcl` deliberately receives a separate shared-source module without
    // SQLite C sources, so the Node artifact remains DB-free.
    const client_ntip = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    client_ntip.addOptions("build_options", options);

    const ntsrv = addExecutable(b, "ntsrv", "src/apps/ntsrv.zig", ntip, target, optimize, options);
    const ntcl = addExecutable(b, "ntcl", "src/apps/ntcl.zig", client_ntip, target, optimize, options);
    const ntip_api = addExecutable(b, "ntip-api", "src/apps/ntip-api.zig", client_ntip, target, optimize, options);
    ntip_api.root_module.addImport("openapi_document", b.createModule(.{
        .root_source_file = b.path("packages/contracts/src/openapi_document.zig"),
        .target = target,
        .optimize = optimize,
    }));
    b.installArtifact(ntsrv);
    b.installArtifact(ntcl);
    b.installArtifact(ntip_api);

    addRunStep(b, "run-ntsrv", "Run the NTIP Master server CLI", ntsrv);
    addRunStep(b, "run-ntcl", "Run the NTIP Node client CLI", ntcl);
    addRunStep(b, "run-ntip-api", "Run the NTIP management HTTP service", ntip_api);

    const unit_tests = b.addTest(.{ .root_module = ntip });
    const run_unit_tests = b.addRunArtifact(unit_tests);

    const server_tests = b.addTest(.{ .root_module = ntsrv.root_module });
    const run_server_tests = b.addRunArtifact(server_tests);
    const client_tests = b.addTest(.{ .root_module = ntcl.root_module });
    const run_client_tests = b.addRunArtifact(client_tests);
    const api_tests = b.addTest(.{ .root_module = ntip_api.root_module });
    const run_api_tests = b.addRunArtifact(api_tests);

    const sqlite_test_module = b.createModule(.{
        .root_source_file = b.path("src/state/sqlite_repository.zig"),
        .target = target,
        .optimize = optimize,
    });
    addSqlite(sqlite_test_module, b);
    const sqlite_tests = b.addTest(.{ .root_module = sqlite_test_module });
    const run_sqlite_tests = b.addRunArtifact(sqlite_tests);

    const protocol_module = b.createModule(.{
        .root_source_file = b.path("src/protocol/mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const protocol_property_module = b.createModule(.{
        .root_source_file = b.path("tests/protocol/all.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ntip_protocol", .module = protocol_module }},
    });
    const protocol_tests = b.addTest(.{ .root_module = protocol_property_module });
    const run_protocol_tests = b.addRunArtifact(protocol_tests);

    const primitive_vector_module = b.createModule(.{
        .root_source_file = b.path("tests/protocol/primitive_vectors.zig"),
        .target = target,
        .optimize = optimize,
    });
    const primitive_vector_tests = b.addTest(.{ .root_module = primitive_vector_module });
    const run_primitive_vector_tests = b.addRunArtifact(primitive_vector_tests);
    const primitive_vector_step = b.step("primitive-vectors", "Check RFC 8439, RFC 5869, and RFC 7748 primitive vectors");
    primitive_vector_step.dependOn(&run_primitive_vector_tests.step);

    const management_contract_module = b.createModule(.{
        .root_source_file = b.path("tests/management_contract.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "ntip", .module = ntip },
            .{ .name = "openapi_document", .module = b.createModule(.{
                .root_source_file = b.path("packages/contracts/src/openapi_document.zig"),
                .target = target,
                .optimize = optimize,
            }) },
        },
    });
    const management_contract_tests = b.addTest(.{ .root_module = management_contract_module });
    const run_management_contract_tests = b.addRunArtifact(management_contract_tests);

    const test_step = b.step("test", "Run portable unit and executable tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(&run_server_tests.step);
    test_step.dependOn(&run_client_tests.step);
    test_step.dependOn(&run_api_tests.step);
    test_step.dependOn(&run_sqlite_tests.step);
    test_step.dependOn(&run_protocol_tests.step);
    test_step.dependOn(primitive_vector_step);
    test_step.dependOn(&run_management_contract_tests.step);

    const integration_module = b.createModule(.{
        .root_source_file = b.path("tests/integration.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ntip", .module = ntip }},
    });
    const integration_tests = b.addTest(.{ .root_module = integration_module });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_step = b.step("integration", "Run portable integration tests");
    integration_step.dependOn(&run_integration_tests.step);

    const fuzz_module = b.createModule(.{
        .root_source_file = b.path("tests/fuzz.zig"),
        .target = target,
        .optimize = optimize,
        // Zig 0.16.0's fuzz test runner currently mixes builtin and std.debug
        // StackTrace types when error tracing is enabled. Coverage fuzzing does
        // not need return traces, so disable them for this dedicated target.
        .error_tracing = false,
        .imports = &.{.{ .name = "ntip", .module = ntip }},
    });
    const fuzz_tests = b.addTest(.{ .root_module = fuzz_module });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run parser/replay smoke tests or a coverage campaign with --fuzz");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    const fmt_check = b.addFmt(.{ .paths = &.{ "build.zig", "src", "tests" }, .check = true });
    const fmt_step = b.step("fmt-check", "Check Zig source formatting");
    fmt_step.dependOn(&fmt_check.step);

    const cross_step = b.step("cross-build", "Cross-build static Linux x86_64 and AArch64 binaries");
    const cross_alias_step = b.step("cross", "Alias for cross-build");
    cross_alias_step.dependOn(cross_step);
    const release_step = b.step("release", "Build ReleaseSafe static Linux artifacts");
    inline for (.{
        .{ .arch = std.Target.Cpu.Arch.x86_64, .name = "x86_64-linux-musl" },
        .{ .arch = std.Target.Cpu.Arch.aarch64, .name = "aarch64-linux-musl" },
    }) |entry| {
        const linux_target = b.resolveTargetQuery(.{
            .cpu_arch = entry.arch,
            .os_tag = .linux,
            .abi = .musl,
        });
        const release_ntip = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = linux_target,
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        release_ntip.addOptions("build_options", options);
        addSqlite(release_ntip, b);
        const release_client_ntip = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = linux_target,
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        release_client_ntip.addOptions("build_options", options);
        const release_ntsrv = addExecutable(b, "ntsrv", "src/apps/ntsrv.zig", release_ntip, linux_target, .ReleaseSafe, options);
        const release_ntcl = addExecutable(b, "ntcl", "src/apps/ntcl.zig", release_client_ntip, linux_target, .ReleaseSafe, options);
        const release_ntip_api = addExecutable(b, "ntip-api", "src/apps/ntip-api.zig", release_client_ntip, linux_target, .ReleaseSafe, options);
        release_ntip_api.root_module.addImport("openapi_document", b.createModule(.{
            .root_source_file = b.path("packages/contracts/src/openapi_document.zig"),
            .target = linux_target,
            .optimize = .ReleaseSafe,
        }));
        release_ntsrv.root_module.strip = true;
        release_ntcl.root_module.strip = true;
        release_ntip_api.root_module.strip = true;
        cross_step.dependOn(&release_ntsrv.step);
        cross_step.dependOn(&release_ntcl.step);
        cross_step.dependOn(&release_ntip_api.step);

        // Zig 0.16.0 can crash when an `addTest` compile-only probe combines
        // `-fstrip` with `-fno-emit-bin`. Keep release executables stripped,
        // but give the type-check probe an otherwise identical unstripped
        // module until the compiler bug is fixed.
        const probe_ntip = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = linux_target,
            .optimize = .ReleaseSafe,
        });
        probe_ntip.addOptions("build_options", options);
        addSqlite(probe_ntip, b);
        const linux_probe_module = b.createModule(.{
            .root_source_file = b.path("tests/linux_compile.zig"),
            .target = linux_target,
            .optimize = .ReleaseSafe,
            .imports = &.{.{ .name = "ntip", .module = probe_ntip }},
        });
        const linux_probe = b.addTest(.{ .root_module = linux_probe_module });
        cross_step.dependOn(&linux_probe.step);

        const sqlite_probe_module = b.createModule(.{
            .root_source_file = b.path("src/state/sqlite_repository.zig"),
            .target = linux_target,
            .optimize = .ReleaseSafe,
        });
        addSqlite(sqlite_probe_module, b);
        const sqlite_probe = b.addTest(.{ .root_module = sqlite_probe_module });
        cross_step.dependOn(&sqlite_probe.step);

        const install_ntsrv = b.addInstallArtifact(release_ntsrv, .{
            .dest_dir = .{ .override = .{ .custom = b.fmt("release/{s}", .{entry.name}) } },
        });
        const install_ntcl = b.addInstallArtifact(release_ntcl, .{
            .dest_dir = .{ .override = .{ .custom = b.fmt("release/{s}", .{entry.name}) } },
        });
        const install_ntip_api = b.addInstallArtifact(release_ntip_api, .{
            .dest_dir = .{ .override = .{ .custom = b.fmt("release/{s}", .{entry.name}) } },
        });
        cross_step.dependOn(&install_ntsrv.step);
        cross_step.dependOn(&install_ntcl.step);
        cross_step.dependOn(&install_ntip_api.step);
        release_step.dependOn(&install_ntsrv.step);
        release_step.dependOn(&install_ntcl.step);
        release_step.dependOn(&install_ntip_api.step);
    }

    const version_check = b.addSystemCommand(&.{ "sh", "scripts/check-version.sh" });
    if (expected_version) |value| version_check.addArg(value);
    const version_step = b.step("version-check", "Verify version consistency across release metadata");
    version_step.dependOn(&version_check.step);

    const oracle_check = b.addSystemCommand(&.{ "sh", "scripts/check-noise-oracles.sh" });
    const oracle_step = b.step("noise-oracles", "Compare positive and negative handshakes plus post-Split transport with two independent Noise implementations");
    oracle_step.dependOn(&oracle_check.step);

    const check_step = b.step("check", "Run all portable verification gates");
    check_step.dependOn(test_step);
    check_step.dependOn(integration_step);
    check_step.dependOn(fuzz_step);
    check_step.dependOn(fmt_step);
    check_step.dependOn(version_step);
    check_step.dependOn(cross_step);
}

fn addSqlite(module: *std.Build.Module, b: *std.Build) void {
    module.addIncludePath(b.path("ext/sqlite"));
    module.addCSourceFiles(.{
        .files = &.{
            "ext/sqlite/sqlite3.c",
            "ext/sqlite/ntip_sqlite.c",
        },
        .flags = sqlite_flags,
    });
    module.link_libc = true;
}

fn addExecutable(
    b: *std.Build,
    name: []const u8,
    root_path: []const u8,
    ntip: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    options: *std.Build.Step.Options,
) *std.Build.Step.Compile {
    const root_module = b.createModule(.{
        .root_source_file = b.path(root_path),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "ntip", .module = ntip }},
    });
    root_module.addOptions("build_options", options);
    return b.addExecutable(.{ .name = name, .root_module = root_module });
}

fn addRunStep(b: *std.Build, name: []const u8, description: []const u8, executable: *std.Build.Step.Compile) void {
    const run_command = b.addRunArtifact(executable);
    if (b.args) |args| run_command.addArgs(args);
    const step = b.step(name, description);
    step.dependOn(&run_command.step);
}
