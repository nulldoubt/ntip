#!/usr/bin/env python3
"""Validate one NTIP release archive and execute it when the host can."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath


TARGET_MACHINES = {
    "x86_64-linux-musl": ("x86_64", 62),
    "aarch64-linux-musl": ("aarch64", 183),
}

COMPONENTS = {
    "core": {
        "package_name": "ntip",
        "package_id": "SPDXRef-Package-NTIP",
        "binaries": ("ntsrv", "ntcl"),
        "internal_sbom_prefix": "ntip",
    },
    "api": {
        "package_name": "ntip-api",
        "package_id": "SPDXRef-Package-NTIP-API",
        "binaries": ("ntip-api",),
        "internal_sbom_prefix": "ntip-api",
    },
    "node": {
        "package_name": "ntip-node",
        "package_id": "SPDXRef-Package-NTIP-Node",
        "binaries": ("ntcl",),
        "internal_sbom_prefix": "ntip-node",
    },
}

SQLITE_COMPONENT = {
    "package_id": "SPDXRef-Package-SQLite",
    "version": "3.53.3",
    "download": "https://www.sqlite.org/2026/sqlite-amalgamation-3530300.zip",
    "archive_sha3": "d45c688a8cb23f68611a894a756a12d7eb6ab6e9e2468ca70adbeab3808b5ab9",
}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_payload(
    repo_root: Path,
    version: str,
    component: str,
) -> tuple[set[str], set[str]]:
    common = {
        "LICENSE",
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
    }
    if component == "core":
        files = common | {
            "bin/ntsrv",
            "bin/ntcl",
            "scripts/install.sh",
            "scripts/uninstall.sh",
            "packaging/config/server.json",
            "packaging/config/client.json",
            "packaging/systemd/ntsrv.service",
            "packaging/systemd/ntcl.service",
            "packaging/tmpfiles/ntip.conf",
            f"ntip-{version}.spdx.json",
        }
        for directory, pattern in (
            ("docs", "*.md"),
            ("packaging/examples/systemd", "*"),
        ):
            source = repo_root / directory
            discovered = sorted(path for path in source.glob(pattern) if path.is_file())
            require(bool(discovered), f"no source files found for {directory}/{pattern}")
            files.update(f"{directory}/{path.name}" for path in discovered)
        directories = {
            ".",
            "bin",
            "docs",
            "packaging",
            "packaging/config",
            "packaging/examples",
            "packaging/examples/systemd",
            "packaging/systemd",
            "packaging/tmpfiles",
            "scripts",
        }
    elif component == "api":
        files = common | {
            "bin/ntip-api",
            "scripts/install-api.sh",
            "scripts/uninstall-api.sh",
            "packaging/config/api.json",
            "packaging/systemd/ntip-api.service",
            f"ntip-api-{version}.spdx.json",
        }
        source = repo_root / "docs"
        discovered = sorted(source.glob("*.md"))
        require(bool(discovered), "no API documentation sources found")
        files.update(f"docs/{path.name}" for path in discovered)
        directories = {
            ".",
            "bin",
            "docs",
            "packaging",
            "packaging/config",
            "packaging/systemd",
            "scripts",
        }
    elif component == "node":
        files = common | {
            "VERSION",
            "TARGET",
            "bin/ntcl",
            "scripts/install-node.sh",
            "scripts/uninstall-node.sh",
            "packaging/config/client.json",
            "packaging/systemd/ntcl.service",
            "packaging/tmpfiles/ntip-node.conf",
            f"ntip-node-{version}.spdx.json",
        }
        files.update(
            f"docs/{name}"
            for name in (
                "node-bootstrap.md",
                "operator-guide.md",
                "protocol.md",
                "threat-model.md",
            )
        )
        directories = {
            ".",
            "bin",
            "docs",
            "packaging",
            "packaging/config",
            "packaging/systemd",
            "packaging/tmpfiles",
            "scripts",
        }
    else:
        raise ContractError(f"unsupported release component: {component}")
    return files, directories


def validate_elf(data: bytes, expected_machine: int, name: str) -> None:
    require(len(data) >= 20, f"{name}: truncated ELF header")
    require(data[:4] == b"\x7fELF", f"{name}: not an ELF binary")
    require(data[4] == 2, f"{name}: release binary is not ELF64")
    require(data[5] == 1, f"{name}: release binary is not little-endian")
    machine = struct.unpack_from("<H", data, 18)[0]
    require(machine == expected_machine, f"{name}: ELF machine {machine} does not match target")


def validate_checksum(archive: Path) -> None:
    sidecar = Path(f"{archive}.sha256")
    require(sidecar.is_file(), f"missing checksum sidecar: {sidecar}")
    fields = sidecar.read_text(encoding="utf-8").strip().split()
    require(len(fields) == 2, f"malformed checksum sidecar: {sidecar}")
    require(fields[1].lstrip("*") == archive.name, "checksum sidecar names the wrong archive")
    require(fields[0] == sha256(archive.read_bytes()), "archive checksum mismatch")


def validate_sbom(
    document: dict[str, object],
    payload: dict[str, bytes],
    version: str,
    component: str,
) -> None:
    metadata = COMPONENTS[component]
    require(document.get("spdxVersion") == "SPDX-2.3", "SBOM is not SPDX-2.3")
    require(document.get("dataLicense") == "CC0-1.0", "SBOM data license is not CC0-1.0")

    packages = document.get("packages")
    expected_package_count = 2 if component == "core" else 1
    require(
        isinstance(packages, list) and len(packages) == expected_package_count,
        f"SBOM must describe {expected_package_count} package(s)",
    )
    package_by_id = {
        item.get("SPDXID"): item
        for item in packages
        if isinstance(item, dict) and isinstance(item.get("SPDXID"), str)
    }
    require(len(package_by_id) == len(packages), "SBOM package IDs must be unique strings")
    package = package_by_id.get(metadata["package_id"])
    require(isinstance(package, dict), "SBOM primary package is missing")
    require(package.get("SPDXID") == metadata["package_id"], "unexpected package SPDXID")
    require(package.get("name") == metadata["package_name"], "unexpected package name")
    require(package.get("versionInfo") == version, "SBOM package version mismatch")

    if component == "core":
        sqlite_package = package_by_id.get(SQLITE_COMPONENT["package_id"])
        require(isinstance(sqlite_package, dict), "core SBOM omits statically linked SQLite")
        require(sqlite_package.get("name") == "sqlite", "unexpected SQLite package name")
        require(
            sqlite_package.get("versionInfo") == SQLITE_COMPONENT["version"],
            "SQLite SBOM version differs from the vendored pin",
        )
        require(
            sqlite_package.get("downloadLocation") == SQLITE_COMPONENT["download"],
            "SQLite SBOM download location differs from the vendored pin",
        )
        require(sqlite_package.get("filesAnalyzed") is False, "SQLite dependency filesAnalyzed must be false")
        require(
            sqlite_package.get("licenseDeclared") == "blessing"
            and sqlite_package.get("licenseConcluded") == "blessing",
            "SQLite SBOM license must use the SPDX blessing identifier",
        )
        sqlite_checksums = sqlite_package.get("checksums")
        require(isinstance(sqlite_checksums, list), "SQLite SBOM checksums are missing")
        require(
            {
                item.get("algorithm"): item.get("checksumValue")
                for item in sqlite_checksums
                if isinstance(item, dict)
            }.get("SHA3-256")
            == SQLITE_COMPONENT["archive_sha3"],
            "SQLite upstream archive checksum differs from the vendored pin",
        )
    else:
        require(
            SQLITE_COMPONENT["package_id"] not in package_by_id,
            "DB-free API SBOM unexpectedly declares SQLite",
        )

    internal_sbom = f"{metadata['internal_sbom_prefix']}-{version}.spdx.json"
    expected_files = set(payload) - {internal_sbom}
    files = document.get("files")
    require(isinstance(files, list), "SBOM files is not an array")

    sbom_files: dict[str, dict[str, object]] = {}
    spdx_ids: set[str] = set()
    for entry in files:
        require(isinstance(entry, dict), "SBOM file entry is not an object")
        filename = entry.get("fileName")
        spdx_id = entry.get("SPDXID")
        require(isinstance(filename, str) and filename.startswith("./"), "invalid SBOM fileName")
        require(isinstance(spdx_id, str), "invalid SBOM file SPDXID")
        relative = filename[2:]
        require(relative not in sbom_files, f"duplicate SBOM file: {relative}")
        require(spdx_id not in spdx_ids, f"duplicate SPDXID: {spdx_id}")
        sbom_files[relative] = entry
        spdx_ids.add(spdx_id)

    require(set(sbom_files) == expected_files, "SBOM file list does not exactly cover archive payload")
    for relative, entry in sbom_files.items():
        checksums = entry.get("checksums")
        require(isinstance(checksums, list), f"{relative}: checksums is not an array")
        matching = [
            item
            for item in checksums
            if isinstance(item, dict) and item.get("algorithm") == "SHA256"
        ]
        require(len(matching) == 1, f"{relative}: expected exactly one SHA256 checksum")
        require(matching[0].get("checksumValue") == sha256(payload[relative]), f"{relative}: SBOM checksum mismatch")

    relationships = document.get("relationships")
    require(isinstance(relationships, list), "SBOM relationships is not an array")
    described = [
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and item.get("relationshipType") == "DESCRIBES"
    ]
    require(described == [metadata["package_id"]], "SBOM DESCRIBES relationship differs")
    contained = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == metadata["package_id"]
        and item.get("relationshipType") == "CONTAINS"
    }
    require(contained == spdx_ids, "SBOM CONTAINS relationships do not match file entries")

    dependency_targets = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == metadata["package_id"]
        and item.get("relationshipType") == "DEPENDS_ON"
    }
    if component == "core":
        require(
            dependency_targets == {SQLITE_COMPONENT["package_id"]},
            "core SBOM dependency relationship must name exactly SQLite",
        )
    else:
        require(not dependency_targets, "DB-free API SBOM must not declare runtime dependencies")

    verification = package.get("packageVerificationCode")
    require(isinstance(verification, dict), "missing package verification code")
    excluded = verification.get("packageVerificationCodeExcludedFiles")
    require(excluded == [f"./{internal_sbom}"], "unexpected package verification exclusions")
    sha1_values = sorted(hashlib.sha1(payload[name]).hexdigest() for name in expected_files)
    calculated = hashlib.sha1("".join(sha1_values).encode("ascii")).hexdigest()
    require(
        verification.get("packageVerificationCodeValue") == calculated,
        "package verification code mismatch",
    )


def native_host_for(target: str) -> bool:
    expected_arch, _ = TARGET_MACHINES[target]
    machine = platform.machine().lower()
    if machine == "arm64":
        machine = "aarch64"
    if machine == "amd64":
        machine = "x86_64"
    return platform.system() == "Linux" and machine == expected_arch


def execute_packaged_binaries(payload: dict[str, bytes], version: str, component: str) -> None:
    readelf = shutil.which("readelf")
    require(readelf is not None, "readelf is required for native static-binary validation")
    with tempfile.TemporaryDirectory(prefix="ntip-release-exec.") as temporary:
        root = Path(temporary)
        binaries = COMPONENTS[component]["binaries"]
        require(isinstance(binaries, tuple), "invalid component binary register")
        for binary in binaries:
            require(isinstance(binary, str), "invalid component binary name")
            path = root / binary
            path.write_bytes(payload[f"bin/{binary}"])
            path.chmod(0o755)
            command = [str(path), "--version"] if binary == "ntip-api" else [str(path), "version"]
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            require(completed.returncode == 0, f"{binary} version failed: {completed.stderr.strip()}")
            require(completed.stdout.strip() == f"{binary} {version}", f"{binary} version mismatch")

            program_headers = subprocess.run(
                [readelf, "-lW", str(path)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            dynamic = subprocess.run(
                [readelf, "-dW", str(path)],
                check=False,
                capture_output=True,
                text=True,
            ).stdout
            require(" INTERP " not in program_headers, f"{binary} has a dynamic interpreter")
            require("(NEEDED)" not in dynamic, f"{binary} has a dynamic library dependency")


def inspect(args: argparse.Namespace) -> None:
    repo_root = Path(__file__).resolve().parent.parent
    archive = args.archive.resolve()
    core_root = f"ntip-v{args.version}-{args.target}"
    api_root = f"ntip-api-v{args.version}-{args.target}"
    node_root = f"ntip-node-v{args.version}-{args.target}"
    if archive.name == f"{core_root}.tar.gz":
        component = "core"
        root_name = core_root
    elif archive.name == f"{api_root}.tar.gz":
        component = "api"
        root_name = api_root
    elif archive.name == f"{node_root}.tar.gz":
        component = "node"
        root_name = node_root
    else:
        raise ContractError("archive filename does not match version, target, or component")
    require(archive.is_file(), f"archive does not exist: {archive}")
    validate_checksum(archive)

    expected_files, expected_directories = expected_payload(repo_root, args.version, component)
    payload: dict[str, bytes] = {}
    directories: set[str] = set()
    seen_members: set[str] = set()
    expected_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    epoch = int(expected_epoch) if expected_epoch is not None else None

    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            require(member.name not in seen_members, f"duplicate archive member: {member.name}")
            seen_members.add(member.name)
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and ".." not in path.parts, f"unsafe archive path: {member.name}")
            require(path.parts and path.parts[0] == root_name, f"member outside archive root: {member.name}")
            relative = PurePosixPath(*path.parts[1:]).as_posix() if len(path.parts) > 1 else "."
            require(member.uid == 0 and member.gid == 0, f"{relative}: archive owner is not numeric root")
            if epoch is not None:
                require(member.mtime == epoch, f"{relative}: mtime is not SOURCE_DATE_EPOCH")
            if member.isdir():
                require(stat.S_IMODE(member.mode) == 0o755, f"{relative}: directory mode is not 0755")
                directories.add(relative)
                continue
            require(member.isfile(), f"{relative}: links and special files are forbidden")
            expected_mode = 0o755 if relative.startswith("bin/") or relative in {
                "scripts/install.sh",
                "scripts/uninstall.sh",
                "scripts/install-api.sh",
                "scripts/uninstall-api.sh",
                "scripts/install-node.sh",
                "scripts/uninstall-node.sh",
            } else 0o644
            require(stat.S_IMODE(member.mode) == expected_mode, f"{relative}: unexpected file mode")
            extracted = bundle.extractfile(member)
            require(extracted is not None, f"{relative}: could not read archive member")
            payload[relative] = extracted.read()

    require(set(payload) == expected_files, "archive file set does not match the release contract")
    require(directories == expected_directories, "archive directory set does not match the release contract")

    _, expected_machine = TARGET_MACHINES[args.target]
    binaries = COMPONENTS[component]["binaries"]
    require(isinstance(binaries, tuple), "invalid component binary register")
    for binary in binaries:
        require(isinstance(binary, str), "invalid component binary name")
        validate_elf(payload[f"bin/{binary}"], expected_machine, binary)

    sbom_prefix = COMPONENTS[component]["internal_sbom_prefix"]
    require(isinstance(sbom_prefix, str), "invalid component SBOM register")
    internal_name = f"{sbom_prefix}-{args.version}.spdx.json"
    external_sbom = archive.parent / f"{root_name}.spdx.json"
    require(external_sbom.is_file(), f"missing external SBOM: {external_sbom}")
    require(payload[internal_name] == external_sbom.read_bytes(), "internal and external SBOMs differ")
    document = json.loads(payload[internal_name])
    require(isinstance(document, dict), "SBOM document is not an object")
    validate_sbom(document, payload, args.version, component)

    can_execute = native_host_for(args.target)
    if args.require_native_execution:
        require(can_execute, "archive target does not match this native Linux host")
    if can_execute:
        execute_packaged_binaries(payload, args.version, component)
        execution = "passed"
    else:
        execution = "skipped-non-native-host"

    print(f"archive={archive.name}")
    print(f"component={component}")
    print(f"sha256={sha256(archive.read_bytes())}")
    print(f"files={len(payload)}")
    print("archive_contract=passed")
    print("sbom_payload_consistency=passed")
    print(f"native_execution={execution}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("target", choices=sorted(TARGET_MACHINES))
    parser.add_argument("archive", type=Path)
    parser.add_argument("--require-native-execution", action="store_true")
    args = parser.parse_args()
    try:
        inspect(args)
    except (
        ContractError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        tarfile.TarError,
    ) as error:
        print(f"release archive validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
