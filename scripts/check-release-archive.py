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


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_payload(repo_root: Path, version: str) -> tuple[set[str], set[str]]:
    files = {
        "bin/ntsrv",
        "bin/ntcl",
        "scripts/install.sh",
        "scripts/uninstall.sh",
        "LICENSE",
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        f"ntip-{version}.spdx.json",
    }
    for directory, pattern in (
        ("docs", "*.md"),
        ("packaging/config", "*.json"),
        ("packaging/systemd", "*.service"),
        ("packaging/tmpfiles", "*.conf"),
    ):
        source = repo_root / directory
        discovered = sorted(source.glob(pattern))
        require(bool(discovered), f"no source files found for {directory}/{pattern}")
        files.update(f"{directory}/{path.name}" for path in discovered)

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
) -> None:
    require(document.get("spdxVersion") == "SPDX-2.3", "SBOM is not SPDX-2.3")
    require(document.get("dataLicense") == "CC0-1.0", "SBOM data license is not CC0-1.0")

    packages = document.get("packages")
    require(isinstance(packages, list) and len(packages) == 1, "SBOM must describe one package")
    package = packages[0]
    require(isinstance(package, dict), "SBOM package is not an object")
    require(package.get("SPDXID") == "SPDXRef-Package-NTIP", "unexpected package SPDXID")
    require(package.get("versionInfo") == version, "SBOM package version mismatch")

    internal_sbom = f"ntip-{version}.spdx.json"
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
    contained = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == "SPDXRef-Package-NTIP"
        and item.get("relationshipType") == "CONTAINS"
    }
    require(contained == spdx_ids, "SBOM CONTAINS relationships do not match file entries")

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


def execute_packaged_binaries(payload: dict[str, bytes], version: str) -> None:
    readelf = shutil.which("readelf")
    require(readelf is not None, "readelf is required for native static-binary validation")
    with tempfile.TemporaryDirectory(prefix="ntip-release-exec.") as temporary:
        root = Path(temporary)
        for binary in ("ntsrv", "ntcl"):
            path = root / binary
            path.write_bytes(payload[f"bin/{binary}"])
            path.chmod(0o755)
            completed = subprocess.run(
                [str(path), "version"],
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
    root_name = f"ntip-v{args.version}-{args.target}"
    require(archive.name == f"{root_name}.tar.gz", "archive filename does not match version and target")
    require(archive.is_file(), f"archive does not exist: {archive}")
    validate_checksum(archive)

    expected_files, expected_directories = expected_payload(repo_root, args.version)
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
            expected_mode = 0o755 if relative in {
                "bin/ntsrv",
                "bin/ntcl",
                "scripts/install.sh",
                "scripts/uninstall.sh",
            } else 0o644
            require(stat.S_IMODE(member.mode) == expected_mode, f"{relative}: unexpected file mode")
            extracted = bundle.extractfile(member)
            require(extracted is not None, f"{relative}: could not read archive member")
            payload[relative] = extracted.read()

    require(set(payload) == expected_files, "archive file set does not match the release contract")
    require(directories == expected_directories, "archive directory set does not match the release contract")

    _, expected_machine = TARGET_MACHINES[args.target]
    validate_elf(payload["bin/ntsrv"], expected_machine, "ntsrv")
    validate_elf(payload["bin/ntcl"], expected_machine, "ntcl")

    internal_name = f"ntip-{args.version}.spdx.json"
    external_sbom = archive.parent / f"{root_name}.spdx.json"
    require(external_sbom.is_file(), f"missing external SBOM: {external_sbom}")
    require(payload[internal_name] == external_sbom.read_bytes(), "internal and external SBOMs differ")
    document = json.loads(payload[internal_name])
    require(isinstance(document, dict), "SBOM document is not an object")
    validate_sbom(document, payload, args.version)

    can_execute = native_host_for(args.target)
    if args.require_native_execution:
        require(can_execute, "archive target does not match this native Linux host")
    if can_execute:
        execute_packaged_binaries(payload, args.version)
        execution = "passed"
    else:
        execution = "skipped-non-native-host"

    print(f"archive={archive.name}")
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
