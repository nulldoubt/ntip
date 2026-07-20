#!/usr/bin/env python3
"""Validate an isolated, pinned-Bun NTIP dashboard release archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path, PurePosixPath


TARGET_MACHINES = {
    "x86_64-linux": (
        "x86_64",
        62,
        "9fd36f87e4b90b07632b987a2e4ec81ca15a62c81bf983190cea6d715be2ad74",
    ),
    "aarch64-linux": (
        "aarch64",
        183,
        "37141662ebed915a2ab89313156e455e2a1374395f5f6760d06407f49406f086",
    ),
}
BUN_VERSION = "1.3.14"
CANONICAL_APPLICATION_ROOT = "/usr/lib/ntip-dashboard/app"
NATIVE_MAGICS = {
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def native_host_for(target: str) -> bool:
    expected, _, _ = TARGET_MACHINES[target]
    machine = platform.machine().lower()
    if machine == "arm64":
        machine = "aarch64"
    if machine == "amd64":
        machine = "x86_64"
    return platform.system() == "Linux" and machine == expected


def validate_elf(data: bytes, expected_machine: int) -> None:
    require(len(data) >= 20 and data[:4] == b"\x7fELF", "runtime/bun is not ELF")
    require(data[4] == 2 and data[5] == 1, "runtime/bun must be little-endian ELF64")
    machine = struct.unpack_from("<H", data, 18)[0]
    require(machine == expected_machine, f"runtime/bun ELF machine differs: {machine}")


def validate_normalized_next_metadata(payload: dict[str, bytes]) -> str:
    manifest_name = "app/apps/dashboard/.next/required-server-files.json"
    manifest = json.loads(payload[manifest_name])
    require(isinstance(manifest, dict), "required-server-files manifest is not an object")
    config = manifest.get("config")
    require(isinstance(config, dict), "required-server-files config is absent")
    require(
        config.get("outputFileTracingRoot") == CANONICAL_APPLICATION_ROOT,
        "standalone tracing root is not normalized",
    )
    experimental = config.get("experimental")
    require(isinstance(experimental, dict), "standalone experimental config is absent")
    require(experimental.get("cpus") == 1, "standalone CPU topology is not normalized")
    require(
        experimental.get("multiZoneDraftMode") is False,
        "standalone multi-zone Draft Mode must remain disabled",
    )
    turbopack = config.get("turbopack")
    require(isinstance(turbopack, dict), "standalone Turbopack config is absent")
    require(turbopack.get("root") == CANONICAL_APPLICATION_ROOT, "Turbopack root is not normalized")
    require(
        manifest.get("appDir") == f"{CANONICAL_APPLICATION_ROOT}/apps/dashboard",
        "standalone application directory is not normalized",
    )

    server = payload["app/apps/dashboard/server.js"].decode("utf-8")
    require(CANONICAL_APPLICATION_ROOT in server, "standalone server lacks the canonical root")
    require('"cpus":1' in server, "standalone server retained a host-derived CPU count")
    for forbidden in (b'"/work"', b'"/workspace"'):
        require(forbidden not in payload[manifest_name], "standalone manifest leaks a common builder root")
        require(forbidden not in payload["app/apps/dashboard/server.js"], "standalone server leaks a common builder root")

    prerender = json.loads(payload["app/apps/dashboard/.next/prerender-manifest.json"])
    require(isinstance(prerender, dict), "prerender manifest is not an object")
    preview = prerender.get("preview")
    require(isinstance(preview, dict), "prerender preview compatibility block is absent")
    preview_mode_id = preview.get("previewModeId")
    require(
        isinstance(preview_mode_id, str) and len(preview_mode_id) == 32,
        "preview compatibility ID is invalid",
    )
    return preview_mode_id


def native_launcher_smoke(payload: dict[str, bytes], preview_mode_id: str) -> None:
    with tempfile.TemporaryDirectory(prefix="ntip-dashboard-native-") as temporary:
        root = Path(temporary)
        for name, data in payload.items():
            if not (name.startswith("app/") or name == "runtime/bun"):
                continue
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        binary = root / "runtime/bun"
        binary.chmod(0o755)
        actual = subprocess.run(
            [binary, "--version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        require(actual == BUN_VERSION, f"bundled Bun version differs: {actual}")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        configuration = root / "dashboard.json"
        configuration.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "bind_address": "127.0.0.1",
                    "port": port,
                    "api_origin": "http://127.0.0.1:8787",
                }
            ),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.update(
            {
                "NEXT_TELEMETRY_DISABLED": "1",
                "NODE_ENV": "production",
                "BUN_RUNTIME_TRANSPILER_CACHE_PATH": "0",
            }
        )
        process = subprocess.Popen(
            [binary, "run", "--no-env-file", root / "app/launcher.ts", "--config", configuration],
            cwd=root / "app",
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            url = f"http://127.0.0.1:{port}/login"
            deadline = time.monotonic() + 20
            while True:
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    raise ContractError(
                        f"packaged dashboard launcher exited early ({process.returncode}): "
                        f"{stderr.strip() or stdout.strip()}"
                    )
                try:
                    with urllib.request.urlopen(url, timeout=1) as response:
                        if response.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    raise ContractError("packaged dashboard launcher did not become ready")
                time.sleep(0.1)

            forged = urllib.request.Request(
                url,
                headers={"Cookie": f"__prerender_bypass={preview_mode_id}"},
            )
            try:
                urllib.request.urlopen(forged, timeout=2)
                raise ContractError("packaged dashboard accepted a forged Draft Mode cookie")
            except urllib.error.HTTPError as error:
                require(error.code == 400, "preview-cookie guard returned the wrong status")
                require(error.headers.get("Cache-Control") == "no-store", "preview-cookie guard is cacheable")
                cleared = "\n".join(error.headers.get_all("Set-Cookie") or [])
                require("__prerender_bypass=" in cleared, "preview-cookie guard did not clear the cookie")

            with urllib.request.urlopen(url, timeout=2) as recovered:
                require(recovered.status == 200, "packaged dashboard did not recover after cookie rejection")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def validate_checksum(archive: Path) -> None:
    sidecar = Path(f"{archive}.sha256")
    require(sidecar.is_file(), f"missing checksum sidecar: {sidecar}")
    fields = sidecar.read_text(encoding="utf-8").strip().split()
    require(len(fields) == 2, "malformed checksum sidecar")
    require(fields[1].lstrip("*") == archive.name, "checksum names the wrong archive")
    require(fields[0] == sha256(archive.read_bytes()), "archive checksum mismatch")


def validate_sbom(
    document: dict[str, object], payload: dict[str, bytes], version: str
) -> None:
    internal_name = f"ntip-dashboard-{version}.spdx.json"
    require(document.get("spdxVersion") == "SPDX-2.3", "SBOM version differs")
    require(document.get("dataLicense") == "CC0-1.0", "SBOM data license differs")

    packages = document.get("packages")
    require(isinstance(packages, list) and len(packages) == 2, "SBOM must describe dashboard and Bun")
    packages_by_id = {
        item.get("SPDXID"): item
        for item in packages
        if isinstance(item, dict) and isinstance(item.get("SPDXID"), str)
    }
    require(len(packages_by_id) == len(packages), "SBOM package IDs must be unique strings")
    dashboard_package = packages_by_id.get("SPDXRef-Package-NTIP-Dashboard")
    bun_package = packages_by_id.get("SPDXRef-Package-Bun")
    require(isinstance(dashboard_package, dict), "dashboard SBOM package absent")
    require(dashboard_package.get("name") == "ntip-dashboard", "dashboard SBOM package name differs")
    require(dashboard_package.get("versionInfo") == version, "dashboard SBOM version differs")
    require(dashboard_package.get("filesAnalyzed") is True, "dashboard SBOM must analyze files")
    require(isinstance(bun_package, dict), "Bun SBOM package absent")
    require(bun_package.get("name") == "bun", "Bun SBOM package name differs")
    require(bun_package.get("versionInfo") == BUN_VERSION, "Bun SBOM version differs")
    require(bun_package.get("filesAnalyzed") is False, "Bun dependency filesAnalyzed must be false")
    bun_checksums = bun_package.get("checksums")
    require(isinstance(bun_checksums, list), "Bun SBOM checksum is absent")
    bun_sha256 = {
        item.get("algorithm"): item.get("checksumValue")
        for item in bun_checksums
        if isinstance(item, dict)
    }.get("SHA256")
    require(bun_sha256 == sha256(payload["runtime/bun"]), "Bun SBOM checksum differs from runtime")

    expected_files = set(payload) - {internal_name}
    files = document.get("files")
    require(isinstance(files, list), "SBOM files is not an array")
    sbom_files: dict[str, dict[str, object]] = {}
    file_ids: set[str] = set()
    for entry in files:
        require(isinstance(entry, dict), "SBOM file entry is not an object")
        filename = entry.get("fileName")
        spdx_id = entry.get("SPDXID")
        require(isinstance(filename, str) and filename.startswith("./"), "invalid SBOM fileName")
        require(isinstance(spdx_id, str), "invalid SBOM file SPDXID")
        relative = filename[2:]
        require(relative not in sbom_files, f"duplicate SBOM file: {relative}")
        require(spdx_id not in file_ids, f"duplicate SBOM file SPDXID: {spdx_id}")
        sbom_files[relative] = entry
        file_ids.add(spdx_id)
    require(set(sbom_files) == expected_files, "SBOM file list does not exactly cover archive payload")
    for relative, entry in sbom_files.items():
        checksums = entry.get("checksums")
        require(isinstance(checksums, list), f"{relative}: SBOM checksums are absent")
        algorithms = {
            item.get("algorithm"): item.get("checksumValue")
            for item in checksums
            if isinstance(item, dict)
        }
        require(algorithms.get("SHA256") == sha256(payload[relative]), f"{relative}: SBOM checksum differs")

    relationships = document.get("relationships")
    require(isinstance(relationships, list), "SBOM relationships is not an array")
    described = [
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == "SPDXRef-DOCUMENT"
        and item.get("relationshipType") == "DESCRIBES"
    ]
    require(described == ["SPDXRef-Package-NTIP-Dashboard"], "SBOM DESCRIBES relationship differs")
    contained = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == "SPDXRef-Package-NTIP-Dashboard"
        and item.get("relationshipType") == "CONTAINS"
    }
    require(contained == file_ids, "SBOM CONTAINS relationships do not match file entries")
    dependencies = {
        item.get("relatedSpdxElement")
        for item in relationships
        if isinstance(item, dict)
        and item.get("spdxElementId") == "SPDXRef-Package-NTIP-Dashboard"
        and item.get("relationshipType") == "DEPENDS_ON"
    }
    require(dependencies == {"SPDXRef-Package-Bun"}, "dashboard SBOM must depend on exactly Bun")

    verification = dashboard_package.get("packageVerificationCode")
    require(isinstance(verification, dict), "dashboard package verification code is absent")
    require(
        verification.get("packageVerificationCodeExcludedFiles") == [f"./{internal_name}"],
        "dashboard package verification exclusions differ",
    )
    sha1_values = sorted(hashlib.sha1(payload[name]).hexdigest() for name in expected_files)
    calculated = hashlib.sha1("".join(sha1_values).encode("ascii")).hexdigest()
    require(
        verification.get("packageVerificationCodeValue") == calculated,
        "dashboard package verification code differs",
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("target", choices=tuple(TARGET_MACHINES))
    parser.add_argument("archive", type=Path)
    parser.add_argument("--require-native-execution", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    repo_root = Path(__file__).resolve().parent.parent
    archive = arguments.archive.resolve()
    expected_root = f"ntip-dashboard-v{arguments.version}-{arguments.target}"
    expected_machine = TARGET_MACHINES[arguments.target][1]
    expected_runtime_digest = TARGET_MACHINES[arguments.target][2]
    try:
        require(archive.name == f"{expected_root}.tar.gz", "archive filename differs")
        validate_checksum(archive)
        payload: dict[str, bytes] = {}
        modes: dict[str, int] = {}
        directories: set[str] = set()
        seen_members: set[str] = set()
        expected_epoch_source = os.environ.get("SOURCE_DATE_EPOCH")
        expected_epoch = int(expected_epoch_source) if expected_epoch_source is not None else None
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                require(member.name not in seen_members, f"duplicate archive member: {member.name}")
                seen_members.add(member.name)
                path = PurePosixPath(member.name)
                require(not path.is_absolute() and ".." not in path.parts, "unsafe archive path")
                require(path.parts and path.parts[0] == expected_root, "unexpected archive root")
                require(member.uid == 0 and member.gid == 0, f"non-root archive ownership: {path}")
                relative = PurePosixPath(*path.parts[1:]).as_posix() if len(path.parts) > 1 else "."
                require(
                    not any(ord(character) < 32 for character in relative),
                    f"control character in archive path: {relative!r}",
                )
                require(not (member.issym() or member.islnk()), f"links are forbidden: {relative}")
                if expected_epoch is not None:
                    require(member.mtime == expected_epoch, f"unexpected archive mtime: {relative}")
                if member.isdir():
                    require(stat.S_IMODE(member.mode) == 0o755, f"unexpected directory mode: {relative}")
                    directories.add(relative)
                    continue
                require(member.isfile(), f"links and special archive entries are forbidden: {relative}")
                stream = bundle.extractfile(member)
                require(stream is not None, f"cannot read archive file: {relative}")
                require(relative not in payload, f"duplicate archive file: {relative}")
                payload[relative] = stream.read()
                modes[relative] = stat.S_IMODE(member.mode)

        required_directories = {
            ".",
            "app",
            "app/apps",
            "app/apps/dashboard",
            "app/apps/dashboard/.next",
            "app/apps/dashboard/.next/static",
            "docs",
            "packaging",
            "packaging/config",
            "packaging/systemd",
            "runtime",
            "scripts",
        }
        require(required_directories <= directories, "required archive directories are absent")

        source_documents = sorted((repo_root / "docs").glob("*.md"))
        require(bool(source_documents), "dashboard documentation sources are absent")
        required_non_application = {
            "VERSION",
            "runtime/bun",
            "packaging/config/dashboard.json",
            "packaging/systemd/ntip-dashboard.service",
            "scripts/install-dashboard.sh",
            "scripts/uninstall-dashboard.sh",
            "LICENSE",
            "README.md",
            "CHANGELOG.md",
            "SECURITY.md",
            f"ntip-dashboard-{arguments.version}.spdx.json",
        }
        required_non_application.update(f"docs/{path.name}" for path in source_documents)
        actual_non_application = {name for name in payload if not name.startswith("app/")}
        require(
            actual_non_application == required_non_application,
            "non-application archive file set differs from the release contract",
        )
        required_application = {
            "app/launcher.ts",
            "app/apps/dashboard/server.js",
            "app/apps/dashboard/.next/server/middleware.js",
            "app/node_modules/@ntip/config/package.json",
            "app/node_modules/@ntip/config/src/index.ts",
        }
        require(
            required_application <= payload.keys(),
            f"required application payload is absent: {sorted(required_application - payload.keys())}",
        )
        require(any(name.startswith("app/apps/dashboard/.next/static/") for name in payload), "static assets absent")
        preview_mode_id = validate_normalized_next_metadata(payload)
        preview_markers = (b"__prerender_bypass", b"__next_preview_data", b"preview modes are unavailable")
        require(
            any(
                all(marker in data for marker in preview_markers)
                for name, data in payload.items()
                if name.startswith("app/apps/dashboard/.next/server/chunks/")
            ),
            "compiled preview-cookie guard differs",
        )
        require(payload["VERSION"].decode("ascii").strip() == arguments.version, "VERSION differs")
        validate_elf(payload["runtime/bun"], expected_machine)
        require(
            sha256(payload["runtime/bun"]) == expected_runtime_digest,
            "bundled Bun digest differs from the pinned glibc Linux runtime",
        )
        executable_files = {
            "runtime/bun",
            "scripts/install-dashboard.sh",
            "scripts/uninstall-dashboard.sh",
        }
        for name, mode in modes.items():
            expected_mode = 0o755 if name in executable_files else 0o644
            require(mode == expected_mode, f"unexpected archive file mode: {name}")
        for name, data in payload.items():
            if not name.startswith("app/"):
                continue
            require(not name.endswith(".node"), f"native Node module is forbidden: {name}")
            require(
                data[:4] not in NATIVE_MAGICS and not data.startswith(b"MZ"),
                f"native application file is forbidden: {name}",
            )

        source_pairs = {
            "app/launcher.ts": repo_root / "apps/dashboard/scripts/launcher.ts",
            "app/node_modules/@ntip/config/package.json": repo_root / "packages/config/package.json",
            "app/node_modules/@ntip/config/src/index.ts": repo_root / "packages/config/src/index.ts",
            "packaging/config/dashboard.json": repo_root / "packaging/config/dashboard.json",
            "packaging/systemd/ntip-dashboard.service": repo_root / "packaging/systemd/ntip-dashboard.service",
            "scripts/install-dashboard.sh": repo_root / "scripts/install-dashboard.sh",
            "scripts/uninstall-dashboard.sh": repo_root / "scripts/uninstall-dashboard.sh",
        }
        for archived, source in source_pairs.items():
            require(payload[archived] == source.read_bytes(), f"archive source copy differs: {archived}")

        sbom_name = f"ntip-dashboard-{arguments.version}.spdx.json"
        external_sbom = archive.parent / f"{expected_root}.spdx.json"
        require(external_sbom.is_file(), f"external SBOM is absent: {external_sbom}")
        require(payload[sbom_name] == external_sbom.read_bytes(), "internal and external SBOMs differ")
        sbom = json.loads(payload[sbom_name])
        require(isinstance(sbom, dict), "SBOM document is not an object")
        validate_sbom(sbom, payload, arguments.version)

        if arguments.require_native_execution:
            require(native_host_for(arguments.target), "native execution requested on wrong host")
            native_launcher_smoke(payload, preview_mode_id)

        print("component=dashboard")
        print(f"target={arguments.target}")
        print(f"files={len(payload)}")
        print(f"bun={BUN_VERSION}")
        if arguments.require_native_execution:
            print("packaged_launcher_smoke=passed")
            print("preview_cookie_guard=passed")
        print("native_application_modules=0")
        print("sbom_payload_consistency=passed")
        print("dashboard_archive=passed")
        return 0
    except (ContractError, OSError, UnicodeError, ValueError, json.JSONDecodeError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f"dashboard archive validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
