#!/usr/bin/env python3
"""Reject common committed secrets and secret-bearing production log calls."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
TEXT_SUFFIXES = {
    ".c",
    ".conf",
    ".h",
    ".json",
    ".lock",
    ".md",
    ".py",
    ".service",
    ".sh",
    ".sql",
    ".timer",
    ".toml",
    ".ts",
    ".tsx",
    ".yaml",
    ".yml",
    ".zig",
}
EXCLUDED = {
    Path("scripts/check-secret-exposure.py"),
    Path("ext/sqlite/sqlite3.c"),
    Path("ext/sqlite/sqlite3.h"),
    Path("ext/sqlite/sqlite3ext.h"),
}

# Construct signatures in pieces so this policy file does not match itself.
SECRET_SIGNATURES = {
    "private key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE" + rb" KEY-----"),
    "GitHub token": re.compile(rb"gh" + rb"[pousr]_[A-Za-z0-9]{30,}"),
    "AWS access key": re.compile(rb"AK" + rb"IA[0-9A-Z]{16}"),
    "Slack token": re.compile(rb"xox" + rb"[aboprs]-[A-Za-z0-9-]{20,}"),
}
LOG_SINK = re.compile(r"std\.log\.(?:debug|info|warn|err)\s*\(")
LOG_SECRET_TERMS = (
    "password",
    "derived_psk",
    "credential.secret",
    "session_token",
    "csrf_token",
    "token_hash",
    "private_key",
    "set-cookie",
)


class ScanError(RuntimeError):
    pass


def repository_files() -> list[Path]:
    completed = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    paths = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        if relative in EXCLUDED or relative.suffix.lower() not in TEXT_SUFFIXES:
            continue
        paths.append(relative)
    return sorted(paths)


def scan_signatures(label: str, data: bytes) -> None:
    for name, pattern in SECRET_SIGNATURES.items():
        if pattern.search(data):
            raise ScanError(f"{label}: possible {name}")


def scan_log_calls(relative: Path, source: str) -> int:
    calls = 0
    offset = 0
    while match := LOG_SINK.search(source, offset):
        end = source.find(");", match.end())
        if end == -1:
            raise ScanError(f"{relative}: unterminated std.log call near byte {match.start()}")
        call = source[match.start() : end + 2].lower()
        found = [term for term in LOG_SECRET_TERMS if term in call]
        if found:
            line = source.count("\n", 0, match.start()) + 1
            raise ScanError(
                f"{relative}:{line}: production log call references secret-bearing term(s): "
                + ", ".join(found)
            )
        calls += 1
        offset = end + 2
    return calls


def scan_repository() -> tuple[int, int]:
    files = repository_files()
    log_calls = 0
    for relative in files:
        data = (ROOT / relative).read_bytes()
        scan_signatures(str(relative), data)
        if relative.suffix == ".zig":
            log_calls += scan_log_calls(relative, data.decode("utf-8"))
    return len(files), log_calls


def scan_archives(archives: list[Path]) -> int:
    members = 0
    for archive in archives:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle.getmembers():
                if not member.isfile():
                    continue
                extracted = bundle.extractfile(member)
                if extracted is None:
                    raise ScanError(f"{archive}: cannot read {member.name}")
                scan_signatures(f"{archive}:{member.name}", extracted.read())
                members += 1
    return members


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archives", nargs="*", type=Path, default=[])
    args = parser.parse_args()
    try:
        files, log_calls = scan_repository()
        archive_members = scan_archives(args.archives)
    except (OSError, UnicodeError, subprocess.SubprocessError, tarfile.TarError, ScanError) as error:
        print(f"secret exposure check failed: {error}", file=sys.stderr)
        return 1
    print(
        "secret_exposure=passed "
        f"source_files={files} production_log_calls={log_calls} "
        f"archive_members={archive_members}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
