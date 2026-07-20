#!/usr/bin/env python3
"""Verify the vendored SQLite pin, source digests, build flags, and SBOM pin."""

from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SQLITE = ROOT / "ext/sqlite"
VERSION = "3.53.3"
VERSION_NUMBER = "3053003"
ARCHIVE = "sqlite-amalgamation-3530300.zip"
URL = f"https://www.sqlite.org/2026/{ARCHIVE}"
EXPECTED_FILES = {ARCHIVE, "sqlite3.c", "sqlite3.h", "sqlite3ext.h"}
REQUIRED_FLAGS = {
    "-DSQLITE_THREADSAFE=1",
    "-DSQLITE_DQS=0",
    "-DSQLITE_DEFAULT_MEMSTATUS=0",
    "-DSQLITE_DEFAULT_WAL_SYNCHRONOUS=2",
    "-DSQLITE_OMIT_DEPRECATED",
    "-DSQLITE_OMIT_LOAD_EXTENSION",
    "-DSQLITE_USE_URI=0",
}


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def read_digests() -> dict[str, str]:
    result: dict[str, str] = {}
    for number, line in enumerate((SQLITE / "SHA3SUMS").read_text(encoding="ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        require(match is not None, f"malformed SHA3SUMS line {number}")
        digest, name = match.groups()
        require(name not in result, f"duplicate SHA3SUMS entry: {name}")
        result[name] = digest
    require(set(result) == EXPECTED_FILES, "SHA3SUMS file register differs from the pin")
    return result


def validate() -> None:
    digests = read_digests()
    for name in sorted(EXPECTED_FILES - {ARCHIVE}):
        source = SQLITE / name
        require(source.is_file(), f"missing vendored SQLite source: {name}")
        actual = hashlib.sha3_256(source.read_bytes()).hexdigest()
        require(actual == digests[name], f"SHA3-256 mismatch: {name}")

    header = (SQLITE / "sqlite3.h").read_text(encoding="utf-8")
    require(f'#define SQLITE_VERSION        "{VERSION}"' in header, "SQLite header version differs")
    require(
        f"#define SQLITE_VERSION_NUMBER {VERSION_NUMBER}" in header,
        "SQLite numeric version differs",
    )
    readme = (SQLITE / "README.md").read_text(encoding="utf-8")
    require(VERSION in readme and URL in readme, "SQLite README pin differs")

    build = (ROOT / "build.zig").read_text(encoding="utf-8")
    for flag in REQUIRED_FLAGS:
        require(f'"{flag}"' in build, f"SQLite build flag missing: {flag}")
    require('"ext/sqlite/sqlite3.c"' in build, "SQLite amalgamation is not in the Master build")
    require(
        "const ntip_api = addExecutable" in build
        and "const ntcl = addExecutable" in build
        and "client_ntip" in build,
        "DB-free client/API module split is missing",
    )

    for relative in ("scripts/generate-sbom.sh", "scripts/check-release-archive.py"):
        policy = (ROOT / relative).read_text(encoding="utf-8")
        require(VERSION in policy, f"{relative} omits SQLite version")
        require(URL in policy, f"{relative} omits SQLite source URL")
        require(digests[ARCHIVE] in policy, f"{relative} omits SQLite archive digest")


def main() -> int:
    try:
        validate()
    except (ContractError, OSError, UnicodeError) as error:
        print(f"vendored SQLite check failed: {error}", file=sys.stderr)
        return 1
    print(
        f"vendored_sqlite=passed version={VERSION} sources=3 "
        f"archive_sha3={read_digests()[ARCHIVE]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
