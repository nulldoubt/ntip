#!/usr/bin/env python3
"""Validate the architecture-neutral Next standalone dashboard payload."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

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


def fail(message: str) -> int:
    print(f"dashboard payload validation failed: {message}", file=sys.stderr)
    return 1


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} APP_ROOT", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    if not root.is_dir():
        return fail(f"not a directory: {root}")
    for required in (
        "launcher.ts",
        "http-gateway.ts",
        "apps/dashboard/server.js",
        "apps/dashboard/.next/static",
        "node_modules/@ntip/config/src/index.ts",
    ):
        if not (root / required).exists():
            return fail(f"required standalone path is absent: {required}")

    regular_files = 0
    for path in sorted(root.rglob("*")):
        metadata = path.lstat()
        relative = path.relative_to(root)
        if any(ord(character) < 32 for character in relative.as_posix()):
            return fail(f"control character is forbidden in payload path: {relative!r}")
        if stat.S_ISLNK(metadata.st_mode):
            return fail(f"symbolic link is forbidden: {relative}")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            return fail(f"non-regular payload entry is forbidden: {relative}")
        regular_files += 1
        if path.suffix == ".node":
            return fail(f"native Node module is forbidden: {relative}")
        with path.open("rb") as stream:
            magic = stream.read(4)
            if magic in NATIVE_MAGICS or magic.startswith(b"MZ"):
                return fail(f"native application file is forbidden: {relative}")
        if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return fail(f"group/world-writable application file: {relative}")
    if regular_files == 0:
        return fail("payload has no regular files")

    print(f"dashboard_payload=passed regular_files={regular_files} native_modules=0 symlinks=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
