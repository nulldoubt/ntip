#!/usr/bin/env python3
"""Validate the strict Master-side Node archive manifest and its payloads."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    pass


def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def validate(version: str, manifest_path: Path, assets: Path) -> None:
    require(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", version) is not None, "invalid version")
    raw = manifest_path.read_bytes()
    require(0 < len(raw) <= 16 * 1024, "manifest size is invalid")
    document = json.loads(raw, object_pairs_hook=pairs)
    require(type(document) is dict, "manifest must be an object")
    require(set(document) == {"schema_version", "version", "archives"}, "manifest fields differ")
    require(type(document["schema_version"]) is int and document["schema_version"] == 1, "schema version differs")
    require(document["version"] == version, "release version differs")
    archives = document["archives"]
    require(type(archives) is list and len(archives) == 2, "manifest must contain exactly two archives")

    expected_targets = {"x86_64-linux-musl", "aarch64-linux-musl"}
    seen: set[str] = set()
    for archive in archives:
        require(type(archive) is dict, "archive record must be an object")
        require(
            set(archive) == {"target", "file", "sha256", "size_bytes"},
            "archive fields differ",
        )
        target = archive["target"]
        require(type(target) is str and target in expected_targets and target not in seen, "archive target differs")
        seen.add(target)
        expected_file = f"ntip-node-v{version}-{target}.tar.gz"
        require(archive["file"] == expected_file, "archive filename differs")
        require(
            type(archive["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", archive["sha256"]) is not None,
            "archive SHA-256 is invalid",
        )
        require(
            type(archive["size_bytes"]) is int
            and type(archive["size_bytes"]) is not bool
            and 0 < archive["size_bytes"] <= 268_435_456,
            "archive size is invalid",
        )
        payload = assets / expected_file
        require(payload.is_file() and not payload.is_symlink(), f"archive payload is missing: {expected_file}")
        require(payload.stat().st_size == archive["size_bytes"], f"archive size mismatch: {expected_file}")
        require(digest(payload) == archive["sha256"], f"archive checksum mismatch: {expected_file}")
        sidecar = Path(f"{payload}.sha256")
        require(sidecar.is_file() and not sidecar.is_symlink(), f"archive sidecar is missing: {expected_file}")
        fields = sidecar.read_text(encoding="ascii").strip().split()
        require(fields == [archive["sha256"], expected_file], f"archive sidecar differs: {expected_file}")
        sbom = assets / f"ntip-node-v{version}-{target}.spdx.json"
        require(sbom.is_file() and not sbom.is_symlink(), f"archive SBOM is missing: {expected_file}")
    require(seen == expected_targets, "archive target set differs")


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} VERSION MANIFEST ASSET_DIR", file=sys.stderr)
        return 2
    try:
        validate(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"bootstrap-assets validation failed: {error}", file=sys.stderr)
        return 1
    print("bootstrap_assets_contract=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
