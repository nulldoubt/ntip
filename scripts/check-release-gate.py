#!/usr/bin/env python3
"""Strictly validate one versioned NTIP production-beta gate record."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


MAX_GATE_BYTES = 1024 * 1024
REQUIRED_GATE_NAMES = (
    "native-x86_64",
    "native-aarch64",
    "24-hour-soak",
    "independent-security-review",
    "noise-interoperability",
    "benchmark-report",
)
TOP_LEVEL_KEYS = {"schema_version", "version", "approved", "gates"}
GATE_KEYS = {"name", "passed", "evidence"}


class GateValidationError(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateValidationError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def reject_non_finite(value: str) -> None:
    raise GateValidationError(f"non-finite JSON number is forbidden: {value}")


def load_document(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if len(raw) > MAX_GATE_BYTES:
        raise GateValidationError(f"gate record exceeds {MAX_GATE_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GateValidationError("gate record is not valid UTF-8") from error
    try:
        document = json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_non_finite,
        )
    except json.JSONDecodeError as error:
        raise GateValidationError(f"invalid JSON at line {error.lineno}, column {error.colno}") from error
    if not isinstance(document, dict):
        raise GateValidationError("top-level JSON value must be an object")
    return document


def require_exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if extra:
            details.append(f"extra={','.join(extra)}")
        raise GateValidationError(f"{context} keys do not match schema ({'; '.join(details)})")


def validate_document(
    document: dict[str, Any],
    expected_version: str,
    *,
    require_approved: bool,
) -> None:
    require_exact_keys(document, TOP_LEVEL_KEYS, "top-level")

    schema_version = document["schema_version"]
    if type(schema_version) is not int or schema_version != 1:
        raise GateValidationError("schema_version must be the integer 1")

    version = document["version"]
    if type(version) is not str or version != expected_version:
        raise GateValidationError(
            f"version must exactly equal {expected_version!r}, found {version!r}"
        )

    approved = document["approved"]
    if type(approved) is not bool:
        raise GateValidationError("approved must be a JSON boolean")

    gates = document["gates"]
    if type(gates) is not list:
        raise GateValidationError("gates must be a JSON array")

    seen: set[str] = set()
    normalized: dict[str, tuple[bool, str]] = {}
    for index, gate in enumerate(gates):
        context = f"gates[{index}]"
        if type(gate) is not dict:
            raise GateValidationError(f"{context} must be an object")
        require_exact_keys(gate, GATE_KEYS, context)

        name = gate["name"]
        passed = gate["passed"]
        evidence = gate["evidence"]
        if type(name) is not str:
            raise GateValidationError(f"{context}.name must be a string")
        if name in seen:
            raise GateValidationError(f"duplicate gate name: {name}")
        seen.add(name)
        if type(passed) is not bool:
            raise GateValidationError(f"gate {name!r} passed must be a JSON boolean")
        if type(evidence) is not str:
            raise GateValidationError(f"gate {name!r} evidence must be a string")
        if passed and not evidence.strip():
            raise GateValidationError(f"passed gate {name!r} requires nonblank evidence")
        normalized[name] = (passed, evidence)

    required = set(REQUIRED_GATE_NAMES)
    actual = set(normalized)
    missing = sorted(required - actual)
    extra = sorted(actual - required)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing={','.join(missing)}")
        if extra:
            details.append(f"extra={','.join(extra)}")
        raise GateValidationError(f"gate names do not exactly match required set ({'; '.join(details)})")

    if require_approved and not approved:
        raise GateValidationError("release requires approved to be true")

    # An approved record is always required to be release-ready, even during
    # shape-only CI. This prevents an internally inconsistent approval from
    # being accepted merely because --require-approved was omitted.
    if approved:
        failed = sorted(name for name, (passed, _) in normalized.items() if not passed)
        if failed:
            raise GateValidationError(f"approved record contains false gates: {','.join(failed)}")
        empty = sorted(name for name, (_, evidence) in normalized.items() if not evidence.strip())
        if empty:
            raise GateValidationError(f"approved record contains empty evidence: {','.join(empty)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("gate_file", type=Path)
    parser.add_argument("expected_version")
    parser.add_argument(
        "--require-approved",
        action="store_true",
        help="require approved=true, every gate passed, and nonblank evidence",
    )
    args = parser.parse_args()

    if not args.expected_version:
        parser.error("expected_version must not be empty")

    try:
        document = load_document(args.gate_file)
        validate_document(
            document,
            args.expected_version,
            require_approved=args.require_approved,
        )
    except (GateValidationError, OSError) as error:
        print(f"release gate validation failed: {error}", file=sys.stderr)
        return 1

    print(
        "release_gate_validation=passed "
        f"file={args.gate_file} version={args.expected_version} "
        f"require_approved={str(args.require_approved).lower()}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
