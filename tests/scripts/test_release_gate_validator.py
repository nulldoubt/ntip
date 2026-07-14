#!/usr/bin/env python3

from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPO_ROOT / "scripts" / "check-release-gate.py"
VERSION = "0.1.0-beta.1"
REQUIRED_GATES = (
    "native-x86_64",
    "native-aarch64",
    "24-hour-soak",
    "independent-security-review",
    "noise-interoperability",
    "benchmark-report",
)


def approved_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "version": VERSION,
        "approved": True,
        "gates": [
            {
                "name": name,
                "passed": True,
                "evidence": f"ci://immutable/{name}",
            }
            for name in REQUIRED_GATES
        ],
    }


class ReleaseGateValidatorTests(unittest.TestCase):
    def run_validator(
        self,
        document: dict[str, object] | None = None,
        *,
        raw: str | None = None,
        require_approved: bool = False,
        expected_version: str = VERSION,
    ) -> subprocess.CompletedProcess[str]:
        self.assertTrue((document is None) != (raw is None))
        with tempfile.TemporaryDirectory(prefix="ntip-gate-test.") as temporary:
            path = Path(temporary) / "gate.json"
            if raw is not None:
                path.write_text(raw, encoding="utf-8")
            else:
                path.write_text(json.dumps(document), encoding="utf-8")
            command = [sys.executable, str(VALIDATOR), str(path), expected_version]
            if require_approved:
                command.append("--require-approved")
            return subprocess.run(command, capture_output=True, text=True, check=False)

    def assert_rejected(self, result: subprocess.CompletedProcess[str], text: str) -> None:
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(text, result.stderr)

    def test_valid_approved_record_passes_release_mode(self) -> None:
        result = self.run_validator(approved_document(), require_approved=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("require_approved=true", result.stdout)

    def test_intentionally_unapproved_record_passes_shape_only_mode(self) -> None:
        document = approved_document()
        document["approved"] = False
        for gate in document["gates"]:  # type: ignore[union-attr]
            gate["passed"] = False
            gate["evidence"] = ""
        result = self.run_validator(document)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("require_approved=false", result.stdout)

    def test_missing_gate_fails(self) -> None:
        document = approved_document()
        document["gates"].pop()  # type: ignore[union-attr]
        self.assert_rejected(self.run_validator(document), "missing=benchmark-report")

    def test_duplicate_gate_name_fails(self) -> None:
        document = approved_document()
        gates = document["gates"]  # type: ignore[assignment]
        gates[-1] = copy.deepcopy(gates[0])
        self.assert_rejected(self.run_validator(document), "duplicate gate name")

    def test_extra_gate_fails(self) -> None:
        document = approved_document()
        document["gates"].append(  # type: ignore[union-attr]
            {"name": "unexpected-gate", "passed": True, "evidence": "ci://extra"}
        )
        self.assert_rejected(self.run_validator(document), "extra=unexpected-gate")

    def test_empty_evidence_fails(self) -> None:
        document = approved_document()
        document["gates"][0]["evidence"] = "   "  # type: ignore[index]
        self.assert_rejected(self.run_validator(document, require_approved=True), "nonblank evidence")

    def test_false_gate_fails_approved_record(self) -> None:
        document = approved_document()
        document["gates"][0]["passed"] = False  # type: ignore[index]
        self.assert_rejected(self.run_validator(document), "false gates")

    def test_false_approval_fails_release_mode(self) -> None:
        document = approved_document()
        document["approved"] = False
        self.assert_rejected(
            self.run_validator(document, require_approved=True),
            "approved to be true",
        )

    def test_non_boolean_passed_fails(self) -> None:
        document = approved_document()
        document["gates"][0]["passed"] = 1  # type: ignore[index]
        self.assert_rejected(self.run_validator(document), "JSON boolean")

    def test_non_boolean_approved_fails(self) -> None:
        document = approved_document()
        document["approved"] = 1
        self.assert_rejected(self.run_validator(document), "approved must be a JSON boolean")

    def test_schema_version_must_be_integer_one(self) -> None:
        for invalid in (True, 2, "1"):
            with self.subTest(invalid=invalid):
                document = approved_document()
                document["schema_version"] = invalid
                self.assert_rejected(self.run_validator(document), "integer 1")

    def test_evidence_must_be_string(self) -> None:
        document = approved_document()
        document["gates"][0]["evidence"] = None  # type: ignore[index]
        self.assert_rejected(self.run_validator(document), "evidence must be a string")

    def test_wrong_version_fails(self) -> None:
        self.assert_rejected(
            self.run_validator(approved_document(), expected_version="0.1.0-beta.2"),
            "version must exactly equal",
        )

    def test_extra_schema_key_fails(self) -> None:
        document = approved_document()
        document["ignored"] = True
        self.assert_rejected(self.run_validator(document), "extra=ignored")

    def test_duplicate_json_object_key_fails(self) -> None:
        raw = json.dumps(approved_document()).replace(
            '"schema_version": 1',
            '"schema_version": 1, "schema_version": 1',
            1,
        )
        self.assert_rejected(self.run_validator(raw=raw), "duplicate JSON object key")


if __name__ == "__main__":
    unittest.main()
