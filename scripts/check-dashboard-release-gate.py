#!/usr/bin/env python3
"""Enforce the non-optional dashboard runtime gate for v0.2 releases."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


REQUIRED_SCRIPTS = (
    "dashboard:lint",
    "dashboard:typecheck",
    "dashboard:test",
    "dashboard:build",
    "dashboard:runtime-smoke",
    "dashboard:e2e",
)

EXPECTED_ROOT_SCRIPTS = {
    "dashboard:lint": "bun run --cwd apps/dashboard lint",
    "dashboard:typecheck": "bun run --cwd apps/dashboard typecheck",
    "dashboard:test": "bun run --cwd apps/dashboard test",
    "dashboard:build": "bun run --cwd apps/dashboard build",
    "dashboard:runtime-smoke": "bun run --cwd apps/dashboard runtime-smoke",
    "dashboard:e2e": "bun run --cwd apps/dashboard e2e",
}


def fail(message: str) -> int:
    print(f"dashboard release gate failed: {message}", file=sys.stderr)
    return 1


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} VERSION", file=sys.stderr)
        return 2
    version = sys.argv[1]
    if not version.startswith("0.2.") or version.endswith("-dev"):
        print(f"dashboard_release_gate=not-applicable version={version}")
        return 0

    root = Path(__file__).resolve().parent.parent
    dashboard = root / "apps/dashboard/package.json"
    if not dashboard.is_file():
        return fail("apps/dashboard is absent; v0.2 cannot be released")

    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        scripts = package["scripts"]
        package_manager = package["packageManager"]
        dashboard_package = json.loads(dashboard.read_text(encoding="utf-8"))
        dashboard_scripts = dashboard_package["scripts"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        return fail(f"invalid root package contract: {error}")
    if not isinstance(package_manager, str) or not package_manager.startswith("bun@"):
        return fail("packageManager must pin Bun exactly")
    bun_version = package_manager.removeprefix("bun@")
    if not bun_version or any(character not in "0123456789." for character in bun_version):
        return fail("packageManager does not contain an exact numeric Bun version")
    missing = [name for name in REQUIRED_SCRIPTS if not isinstance(scripts.get(name), str)]
    if missing:
        return fail("missing root scripts: " + ", ".join(missing))
    for name, expected in EXPECTED_ROOT_SCRIPTS.items():
        if scripts.get(name) != expected:
            return fail(f"root script {name} must be exactly: {expected}")
    if dashboard_package.get("version") != version:
        return fail(
            f"dashboard package version must be {version}, found {dashboard_package.get('version')!r}"
        )
    build_script = dashboard_scripts.get("build")
    start_script = dashboard_scripts.get("start")
    if build_script != "bun --bun next build && bun run scripts/normalize-build.ts":
        return fail("dashboard build must use pinned Bun and deterministic normalization")
    if start_script != "bun run scripts/start-standalone.ts":
        return fail("dashboard start must execute the standalone server with Bun")
    for name in ("build", "start", "runtime-smoke"):
        command = dashboard_scripts.get(name)
        if not isinstance(command, str):
            return fail(f"dashboard package script is missing: {name}")
        if any(token in command.split() for token in ("node", "npm", "npx", "pnpm", "yarn")):
            return fail(f"dashboard {name} contains a forbidden runtime fallback")
    e2e_tests = sorted((root / "apps/dashboard/test/e2e").glob("*.spec.ts"))
    if not e2e_tests:
        return fail("dashboard has no Playwright end-to-end tests")
    playwright_config = root / "apps/dashboard/playwright.config.ts"
    if not playwright_config.is_file():
        return fail("dashboard Playwright configuration is absent")
    for required in (
        root / "apps/dashboard/scripts/normalize-build.ts",
        root / "apps/dashboard/scripts/start-standalone.ts",
        root / "apps/dashboard/src/proxy.ts",
    ):
        if not required.is_file():
            return fail(f"dashboard production script is absent: {required.name}")
    preview_guard = (root / "apps/dashboard/src/proxy.ts").read_text(encoding="utf-8")
    for cookie in ("__prerender_bypass", "__next_preview_data"):
        if cookie not in preview_guard:
            return fail(f"dashboard proxy must reject the Next preview cookie: {cookie}")
    if "export function proxy" not in preview_guard or "export const config" in preview_guard:
        return fail("dashboard preview-cookie guard must be an all-request Next proxy")

    source_roots = [root / "apps/dashboard/src"]
    source_roots.extend(path / "src" for path in sorted((root / "packages").iterdir()))
    for source_root in source_roots:
        if not source_root.is_dir():
            continue
        for source in source_root.rglob("*"):
            if source.suffix not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"}:
                continue
            text = source.read_text(encoding="utf-8")
            if '"use server"' in text or "'use server'" in text:
                return fail(f"Next Server Actions are forbidden: {source.relative_to(root)}")
            if "draftMode" in text:
                return fail(f"Next Draft Mode is forbidden: {source.relative_to(root)}")

    try:
        actual = subprocess.run(
            ["bun", "--version"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if actual != bun_version:
            return fail(f"Bun {bun_version} is required, found {actual}")
        subprocess.run(["bun", "install", "--frozen-lockfile"], cwd=root, check=True)
        for script in REQUIRED_SCRIPTS:
            subprocess.run(["bun", "run", script], cwd=root, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        return fail(str(error))

    print(
        f"dashboard_release_gate=passed version={version} bun={bun_version} "
        "node_fallback=forbidden"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
