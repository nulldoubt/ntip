#!/usr/bin/env python3
"""Validate v0.2 bootstrap samples and deployment trust boundaries."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


class ContractError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_object(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if not raw or len(raw) > 16 * 1024:
        raise ContractError(f"invalid bootstrap size: {path}")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates)
    if type(value) is not dict:
        raise ContractError(f"bootstrap must be a JSON object: {path}")
    return value


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def require_exact(value: dict[str, Any], expected: set[str], name: str) -> None:
    actual = set(value)
    require(actual == expected, f"{name} fields differ: expected={sorted(expected)} actual={sorted(actual)}")


def unit_lines(path: Path) -> set[str]:
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith(("#", ";"))
    }


def validate(repo: Path) -> None:
    server = load_object(repo / "packaging/config/server.json")
    require_exact(
        server,
        {
            "schema_version",
            "listen_port",
            "tun_name",
            "service_socket_path",
            "public_udp_endpoint",
        },
        "server bootstrap",
    )
    require(type(server["schema_version"]) is int and server["schema_version"] == 2, "server schema must be 2")
    require(type(server["listen_port"]) is int and server["listen_port"] == 49152, "unexpected server port")
    require(server["tun_name"] == "ntip0", "unexpected server TUN name")
    require(
        server["service_socket_path"] == "/run/ntip-api/ntsrv-api.sock",
        "unexpected server API socket",
    )
    require(
        server["public_udp_endpoint"] == "ntip.example.invalid:49152",
        "unexpected authoritative public UDP endpoint placeholder",
    )

    api = load_object(repo / "packaging/config/api.json")
    require_exact(
        api,
        {
            "schema_version",
            "bind_address",
            "port",
            "service_socket",
            "public_https_origin",
            "bootstrap_spki_pin",
            "bootstrap_manifest_path",
            "workers",
            "maximum_connections",
        },
        "API bootstrap",
    )
    require(type(api["schema_version"]) is int and api["schema_version"] == 2, "API schema must be 2")
    require(api["bind_address"] == "127.0.0.1" and api["port"] == 8787, "API must bind to loopback:8787")
    require(api["service_socket"] == server["service_socket_path"], "service socket samples differ")
    origin = api["public_https_origin"]
    require(
        type(origin) is str
        and origin.startswith("https://")
        and origin.endswith(".invalid")
        and origin.count("/") == 2,
        "API origin must be an exact HTTPS placeholder",
    )
    require(type(api["workers"]) is int and 0 < api["workers"] <= 64, "invalid fixed worker count")
    require(
        api["bootstrap_spki_pin"] == "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "API SPKI pin must be an exact non-production placeholder",
    )
    require(
        api["bootstrap_manifest_path"] == "/etc/ntip/bootstrap-assets.json",
        "API bootstrap manifest path differs",
    )
    require(
        type(api["maximum_connections"]) is int
        and api["workers"] <= api["maximum_connections"] <= 65_535,
        "invalid fixed connection limit",
    )

    dashboard = load_object(repo / "packaging/config/dashboard.json")
    require_exact(
        dashboard,
        {
            "schema_version",
            "bind_address",
            "port",
            "api_origin",
            "bootstrap_assets_root",
        },
        "dashboard bootstrap",
    )
    require(
        type(dashboard["schema_version"]) is int and dashboard["schema_version"] == 2,
        "dashboard schema must be 2",
    )
    require(
        dashboard["bind_address"] == "0.0.0.0" and dashboard["port"] == 443,
        "dashboard gateway must bind plain HTTP on 0.0.0.0:443",
    )
    require(
        dashboard["api_origin"] == f'http://{api["bind_address"]}:{api["port"]}',
        "dashboard must use the loopback API sample",
    )
    require(
        dashboard["bootstrap_assets_root"] == "/usr/share/ntip/bootstrap-assets",
        "dashboard bootstrap-assets root differs",
    )

    master_unit = unit_lines(repo / "packaging/systemd/ntsrv.service")
    api_unit = unit_lines(repo / "packaging/systemd/ntip-api.service")
    dashboard_unit = unit_lines(repo / "packaging/systemd/ntip-dashboard.service")
    tmpfiles = (repo / "packaging/tmpfiles/ntip.conf").read_text(encoding="utf-8").splitlines()
    require(
        "ReadWritePaths=/var/lib/ntip/server /run/ntip /run/ntip-api" in master_unit,
        "ntsrv must be able to create the typed API socket",
    )
    require("RestartForceExitStatus=75" in master_unit, "ntsrv restart exit status differs")
    require("d /run/ntip-api 0750 ntip ntip-api -" in tmpfiles, "typed API runtime ownership differs")
    for line in {
        "User=ntip-api",
        "Group=ntip-api",
        "ExecStart=/usr/bin/ntip-api --config /etc/ntip/api.json",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "InaccessiblePaths=/var/lib/ntip /run/ntip",
        "ReadOnlyPaths=/etc/ntip/api.json /etc/ntip/bootstrap-assets.json /run/ntip-api",
        "IPAddressDeny=any",
        "IPAddressAllow=localhost",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    }:
        require(line in api_unit, f"API unit is missing confinement: {line}")
    require(
        not any(line.startswith(("StateDirectory=", "ReadWritePaths=/var/lib/ntip")) for line in api_unit),
        "API unit must not receive a writable state directory",
    )
    require(
        "ConditionPathExists=/etc/ntip/bootstrap-assets.json" in api_unit,
        "API must not start without the root-owned bootstrap manifest",
    )

    require(
        not (repo / "packaging/nginx/ntip.conf.example").exists(),
        "same-host NGINX configuration must not ship beside the dashboard gateway",
    )

    bootstrap_installer = (repo / "scripts/install-bootstrap-assets.sh").read_text(encoding="utf-8")
    for contract in {
        "python3 \"$validator\" \"$version\" \"$manifest\" \"$asset_source\"",
        "install_dir root root 0755 /usr/share/ntip/bootstrap-assets",
        "install_file root root 0644 \"$source\" \"/usr/share/ntip/bootstrap-assets/$name\"",
        "install -o root -g ntip-api -m 0640 \"$manifest\" \"$manifest_tmp\"",
        "mv -f \"$manifest_tmp\" /etc/ntip/bootstrap-assets.json",
        "configure the external TLS proxy separately",
    }:
        require(contract in bootstrap_installer, f"bootstrap-assets installer lacks contract: {contract}")
    bootstrap_packager = (repo / "scripts/package-bootstrap-assets.sh").read_text(encoding="utf-8")
    for package_path in {
        "scripts/install-bootstrap-assets.sh",
        "scripts/uninstall-bootstrap-assets.sh",
        "scripts/check-bootstrap-assets.py",
    }:
        require(package_path in bootstrap_packager, f"bootstrap-assets package omits {package_path}")
    for line in {
        "User=ntip-dashboard",
        "Group=ntip-dashboard",
        "ExecStart=/usr/lib/ntip-dashboard/runtime/bun run --no-env-file /usr/lib/ntip-dashboard/app/launcher.ts --config /etc/ntip/dashboard.json",
        "Environment=BUN_RUNTIME_TRANSPILER_CACHE_PATH=0",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "InaccessiblePaths=/var/lib/ntip /run/ntip /run/ntip-api",
        "ReadOnlyPaths=/etc/ntip/dashboard.json /usr/lib/ntip-dashboard /usr/share/ntip/bootstrap-assets",
        "RestrictAddressFamilies=AF_INET AF_INET6",
    }:
        require(line in dashboard_unit, f"dashboard unit is missing confinement: {line}")
    require(
        not any(line.startswith(("StateDirectory=", "ReadWritePaths=")) for line in dashboard_unit),
        "dashboard unit must not receive writable persistent paths",
    )
    require(
        "MemoryDenyWriteExecute=yes" not in dashboard_unit,
        "dashboard unit must retain JavaScriptCore JIT mappings",
    )
    require(
        "ConditionPathExists=/usr/share/ntip/bootstrap-assets" in dashboard_unit,
        "dashboard gateway must not start without immutable bootstrap assets",
    )

    backup_service = repo / "packaging/examples/systemd/ntip-online-backup.service"
    backup_timer = repo / "packaging/examples/systemd/ntip-online-backup.timer"
    require(backup_service.is_file() and backup_timer.is_file(), "backup examples are incomplete")
    require(
        "ExecStart=/usr/bin/ntsrv backup --output-dir /var/backups/ntip"
        in unit_lines(backup_service),
        "backup example CLI contract differs",
    )
    backup_lines = unit_lines(backup_service)
    for line in {
        "Type=oneshot",
        "User=root",
        "Group=ntip-admin",
        "UMask=0077",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "NoNewPrivileges=yes",
        "ReadWritePaths=/var/backups/ntip /run/ntip",
        "RestrictAddressFamilies=AF_UNIX",
    }:
        require(line in backup_lines, f"backup example is missing confinement: {line}")
    timer_lines = unit_lines(backup_timer)
    require("Persistent=true" in timer_lines, "backup timer must catch up after downtime")
    require(
        "Unit=ntip-online-backup.service" in timer_lines,
        "backup timer points at the wrong unit",
    )
    core_installer = (repo / "scripts/install.sh").read_text(encoding="utf-8")
    require(
        '--comment "NTIP management API service account"' in core_installer
        and '"$(id -G ntip-api)" != "$ntip_api_group_gid"' in core_installer,
        "core installer must provision and isolate the SO_PEERCRED identity",
    )
    require("usermod -a -G ntip-admin ntip-api" not in core_installer, "API identity gained admin group")
    installer_paths = (
        "scripts/install.sh",
        "scripts/install-api.sh",
        "scripts/install-dashboard.sh",
    )
    installer_sources = {
        path: (repo / path).read_text(encoding="utf-8") for path in installer_paths
    }
    for path, source in installer_sources.items():
        if path.endswith("install-dashboard.sh"):
            continue
        for contract in {
            'require_unique_passwd_id ntip "$ntip_uid"',
            "require_unique_passwd_id ntip-api",
            'require_unique_group_id ntip "$ntip_group_gid"',
            'require_unique_group_id ntip-api "$ntip_api_group_gid"',
            "require_unique_group_id ntip-admin",
            "ntip and ntip-api must have distinct unprivileged numeric UIDs",
            "ntip, ntip-api, and ntip-admin must have distinct numeric GIDs",
            '"$(id -G ntip-api)" != "$ntip_api_group_gid"',
        }:
            require(contract in source, f"{path} lacks numeric identity isolation: {contract}")
    dashboard_installer = installer_sources["scripts/install-dashboard.sh"]
    for contract in {
        '--comment "NTIP dashboard service account"',
        'if [ "$(id -G ntip-dashboard)" != "$dashboard_gid" ]',
        "dashboard, core, and API versions must match exactly",
        "ntip-dashboard must have a distinct numeric UID",
        "ntip-dashboard must have a distinct numeric GID",
    }:
        require(contract in dashboard_installer, f"dashboard installer lacks isolation: {contract}")
    require(
        "usermod" not in dashboard_installer,
        "dashboard identity must never receive supplementary groups",
    )
    installers = "\n".join(installer_sources.values())
    require(
        "/usr/lib/systemd/system/ntip-online-backup.service" not in installers,
        "backup example must not be installed as a system unit",
    )
    require(
        "/usr/lib/systemd/system/ntip-online-backup.timer" not in installers,
        "backup timer must not be installed as a system unit",
    )
    require(
        "enable --now ntip-online-backup" not in installers,
        "backup timer must never be enabled by an installer",
    )
    require(
        "enable --now ntip-dashboard" not in installers,
        "dashboard must never be enabled by an installer",
    )
    for lower_uninstaller in ("scripts/uninstall.sh", "scripts/uninstall-api.sh"):
        require(
            "disable --now ntip-dashboard.service"
            in (repo / lower_uninstaller).read_text(encoding="utf-8"),
            f"{lower_uninstaller} must stop the dependent dashboard first",
        )


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    try:
        validate(repo)
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"packaging contract validation failed: {error}", file=sys.stderr)
        return 1
    print(
        "packaging_contract=passed server_schema=2 api_loopback=true "
        "dashboard_gateway=0.0.0.0:443 api_state_access=denied dashboard_state_access=denied"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
