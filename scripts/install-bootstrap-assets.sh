#!/bin/sh
set -eu

umask 077

destdir=${DESTDIR:-}
if [ -n "$destdir" ] && [ "$destdir" != / ]; then
    case "$destdir" in
        /*) ;;
        *)
            echo "DESTDIR must be an absolute path" >&2
            exit 2
            ;;
    esac
    destdir=${destdir%/}
    staging=1
else
    destdir=
    staging=0
fi

root_path() {
    printf '%s%s\n' "$destdir" "$1"
}

install_dir() {
    owner=$1
    group=$2
    mode=$3
    destination=$(root_path "$4")
    if [ "$staging" -eq 1 ]; then
        install -d -m "$mode" "$destination"
    else
        install -d -o "$owner" -g "$group" -m "$mode" "$destination"
    fi
}

install_file() {
    owner=$1
    group=$2
    mode=$3
    source=$4
    destination=$(root_path "$5")
    if [ "$staging" -eq 1 ]; then
        install -m "$mode" "$source" "$destination"
    else
        install -o "$owner" -g "$group" -m "$mode" "$source" "$destination"
    fi
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
package_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
manifest=$package_root/bootstrap-assets.json
asset_source=$package_root/assets
validator=$package_root/scripts/check-bootstrap-assets.py

for path in "$manifest" "$validator"; do
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "bootstrap-assets package file is missing or unsafe: $path" >&2
        exit 1
    fi
done
if [ ! -d "$asset_source" ] || [ -L "$asset_source" ]; then
    echo "bootstrap-assets package directory is missing or unsafe: $asset_source" >&2
    exit 1
fi

for command in install python3; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required bootstrap-assets installation command not found: $command" >&2
        exit 1
    }
done

version=$(python3 - "$manifest" <<'PY'
import json, pathlib, re, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
version = value.get("version") if type(value) is dict else None
if type(version) is not str or re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,63}", version) is None:
    raise SystemExit("bootstrap-assets manifest version is invalid")
print(version)
PY
)
python3 "$validator" "$version" "$manifest" "$asset_source"

asset_names=$(python3 - "$manifest" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for archive in value["archives"]:
    name = archive["file"]
    print(name)
    print(name + ".sha256")
    print(name.removesuffix(".tar.gz") + ".spdx.json")
PY
)

if [ "$staging" -eq 1 ]; then
    install -d -m 0755 "$destdir"
else
    if [ "$(id -u)" -ne 0 ]; then
        echo "install-bootstrap-assets.sh must run as root" >&2
        exit 1
    fi
    if [ "$(uname -s)" != Linux ]; then
        echo "NTIP bootstrap-assets installation supports Linux only" >&2
        exit 1
    fi
    for command in awk getent id mv systemctl uname; do
        command -v "$command" >/dev/null 2>&1 || {
            echo "required bootstrap-assets installation command not found: $command" >&2
            exit 1
        }
    done
    if systemctl is-active --quiet ntip-api.service; then
        echo "stop ntip-api.service before replacing its bootstrap manifest" >&2
        exit 1
    fi
    if ! getent passwd ntip-api >/dev/null 2>&1 || ! getent group ntip-api >/dev/null 2>&1 || \
        [ ! -x /usr/bin/ntip-api ]
    then
        echo "install the architecture-matched NTIP API package first" >&2
        exit 1
    fi
    api_uid=$(getent passwd ntip-api | awk -F: '{print $3}')
    api_gid=$(getent passwd ntip-api | awk -F: '{print $4}')
    expected_gid=$(getent group ntip-api | awk -F: '{print $3}')
    case "$api_uid:$api_gid:$expected_gid" in
        *[!0-9:]*|:*|*::*|*:)
            echo "could not resolve the numeric ntip-api identity" >&2
            exit 1
            ;;
    esac
    if [ "$api_uid" = 0 ] || [ "$api_gid" = 0 ] || [ "$api_gid" != "$expected_gid" ]; then
        echo "ntip-api is not the expected unprivileged service identity" >&2
        exit 1
    fi
fi

install_dir root root 0755 /etc/ntip
install_dir root root 0755 /usr/share/ntip
install_dir root root 0755 /usr/share/ntip/bootstrap-assets
install_dir root root 0755 /usr/share/doc/ntip-bootstrap-assets

for name in $asset_names; do
    case "$name" in
        ntip-node-v*-x86_64-linux-musl.tar.gz|ntip-node-v*-x86_64-linux-musl.tar.gz.sha256|ntip-node-v*-x86_64-linux-musl.spdx.json|\
        ntip-node-v*-aarch64-linux-musl.tar.gz|ntip-node-v*-aarch64-linux-musl.tar.gz.sha256|ntip-node-v*-aarch64-linux-musl.spdx.json)
            ;;
        *)
            echo "refusing unexpected bootstrap asset basename: $name" >&2
            exit 1
            ;;
    esac
    source=$asset_source/$name
    if [ ! -f "$source" ] || [ -L "$source" ]; then
        echo "bootstrap asset is missing or unsafe: $name" >&2
        exit 1
    fi
    install_file root root 0644 "$source" "/usr/share/ntip/bootstrap-assets/$name"
done

if [ "$staging" -eq 1 ]; then
    install_file root root 0640 "$manifest" /etc/ntip/bootstrap-assets.json
else
    manifest_tmp=/etc/ntip/.bootstrap-assets.json.new.$$
    trap 'rm -f "$manifest_tmp"' EXIT INT TERM HUP
    install -o root -g ntip-api -m 0640 "$manifest" "$manifest_tmp"
    mv -f "$manifest_tmp" /etc/ntip/bootstrap-assets.json
    trap - EXIT INT TERM HUP
fi

if [ -f "$package_root/docs/node-bootstrap.md" ] && [ ! -L "$package_root/docs/node-bootstrap.md" ]; then
    install_file root root 0644 "$package_root/docs/node-bootstrap.md" \
        /usr/share/doc/ntip-bootstrap-assets/node-bootstrap.md
fi

installed_manifest=$(root_path /etc/ntip/bootstrap-assets.json)
installed_assets=$(root_path /usr/share/ntip/bootstrap-assets)
python3 "$validator" "$version" "$installed_manifest" "$installed_assets"

if [ "$staging" -eq 1 ]; then
    echo "NTIP bootstrap assets staged under DESTDIR=$destdir."
else
    echo "NTIP bootstrap assets $version installed."
    echo "The dashboard gateway serves these assets; configure the external TLS proxy separately."
fi
