#!/bin/sh
set -eu

for command in cmp install mktemp python3 sha256sum; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required bootstrap-assets installer test command not found: $command" >&2
        exit 77
    }
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-bootstrap-install.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP
package=$work/ntip-bootstrap-assets-v0.2.0-test
root=$work/root
install -d -m 0755 \
    "$package/assets" \
    "$package/scripts" \
    "$root"
install -m 0755 "$repo_root/scripts/install-bootstrap-assets.sh" "$package/scripts/"
install -m 0755 "$repo_root/scripts/uninstall-bootstrap-assets.sh" "$package/scripts/"
install -m 0755 "$repo_root/scripts/check-bootstrap-assets.py" "$package/scripts/"

version=0.2.0-test
x86=ntip-node-v$version-x86_64-linux-musl.tar.gz
arm=ntip-node-v$version-aarch64-linux-musl.tar.gz
printf '%s\n' x86-node-archive >"$package/assets/$x86"
printf '%s\n' arm-node-archive >"$package/assets/$arm"
for name in "$x86" "$arm"; do
    digest=$(sha256sum "$package/assets/$name")
    digest=${digest%% *}
    printf '%s  %s\n' "$digest" "$name" >"$package/assets/$name.sha256"
    printf '%s\n' '{"spdxVersion":"SPDX-2.3"}' \
        >"$package/assets/${name%.tar.gz}.spdx.json"
done
x86_digest=$(sha256sum "$package/assets/$x86")
x86_digest=${x86_digest%% *}
arm_digest=$(sha256sum "$package/assets/$arm")
arm_digest=${arm_digest%% *}
x86_size=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$package/assets/$x86")
arm_size=$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_size)' "$package/assets/$arm")
printf '%s\n' \
    "{\"schema_version\":1,\"version\":\"$version\",\"archives\":[{\"target\":\"x86_64-linux-musl\",\"file\":\"$x86\",\"sha256\":\"$x86_digest\",\"size_bytes\":$x86_size},{\"target\":\"aarch64-linux-musl\",\"file\":\"$arm\",\"sha256\":\"$arm_digest\",\"size_bytes\":$arm_size}]}" \
    >"$package/bootstrap-assets.json"

DESTDIR=$root "$package/scripts/install-bootstrap-assets.sh" >/dev/null
cmp "$package/bootstrap-assets.json" "$root/etc/ntip/bootstrap-assets.json"
for name in \
    "$x86" "$x86.sha256" "${x86%.tar.gz}.spdx.json" \
    "$arm" "$arm.sha256" "${arm%.tar.gz}.spdx.json"
do
    cmp "$package/assets/$name" "$root/usr/share/ntip/bootstrap-assets/$name"
done
test ! -e "$root/etc/nginx"
python3 - "$root" <<'PY'
import os, pathlib, stat, sys
root = pathlib.Path(sys.argv[1])
expected = {
    "etc/ntip/bootstrap-assets.json": 0o640,
    "usr/share/ntip/bootstrap-assets": 0o755,
}
for relative, mode in expected.items():
    actual = stat.S_IMODE(os.stat(root / relative).st_mode)
    if actual != mode:
        raise SystemExit(f"mode mismatch for {relative}: {oct(actual)}")
PY

DESTDIR=$root "$package/scripts/uninstall-bootstrap-assets.sh" >/dev/null
test ! -e "$root/etc/ntip/bootstrap-assets.json"
test ! -e "$root/usr/share/ntip/bootstrap-assets"
test ! -e "$root/usr/share/doc/ntip-bootstrap-assets"
echo "bootstrap_assets_install=passed"
