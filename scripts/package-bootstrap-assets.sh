#!/bin/sh
set -eu
umask 022

if [ "$#" -ne 1 ]; then
    echo "usage: $0 VERSION" >&2
    exit 2
fi
version=$1
case "$version" in
    ''|*[!0-9A-Za-z.+-]*)
        echo "invalid release version: $version" >&2
        exit 2
        ;;
esac

for command in awk find gzip install jq mktemp python3 sha256sum stat tar; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required bootstrap-assets packaging command not found: $command" >&2
        exit 1
    }
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh "$version" >/dev/null)
(CDPATH='' cd -- "$repo_root" && ./scripts/check-node-bootstrap-installer.sh >/dev/null)
dist=${NTIP_NODE_DIST_DIR:-$repo_root/dist}
case "$dist" in
    /*) ;;
    *) dist=$repo_root/$dist ;;
esac

x86_name=ntip-node-v$version-x86_64-linux-musl.tar.gz
arm_name=ntip-node-v$version-aarch64-linux-musl.tar.gz
for name in "$x86_name" "$arm_name"; do
    for suffix in '' .sha256; do
        [ -f "$dist/$name$suffix" ] || {
            echo "missing Node bootstrap asset: $dist/$name$suffix" >&2
            exit 1
        }
    done
    sbom=${name%.tar.gz}.spdx.json
    [ -f "$dist/$sbom" ] || {
        echo "missing Node SBOM: $dist/$sbom" >&2
        exit 1
    }
    (CDPATH='' cd -- "$dist" && sha256sum --check --status "$name.sha256") || {
        echo "Node archive checksum failed: $name" >&2
        exit 1
    }
done

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --verify HEAD >/dev/null 2>&1; then
        SOURCE_DATE_EPOCH=$(git -C "$repo_root" show -s --format=%ct HEAD)
    else
        echo "SOURCE_DATE_EPOCH is required outside a Git checkout" >&2
        exit 2
    fi
fi
case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*)
        echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2
        exit 2
        ;;
esac
export SOURCE_DATE_EPOCH

digest_of() {
    sha256sum "$1" | awk '{print $1}'
}
size_of() {
    stat -c %s -- "$1"
}
x86_digest=$(digest_of "$dist/$x86_name")
arm_digest=$(digest_of "$dist/$arm_name")
x86_size=$(size_of "$dist/$x86_name")
arm_size=$(size_of "$dist/$arm_name")

archive_root=ntip-bootstrap-assets-v$version
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-bootstrap-assets.XXXXXX")
stage=$work/$archive_root
trap 'rm -rf "$work"' EXIT INT TERM HUP
install -d -m 0755 \
    "$stage/assets" \
    "$stage/docs" \
    "$stage/scripts"

jq -n \
    --arg version "$version" \
    --arg x86_file "$x86_name" --arg x86_sha256 "$x86_digest" --argjson x86_size "$x86_size" \
    --arg arm_file "$arm_name" --arg arm_sha256 "$arm_digest" --argjson arm_size "$arm_size" \
    '{
      schema_version: 1,
      version: $version,
      archives: [
        {target: "x86_64-linux-musl", file: $x86_file, sha256: $x86_sha256, size_bytes: $x86_size},
        {target: "aarch64-linux-musl", file: $arm_file, sha256: $arm_sha256, size_bytes: $arm_size}
      ]
    }' >"$stage/bootstrap-assets.json"
(CDPATH='' cd -- "$stage" && sha256sum bootstrap-assets.json >bootstrap-assets.json.sha256)

for name in "$x86_name" "$arm_name"; do
    install -m 0644 "$dist/$name" "$stage/assets/$name"
    install -m 0644 "$dist/$name.sha256" "$stage/assets/$name.sha256"
    sbom=${name%.tar.gz}.spdx.json
    install -m 0644 "$dist/$sbom" "$stage/assets/$sbom"
done
install -m 0644 "$repo_root/src/management/node-bootstrap-installer.sh.in" \
    "$stage/scripts/node-bootstrap-installer.sh.in"
install -m 0755 "$repo_root/scripts/install-bootstrap-assets.sh" \
    "$stage/scripts/install-bootstrap-assets.sh"
install -m 0755 "$repo_root/scripts/uninstall-bootstrap-assets.sh" \
    "$stage/scripts/uninstall-bootstrap-assets.sh"
install -m 0755 "$repo_root/scripts/check-bootstrap-assets.py" \
    "$stage/scripts/check-bootstrap-assets.py"
install -m 0644 "$repo_root/docs/node-bootstrap.md" "$stage/docs/node-bootstrap.md"
install -m 0644 "$repo_root/LICENSE" "$stage/LICENSE"

python3 "$repo_root/scripts/check-bootstrap-assets.py" \
    "$version" "$stage/bootstrap-assets.json" "$stage/assets"

find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --pax-option=delete=atime,delete=ctime \
    -C "$work" -cf "$dist/$archive_root.tar" "$archive_root"
gzip -n -9 -f "$dist/$archive_root.tar"
(CDPATH='' cd -- "$dist" && sha256sum "$archive_root.tar.gz" >"$archive_root.tar.gz.sha256")
install -m 0644 "$stage/bootstrap-assets.json" "$dist/bootstrap-assets.json"
install -m 0644 "$stage/bootstrap-assets.json.sha256" "$dist/bootstrap-assets.json.sha256"
touch -h -d "@$SOURCE_DATE_EPOCH" "$dist/bootstrap-assets.json" "$dist/bootstrap-assets.json.sha256"
echo "created $dist/$archive_root.tar.gz"
echo "Master manifest source: $dist/bootstrap-assets.json"
echo "Install with: sudo $archive_root/scripts/install-bootstrap-assets.sh"
echo "The manifest is installed root:ntip-api mode 0640 at /etc/ntip/bootstrap-assets.json"
