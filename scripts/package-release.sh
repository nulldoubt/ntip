#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 VERSION TARGET" >&2
    echo "targets: x86_64-linux-musl, aarch64-linux-musl" >&2
    exit 2
fi

version=$1
target=$2

case "$version" in
    ''|*[!0-9A-Za-z.-]*)
        echo "invalid release version: $version" >&2
        exit 2
        ;;
esac

case "$target" in
    x86_64-linux-musl|aarch64-linux-musl) ;;
    *)
        echo "unsupported release target: $target" >&2
        exit 2
        ;;
esac

for command in install tar gzip sha256sum jq sha1sum; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required packaging command not found: $command" >&2
        exit 1
    fi
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh "$version" >/dev/null)
release_dir=${NTIP_RELEASE_DIR:-$repo_root/zig-out/release}
case "$release_dir" in
    /*) ;;
    *) release_dir=$repo_root/$release_dir ;;
esac
binary_dir=$release_dir/$target

for binary in ntsrv ntcl ntip-api; do
    if [ ! -x "$binary_dir/$binary" ]; then
        echo "missing release binary: $binary_dir/$binary" >&2
        echo "run: zig build release" >&2
        exit 1
    fi
done

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if command -v git >/dev/null 2>&1 && git -C "$repo_root" rev-parse --verify HEAD >/dev/null 2>&1; then
        SOURCE_DATE_EPOCH=$(git -C "$repo_root" show -s --format=%ct HEAD)
    else
        echo "SOURCE_DATE_EPOCH is required outside a Git checkout" >&2
        exit 2
    fi
fi
export SOURCE_DATE_EPOCH

dist=$repo_root/dist
archive_root=ntip-v$version-$target
api_archive_root=ntip-api-v$version-$target
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-release.XXXXXX")
stage=$work/$archive_root
api_stage=$work/$api_archive_root
trap 'rm -rf "$work"' EXIT INT TERM HUP

install -d -m 0755 "$stage/bin" "$stage/docs" "$stage/packaging/config" \
    "$stage/packaging/examples/systemd" "$stage/packaging/systemd" \
    "$stage/packaging/tmpfiles" "$stage/scripts"
install -m 0755 "$binary_dir/ntsrv" "$stage/bin/ntsrv"
install -m 0755 "$binary_dir/ntcl" "$stage/bin/ntcl"
install -m 0755 "$repo_root/scripts/install.sh" "$stage/scripts/install.sh"
install -m 0755 "$repo_root/scripts/uninstall.sh" "$stage/scripts/uninstall.sh"
install -m 0644 "$repo_root/LICENSE" "$stage/LICENSE"
install -m 0644 "$repo_root/README.md" "$stage/README.md"
install -m 0644 "$repo_root/CHANGELOG.md" "$stage/CHANGELOG.md"
install -m 0644 "$repo_root/SECURITY.md" "$stage/SECURITY.md"

for file in "$repo_root"/docs/*.md; do
    install -m 0644 "$file" "$stage/docs/$(basename "$file")"
done
install -m 0644 "$repo_root/packaging/config/server.json" "$stage/packaging/config/server.json"
install -m 0644 "$repo_root/packaging/config/client.json" "$stage/packaging/config/client.json"
install -m 0644 "$repo_root/packaging/systemd/ntsrv.service" "$stage/packaging/systemd/ntsrv.service"
install -m 0644 "$repo_root/packaging/systemd/ntcl.service" "$stage/packaging/systemd/ntcl.service"
install -m 0644 "$repo_root/packaging/tmpfiles/ntip.conf" "$stage/packaging/tmpfiles/ntip.conf"
for file in "$repo_root"/packaging/examples/systemd/*; do
    install -m 0644 "$file" "$stage/packaging/examples/systemd/$(basename "$file")"
done

"$repo_root/scripts/generate-sbom.sh" \
    "$stage" "$version" "$stage/ntip-$version.spdx.json"

find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
install -d -m 0755 "$dist"
install -m 0644 "$stage/ntip-$version.spdx.json" \
    "$dist/$archive_root.spdx.json"
touch -h -d "@$SOURCE_DATE_EPOCH" "$dist/$archive_root.spdx.json"

tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --pax-option=delete=atime,delete=ctime \
    -C "$work" -cf "$dist/$archive_root.tar" "$archive_root"
gzip -n -9 -f "$dist/$archive_root.tar"

(CDPATH='' cd -- "$dist" && sha256sum "$archive_root.tar.gz" >"$archive_root.tar.gz.sha256")
echo "created $dist/$archive_root.tar.gz"

# The HTTP management service is intentionally a separate, optional artifact.
# It must still be built for the same architecture as its core package peer.
install -d -m 0755 "$api_stage/bin" "$api_stage/docs" "$api_stage/packaging/config" \
    "$api_stage/packaging/systemd" "$api_stage/scripts"
install -m 0755 "$binary_dir/ntip-api" "$api_stage/bin/ntip-api"
install -m 0755 "$repo_root/scripts/install-api.sh" "$api_stage/scripts/install-api.sh"
install -m 0755 "$repo_root/scripts/uninstall-api.sh" "$api_stage/scripts/uninstall-api.sh"
install -m 0644 "$repo_root/LICENSE" "$api_stage/LICENSE"
install -m 0644 "$repo_root/README.md" "$api_stage/README.md"
install -m 0644 "$repo_root/CHANGELOG.md" "$api_stage/CHANGELOG.md"
install -m 0644 "$repo_root/SECURITY.md" "$api_stage/SECURITY.md"
for file in "$repo_root"/docs/*.md; do
    install -m 0644 "$file" "$api_stage/docs/$(basename "$file")"
done
install -m 0644 "$repo_root/packaging/config/api.json" "$api_stage/packaging/config/api.json"
install -m 0644 "$repo_root/packaging/systemd/ntip-api.service" "$api_stage/packaging/systemd/ntip-api.service"

"$repo_root/scripts/generate-sbom.sh" \
    "$api_stage" "$version" "$api_stage/ntip-api-$version.spdx.json" api

find "$api_stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
install -m 0644 "$api_stage/ntip-api-$version.spdx.json" \
    "$dist/$api_archive_root.spdx.json"
touch -h -d "@$SOURCE_DATE_EPOCH" "$dist/$api_archive_root.spdx.json"

tar --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --pax-option=delete=atime,delete=ctime \
    -C "$work" -cf "$dist/$api_archive_root.tar" "$api_archive_root"
gzip -n -9 -f "$dist/$api_archive_root.tar"

(CDPATH='' cd -- "$dist" && sha256sum "$api_archive_root.tar.gz" >"$api_archive_root.tar.gz.sha256")
echo "created $dist/$api_archive_root.tar.gz"
