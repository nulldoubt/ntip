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

for binary in ntsrv ntcl; do
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
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-release.XXXXXX")
stage=$work/$archive_root
trap 'rm -rf "$work"' EXIT INT TERM HUP

install -d -m 0755 "$stage/bin" "$stage/docs" "$stage/packaging/config" \
    "$stage/packaging/systemd" "$stage/packaging/tmpfiles" "$stage/scripts"
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
for file in "$repo_root"/packaging/config/*.json; do
    install -m 0644 "$file" "$stage/packaging/config/$(basename "$file")"
done
for file in "$repo_root"/packaging/systemd/*.service; do
    install -m 0644 "$file" "$stage/packaging/systemd/$(basename "$file")"
done
for file in "$repo_root"/packaging/tmpfiles/*.conf; do
    install -m 0644 "$file" "$stage/packaging/tmpfiles/$(basename "$file")"
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
