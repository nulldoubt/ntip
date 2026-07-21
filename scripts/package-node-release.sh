#!/bin/sh
set -eu
umask 022

if [ "$#" -ne 2 ]; then
    echo "usage: $0 VERSION TARGET" >&2
    echo "targets: x86_64-linux-musl, aarch64-linux-musl" >&2
    exit 2
fi

version=$1
target=$2
case "$version" in
    ''|*[!0-9A-Za-z.+-]*)
        echo "invalid release version: $version" >&2
        exit 2
        ;;
esac
case "$target" in
    x86_64-linux-musl|aarch64-linux-musl) ;;
    *)
        echo "unsupported Node release target: $target" >&2
        exit 2
        ;;
esac

for command in find gzip install jq sha1sum sha256sum tar; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required Node packaging command not found: $command" >&2
        exit 1
    }
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh "$version" >/dev/null)

release_dir=${NTIP_RELEASE_DIR:-$repo_root/zig-out/release}
case "$release_dir" in
    /*) ;;
    *) release_dir=$repo_root/$release_dir ;;
esac
binary=$release_dir/$target/ntcl
if [ ! -x "$binary" ]; then
    echo "missing Node release binary: $binary" >&2
    echo "run: zig build release" >&2
    exit 1
fi

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

dist=${NTIP_NODE_DIST_DIR:-$repo_root/dist}
case "$dist" in
    /*) ;;
    *) dist=$repo_root/$dist ;;
esac
archive_root=ntip-node-v$version-$target
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-node-release.XXXXXX")
stage=$work/$archive_root
trap 'rm -rf "$work"' EXIT INT TERM HUP

install -d -m 0755 "$stage/bin" "$stage/docs" "$stage/packaging/config" \
    "$stage/packaging/systemd" "$stage/packaging/tmpfiles" "$stage/scripts"
install -m 0755 "$binary" "$stage/bin/ntcl"
install -m 0755 "$repo_root/scripts/install-node.sh" "$stage/scripts/install-node.sh"
install -m 0755 "$repo_root/scripts/uninstall-node.sh" "$stage/scripts/uninstall-node.sh"
for document in LICENSE README.md CHANGELOG.md SECURITY.md; do
    install -m 0644 "$repo_root/$document" "$stage/$document"
done
for document in node-bootstrap.md operator-guide.md protocol.md threat-model.md; do
    install -m 0644 "$repo_root/docs/$document" "$stage/docs/$document"
done
install -m 0644 "$repo_root/packaging/config/client.json" \
    "$stage/packaging/config/client.json"
install -m 0644 "$repo_root/packaging/systemd/ntcl.service" \
    "$stage/packaging/systemd/ntcl.service"
install -m 0644 "$repo_root/packaging/tmpfiles/ntip-node.conf" \
    "$stage/packaging/tmpfiles/ntip-node.conf"
printf '%s\n' "$version" >"$stage/VERSION"
printf '%s\n' "$target" >"$stage/TARGET"

"$repo_root/scripts/generate-sbom.sh" \
    "$stage" "$version" "$stage/ntip-node-$version.spdx.json" node

find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
install -d -m 0755 "$dist"
install -m 0644 "$stage/ntip-node-$version.spdx.json" \
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
