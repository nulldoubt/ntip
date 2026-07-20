#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 VERSION" >&2
    exit 2
fi
version=$1
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    echo "SOURCE_DATE_EPOCH is required for dashboard reproducibility" >&2
    exit 2
fi
export NEXT_TELEMETRY_DISABLED=1
for command in bun cmp cp install mktemp rm tar; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required reproducibility command not found: $command" >&2
        exit 1
    }
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-dashboard-reproducibility.XXXXXX")
first=$work/first
second=$work/second
first_source=$work/source-a
second_source=$work/different-depth/source-b
trap 'rm -rf "$work"' EXIT INT TERM HUP
install -d -m 0755 "$first" "$second" "$first_source" "$second_source" \
    "$repo_root/dist"

if [ "$(bun --version)" != 1.3.14 ]; then
    echo "dashboard reproducibility requires Bun 1.3.14 exactly" >&2
    exit 1
fi

# Prove two independent Next production builds from different absolute checkout
# roots. Generated state, dependency installations, and output directories are
# excluded from the source snapshot so neither build can observe the other's
# cache. The different nesting depths catch checkout paths serialized by Next.
copy_source() {
    destination=$1
    tar -C "$repo_root" \
        --exclude='./.git' \
        --exclude='./.zig-cache' \
        --exclude='./zig-cache' \
        --exclude='./zig-out' \
        --exclude='./dist' \
        --exclude='./node_modules' \
        --exclude='./*/node_modules' \
        --exclude='./apps/dashboard/.next' \
        --exclude='./output' \
        --exclude='./results' \
        -cf - . | tar -C "$destination" -xf -
}

build_release() {
    source_root=$1
    destination=$2
    (CDPATH='' cd -- "$source_root" && bun install --frozen-lockfile)
    bun run --cwd "$source_root" dashboard:build
    for target in x86_64-linux aarch64-linux; do
        NTIP_DASHBOARD_DIST_DIR=$destination \
            "$source_root/scripts/package-dashboard-release.sh" "$version" "$target"
    done
}

copy_source "$first_source"
copy_source "$second_source"
build_release "$first_source" "$first"
build_release "$second_source" "$second"

for target in x86_64-linux aarch64-linux; do
    stem=ntip-dashboard-v$version-$target
    for suffix in tar.gz tar.gz.sha256 spdx.json; do
        cmp "$first/$stem.$suffix" "$second/$stem.$suffix"
        install -m 0644 "$first/$stem.$suffix" "$repo_root/dist/$stem.$suffix"
    done
    echo "dashboard_reproducibility=passed target=$target"
done

# Preserve one already-compared build for subsequent runtime/e2e verification
# without weakening the proof above. The source build remains untouched until
# every archive and SBOM comparison has succeeded.
rm -rf "$repo_root/apps/dashboard/.next"
cp -R "$second_source/apps/dashboard/.next" "$repo_root/apps/dashboard/.next"
