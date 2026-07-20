#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

if [ "$#" -eq 0 ]; then
    version=$(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh)
    set -- x86_64-linux-musl aarch64-linux-musl
else
    version=$1
    shift
    if [ "$#" -eq 0 ]; then
        set -- x86_64-linux-musl aarch64-linux-musl
    fi
fi

(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh "$version" >/dev/null)

for command in cmp cp git mktemp python3 sha256sum; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required reproducibility command not found: $command" >&2
        exit 1
    fi
done

if [ "${NTIP_REQUIRE_CLEAN_SOURCE:-0}" = 1 ]; then
    dirty=$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)
    if [ -n "$dirty" ]; then
        echo "release reproducibility requires a clean source tree" >&2
        printf '%s\n' "$dirty" >&2
        exit 1
    fi
fi

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
    if git -C "$repo_root" rev-parse --verify HEAD >/dev/null 2>&1; then
        SOURCE_DATE_EPOCH=$(git -C "$repo_root" show -s --format=%ct HEAD)
    else
        echo "SOURCE_DATE_EPOCH is required when HEAD is unavailable" >&2
        exit 2
    fi
fi
case "$SOURCE_DATE_EPOCH" in
    *[!0-9]*|'')
        echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2
        exit 2
        ;;
esac
export SOURCE_DATE_EPOCH

work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-reproducibility.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP

for target in "$@"; do
    case "$target" in
        x86_64-linux-musl|aarch64-linux-musl) ;;
        *)
            echo "unsupported release target: $target" >&2
            exit 2
            ;;
    esac

    core_base="ntip-v$version-$target"
    api_base="ntip-api-v$version-$target"
    for base in "$core_base" "$api_base"; do
        archive="$repo_root/dist/$base.tar.gz"
        sbom="$repo_root/dist/$base.spdx.json"
        checksum="$archive.sha256"
        rm -f "$archive" "$sbom" "$checksum"
    done

    (CDPATH='' cd -- "$repo_root" && ./scripts/package-release.sh "$version" "$target")
    for base in "$core_base" "$api_base"; do
        archive="$repo_root/dist/$base.tar.gz"
        sbom="$repo_root/dist/$base.spdx.json"
        checksum="$archive.sha256"
        python3 "$repo_root/scripts/check-release-archive.py" "$version" "$target" "$archive"
        cp "$archive" "$work/$base.first.tar.gz"
        cp "$sbom" "$work/$base.first.spdx.json"
        cp "$checksum" "$work/$base.first.tar.gz.sha256"
    done

    (CDPATH='' cd -- "$repo_root" && ./scripts/package-release.sh "$version" "$target")
    for base in "$core_base" "$api_base"; do
        archive="$repo_root/dist/$base.tar.gz"
        sbom="$repo_root/dist/$base.spdx.json"
        checksum="$archive.sha256"
        cmp "$work/$base.first.tar.gz" "$archive"
        cmp "$work/$base.first.spdx.json" "$sbom"
        cmp "$work/$base.first.tar.gz.sha256" "$checksum"
        python3 "$repo_root/scripts/check-release-archive.py" "$version" "$target" "$archive"

        echo "reproducible_package=$base"
        sha256sum "$archive" "$sbom"
    done
done

echo "release_archive_reproducibility=passed"
echo "note=packaging passes reused the same compiled binaries; compiler output reproducibility is a separate gate"
