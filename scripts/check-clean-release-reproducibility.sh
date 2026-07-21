#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [VERSION]" >&2
    exit 2
fi
if [ "$#" -eq 1 ]; then
    version=$1
else
    version=$(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh)
fi

for command in cmp git install mktemp python3 sha256sum tar zig; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required clean-build command not found: $command" >&2
        exit 1
    fi
done

if [ "$(zig version)" != 0.16.0 ]; then
    echo "clean release builds require Zig 0.16.0 (found $(zig version))" >&2
    exit 1
fi
(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh "$version" >/dev/null)

commit=$(git -C "$repo_root" rev-parse --verify HEAD 2>/dev/null) || {
    echo "clean release builds require a committed HEAD" >&2
    exit 1
}
dirty=$(git -C "$repo_root" status --porcelain=v1 --untracked-files=normal)
if [ -n "$dirty" ]; then
    echo "clean release builds require a clean source tree" >&2
    printf '%s\n' "$dirty" >&2
    exit 1
fi

commit_epoch=$(git -C "$repo_root" show -s --format=%ct "$commit")
if [ -n "${SOURCE_DATE_EPOCH:-}" ] && [ "$SOURCE_DATE_EPOCH" != "$commit_epoch" ]; then
    echo "SOURCE_DATE_EPOCH must equal the release commit timestamp $commit_epoch" >&2
    exit 2
fi
SOURCE_DATE_EPOCH=$commit_epoch
export SOURCE_DATE_EPOCH

work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-clean-release.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP
source_archive=$work/source.tar
git -C "$repo_root" archive --format=tar --output="$source_archive" "$commit"

for pass in 1 2; do
    pass_root=$work/pass-$pass
    source_root=$pass_root/source
    prefix=$pass_root/prefix
    local_cache=$pass_root/local-cache
    global_cache=$pass_root/global-cache
    install -d -m 0755 "$source_root" "$prefix" "$local_cache" "$global_cache"
    tar -xf "$source_archive" -C "$source_root"
    echo "clean_release_build=starting pass=$pass source=$source_root prefix=$prefix"

    (
        CDPATH='' cd -- "$source_root"
        ./scripts/check-version.sh "$version" >/dev/null
        zig build release \
            --prefix "$prefix" \
            --cache-dir "$local_cache" \
            --global-cache-dir "$global_cache" \
            --summary failures

        for target in x86_64-linux-musl aarch64-linux-musl; do
            NTIP_RELEASE_DIR="$prefix/release" \
                ./scripts/package-release.sh "$version" "$target"
            NTIP_RELEASE_DIR="$prefix/release" \
                ./scripts/package-node-release.sh "$version" "$target"
            python3 scripts/check-release-archive.py \
                "$version" "$target" \
                "dist/ntip-v$version-$target.tar.gz"
            python3 scripts/check-release-archive.py \
                "$version" "$target" \
                "dist/ntip-api-v$version-$target.tar.gz"
            python3 scripts/check-release-archive.py \
                "$version" "$target" \
                "dist/ntip-node-v$version-$target.tar.gz"
        done
        ./scripts/package-bootstrap-assets.sh "$version"
    )
    echo "clean_release_build=completed pass=$pass"
done

install -d -m 0755 "$repo_root/dist"
for target in x86_64-linux-musl aarch64-linux-musl; do
    first_prefix=$work/pass-1/prefix/release/$target
    second_prefix=$work/pass-2/prefix/release/$target
    first_dist=$work/pass-1/source/dist
    second_dist=$work/pass-2/source/dist
    base=ntip-v$version-$target

    for binary in ntsrv ntcl ntip-api; do
        if ! cmp "$first_prefix/$binary" "$second_prefix/$binary"; then
            echo "clean release binary mismatch: target=$target binary=$binary" >&2
            exit 1
        fi
    done
    api_base=ntip-api-v$version-$target
    node_base=ntip-node-v$version-$target
    for artifact_base in "$base" "$api_base" "$node_base"; do
        for suffix in tar.gz spdx.json tar.gz.sha256; do
            if ! cmp "$first_dist/$artifact_base.$suffix" "$second_dist/$artifact_base.$suffix"; then
                echo "clean release artifact mismatch: $artifact_base.$suffix" >&2
                exit 1
            fi
            install -m 0644 "$first_dist/$artifact_base.$suffix" "$repo_root/dist/$artifact_base.$suffix"
        done
    done

    output_dir=$repo_root/zig-out/release/$target
    install -d -m 0755 "$output_dir"
    install -m 0755 "$first_prefix/ntsrv" "$output_dir/ntsrv"
    install -m 0755 "$first_prefix/ntcl" "$output_dir/ntcl"
    install -m 0755 "$first_prefix/ntip-api" "$output_dir/ntip-api"

    echo "clean_release_reproducibility=passed target=$target commit=$commit"
    sha256sum \
        "$first_prefix/ntsrv" \
        "$first_prefix/ntcl" \
        "$first_prefix/ntip-api" \
        "$first_dist/$base.tar.gz" \
        "$first_dist/$base.spdx.json" \
        "$first_dist/$api_base.tar.gz" \
        "$first_dist/$api_base.spdx.json" \
        "$first_dist/$node_base.tar.gz" \
        "$first_dist/$node_base.spdx.json"
done

first_dist=$work/pass-1/source/dist
second_dist=$work/pass-2/source/dist
bootstrap_base=ntip-bootstrap-assets-v$version
for suffix in tar.gz tar.gz.sha256; do
    if ! cmp "$first_dist/$bootstrap_base.$suffix" "$second_dist/$bootstrap_base.$suffix"; then
        echo "clean release artifact mismatch: $bootstrap_base.$suffix" >&2
        exit 1
    fi
    install -m 0644 "$first_dist/$bootstrap_base.$suffix" \
        "$repo_root/dist/$bootstrap_base.$suffix"
done
for manifest in bootstrap-assets.json bootstrap-assets.json.sha256; do
    if ! cmp "$first_dist/$manifest" "$second_dist/$manifest"; then
        echo "clean release artifact mismatch: $manifest" >&2
        exit 1
    fi
    install -m 0644 "$first_dist/$manifest" "$repo_root/dist/$manifest"
done
echo "clean_release_reproducibility=passed component=bootstrap-assets commit=$commit"
sha256sum \
    "$first_dist/$bootstrap_base.tar.gz" \
    "$first_dist/bootstrap-assets.json"

echo "clean_release_reproducibility=passed builds=2 isolated_source_roots=2 isolated_local_caches=2 isolated_global_caches=2"
