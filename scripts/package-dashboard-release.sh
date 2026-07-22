#!/bin/sh
set -eu
umask 022

if [ "$#" -ne 2 ]; then
    echo "usage: $0 VERSION TARGET" >&2
    echo "targets: x86_64-linux, aarch64-linux" >&2
    exit 2
fi

version=$1
target=$2
bun_version=1.3.14
case "$version" in
    ''|*[!0-9A-Za-z.-]*)
        echo "invalid release version: $version" >&2
        exit 2
        ;;
esac
case "$target" in
    x86_64-linux)
        bun_asset=bun-linux-x64
        bun_archive_sha256=951ee2aee855f08595aeec6225226a298d3fea83a3dcd6465c09cbccdf7e848f
        native_machine=x86_64
        ;;
    aarch64-linux)
        bun_asset=bun-linux-aarch64
        bun_archive_sha256=a27ffb63a8310375836e0d6f668ae17fa8d8d18b88c37c821c65331973a19a3b
        native_machine=aarch64
        ;;
    *)
        echo "unsupported dashboard release target: $target" >&2
        exit 2
        ;;
esac

for command in cp curl find gzip install jq python3 rm sha1sum sha256sum tar unzip; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required dashboard packaging command not found: $command" >&2
        exit 1
    }
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
(CDPATH='' cd -- "$repo_root" && ./scripts/check-version.sh "$version" >/dev/null)
standalone=$repo_root/apps/dashboard/.next/standalone
static_assets=$repo_root/apps/dashboard/.next/static
required_server_files=$repo_root/apps/dashboard/.next/required-server-files.json
if [ ! -f "$repo_root/apps/dashboard/.next/BUILD_ID" ] || \
    [ ! -f "$standalone/apps/dashboard/server.js" ] || \
    [ ! -d "$static_assets" ] || \
    [ ! -f "$required_server_files" ]; then
    echo "production dashboard build is absent; run bun run dashboard:build" >&2
    exit 1
fi
if ! jq -e '.config.images.unoptimized == true' "$required_server_files" >/dev/null; then
    echo "dashboard release requires Next image optimization to remain disabled" >&2
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

work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-dashboard-release.XXXXXX")
archive_root=ntip-dashboard-v$version-$target
stage=$work/$archive_root
trace=$work/standalone
trap 'rm -rf "$work"' EXIT INT TERM HUP
install -d -m 0755 "$stage/runtime" "$stage/app" "$stage/docs" \
    "$stage/packaging/config" "$stage/packaging/systemd" "$stage/scripts" "$trace"

if [ -n "${NTIP_DASHBOARD_BUN_BINARY:-}" ]; then
    case "$NTIP_DASHBOARD_BUN_BINARY" in
        /*) ;;
        *)
            echo "NTIP_DASHBOARD_BUN_BINARY must be an absolute path" >&2
            exit 2
            ;;
    esac
    install -m 0755 "$NTIP_DASHBOARD_BUN_BINARY" "$stage/runtime/bun"
else
    bun_zip=$work/$bun_asset.zip
    curl --fail --location --proto '=https' --tlsv1.2 \
        "https://github.com/oven-sh/bun/releases/download/bun-v$bun_version/$bun_asset.zip" \
        --output "$bun_zip"
    printf '%s  %s\n' "$bun_archive_sha256" "$bun_zip" | sha256sum --check --status
    unzip -q "$bun_zip" -d "$work/bun"
    install -m 0755 "$work/bun/$bun_asset/bun" "$stage/runtime/bun"
fi

host_machine=$(uname -m 2>/dev/null || printf unknown)
if [ "$(uname -s 2>/dev/null || printf unknown)" = Linux ] && [ "$host_machine" = "$native_machine" ]; then
    actual_bun_version=$("$stage/runtime/bun" --version)
    if [ "$actual_bun_version" != "$bun_version" ]; then
        echo "bundled Bun version differs: expected=$bun_version actual=$actual_bun_version" >&2
        exit 1
    fi
fi

# Next's standalone tracer can retain the build-host Sharp implementation even
# when runtime image optimization is disabled. It is both unused in this
# configuration and architecture-specific, so remove only these traced optional
# image packages from a private copy of the generated trace. Next/Bun can also
# emit dangling workspace links for dependencies that were not traced; those
# links cannot be consumed at runtime and must be removed before dereferencing
# the remaining links into the final, self-contained payload.
cp -R "$standalone/." "$trace/"
if [ -d "$trace/node_modules" ]; then
    find "$trace/node_modules" -type d \
        \( -name sharp -o -name 'sharp@*' -o -name @img -o -name '@img+*' \) \
        -prune -exec rm -rf {} +
fi
find "$trace" -type l -exec sh -c '
    for link do
        [ -e "$link" ] || rm -f "$link"
    done
' sh {} +
# Dereference all surviving Bun workspace links so installed payloads never
# depend on source paths and archives contain only regular files/directories.
cp -RL "$trace/." "$stage/app/"
# Dereferencing the dashboard's `next` link changes Node/Bun package lookup:
# dependencies that used to be siblings of the link target must also be
# materialized beside `next` in the dashboard package directory.
flattened_modules=$stage/app/node_modules/.bun/node_modules
dashboard_modules=$stage/app/apps/dashboard/node_modules
if [ -d "$flattened_modules" ] && [ -d "$dashboard_modules" ]; then
    cp -R "$flattened_modules/." "$dashboard_modules/"
fi
install -d -m 0755 "$stage/app/apps/dashboard/.next/static"
cp -R "$static_assets/." "$stage/app/apps/dashboard/.next/static/"
if [ -d "$repo_root/apps/dashboard/public" ]; then
    install -d -m 0755 "$stage/app/apps/dashboard/public"
    cp -R "$repo_root/apps/dashboard/public/." "$stage/app/apps/dashboard/public/"
fi
install -m 0644 "$repo_root/apps/dashboard/scripts/launcher.ts" "$stage/app/launcher.ts"
install -m 0644 "$repo_root/apps/dashboard/scripts/http-gateway.ts" "$stage/app/http-gateway.ts"
install -d -m 0755 "$stage/app/node_modules/@ntip/config/src"
install -m 0644 "$repo_root/packages/config/package.json" \
    "$stage/app/node_modules/@ntip/config/package.json"
install -m 0644 "$repo_root/packages/config/src/index.ts" \
    "$stage/app/node_modules/@ntip/config/src/index.ts"
find "$stage/app" -type d -exec chmod 0755 {} +
find "$stage/app" -type f -exec chmod 0644 {} +
python3 "$repo_root/scripts/check-dashboard-payload.py" "$stage/app"

printf '%s\n' "$version" >"$stage/VERSION"
install -m 0755 "$repo_root/scripts/install-dashboard.sh" "$stage/scripts/install-dashboard.sh"
install -m 0755 "$repo_root/scripts/uninstall-dashboard.sh" "$stage/scripts/uninstall-dashboard.sh"
install -m 0644 "$repo_root/packaging/config/dashboard.json" "$stage/packaging/config/dashboard.json"
install -m 0644 "$repo_root/packaging/systemd/ntip-dashboard.service" "$stage/packaging/systemd/ntip-dashboard.service"
for document in LICENSE README.md CHANGELOG.md SECURITY.md; do
    install -m 0644 "$repo_root/$document" "$stage/$document"
done
for document in "$repo_root"/docs/*.md; do
    install -m 0644 "$document" "$stage/docs/$(basename "$document")"
done

"$repo_root/scripts/generate-sbom.sh" \
    "$stage" "$version" "$stage/ntip-dashboard-$version.spdx.json" dashboard

find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dist=${NTIP_DASHBOARD_DIST_DIR:-$repo_root/dist}
case "$dist" in
    /*) ;;
    *) dist=$repo_root/$dist ;;
esac
install -d -m 0755 "$dist"
install -m 0644 "$stage/ntip-dashboard-$version.spdx.json" \
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
