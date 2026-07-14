#!/bin/sh
set -eu

build_version=$(sed -n 's/^pub const version = "\([^"]*\)";$/\1/p' build.zig)
package_version=$(sed -n 's/^[[:space:]]*\.version = "\([^"]*\)",$/\1/p' build.zig.zon)

if [ -z "$build_version" ] || [ -z "$package_version" ]; then
    echo "could not determine the NTIP version" >&2
    exit 1
fi

if [ "$build_version" != "$package_version" ]; then
    echo "version mismatch: build.zig=$build_version build.zig.zon=$package_version" >&2
    exit 1
fi

case "$build_version" in
    *[!0-9A-Za-z.-]*|'')
        echo "invalid NTIP version: $build_version" >&2
        exit 1
        ;;
esac

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [EXPECTED_VERSION]" >&2
    exit 2
fi

if [ "$#" -eq 1 ] && [ "$build_version" != "$1" ]; then
    echo "release version mismatch: source=$build_version expected=$1" >&2
    exit 1
fi

if ! grep -Fq "Development status:** \`$build_version\`" README.md; then
    echo "README development status does not match $build_version" >&2
    exit 1
fi

if ! grep -Fq "\`$build_version\`" docs/protocol.md; then
    echo "protocol specification does not mention $build_version" >&2
    exit 1
fi

if ! grep -Fq "Development version: \`$build_version\`" CHANGELOG.md; then
    echo "changelog development version does not match $build_version" >&2
    exit 1
fi

if ! grep -Fq "currently \`$build_version\`" SECURITY.md; then
    echo "security policy version does not match $build_version" >&2
    exit 1
fi

echo "$build_version"
