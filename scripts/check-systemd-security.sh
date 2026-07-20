#!/bin/sh
set -eu

LC_ALL=C
export LC_ALL

offline=0
if [ "${1:-}" = --offline ]; then
    offline=1
    shift
fi

if [ "$#" -eq 0 ]; then
    echo "usage: $0 [--offline] UNIT [...]" >&2
    exit 2
fi

for command in awk mktemp sed systemd-analyze; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required systemd-security command not found: $command" >&2
        exit 1
    fi
done

# systemd expresses the threshold in tenths: 30 means an exposure score of
# 3.0. Ubuntu 24.04 systemd 255 reports below this ceiling for every bundled
# unit; the API unit is expected to score lower because it has no capabilities,
# device access, or writable state directory.
# The small margin catches meaningful sandbox regression without pretending
# that this heuristic replaces capability tests or security review.
threshold=${NTIP_SYSTEMD_SECURITY_THRESHOLD:-30}
case "$threshold" in
    *[!0-9]*|'')
        echo "NTIP_SYSTEMD_SECURITY_THRESHOLD must be an unsigned integer in tenths" >&2
        exit 2
        ;;
esac
if [ "$threshold" -gt 100 ]; then
    echo "NTIP_SYSTEMD_SECURITY_THRESHOLD must not exceed 100" >&2
    exit 2
fi
display_threshold=$(awk -v threshold="$threshold" 'BEGIN { printf "%.1f", threshold / 10 }')

work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-systemd-security.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP

index=0
for unit in "$@"; do
    index=$((index + 1))
    output=$work/unit-$index.txt
    status=0
    if [ "$offline" -eq 1 ]; then
        systemd-analyze security --offline=yes --no-pager \
            --threshold="$threshold" "$unit" >"$output" 2>&1 || status=$?
    else
        systemd-analyze security --no-pager \
            --threshold="$threshold" "$unit" >"$output" 2>&1 || status=$?
    fi
    cat "$output"
    if [ "$status" -ne 0 ]; then
        echo "systemd security exposure exceeded $display_threshold or analysis failed: $unit" >&2
        exit "$status"
    fi
    score=$(sed -n 's/.*Overall exposure level for .*: \([0-9][0-9.]*\) .*/\1/p' "$output" | tail -n 1)
    if [ -z "$score" ]; then
        echo "could not extract systemd exposure score for $unit" >&2
        exit 1
    fi
    echo "systemd_security=passed unit=$unit score=$score maximum=$display_threshold"
done

echo "note=systemd-analyze is version-dependent evidence and does not satisfy the independent security-review gate"
