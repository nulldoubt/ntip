#!/bin/sh
set -eu

usage() {
    echo "usage: TARGET=IP UDP_RATES='250M 500M ...' [WIREGUARD_TARGET=IP] $0" >&2
    exit 2
}

target=${TARGET:-}
[ -n "$target" ] || usage
case "$target" in
    -*) usage ;;
esac

duration=${DURATION:-60}
omit=${OMIT:-10}
parallel=${PARALLEL:-8}
udp_rates=${UDP_RATES:-}
repetitions=${REPETITIONS:-5}
ping_count=${PING_COUNT:-10000}
out_root=${OUT_ROOT:-results}

case "$duration:$omit:$parallel:$repetitions:$ping_count" in
    *[!0-9:]*|::*|:*:|:*) usage ;;
esac
[ -n "$udp_rates" ] || usage

for command in date hostname uname ip iperf3 ping ps; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required benchmark command not found: $command" >&2
        exit 1
    fi
done

timestamp=$(date -u +%Y%m%d-%H%M%S)
host=$(hostname | tr -c 'A-Za-z0-9._-' '_')
out_dir=$out_root/$timestamp-$host
mkdir -p "$out_dir"

cleanup() {
    if [ -n "${sampler_pid:-}" ]; then
        kill "$sampler_pid" >/dev/null 2>&1 || true
        wait "$sampler_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM HUP

{
    echo "timestamp_utc=$timestamp"
    echo "target=$target"
    echo "wireguard_target=${WIREGUARD_TARGET:-}"
    echo "duration_seconds=$duration"
    echo "omit_seconds=$omit"
    echo "parallel_streams=$parallel"
    echo "repetitions=$repetitions"
    echo "ping_count=$ping_count"
    echo "udp_rates=$udp_rates"
    echo "source_date_epoch=${SOURCE_DATE_EPOCH:-}"
    if command -v zig >/dev/null 2>&1; then
        echo "zig_version=$(zig version)"
    fi
    if command -v ntsrv >/dev/null 2>&1; then
        echo "ntsrv_version=$(ntsrv version 2>&1 | tr '\n' ' ')"
    fi
    if command -v ntcl >/dev/null 2>&1; then
        echo "ntcl_version=$(ntcl version 2>&1 | tr '\n' ' ')"
    fi
} >"$out_dir/metadata.txt"

uname -a >"$out_dir/kernel.txt"
ip -details address show >"$out_dir/network.txt"
ip -details route show table all >>"$out_dir/network.txt"
if command -v lscpu >/dev/null 2>&1; then
    lscpu >"$out_dir/lscpu.txt"
fi
if command -v nft >/dev/null 2>&1; then
    nft list ruleset >"$out_dir/nftables.txt" 2>/dev/null || true
fi
if command -v sysctl >/dev/null 2>&1; then
    sysctl net.ipv4.ip_forward \
        net.ipv4.conf.all.rp_filter \
        net.core.rmem_max \
        net.core.wmem_max >"$out_dir/sysctls.txt" 2>/dev/null || true
fi

if command -v ntsrv >/dev/null 2>&1; then
    ntsrv status --json >"$out_dir/ntsrv-status.json" 2>/dev/null || true
fi
if command -v ntcl >/dev/null 2>&1; then
    ntcl status --json >"$out_dir/ntcl-status.json" 2>/dev/null || true
fi

(
    echo "timestamp,pid,comm,pcpu,rss_kib,vsz_kib"
    while :; do
        now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
        ps -eo pid=,comm=,pcpu=,rss=,vsz= | \
            awk -v timestamp="$now" '$2 == "ntsrv" || $2 == "ntcl" {
                print timestamp "," $1 "," $2 "," $3 "," $4 "," $5
            }'
        sleep 1
    done
) >"$out_dir/cpu-memory.csv" &
sampler_pid=$!

ping -n -c "$ping_count" "$target" >"$out_dir/latency-idle.txt"

repetition=1
while [ "$repetition" -le "$repetitions" ]; do
    iperf3 --client "$target" --time "$duration" --omit "$omit" \
        --parallel 1 --json >"$out_dir/tcp-r${repetition}-p1-forward.json"
    iperf3 --client "$target" --time "$duration" --omit "$omit" \
        --parallel "$parallel" --json \
        >"$out_dir/tcp-r${repetition}-p${parallel}-forward.json"
    iperf3 --client "$target" --time "$duration" --omit "$omit" \
        --parallel "$parallel" --reverse --json \
        >"$out_dir/tcp-r${repetition}-p${parallel}-reverse.json"

    for rate in $udp_rates; do
        safe_rate=$(printf '%s' "$rate" | tr -c 'A-Za-z0-9._-' '_')
        iperf3 --client "$target" --udp --bitrate "$rate" --length 1200 \
            --time "$duration" --omit "$omit" --json \
            >"$out_dir/udp-r${repetition}-$safe_rate.json"
    done

    if [ -n "${WIREGUARD_TARGET:-}" ]; then
        iperf3 --client "$WIREGUARD_TARGET" --time "$duration" --omit "$omit" \
            --parallel "$parallel" --json \
            >"$out_dir/wireguard-r${repetition}-tcp.json"
    fi
    repetition=$((repetition + 1))
done

{
    echo "# Benchmark run $timestamp"
    echo
    echo "Raw results are in this directory. Add medians, percentiles, CPU,"
    echo "loss, environment notes, and small-packet-generator results after"
    echo "reviewing all repetitions. Do not publish a speed claim from one run."
} >"$out_dir/summary.md"

echo "benchmark output: $out_dir"
