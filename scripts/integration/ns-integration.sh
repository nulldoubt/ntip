#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "namespace integration must run as root" >&2
    exit 1
fi

for command in ip sysctl nft tc conntrack iperf3 ping jq timeout install getent \
    stat id awk grep tail sleep chown chmod mkdir tr python3 curl runuser
do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required integration command not found: $command" >&2
        exit 1
    fi
done

if ! getent passwd ntip >/dev/null 2>&1 || \
    ! getent passwd ntip-api >/dev/null 2>&1 || \
    ! getent group ntip-admin >/dev/null 2>&1 || \
    ! getent group ntip-api >/dev/null 2>&1
then
    echo "the ntip/ntip-api service users and ntip-admin/ntip-api groups are required" >&2
    echo "build first, then run scripts/install.sh on this disposable test host" >&2
    exit 1
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
bin_dir=${NTIP_BIN_DIR:-$repo_root/zig-out/bin}
ntsrv=$bin_dir/ntsrv
ntcl=${NTIP_CLIENT_BIN:-$bin_dir/ntcl}
ntip_api=$bin_dir/ntip-api
compatibility_only=${NTIP_COMPATIBILITY_ONLY:-0}

if [ ! -x "$ntsrv" ]; then
    echo "missing current ntsrv at $ntsrv; run zig build first" >&2
    exit 1
fi
if [ ! -x "$ntcl" ]; then
    echo "missing Node client at $ntcl" >&2
    exit 1
fi
if [ ! -x "$ntip_api" ]; then
    echo "missing current management API at $ntip_api; run zig build first" >&2
    exit 1
fi
case "$compatibility_only" in
    0|1) ;;
    *)
        echo "NTIP_COMPATIBILITY_ONLY must be 0 or 1" >&2
        exit 2
        ;;
esac
printf 'NTIP namespace binaries: %s; %s\n' \
    "$("$ntsrv" version)" "$("$ntcl" version)"

run_id=${NTIP_TEST_ID:-$$}
case "$run_id" in
    ''|*[!A-Za-z0-9]*)
        echo "NTIP_TEST_ID must contain only ASCII letters and digits" >&2
        exit 2
        ;;
esac

short_id=$(printf '%s' "$run_id" | tail -c 6)
master_ns=ntip-$run_id-master
node1_ns=ntip-$run_id-node1
node2_ns=ntip-$run_id-node2
nat_ns=ntip-$run_id-nat
lan_ns=ntip-$run_id-lan
work=/tmp/ntip-integration-$run_id

case "$work" in
    /tmp/ntip-integration-[A-Za-z0-9]*) ;;
    *)
        echo "refusing unsafe integration work path: $work" >&2
        exit 2
        ;;
esac

if [ -e "$work" ]; then
    echo "integration work path already exists: $work" >&2
    exit 3
fi

for namespace in "$master_ns" "$node1_ns" "$node2_ns" "$nat_ns" "$lan_ns"; do
    if ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null 2>&1; then
        echo "network namespace already exists: $namespace" >&2
        exit 3
    fi
done

daemon_pids=
created_namespaces=
passed=0

dump_failure_diagnostics() {
    [ -d "$work/logs" ] || return
    {
        printf 'NTIP namespace integration failure diagnostics\n'
        if [ -n "${server_args:-}" ]; then
            printf '\nSERVER STATUS\n'
            # shellcheck disable=SC2086
            "$ntsrv" $server_args status --json
            # shellcheck disable=SC2086
            "$ntsrv" $server_args node show node01 --json
            # shellcheck disable=SC2086
            "$ntsrv" $server_args node show node02 --json
        fi
        if [ -n "${node1_args:-}" ]; then
            printf '\nNODE 1 STATUS\n'
            # shellcheck disable=SC2086
            "$ntcl" $node1_args status --json
        fi
        if [ -n "${node2_args:-}" ]; then
            printf '\nNODE 2 STATUS\n'
            # shellcheck disable=SC2086
            "$ntcl" $node2_args status --json
        fi
        for namespace in "$master_ns" "$node1_ns" "$node2_ns" "$nat_ns" "$lan_ns"; do
            if ! ip netns list | awk '{print $1}' | grep -Fx "$namespace" >/dev/null 2>&1; then
                continue
            fi
            printf '\nNAMESPACE %s LINKS AND ADDRESSES\n' "$namespace"
            ip -s -n "$namespace" address show
            printf '\nNAMESPACE %s ROUTES\n' "$namespace"
            ip -n "$namespace" route show table all
            printf '\nNAMESPACE %s UDP SOCKETS\n' "$namespace"
            ip netns exec "$namespace" ss -uapn
        done
    } >"$work/logs/diagnostics.log" 2>&1
    cat "$work/logs/diagnostics.log" >&2
}

cleanup() {
    set +e
    if [ "$passed" -ne 1 ]; then
        dump_failure_diagnostics
    fi
    for pid in $daemon_pids; do
        kill -TERM "$pid" >/dev/null 2>&1 || true
    done
    for pid in $daemon_pids; do
        wait "$pid" >/dev/null 2>&1 || true
    done
    for namespace in $created_namespaces; do
        ip netns delete "$namespace" >/dev/null 2>&1 || true
    done
    if [ "${NTIP_KEEP_FAILED:-0}" = 1 ] && [ "$passed" -ne 1 ]; then
        echo "preserved failed integration artifacts: $work" >&2
    else
        case "$work" in
            /tmp/ntip-integration-[A-Za-z0-9]*) rm -rf --one-file-system "$work" ;;
        esac
    fi
}
trap cleanup EXIT INT TERM HUP

mkdir -m 0755 "$work"
mkdir -m 0755 "$work/logs"

for namespace in "$master_ns" "$node1_ns" "$node2_ns" "$nat_ns" "$lan_ns"; do
    ip netns add "$namespace"
    created_namespaces="$namespace $created_namespaces"
    ip -n "$namespace" link set lo up
done

link_index=0
make_link() {
    left_ns=$1
    left_if=$2
    left_address=$3
    right_ns=$4
    right_if=$5
    right_address=$6

    link_index=$((link_index + 1))
    left_tmp=v${short_id}${link_index}a
    right_tmp=v${short_id}${link_index}b

    ip link add "$left_tmp" type veth peer name "$right_tmp"
    ip link set "$left_tmp" netns "$left_ns"
    ip link set "$right_tmp" netns "$right_ns"
    ip -n "$left_ns" link set "$left_tmp" name "$left_if"
    ip -n "$right_ns" link set "$right_tmp" name "$right_if"
    ip -n "$left_ns" address add "$left_address" dev "$left_if"
    ip -n "$right_ns" address add "$right_address" dev "$right_if"
    ip -n "$left_ns" link set "$left_if" up
    ip -n "$right_ns" link set "$right_if" up
}

make_link "$master_ns" mn1 198.18.0.1/30 \
    "$node1_ns" n1wan 198.18.0.2/30
make_link "$master_ns" mnat 198.18.1.1/29 \
    "$nat_ns" natwan 198.18.1.2/29
make_link "$nat_ns" natin 192.0.2.1/30 \
    "$node2_ns" n2wan 192.0.2.2/30
make_link "$node1_ns" n1lan 192.168.178.1/24 \
    "$lan_ns" lan0 192.168.178.20/24

ip -n "$node1_ns" route add default via 198.18.0.1
ip -n "$nat_ns" route add default via 198.18.1.1
ip -n "$node2_ns" route add default via 192.0.2.1
ip -n "$lan_ns" route add default via 192.168.178.1

ip netns exec "$master_ns" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$nat_ns" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$node1_ns" sysctl -q -w net.ipv4.ip_forward=1

ip netns exec "$nat_ns" nft -f - <<'EOF'
table ip ntip_test_nat {
    chain forward {
        type filter hook forward priority filter; policy accept;
    }
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "natwan" ip saddr 192.0.2.0/30 masquerade
    }
}
EOF

for role in server node1 node2; do
    install -d -o ntip -g ntip -m 0700 "$work/$role-state"
    install -d -o root -g ntip-admin -m 0770 "$work/$role-run"
done
install -d -o ntip -g ntip-api -m 0750 "$work/api-run"

service_socket=$work/api-run/ntsrv-api.sock
jq --arg service_socket "$service_socket" \
    --arg public_endpoint "198.18.1.1:49152" \
    '.service_socket_path = $service_socket | .public_udp_endpoint = $public_endpoint' \
    "$repo_root/packaging/config/server.json" >"$work/server.json"
chmod 0644 "$work/server.json"

# The namespace scenario exercises the real anonymous redemption bridge. The
# archives are immutable metadata only here; archive payload validation has a
# separate release/installer gate.
jq -n '{
    schema_version: 1,
    version: "0.2.0-dev",
    archives: [
        {
            target: "x86_64-linux-musl",
            file: "ntip-node-v0.2.0-dev-x86_64-linux-musl.tar.gz",
            sha256: ("a" * 64),
            size_bytes: 1
        },
        {
            target: "aarch64-linux-musl",
            file: "ntip-node-v0.2.0-dev-aarch64-linux-musl.tar.gz",
            sha256: ("b" * 64),
            size_bytes: 1
        }
    ]
}' >"$work/bootstrap-assets.json"
chmod 0644 "$work/bootstrap-assets.json"

jq -n \
    --arg service_socket "$service_socket" \
    --arg manifest "$work/bootstrap-assets.json" \
    '{
        schema_version: 2,
        bind_address: "127.0.0.1",
        port: 8787,
        service_socket: $service_socket,
        public_https_origin: "https://198.18.1.1",
        bootstrap_spki_pin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        bootstrap_manifest_path: $manifest,
        workers: 2,
        maximum_connections: 16
    }' >"$work/api.json"
chmod 0644 "$work/api.json"

server_args="--config $work/server.json --state-dir $work/server-state --runtime-dir $work/server-run"
node1_args="--config $work/node1.json --state-dir $work/node1-state --runtime-dir $work/node1-run"
node2_args="--config $work/node2.json --state-dir $work/node2-state --runtime-dir $work/node2-run"

# Offline administrative setup.
# shellcheck disable=SC2086
"$ntsrv" $server_args vnr create vnr0 10.1.0.0/24
# shellcheck disable=SC2086
"$ntsrv" $server_args node create node01 --vnr vnr0 --addr 10.1.0.2 \
    --bootstrap-out "$work/node01.bootstrap.json"
# shellcheck disable=SC2086
"$ntsrv" $server_args node create node02 --vnr vnr0 --addr 10.1.0.3 \
    --bootstrap-out "$work/node02.bootstrap.json"
# shellcheck disable=SC2086
"$ntsrv" $server_args route add 192.168.178.0/24 node01

chown -R ntip:ntip "$work/server-state" "$work/node1-state" "$work/node2-state"
chmod 0700 "$work/server-state" "$work/node1-state" "$work/node2-state"

# An operator-owned interface is never adopted or removed. The daemon must
# fail promptly and leave the pre-existing link untouched.
ip -n "$master_ns" link add ntip0 type dummy
set +e
# shellcheck disable=SC2086
timeout 5 ip netns exec "$master_ns" "$ntsrv" $server_args up \
    >"$work/logs/operator-interface-collision.log" 2>&1
collision_code=$?
set -e
if [ "$collision_code" -eq 0 ]; then
    echo "ntsrv unexpectedly adopted an operator-owned ntip0" >&2
    exit 1
fi
if [ "$collision_code" -eq 124 ]; then
    echo "ntsrv did not fail promptly on an operator-owned ntip0" >&2
    exit 1
fi
ip -d -n "$master_ns" link show dev ntip0 | grep -F "dummy" >/dev/null
ip -n "$master_ns" link delete dev ntip0

start_master() {
    # shellcheck disable=SC2086
    ip netns exec "$master_ns" "$ntsrv" $server_args up \
        >"$work/logs/ntsrv.log" 2>&1 &
    master_pid=$!
    daemon_pids="$master_pid $daemon_pids"
}

start_api() {
    ip netns exec "$master_ns" runuser -u ntip-api -- \
        "$ntip_api" --config "$work/api.json" \
        >"$work/logs/ntip-api.log" 2>&1 &
    api_pid=$!
    daemon_pids="$api_pid $daemon_pids"
}

wait_api() {
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        if ip netns exec "$master_ns" curl -q --http1.1 --fail --silent \
            --show-error --connect-timeout 1 --max-time 2 \
            http://127.0.0.1:8787/api/v1/health/ready 2>/dev/null | \
            jq -e '.status == "ready" and .databaseSchemaVersion == 2' >/dev/null 2>&1
        then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.25
    done
    echo "ntip-api readiness timed out" >&2
    tail -n 200 "$work/logs/ntip-api.log" >&2 || true
    return 1
}

redeem_invitation() {
    invitation=$1
    jq -c '{bootstrapId: .bootstrapId, secretCode: .secretCode}' "$invitation" | \
        ip netns exec "$master_ns" curl -q --http1.1 --fail --silent --show-error \
            --connect-timeout 2 --max-time 10 --request POST \
            --header 'Content-Type: application/json' \
            --header 'Accept: application/json' --data-binary @- \
            http://127.0.0.1:8787/enrollment/v1/redeem
}

configure_nodes_from_bootstrap() {
    if [ "$compatibility_only" -eq 1 ]; then
        # The pinned v0.1 binary predates bootstrap-import. This test-only
        # adapter extracts the unchanged internal credential from the real
        # redemption response and feeds it over stdin; no operator-facing
        # long-credential issuance surface is restored.
        # shellcheck disable=SC2086
        redeem_invitation "$work/node01.bootstrap.json" | \
            jq -er '.enrollmentCredential' | \
            "$ntcl" $node1_args config 198.18.1.1:49152 node01 --credential-stdin
        # shellcheck disable=SC2086
        redeem_invitation "$work/node02.bootstrap.json" | \
            jq -er '.enrollmentCredential' | \
            "$ntcl" $node2_args config 198.18.1.1:49152 node02 --credential-stdin
    else
        # Current Nodes consume the complete strict bundle directly without
        # retaining the internal credential in a shell variable or file.
        # shellcheck disable=SC2086
        redeem_invitation "$work/node01.bootstrap.json" | \
            "$ntcl" $node1_args bootstrap-import --stdin
        # shellcheck disable=SC2086
        redeem_invitation "$work/node02.bootstrap.json" | \
            "$ntcl" $node2_args bootstrap-import --stdin
    fi
    chown -R ntip:ntip "$work/node1-state" "$work/node2-state"
    chown ntip:ntip "$work/node1.json" "$work/node2.json"
    chmod 0700 "$work/node1-state" "$work/node2-state"
    chmod 0600 "$work/node1.json" "$work/node2.json"
}

start_nodes() {
    # shellcheck disable=SC2086
    ip netns exec "$node1_ns" "$ntcl" $node1_args up \
        >"$work/logs/ntcl-node1.log" 2>&1 &
    node1_pid=$!
    daemon_pids="$node1_pid $daemon_pids"

    # shellcheck disable=SC2086
    ip netns exec "$node2_ns" "$ntcl" $node2_args up \
        >"$work/logs/ntcl-node2.log" 2>&1 &
    node2_pid=$!
    daemon_pids="$node2_pid $daemon_pids"
}

wait_status() {
    binary=$1
    args=$2
    socket=$3
    attempts=0
    while [ "$attempts" -lt 120 ]; do
        # shellcheck disable=SC2086
        if [ -S "$socket" ] && "$binary" $args status --json 2>/dev/null | \
            jq -e '.state != "stopped"' >/dev/null 2>&1
        then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.25
    done
    echo "daemon readiness timed out; logs follow" >&2
    tail -n 200 "$work"/logs/*.log >&2 || true
    return 1
}

wait_node_online() {
    node_name=$1
    attempts=0
    while [ "$attempts" -lt 300 ]; do
        # shellcheck disable=SC2086
        if "$ntsrv" $server_args node show "$node_name" --json 2>/dev/null | \
            jq -e '.node.state == "online"' >/dev/null 2>&1; then
            return 0
        fi
        attempts=$((attempts + 1))
        sleep 0.25
    done
    echo "Node did not become online: $node_name" >&2
    tail -n 200 "$work"/logs/*.log >&2 || true
    return 1
}

assert_daemon_privileges() {
    pid=$1
    expected_uid=$(id -u ntip)
    actual_uid=$(awk '/^Uid:/ { print $2 }' "/proc/$pid/status")
    effective_caps=$(awk '/^CapEff:/ { print $2 }' "/proc/$pid/status")
    permitted_caps=$(awk '/^CapPrm:/ { print $2 }' "/proc/$pid/status")
    if [ "$actual_uid" != "$expected_uid" ]; then
        echo "daemon $pid did not drop to ntip (uid $actual_uid)" >&2
        return 1
    fi
    if [ "$effective_caps" != 0000000000001000 ] || \
        [ "$permitted_caps" != 0000000000001000 ]; then
        echo "daemon $pid retained unexpected capabilities" >&2
        grep '^Cap' "/proc/$pid/status" >&2
        return 1
    fi
}

assert_socket_mode() {
    socket=$1
    actual=$(stat -c '%U:%G:%a' "$socket")
    if [ "$actual" != root:ntip-admin:660 ]; then
        echo "unexpected IPC socket ownership/mode for $socket: $actual" >&2
        return 1
    fi
}

restart_master_and_assert_reconnect() {
    # A Master restart discards sessions. Persisted Nodes must reconnect with
    # fresh IK, including when `$ntcl` is the pinned v0.1 binary.
    # shellcheck disable=SC2086
    "$ntsrv" $server_args down
    wait "$master_pid" || true
    daemon_pids=$(printf '%s\n' "$daemon_pids" | tr ' ' '\n' | \
        grep -v "^$master_pid$" | tr '\n' ' ')
    start_master
    wait_status "$ntsrv" "$server_args" "$work/server-run/ntsrv.sock"
    wait_node_online node01
    wait_node_online node02
    ip netns exec "$node1_ns" ping -n -c 3 -W 2 10.1.0.3
}

start_master
wait_status "$ntsrv" "$server_args" "$work/server-run/ntsrv.sock"
assert_daemon_privileges "$master_pid"
assert_socket_mode "$work/server-run/ntsrv.sock"
start_api
wait_api
configure_nodes_from_bootstrap

# A duplicate lifetime lock must fail promptly.
# shellcheck disable=SC2086
if timeout 5 "$ntsrv" $server_args up >/dev/null 2>&1; then
    echo "duplicate ntsrv start unexpectedly succeeded" >&2
    exit 1
fi

start_nodes
wait_status "$ntcl" "$node1_args" "$work/node1-run/ntcl.sock"
wait_status "$ntcl" "$node2_args" "$work/node2-run/ntcl.sock"
assert_daemon_privileges "$node1_pid"
assert_daemon_privileges "$node2_pid"
assert_socket_mode "$work/node1-run/ntcl.sock"
assert_socket_mode "$work/node2-run/ntcl.sock"
wait_node_online node01
wait_node_online node02

if [ "$compatibility_only" -eq 0 ]; then
    if [ -e "$work/node1-state/bootstrap.id" ] || [ -e "$work/node2-state/bootstrap.id" ]; then
        echo "authenticated enrollment did not clear the bootstrap marker" >&2
        exit 1
    fi
fi

if [ "$compatibility_only" -eq 1 ]; then
    # This focused mode is run with a client built from the pinned v0.1 base
    # commit. Reaching both addresses proves enrollment and DATA transport;
    # the restart assertion below proves persisted-state IK reconnect.
    ip netns exec "$master_ns" ping -n -c 3 -W 2 10.1.0.2
    ip netns exec "$master_ns" ping -n -c 3 -W 2 10.1.0.3
    restart_master_and_assert_reconnect
    passed=1
    echo "NTIP v0.1 Node enrollment and reconnect compatibility passed"
    exit 0
fi

# ICMP through every functional path.
ip netns exec "$master_ns" ping -n -c 3 -W 2 10.1.0.2
ip netns exec "$master_ns" ping -n -c 3 -W 2 10.1.0.3
ip netns exec "$node1_ns" ping -n -c 3 -W 2 10.1.0.3
ip netns exec "$master_ns" ping -n -c 3 -W 2 192.168.178.20

# TCP and UDP, including Node-to-Node through Master kernel routing. Keep the
# server in the foreground so its PID remains owned by this scenario; iperf3's
# daemon mode reparents itself and can otherwise outlive namespace teardown.
ip netns exec "$node1_ns" iperf3 -s -B 10.1.0.2 -p 5201 \
    >"$work/logs/iperf3-node1.log" 2>&1 &
iperf_pid=$!
daemon_pids="$iperf_pid $daemon_pids"
sleep 0.5
ip netns exec "$master_ns" iperf3 -c 10.1.0.2 -p 5201 -t 2
ip netns exec "$node2_ns" iperf3 -c 10.1.0.2 -p 5201 -t 2
ip netns exec "$node2_ns" iperf3 -c 10.1.0.2 -p 5201 -u -b 10M -t 2

# Master nftables remains authoritative for inter-Node firewall policy.
ip netns exec "$master_ns" nft -f - <<'EOF'
table inet ntip_test_filter {
    chain forward {
        type filter hook forward priority filter; policy accept;
        iifname "ntip0" oifname "ntip0" ip saddr 10.1.0.3 ip daddr 10.1.0.2 \
            icmp type echo-request drop
    }
}
EOF
if ip netns exec "$node2_ns" ping -n -c 1 -W 1 10.1.0.2 >/dev/null 2>&1; then
    echo "Master firewall denial did not block Node-to-Node ICMP" >&2
    exit 1
fi
ip netns exec "$master_ns" nft delete table inet ntip_test_filter

# DNAT from the Master underlay reaches the Node service through ntip0.
ip netns exec "$master_ns" nft -f - <<'EOF'
table ip ntip_test_dnat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "mnat" tcp dport 5443 dnat to 10.1.0.2:5201
    }
}
EOF
ip netns exec "$node2_ns" iperf3 -c 198.18.1.1 -p 5443 -t 2
ip netns exec "$master_ns" nft delete table ip ntip_test_dnat

# Deterministic round-robin DNAT exercises Linux load balancing and conntrack;
# NTIP remains unaware of the policy. Separate HTTP response bodies prove that
# both backends were selected without relying on iperf3's single-daemon state.
install -d -m 0755 "$work/backend-node1" "$work/backend-node2"
printf 'node01\n' >"$work/backend-node1/index.html"
printf 'node02\n' >"$work/backend-node2/index.html"
ip netns exec "$node1_ns" python3 -m http.server 5444 --bind 10.1.0.2 \
    --directory "$work/backend-node1" >"$work/logs/backend-node1.log" 2>&1 &
backend1_pid=$!
daemon_pids="$backend1_pid $daemon_pids"
ip netns exec "$node2_ns" python3 -m http.server 5444 --bind 10.1.0.3 \
    --directory "$work/backend-node2" >"$work/logs/backend-node2.log" 2>&1 &
backend2_pid=$!
daemon_pids="$backend2_pid $daemon_pids"
sleep 0.5
ip netns exec "$master_ns" nft -f - <<'EOF'
table ip ntip_test_lb {
    map backends {
        type mark : ipv4_addr
        elements = { 0 : 10.1.0.2, 1 : 10.1.0.3 }
    }
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "mn1" tcp dport 5444 \
            dnat to numgen inc mod 2 map @backends
    }
    # Preserve a symmetric conntrack path even when the selected backend is
    # node01, whose LAN contains the test client. This is ordinary Linux
    # load-balancer policy; NTIP does not synthesize it.
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "ntip0" ip daddr 10.1.0.0/24 tcp dport 5444 snat to 10.1.0.1
    }
}
EOF
load_balancer_results=$work/load-balancer-results.txt
for _ in 1 2 3 4; do
    ip netns exec "$lan_ns" python3 -c '
import socket
s = socket.create_connection(("198.18.0.1", 5444), timeout=5)
s.sendall(b"GET / HTTP/1.0\r\nHost: ntip-test\r\n\r\n")
response = b"".join(iter(lambda: s.recv(4096), b""))
s.close()
print(response.split(b"\r\n\r\n", 1)[1].decode().strip())
' >>"$load_balancer_results"
done
grep -Fx node01 "$load_balancer_results" >/dev/null
grep -Fx node02 "$load_balancer_results" >/dev/null
ip netns exec "$master_ns" conntrack -L -p tcp --dport 5444 \
    >"$work/load-balancer-conntrack.txt"
grep -F 'src=10.1.0.2' "$work/load-balancer-conntrack.txt" >/dev/null
grep -F 'src=10.1.0.3' "$work/load-balancer-conntrack.txt" >/dev/null
ip netns exec "$master_ns" nft delete table ip ntip_test_lb

# Change the NAT's authenticated outer source. PATH_CHALLENGE/PATH_RESPONSE must
# validate it before the Master commits the candidate endpoint.
ip -n "$nat_ns" address del 198.18.1.2/29 dev natwan
ip -n "$nat_ns" address add 198.18.1.3/29 dev natwan
ip netns exec "$nat_ns" conntrack -F >/dev/null
ip netns exec "$node2_ns" ping -n -c 5 -W 2 10.1.0.1

attempts=0
while [ "$attempts" -lt 120 ]; do
    # shellcheck disable=SC2086
    if "$ntsrv" $server_args node show node02 --json 2>/dev/null | \
        jq -e '.node.endpoint | startswith("198.18.1.3:")' >/dev/null 2>&1; then
        break
    fi
    attempts=$((attempts + 1))
    sleep 0.25
done
if [ "$attempts" -eq 120 ]; then
    echo "roamed endpoint was not committed" >&2
    exit 1
fi

# Loss, delay, duplicate, and reorder remain within the reconnect behavior.
ip netns exec "$nat_ns" tc qdisc replace dev natwan root netem \
    delay 20ms 5ms loss 5% duplicate 2% reorder 10% 50%
ip netns exec "$node2_ns" ping -n -c 20 -W 2 10.1.0.1
ip netns exec "$nat_ns" tc qdisc delete dev natwan root

# MTU boundary: IPv4 + ICMP headers (28 bytes) plus 1352-byte payload = 1380.
ip netns exec "$master_ns" ping -n -M "do" -s 1352 -c 1 -W 2 10.1.0.2
if ip netns exec "$master_ns" ping -n -M "do" -s 1353 -c 1 -W 1 \
    10.1.0.2 >/dev/null 2>&1; then
    echo "oversize inner packet unexpectedly crossed the 1380-byte MTU" >&2
    exit 1
fi

# Force an outer IPv4 EMSGSIZE below the configured NTIP envelope. The data
# worker must inject an ICMPv4 fragmentation-needed reply for the exact-MTU
# inner packet instead of fragmenting or silently hanging the sender.
ip -n "$master_ns" link set dev mn1 mtu 1400
set +e
icmp_output=$(ip netns exec "$master_ns" ping -n -M "do" -s 1352 -c 1 -W 2 \
    10.1.0.2 2>&1)
icmp_code=$?
set -e
ip -n "$master_ns" link set dev mn1 mtu 1500
printf '%s\n' "$icmp_output" >"$work/logs/icmp-fragmentation-needed.log"
if [ "$icmp_code" -eq 0 ]; then
    echo "outer MTU failure unexpectedly delivered the packet" >&2
    exit 1
fi
if ! grep -E "Frag needed|[Mm]essage too long" \
    "$work/logs/icmp-fragmentation-needed.log" >/dev/null; then
    echo "outer EMSGSIZE did not produce a visible fragmentation-needed error" >&2
    cat "$work/logs/icmp-fragmentation-needed.log" >&2
    exit 1
fi

restart_master_and_assert_reconnect

passed=1
echo "NTIP namespace integration passed"
