#!/bin/sh
set -eu

if [ -z "${NTIP_BIN_DIR:-}" ]; then
    echo "NTIP_BIN_DIR must name a directory containing ntsrv and ntcl" >&2
    exit 2
fi
case "$NTIP_BIN_DIR" in
    /*) ;;
    *)
        echo "NTIP_BIN_DIR must be absolute" >&2
        exit 2
        ;;
esac
for binary in ntsrv ntcl; do
    if [ ! -x "$NTIP_BIN_DIR/$binary" ]; then
        echo "missing executable: $NTIP_BIN_DIR/$binary" >&2
        exit 1
    fi
done
for command in unshare mount ip install sed grep sleep find; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required user-namespace smoke command not found: $command" >&2
        exit 1
    fi
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/../.." && pwd)

if [ "$(id -u)" -ne 0 ]; then
    work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-userns.XXXXXX")
    sed 's/^root:/ntip:/' /etc/passwd >"$work/passwd"
    sed 's/^root:/ntip-admin:/' /etc/group >"$work/group"
    chmod 0600 "$work/passwd" "$work/group"

    status=0
    NTIP_USERNS_WORK="$work" unshare -Urnm "$0" || status=$?
    find "$work" -xdev -depth -delete
    exit "$status"
fi

work=${NTIP_USERNS_WORK:?NTIP_USERNS_WORK is required inside the namespace}
daemon_pid=
cleanup() {
    set +e
    if [ -n "$daemon_pid" ]; then
        kill -TERM "$daemon_pid" >/dev/null 2>&1 || true
        wait "$daemon_pid" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM HUP

# The mount namespace disappears with this process. These bind mounts never
# alter the host's account database; uid/gid zero are mapped to the invoking
# unprivileged user solely inside this user namespace.
mount --make-rprivate /
mount --bind "$work/passwd" /etc/passwd
mount --bind "$work/group" /etc/group

state_dir=$work/state
runtime_dir=$work/run
install -d -m 0700 "$state_dir"
install -d -m 0770 "$runtime_dir"
server_args="--config $repo_root/packaging/config/server.json --state-dir $state_dir --runtime-dir $runtime_dir"

# shellcheck disable=SC2086
"$NTIP_BIN_DIR/ntsrv" $server_args vnr create vnr0 10.30.0.0/24
# shellcheck disable=SC2086
"$NTIP_BIN_DIR/ntsrv" $server_args up >"$work/ntsrv.log" 2>&1 &
daemon_pid=$!

attempts=0
while [ "$attempts" -lt 100 ]; do
    if [ -S "$runtime_dir/ntsrv.sock" ]; then
        break
    fi
    if ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
        echo "ntsrv exited during user-namespace startup" >&2
        sed -n '1,200p' "$work/ntsrv.log" >&2
        exit 1
    fi
    attempts=$((attempts + 1))
    sleep 0.1
done
if [ ! -S "$runtime_dir/ntsrv.sock" ]; then
    echo "ntsrv user-namespace readiness timed out" >&2
    sed -n '1,200p' "$work/ntsrv.log" >&2
    exit 1
fi

# shellcheck disable=SC2086
status_json=$("$NTIP_BIN_DIR/ntsrv" $server_args status --json)
printf '%s\n' "$status_json"
printf '%s\n' "$status_json" | grep -F '"state":"running"' >/dev/null
ip -d link show dev ntip0
ip address show dev ntip0 | grep -F 'inet 10.30.0.1/24' >/dev/null

# shellcheck disable=SC2086
"$NTIP_BIN_DIR/ntsrv" $server_args down
wait "$daemon_pid"
daemon_pid=
if ip link show dev ntip0 >/dev/null 2>&1; then
    echo "ntip0 survived daemon shutdown" >&2
    exit 1
fi
printf 'NTIP unprivileged user-namespace smoke passed\n'
