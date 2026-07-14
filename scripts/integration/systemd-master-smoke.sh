#!/bin/sh
set -eu

if [ "${NTIP_SYSTEMD_SMOKE_DISPOSABLE:-0}" != 1 ]; then
    echo "refusing systemd smoke without NTIP_SYSTEMD_SMOKE_DISPOSABLE=1" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "systemd smoke must run as root on a disposable host" >&2
    exit 1
fi
for command in awk find getent grep id ip jq journalctl stat systemctl; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required systemd smoke command not found: $command" >&2
        exit 1
    fi
done
for path in /usr/bin/ntsrv /usr/lib/systemd/system/ntsrv.service \
    /etc/ntip/server.json /var/lib/ntip/server
do
    if [ ! -e "$path" ]; then
        echo "required installed NTIP path not found: $path" >&2
        exit 1
    fi
done
if systemctl is-active --quiet ntsrv.service || systemctl is-active --quiet ntcl.service; then
    echo "refusing to disturb an active NTIP service" >&2
    exit 3
fi
if [ -n "$(find /var/lib/ntip/server -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "systemd smoke requires an empty disposable server state directory" >&2
    exit 3
fi

cleanup() {
    set +e
    systemctl stop ntsrv.service >/dev/null 2>&1
    systemctl reset-failed ntsrv.service >/dev/null 2>&1
}
trap cleanup EXIT INT TERM HUP

systemctl reset-failed ntsrv.service
systemctl start ntsrv.service

attempts=0
status_json=
while [ "$attempts" -lt 100 ]; do
    status_json=$(/usr/bin/ntsrv status --json 2>/dev/null) && break
    if systemctl is-failed --quiet ntsrv.service; then
        echo "ntsrv failed during systemd smoke" >&2
        journalctl -u ntsrv.service -n 100 --no-pager >&2
        exit 1
    fi
    attempts=$((attempts + 1))
    sleep 0.1
done
if [ -z "$status_json" ]; then
    echo "ntsrv readiness timed out during systemd smoke" >&2
    journalctl -u ntsrv.service -n 100 --no-pager >&2
    exit 1
fi
printf '%s\n' "$status_json" | jq -e '.state == "running"' >/dev/null

pid=$(systemctl show -p MainPID --value ntsrv.service)
case "$pid" in
    ''|*[!0-9]*|0)
        echo "systemd did not report a live ntsrv PID" >&2
        exit 1
        ;;
esac
expected_uid=$(id -u ntip)
expected_gid=$(id -g ntip)
expected_admin_gid=$(getent group ntip-admin | awk -F: '{ print $3 }')
actual_uid=$(awk '/^Uid:/ { print $2 }' "/proc/$pid/status")
actual_gid=$(awk '/^Gid:/ { print $2 }' "/proc/$pid/status")
if [ "$actual_uid" != "$expected_uid" ]; then
    echo "ntsrv did not drop to ntip (uid $actual_uid)" >&2
    exit 1
fi
if [ "$actual_gid" != "$expected_gid" ]; then
    echo "ntsrv did not drop to the ntip primary group (gid $actual_gid)" >&2
    exit 1
fi
if ! awk -v gid="$expected_admin_gid" '
    /^Groups:/ {
        for (index = 2; index <= NF; index += 1) {
            if ($index == gid) found = 1
        }
    }
    END { exit(found ? 0 : 1) }
' "/proc/$pid/status"; then
    echo "ntsrv did not retain the ntip-admin supplementary group" >&2
    exit 1
fi
if [ "$(awk '/^NoNewPrivs:/ { print $2 }' "/proc/$pid/status")" != 1 ]; then
    echo "ntsrv did not enable no_new_privs after startup" >&2
    exit 1
fi
for field in CapInh CapPrm CapEff CapAmb; do
    value=$(awk -v field="$field:" '$1 == field { print $2 }' "/proc/$pid/status")
    if [ "$value" != 0000000000001000 ]; then
        echo "ntsrv retained unexpected $field value: $value" >&2
        grep '^Cap' "/proc/$pid/status" >&2
        exit 1
    fi
done
if [ "$(stat -c '%U:%G:%a' /run/ntip)" != root:ntip-admin:770 ]; then
    echo "unexpected /run/ntip ownership or mode" >&2
    stat -c '%U:%G:%a %n' /run/ntip >&2
    exit 1
fi
if [ "$(stat -c '%U:%G:%a' /run/ntip/ntsrv.sock)" != root:ntip-admin:660 ]; then
    echo "unexpected ntsrv IPC ownership or mode" >&2
    stat -c '%U:%G:%a %n' /run/ntip/ntsrv.sock >&2
    exit 1
fi
if ! ip link show ntip0 >/dev/null 2>&1; then
    echo "ntsrv did not create ntip0" >&2
    exit 1
fi

systemctl stop ntsrv.service
if ip link show ntip0 >/dev/null 2>&1; then
    echo "ntip0 survived systemd service shutdown" >&2
    exit 1
fi
if [ -S /run/ntip/ntsrv.sock ]; then
    echo "ntsrv IPC socket survived systemd service shutdown" >&2
    exit 1
fi

printf 'NTIP systemd Master smoke passed pid=%s post_drop_caps=CAP_NET_ADMIN\n' "$pid"
