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
for command in awk curl find getent grep id ip jq journalctl stat systemctl; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required systemd smoke command not found: $command" >&2
        exit 1
    fi
done
for path in /usr/bin/ntsrv /usr/bin/ntip-api \
    /usr/lib/systemd/system/ntsrv.service \
    /usr/lib/systemd/system/ntip-api.service \
    /etc/ntip/server.json /etc/ntip/api.json \
    /etc/ntip/bootstrap-assets.json /usr/share/ntip/bootstrap-assets \
    /var/lib/ntip/server
do
    if [ ! -e "$path" ]; then
        echo "required installed NTIP path not found: $path" >&2
        exit 1
    fi
done
if systemctl is-active --quiet ntsrv.service || \
    systemctl is-active --quiet ntcl.service || \
    systemctl is-active --quiet ntip-api.service
then
    echo "refusing to disturb an active NTIP service" >&2
    exit 3
fi
if [ -n "$(find /var/lib/ntip/server -mindepth 1 -maxdepth 1 -print -quit)" ]; then
    echo "systemd smoke requires an empty disposable server state directory" >&2
    exit 3
fi
if [ "$(stat -c '%U:%G:%a' /etc/ntip/bootstrap-assets.json)" != root:ntip-api:640 ]; then
    echo "unexpected bootstrap-assets manifest ownership or mode" >&2
    stat -c '%U:%G:%a %n' /etc/ntip/bootstrap-assets.json >&2
    exit 1
fi
if [ "$(stat -c '%U:%G:%a' /usr/share/ntip/bootstrap-assets)" != root:root:755 ]; then
    echo "unexpected bootstrap-assets directory ownership or mode" >&2
    stat -c '%U:%G:%a %n' /usr/share/ntip/bootstrap-assets >&2
    exit 1
fi

cleanup() {
    set +e
    systemctl stop ntip-api.service >/dev/null 2>&1
    systemctl stop ntsrv.service >/dev/null 2>&1
    systemctl reset-failed ntip-api.service >/dev/null 2>&1
    systemctl reset-failed ntsrv.service >/dev/null 2>&1
}
trap cleanup EXIT INT TERM HUP

reset_failed_if_needed() {
    unit=$1
    if systemctl is-failed --quiet "$unit"; then
        systemctl reset-failed "$unit"
    fi
}

reset_failed_if_needed ntsrv.service
systemctl start ntsrv.service

attempts=0
status_json=
while [ "$attempts" -lt 100 ]; do
    if [ -S /run/ntip/ntsrv.sock ] && \
        status_candidate=$(/usr/bin/ntsrv status --json 2>/dev/null) && \
        printf '%s\n' "$status_candidate" | jq -e '.state == "running"' >/dev/null
    then
        status_json=$status_candidate
        break
    fi
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
        for (field_index = 2; field_index <= NF; field_index += 1) {
            if ($field_index == gid) found = 1
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
if [ "$(stat -c '%U:%G:%a' /run/ntip-api)" != ntip:ntip-api:750 ]; then
    echo "unexpected /run/ntip-api ownership or mode" >&2
    stat -c '%U:%G:%a %n' /run/ntip-api >&2
    exit 1
fi
if [ "$(stat -c '%U:%G:%a' /run/ntip-api/ntsrv-api.sock)" != ntip:ntip-api:660 ]; then
    echo "unexpected typed service IPC ownership or mode" >&2
    stat -c '%U:%G:%a %n' /run/ntip-api/ntsrv-api.sock >&2
    exit 1
fi
if ! ip link show ntip0 >/dev/null 2>&1; then
    echo "ntsrv did not create ntip0" >&2
    exit 1
fi

# Starting the separately installed DB-free HTTP tier and reaching readiness
# proves the packaged binary can execute under its confined identity and that
# ntsrv accepts its numeric SO_PEERCRED identity on the typed Unix socket.
reset_failed_if_needed ntip-api.service
systemctl start ntip-api.service
attempts=0
api_ready=
while [ "$attempts" -lt 100 ]; do
    api_ready=$(curl --fail --silent --show-error --max-time 2 \
        http://127.0.0.1:8787/api/v1/health/ready 2>/dev/null) && break
    if systemctl is-failed --quiet ntip-api.service; then
        echo "ntip-api failed during systemd smoke" >&2
        journalctl -u ntip-api.service -n 100 --no-pager >&2
        exit 1
    fi
    attempts=$((attempts + 1))
    sleep 0.1
done
if [ -z "$api_ready" ]; then
    echo "ntip-api readiness timed out during systemd smoke" >&2
    journalctl -u ntip-api.service -n 100 --no-pager >&2
    journalctl -u ntsrv.service -n 100 --no-pager >&2
    exit 1
fi
printf '%s\n' "$api_ready" | jq -e \
    '.status == "ready" and .ntsrv == "ready" and .databaseSchemaVersion == 2' \
    >/dev/null
curl --fail --silent --show-error --max-time 2 \
    http://127.0.0.1:8787/api/v1/health/live \
    | jq -e '.status == "live"' >/dev/null
curl --fail --silent --show-error --max-time 2 \
    http://127.0.0.1:8787/api/v1/openapi.json \
    | jq -e '.openapi == "3.1.1" and .info.version == "1.1.0"' >/dev/null

api_pid=$(systemctl show -p MainPID --value ntip-api.service)
case "$api_pid" in
    ''|*[!0-9]*|0)
        echo "systemd did not report a live ntip-api PID" >&2
        exit 1
        ;;
esac
api_uid=$(id -u ntip-api)
api_gid=$(id -g ntip-api)
actual_api_uid=$(awk '/^Uid:/ { print $2 }' "/proc/$api_pid/status")
actual_api_gid=$(awk '/^Gid:/ { print $2 }' "/proc/$api_pid/status")
if [ "$actual_api_uid" != "$api_uid" ] || [ "$actual_api_gid" != "$api_gid" ]; then
    echo "ntip-api did not run under its dedicated numeric identity" >&2
    exit 1
fi
if [ "$(awk '/^Groups:/ { print NF - 1 }' "/proc/$api_pid/status")" != 1 ]; then
    echo "ntip-api unexpectedly retained supplementary groups" >&2
    grep '^Groups:' "/proc/$api_pid/status" >&2
    exit 1
fi
for field in CapInh CapPrm CapEff CapAmb; do
    value=$(awk -v field="$field:" '$1 == field { print $2 }' "/proc/$api_pid/status")
    if [ "$value" != 0000000000000000 ]; then
        echo "ntip-api retained unexpected $field value: $value" >&2
        exit 1
    fi
done

systemctl stop ntip-api.service
systemctl stop ntsrv.service
if ip link show ntip0 >/dev/null 2>&1; then
    echo "ntip0 survived systemd service shutdown" >&2
    exit 1
fi
if [ -S /run/ntip/ntsrv.sock ]; then
    echo "ntsrv IPC socket survived systemd service shutdown" >&2
    exit 1
fi
if [ -S /run/ntip-api/ntsrv-api.sock ]; then
    echo "typed service IPC socket survived ntsrv shutdown" >&2
    exit 1
fi

printf 'NTIP systemd Master/API smoke passed ntsrv_pid=%s api_pid=%s typed_peer=SO_PEERCRED post_drop_caps=CAP_NET_ADMIN/none\n' \
    "$pid" "$api_pid"
