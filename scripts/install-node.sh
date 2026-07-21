#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
IFS=$' \t\n'
umask 077

fail() {
    printf 'NTIP Node installation refused: %s\n' "$1" >&2
    exit 1
}

usage() {
    printf 'usage: %s [--bootstrap-id ID] [--start]\n' "$0" >&2
    exit 2
}

bootstrap_id=
start_node=0
while (($# > 0)); do
    case "$1" in
        --bootstrap-id)
            (($# >= 2)) || usage
            bootstrap_id=$2
            shift 2
            ;;
        --start)
            start_node=1
            shift
            ;;
        *) usage ;;
    esac
done
if [[ -n "$bootstrap_id" && ! "$bootstrap_id" =~ ^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{8}$ ]]; then
    fail "bootstrap ID is not canonical"
fi

destdir=${DESTDIR:-}
if [[ -n "$destdir" && "$destdir" != / ]]; then
    [[ "$destdir" == /* ]] || fail "DESTDIR must be an absolute path"
    destdir=${destdir%/}
    staging=1
else
    destdir=
    staging=0
fi

root_path() {
    printf '%s%s\n' "$destdir" "$1"
}

install_dir() {
    local owner=$1 group=$2 mode=$3 destination
    destination=$(root_path "$4")
    if ((staging)); then
        install -d -m "$mode" "$destination"
    else
        install -d -o "$owner" -g "$group" -m "$mode" "$destination"
    fi
}

install_file() {
    local owner=$1 group=$2 mode=$3 source=$4 destination
    destination=$(root_path "$5")
    if ((staging)); then
        install -m "$mode" "$source" "$destination"
    else
        install -o "$owner" -g "$group" -m "$mode" "$source" "$destination"
    fi
}

require_unique_passwd_id() {
    local identity_name=$1 identity_uid=$2 matches
    matches=$(getent passwd | awk -F: -v wanted="$identity_uid" \
        '$3 == wanted { count += 1 } END { print count + 0 }')
    [[ "$matches" == 1 ]] || fail "$identity_name UID has duplicate numeric passwd aliases"
}

require_unique_group_id() {
    local identity_name=$1 identity_gid=$2 matches
    matches=$(getent group | awk -F: -v wanted="$identity_gid" \
        '$3 == wanted { count += 1 } END { print count + 0 }')
    [[ "$matches" == 1 ]] || fail "$identity_name GID has duplicate numeric group aliases"
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
package_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
for relative in \
    bin/ntcl VERSION TARGET \
    packaging/config/client.json \
    packaging/systemd/ntcl.service \
    packaging/tmpfiles/ntip-node.conf
do
    [[ -f "$package_root/$relative" && ! -L "$package_root/$relative" ]] || \
        fail "package payload is incomplete: $relative"
done
[[ -x "$package_root/bin/ntcl" ]] || fail "packaged ntcl is not executable"

version=$(<"$package_root/VERSION")
target=$(<"$package_root/TARGET")
[[ "$version" =~ ^[0-9A-Za-z][0-9A-Za-z.+-]{0,63}$ ]] || fail "package version is invalid"
case "$target" in
    x86_64-linux-musl) expected_machine=x86_64 ;;
    aarch64-linux-musl) expected_machine=aarch64 ;;
    *) fail "package target is invalid" ;;
esac

if ((staging)); then
    command -v install >/dev/null 2>&1 || fail "required command not found: install"
    install -d -m 0755 "$destdir"
    ((start_node == 0)) || fail "--start cannot be used with DESTDIR"
else
    ((EUID == 0)) || fail "installer must run as root"
    [[ -n "${BASH_VERSION:-}" ]] || fail "installer requires Bash"
    [[ $(uname -s) == Linux ]] || fail "NTIP v0.2 supports Linux only"
    for command in awk basename cmp find getent grep groupadd id install ip sleep sort stat \
        systemctl systemd-tmpfiles uname useradd usermod; do
        command -v "$command" >/dev/null 2>&1 || fail "required command not found: $command"
    done
    [[ -d /run/systemd/system ]] || fail "systemd is not the active service manager"
    [[ -c /dev/net/tun ]] || fail "TUN is unavailable at /dev/net/tun"
    [[ $(uname -m) == "$expected_machine" ]] || \
        fail "archive target $target does not match this host"
    [[ $("$package_root/bin/ntcl" version) == "ntcl $version" ]] || \
        fail "packaged ntcl version does not match VERSION"

    kernel_release=$(uname -r)
    kernel_major=${kernel_release%%.*}
    kernel_rest=${kernel_release#*.}
    kernel_minor=${kernel_rest%%.*}
    [[ "$kernel_major" =~ ^[0-9]+$ && "$kernel_minor" =~ ^[0-9]+$ ]] || \
        fail "could not parse Linux kernel release $kernel_release"
    if ((kernel_major < 6 || (kernel_major == 6 && kernel_minor < 1))); then
        fail "Linux kernel 6.1 or newer is required (found $kernel_release)"
    fi
    if ip link show dev ntip0 >/dev/null 2>&1; then
        fail "network interface ntip0 is already occupied"
    fi

    for service in ntsrv.service ntip-api.service ntip-dashboard.service; do
        if systemctl is-active --quiet "$service"; then
            fail "Master-side service $service is active"
        fi
    done
    if systemctl is-active --quiet ntcl.service; then
        fail "ntcl.service is already active"
    fi
    for path in \
        /usr/bin/ntsrv \
        /etc/ntip/server.json \
        /etc/ntip/api.json \
        /etc/ntip/dashboard.json \
        /var/lib/ntip/server \
        /run/ntip-api \
        /usr/lib/systemd/system/ntsrv.service \
        /etc/systemd/system/ntsrv.service \
        /lib/systemd/system/ntsrv.service
    do
        if [[ -e "$path" || -L "$path" ]]; then
            fail "Master or management-plane trace exists at $path"
        fi
    done
    [[ ! -S /run/ntip/ntsrv.sock ]] || fail "a Master runtime socket is present"
    [[ ! -S /run/ntip/ntcl.sock ]] || fail "a Node runtime socket is present"

    for pair in \
        "/usr/bin/ntcl:$package_root/bin/ntcl" \
        "/usr/lib/systemd/system/ntcl.service:$package_root/packaging/systemd/ntcl.service" \
        "/usr/lib/tmpfiles.d/ntip-node.conf:$package_root/packaging/tmpfiles/ntip-node.conf"
    do
        destination=${pair%%:*}
        source=${pair#*:}
        if [[ -e "$destination" || -L "$destination" ]]; then
            [[ -f "$destination" && ! -L "$destination" ]] || \
                fail "existing Node payload path is not a regular file: $destination"
            cmp -s "$source" "$destination" || fail "existing Node payload differs at $destination"
        fi
    done

    state_dir=/var/lib/ntip/client
    marker_path=$state_dir/bootstrap.id
    [[ ! -L "$state_dir" ]] || fail "Node state path must not be a symbolic link"
    if [[ -e "$marker_path" || -L "$marker_path" ]]; then
        [[ -d "$state_dir" && ! -L "$state_dir" ]] || fail "Node state path is not a real directory"
        [[ -f "$marker_path" && ! -L "$marker_path" ]] || fail "bootstrap marker is not a regular file"
        [[ -n "$bootstrap_id" ]] || fail "existing bootstrap state requires --bootstrap-id"
        marker=$(<"$marker_path")
        [[ "$marker" == "$bootstrap_id" ]] || fail "existing Node belongs to a different bootstrap ticket"
        if [[ -e "$state_dir/identity.key" || -L "$state_dir/identity.key" ]]; then
            [[ -f "$state_dir/identity.key" && ! -L "$state_dir/identity.key" ]] || \
                fail "same-ticket identity is not a regular file"
        fi
        [[ -f "$state_dir/enrollment.token" && ! -L "$state_dir/enrollment.token" ]] || \
            fail "same-ticket state is missing its enrollment token"
        [[ -f /etc/ntip/client.json && ! -L /etc/ntip/client.json ]] || \
            fail "same-ticket state is missing its public configuration"
        if [[ -f "$state_dir/state.json" ]]; then
            if grep -Eq '"enrollment_state"[[:space:]]*:[[:space:]]*"enrolled"' "$state_dir/state.json"; then
                fail "the existing Node is already enrolled"
            fi
        fi
        while IFS= read -r entry; do
            case "$entry" in
                bootstrap.id|enrollment.token|identity.key|state.json|state.lock|reconfigure.pending)
                    [[ -f "$state_dir/$entry" && ! -L "$state_dir/$entry" ]] || \
                        fail "Node state entry is not a regular file: $state_dir/$entry"
                    ;;
                *) fail "unrelated Node state exists at $state_dir/$entry" ;;
            esac
        done < <(find "$state_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
    else
        if [[ -d "$state_dir" ]]; then
            while IFS= read -r entry; do
                case "$entry" in
                    state.lock)
                        [[ -f "$state_dir/$entry" && ! -L "$state_dir/$entry" ]] || \
                            fail "Node state lock is not a regular file"
                        ;;
                    *) fail "unrelated Node state exists at $state_dir/$entry" ;;
                esac
            done < <(find "$state_dir" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)
        elif [[ -e "$state_dir" || -L "$state_dir" ]]; then
            fail "$state_dir is not a directory"
        fi
        if [[ -e /etc/ntip/client.json || -L /etc/ntip/client.json ]]; then
            [[ -f /etc/ntip/client.json && ! -L /etc/ntip/client.json ]] || \
                fail "existing Node configuration is not a regular file"
            cmp -s "$package_root/packaging/config/client.json" /etc/ntip/client.json || \
                fail "existing Node configuration is not the packaged sample"
        fi
    fi
fi

for directory in /etc/ntip /var/lib/ntip /var/lib/ntip/client /run/ntip /usr/share/doc/ntip-node; do
    destination=$(root_path "$directory")
    [[ ! -L "$destination" ]] || fail "installation directory must not be a symbolic link: $directory"
    [[ ! -e "$destination" || -d "$destination" ]] || fail "installation path is not a directory: $directory"
done

if ((!staging)); then
    if ! getent group ntip-admin >/dev/null 2>&1; then
        groupadd --system ntip-admin
    fi
    if ! getent group ntip >/dev/null 2>&1; then
        groupadd --system ntip
    fi
    ntip_admin_gid=$(getent group ntip-admin | awk -F: '{print $3}')
    ntip_gid=$(getent group ntip | awk -F: '{print $3}')
    [[ "$ntip_admin_gid" =~ ^[0-9]+$ && "$ntip_gid" =~ ^[0-9]+$ ]] || \
        fail "could not resolve NTIP group IDs"
    ((ntip_admin_gid != 0 && ntip_gid != 0 && ntip_admin_gid != ntip_gid)) || \
        fail "NTIP groups must be distinct and unprivileged"
    require_unique_group_id ntip-admin "$ntip_admin_gid"
    require_unique_group_id ntip "$ntip_gid"

    if ! getent passwd ntip >/dev/null 2>&1; then
        nologin_shell=/usr/sbin/nologin
        [[ -x "$nologin_shell" ]] || nologin_shell=/sbin/nologin
        [[ -x "$nologin_shell" ]] || fail "could not locate a nologin shell"
        useradd --system --gid ntip --groups ntip-admin --home-dir /var/lib/ntip \
            --no-create-home --shell "$nologin_shell" --comment "NTIP Node service account" ntip
    else
        ntip_record=$(getent passwd ntip)
        ntip_uid=$(awk -F: '{print $3}' <<<"$ntip_record")
        ntip_primary_gid=$(awk -F: '{print $4}' <<<"$ntip_record")
        ntip_home=$(awk -F: '{print $6}' <<<"$ntip_record")
        ntip_shell=$(awk -F: '{print $7}' <<<"$ntip_record")
        [[ "$ntip_uid" =~ ^[0-9]+$ && "$ntip_uid" -ne 0 && "$ntip_primary_gid" == "$ntip_gid" && \
            "$ntip_home" == /var/lib/ntip ]] || fail "existing ntip account is incompatible"
        case "$ntip_shell" in
            /usr/sbin/nologin|/sbin/nologin) ;;
            *) fail "existing ntip account has an interactive shell" ;;
        esac
    fi
    ntip_uid=$(getent passwd ntip | awk -F: '{print $3}')
    require_unique_passwd_id ntip "$ntip_uid"
    usermod -a -G ntip-admin ntip
fi

install_dir root root 0755 /etc/ntip
install_dir root root 0755 /var/lib/ntip
install_dir ntip ntip 0700 /var/lib/ntip/client
install_dir root ntip-admin 0770 /run/ntip
install_dir root root 0755 /usr/share/doc/ntip-node
if ((staging)); then
    install_dir root root 0755 /usr/bin
    install_dir root root 0755 /usr/lib/systemd/system
    install_dir root root 0755 /usr/lib/tmpfiles.d
fi

install_file root root 0755 "$package_root/bin/ntcl" /usr/bin/ntcl
install_file root root 0644 "$package_root/LICENSE" /usr/share/doc/ntip-node/LICENSE
install_file root root 0644 "$package_root/README.md" /usr/share/doc/ntip-node/README.md
install_file root root 0644 "$package_root/CHANGELOG.md" /usr/share/doc/ntip-node/CHANGELOG.md
install_file root root 0644 "$package_root/SECURITY.md" /usr/share/doc/ntip-node/SECURITY.md
install_file root root 0644 "$package_root/VERSION" /usr/share/doc/ntip-node/VERSION
install_file root root 0644 "$package_root/TARGET" /usr/share/doc/ntip-node/TARGET
for document in "$package_root"/docs/*.md; do
    install_file root root 0644 "$document" "/usr/share/doc/ntip-node/$(basename "$document")"
done

client_config=$(root_path /etc/ntip/client.json)
if [[ ! -e "$client_config" && ! -L "$client_config" ]]; then
    install_file root root 0644 "$package_root/packaging/config/client.json" /etc/ntip/client.json
fi
install_file root root 0644 "$package_root/packaging/systemd/ntcl.service" \
    /usr/lib/systemd/system/ntcl.service
install_file root root 0644 "$package_root/packaging/tmpfiles/ntip-node.conf" \
    /usr/lib/tmpfiles.d/ntip-node.conf

if ((staging)); then
    printf 'NTIP Node installation staged under DESTDIR=%s; host state was not changed.\n' "$destdir"
    exit 0
fi

systemd-tmpfiles --create /usr/lib/tmpfiles.d/ntip-node.conf
systemctl daemon-reload
if ((start_node)); then
    [[ -n "$bootstrap_id" ]] || fail "--start requires --bootstrap-id"
    [[ -f /var/lib/ntip/client/bootstrap.id ]] || fail "bootstrap import has not committed"
    [[ $(</var/lib/ntip/client/bootstrap.id) == "$bootstrap_id" ]] || \
        fail "bootstrap import committed a different ticket"
    [[ -f /var/lib/ntip/client/enrollment.token ]] || fail "bootstrap import did not store enrollment material"
    cmp -s "$package_root/packaging/config/client.json" /etc/ntip/client.json && \
        fail "bootstrap import did not replace the sample configuration"

    systemctl enable --now ntcl.service
    online=0
    for ((attempt = 0; attempt < 60; attempt++)); do
        if systemctl is-failed --quiet ntcl.service; then
            printf '%s\n' \
                'Enrollment state was preserved. Diagnostic commands:' \
                '  systemctl status --no-pager ntcl.service' \
                '  journalctl -u ntcl.service -n 100 --no-pager' \
                '  ntcl status --json' >&2
            fail "ntcl.service failed during enrollment"
        fi
        status=$(/usr/bin/ntcl --config /etc/ntip/client.json \
            --state-dir /var/lib/ntip/client --runtime-dir /run/ntip status --json 2>/dev/null || true)
        if [[ "$status" == *'"state":"online"'* ]]; then
            online=1
            break
        fi
        sleep 1
    done
    if ((!online)); then
        printf '%s\n' \
            'Enrollment remains pending and all state was preserved. Diagnostic commands:' \
            '  systemctl status --no-pager ntcl.service' \
            '  journalctl -u ntcl.service -n 100 --no-pager' \
            '  ntcl status --json' \
            'To retry the same invitation after stopping the pending service:' \
            '  systemctl stop ntcl.service' >&2
        fail "Node did not become online within 60 seconds"
    fi
    printf 'NTIP Node %s is installed, enrolled, and online.\n' "$version"
else
    printf 'NTIP Node %s installed. Import a bootstrap bundle before starting ntcl.service.\n' "$version"
fi
