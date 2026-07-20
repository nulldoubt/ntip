#!/bin/sh
set -eu

umask 077

destdir=${DESTDIR:-}
if [ -n "$destdir" ] && [ "$destdir" != / ]; then
    case "$destdir" in
        /*) ;;
        *)
            echo "DESTDIR must be an absolute path" >&2
            exit 2
            ;;
    esac
    destdir=${destdir%/}
    staging=1
else
    destdir=
    staging=0
fi

root_path() {
    printf '%s%s\n' "$destdir" "$1"
}

require_unique_passwd_id() {
    identity_name=$1
    identity_uid=$2
    identity_matches=$(getent passwd | awk -F: -v wanted="$identity_uid" \
        '$3 == wanted { count += 1 } END { print count + 0 }')
    if [ "$identity_matches" != 1 ]; then
        echo "$identity_name UID $identity_uid has duplicate numeric passwd aliases" >&2
        exit 1
    fi
}

require_unique_group_id() {
    identity_name=$1
    identity_gid=$2
    identity_matches=$(getent group | awk -F: -v wanted="$identity_gid" \
        '$3 == wanted { count += 1 } END { print count + 0 }')
    if [ "$identity_matches" != 1 ]; then
        echo "$identity_name GID $identity_gid has duplicate numeric group aliases" >&2
        exit 1
    fi
}

install_dir() {
    owner=$1
    group=$2
    mode=$3
    destination=$(root_path "$4")
    if [ "$staging" -eq 1 ]; then
        install -d -m "$mode" "$destination"
    else
        install -d -o "$owner" -g "$group" -m "$mode" "$destination"
    fi
}

install_file() {
    owner=$1
    group=$2
    mode=$3
    source=$4
    destination=$(root_path "$5")
    if [ "$staging" -eq 1 ]; then
        install -m "$mode" "$source" "$destination"
    else
        install -o "$owner" -g "$group" -m "$mode" "$source" "$destination"
    fi
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
package_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

if [ "$staging" -eq 1 ]; then
    if ! command -v install >/dev/null 2>&1; then
        echo "required staging command not found: install" >&2
        exit 1
    fi
    install -d -m 0755 "$destdir"
else
    if [ "$(id -u)" -ne 0 ]; then
        echo "install-api.sh must run as root" >&2
        exit 1
    fi
    if [ "$(uname -s)" != Linux ]; then
        echo "NTIP API runtime installation supports Linux only" >&2
        exit 1
    fi
    for command in awk getent id install systemctl systemd-tmpfiles uname; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "required command not found: $command" >&2
            exit 1
        fi
    done
    case "$(uname -m)" in
        x86_64|aarch64) ;;
        *)
            echo "NTIP API supports only Linux x86_64 and AArch64" >&2
            exit 1
            ;;
    esac
fi

find_binary() {
    for candidate in \
        "$package_root/bin/ntip-api" \
        "$package_root/zig-out/bin/ntip-api"
    do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    echo "could not find executable ntip-api under $package_root/bin or zig-out/bin" >&2
    return 1
}

ntip_api_binary=$(find_binary)

if [ "$staging" -eq 0 ]; then
    if systemctl is-active --quiet ntip-api.service; then
        echo "stop ntip-api.service before upgrade" >&2
        exit 1
    fi
    if ! getent passwd ntip >/dev/null 2>&1 || ! getent group ntip >/dev/null 2>&1 || \
        ! getent group ntip-admin >/dev/null 2>&1 || \
        [ ! -x /usr/bin/ntsrv ] || [ ! -f /usr/lib/tmpfiles.d/ntip.conf ]
    then
        echo "install the architecture-matched NTIP core package before ntip-api" >&2
        exit 1
    fi
    core_version=$(/usr/bin/ntsrv version) || {
        echo "installed ntsrv cannot execute on this architecture" >&2
        exit 1
    }
    api_version=$("$ntip_api_binary" --version) || {
        echo "ntip-api cannot execute on this architecture" >&2
        exit 1
    }
    case "$core_version:$api_version" in
        "ntsrv "*:"ntip-api "*) ;;
        *)
            echo "could not read NTIP component versions" >&2
            exit 1
            ;;
    esac
    if [ "${core_version#ntsrv }" != "${api_version#ntip-api }" ]; then
        echo "ntip-api version does not match installed ntsrv" >&2
        exit 1
    fi
    if ! getent group ntip-api >/dev/null 2>&1 || ! getent passwd ntip-api >/dev/null 2>&1; then
        echo "installed NTIP core is missing the dedicated ntip-api identity" >&2
        exit 1
    fi
    ntip_admin_gid=$(getent group ntip-admin | awk -F: '{print $3}')
    ntip_group_gid=$(getent group ntip | awk -F: '{print $3}')
    ntip_api_group_gid=$(getent group ntip-api | awk -F: '{print $3}')
    case "$ntip_admin_gid:$ntip_group_gid:$ntip_api_group_gid" in
        *[!0-9:]*|:*|*::*|*:)
            echo "could not resolve numeric NTIP group identities" >&2
            exit 1
            ;;
    esac
    if [ "$ntip_admin_gid" = 0 ] || [ "$ntip_group_gid" = 0 ] || \
        [ "$ntip_api_group_gid" = 0 ]
    then
        echo "NTIP service groups must not resolve to the privileged GID" >&2
        exit 1
    fi
    if [ "$ntip_admin_gid" = "$ntip_group_gid" ] || \
        [ "$ntip_admin_gid" = "$ntip_api_group_gid" ] || \
        [ "$ntip_group_gid" = "$ntip_api_group_gid" ]
    then
        echo "ntip, ntip-api, and ntip-admin must have distinct numeric GIDs" >&2
        exit 1
    fi
    ntip_record=$(getent passwd ntip)
    ntip_uid=$(printf '%s\n' "$ntip_record" | awk -F: '{print $3}')
    ntip_primary_gid=$(printf '%s\n' "$ntip_record" | awk -F: '{print $4}')
    case "$ntip_uid:$ntip_primary_gid" in
        *[!0-9:]*|:*|*::*|*:)
            echo "could not resolve the numeric ntip service identity" >&2
            exit 1
            ;;
    esac
    if [ "$ntip_uid" = 0 ] || [ "$ntip_primary_gid" != "$ntip_group_gid" ]; then
        echo "existing ntip account is not the dedicated service identity" >&2
        exit 1
    fi
    api_record=$(getent passwd ntip-api)
    api_uid=$(printf '%s\n' "$api_record" | awk -F: '{print $3}')
    api_primary_gid=$(printf '%s\n' "$api_record" | awk -F: '{print $4}')
    api_home=$(printf '%s\n' "$api_record" | awk -F: '{print $6}')
    api_shell=$(printf '%s\n' "$api_record" | awk -F: '{print $7}')
    if [ "$api_uid" -eq 0 ] || [ "$api_primary_gid" != "$ntip_api_group_gid" ] || \
        [ "$api_home" != /nonexistent ]
    then
        echo "existing ntip-api account is not the dedicated API identity" >&2
        exit 1
    fi
    case "$api_shell" in
        /usr/sbin/nologin|/sbin/nologin) ;;
        *)
            echo "existing ntip-api account has an interactive shell: $api_shell" >&2
            exit 1
            ;;
    esac
    if [ "$(id -G ntip-api)" != "$ntip_api_group_gid" ]; then
        echo "ntip-api account must not have supplementary groups" >&2
        exit 1
    fi
    if [ "$ntip_uid" = "$api_uid" ]; then
        echo "ntip and ntip-api must have distinct unprivileged numeric UIDs" >&2
        exit 1
    fi
    require_unique_passwd_id ntip "$ntip_uid"
    require_unique_passwd_id ntip-api "$api_uid"
    require_unique_group_id ntip "$ntip_group_gid"
    require_unique_group_id ntip-api "$ntip_api_group_gid"
    require_unique_group_id ntip-admin "$ntip_admin_gid"
fi

install_dir root root 0755 /etc/ntip
install_dir root root 0755 /usr/share/doc/ntip-api
install_dir ntip ntip-api 0750 /run/ntip-api
if [ "$staging" -eq 1 ]; then
    install_dir root root 0755 /usr/bin
    install_dir root root 0755 /usr/lib/systemd/system
fi

install_file root root 0755 "$ntip_api_binary" /usr/bin/ntip-api
for document in LICENSE README.md CHANGELOG.md SECURITY.md; do
    if [ -f "$package_root/$document" ]; then
        install_file root root 0644 "$package_root/$document" "/usr/share/doc/ntip-api/$document"
    fi
done
for document in "$package_root"/docs/*.md; do
    install_file root root 0644 "$document" "/usr/share/doc/ntip-api/$(basename "$document")"
done

api_config=$(root_path /etc/ntip/api.json)
if [ ! -e "$api_config" ]; then
    install_file root ntip-api 0640 "$package_root/packaging/config/api.json" /etc/ntip/api.json
fi
install_file root root 0644 \
    "$package_root/packaging/systemd/ntip-api.service" \
    /usr/lib/systemd/system/ntip-api.service

if [ "$staging" -eq 0 ]; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/ntip.conf
    systemctl daemon-reload
    echo "NTIP API installed but not started. Replace the placeholder origin in /etc/ntip/api.json before enabling ntip-api.service."
else
    echo "NTIP API installation staged under DESTDIR=$destdir; no accounts, services, or host runtime resources were changed."
fi
