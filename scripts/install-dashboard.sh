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

install_dir() {
    directory_owner=$1
    directory_group=$2
    directory_mode=$3
    directory_target=$(root_path "$4")
    if [ "$staging" -eq 1 ]; then
        install -d -m "$directory_mode" "$directory_target"
    else
        install -d -o "$directory_owner" -g "$directory_group" \
            -m "$directory_mode" "$directory_target"
    fi
}

install_file() {
    file_owner=$1
    file_group=$2
    file_mode=$3
    file_source=$4
    file_target=$(root_path "$5")
    if [ "$staging" -eq 1 ]; then
        install -m "$file_mode" "$file_source" "$file_target"
    else
        install -o "$file_owner" -g "$file_group" -m "$file_mode" \
            "$file_source" "$file_target"
    fi
}

copy_read_only_tree() {
    tree_source=$1
    tree_destination=$2
    install_dir root root 0755 "$tree_destination"
    (CDPATH='' cd -- "$tree_source" && find . -type d -print) | while IFS= read -r relative; do
        [ "$relative" = . ] && continue
        install_dir root root 0755 "$tree_destination/${relative#./}"
    done
    (CDPATH='' cd -- "$tree_source" && find . -type f -print) | while IFS= read -r relative; do
        install_file root root 0644 "$tree_source/${relative#./}" \
            "$tree_destination/${relative#./}"
    done
}

remove_tree_one_file_system() {
    remove_directory=$1
    if rm -rf --one-file-system "$remove_directory" 2>/dev/null; then
        return
    fi
    if find "$remove_directory" -xdev -depth -delete; then
        return
    fi
    echo "could not safely replace directory without crossing filesystems: $remove_directory" >&2
    return 1
}

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
package_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

for required in runtime/bun app/launcher.ts app/http-gateway.ts app/apps/dashboard/server.js VERSION \
    packaging/config/dashboard.json packaging/systemd/ntip-dashboard.service; do
    if [ ! -f "$package_root/$required" ]; then
        echo "dashboard package is incomplete: $required" >&2
        exit 1
    fi
done
if [ ! -x "$package_root/runtime/bun" ]; then
    echo "dashboard Bun runtime is not executable" >&2
    exit 1
fi

if [ "$staging" -eq 1 ]; then
    for command in find install rm; do
        command -v "$command" >/dev/null 2>&1 || {
            echo "required staging command not found: $command" >&2
            exit 1
        }
    done
    install -d -m 0755 "$destdir"
else
    if [ "$(id -u)" -ne 0 ]; then
        echo "install-dashboard.sh must run as root" >&2
        exit 1
    fi
    if [ "$(uname -s)" != Linux ]; then
        echo "NTIP dashboard runtime installation supports Linux only" >&2
        exit 1
    fi
    for command in awk find getent groupadd id install rm systemctl tr uname useradd; do
        command -v "$command" >/dev/null 2>&1 || {
            echo "required command not found: $command" >&2
            exit 1
        }
    done
    case "$(uname -m)" in
        x86_64|aarch64) ;;
        *)
            echo "NTIP dashboard supports only Linux x86_64 and AArch64" >&2
            exit 1
            ;;
    esac
    if ! bundled_bun_version=$("$package_root/runtime/bun" --version 2>/dev/null); then
        echo "dashboard Bun runtime does not match this Linux architecture" >&2
        exit 1
    fi
    if [ "$bundled_bun_version" != 1.3.14 ]; then
        echo "dashboard package must bundle Bun 1.3.14 exactly" >&2
        exit 1
    fi
    if systemctl is-active --quiet ntip-dashboard.service; then
        echo "stop ntip-dashboard.service before upgrade" >&2
        exit 1
    fi
    if [ ! -x /usr/bin/ntsrv ] || [ ! -x /usr/bin/ntip-api ] || \
        [ ! -f /usr/lib/systemd/system/ntip-api.service ]; then
        echo "install the architecture-matched NTIP core and API packages first" >&2
        exit 1
    fi
    package_version=$(tr -d '\r\n' <"$package_root/VERSION")
    core_version=$(/usr/bin/ntsrv version)
    api_version=$(/usr/bin/ntip-api --version)
    if [ "$core_version" != "ntsrv $package_version" ] || \
        [ "$api_version" != "ntip-api $package_version" ]; then
        echo "dashboard, core, and API versions must match exactly" >&2
        exit 1
    fi
    if ! getent group ntip-dashboard >/dev/null 2>&1; then
        groupadd --system ntip-dashboard
    fi
    if ! getent passwd ntip-dashboard >/dev/null 2>&1; then
        useradd --system --gid ntip-dashboard --home-dir /nonexistent \
            --shell /usr/sbin/nologin --comment "NTIP dashboard service account" \
            ntip-dashboard
    fi
    dashboard_gid=$(getent group ntip-dashboard | awk -F: '{print $3}')
    dashboard_record=$(getent passwd ntip-dashboard)
    dashboard_uid=$(printf '%s\n' "$dashboard_record" | awk -F: '{print $3}')
    dashboard_primary_gid=$(printf '%s\n' "$dashboard_record" | awk -F: '{print $4}')
    dashboard_home=$(printf '%s\n' "$dashboard_record" | awk -F: '{print $6}')
    dashboard_shell=$(printf '%s\n' "$dashboard_record" | awk -F: '{print $7}')
    case "$dashboard_uid:$dashboard_gid:$dashboard_primary_gid" in
        *[!0-9:]*|:*|*::*|*:)
            echo "could not resolve numeric dashboard identity" >&2
            exit 1
            ;;
    esac
    if [ "$dashboard_uid" -eq 0 ] || [ "$dashboard_gid" -eq 0 ] || \
        [ "$dashboard_primary_gid" != "$dashboard_gid" ] || \
        [ "$dashboard_home" != /nonexistent ]; then
        echo "existing ntip-dashboard account is not the isolated service identity" >&2
        exit 1
    fi
    case "$dashboard_shell" in
        /usr/sbin/nologin|/sbin/nologin) ;;
        *)
            echo "existing ntip-dashboard account has an interactive shell" >&2
            exit 1
            ;;
    esac
    if [ "$(id -G ntip-dashboard)" != "$dashboard_gid" ]; then
        echo "ntip-dashboard account must not have supplementary groups" >&2
        exit 1
    fi
    for peer in ntip ntip-api; do
        peer_uid=$(getent passwd "$peer" | awk -F: '{print $3}')
        if [ "$peer_uid" = "$dashboard_uid" ]; then
            echo "ntip-dashboard must have a distinct numeric UID" >&2
            exit 1
        fi
    done
    for peer in ntip ntip-api ntip-admin; do
        peer_gid=$(getent group "$peer" | awk -F: '{print $3}')
        if [ "$peer_gid" = "$dashboard_gid" ]; then
            echo "ntip-dashboard must have a distinct numeric GID" >&2
            exit 1
        fi
    done
fi

application_directory=$(root_path /usr/lib/ntip-dashboard/app)
if [ -d "$application_directory" ]; then
    remove_tree_one_file_system "$application_directory"
fi

install_dir root root 0755 /etc/ntip
install_dir root root 0755 /usr/lib/ntip-dashboard
install_dir root root 0755 /usr/lib/ntip-dashboard/runtime
install_dir root root 0755 /usr/share/doc/ntip-dashboard
if [ "$staging" -eq 1 ]; then
    install_dir root root 0755 /usr/lib/systemd/system
fi

install_file root root 0755 "$package_root/runtime/bun" /usr/lib/ntip-dashboard/runtime/bun
copy_read_only_tree "$package_root/app" /usr/lib/ntip-dashboard/app
for document in LICENSE README.md CHANGELOG.md SECURITY.md; do
    if [ -f "$package_root/$document" ]; then
        install_file root root 0644 "$package_root/$document" "/usr/share/doc/ntip-dashboard/$document"
    fi
done
for document in "$package_root"/docs/*.md; do
    [ -f "$document" ] || continue
    install_file root root 0644 "$document" "/usr/share/doc/ntip-dashboard/$(basename "$document")"
done

dashboard_config=$(root_path /etc/ntip/dashboard.json)
if [ ! -e "$dashboard_config" ]; then
    install_file root ntip-dashboard 0640 \
        "$package_root/packaging/config/dashboard.json" /etc/ntip/dashboard.json
fi
install_file root root 0644 \
    "$package_root/packaging/systemd/ntip-dashboard.service" \
    /usr/lib/systemd/system/ntip-dashboard.service

if [ "$staging" -eq 0 ]; then
    systemctl daemon-reload
    echo "NTIP dashboard installed but not started. Restrict its plain-HTTP gateway to the same-origin TLS reverse proxy before enabling ntip-dashboard.service."
else
    echo "NTIP dashboard installation staged under DESTDIR=$destdir; no accounts or services were changed."
fi
