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
        echo "install.sh must run as root" >&2
        exit 1
    fi

    if [ "$(uname -s)" != "Linux" ]; then
        echo "NTIP v0.1 runtime installation supports Linux only" >&2
        exit 1
    fi

    for command in getent groupadd useradd usermod install systemctl systemd-tmpfiles ip awk uname; do
        if ! command -v "$command" >/dev/null 2>&1; then
            echo "required command not found: $command" >&2
            exit 1
        fi
    done

    case "$(uname -m)" in
        x86_64|aarch64) ;;
        *)
            echo "NTIP v0.1 supports only Linux x86_64 and AArch64" >&2
            exit 1
            ;;
    esac

    kernel_release=$(uname -r)
    kernel_major=$(printf '%s\n' "$kernel_release" | awk -F. '{print $1}')
    kernel_minor=$(printf '%s\n' "$kernel_release" | awk -F. '{print $2}')
    case "$kernel_major:$kernel_minor" in
        *[!0-9:]*|:*)
            echo "could not parse Linux kernel release: $kernel_release" >&2
            exit 1
            ;;
    esac
    if [ "$kernel_major" -lt 6 ] || { [ "$kernel_major" -eq 6 ] && [ "$kernel_minor" -lt 1 ]; }; then
        echo "NTIP v0.1 requires Linux kernel 6.1 or newer (found $kernel_release)" >&2
        exit 1
    fi
    if [ ! -c /dev/net/tun ]; then
        echo "TUN device is unavailable: /dev/net/tun" >&2
        exit 1
    fi
fi

find_binary() {
    name=$1
    for candidate in \
        "$package_root/bin/$name" \
        "$package_root/zig-out/bin/$name"
    do
        if [ -f "$candidate" ] && [ -x "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    echo "could not find executable $name under $package_root/bin or zig-out/bin" >&2
    return 1
}

ntsrv_binary=$(find_binary ntsrv)
ntcl_binary=$(find_binary ntcl)

if [ "$staging" -eq 0 ]; then
    if systemctl is-active --quiet ntsrv.service || systemctl is-active --quiet ntcl.service; then
        echo "stop NTIP services and take a coherent state snapshot before upgrade" >&2
        exit 1
    fi
    if [ -S /run/ntip/ntsrv.sock ] && [ -x /usr/bin/ntsrv ] && \
        /usr/bin/ntsrv status >/dev/null 2>&1
    then
        echo "a manual ntsrv daemon is active; stop it before upgrade" >&2
        exit 1
    fi
    if [ -S /run/ntip/ntcl.sock ] && [ -x /usr/bin/ntcl ] && \
        /usr/bin/ntcl status >/dev/null 2>&1
    then
        echo "a manual ntcl daemon is active; stop it before upgrade" >&2
        exit 1
    fi

    if ! getent group ntip-admin >/dev/null 2>&1; then
        groupadd --system ntip-admin
    fi

    if ! getent group ntip >/dev/null 2>&1; then
        groupadd --system ntip
    fi

    if ! getent passwd ntip >/dev/null 2>&1; then
        nologin_shell=/usr/sbin/nologin
        if [ ! -x "$nologin_shell" ]; then
            nologin_shell=/sbin/nologin
        fi
        if [ ! -x "$nologin_shell" ]; then
            echo "could not locate a nologin shell" >&2
            exit 1
        fi
        useradd --system \
            --gid ntip \
            --groups ntip-admin \
            --home-dir /var/lib/ntip \
            --no-create-home \
            --shell "$nologin_shell" \
            --comment "NTIP service account" \
            ntip
    else
        ntip_record=$(getent passwd ntip)
        ntip_uid=$(printf '%s\n' "$ntip_record" | awk -F: '{print $3}')
        ntip_primary_gid=$(printf '%s\n' "$ntip_record" | awk -F: '{print $4}')
        ntip_home=$(printf '%s\n' "$ntip_record" | awk -F: '{print $6}')
        ntip_shell=$(printf '%s\n' "$ntip_record" | awk -F: '{print $7}')
        expected_gid=$(getent group ntip | awk -F: '{print $3}')
        if [ "$ntip_uid" -eq 0 ] || [ "$ntip_primary_gid" != "$expected_gid" ] || \
            [ "$ntip_home" != /var/lib/ntip ]
        then
            echo "existing ntip account is not the dedicated service identity" >&2
            exit 1
        fi
        case "$ntip_shell" in
            /usr/sbin/nologin|/sbin/nologin) ;;
            *)
                echo "existing ntip account has an interactive shell: $ntip_shell" >&2
                exit 1
                ;;
        esac
        usermod -a -G ntip-admin ntip
    fi
fi

install_dir root root 0755 /etc/ntip
install_dir root root 0755 /var/lib/ntip
install_dir root root 0755 /usr/share/doc/ntip
install_dir ntip ntip 0700 /var/lib/ntip/server
install_dir ntip ntip 0700 /var/lib/ntip/client
install_dir root ntip-admin 0770 /run/ntip
if [ "$staging" -eq 1 ]; then
    install_dir root root 0755 /usr/bin
    install_dir root root 0755 /usr/lib/systemd/system
    install_dir root root 0755 /usr/lib/tmpfiles.d
fi

install_file root root 0755 "$ntsrv_binary" /usr/bin/ntsrv
install_file root root 0755 "$ntcl_binary" /usr/bin/ntcl
install_file root root 0644 "$package_root/LICENSE" /usr/share/doc/ntip/LICENSE
install_file root root 0644 "$package_root/README.md" /usr/share/doc/ntip/README.md
install_file root root 0644 "$package_root/CHANGELOG.md" /usr/share/doc/ntip/CHANGELOG.md
install_file root root 0644 "$package_root/SECURITY.md" /usr/share/doc/ntip/SECURITY.md
for document in "$package_root"/docs/*.md; do
    install_file root root 0644 "$document" "/usr/share/doc/ntip/$(basename "$document")"
done

server_config=$(root_path /etc/ntip/server.json)
client_config=$(root_path /etc/ntip/client.json)
if [ ! -e "$server_config" ]; then
    install_file root root 0644 "$package_root/packaging/config/server.json" /etc/ntip/server.json
fi
if [ ! -e "$client_config" ]; then
    install_file root root 0644 "$package_root/packaging/config/client.json" /etc/ntip/client.json
fi

install_file root root 0644 \
    "$package_root/packaging/systemd/ntsrv.service" \
    /usr/lib/systemd/system/ntsrv.service
install_file root root 0644 \
    "$package_root/packaging/systemd/ntcl.service" \
    /usr/lib/systemd/system/ntcl.service
install_file root root 0644 \
    "$package_root/packaging/tmpfiles/ntip.conf" \
    /usr/lib/tmpfiles.d/ntip.conf

if [ "$staging" -eq 0 ]; then
    systemd-tmpfiles --create /usr/lib/tmpfiles.d/ntip.conf
    systemctl daemon-reload
    echo "NTIP installed. Configuration and services were not started automatically."
    echo "Review /etc/ntip and /usr/share/doc/ntip/operator-guide.md before enabling a service."
else
    echo "NTIP installation staged under DESTDIR=$destdir; no accounts, services, or host runtime resources were changed."
fi
