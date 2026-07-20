#!/bin/sh
set -eu

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

remove_tree_one_file_system() {
    directory=$1
    if rm -rf --one-file-system "$directory" 2>/dev/null; then
        return
    fi
    if find "$directory" -xdev -depth -delete; then
        return
    fi
    echo "could not safely remove directory without crossing filesystems: $directory" >&2
    return 1
}

if [ "$staging" -eq 0 ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "uninstall-dashboard.sh must run as root" >&2
        exit 1
    fi
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now ntip-dashboard.service >/dev/null 2>&1 || true
    fi
else
    if [ ! -d "$destdir" ]; then
        echo "DESTDIR does not exist: $destdir" >&2
        exit 2
    fi
fi

rm -f "$(root_path /usr/lib/systemd/system/ntip-dashboard.service)"
for directory in /usr/lib/ntip-dashboard /usr/share/doc/ntip-dashboard; do
    resolved=$(root_path "$directory")
    if [ -d "$resolved" ]; then
        remove_tree_one_file_system "$resolved"
    fi
done

if [ "$staging" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "NTIP dashboard runtime, application, documentation, and unit removed."
echo "Preserved: /etc/ntip/dashboard.json and the ntip-dashboard account and group."
if [ "$staging" -eq 1 ]; then
    echo "Isolated NTIP dashboard uninstall completed under DESTDIR=$destdir; the host was not changed."
fi
