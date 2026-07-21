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
        echo "uninstall-bootstrap-assets.sh must run as root" >&2
        exit 1
    fi
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet ntip-api.service; then
        echo "stop ntip-api.service before removing its bootstrap manifest" >&2
        exit 1
    fi
elif [ ! -d "$destdir" ]; then
    echo "DESTDIR does not exist: $destdir" >&2
    exit 2
fi

rm -f "$(root_path /etc/ntip/bootstrap-assets.json)"
for directory in \
    "$(root_path /usr/share/ntip/bootstrap-assets)" \
    "$(root_path /usr/share/doc/ntip-bootstrap-assets)"
do
    if [ -d "$directory" ]; then
        remove_tree_one_file_system "$directory"
    fi
done

echo "NTIP bootstrap manifest, immutable assets, and packaged NGINX example removed."
echo "Operator-owned enabled NGINX configuration was not changed."

