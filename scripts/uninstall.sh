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
    # GNU rm provides the clearest mount-boundary guard. BusyBox rm does not,
    # so use find's portable xdev traversal there instead of crossing into a
    # filesystem mounted below an NTIP-owned directory.
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
        echo "uninstall.sh must run as root" >&2
        exit 1
    fi

    if [ -x /usr/bin/ntsrv ]; then
        /usr/bin/ntsrv down >/dev/null 2>&1 || true
    fi
    if [ -x /usr/bin/ntcl ]; then
        /usr/bin/ntcl down >/dev/null 2>&1 || true
    fi

    if command -v systemctl >/dev/null 2>&1; then
        # The separately packaged dashboard and API are consumers of the
        # lower service layers. Stop them before the core socket disappears.
        systemctl disable --now ntip-dashboard.service >/dev/null 2>&1 || true
        systemctl disable --now ntsrv.service >/dev/null 2>&1 || true
        systemctl disable --now ntcl.service >/dev/null 2>&1 || true
        # ntip-api depends on the core service socket. Disable it before the
        # provider disappears, but leave the separately owned artifact intact.
        systemctl disable --now ntip-api.service >/dev/null 2>&1 || true
    fi
else
    if [ ! -d "$destdir" ]; then
        echo "DESTDIR does not exist: $destdir" >&2
        exit 2
    fi
fi

rm -f \
    "$(root_path /usr/bin/ntsrv)" \
    "$(root_path /usr/bin/ntcl)" \
    "$(root_path /usr/lib/systemd/system/ntsrv.service)" \
    "$(root_path /usr/lib/systemd/system/ntcl.service)" \
    "$(root_path /usr/lib/tmpfiles.d/ntip.conf)"

documentation=$(root_path /usr/share/doc/ntip)
runtime=$(root_path /run/ntip)
if [ -d "$documentation" ]; then
    remove_tree_one_file_system "$documentation"
fi
if [ -d "$runtime" ]; then
    remove_tree_one_file_system "$runtime"
fi

if [ "$staging" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

echo "NTIP executables, units, and runtime files removed."
echo "Preserved: /etc/ntip, /var/lib/ntip, /run/ntip-api, service accounts, and service groups."
echo "Persistent identity and state are never deleted automatically."
if [ "$staging" -eq 1 ]; then
    echo "Isolated uninstall completed under DESTDIR=$destdir; the host was not changed."
fi
