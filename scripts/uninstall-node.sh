#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset CDPATH ENV BASH_ENV
IFS=$' \t\n'
umask 077

fail() {
    printf 'NTIP Node uninstall failed: %s\n' "$1" >&2
    exit 1
}

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

remove_tree_one_file_system() {
    local directory=$1
    if rm -rf --one-file-system "$directory" 2>/dev/null; then
        return
    fi
    find "$directory" -xdev -depth -delete || \
        fail "could not safely remove $directory without crossing filesystems"
}

if ((staging)); then
    [[ -d "$destdir" ]] || fail "DESTDIR does not exist"
else
    ((EUID == 0)) || fail "uninstaller must run as root"
    [[ $(uname -s) == Linux ]] || fail "NTIP v0.2 supports Linux only"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now ntcl.service >/dev/null 2>&1 || true
    fi
fi

rm -f -- \
    "$(root_path /usr/bin/ntcl)" \
    "$(root_path /usr/lib/systemd/system/ntcl.service)" \
    "$(root_path /usr/lib/tmpfiles.d/ntip-node.conf)"

documentation=$(root_path /usr/share/doc/ntip-node)
runtime=$(root_path /run/ntip)
[[ ! -d "$documentation" ]] || remove_tree_one_file_system "$documentation"
[[ ! -d "$runtime" ]] || remove_tree_one_file_system "$runtime"

if ((!staging)) && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi

printf 'NTIP Node executable, unit, tmpfiles rule, documentation, and runtime files removed.\n'
printf 'Preserved: /etc/ntip/client.json, /var/lib/ntip/client, and service identities.\n'
printf 'Persistent enrollment material and identity are never deleted automatically.\n'
if ((staging)); then
    printf 'Isolated uninstall completed under DESTDIR=%s; the host was not changed.\n' "$destdir"
fi
