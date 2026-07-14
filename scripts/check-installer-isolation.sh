#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 ARCHIVE.tar.gz [...]" >&2
    exit 2
fi

for command in cmp grep mktemp stat tar; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required installer-test command not found: $command" >&2
        exit 1
    fi
done

work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-installer-test.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP

index=0
for archive in "$@"; do
    if [ ! -f "$archive" ]; then
        echo "release archive does not exist: $archive" >&2
        exit 2
    fi
    case "$(basename "$archive")" in
        *.tar.gz) ;;
        *)
            echo "release archive must end in .tar.gz: $archive" >&2
            exit 2
            ;;
    esac

    index=$((index + 1))
    case_root=$work/case-$index
    extract=$case_root/extract
    root=$case_root/root
    mkdir -p "$extract" "$root"
    tar --no-same-owner -xzf "$archive" -C "$extract"
    package_root=$extract/$(basename "$archive" .tar.gz)
    if [ ! -x "$package_root/scripts/install.sh" ] || [ ! -x "$package_root/scripts/uninstall.sh" ]; then
        echo "archive does not contain executable installer scripts: $archive" >&2
        exit 1
    fi

    DESTDIR=$root "$package_root/scripts/install.sh"

    test -x "$root/usr/bin/ntsrv"
    test -x "$root/usr/bin/ntcl"
    test -f "$root/usr/lib/systemd/system/ntsrv.service"
    test -f "$root/usr/lib/systemd/system/ntcl.service"
    test -f "$root/usr/lib/tmpfiles.d/ntip.conf"
    test -f "$root/etc/ntip/server.json"
    test -f "$root/etc/ntip/client.json"
    cmp "$package_root/bin/ntsrv" "$root/usr/bin/ntsrv"
    cmp "$package_root/bin/ntcl" "$root/usr/bin/ntcl"
    cmp "$package_root/packaging/systemd/ntsrv.service" \
        "$root/usr/lib/systemd/system/ntsrv.service"
    cmp "$package_root/packaging/systemd/ntcl.service" \
        "$root/usr/lib/systemd/system/ntcl.service"
    grep -Fq 'ExecStart=/usr/bin/ntsrv ' "$root/usr/lib/systemd/system/ntsrv.service"
    grep -Fq 'ExecStart=/usr/bin/ntcl ' "$root/usr/lib/systemd/system/ntcl.service"
    for unit in ntsrv ntcl; do
        unit_path=$root/usr/lib/systemd/system/$unit.service
        grep -Fxq 'User=root' "$unit_path"
        grep -Fxq 'Group=ntip-admin' "$unit_path"
        if grep -q '^ExecStartPre=' "$unit_path"; then
            echo "unit unexpectedly carries a packaged pre-start command: $unit" >&2
            exit 1
        fi
        grep -Fxq \
            'CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID CAP_NET_ADMIN' \
            "$unit_path"
        grep -Fxq \
            'AmbientCapabilities=CAP_CHOWN CAP_DAC_OVERRIDE CAP_SETGID CAP_SETUID CAP_NET_ADMIN' \
            "$unit_path"
    done
    test "$(stat -c %a "$root/usr/bin/ntsrv")" = 755
    test "$(stat -c %a "$root/etc/ntip/server.json")" = 644
    test "$(stat -c %a "$root/var/lib/ntip/server")" = 700
    test "$(stat -c %a "$root/var/lib/ntip/client")" = 700
    test "$(stat -c %a "$root/run/ntip")" = 770

    printf '%s\n' 'operator-owned-server-config' >"$root/etc/ntip/server.json"
    printf '%s\n' 'operator-owned-client-config' >"$root/etc/ntip/client.json"
    printf '%s\n' 'persistent-server-state' >"$root/var/lib/ntip/server/state.json"
    printf '%s\n' 'persistent-client-key' >"$root/var/lib/ntip/client/identity.key"
    chmod 0600 "$root/var/lib/ntip/server/state.json" "$root/var/lib/ntip/client/identity.key"
    printf '%s\n' 'transient-runtime' >"$root/run/ntip/test.sock"

    # A staged upgrade must replace packaged material but preserve operator
    # configuration and machine-managed state.
    DESTDIR=$root "$package_root/scripts/install.sh"
    grep -Fxq 'operator-owned-server-config' "$root/etc/ntip/server.json"
    grep -Fxq 'operator-owned-client-config' "$root/etc/ntip/client.json"
    grep -Fxq 'persistent-server-state' "$root/var/lib/ntip/server/state.json"
    grep -Fxq 'persistent-client-key' "$root/var/lib/ntip/client/identity.key"

    DESTDIR=$root "$package_root/scripts/uninstall.sh"
    test ! -e "$root/usr/bin/ntsrv"
    test ! -e "$root/usr/bin/ntcl"
    test ! -e "$root/usr/lib/systemd/system/ntsrv.service"
    test ! -e "$root/usr/lib/systemd/system/ntcl.service"
    test ! -e "$root/usr/lib/tmpfiles.d/ntip.conf"
    test ! -e "$root/usr/share/doc/ntip"
    test ! -e "$root/run/ntip"
    grep -Fxq 'operator-owned-server-config' "$root/etc/ntip/server.json"
    grep -Fxq 'operator-owned-client-config' "$root/etc/ntip/client.json"
    grep -Fxq 'persistent-server-state' "$root/var/lib/ntip/server/state.json"
    grep -Fxq 'persistent-client-key' "$root/var/lib/ntip/client/identity.key"

    # Uninstall remains safe and idempotent after packaged files are gone.
    DESTDIR=$root "$package_root/scripts/uninstall.sh" >/dev/null
    echo "isolated_installer_lifecycle=passed archive=$(basename "$archive")"
done
