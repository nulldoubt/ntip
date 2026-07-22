#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 ARCHIVE.tar.gz [...]" >&2
    exit 2
fi

for command in cmp find grep mktemp python3 sha256sum stat tar tr wc; do
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
    case "$(basename "$archive")" in
        ntip-bootstrap-assets-v*)
            install_script=$package_root/scripts/install-bootstrap-assets.sh
            uninstall_script=$package_root/scripts/uninstall-bootstrap-assets.sh
            if [ ! -x "$install_script" ] || [ ! -x "$uninstall_script" ]; then
                echo "bootstrap-assets archive lacks executable installer scripts: $archive" >&2
                exit 1
            fi

            DESTDIR=$root "$install_script"
            test -f "$root/etc/ntip/bootstrap-assets.json"
            test -d "$root/usr/share/ntip/bootstrap-assets"
            test -f "$root/usr/share/doc/ntip-bootstrap-assets/ntip-nginx.conf.example"
            test "$(find "$root/usr/share/ntip/bootstrap-assets" -maxdepth 1 -type f -name 'ntip-node-v*-linux-musl.tar.gz' | wc -l | tr -d ' ')" = 2
            test ! -e "$root/usr/bin/ntsrv"
            test ! -e "$root/usr/bin/ntcl"
            test ! -e "$root/usr/bin/ntip-api"
            test ! -e "$root/usr/lib/systemd/system/ntsrv.service"
            test ! -e "$root/usr/lib/systemd/system/ntcl.service"
            test ! -e "$root/usr/lib/systemd/system/ntip-api.service"
            test ! -e "$root/var/lib/ntip"
            test ! -e "$root/etc/nginx"
            test "$(stat -c %a "$root/etc/ntip/bootstrap-assets.json")" = 640
            test "$(stat -c %a "$root/usr/share/ntip/bootstrap-assets")" = 755

            DESTDIR=$root "$uninstall_script"
            test ! -e "$root/etc/ntip/bootstrap-assets.json"
            test ! -e "$root/usr/share/ntip/bootstrap-assets"
            test ! -e "$root/usr/share/doc/ntip-bootstrap-assets"
            DESTDIR=$root "$uninstall_script" >/dev/null
            ;;
        ntip-node-v*)
            install_script=$package_root/scripts/install-node.sh
            uninstall_script=$package_root/scripts/uninstall-node.sh
            if [ ! -x "$install_script" ] || [ ! -x "$uninstall_script" ]; then
                echo "Node archive does not contain executable installer scripts: $archive" >&2
                exit 1
            fi

            DESTDIR=$root "$install_script"
            test -x "$root/usr/bin/ntcl"
            test -f "$root/usr/lib/systemd/system/ntcl.service"
            test -f "$root/usr/lib/tmpfiles.d/ntip-node.conf"
            test -f "$root/etc/ntip/client.json"
            test -f "$root/usr/share/doc/ntip-node/node-bootstrap.md"
            test -d "$root/var/lib/ntip/client"
            test -d "$root/run/ntip"
            test ! -e "$root/usr/bin/ntsrv"
            test ! -e "$root/usr/bin/ntip-api"
            test ! -e "$root/usr/lib/systemd/system/ntsrv.service"
            test ! -e "$root/usr/lib/systemd/system/ntip-api.service"
            test ! -e "$root/etc/ntip/server.json"
            test ! -e "$root/etc/ntip/api.json"
            test ! -e "$root/var/lib/ntip/server"
            test ! -e "$root/run/ntip-api"
            cmp "$package_root/bin/ntcl" "$root/usr/bin/ntcl"
            cmp "$package_root/packaging/systemd/ntcl.service" \
                "$root/usr/lib/systemd/system/ntcl.service"
            cmp "$package_root/packaging/tmpfiles/ntip-node.conf" \
                "$root/usr/lib/tmpfiles.d/ntip-node.conf"
            grep -Fq 'ExecStart=/usr/bin/ntcl ' "$root/usr/lib/systemd/system/ntcl.service"
            grep -Fxq 'd /var/lib/ntip/client 0700 ntip ntip -' \
                "$root/usr/lib/tmpfiles.d/ntip-node.conf"
            if grep -Eq 'ntsrv|ntip-api|ntip-dashboard|server.json|/var/lib/ntip/server' \
                "$root/usr/lib/tmpfiles.d/ntip-node.conf"; then
                echo "Node tmpfiles rule contains a Master or management-plane path" >&2
                exit 1
            fi
            test "$(stat -c %a "$root/usr/bin/ntcl")" = 755
            test "$(stat -c %a "$root/etc/ntip/client.json")" = 644
            test "$(stat -c %a "$root/var/lib/ntip/client")" = 700
            test "$(stat -c %a "$root/run/ntip")" = 770

            printf '%s\n' 'operator-owned-client-config' >"$root/etc/ntip/client.json"
            printf '%s\n' 'persistent-client-key' >"$root/var/lib/ntip/client/identity.key"
            chmod 0600 "$root/var/lib/ntip/client/identity.key"
            DESTDIR=$root "$uninstall_script"
            test ! -e "$root/usr/bin/ntcl"
            test ! -e "$root/usr/lib/systemd/system/ntcl.service"
            test ! -e "$root/usr/lib/tmpfiles.d/ntip-node.conf"
            test ! -e "$root/usr/share/doc/ntip-node"
            test ! -e "$root/run/ntip"
            grep -Fxq 'operator-owned-client-config' "$root/etc/ntip/client.json"
            grep -Fxq 'persistent-client-key' "$root/var/lib/ntip/client/identity.key"
            DESTDIR=$root "$uninstall_script" >/dev/null
            ;;
        ntip-dashboard-v*)
            install_script=$package_root/scripts/install-dashboard.sh
            uninstall_script=$package_root/scripts/uninstall-dashboard.sh
            if [ ! -x "$install_script" ] || [ ! -x "$uninstall_script" ]; then
                echo "dashboard archive does not contain executable installer scripts: $archive" >&2
                exit 1
            fi

            DESTDIR=$root "$install_script"
            test -x "$root/usr/lib/ntip-dashboard/runtime/bun"
            test -f "$root/usr/lib/ntip-dashboard/app/launcher.ts"
            test -f "$root/usr/lib/ntip-dashboard/app/http-gateway.ts"
            test -f "$root/usr/lib/ntip-dashboard/app/apps/dashboard/server.js"
            test -f "$root/usr/lib/systemd/system/ntip-dashboard.service"
            test -f "$root/etc/ntip/dashboard.json"
            test -f "$root/usr/share/doc/ntip-dashboard/management-plane.md"
            test ! -e "$root/usr/bin/ntsrv"
            test ! -e "$root/usr/bin/ntip-api"
            test ! -e "$root/var/lib/ntip"
            test ! -e "$root/run/ntip"
            test ! -e "$root/run/ntip-api"
            cmp "$package_root/runtime/bun" "$root/usr/lib/ntip-dashboard/runtime/bun"
            cmp "$package_root/app/launcher.ts" "$root/usr/lib/ntip-dashboard/app/launcher.ts"
            cmp "$package_root/app/http-gateway.ts" "$root/usr/lib/ntip-dashboard/app/http-gateway.ts"
            cmp "$package_root/packaging/systemd/ntip-dashboard.service" \
                "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fxq 'User=ntip-dashboard' "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fxq 'Group=ntip-dashboard' "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fxq 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE' "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fxq 'AmbientCapabilities=CAP_NET_BIND_SERVICE' "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fxq 'InaccessiblePaths=/var/lib/ntip /run/ntip /run/ntip-api' \
                "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fxq 'ReadOnlyPaths=/etc/ntip/dashboard.json /usr/lib/ntip-dashboard /usr/share/ntip/bootstrap-assets' \
                "$root/usr/lib/systemd/system/ntip-dashboard.service"
            grep -Fq 'dashboard Bun runtime does not match this Linux architecture' "$install_script"
            grep -Fq 'dashboard package must bundle Bun 1.3.14 exactly' "$install_script"
            if grep -Fxq 'MemoryDenyWriteExecute=yes' "$root/usr/lib/systemd/system/ntip-dashboard.service"; then
                echo "dashboard unit incorrectly blocks JavaScriptCore JIT mappings" >&2
                exit 1
            fi
            test "$(stat -c %a "$root/usr/lib/ntip-dashboard/runtime/bun")" = 755
            test "$(stat -c %a "$root/etc/ntip/dashboard.json")" = 640

            printf '%s\n' 'operator-owned-dashboard-config' >"$root/etc/ntip/dashboard.json"
            DESTDIR=$root "$install_script"
            grep -Fxq 'operator-owned-dashboard-config' "$root/etc/ntip/dashboard.json"

            DESTDIR=$root "$uninstall_script"
            test ! -e "$root/usr/lib/ntip-dashboard"
            test ! -e "$root/usr/lib/systemd/system/ntip-dashboard.service"
            test ! -e "$root/usr/share/doc/ntip-dashboard"
            grep -Fxq 'operator-owned-dashboard-config' "$root/etc/ntip/dashboard.json"
            DESTDIR=$root "$uninstall_script" >/dev/null
            ;;
        ntip-api-v*)
            install_script=$package_root/scripts/install-api.sh
            uninstall_script=$package_root/scripts/uninstall-api.sh
            if [ ! -x "$install_script" ] || [ ! -x "$uninstall_script" ]; then
                echo "API archive does not contain executable installer scripts: $archive" >&2
                exit 1
            fi

            DESTDIR=$root "$install_script"
            test -x "$root/usr/bin/ntip-api"
            test -f "$root/usr/lib/systemd/system/ntip-api.service"
            test -f "$root/etc/ntip/api.json"
            test -f "$root/usr/share/doc/ntip-api/management-plane.md"
            test -f "$root/usr/share/doc/ntip-api/operator-guide.md"
            test ! -e "$root/usr/bin/ntsrv"
            test ! -e "$root/usr/bin/ntcl"
            test ! -e "$root/var/lib/ntip"
            cmp "$package_root/bin/ntip-api" "$root/usr/bin/ntip-api"
            cmp "$package_root/packaging/systemd/ntip-api.service" \
                "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'User=ntip-api' "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'Group=ntip-api' "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'CapabilityBoundingSet=' "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'AmbientCapabilities=' "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'InaccessiblePaths=/var/lib/ntip /run/ntip' \
                "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'IPAddressDeny=any' "$root/usr/lib/systemd/system/ntip-api.service"
            grep -Fxq 'IPAddressAllow=localhost' "$root/usr/lib/systemd/system/ntip-api.service"
            test "$(stat -c %a "$root/usr/bin/ntip-api")" = 755
            test "$(stat -c %a "$root/etc/ntip/api.json")" = 640
            test "$(stat -c %a "$root/run/ntip-api")" = 750

            printf '%s\n' 'operator-owned-api-config' >"$root/etc/ntip/api.json"
            printf '%s\n' 'shared-runtime-seam' >"$root/run/ntip-api/owner-marker"
            DESTDIR=$root "$install_script"
            grep -Fxq 'operator-owned-api-config' "$root/etc/ntip/api.json"
            grep -Fxq 'shared-runtime-seam' "$root/run/ntip-api/owner-marker"

            DESTDIR=$root "$uninstall_script"
            test ! -e "$root/usr/bin/ntip-api"
            test ! -e "$root/usr/lib/systemd/system/ntip-api.service"
            test ! -e "$root/usr/share/doc/ntip-api"
            grep -Fxq 'operator-owned-api-config' "$root/etc/ntip/api.json"
            grep -Fxq 'shared-runtime-seam' "$root/run/ntip-api/owner-marker"
            DESTDIR=$root "$uninstall_script" >/dev/null
            ;;
        ntip-v*)
            install_script=$package_root/scripts/install.sh
            uninstall_script=$package_root/scripts/uninstall.sh
            if [ ! -x "$install_script" ] || [ ! -x "$uninstall_script" ]; then
                echo "core archive does not contain executable installer scripts: $archive" >&2
                exit 1
            fi

            DESTDIR=$root "$install_script"
            test -x "$root/usr/bin/ntsrv"
            test -x "$root/usr/bin/ntcl"
            test ! -e "$root/usr/bin/ntip-api"
            test -f "$root/usr/lib/systemd/system/ntsrv.service"
            test -f "$root/usr/lib/systemd/system/ntcl.service"
            test ! -e "$root/usr/lib/systemd/system/ntip-api.service"
            test -f "$root/usr/lib/tmpfiles.d/ntip.conf"
            test -f "$root/usr/share/doc/ntip/examples/systemd/ntip-online-backup.service"
            test -f "$root/usr/share/doc/ntip/examples/systemd/ntip-online-backup.timer"
            test -f "$root/etc/ntip/server.json"
            test -f "$root/etc/ntip/client.json"
            test ! -e "$root/etc/ntip/api.json"
            cmp "$package_root/bin/ntsrv" "$root/usr/bin/ntsrv"
            cmp "$package_root/bin/ntcl" "$root/usr/bin/ntcl"
            cmp "$package_root/packaging/systemd/ntsrv.service" \
                "$root/usr/lib/systemd/system/ntsrv.service"
            cmp "$package_root/packaging/systemd/ntcl.service" \
                "$root/usr/lib/systemd/system/ntcl.service"
            grep -Fq 'ExecStart=/usr/bin/ntsrv ' "$root/usr/lib/systemd/system/ntsrv.service"
            grep -Fq 'ExecStart=/usr/bin/ntcl ' "$root/usr/lib/systemd/system/ntcl.service"
            grep -Fxq 'ReadWritePaths=/var/lib/ntip/server /run/ntip /run/ntip-api' \
                "$root/usr/lib/systemd/system/ntsrv.service"
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
            grep -Fq '"schema_version": 2' "$root/etc/ntip/server.json"
            grep -Fq '"service_socket_path": "/run/ntip-api/ntsrv-api.sock"' \
                "$root/etc/ntip/server.json"
            if grep -Eq 'inner_mtu|maximum_nodes|heartbeat|traffic' "$root/etc/ntip/server.json"; then
                echo "server bootstrap config contains operational settings" >&2
                exit 1
            fi
            grep -Fxq 'd /run/ntip-api 0750 ntip ntip-api -' \
                "$root/usr/lib/tmpfiles.d/ntip.conf"
            cmp "$package_root/packaging/examples/systemd/ntip-online-backup.service" \
                "$root/usr/share/doc/ntip/examples/systemd/ntip-online-backup.service"
            cmp "$package_root/packaging/examples/systemd/ntip-online-backup.timer" \
                "$root/usr/share/doc/ntip/examples/systemd/ntip-online-backup.timer"
            test "$(stat -c %a "$root/usr/bin/ntsrv")" = 755
            test "$(stat -c %a "$root/etc/ntip/server.json")" = 644
            test "$(stat -c %a "$root/var/lib/ntip/server")" = 700
            test "$(stat -c %a "$root/var/lib/ntip/client")" = 700
            test "$(stat -c %a "$root/run/ntip")" = 770
            test "$(stat -c %a "$root/run/ntip-api")" = 750

            printf '%s\n' 'operator-owned-server-config' >"$root/etc/ntip/server.json"
            printf '%s\n' 'operator-owned-client-config' >"$root/etc/ntip/client.json"
            printf '%s\n' 'persistent-server-state' >"$root/var/lib/ntip/server/ntip.sqlite3"
            printf '%s\n' 'persistent-client-key' >"$root/var/lib/ntip/client/identity.key"
            chmod 0600 "$root/var/lib/ntip/server/ntip.sqlite3" "$root/var/lib/ntip/client/identity.key"
            printf '%s\n' 'transient-runtime' >"$root/run/ntip/test.sock"
            printf '%s\n' 'shared-runtime-seam' >"$root/run/ntip-api/owner-marker"

            DESTDIR=$root "$install_script"
            grep -Fxq 'operator-owned-server-config' "$root/etc/ntip/server.json"
            grep -Fxq 'operator-owned-client-config' "$root/etc/ntip/client.json"
            grep -Fxq 'persistent-server-state' "$root/var/lib/ntip/server/ntip.sqlite3"
            grep -Fxq 'persistent-client-key' "$root/var/lib/ntip/client/identity.key"

            DESTDIR=$root "$uninstall_script"
            test ! -e "$root/usr/bin/ntsrv"
            test ! -e "$root/usr/bin/ntcl"
            test ! -e "$root/usr/lib/systemd/system/ntsrv.service"
            test ! -e "$root/usr/lib/systemd/system/ntcl.service"
            test ! -e "$root/usr/lib/tmpfiles.d/ntip.conf"
            test ! -e "$root/usr/share/doc/ntip"
            test ! -e "$root/run/ntip"
            grep -Fxq 'shared-runtime-seam' "$root/run/ntip-api/owner-marker"
            grep -Fxq 'operator-owned-server-config' "$root/etc/ntip/server.json"
            grep -Fxq 'operator-owned-client-config' "$root/etc/ntip/client.json"
            grep -Fxq 'persistent-server-state' "$root/var/lib/ntip/server/ntip.sqlite3"
            grep -Fxq 'persistent-client-key' "$root/var/lib/ntip/client/identity.key"
            DESTDIR=$root "$uninstall_script" >/dev/null
            ;;
        *)
            echo "unrecognized NTIP release artifact: $archive" >&2
            exit 2
            ;;
    esac
    echo "isolated_installer_lifecycle=passed archive=$(basename "$archive")"
done
