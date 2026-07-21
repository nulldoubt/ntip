#!/bin/sh
set -eu

for command in nginx openssl awk mktemp; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required NGINX configuration check command not found: $command" >&2
        exit 77
    }
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
example=$repo_root/packaging/nginx/ntip.conf.example
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-nginx-check.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj /CN=ntip.example.invalid \
    -keyout "$work/ntip.key" \
    -out "$work/ntip.crt" >/dev/null 2>&1

{
    printf '%s\n' 'events {}' 'http {'
    awk -v cert="$work/ntip.crt" -v key="$work/ntip.key" '
        {
            gsub("/etc/nginx/ntip/ntip[.]crt", cert)
            gsub("/etc/nginx/ntip/ntip[.]key", key)
            gsub("127[.]0[.]0[.]1:443", "127.0.0.1:18443")
            print "    " $0
        }
    ' "$example"
    printf '%s\n' '}'
} >"$work/nginx.conf"

nginx -t -p "$work" -c "$work/nginx.conf"

api_close_count=$(grep -F -c 'proxy_set_header Connection close;' "$example" || true)
if [ "$api_close_count" -ne 3 ]; then
    echo "NGINX example must close all three ntip-api upstream connections" >&2
    exit 1
fi
dashboard_keepalive_count=$(grep -F -c 'proxy_set_header Connection "";' "$example" || true)
if [ "$dashboard_keepalive_count" -ne 1 ]; then
    echo "NGINX example has an unexpected loopback Connection policy" >&2
    exit 1
fi
echo "nginx_bootstrap_config=passed"
