#!/bin/sh
set -eu

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [TEMPLATE]" >&2
    exit 2
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
template=${1:-$repo_root/src/management/node-bootstrap-installer.sh.in}
node_installer=$repo_root/scripts/install-node.sh

[ -f "$template" ] && [ ! -L "$template" ] || {
    echo "bootstrap installer template is missing or unsafe: $template" >&2
    exit 1
}
bash -n "$template"
bash -n "$node_installer"
grep -Fq 'set +x' "$template" || {
    echo "bootstrap installer does not disable inherited shell tracing" >&2
    exit 1
}
grep -Fq 'unset CDPATH ENV BASH_ENV' "$template" || {
    echo "bootstrap installer does not sanitize shell startup hooks" >&2
    exit 1
}

require_count() {
    expected=$1
    text=$2
    actual=$(grep -F -c -- "$text" "$template" || true)
    if [ "$actual" -ne "$expected" ]; then
        echo "bootstrap installer must contain $expected occurrence(s) of: $text" >&2
        exit 1
    fi
}

# One archive download and one redemption. Both deliberately bypass curlrc,
# force HTTP/1.1, constrain HTTPS, pin the leaf SPKI, forbid redirects, and
# carry finite deadlines.
# shellcheck disable=SC2016 # These are literal source-contract fragments.
for token in \
    'curl -q --http1.1' \
    "--proto '=https'" \
    '--insecure' \
    '--pinnedpubkey "$spki_pin"' \
    '--globoff --fail --silent --show-error' \
    '--connect-timeout 10' \
    '--max-redirs 0'
do
    require_count 2 "$token"
done
require_count 1 '--data-binary @-'
require_count 1 'bootstrap-import --stdin'
require_count 1 'IFS= read -r -s -p'
require_count 1 '</dev/tty'
require_count 1 '>/dev/tty'

# The secret-bearing response must flow directly from curl into the bounded
# importer. It may never be retained in a shell variable or written to disk.
if grep -Eq '(^|[[:space:]])(bundle|redeem_body|selection)=' "$template"; then
    echo "bootstrap installer retains secret-bearing redemption data" >&2
    exit 1
fi
# shellcheck disable=SC2016 # Match the literal generated-script variable.
grep -Fq '"$public_origin/enrollment/v1/redeem" |' "$template" || {
    echo "redemption response is not a direct pipeline" >&2
    exit 1
}
if grep -Eq -- '--location|^[[:space:]]*-L([[:space:]]|$)' "$template"; then
    echo "bootstrap installer must never follow redirects" >&2
    exit 1
fi
if grep -Eq 'export[[:space:]]+.*secret_code|secret_code=.*curl|--data[^-]' "$template"; then
    echo "bootstrap secret could reach argv or the environment" >&2
    exit 1
fi

# All definitions precede the sole final invocation. A truncated download
# therefore cannot begin mutation before Bash has received the complete body.
last_line=$(awk 'NF { line=$0 } END { print line }' "$template")
[ "$last_line" = 'main "$@"' ] || {
    echo "bootstrap installer main call is not the final statement" >&2
    exit 1
}
require_count 1 'main "$@"'

# A service failure can create the Node identity before enrollment finishes.
# Both layers must accept only that same-ticket interrupted state, retain its
# token, and tell the operator how to diagnose and stop it before retrying.
grep -Fq '[[ -f /var/lib/ntip/client/bootstrap.id && ! -L /var/lib/ntip/client/bootstrap.id ]]' "$template" || {
    echo "bootstrap preflight does not bind an existing identity to the same ticket" >&2
    exit 1
}
grep -Fq 'bootstrap.id|enrollment.token|identity.key|state.json|state.lock|reconfigure.pending)' "$node_installer" || {
    echo "Node installer does not admit a same-ticket interrupted identity" >&2
    exit 1
}
grep -Fq 'fail "same-ticket state is missing its enrollment token"' "$node_installer" || {
    echo "Node installer does not require retained enrollment material" >&2
    exit 1
}
for diagnostic in \
    'systemctl status --no-pager ntcl.service' \
    'journalctl -u ntcl.service -n 100 --no-pager' \
    'ntcl status --json' \
    'systemctl stop ntcl.service'
do
    grep -Fq -- "$diagnostic" "$node_installer" || {
        echo "Node installer omits required recovery guidance: $diagnostic" >&2
        exit 1
    }
done

# Parse checks alone cannot prove that Bash's ERE dialect accepts the exact
# validated origins embedded by ntip-api. Render every token, remove only the
# final mutation entry point, source the definitions, and execute the generated
# constant guard against representative DNS, IPv4, and bracketed IPv6 origins.
runtime_dir=$(mktemp -d "${TMPDIR:-/tmp}/ntip-bootstrap-origin.XXXXXX")
trap 'rm -rf -- "$runtime_dir"' 0 HUP INT TERM
runtime_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

render_runtime_installer() {
    runtime_origin=$1
    runtime_output=$2
    sed \
        -e 's|@NTIP_BOOTSTRAP_ID@|ABCDEFGH|g' \
        -e "s|@NTIP_PUBLIC_HTTPS_ORIGIN@|$runtime_origin|g" \
        -e 's|@NTIP_BOOTSTRAP_SPKI_PIN@|sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=|g' \
        -e 's|@NTIP_NODE_VERSION@|0.2.0-dev|g' \
        -e 's|@NTIP_X86_64_ARCHIVE_PATH@|/enrollment/assets/ntip-node-v0.2.0-dev-x86_64-linux-musl.tar.gz|g' \
        -e "s|@NTIP_X86_64_ARCHIVE_SHA256@|$runtime_digest|g" \
        -e 's|@NTIP_X86_64_ARCHIVE_SIZE@|1024|g' \
        -e 's|@NTIP_AARCH64_ARCHIVE_PATH@|/enrollment/assets/ntip-node-v0.2.0-dev-aarch64-linux-musl.tar.gz|g' \
        -e "s|@NTIP_AARCH64_ARCHIVE_SHA256@|$runtime_digest|g" \
        -e 's|@NTIP_AARCH64_ARCHIVE_SIZE@|1024|g' \
        "$template" | sed '$d' >"$runtime_output"
}

for runtime_origin in \
    https://ntip.example.test \
    https://ntip.example.test:8443 \
    https://10.2.40.49:8443 \
    'https://[::1]:8443'
do
    runtime_fixture=$runtime_dir/valid.sh
    render_runtime_installer "$runtime_origin" "$runtime_fixture"
    bash -c '. "$1"; validate_generated_constants' ntip-origin-check "$runtime_fixture"
done

for runtime_origin in \
    http://ntip.example.test \
    https://ntip.example.test/path \
    https://user@ntip.example.test
do
    runtime_fixture=$runtime_dir/invalid.sh
    render_runtime_installer "$runtime_origin" "$runtime_fixture"
    if bash -c '. "$1"; validate_generated_constants' ntip-origin-check "$runtime_fixture" \
        >/dev/null 2>&1
    then
        echo "bootstrap installer accepted invalid generated origin: $runtime_origin" >&2
        exit 1
    fi
done

echo "node_bootstrap_installer_contract=passed"
