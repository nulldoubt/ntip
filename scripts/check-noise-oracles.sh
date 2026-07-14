#!/bin/sh
set -eu

for command in python3 go jq cmp mktemp; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required oracle command not found: $command" >&2
        exit 1
    fi
done

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-noise-oracles.XXXXXX")
trap 'rm -rf "$work"' EXIT INT TERM HUP

python3 -m venv "$work/venv"
"$work/venv/bin/python" -m pip install \
    --disable-pip-version-check --no-input --quiet \
    -r "$repo_root/tests/protocol/requirements-oracle.txt"
"$work/venv/bin/python" "$repo_root/tests/protocol/noise_oracle.py" \
    >"$work/python.json"
(CDPATH='' cd -- "$repo_root/tests/protocol/go_oracle" && go run .) \
    >"$work/go.json"

jq -S '{xkpsk1, ik, negative}' "$repo_root/tests/protocol/noise_vectors.json" \
    >"$work/expected.json"
jq -S '{xkpsk1, ik, negative}' "$work/python.json" >"$work/python-normalized.json"
jq -S '{xkpsk1, ik, negative}' "$work/go.json" >"$work/go-normalized.json"

cmp "$work/expected.json" "$work/python-normalized.json"
cmp "$work/expected.json" "$work/go-normalized.json"
jq -e '[.negative[]] | all' "$work/python.json" >/dev/null
jq -e '[.negative[]] | all' "$work/go.json" >/dev/null
echo "Positive and negative Noise handshakes plus first post-Split transport ciphertexts agree with Python and Go independent oracles"
