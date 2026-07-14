#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: $0 FILE.spdx.json [...]" >&2
    exit 2
fi

if ! command -v pyspdxtools >/dev/null 2>&1; then
    echo "pyspdxtools is required (CI pins the official spdx-tools package)" >&2
    exit 1
fi

for document in "$@"; do
    if [ ! -f "$document" ]; then
        echo "SPDX document does not exist: $document" >&2
        exit 2
    fi
    pyspdxtools -i "$document"
    echo "official_spdx_validation=passed file=$document"
done
