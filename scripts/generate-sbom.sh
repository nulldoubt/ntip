#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 PACKAGE_ROOT VERSION OUTPUT.spdx.json" >&2
    exit 2
fi

package_root=$1
version=$2
output=$3

if [ ! -d "$package_root" ]; then
    echo "package root is not a directory: $package_root" >&2
    exit 2
fi

for command in jq sha1sum sha256sum find sort date; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "required SBOM command not found: $command" >&2
        exit 1
    fi
done

if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
    case "$SOURCE_DATE_EPOCH" in
        *[!0-9]*|'')
            echo "SOURCE_DATE_EPOCH must be an unsigned integer" >&2
            exit 2
            ;;
    esac
    created=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)
else
    created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
fi
namespace="https://ntip.invalid/spdx/ntip-$version-$(sha256sum "$package_root/bin/ntsrv" | awk '{print $1}')"
work=$(mktemp -d "${TMPDIR:-/tmp}/ntip-sbom.XXXXXX")
tmp=$work/document.spdx.json
files_tmp=$work/files
trap 'rm -rf "$work"' EXIT INT TERM HUP

# Keep generator scratch files outside the package root. The output SBOM lives
# inside release archives but is deliberately excluded from its own file list
# and package verification code.
(CDPATH='' cd -- "$package_root" && find . -type f ! -path "./$(basename "$output")" -print | LC_ALL=C sort) >"$files_tmp"

verification=$(
    while IFS= read -r relative; do
        sha1sum "$package_root/${relative#./}" | awk '{print $1}'
    done <"$files_tmp" | LC_ALL=C sort | tr -d '\n' | sha1sum | awk '{print $1}'
)

jq -n \
    --arg name "ntip-$version" \
    --arg namespace "$namespace" \
    --arg created "$created" \
    --arg version "$version" \
    --arg verification "$verification" \
    '{
      spdxVersion: "SPDX-2.3",
      dataLicense: "CC0-1.0",
      SPDXID: "SPDXRef-DOCUMENT",
      name: $name,
      documentNamespace: $namespace,
      creationInfo: {
        created: $created,
        creators: ["Tool: ntip-generate-sbom.sh"]
      },
      packages: [{
        name: "ntip",
        SPDXID: "SPDXRef-Package-NTIP",
        versionInfo: $version,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: true,
        packageVerificationCode: {
          packageVerificationCodeValue: $verification,
          packageVerificationCodeExcludedFiles: [("./ntip-" + $version + ".spdx.json")]
        },
        licenseConcluded: "Apache-2.0",
        licenseDeclared: "Apache-2.0",
        copyrightText: "Copyright 2026 NTIP contributors"
      }],
      files: [],
      relationships: [{
        spdxElementId: "SPDXRef-DOCUMENT",
        relationshipType: "DESCRIBES",
        relatedSpdxElement: "SPDXRef-Package-NTIP"
      }]
    }' >"$tmp"

index=0
while IFS= read -r relative; do
    path=${relative#./}
    digest=$(sha256sum "$package_root/$path" | awk '{print $1}')
    sha1_digest=$(sha1sum "$package_root/$path" | awk '{print $1}')
    index=$((index + 1))
    spdx_id="SPDXRef-File-$index"
    jq \
        --arg path "./$path" \
        --arg digest "$digest" \
        --arg sha1_digest "$sha1_digest" \
        --arg id "$spdx_id" \
        '.files += [{
           fileName: $path,
           SPDXID: $id,
           checksums: [
             { algorithm: "SHA1", checksumValue: $sha1_digest },
             { algorithm: "SHA256", checksumValue: $digest }
           ],
           licenseConcluded: "NOASSERTION",
           licenseInfoInFiles: ["NOASSERTION"],
           copyrightText: "NOASSERTION"
         }]
         | .relationships += [{
           spdxElementId: "SPDXRef-Package-NTIP",
           relationshipType: "CONTAINS",
           relatedSpdxElement: $id
         }]' "$tmp" >"$tmp.next"
    mv "$tmp.next" "$tmp"
done <"$files_tmp"

chmod 0644 "$tmp"
mv "$tmp" "$output"
trap - EXIT INT TERM HUP
rm -rf "$work"
