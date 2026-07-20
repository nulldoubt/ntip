#!/bin/sh
set -eu

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
    echo "usage: $0 PACKAGE_ROOT VERSION OUTPUT.spdx.json [core|api|dashboard]" >&2
    exit 2
fi

package_root=$1
version=$2
output=$3
component=${4:-core}

case "$component" in
    core)
        package_name=ntip
        package_id=SPDXRef-Package-NTIP
        primary_path=bin/ntsrv
        sqlite_version=3.53.3
        sqlite_package_id=SPDXRef-Package-SQLite
        sqlite_download=https://www.sqlite.org/2026/sqlite-amalgamation-3530300.zip
        sqlite_archive_sha3=d45c688a8cb23f68611a894a756a12d7eb6ab6e9e2468ca70adbeab3808b5ab9
        ;;
    api)
        package_name=ntip-api
        package_id=SPDXRef-Package-NTIP-API
        primary_path=bin/ntip-api
        ;;
    dashboard)
        package_name=ntip-dashboard
        package_id=SPDXRef-Package-NTIP-Dashboard
        primary_path=runtime/bun
        bun_version=1.3.14
        bun_package_id=SPDXRef-Package-Bun
        ;;
    *)
        echo "unsupported SBOM component: $component" >&2
        exit 2
        ;;
esac

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
if [ ! -f "$package_root/$primary_path" ]; then
    echo "missing SBOM identity binary: $package_root/$primary_path" >&2
    exit 2
fi
namespace="https://ntip.invalid/spdx/$package_name-$version-$(sha256sum "$package_root/$primary_path" | awk '{print $1}')"
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
    --arg name "$package_name-$version" \
    --arg package_name "$package_name" \
    --arg package_id "$package_id" \
    --arg namespace "$namespace" \
    --arg created "$created" \
    --arg version "$version" \
    --arg excluded_file "./$(basename "$output")" \
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
        name: $package_name,
        SPDXID: $package_id,
        versionInfo: $version,
        downloadLocation: "NOASSERTION",
        filesAnalyzed: true,
        packageVerificationCode: {
          packageVerificationCodeValue: $verification,
          packageVerificationCodeExcludedFiles: [$excluded_file]
        },
        licenseConcluded: "Apache-2.0",
        licenseDeclared: "Apache-2.0",
        copyrightText: "Copyright 2026 NTIP contributors"
      }],
      files: [],
      relationships: [{
        spdxElementId: "SPDXRef-DOCUMENT",
        relationshipType: "DESCRIBES",
        relatedSpdxElement: $package_id
      }]
    }' >"$tmp"

if [ "$component" = core ]; then
    # SQLite is compiled into ntsrv and therefore does not appear as a
    # separate archive file. Record it as a first-class dependency instead of
    # allowing a file-only SBOM to hide the vendored runtime component.
    jq \
        --arg package_id "$package_id" \
        --arg sqlite_id "$sqlite_package_id" \
        --arg sqlite_version "$sqlite_version" \
        --arg sqlite_download "$sqlite_download" \
        --arg sqlite_archive_sha3 "$sqlite_archive_sha3" \
        '.packages += [{
           name: "sqlite",
           SPDXID: $sqlite_id,
           versionInfo: $sqlite_version,
           downloadLocation: $sqlite_download,
           filesAnalyzed: false,
           checksums: [{
             algorithm: "SHA3-256",
             checksumValue: $sqlite_archive_sha3
           }],
           licenseConcluded: "blessing",
           licenseDeclared: "blessing",
           copyrightText: "NOASSERTION",
           externalRefs: [{
             referenceCategory: "PACKAGE-MANAGER",
             referenceType: "purl",
             referenceLocator: ("pkg:generic/sqlite@" + $sqlite_version)
           }]
         }]
         | .relationships += [{
           spdxElementId: $package_id,
           relationshipType: "DEPENDS_ON",
           relatedSpdxElement: $sqlite_id
         }]' "$tmp" >"$tmp.next"
    mv "$tmp.next" "$tmp"
fi

if [ "$component" = dashboard ]; then
    bun_digest=$(sha256sum "$package_root/runtime/bun" | awk '{print $1}')
    jq \
        --arg package_id "$package_id" \
        --arg bun_id "$bun_package_id" \
        --arg bun_version "$bun_version" \
        --arg bun_digest "$bun_digest" \
        '.packages += [{
           name: "bun",
           SPDXID: $bun_id,
           versionInfo: $bun_version,
           downloadLocation: ("https://github.com/oven-sh/bun/releases/tag/bun-v" + $bun_version),
           filesAnalyzed: false,
           checksums: [{ algorithm: "SHA256", checksumValue: $bun_digest }],
           licenseConcluded: "MIT",
           licenseDeclared: "MIT",
           copyrightText: "NOASSERTION",
           externalRefs: [{
             referenceCategory: "PACKAGE-MANAGER",
             referenceType: "purl",
             referenceLocator: ("pkg:generic/bun@" + $bun_version)
           }]
         }]
         | .relationships += [{
           spdxElementId: $package_id,
           relationshipType: "DEPENDS_ON",
           relatedSpdxElement: $bun_id
         }]' "$tmp" >"$tmp.next"
    mv "$tmp.next" "$tmp"
fi

index=0
records_tmp=$work/file-records.tsv
records_json=$work/file-records.json
: >"$records_tmp"
while IFS= read -r relative; do
    path=${relative#./}
    digest=$(sha256sum "$package_root/$path" | awk '{print $1}')
    sha1_digest=$(sha1sum "$package_root/$path" | awk '{print $1}')
    index=$((index + 1))
    spdx_id="SPDXRef-File-$index"
    case "$path" in
        *"	"*)
            echo "SBOM path contains a forbidden tab: $path" >&2
            exit 1
            ;;
    esac
    printf '%s\t%s\t%s\t%s\n' "$path" "$spdx_id" "$sha1_digest" "$digest" \
        >>"$records_tmp"
done <"$files_tmp"

# Build all file objects once. Rewriting the complete SPDX document for every
# standalone Next file is quadratic and can exhaust release-runner memory.
jq -Rn '
  [inputs
   | split("\t") as $fields
   | {
       fileName: ("./" + $fields[0]),
       SPDXID: $fields[1],
       checksums: [
         { algorithm: "SHA1", checksumValue: $fields[2] },
         { algorithm: "SHA256", checksumValue: $fields[3] }
       ],
       licenseConcluded: "NOASSERTION",
       licenseInfoInFiles: ["NOASSERTION"],
       copyrightText: "NOASSERTION"
     }]
' <"$records_tmp" >"$records_json"
jq \
    --arg package_id "$package_id" \
    --slurpfile generated_files "$records_json" \
    '.files = $generated_files[0]
     | .relationships += ($generated_files[0] | map({
         spdxElementId: $package_id,
         relationshipType: "CONTAINS",
         relatedSpdxElement: .SPDXID
       }))' "$tmp" >"$tmp.next"
mv "$tmp.next" "$tmp"

chmod 0644 "$tmp"
mv "$tmp" "$output"
trap - EXIT INT TERM HUP
rm -rf "$work"
