# Release-gate evidence

A production-beta tag is intentionally blocked until a version-matched JSON
record in this directory has every gate marked `passed`, a nonempty evidence
reference for every gate, and `approved: true`. Evidence references identify
immutable CI runs, signed reports, or review artifacts; secrets and private
infrastructure details do not belong here.

Schema version 1 is deliberately closed. The top-level object contains exactly
`schema_version`, `version`, `approved`, and `gates`; every gate contains
exactly `name`, `passed`, and `evidence`. `approved` and `passed` are JSON
booleans, not numeric or string substitutes, and evidence is a JSON string.
The exact, unique gate-name set is:

- `native-x86_64`
- `native-aarch64`
- `24-hour-soak`
- `independent-security-review`
- `noise-interoperability`
- `benchmark-report`

CI validates the shape of every checked-in record against the version in its
filename without requiring approval:

```sh
python3 scripts/check-release-gate.py \
  release/gates/0.1.0-beta.1.json 0.1.0-beta.1
```

The release workflow adds `--require-approved`. That mode rejects
`approved: false`, any `passed: false`, and empty or whitespace-only evidence:

```sh
python3 scripts/check-release-gate.py \
  release/gates/0.1.0-beta.1.json 0.1.0-beta.1 --require-approved
```

An approved record is required to be internally release-ready even in
shape-only mode. Duplicate JSON keys, duplicate/missing/extra gate names,
unknown schema fields, wrong types, and a version mismatch fail closed.

Changing a record is a security-sensitive review action. The GitHub `release`
environment must also require a human reviewer. Release tags must be signed,
annotated tags whose GitHub tag-object verification is `valid`, resolve
directly to a commit, and point to a commit on `origin/main`.

Release validation/building runs with read-only repository permissions and a
checkout that does not persist credentials. The downstream publication job is
the only job granted content-write, OIDC, and attestation authority; it does
not check out or execute repository code and revalidates the downloaded
artifact checksums and signed tag identity after environment approval.
Development-only Noise oracles and the external SPDX validator run in separate
read-only jobs, so their network-fetched dependencies cannot modify the build
workspace or execute with publication authority.

CI archive reproducibility, packaged-binary execution, SPDX validation,
isolated installer tests, and `systemd-analyze security` reports are mechanical
evidence only. Automation never edits these records or changes `passed`,
`evidence`, or `approved`. In particular, a systemd exposure score and green CI
do not substitute for a 24-hour soak, benchmark report, native rollout record,
or independent review. The initial `0.1.0-beta.1` record intentionally remains
unapproved until those artifacts exist and are reviewed.
