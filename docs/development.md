# Development and testing

## Toolchain and repository contract

NTIP requires Zig 0.16.0 and has no third-party Zig or dynamically linked
runtime libraries. Linux operation uses `iproute2`, and packaged services use
systemd. The package
version begins at `0.1.0-dev`; `build.zig.zon`, the shared version module, CLI
`version` output, release archive names, and changelog are checked for
consistency.

On macOS or Linux:

```sh
zig version
zig fmt --check build.zig src tests
zig build check
zig build test
zig build integration
zig build fuzz
zig build version-check
zig build cross
```

`check` runs formatting, version consistency, all portable test executables, and
both cross-builds. `cross` (also exposed as `cross-build`) compiles static-musl `ReleaseSafe`
artifacts for `x86_64-linux-musl` and `aarch64-linux-musl`. Cross-compilation is
not native runtime validation; release candidates must execute on both native
architectures.

The expected release output is:

```text
zig-out/release/
├── x86_64-linux-musl/
│   ├── ntsrv
│   └── ntcl
└── aarch64-linux-musl/
    ├── ntsrv
    └── ntcl
```

## Mechanical release-artifact checks

Release packaging runs on Linux with GNU tar/coreutils, `jq`, Python 3, and
`readelf` from binutils. The CI/release reproducibility gate requires a clean,
committed tree and Zig 0.16.0:

```sh
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
scripts/check-clean-release-reproducibility.sh "$(scripts/check-version.sh)"
scripts/check-installer-isolation.sh dist/*.tar.gz
```

The clean-build script exports the committed tree into two different source
roots, gives each build a separate local cache, global cache, and install
prefix, runs `zig build release` twice, and compares `ntsrv`, `ntcl`, archives,
external SBOMs, and checksum sidecars byte-for-byte. Only one verified result
is copied into the repository's `zig-out/release` and `dist` directories.

For a faster packaging-only development check after `zig build release`, run
`check-release-reproducibility.sh`. That helper packages the same binaries
twice. It proves deterministic archive construction but is intentionally not
used as the clean compiler-output reproducibility gate.

`check-release-archive.py` rejects unexpected archive entries, unsafe paths,
links or special files, wrong modes/owners/timestamps, target-architecture
mismatches, checksum-sidecar mismatches, incomplete SPDX coverage, incorrect
file digests, and an incorrect SPDX package verification code. On a matching
Linux architecture it extracts and executes the packaged static `ntsrv` and
`ntcl` binaries, verifies their exact `version` output, and uses `readelf` to
reject an ELF interpreter or `NEEDED` dynamic-library entry. Native CI passes
`--require-native-execution`, so a skipped execution is a failure there.

The isolated installer check runs the installer and uninstaller shipped inside
each archive under a temporary `DESTDIR`. It covers initial installation,
idempotent upgrade, packaged-file replacement, preservation of operator config
and machine state, transient-runtime removal, uninstall preservation, and a
second idempotent uninstall without creating accounts or touching the host.
Normal installation with no `DESTDIR` retains all Linux/root/account/TUN and
systemd prerequisites.

CI validates every generated SPDX 2.3 JSON document with the official SPDX
project's `spdx-tools==0.8.5` parser and validator, in addition to NTIP's
archive-to-SBOM digest reconciliation:

```sh
python3 -m venv /tmp/ntip-spdx-tools
/tmp/ntip-spdx-tools/bin/pip install spdx-tools==0.8.5
PATH="/tmp/ntip-spdx-tools/bin:$PATH" \
  scripts/validate-spdx.sh dist/*.spdx.json
```

The packaged systemd units are syntax-checked and passed to
`check-systemd-security.sh`. On Ubuntu 24.04's systemd 255 both currently score
2.9; CI enforces a maximum exposure score of 3.0 (`--threshold=30`) and uploads
the full report for both native architectures. This score is a
version-dependent regression heuristic. It does not prove runtime privilege
dropping and does not satisfy the independent security-review gate.

Native disposable CI additionally runs:

```sh
sudo env NTIP_SYSTEMD_SMOKE_DISPOSABLE=1 \
  scripts/integration/systemd-master-smoke.sh
```

The explicit opt-in and empty-state check prevent accidental use on an operator
Master. The smoke starts the installed unit, proves its runtime-directory and
socket ownership, checks that the process dropped to `ntip` with only
`CAP_NET_ADMIN` live, exercises IPC, stops the unit, and verifies TUN/socket
teardown. Static unit analysis alone cannot establish those runtime facts.

## Test layers

### Unit and contract tests

`zig build test` executes the shared module tests, both CLI executable-root
tests, and `tests/protocol/all.zig`. Together they currently cover:

- canonical IPv4/CIDR parsing and range classification;
- VNR, Node, address, routed-prefix, and deletion invariants;
- strict schema JSON, state-version rejection, binary secret formats, and
  stable CLI/JSON presentation;
- datagram/control codecs and exact length/bounds behavior;
- credential parsing and HKDF derivation;
- Noise deterministic transcripts and negative cases;
- 2048-packet replay behavior;
- route snapshots, open-addressed session lookup, traffic-state hysteresis, and
  bounded queues.

Tests must use deterministic randomness only through explicit injected test
sources. Production randomness always uses the operating system CSPRNG.

### Crash consistency

Atomic-file tests inject failure before rename and prove the prior file remains
visible. The coupled Master-state/enrollment transaction test injects a crash at
each of its declared two-file commit boundaries and then runs recovery, which
must roll forward to one complete generation. Repository tests also prove that
corrupt and newer-schema state fails closed. Enrollment tests cover credential
renewal revocation, single-use consumption, and pending assignment recovery
after a lost completion acknowledgement. Native filesystem ownership, mode,
and symlink behavior remains part of the privileged Linux gate.

### Fuzz and negative tests

```sh
zig build fuzz
```

`tests/fuzz.zig` feeds deterministic byte prefixes from length 0 through 768 to
the outer header, handshake envelope and fixed payloads, control and
configuration codecs, credential, retry-cookie, transport, inner IPv4, strict
server/client state and configuration JSON, and IPC parsers. Allocating JSON and
IPC targets use independent 16 KiB fixed-buffer allocators. Structured cases
then mutate every byte of authenticated transport, control, a configuration
snapshot, and an enrollment credential; exercise replay reorder/stale/future
boundaries; mutate valid server-state JSON; and corrupt representative fields
in the binary identity secret format.

The same target exposes a Zig 0.16 coverage-guided entry point that drives every
bounded wire/state/configuration/IPC parser with inputs up to 4096 bytes and
compares the replay window with an independent bounded reference model. Run a
finite local campaign with:

```sh
zig build fuzz --fuzz=100K
```

The scheduled extended-security workflow runs two million iterations and
retains its campaign log. This provides continuously exercised fuzz targets;
the production-beta record must still cite a longer reviewed campaign and its
corpus/crash evidence before approval.

`tests/protocol/all.zig` independently sweeps short parser prefixes, mutates
every byte of an authenticated datagram, checks replay behavior, and rejects
non-base64url credentials. Unit tests provide the fixed Noise wrong-PSK,
wrong-static-key, all-zero-DH, altered-context, and tamper cases, plus endpoint
validation and source-prefix anti-spoofing. These deterministic tests remain
the pull-request smoke gate and do not replace the longer production-beta
campaign.

### Portable integration executable

```sh
zig build integration
```

`tests/integration.zig` requires no privileges. It crosses persisted Master
state into immutable forwarding/anti-spoof snapshots, delivers a multi-chunk
configuration through encoded control frames out of order, authenticates an
IPv4 DATA packet, applies replay and route ownership, and proves a forged
future sequence cannot advance replay state. Separate scenarios carry an
enrollment completion from credential derivation into client persistent state,
confirm that bearer material is excluded from that state, and exercise the
versioned IPC/client-configuration identity contracts.

### Linux namespace integration

Privileged integration is a separate shell scenario. It requires Linux 6.1+,
root, `iproute2`, `nftables`, `iperf3`, `jq`, `python3`, `tc`, and conntrack
tools:

```sh
zig build
sudo scripts/integration/ns-integration.sh
```

The scenario creates only namespace/veth/nftables resources bearing a unique
per-run prefix and records each resource before cleanup. It refuses an unsafe
prefix, handles signals, and removes only its own namespaces and temporary
files. It covers:

1. one Master, two Nodes, one NAT gateway, and a LAN behind Node 1;
2. enrollment and reconnect through NAT;
3. ICMP, TCP, and UDP Master-to-Node and Node-to-Node via the Master;
4. an explicit routed prefix behind Node 1;
5. nftables DNAT, filtering, conntrack, and load-balancer behavior;
6. authenticated endpoint migration after the NAT external source changes;
7. Master restart and fresh IK sessions;
8. loss, reorder, duplication, and delay with `tc netem`;
9. exact-MTU success, oversize DF rejection, and synthesized ICMPv4
   fragmentation-needed after an induced outer `EMSGSIZE`;
10. refusal to adopt or remove an operator-owned `ntip0`;
11. duplicate daemon start refusal plus daemon UID/capability and IPC-socket
    ownership checks.

The ICMP packet builder also has a deterministic checksum, quoted-packet, and
next-hop-MTU unit test; the namespace scenario exercises its real TUN/UDP error
path.

Never run namespace integration on a host where its configured namespace prefix
is already in use. The CI runner is disposable; on operator hardware, inspect
the script and current namespace list first.

### Unprivileged Linux runtime smoke

On a Linux host that permits unprivileged user and network namespaces, a
smaller smoke test can exercise the native daemon without installing accounts
or changing the host network namespace:

```sh
NTIP_BIN_DIR="$PWD/zig-out/bin" scripts/integration/userns-smoke.sh
```

The script creates private user, network, and mount namespaces; overlays a
synthetic `ntip` user and `ntip-admin` group only inside those namespaces;
starts `ntsrv`; verifies IPC, the `ntip0` TUN, its Master address, and `down`;
and confirms that closing the TUN descriptor removes the interface. Its
temporary directory and mount namespace are removed on exit.

This smoke is useful for native AArch64 execution on a constrained host, but it
does not exercise real service-account privilege dropping, systemd, NAT,
roaming, forwarding between Nodes, nftables, or conntrack. It therefore does
not replace the privileged namespace integration or native release gates.

### Soak and bounded resources

The release soak applies representative DATA, idle Nodes, malformed UDP,
periodic rekey, loss/reorder, endpoint changes, and Master restart for at least
24 continuous hours. Record RSS, allocation counters, queue occupancy, drops,
sequence/replay state summaries, CPU, file descriptor count, and liveness.

The beta gate requires:

- no allocator call in the packet path after worker initialization;
- bounded RSS under malformed unauthenticated traffic;
- no leaked TUN, namespace, socket, route, file descriptor, or temporary file;
- no sequence reuse, replay-window movement on failed authentication, or
  configuration partial apply;
- no critical/high finding from independent review.

## Noise interoperability

The runtime implementation is internal Zig over `std.crypto`. Independent Noise
libraries are development-only oracles and never runtime dependencies. Golden
tests pin exact prologue, protocol name, keys, ephemeral values, payloads,
handshake hashes, and the first nonce-zero transport ciphertext in both Split
directions. They also require both libraries to reject a deterministic wrong
XKpsk1 PSK and, for both XKpsk1 and IK, a wrong responder static key or altered
prologue. The checked-in evidence is compared with `noiseprotocol==0.3.1` and
`github.com/flynn/noise@v1.1.0` by running:

```sh
zig build noise-oracles
```

The in-tree Zig tests independently pin the exact official primitive vectors
used by the Noise composition:

- ChaCha20-Poly1305 AEAD from [RFC 8439 Section 2.8.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8.2);
- HKDF-SHA256 from [RFC 5869 Appendix A.1](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1);
- both X25519 vectors from [RFC 7748 Section 5.2](https://www.rfc-editor.org/rfc/rfc7748.html#section-5.2).

Run these directly with:

```sh
zig build primitive-vectors
```

They are also part of `zig build test`, so official-vector agreement is a
portable release check without adding a runtime dependency.

When updating a transcript fixture:

1. explain the intended protocol change in the wire specification;
2. increment the appropriate wire/snapshot schema when compatibility changes;
3. generate the fixture independently in both oracles;
4. retain old negative and downgrade fixtures;
5. obtain review from someone other than the state-machine author.

## CI matrix

[GitHub-hosted runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
run:

- format, unit, and version checks on macOS and Ubuntu;
- Linux x86_64/AArch64 static-musl cross-builds;
- privileged namespaces on Ubuntu 24.04;
- native AArch64 smoke/integration on an Ubuntu 24.04 ARM runner;
- parser fuzz smoke tests on every pull request and extended fuzz runs on a
  schedule or explicit dispatch;
- release packaging, SHA-256, SPDX SBOM, and provenance only from a matching
  signed `v*` tag after all manual beta gates are attested using GitHub
  [artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

The cross-build job also performs the byte-for-byte packaging and isolated
installer checks. Native x86_64 and AArch64 jobs execute their actual packaged
static binaries and retain the archive/security reports as CI evidence. These
automated checks never modify `release/gates/*.json` and do not turn native,
soak, benchmark, or independent-review evidence into an approval.

CI green status is necessary but cannot substitute for the native, 24-hour, and
independent-review gates.

The 24-hour soak is an explicitly observed release-gate run on dedicated Linux
hosts, not a claim made by the scheduled hosted-runner workflow. Its evidence
must include the continuous-session and resource measurements listed above.

## Release procedure

1. Confirm a clean tree, exact Zig 0.16.0, and version consistency.
2. Run all local and CI gates at the release commit.
3. Complete native x86_64/AArch64 integration and the 24-hour soak.
4. Resolve all critical/high review findings and archive the independent review
   summary.
5. Update `CHANGELOG.md` from Unreleased and set the final version.
6. Build with `zig build release` and package each target with
   `scripts/package-release.sh`.
7. Run the two-isolated-build archive/SBOM/installer checks above. For a final
   candidate, also reproduce the result on a separately provisioned builder;
   two roots and caches on one CI runner do not establish diverse-builder
   reproducibility.
8. Create the release tag only after gates 1–7. CI publishes archives,
   `SHA256SUMS`, SPDX SBOMs, and attestations.
9. Roll out one Master/one Node, then two Nodes/roaming, then routed-prefix/NAT,
   then scale tests, with a state snapshot before each expansion.
