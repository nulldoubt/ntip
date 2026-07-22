# Development and testing

## Toolchain and repository contract

NTIP requires Zig 0.16.0 and has no third-party Zig modules or dynamically
linked runtime libraries. `ntsrv` statically compiles the pinned SQLite 3.53.3
amalgamation; `ntcl` and `ntip-api` deliberately do not. Linux operation uses
`iproute2`, and packaged services use systemd. The package version remains
`0.2.0-dev`; `build.zig.zon`, the Bun workspace manifests, the shared version
module, CLI `version` output, release archive names, and changelog are checked
for consistency.

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

Management contracts and the dashboard require the exact Bun 1.3.14 runtime
declared in `package.json`. Frozen installation and portable workspace gates
are:

```sh
test "$(bun --version)" = 1.3.14
bun install --frozen-lockfile
bun run contracts:validate
bun run contracts:check
bun run typecheck
bun run test
python3 scripts/check-packaging-contract.py
python3 scripts/check-vendored-sqlite.py
python3 scripts/check-secret-exposure.py
```

OpenAPI is canonical. `contracts:check` regenerates in memory and fails when the
embedded JSON, Zig document, TypeScript schema, or `openapi-fetch` client has
drifted.

The dashboard is a Next.js 16.2.10 App Router service. Development, builds,
standalone startup, and release checks use the pinned Bun runtime with no
Node.js fallback:

```sh
bun run dashboard:dev
bun run dashboard:lint
bun run dashboard:typecheck
bun run dashboard:test
bun run dashboard:build
bun run dashboard:start
bun run dashboard:runtime-smoke
bun run dashboard:e2e
```

Initial reads are Server Components using the loopback-only API origin and
`no-store`; browser reads and mutations use same-origin `/api/v1`. Next defines
no `/api/v1` rewrite; the packaged Bun gateway owns browser API, bootstrap, and
immutable-asset routing behind the operator's whole-origin TLS reverse proxy. The production build
uses `output: "standalone"`. `dashboard:runtime-smoke` must
start that output through the same checked launcher as `dashboard:start`, and
Playwright must exercise the production page/API split through one HTTPS
origin. Native archive validation separately starts the schema-2 packaged
gateway launcher and probes `/login`. `check-dashboard-release-gate.py` requires every
bounded verification command for a v0.2 release and rejects any
build/start/smoke script that introduces a Node, npm, npx, pnpm, or yarn
runtime fallback.

Next emits build-host paths, a host-derived worker count, and random
compatibility values even though NTIP uses neither Draft Mode nor Server
Actions. The dashboard fixes the build worker count, normalizes build-only path
metadata to the installed application root, rejects generated Server Actions,
and canonicalizes the remaining unsupported compatibility fields. An
all-request Next proxy rejects and clears preview cookies before routing;
Playwright and native archive smoke cover a forged compatibility cookie.
Adding Draft Mode or Server Actions requires a new security and reproducibility
design.

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
│   ├── ntcl
│   └── ntip-api
└── aarch64-linux-musl/
    ├── ntsrv
    ├── ntcl
    └── ntip-api
```

Packaging emits four architecture-matched artifacts per architecture: the core
`ntip-v...` archive (`ntsrv` and `ntcl`), `ntip-api-v...`,
`ntip-dashboard-v...`, and the Node-only `ntip-node-v...` archive. One
architecture-neutral `ntip-bootstrap-assets-v...` Master package contains both
Node-only archives, their checksum/SBOM sidecars, the strict manifest, the
installer template, and bootstrap documentation. The API installer
verifies its version against the installed core and receives no SQLite or
state-directory access. The bootstrap-assets installer validates both Node
archives and installs the manifest required by `ntip-api`; reverse-proxy
configuration remains entirely operator-owned. The dashboard installer
requires matching installed core and API
versions and bundles Bun 1.3.14 with architecture-neutral Next standalone
output.

The target names deliberately differ by component:

| Component | x86_64 target | AArch64 target | Runtime model |
|---|---|---|---|
| Core/API/Node | `x86_64-linux-musl` | `aarch64-linux-musl` | static-musl Zig binaries |
| Dashboard | `x86_64-linux` | `aarch64-linux` | glibc Bun runtime plus standalone JavaScript |
| Bootstrap assets | both Node targets in one package | both Node targets in one package | immutable static archives and strict JSON manifest |

Bun's musl assets require a musl loader that is absent on the supported
Ubuntu/systemd hosts, so they are not valid dashboard service artifacts. This
does not change the static-musl core/API/Node contract.

## Mechanical release-artifact checks

Release packaging runs on Linux with GNU tar/coreutils, `jq`, Python 3, and
`readelf` from binutils. The CI/release reproducibility gate requires a clean,
committed tree and Zig 0.16.0:

```sh
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
scripts/check-clean-release-reproducibility.sh "$(scripts/check-version.sh)"
scripts/check-installer-isolation.sh dist/*.tar.gz
scripts/check-bootstrap-assets-install.sh
```

The static-musl clean-build script exports the committed tree into two different
source roots, gives each build a separate local cache, global cache, and install
prefix, runs `zig build release` twice, and compares `ntsrv`, `ntcl`,
`ntip-api`, every core/API/Node component archive, both Node SBOMs, the combined
bootstrap-assets archive, manifests, and checksum sidecars byte-for-byte. Only
one verified result is copied into the repository's `zig-out/release` and
`dist` directories. Installer-isolation checks reject Master/API material in a
Node package and exercise installation/removal of the real bootstrap-assets
archive. Installed-system smoke probes the schema-2 dashboard gateway on its
packaged plain-HTTP port, while public TLS and forwarding policy remain an
external deployment concern.

The dashboard has a separate two-build archive check:

```sh
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
scripts/check-dashboard-release-reproducibility.sh \
  "$(scripts/check-version.sh)"
```

It copies the current source into two different absolute roots, installs each
workspace independently, performs two cache-free Next production builds, then
packages the glibc `x86_64-linux` and `aarch64-linux` dashboard targets from
each. It compares every archive, checksum sidecar, and external SPDX document
byte-for-byte. It never packages one preexisting build twice as reproducibility
proof.

For a faster packaging-only development check after `zig build release`, run
`check-release-reproducibility.sh`. That helper packages the same binaries
twice, including Node-only and—when both Node targets are selected—the combined
bootstrap-assets package. It proves deterministic archive construction but is
intentionally not used as the clean compiler-output reproducibility gate.

`check-release-archive.py` validates core, API, and Node-only archives and
rejects unexpected entries, unsafe paths,
links or special files, wrong modes/owners/timestamps, target-architecture
mismatches, checksum-sidecar mismatches, incomplete SPDX coverage, incorrect
file digests, and an incorrect SPDX package verification code. The core SBOM
must identify the exact statically linked SQLite version, upstream SHA3-256,
license, and `DEPENDS_ON` relationship; the DB-free API SBOM must omit SQLite.
On a matching Linux architecture it extracts and executes packaged static
the component binaries, verifies exact version output, and uses `readelf` to
reject an ELF interpreter or `NEEDED` dynamic-library entry. Native CI passes
`--require-native-execution`, so a skipped execution is a failure there.

`check-dashboard-release-archive.py` additionally verifies the bundled glibc
Bun ELF architecture and exact 1.3.14 SBOM entry, standalone application/static
assets, absence of links, native `.node` modules, and other ELF application
payloads, and native Bun execution when the host architecture matches.

Dashboard packaging requires `images.unoptimized=true`, copies a private
generated standalone trace, removes only trace-confirmed optional Sharp/`@img`
native image dependencies, removes dangling links, dereferences remaining
workspace links, and materializes traced sibling dependencies. This avoids
silently shipping host-native image binaries or source-tree-only Bun workspace
links. `check-dashboard-payload.py` then requires regular, non-group-writable
application files with zero symlinks, `.node` modules, or ELF application
objects before archive construction.

The isolated installer check runs the installer and uninstaller shipped inside
each of the three archives under a temporary `DESTDIR`. It covers initial
installation,
idempotent upgrade, packaged-file replacement, preservation of operator config
and machine state, core/API ownership isolation, preservation of the typed
runtime seam, dashboard application/runtime isolation, transient-runtime
removal, uninstall preservation, and a second idempotent uninstall without
creating accounts or touching the host.
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

The packaged `ntsrv`, `ntcl`, `ntip-api`, and `ntip-dashboard` systemd units
are syntax-checked and passed to `check-systemd-security.sh`. CI enforces a
maximum exposure score
of 3.0 (`--threshold=30`) and uploads the full report for both native
architectures. This score is a
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
`CAP_NET_ADMIN` live, then starts the separately installed `ntip-api` as its
zero-capability numeric identity. `/health/ready` must cross the
`SO_PEERCRED`-authenticated typed socket; liveness and the embedded OpenAPI
document are also fetched over loopback. The smoke stops both units and verifies
TUN plus human/typed-socket teardown. Static unit analysis alone cannot
establish those runtime facts.

The dashboard unit has no writable state path, supplementary groups, or access
to either Unix-socket directory. Its sole capability is
`CAP_NET_BIND_SERVICE`; it reads only its strict bootstrap, installed
application, and immutable bootstrap-assets tree. The public plain-HTTP bind
must be firewalled to the external TLS reverse proxy. It intentionally omits
`MemoryDenyWriteExecute=yes` because Bun's
JavaScriptCore needs executable JIT mappings. Native Linux service evidence
must confirm that the remaining sandbox stays intact and that the page service
cannot reach Master state or sockets.

`check-secret-exposure.py` scans repository text and release-archive members
for common private-key and provider-token signatures. It also examines complete
production `std.log` calls and rejects references to password, enrollment PSK,
opaque session/CSRF token, token-hash, private-key, or cookie material. This is
a deterministic regression gate, not a substitute for scanning release-host
state, service logs, backups, or Git history.

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
- transactional SQLite migrations/checksums, inventory invariants, immutable
  audit/export/prune rules, settings reconciliation, online backup and stopped
  restore;
- Argon2/session/throttle lifecycle, strict service IPC, bounded HTTP framing,
  CSRF/Origin/RBAC/ETag/idempotency rules, runtime read models, diagnostics,
  and audit streaming.

Tests must use deterministic randomness only through explicit injected test
sources. Production randomness always uses the operating system CSPRNG.

### Crash consistency

Node atomic-file tests inject failure before rename and prove the prior file
remains visible. Recoverable Node reconfiguration tests cover multi-file
boundaries and lost enrollment acknowledgement. Master repository tests
exercise transactional migration failure, WAL reopen, persist-before-publish,
credential replacement/consumption races, settings acknowledgement, queue
pressure, online backup, integrity-checked restore, and restored-session
revocation. Legacy Master JSON/intent refusal is tested byte-for-byte. Native
filesystem ownership, mode, hard-link, sidecar, and symlink behavior remains
part of the privileged Linux gate.

### Dashboard unit and browser tests

The Bun unit suite covers the shared two-request polling scheduler, visibility
and offline pauses, interval jitter and 20/40/60-second failure backoff,
last-known-good freshness, deterministic topology construction, role
capabilities, theme preference parsing, and mutation safety. Shared config
tests reject unknown bootstrap fields, non-loopback API origins and binds, and
invalid ports. Shared UI tests cover class composition.

Playwright uses the production build behind a same-origin HTTPS harness. The
harness launches `.next/standalone/apps/dashboard/server.js` directly with Bun
1.3.14 rather than a development server or `next start`. Its fixture separates
page traffic from `/api/v1`, implements the OpenAPI-shaped browser boundary,
and validates session cookies, Origin, CSRF,
`Idempotency-Key`, and `If-Match` behavior instead of bypassing Server Component
requests with browser-only route interception. Required journeys include login
and forced password change, all roles, inventory navigation and CRUD, the
topology table equivalent, enrollment download, diagnostics/activity, settings
rollback, session revocation, restart/shutdown recovery, stale polling, logout,
keyboard/accessibility checks, and the desktop-size guard.

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

The harness normally uses `zig-out/bin/ntcl`, preserving the complete
current-client/current-Master scenario. To prove wire compatibility with an
older Node binary, set an explicit client path and select the focused scenario:

```sh
sudo env \
  NTIP_BIN_DIR="$PWD/zig-out/bin" \
  NTIP_CLIENT_BIN=/absolute/path/to/v0.1/ntcl \
  NTIP_COMPATIBILITY_ONLY=1 \
  NTIP_TEST_ID=v01local \
  scripts/integration/ns-integration.sh
```

Focused compatibility mode still creates two fresh Nodes, configures them with
the selected client, enrolls both against the current `ntsrv`, carries DATA,
restarts the Master, and requires both persisted Nodes to reconnect before a
final Node-to-Node probe. It skips unrelated NAT, load-balancer, netem, and MTU
coverage, which remains in the default scenario.

CI builds that client from the immutable base commit
`612fec453bb112b36e547c0f7ce6317f8e23e85b` in a separate checkout and verifies
its `ntcl 0.1.0-dev` identity before running the focused scenario. This is
executable Linux evidence of v0.1 enrollment and reconnect compatibility; it
does not replace current-current namespace coverage.

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
- pinned-Bun dashboard lint, typecheck, unit, production standalone
  build/start smoke, same-origin HTTPS Playwright, and both dashboard archives;
- Linux x86_64/AArch64 static-musl cross-builds;
- privileged namespaces on Ubuntu 24.04;
- pinned v0.1 Node enrollment and reconnect against the current Master on the
  privileged x86_64 runner;
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
6. Build with `zig build release` and package each core/API target with
   `scripts/package-release.sh` using `x86_64-linux-musl` and
   `aarch64-linux-musl`; build the dashboard with the exact pinned Bun and use
   `scripts/package-dashboard-release.sh` with `x86_64-linux` and
   `aarch64-linux`.
7. Run the dashboard release gate, both reproducibility checks, and all
   archive/SBOM/installer checks above. For a final
   candidate, also reproduce the result on a separately provisioned builder;
   two roots and caches on one CI runner do not establish diverse-builder
   reproducibility.
8. Create the release tag only after gates 1–7. CI publishes archives,
   `SHA256SUMS`, SPDX SBOMs, and attestations.
9. Roll out one Master/one Node, then two Nodes/roaming, then routed-prefix/NAT,
   then scale tests, with a state snapshot before each expansion.
