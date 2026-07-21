# NTIP Repository Brief

This file is the living implementation brief for NTIP. It records what the
repository does today, the accepted v0.2 destination, and the evidence for each
implemented milestone. It must be updated in the same changeset as any change
to architecture, persistence, public interfaces, configuration, deployment,
security policy, or milestone status.

## Verification Header

- Base commit: `612fec4`
- Development version: `0.2.0-dev`
- Current milestone: segmented inventory inputs and actionable management
  errors are implemented and pass the complete local pre-deployment gate.
  Settled-tree backend, contract, dashboard, browser, production-runtime,
  archive, SBOM, and secret-exposure proofs pass; live deployment and native
  x86_64 service evidence remain pending.
- SQLite schema version: `1`
- Management API: canonical contract, hardened transport, auth/inventory/
  security/enrollment/diagnostics/operations/settings/read-model adapters and
  runtime lifecycle wiring implemented
- OpenAPI revision: `1.0.1` (`packages/contracts/openapi/ntip-v1.yaml`, 81
  schemas). This revision fixes inventory-error semantics without adding or
  removing a public path, operation, or schema shape.
- Dashboard: Direction A implementation present as a pinned Bun 1.3.14 /
  Next.js 16.2.10 standalone service. The current segmented-input/actionable-
  error tree passes typecheck, lint, 37/37 unit tests, the 12-route production
  build, exact-Bun runtime smoke, and 19/19 Playwright journeys.
- Last verified commit: `a718a835107438da545c56787689ca5c4e8530f6`
  (v0.2 implementation)
- Last verified implementation: commit `a718a835107438da545c56787689ca5c4e8530f6`;
  live/offline SQLite Master cutover, DB-free
  `ntip-api`, embedded contract, authenticated auth/inventory/security and
  operations dispatch, both live admin sockets, encrypted-path connectivity
  checks, enrollment application service, bounded/yielding backup and locked
  atomically audited and semantically validated restore, exact immutable-
  generation publication barriers, atomic mutation/audit/idempotency markers,
  absolute local-socket phase deadlines, off-thread Argon2 runtime checkpoints,
  staged service control, transition-only runtime events, revision
  acknowledgement, contract-aligned percent-decoded management queries,
  Direction A dashboard pages, and three separately installable deployment
  packaging paths, 2026-07-20
- Migration 0001 SHA-256:
  `d7aab9680379dec566989e2998828e063e67c9d441ae860a3871d7393f3d4678`
- Proof commands: `zig build check --summary all` (429/429 aggregate tests)
  and `zig build test --summary all` (420/420) pass for the current backend
  slice; dashboard typecheck, lint, tests (37/37), production build, exact-Bun
  runtime smoke, and Playwright (19/19) pass. Settled-tree contract validation,
  typecheck, lint, generated-artifact drift, and 13/13 tests pass. The three
  x86_64 release archives pass structure and SBOM checks, and the combined
  source/archive secret scan passes across 3,333 archive members. Prior
  verified evidence includes
  `zig build cross-build --summary all` for both static-musl targets (18/18),
  native build/version smoke, dashboard production build/runtime smoke and
  14/14 Playwright, different-root dashboard reproducibility,
  archive/installer and packaging checks, privileged AArch64 systemd/runtime
  and namespace checks, and exact-v0.1 compatibility execution. Native x86_64
  hardware execution remains open.

## Current State

At base commit `612fec4`, NTIP is a Zig 0.16 secure overlay with two primary
binaries:

- `ntsrv` is the authoritative Master and owns protocol coordination,
  enrollment, routing, the Master TUN interface, and local administration.
- `ntcl` is a Node and owns its local identity, enrollment token/state, TUN
  interface, and Master session.

The durable domain is `Store { vnrs, nodes, routes }`. A Node belongs to
exactly one VNR. VNR ranges and routed prefixes are globally non-overlapping;
Node addresses, IDs, and enrolled public keys are unique. The Master is the
transport hub, so topology does not imply direct Node-to-Node links.

Master inventory is currently stored in strict, bounded `state.json` and
enrollment data in `enrollments.json`. Coupled changes use a synced transaction
intent for crash recovery. `identity.key` remains a separate private file.
Node-local JSON state, identity, and enrollment files are independent of the
Master persistence format.

At runtime, `ntsrv` has a control loop and a separate data worker. Session
liveness, observed endpoints, counters, and traffic state are intentionally
memory-only. A versioned Unix socket exposes CLI-shaped local administration;
when the daemon is stopped, the CLI acquires the state lock and performs the
same operations offline.

The build and release system currently produces reproducible static-musl
x86_64 and AArch64 artifacts without third-party Zig packages or dynamic
runtime libraries. Existing CI covers unit, integration, namespace, systemd,
installer, release, reproducibility, hardening, and SPDX checks.

QAWS is a reference repository only. Its bounded HTTP parser, connection
admission, event-worker, keep-alive, partial-write, and integration-test
patterns may guide `ntip-api`; NTIP will not depend on or embed QAWS as a
package.

## Accepted v0.2 State

### Trust and process boundaries

```text
Browser
  -> operator-managed same-origin TLS proxy
       -> Bun/Next.js dashboard for pages
       -> loopback-only ntip-api for /api/v1
            -> peer-authenticated typed Unix socket
                 -> ntsrv operator worker
                      -> SQLite and bounded runtime queues
```

- `ntsrv` is the sole live SQLite owner and remains the protocol authority.
- `ntip-api` is an unprivileged, DB-free Zig HTTP service.
- `ntip-dashboard` is a separately packaged Bun system service.
- The private typed service socket is a lockstep-deployed implementation
  boundary. Its v2 response frame may carry bounded field violations from
  `ntsrv` to `ntip-api`; v1 frames fail closed instead of being reinterpreted.
- The existing human CLI socket, public `/api/v1` route/schema shapes, and Node
  wire protocol remain compatible.

### Persistence

Fresh v0.2 Masters use `$state_dir/ntip.sqlite3` for VNRs, Nodes, routes,
enrollment credentials, users, web sessions, throttles, settings revisions,
runtime events, connectivity checks, audit entries, and audit export receipts.
SQLite is a pinned, checksummed amalgamation statically linked into `ntsrv`.

Master `state.json`, `enrollments.json`, and the old transaction intent are no
longer authoritative. If legacy Master state is present without a v0.2
database, startup fails closed and leaves every legacy file untouched. The
Master identity key, lifetime lock, and all Node-local files remain unchanged.

Inventory mutations and their audit entries commit atomically. Durable state
is published to the protocol runtime only after commit. Runtime observations
are separate projections; transition events default to 90-day retention and
connectivity results to 30 days. Audit is append-only and has no automatic
retention.

### Configuration

Strict bootstrap files retain listeners, TUN identity, service sockets,
paths, public HTTPS origin, and HTTP capacity limits. SQLite owns revisioned
operational settings. MTU, liveness, enrollment lifetime, traffic thresholds,
and retention apply live; maximum Node capacity applies after restart. A
rollback always creates a new audited revision.

### Management contract

`/api/v1` is the documented dashboard contract. It uses opaque cookie-backed
sessions, Argon2id passwords, CSRF and exact-Origin validation, RBAC, ETags,
idempotency keys, cursor pagination, stable error codes, and strict bounded
JSON. OpenAPI is canonical and generates the TypeScript client. Machine tokens
and third-party automation guarantees are deferred.

Inventory failures may add bounded `violations` entries with canonical
`field`, stable machine-readable `code`, and human-readable `message` values.
HTTP 400 with top-level `validation_failed` covers address/CIDR parsing and
prefix-range failures. HTTP 409 with `invariant_violation` covers reserved,
outside-VNR, overlap, and dependent-resource failures; an address allocated to
another Node uses HTTP 409 with top-level `conflict` and violation code
`address_in_use`. Status and top-level code remain authoritative, message text
is not stable, and clients must preserve unknown additive violation codes.
OpenAPI 1.0.1 documents those existing public shapes and semantics; it does not
add a public route, operation, schema shape, or Node wire message.

Roles are:

- viewer: read inventory, runtime, checks, settings, events, and redacted audit;
- operator: viewer plus VNR/Node/route create/update and connectivity checks;
- superuser: deletes, enrollment, users, all sessions, settings, audit
  export/prune, restart, and shutdown.

### Dashboard contract

The dashboard is a desktop-only Next.js App Router product surface for small
infrastructure teams managing 10-250 Nodes. It uses Server Components for
initial authenticated reads and bounded client polling for live views. Its
visual language is a precise instrument: system-adaptive light/dark themes,
tinted neutrals, an oxidized-copper accent, Geist Sans/Mono, compact tables,
quiet motion, and no decorative imagery. The topology is deterministic and
read-only with an accessible table equivalent.

The deployed page service binds only to loopback. Initial Server Component
reads forward only the named session cookie to the loopback API with
`Cache-Control: no-store`; browser reads and mutations use same-origin
`/api/v1`. The operator TLS proxy routes pages to the dashboard and `/api/v1`
directly to `ntip-api`. Next defines no `/api/v1` rewrite or fallback, so a
proxy routing error fails visibly instead of silently using a build-time API
destination that can disagree with runtime `api_origin`. The dashboard owns no
state, database handle, or Unix socket access.

## Decision Log

### Accepted

- v0.2 clean break; no Master JSON import.
- VNR terminology everywhere; one VNR per Node and routes remain first-class.
- Preserve the Zig layout and v0.1 wire compatibility.
- Separate `ntip-api` and Next.js/Bun system services behind a same-origin TLS
  proxy.
- Master-only SQLite migration; Node-local persistence stays as-is.
- Filesystem protection plus online backup and verified offline restore; no
  SQLCipher.
- Three-role controlled-operator RBAC and hardened database-backed sessions.
- Append-only audit, bounded polling, Master-originated ICMP checks, and
  validated in-place inventory edits.
- Inventory IPv4 entry is selection-only: four owned Radix octet controls,
  prefix-aware VNR/route CIDRs, topology-derived Node availability, explicit
  retained-invalid host bits, and no free-text normalization.
- Actionable inventory errors cross the private socket as bounded structured
  violations. The private protocol advances to v2 in lockstep, while OpenAPI
  1.0.1 only fixes the semantics of its existing public error shape; public
  route/schema shapes, the human CLI protocol, and Node wire remain unchanged.
- Dashboard is distributed as a separate versioned artifact and runs on a
  pinned Bun runtime. Its `x86_64-linux`/`aarch64-linux` artifacts use Bun's
  glibc builds while core/API remain static-musl. Release is blocked if the
  exact Bun/Next combination fails production smoke tests.

### Implemented

- Living repository brief established.
- Product register and seed visual design context established.
- Direction A, "The Calibrated Field Instrument," is the approved dashboard
  shell. Its permanent rail and compact overview are authoritative; the
  topology and activity pages inherit the approved B/C information treatments
  without changing that shell. `DESIGN.md` records the fidelity inventory and
  the contract fields that must not be fabricated from the visual mock.
- The Direction A App Router implementation now supplies `/login`, `/overview`,
  `/vnrs`, `/vnrs/[name]`, `/nodes`, `/nodes/[id]`, `/topology`, `/activity`,
  `/security/users`, `/security/sessions`, and `/settings`. Protected Server
  Components authorize through `/auth/me`; owned Radix-backed components,
  Geist Sans/Mono, light/dark/system themes, a permanent desktop rail, explicit
  freshness/error states, role-aware actions, one-time credential handling,
  and the below-1024-pixel guard implement the approved register without fake
  vendor, hardware, or software-version telemetry.
- One shared two-slot polling scheduler serves the client islands. Overview,
  topology, Node runtime, and active-check views poll every 10 seconds;
  event/audit activity every 15 seconds; VNR and session views every 30
  seconds; and users/settings on focus or mutation. Polling
  pauses while hidden/offline, jitters, backs off through 20/40/60 seconds,
  and retains a visibly stale last-known-good projection. The read-only
  topology deterministically lays out Master/VNR/Node/route relationships and
  provides filters, pan/zoom, an inspector, and an accessible table equivalent.
- The dashboard's strict runtime `api_origin` is consumed only by server-side
  initial reads. Browser `/api/v1` has no Next rewrite; the operator TLS proxy
  is the sole router for that path and misconfiguration remains fail-visible.
- Every protected Server Component read treats an authoritative API `401` as a
  login redirect. This prevents parallel layout/page rendering from logging a
  child `ApiError`; `/auth/me` remains the authorization source and cookie
  presence alone still grants nothing.
- Private service IPC advances to v2; its only frame-shape extension is
  optional, strictly bounded field violations on terminal errors. `ntsrv` maps
  domain errors before framing, `ntip-api` validates and forwards the exact
  bounded shape, and v1 requests or responses are rejected. The public HTTP
  paths, DTO shapes, existing human CLI socket, and protocol DATA/control
  messages do not change.
- OpenAPI 1.0.1 fixes the stable inventory-violation register for fields
  `address`, `cidr`, and `prefix`: `invalid_ipv4_address`,
  `address_outside_vnr`, `address_reserved_network`,
  `address_reserved_master`, `address_reserved_broadcast`, `address_in_use`,
  `invalid_ipv4_cidr`, `noncanonical_ipv4_cidr`, `prefix_out_of_range`,
  `range_reserved`, `range_overlaps_vnr`, `range_overlaps_route`,
  `range_excludes_node`, and `range_reserves_node_address`. The code property
  deliberately remains open to additive future values; stable HTTP/top-level
  semantics and non-stable human message wording are enforced by contract
  validation and generated-artifact drift checks.
- VNR create/edit, Node create/edit, and route create/edit now use the shared
  four-octet selection core. BigInt-safe interval arithmetic derives partial
  prefixes and sparse Node availability without enumerating host ranges;
  fixed segments disable, variable segments choose the lowest compatible
  completion, VNR `/1`-`/30` and route `/1`-`/32` rules remain distinct, and a
  prefix change retains invalid host bits until an explicit correction.
- Inventory forms now focus a shared actionable-error summary, associate each
  structured violation with its field, retain request IDs, and render unknown
  additive codes safely. `address_in_use` refreshes topology, removes the
  rejected address, selects the next lowest free address, announces the
  change, and requires explicit resubmission; unavailable or exhausted
  topology disables submission.
- Domain-level VNR range, Node identity-preserving, and route update operations
  validate every dependent invariant before committing exactly one generation.
  Route IDs now travel with the in-memory projection, so prefix and owner edits
  retain the same durable management identity without changing legacy JSON or
  Node protocol representations.
- Official SQLite 3.53.3 is vendored with upstream SHA3 evidence and compiled
  with the fixed NTIP hardening flags. It is linked into `ntsrv` and dedicated
  database tests, but not `ntcl`.
- Transactional migration 0001 defines the complete v0.2 inventory, access,
  settings, operations, audit/export, and idempotency schema. Open verifies its
  source and recorded checksum, enforces WAL/FULL/foreign-key/secure-delete/
  untrusted-schema policy, and rejects legacy Master files without modifying
  them.
- A fixed-capacity connectivity correlator builds ICMP echo requests for the
  existing DATA path, intercepts only exact authenticated replies, and models
  success, timeout, and restart interruption without wire changes.
- The pinned Bun 1.3.14 workspace and canonical OpenAPI 3.1.1 document define
  all 35 `/api/v1` paths, 49 operations, 81 schemas, browser-security headers,
  stable failures, RBAC annotations, ETags, idempotency, and secret-redacted
  runtime DTOs. Generation produces immutable TypeScript definitions and an
  `openapi-fetch` client; policy validation and drift checks are executable.
  A deterministic JSON rendering is generated for the API's embedded
  `/openapi.json` response; production performs no YAML parsing. Exact
  operation and operational-setting field registers prevent structurally
  valid contract drift.
- The canonical Audit collection response now publishes the strong `ETag`
  already emitted by `ntsrv`, and the shared Timestamp schema exactly records
  the service's whole-second UTC form. Both authoritative Zig query parsers
  percent-decode URI components into bounded caller-owned scratch storage, so
  the generated `openapi-fetch` client can round-trip encoded RFC 3339 values
  and opaque cursors while malformed escapes, controls, encoded delimiters,
  unknown fields, and duplicate fields still fail closed. Numeric cursor
  decoders re-encode and compare the decoded value, rejecting non-canonical
  aliases such as leading-zero timestamps or sequences.
- Management transport foundations now include the strict loopback API
  bootstrap decoder, OpenAPI-aligned error envelope, a separate versioned
  service IPC codec, and a bounded HTTP/1.1 parser/router/partial-write cursor.
  The parser rejects transfer-encoded requests, ambiguous duplicate headers,
  oversized headers/bodies, and non-canonical framing.
- A DB-free `ntip-api` executable now serves the fixed 49-operation route
  table on a strictly loopback listener with bounded admission, workers,
  requests, keep-alive, deadlines, and response framing. Liveness and the
  generated OpenAPI JSON are local; all authoritative operations cross the
  typed Unix-socket bridge. The same executable is wired into native and both
  static-musl release architectures without SQLite linkage.
- Authentication policy implements canonical usernames, 14-256-codepoint
  passwords, fixed Argon2id (64 MiB, t=3, p=1) with rehash detection, opaque
  256-bit token hashing, role permissions, session/reauthentication lifetimes,
  exact Origin/CSRF checks, dangerous-operation preconditions, final-superuser
  protection, fixed throttling policy, and one-time temporary passwords.
- The access repository transactionally implements first-superuser bootstrap,
  canonical/tombstoned users, temporary and changed passwords, final-superuser
  protection, hash-only sliding web sessions, reauthentication, scoped
  revocation, and principal throttles. Successful authentication and lockout
  transitions commit their audit/security records with the access mutation;
  plaintext credentials and raw session/CSRF tokens never enter SQLite.
- Server and Node builds now use separate shared-source Zig modules: SQLite C
  sources are attached only to the Master/test module, keeping `ntcl` DB-free.
- SQLite maintenance implements non-replacing online backups and locked,
  stopped-service restores. Live backup copies 64 pages per step, bounds
  `BUSY`/`LOCKED` retries, and advances the non-reentrant protocol/runtime
  checkpoint between steps. Restore validates source and staged images twice,
  checkpoints WAL, retains a standalone recovery copy, revokes every restored
  web session, and commits the immutable `database.restore` audit in that same
  staged transaction before the validated image is atomically installed.
- Initial Node inventory and its one-time enrollment verifier now have a
  dedicated single-transaction repository operation. A failed credential
  insertion rolls the candidate inventory, audit entry, and durable generation
  back together.
- Enrollment completion now carries the exact PSK verified by the Noise
  handshake into the atomic persistence callback. A credential replaced after
  lookup cannot authorize consumption of its successor; persistence still
  completes before session installation.
- A strict v0.2 Master bootstrap decoder now accepts only schema version 2,
  UDP listen port, TUN name, and the absolute service-socket path. Operational
  fields are rejected rather than shadowing SQLite settings.
- The shared operator/application boundary serializes CLI and typed-service
  work around the sole live SQLite connection. Production drains protocol work
  before accepting another admin request, admits at most one management
  connection per complete runtime checkpoint, applies one absolute monotonic
  100 ms deadline across each request prefix/body and each human response or
  typed response-frame prefix/body, checkpoints long exports/backups and off-
  thread Argon2 waits, and closes mutation admission after each generation-
  producing callback. Application execution is outside the socket phase timer.
  Every committed generation is copied into an allocation-owned topology and
  kernel-route projection; the next mutation waits for its ordered, dedicated
  DATA-worker barrier acknowledgement. Replaceable runtime observations alone
  may coalesce. A post-commit capture allocation failure is fail-stop and
  startup reconstructs the exact authoritative SQLite generation.
- Both live `ntsrv` and stopped-service CLI operation now acquire the lifetime
  lock, open only `ntip.sqlite3`, load the committed Store and effective
  settings, and execute the unchanged human commands through one SQLite-backed
  application. Legacy Master JSON/intent is rejected explicitly and left
  untouched. Startup retries pending live settings through the normal runtime
  command/ack path before acknowledgement. Only an already
  `pending_restart` capacity is used to construct bounded tables; a mixed
  `pending_apply` revision keeps the prior capacity until its live portion is
  effective and a later clean restart records activation. Node admission uses
  the smaller of constructed capacity and any non-failed pending desired
  capacity, with a definitive recheck inside the inventory transaction. A
  pending reduction therefore cannot be overtaken before restart; failed
  desired history neither constrains later inventory nor poisons restore.
- `ntsrv user bootstrap USERNAME --password-stdin` is a stopped-service,
  Linux-root-only command that hashes a bounded stdin password with the fixed
  Argon2id policy and transactionally creates the sole initial superuser plus
  its immutable audit entry. `ntsrv backup --output-dir` uses SQLite's online
  backup API through both live and stopped command paths. `ntsrv restore
  --input` requires the lifetime lock, installs only an integrity-checked
  snapshot, keeps a private pre-restore recovery copy, validates the loaded
  inventory plus cross-row settings state (including restored Node capacity),
  and transactionally revokes restored web sessions plus records the completed
  restore before the staged database can become authoritative.
- A SQLite-backed handshake registry performs prepared lookups and exact-PSK
  atomic consumption, updates the live Store only after commit, and invokes an
  optional generation publisher after installation.
- Settings repository transitions commit revision payloads and audit together.
  Live changes remain pending until acknowledgement; failure preserves the
  prior effective snapshot. Mixed live/restart changes create an immutable
  system projection for the exact live-effective values, then activate the
  capacity only after a matching restart. Production now uses a capacity-one,
  newest-revision-coalescing settings mailbox. TUN/link routes and liveness are
  applied before a bounded DATA-worker command; its non-droppable
  acknowledgement atomically activates the revision, audit row, and shared
  durable configuration generation before Node configuration publication.
  Queue saturation restores the prior kernel/control snapshot and retries.
  Runtime-event and terminal connectivity retention use the effective periods
  in bounded 1,000-row-per-table startup/daily passes, with hourly catch-up
  while a saturated pass leaves an overdue backlog. Security events retain the
  fixed 90-day security policy independently of dashboard settings; expired
  sessions, stale throttle rows, and expired idempotency rows are also removed
  in bounded maintenance. Audit is never automatically pruned. A database
  trigger prevents revision payload edits.
- The production runtime-event recorder establishes a silent baseline rather
  than flooding startup state, persists only liveness/session/traffic
  transitions, drains at most 16 writes per operator-loop tick, and retains the
  newest coalesced observation through transient database pressure.
- The operations repository implements newest-first stable cursor pages for
  audit, runtime transitions, and connectivity checks. Export receipts bind an
  exact streamed SHA-256/count/cutoff proof; audit deletion is restricted to a
  recently reauthenticated, typed-confirmed prefix covered by that receipt.
  Runtime and completed-check retention default to 90 and 30 days, and startup
  durably marks unfinished checks interrupted.
- The authenticated inventory application slice now exposes bounded keyset
  reads and audited VNR, Node, and route CRUD over the committed Store. It
  enforces Viewer/Operator/Superuser boundaries, strong resource ETags, stable
  route identities, preallocated retirement sets, and persist-before-publish
  callback ordering; enrollment secrets and idempotency replay remain outside
  this inventory-only boundary.
- The production authentication application now places fixed-policy Argon2id
  work behind a global bounded queue and uses a constant dummy PHC path for
  unknown principals. A per-process HMAC selector maps unknown canonical
  usernames into 64 fixed durable rows, bounding rotation without exposing a
  predictable bucket mapping. Every bounded invalid known/unknown candidate
  performs Argon2, records its throttle side effect transactionally, and
  returns `401`; replaying the same login idempotency key returns that exact
  failure without counting it twice. Only a correct credential for a throttled
  principal or saturated admission returns `429`. Production hash/verify jobs
  run off the serialized owner on copied, wiped buffers. The owner retains no
  SQLite transaction and advances protocol-critical work at intervals no
  longer than 100 ms. Successful login, optional PHC rehash, session creation,
  throttle reset, and audit commit atomically. Access read models add bounded
  cursor pages for users and sessions without exposing token hashes.
- A central typed-service API dispatcher now revalidates method, target,
  headers, query, and strict JSON independently of the HTTP edge; performs
  session, password-change, CSRF, exact-Origin, RBAC, reauthentication,
  confirmation, and ETag checks; and serves the auth and VNR/Node/route slices
  using camelCase JSON and stable public errors. The service request arena and
  fixed I/O buffers are wiped after every request.
- Durable idempotency storage now hashes keys and canonical request material
  with an identity-derived HMAC bound to the raw idempotency key,
  supports bounded replay records, and prunes expired entries. Central POST
  dispatch authenticates before reservation or non-login replay, scopes keys
  to a login principal or live opaque session, hashes a recursively key-sorted
  request projection, and replaces authentication secret fields with a
  constant marker to prevent password-equality oracles. Audited operations arm
  a SQLite commit hook when they insert the web audit row; the hook moves the
  internal reservation from `102` to consumed-without-response `103` in the
  same transaction as the mutation and audit. Failed authentication is the
  intentional non-audited exception: it explicitly arms the hook so its
  throttle update and marker commit together; the first lockout transition
  also records its required security event. Exact safe response attachment
  follows in a separate
  transaction; its failure retains `103`, returns a stable conflict on retry,
  and never re-executes the operation. Startup releases only abandoned `102`
  rows. Safe error envelopes, including failed-login `401` results, are
  replayed exactly after their committed side effect. Successful login,
  enrollment, temporary-password, and audit-export responses never persist raw
  one-time material.
- Typed error frames now carry strictly validated, code-specific public
  metadata through capture, replay, streaming, and DB-free edge fallbacks.
  Stale preconditions return the authoritative current `ETag`; rate-limited and
  unavailable responses return a bounded `Retry-After`. Zig conformance and
  HTTP integration tests enforce the OpenAPI `412`, `429`, and `503` contract.
- The security API slice now serves superuser-scoped user pages/read/create/
  update/tombstone/password-reset and own-or-superuser session pages/revokes.
  It enforces strict bodies and cursors, CSRF, RBAC, strong user/session ETags,
  recent reauthentication and exact username confirmation where dangerous,
  final-superuser rules, atomic session revocation, one-time password wiping,
  and cookie clearing when the current session is revoked.
- Web-originated authentication, user/session, VNR, Node, route, enrollment,
  settings, diagnostic, audit, and service-control audit rows retain the
  bounded User-Agent and the independently revalidated `loopback` proxy peer.
  Passwords, cookies, CSRF/session tokens, enrollment material, and private
  resource projections never enter audit details.
- Master startup now validates the isolated `ntip-api` UID/GID and its
  `0750` socket directory, creates `/run/ntip-api/ntsrv-api.sock` as
  `ntip:ntip-api` mode `0660` before dropping privilege, authenticates every
  accepted service peer with `SO_PEERCRED`, and registers the typed listener
  alongside the unchanged OS-authorized human CLI listener. Dot-segment and
  ambiguous service-socket paths are rejected. Runtime startup also requires
  numerically distinct `ntip`/`ntip-api` UIDs and pairwise-distinct `ntip`,
  `ntip-api`, and `ntip-admin` GIDs; installers reject duplicate numeric
  passwd/group aliases for each trusted identity.
- Strict configuration validation now rejects service-socket dot segments and
  ambiguous HTTPS origin labels. API and human-CLI Node creation enforce both
  the constructed restart-applied `maximum_nodes` capacity and any lower non-
  failed pending capacity, then transactionally recheck before persistence.
  Settings plus every enrollment issuance path share the
  60–2,592,000-second default-lifetime bound. OpenAPI,
  Zig DTO conformance, runtime validation, and SQLite also share the
  1–3,600-second traffic-hysteresis bound.
- Packaging defines separately installable core, DB-free `ntip-api`, and
  dashboard artifacts with exact-version install order. The dashboard archive
  uses glibc targets `x86_64-linux` and `aarch64-linux` because Bun's official
  musl binaries require a musl loader that is absent on the supported
  Ubuntu/systemd hosts. Core and API remain static-musl. The dashboard carries
  its architecture-matched pinned Bun 1.3.14 runtime, architecture-neutral
  Next standalone output, strict bootstrap, isolated identity, systemd unit,
  component SBOM, checksum, installer, and uninstaller. Its unit owns no state
  or socket access and permits loopback IP only; JavaScriptCore's JIT is the
  documented reason it omits `MemoryDenyWriteExecute=yes`. Native AArch64 glibc
  archive/SBOM/Bun execution and isolated installer lifecycle are verified.
  The x86_64 runtime, strict launcher, preview guard, and installer lifecycle
  also pass in an AMD64 Ubuntu container on the ARM development host; native
  x86_64 hardware and privileged service lifecycle evidence remain pending.
- Dashboard runtime parsing uses the namespaced
  `NTIP_DASHBOARD_LISTEN_HOST` variable populated by the strict launcher;
  ambient Linux/container `HOSTNAME` values cannot alter or prevent its
  loopback-only bind. The launcher separately sets Next's framework-level
  `HOSTNAME` immediately before importing the standalone server.
- Delivery now has a pinned-Bun dashboard CI job and a v0.2 release guard that
  requires lint, typecheck, unit tests, exact-Bun production build/start smoke,
  and same-origin HTTPS Playwright. There is no Node.js runtime fallback.
  Local production start and the browser harness share the checked standalone
  launcher, which imports generated `server.js` directly with Bun; the package
  has a separately tested strict-JSON launcher and neither path uses the
  incompatible `next start` command. Because NTIP deliberately uses neither
  Next Server Actions nor Draft Mode, the release gate scans dashboard and
  shared source extensions, the build rejects generated actions, and an
  all-request proxy rejects and clears preview cookies. The build fixes worker
  topology and normalizes build-host paths plus unsupported compatibility
  fields; two clean installs at different absolute source roots now produce
  byte-identical archives for both dashboard targets.
  Source/archive secret-signature and production-log sink scanning,
  component-specific SBOMs that identify SQLite only in the core dependency
  graph, and installed-but-never-enabled backup unit examples remain enforced.
  README, architecture, storage/IPC, threat, development, and operator
  documentation now describe the clean-break database, dual IPC trust
  boundary, API isolation, recovery, deployment, and unchanged Node wire.
- Active version surfaces now consistently use `0.2.0-dev` across Zig package
  metadata, the Bun workspace manifests/lockfile, README, protocol, changelog,
  security, and development documentation. The version gate checks both
  workspaces. The
  unreleased v0.1 beta gate remains an explicitly superseded historical record.
- A transport-independent operations service now projects bounded event,
  redacted audit, connectivity-check, and settings pages; enforces strict
  cursors, deadlines, RBAC, strong state-sensitive ETags, recent reauth and
  typed confirmation; and owns audited check creation, settings revisions and
  rollback, prefix-safe audit export/prune, and restart/shutdown decisions.
  Audit export pre-generates its receipt ID before streaming, scans the exact
  ascending prefix in 64-row prepared-statement batches, finalizes every
  batch before checkpointing higher-priority work, and commits the receipt and
  audit before emitting its terminal receipt record. Production checkpoints
  enforce the absolute deadline and advance control/protocol, connectivity,
  settings, runtime-event, and snapshot work without recursively accepting a
  service request.
- The operations HTTP/IPC adapter now implements connectivity checks, events,
  redacted audit, bounded audit-export frames and metadata, prefix pruning,
  settings/revisions/rollback, and restart/shutdown contract DTOs with strict
  targets, queries, bodies, cursors, deadlines, ETags, RBAC, and dangerous-
  operation checks. The central dispatcher authenticates and CSRF-checks the
  request before invoking it.
- Audit export is the sole end-to-end streaming HTTP operation. Its NDJSON
  body crosses the private socket and public HTTP/1.1 response in bounded
  32-KiB chunks without whole-body buffering, under the existing 1,024-frame
  and absolute-deadline limits. The API edge validates the exact download
  metadata before sending a chunked, no-store, connection-closing response;
  pre-header failures remain normal JSON errors, while any failure after the
  head closes an unterminated stream. The central idempotency path stores only
  an internal consumed marker in the same transaction as the durable export
  receipt and audit; it never stores export bytes. Failure to attach the later
  exact completion envelope leaves that marker intact, produces a truncated
  public stream, and prevents a second export. Credential-bearing routes retain
  capture-before-delivery.
- The HTTP edge uses reclaiming request allocation and wipes keep-alive input,
  decoded/reparsed private response trees, streamed chunks, owned one-time
  bodies/cookies, and stack response heads. This covers session cookies, CSRF
  values, temporary passwords, and enrollment credentials on success and
  malformed/error paths.
- Enrollment administration now issues or atomically replaces a one-time raw
  credential while persisting only its derived PSK, and resets enrollment by
  revoking unused credentials, clearing the Node key/state, auditing, and
  publishing one generation in the same ordered application flow. The raw
  download is wiped after response encoding and is explicitly non-replayable.
- Public Node reads now derive the three-state enrollment projection
  (`unenrolled`, `credential_issued`, `enrolled`) with prepared SQL and
  authoritative time while the protocol/domain Store deliberately retains its
  wire-compatible two-state model. Expiry, replacement, reset, precedence,
  and all three list filters are covered.
- Connectivity checks are now wired into the live Master runtime through a
  bounded reservation/completion channel. The data worker injects ICMP echo
  requests through the existing authenticated DATA path, intercepts only the
  exact authenticated reply before TUN delivery, and durably records success,
  timeout, failure, interruption, or startup recovery without any wire change.
- Restart/shutdown decisions remain audited but non-executable while `staged`.
  The mutation/audit/consumed marker commits atomically, the exact `202`
  envelope is then made durable, and only then does the decision become
  runtime-visible. It is armed before delivery so an in-process failed response
  flush still executes it at most once; the serialized runtime observes it only
  after request handling returns. Pre-completion failures discard only their
  exact stage, and replay never re-arms. Shutdown unwinds normally; managed
  restart exits with status 75, while manual launches reject restart. Abrupt
  process death between durable response completion and process-local arming is
  not recovered as a pending control intent in v0.2.
- Overview, deterministic topology, and paginated runtime-Node read models now
  join one coherent observation timestamp with the committed inventory and
  settings snapshots. Their strong ETags cover exact projections, credential
  state is re-derived without selecting credential material, and public
  runtime DTOs have compile-time guards against keys, PSKs, protocol session
  IDs, and software versions. `/overview` also supplies the distinct fresh
  service-control ETag required for restart/shutdown If-Match requests.
- Node detail responses now join the same bounded, secret-free runtime
  observation used by topology/runtime pages. A transient ephemeral-runtime
  lookup failure yields the contract's nullable runtime field and cannot turn
  an already committed Node mutation into an apparent retryable failure.
- Public runtime traffic DTOs preserve the configured telemetry vocabulary
  (`unknown`, `cold`, `warm`, `hot`, `saturated`) instead of collapsing it to
  idle/active.
- Linux CI now builds the exact base-commit `ntcl 0.1.0-dev`, substitutes only
  that client into a focused namespace scenario, proves two fresh enrollments
  and DATA flow, restarts the current v0.2 Master, and requires both persisted
  v0.1 Nodes to reconnect. The installed systemd smoke also starts the
  separately packaged `ntip-api`, crosses the peer-authenticated typed socket
  through `/health/ready`, validates liveness/OpenAPI, and checks its zero-capability
  numeric identity. Both scenarios passed in the privileged,
  architecture-matched AArch64 Linux container; native x86_64 remains CI-only.

### Deployment-pending

- Take an online SQLite backup, then deploy `ntsrv` and `ntip-api` together
  because private IPC v1 and v2 are
  intentionally incompatible. Exercise VNR, Node, route, collision,
  unavailable, and exhausted flows through the real same-origin UI before
  recording live verification.
- Complete native x86_64 hardware execution during that deployment. No current
  statement in this brief claims that the segmented-input/actionable-error tree
  is deployed or release-final.

### Deferred or out of scope

- SSO, MFA, API tokens, SSE/WebSockets, mobile administration, Node software
  version telemetry, direct Node-to-Node probes, SQLCipher, automatic backup
  scheduling, legacy Master import, and Zig source-tree relocation.
- Durable resumption of a restart/shutdown intent after abrupt process death in
  the narrow interval between persisted `202` completion and in-memory arming.
  The accepted in-process path remains audited, response-ordered, and at-most-
  once; the existing idempotency row prevents re-execution after recovery.

## Milestones

- [x] Repository intake and decision-complete v0.2 plan
- [x] Product/design context and approved visual direction
- [x] Shared operator seam and SQLite application repository
- [x] Authentication, audit, settings, backup/restore
- [x] Typed service IPC and hardened HTTP API
- [x] OpenAPI and generated TypeScript client
- [x] Bun workspace and Direction A dashboard implementation verification
- [x] Segmented inventory inputs, private IPC v2 violations, and scoped
  backend/dashboard verification
- [x] Settled-tree contract, production dashboard, browser, and release-archive
  proof for the segmented-input/actionable-error milestone
- [ ] Live deployment, native x86_64 service, and same-origin verification
- [x] Packaging, systemd, CI, documentation, and release evidence

## Verification Commands

The list grows with the implementation and is invoked from the repository
root. GNU/Linux, matching-architecture, root, namespace, and systemd
prerequisites still apply to the commands that exercise those facilities.

```sh
zig build check --summary all
zig build test --summary all
zig build
zig build cross-build
bun install --frozen-lockfile
bun run contracts:validate
bun run contracts:check
bun run --cwd packages/contracts typecheck
bun run --cwd packages/contracts test
bun run typecheck
bun run test
bun run dashboard:lint
bun run dashboard:typecheck
bun run dashboard:test
bun test ./apps/dashboard/test/unit/segmented-network-input.test.tsx
bun run dashboard:build
bun run dashboard:runtime-smoke
bun run dashboard:e2e
python3 scripts/check-packaging-contract.py
python3 scripts/check-vendored-sqlite.py
python3 scripts/check-secret-exposure.py
python3 scripts/check-dashboard-release-gate.py "$(scripts/check-version.sh)"
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct HEAD)"
scripts/check-dashboard-release-reproducibility.sh "$(scripts/check-version.sh)"
python3 scripts/check-dashboard-release-archive.py "$(scripts/check-version.sh)" \
  x86_64-linux "dist/ntip-dashboard-v$(scripts/check-version.sh)-x86_64-linux.tar.gz"
python3 scripts/check-dashboard-release-archive.py "$(scripts/check-version.sh)" \
  aarch64-linux "dist/ntip-dashboard-v$(scripts/check-version.sh)-aarch64-linux.tar.gz"
# Add --require-native-execution to the matching target on each Linux host.
scripts/check-installer-isolation.sh \
  "dist/ntip-dashboard-v$(scripts/check-version.sh)-x86_64-linux.tar.gz" \
  "dist/ntip-dashboard-v$(scripts/check-version.sh)-aarch64-linux.tar.gz"
scripts/check-systemd-security.sh --offline packaging/systemd/*.service
```

Latest evidence:

- Current working-tree backend slice: `zig build test --summary all` passed
  420/420 and `zig build check --summary all` passed 429/429, including private
  IPC v2 field-violation framing, public mapping, bounded forwarding, and
  contract-conformance coverage.
- Current integrated dashboard slice: `bun run dashboard:typecheck`,
  `bun run dashboard:lint`, and `bun run dashboard:test` passed; the unit
  result is 37/37 and includes 14 segmented-network tests for BigInt
  boundaries, `/20` partial prefixes, `/24` allocation holes, `/30`
  exhaustion, `/16` host/broadcast semantics, retained-invalid host bits,
  fixed segments, and no parent change callback during render.
- Settled-tree contract validation, typecheck/lint, generated-artifact drift,
  and 13/13 contract tests pass. The 12-route dashboard production build,
  exact-Bun runtime smoke, and 19/19 Playwright journeys pass on the same tree.
  The core and API x86_64 static-musl archives and dashboard x86_64 glibc
  archive pass contract/SBOM checks; source and all 3,333 archive members pass
  the secret-exposure scan. Live deployment and native x86_64 service proof
  remain pending. These working-tree results do not advance the Last verified
  commit field or claim release-final verification.

The remaining evidence in this section records the previously verified
implementation unless a bullet explicitly identifies the current working-tree
milestone. It must not be read as production proof for the new controls or
private IPC v2.

- `zig build check --summary all`: 47/47 steps and 421/421 aggregate unit,
  integration, primitive-vector, and fuzz tests passed, including formatting,
  version consistency, and both cross-build compile probes.
- `zig build fmt-check --summary all`: 2/2 formatting steps passed on the
  current tree.
- Native build completed 8/8 and `ntsrv version`, `ntcl version`, and
  `ntip-api --version` each reported `0.2.0-dev`.
- `zig build test --summary all`: 412 tests passed after Master-only SQLite,
  management transport/security, application-repository, and bounded
  connectivity-correlation integration, backup/restore, enrollment
  replacement-race hardening, the DB-free HTTP executable, and access/audit/
  event/connectivity repository integration, stable route identities, and the
  live/offline clean-break application cutover, and the operator lifecycle
  command integration, authenticated inventory and auth application
  integration, hardened service-request memory handling, and live registration
  of the peer-authenticated typed service socket, security user/session
  dispatch, central durable idempotency reservation/replay integration,
  enrollment reset/credential transactions, the operations HTTP/IPC adapter,
  live encrypted-path connectivity dispatch/completion wiring, and post-flush
  managed restart/shutdown execution, and time-correct three-state enrollment
  read projections, bounded end-to-end audit-export streaming, effective
  capacity/lifetime validation, transition-only runtime-event persistence, and
  priority-safe export/backup checkpointing, Zig/OpenAPI route/DTO
  conformance, real HTTP-to-typed-service integration coverage, audit
  attribution, bounded unknown-principal throttling, secret-memory wiping,
  immutable publication saturation, staged service-control failure/replay,
  Node-detail runtime coverage, restart-required generation activation, and
  failure-atomic staged restore auditing, live-session-before-replay,
  mutation/audit/idempotency crash windows, anonymous-throttle non-enumeration,
  exact failed-login replay, expired-session replay denial, off-thread Argon2
  progress, absolute partial-I/O socket deadlines, restored settings/inventory
  semantic validation, transactional pending-capacity admission (including
  failed-revision release), and runtime `ETag`/`Retry-After` conformance.
- `zig test src/management/api_request.zig`: 24/24 focused forwarded-request,
  bounded query-decoding, HTTP parser, auth, and service-IPC tests passed.
- `zig test src/management/root.zig`: 30 tests passed in Debug and ReleaseSafe
  before root-module integration.
- `zig test src/runtime/connectivity.zig`: 6 tests passed.
- SQLite repository target: 8 tests passed with the production C flags.
- SQLite x86_64-linux-musl and aarch64-linux-musl compile probes passed.
- Full static-musl `cross-build` passed (18/18 steps) for `ntsrv`, DB-free
  `ntcl`, and DB-free `ntip-api` on x86_64 and AArch64.
- `zig build release --summary all` passed 14/14 steps for the same two
  architecture-matched artifact sets.
- `file` identified the current x86_64 and AArch64 `ntsrv`/`ntip-api` release
  binaries as statically linked ELF executables.
- Bun 1.3.14 frozen install passed with no lockfile changes.
- OpenAPI validation passed: 35 paths, 49 exact method/operation pairs, 81
  schemas. The exact-operation gate prevents a valid-YAML operation from being
  misplaced outside its path item.
- Contract generation/drift check and TypeScript typecheck passed.
- Bun contract tests: 11 passed, 0 failed, including exact public runtime
  traffic-state vocabulary, the Audit collection ETag, canonical whole-second
  UTC timestamps, and `openapi-fetch` URI encoding for cursors and timestamps.
- Dashboard TypeScript checking and the 12-route Next standalone production
  build passed on the current page implementation. Production-start smoke
  passed under Bun 1.3.14, covering build presence, anonymous `307`, an
  authenticated production Server Component read, and clean `SIGTERM`.
  Dashboard unit tests passed 18/18 with 103 assertions; shared configuration
  tests passed 4/4 and owned UI tests passed 1/1. Full dashboard lint passed.
- Exact-tree production-standalone Playwright passed 14/14 in 18.8 seconds with
  one worker after removal of the Next API rewrite. The harness launched the
  same checked standalone entry as `dashboard:start` under Bun 1.3.14 with no
  `next start` fallback or warning. It covered anonymous redirect, forced
  temporary-password change, exact forged-preview-cookie rejection/recovery,
  mutation framing and explicit `501`, Viewer RBAC/navigation, Operator VNR/
  connectivity creation, ETag `428`/`412`, stale polling with the two-request
  ceiling, the 1023/1024 desktop guard, keyboard topology/table parity,
  automated WCAG 2.2 AA checks, light/dark rendering, one-time user-secret
  download/redaction, all-session revocation, settings commit, and restart.
  Service control forced a readiness interruption before the UI emitted its
  recovered state, then accepted shutdown, with both `If-Match` and idempotency
  headers verified.
  Visual evidence is retained under `output/playwright/direction-a-overview-
  {light,dark}.png`.
- Packaging bootstrap/trust-boundary validation passed; source plus all six
  current core/API/dashboard archives' secret scan inspected 295 text files,
  16 complete production log calls, and 6,660 archive members without a
  finding.
- Dashboard payload packaging now requires unoptimized Next images, prunes only
  trace-confirmed optional Sharp/`@img` native dependencies, removes dangling
  links, dereferences workspace links, and materializes traced sibling
  dependencies. Each complete package-shaped payload passed with 3,266 regular
  files, zero symlinks, and zero `.node` modules. Both final archives contain
  3,286 files with exact checksum/SBOM coverage, and both external SPDX
  documents passed official `spdx-tools==0.8.5` validation. Native AArch64 and
  AMD64-emulated Ubuntu runs executed the pinned Bun 1.3.14 runtime, started the
  strict packaged launcher, rejected the exact forged preview cookie, served
  `/login`, and passed staged install, repeated upgrade, and uninstall
  isolation. Native x86_64 hardware proof remains pending.
- Dashboard reproducibility copied the current source into two different
  absolute roots, performed separate frozen installs and cache-free Next
  production builds, and produced byte-identical `x86_64-linux` and
  `aarch64-linux` archives, checksum sidecars, and external SPDX documents. It
  does not package one preexisting build twice or compare two same-root builds.
- Ubuntu 24.04 AArch64 `systemd-analyze security --offline` passed the 3.0
  maximum for all four service units; `ntsrv` scored 2.9 and `ntip-api` plus
  `ntip-dashboard` scored 1.3. This is static, version-specific evidence and
  does not replace installed service-lifecycle smoke.
- A privileged Ubuntu 24.04 AArch64 systemd boot installed the current core,
  API, and dashboard archives and verified all four installed units. The
  Master/API smoke passed runtime UID/GID and exact capability checks, human
  and typed socket ownership, live/ready/OpenAPI requests through the
  `SO_PEERCRED` boundary, and clean TUN/socket teardown. The packaged dashboard
  then served `/login` under its dedicated UID with no capabilities. The smoke
  harness was hardened to reset only actually failed units, wait for the live
  admin socket and a `running` projection instead of accepting an offline
  `stopped` response, and remain portable to Ubuntu's `mawk`.
- The full current-client AArch64 namespace scenario passed enrollment,
  routed and Node-to-Node traffic, TCP/UDP load, NAT state loss and roaming,
  MTU-sized DATA, Master restart, reconnect, and cleanup. A second focused run
  built `ntcl 0.1.0-dev` from exact commit
  `612fec453bb112b36e547c0f7ce6317f8e23e85b`, enrolled both Nodes against the
  v0.2 Master, exchanged DATA, restarted the Master, and passed persisted v0.1
  reconnect compatibility without a protocol change.
- Vendored SQLite verification matched version 3.53.3, all three retained
  source SHA3-256 digests, fixed C flags, the DB-free client/API module split,
  and the upstream archive pin used by both SBOM generation and validation.
- Current core/API packages for both targets passed archive structure,
  checksum, exact-SBOM, static-linkage metadata, and isolated `DESTDIR`
  install/upgrade/uninstall checks, including documented-but-not-enabled backup
  examples and absence of API state access. Native AArch64 executed all three
  static binaries; Docker Desktop's x86_64 Rosetta path rejected the static
  binary with `bss_size overflow`, so native x86_64 execution remains CI-only
  evidence and is not counted as passed here.
- Repackaging the same current core/API binaries twice produced byte-identical
  archives, external SPDX documents, and checksum sidecars for both targets.
  This package-construction result is complemented by the clean compiler proof
  below.
- An architecture-matched Ubuntu AArch64 disposable snapshot of the current
  working tree passed the exact Zig 0.16.0 clean-release gate. Two committed
  source roots with separate local and global Zig caches independently rebuilt
  `ntsrv`, `ntcl`, and `ntip-api` for both musl targets; every binary, core/API
  archive, checksum sidecar, and SPDX document compared byte-for-byte. Native
  AArch64 archive execution also passed in both builds; x86_64 execution was
  correctly skipped on the non-native host.
- All six generated core/API/dashboard SPDX documents passed official
  `spdx-tools==0.8.5` validation; the core documents declare pinned SQLite
  3.53.3 and API documents do not.
- Workflow YAML, Python bytecode compilation, shell syntax, repository-local
  Markdown links, version-surface consistency, and the dashboard packaging
  contract passed.
- The exact base commit `612fec453bb112b36e547c0f7ce6317f8e23e85b`
  builds locally as `ntcl 0.1.0-dev`; CI now records that identity and runs the
  pinned-client enrollment/DATA/reconnect namespace proof against current
  `ntsrv`.
- All 15 release-gate validator negative/positive tests passed, and the
  superseded v0.1 beta record remains valid but deliberately unapproved.
- The v0.2 dashboard release gate fails closed unless lint, typecheck, unit,
  production build/start smoke, and Playwright all pass under Bun 1.3.14. Each
  constituent dashboard command passed on this development tree; the final-
  version wrapper remains not applicable to `0.2.0-dev`.
- Final independent security/concurrency re-audits found no remaining P0/P1 in
  the implemented non-visual slices; the documented process-death control-
  intent recovery limitation remains deferred. A separate read-only review of
  the pending-capacity fix found no actionable P0/P1/P2.

Native x86_64 hardware execution remains release work. macOS cannot provide
that matching-host proof; the architecture-matched AArch64 container and
AMD64-emulated checks recorded above are strong preflight evidence, not a
substitute for the native x86_64 CI job.
A milestone is not complete until its commands have been run against the
current working tree and the result is recorded here.
