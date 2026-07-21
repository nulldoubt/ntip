# Goals and non-goals

## Purpose

NTIP is a centrally managed Layer-3 interconnect for small infrastructure
teams. One authoritative Master enrolls and routes 10–250 Nodes while Linux
continues to own forwarding, firewalling, NAT, policy routing, and load
balancing.

The v0.2 objective is to add a secure management plane and operator dashboard
without changing the v0.1 Node wire protocol. Correctness, bounded resource
use, durable state, explicit trust boundaries, and reproducible evidence take
priority over throughput claims or a broad automation surface.

## Goals

### Preserve the bounded data plane

- Carry one complete IPv4 packet in each v0.1 DATA datagram.
- Keep ordinary packet handling to bounded parsing, session lookup,
  authentication, replay checks, ownership validation, routing, and I/O.
- Keep JSON, SQLite, formatted logging, and unbounded work out of the DATA hot
  path.
- Reuse bounded packet buffers and drop traffic for offline destinations
  instead of retaining unbounded queues.
- Enroll and reconnect existing v0.1 Nodes without a protocol change.

### Keep one durable authority

- Make `ntsrv` the only live SQLite owner and the authority for inventory,
  enrollment, access control, settings, operations, and immutable audit.
- Preserve one VNR per Node, unique identities/addresses/keys, non-overlapping
  VNRs and routes, reserved-address checks, and valid route ownership in
  transactions.
- Commit a mutation and its audit row before publishing one immutable runtime
  generation through bounded queues.
- Preserve Node-local identity and enrollment files independently of the
  Master database.
- Fail explicitly on unsupported legacy Master JSON instead of importing,
  deleting, or reinterpreting it automatically.

### Provide a narrow management boundary

- Keep the human CLI socket OS-authorized and add a separately peer-authorized,
  versioned service socket for the unprivileged `ntip-api` process.
- Bind `ntip-api` to loopback, enforce bounded HTTP/1.1 parsing and connection
  admission, and expose the canonical `/api/v1` OpenAPI contract.
- Require opaque web sessions, CSRF and exact-Origin checks, RBAC, ETags,
  idempotency keys, recent reauthentication, and typed confirmation where the
  operation warrants them.
- Redact protocol and enrollment secrets from public DTOs, logs, audit views,
  and generated artifacts.
- Keep QAWS as an architectural reference only; NTIP has no QAWS dependency.

### Give operators a focused dashboard

- Serve authenticated Next.js App Router pages under pinned Bun from a
  separately installed, unprivileged loopback service.
- Cover overview, VNRs, Nodes, topology, activity, users, sessions, and
  settings with role-aware workflows against real API contracts.
- Provide deterministic topology plus an accessible table, bounded polling,
  visible stale state, keyboard operation, reduced motion, and WCAG 2.2 AA
  behavior.
- Treat the TLS proxy as the sole browser router for `/api/v1`; the dashboard
  never embeds a second browser API destination.
- Use that same HTTPS edge for pinned one-command Node bootstrap: strict
  installer/redeem routes reach the API and immutable Node-only archives come
  from the root-owned bootstrap-assets directory.
- Support desktop administration at 1024 pixels and wider. Smaller viewports
  receive an explicit unsupported-size state.

### Make operations recoverable and releases inspectable

- Use transactional migrations, WAL, `synchronous=FULL`, integrity-checked
  backup/restore, a recoverable pre-restore copy, and restored-session
  revocation.
- Reconcile live and restart-required settings through immutable revisions and
  explicit desired/effective state.
- Package core, API, and Node-only static-musl Zig artifacts for x86_64 and
  AArch64; combine both Node archives in a Master bootstrap-assets package; and
  package the optional dashboard with the matching pinned glibc Bun runtime.
- Publish checksums, component SPDX SBOMs, provenance, installer isolation,
  reproducibility comparisons, systemd hardening evidence, and secret scans.
- Make every architecture, schema, contract, configuration, deployment,
  security, and milestone change update `CODEX.md` in the same changeset.

## Non-goals for v0.2

NTIP v0.2 deliberately does not provide:

- Ethernet emulation, Layer 2 frames, ARP, broadcast, STP, or multicast-domain
  behavior;
- IPv6 inner packets or IPv6 VNRs;
- overlapping VNRs, automatic address allocation, multi-VNR Nodes, multiple
  Masters, HA/failover, federation, or direct Node-to-Node transport;
- reliable or buffered DATA delivery;
- automatic firewall, NAT, load-balancer, forwarding, sysctl, TLS-proxy, or
  backup-schedule management;
- cipher negotiation, AES/FIPS agility, post-quantum exchange, 0-RTT DATA, or
  0-RTT mutation;
- SSO, MFA, API tokens, a supported external-automation contract, SSE,
  WebSockets, or mobile administration;
- SQLCipher, automatic legacy JSON migration, Node software-version telemetry,
  or direct Node-to-Node diagnostic probes;
- Next Draft Mode or Server Actions in the dashboard;
- multiqueue TUN, raw `recvmmsg`, per-core sharding, AF_XDP, DPDK, a kernel
  module, NUMA tuning, SmartNIC support, or hardware offload;
- Windows, macOS, Android, or BSD production runtime support.

These exclusions are compatibility and security boundaries, not promises about
later versions. A future feature must justify its wire, trust, persistence, and
operational cost independently.

## v0.2 release definition

A v0.2 release tag is permitted only when all of the following are true:

1. Zig formatting, unit, integration, negative, fuzz, migration, crash,
   concurrency, and two-target static-musl build gates pass.
2. Existing v0.1 Nodes enroll, exchange DATA, survive a current-Master restart,
   and reconnect unchanged in the pinned compatibility scenario.
3. HTTP/IPC framing, authentication, authorization, session, CSRF/Origin,
   ETag, idempotency, secret-redaction, and unavailable-service tests pass.
4. Dashboard lint, typecheck, unit tests, production build/start smoke, and
   Playwright pass under exactly Bun 1.3.14 with no Node.js fallback.
5. Core, API, optional dashboard, Node-only, and combined bootstrap-assets
   artifacts validate on native x86_64 and AArch64 Linux, including checksums,
   exact SBOM coverage, installer lifecycle, static/dynamic linkage policy,
   NGINX syntax, and systemd isolation.
6. Two clean source roots produce byte-identical release artifacts for each
   architecture and component.
7. No unresolved critical or high-severity security finding remains, and the
   release record identifies any still-open operational evidence explicitly.

This release definition does not claim that NTIP outperforms WireGuard. Project
materials require reproducible benchmark evidence before making a comparative
performance claim.
