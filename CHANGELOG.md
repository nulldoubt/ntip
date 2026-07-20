# Changelog

All notable changes to NTIP are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and release tags use
semantic versioning once the beta release gate is met.

Development version: `0.2.0-dev`.

## Unreleased

### Added

- Clean-break v0.2 SQLite management plane, authenticated loopback HTTP API,
  typed service IPC, access/audit/settings/diagnostics application services,
  and canonical generated OpenAPI contracts.
- Architecture-matched, separately installable DB-free `ntip-api` artifacts,
  hardened systemd deployment, online backup/stopped restore, and component
  SBOM/reproducibility/secret-scan gates.
- Direction A operations dashboard with authenticated Next.js App Router
  pages, owned Radix-backed UI primitives, deterministic topology and table
  alternative, bounded stale-aware polling, role-aware management flows, and
  system/light/dark desktop presentation.
- Separately installable glibc `ntip-dashboard` artifacts for
  `x86_64-linux` and `aarch64-linux`, containing pinned Bun 1.3.14 and Next
  standalone output, strict loopback bootstrap, an isolated systemd identity,
  component SBOM/checksum, and a release gate that forbids a Node.js runtime
  fallback. Zig core/API artifacts remain static-musl.
- Cross-root dashboard reproducibility checks plus a direct standalone Bun
  launcher for local, browser-test, and packaged production startup.
- Initial `ntsrv` and `ntcl` project structure for Zig 0.16.0.
- Versioned NTIP wire and local IPC contracts.
- VNR, Node, routed-prefix, enrollment, and persistent-state model.
- Portable Linux TUN/UDP runtime and network-namespace test topology.
- Installation, operation, recovery, threat-model, benchmark, and release
  documentation.
- Reproducible static-musl core/API release packaging for Linux x86_64 and
  AArch64.
- Coverage-guided parser/replay fuzzing and strict evidence-backed release
  gating that remains closed until every production-beta prerequisite passes.

### Security

- Isolated the dashboard from Master state and both local IPC sockets; its
  systemd unit has no capabilities, permits loopback IP only, and documents
  the JavaScriptCore JIT exception to `MemoryDenyWriteExecute`.
- Kept initial authenticated page reads on the server-only loopback API path
  while browser mutations use same-origin `/api/v1` with the API's existing
  session, Origin, CSRF, ETag, idempotency, and reauthentication controls.
- Removed the dashboard's build-time `/api/v1` rewrite so the TLS proxy is the
  sole browser API router and proxy/config drift fails visibly.
- Isolated the dashboard bind policy from ambient container `HOSTNAME` through
  `NTIP_DASHBOARD_LISTEN_HOST`, normalized build-host-only Next metadata, and
  rejected preview compatibility cookies before routing. Draft Mode and Server
  Actions remain forbidden and are covered by source, generated-artifact,
  browser, and packaged-launcher gates.
- Made idempotent mutation, immutable audit, and consumed-marker persistence
  one SQLite commit; revoked or expired sessions can no longer retrieve cached
  mutation responses.
- Removed the unknown-user throttle response oracle with bounded HMAC-selected
  anonymous buckets, constant-work `401` failures, and `429` only for a
  correct-but-throttled credential or saturated Argon2 admission.
- Moved production Argon2 work off the serialized SQLite owner and added
  bounded runtime checkpoints while it runs.
- Enforced OpenAPI's current `ETag` on `412` and bounded `Retry-After` on
  `429`/`503` across the typed service boundary and public HTTP response.
- Added absolute monotonic deadlines across every local request/frame phase so
  partial socket progress cannot monopolize the serialized operator worker.
- Made failed-login throttle effects idempotent with exact safe-error replay,
  and strengthened restore validation across inventory, settings transitions,
  and restored Node capacity.
- Reserved non-failed pending Node-capacity reductions in API/CLI preflight and
  the authoritative inventory transaction, preventing later Node creation from
  making the next restart reject its own database.
- Fixed packaged systemd startup so its runtime directory is consistently
  `root:ntip-admin` and its root initialization phase can enter private
  service-owned state before dropping to `ntip` with only `CAP_NET_ADMIN`.
- Make `ntcl config` a crash-recoverable identity transition that rotates the
  Node static key instead of retaining it across enrollment reset.
- Fixed Noise XKpsk1 enrollment and IK session patterns with
  ChaCha20-Poly1305 and BLAKE2s.
- Bearer-equivalent enrollment records, replay protection, endpoint validation,
  bounded parsing, and fail-closed persistence requirements.

## 0.1.0-beta.1 - Superseded before release

The original v0.1 beta candidate was not released. Its wire protocol remains
the compatibility baseline for v0.2 Nodes; its intentionally unapproved gate
record is retained as historical evidence.
