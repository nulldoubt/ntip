# Security policy

## Supported versions

NTIP is currently `0.2.0-dev`; no version is yet supported for production use.
After the production-beta gate, the latest beta point release will receive
security fixes. Older development snapshots may be changed without notice.

## Reporting a vulnerability

Use the repository's **private vulnerability reporting** feature under the
Security tab. If that feature is unavailable, contact a project maintainer over
a private channel and ask for a secure reporting path before sending details.
Do not open a public issue, discussion, or pull request containing an exploit,
private key, bootstrap short code, redemption bundle, legacy enrollment
credential, packet capture with secrets, or unredacted state file.

Include, when safe:

- affected commit or version and target architecture;
- whether the issue affects enrollment, Noise state, replay handling, parser
  bounds, persistence, IPC authorization, TUN routing, or privilege dropping;
- minimal reproduction steps and the expected security boundary;
- crash output with all credentials, keys, endpoints, and Node identities
  redacted;
- whether active exploitation is known.

The project will acknowledge a complete report as soon as practical, establish
a private remediation channel, and coordinate disclosure after a fix and
release are available. No fixed response-time guarantee is made during the
pre-release phase.

## Security expectations

- Treat `identity.key`, `enrollment.token`, and server enrollment records as
  secrets. Enrollment PSKs stored by the Master remain bearer-equivalent while
  unused. Protect `ntip.sqlite3`, backups, password verifiers, and web-session
  hashes as security-sensitive state.
- Enter bootstrap short codes only at the installer's hidden `/dev/tty` prompt;
  never put them in a URL, command argument, environment variable, ticket, or
  log. File/standard-input credential ingestion remains for already-issued
  pending v0.1 credentials only. Positional legacy credentials can leak through
  shell history or process inspection.
- Keep `/var/lib/ntip` and configuration backups encrypted and access-limited.
- Use nftables to define trust boundaries. VNRs are allocation domains and are
  routable across each other by default.
- Run only the packaged systemd units or equivalent confinement. `ntsrv` and
  `ntcl` require `CAP_NET_ADMIN`; they do not require unrestricted root after
  initialization.
- Keep `ntip-api` on canonical loopback behind the exact configured same-origin
  HTTPS proxy. Serve the strict installer/redeem routes through that API and
  immutable Node archives from the root-owned bootstrap-assets directory. Keep
  the configured SPKI pin synchronized with the TLS key. `ntip-api` needs no
  capabilities or access to `/var/lib/ntip`.
- Keep `ntip-dashboard` on canonical loopback behind that same proxy. Route
  pages to its listener and `/api/v1` directly to `ntip-api`; never expose
  ports 3000 or 8787. The dashboard identity must have no supplementary groups,
  state-directory access, or access to `/run/ntip` or `/run/ntip-api`. Next has
  no `/api/v1` fallback rewrite, so treat a browser API routing failure as a TLS
  proxy/configuration error rather than adding another upstream path.
- Treat the dashboard as an unprivileged presentation process, not an
  authorization boundary. Protected layouts verify `/auth/me`, initial reads
  forward only the named session cookie to the loopback API, and browser
  mutations remain subject to the API's exact-Origin, CSRF, ETag,
  idempotency, RBAC, and recent-reauthentication checks. Protected Server
  Component reads redirect only when the authoritative API returns `401`; this
  suppresses parallel-render error noise without treating cookie presence as
  authentication.
- The packaged dashboard intentionally omits `MemoryDenyWriteExecute=yes`
  because Bun's JavaScriptCore runtime requires executable JIT mappings. Keep
  the unit's empty capability sets, read-only application tree, inaccessible
  state/sockets, namespace restrictions, and localhost-only networking as the
  compensating boundary.
- Verify release checksums and GitHub build-provenance attestations before
  installation. Verify that a dashboard archive contains the expected
  glibc `x86_64-linux` or `aarch64-linux` Bun 1.3.14 runtime and component SPDX
  document; dashboard packages are not static-musl and NTIP has no Node.js
  production fallback. Dashboard payload checks reject symlinks, native
  `.node` modules, and ELF files outside the separately validated Bun runtime.
  Verify Node-only archives separately: they must contain `ntcl` but no Master,
  API, dashboard, server configuration, or server unit. Verify the combined
  bootstrap-assets manifest before enabling new-Node enrollment. Independently
  review the operator-owned TLS proxy and firewall policy: the proxy must
  forward the complete public origin to the dashboard gateway, and the plain-
  HTTP listener must not be generally reachable.

## Cryptography policy

NTIP does not invent cryptographic primitives. Wire protocol version 1,
unchanged in v0.2, pins Noise Framework r34, X25519, ChaCha20-Poly1305,
BLAKE2s, and HKDF-SHA256 as specified in
`docs/protocol.md`. There is no cipher negotiation, FIPS suite, 0-RTT DATA, or
0-RTT administrative mutation. Changes to cryptographic state machines require
deterministic vectors, interoperability testing against two independent Noise
implementations, negative tests, and independent review.
