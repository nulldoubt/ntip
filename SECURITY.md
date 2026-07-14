# Security policy

## Supported versions

NTIP is currently `0.1.0-dev`; no version is yet supported for production use.
After the production-beta gate, the latest beta point release will receive
security fixes. Older development snapshots may be changed without notice.

## Reporting a vulnerability

Use the repository's **private vulnerability reporting** feature under the
Security tab. If that feature is unavailable, contact a project maintainer over
a private channel and ask for a secure reporting path before sending details.
Do not open a public issue, discussion, or pull request containing an exploit,
private key, enrollment credential, packet capture with secrets, or unredacted
state file.

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
  secrets. Enrollment PSKs stored by the Master remain bearer-equivalent.
- Prefer file, standard-input, or hidden-prompt credential ingestion. Positional
  credentials can leak through shell history or process inspection.
- Keep `/var/lib/ntip` and configuration backups encrypted and access-limited.
- Use nftables to define trust boundaries. VNRs are allocation domains and are
  routable across each other by default.
- Run only the packaged systemd units or equivalent confinement. `ntsrv` and
  `ntcl` require `CAP_NET_ADMIN`; they do not require unrestricted root after
  initialization.
- Verify release checksums and GitHub build-provenance attestations before
  installation.

## Cryptography policy

NTIP does not invent cryptographic primitives. v0.1 pins Noise Framework r34,
X25519, ChaCha20-Poly1305, BLAKE2s, and HKDF-SHA256 as specified in
`docs/protocol.md`. There is no cipher negotiation, FIPS suite, 0-RTT DATA, or
0-RTT administrative mutation. Changes to cryptographic state machines require
deterministic vectors, interoperability testing against two independent Noise
implementations, negative tests, and independent review.
