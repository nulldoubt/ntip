# Changelog

All notable changes to NTIP are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and release tags use
semantic versioning once the beta release gate is met.

Development version: `0.1.0-dev`.

## Unreleased

### Added

- Initial `ntsrv` and `ntcl` project structure for Zig 0.16.0.
- Versioned NTIP wire and local IPC contracts.
- VNR, Node, routed-prefix, enrollment, and persistent-state model.
- Portable Linux TUN/UDP runtime and network-namespace test topology.
- Installation, operation, recovery, threat-model, benchmark, and release
  documentation.
- Reproducible static-musl release packaging for Linux x86_64 and AArch64.
- Coverage-guided parser/replay fuzzing and strict evidence-backed release
  gating that remains closed until every production-beta prerequisite passes.

### Security

- Fixed packaged systemd startup so its runtime directory is consistently
  `root:ntip-admin` and its root initialization phase can enter private
  service-owned state before dropping to `ntip` with only `CAP_NET_ADMIN`.
- Make `ntcl config` a crash-recoverable identity transition that rotates the
  Node static key instead of retaining it across enrollment reset.
- Fixed Noise XKpsk1 enrollment and IK session patterns with
  ChaCha20-Poly1305 and BLAKE2s.
- Bearer-equivalent enrollment records, replay protection, endpoint validation,
  bounded parsing, and fail-closed persistence requirements.

## 0.1.0-beta.1 - Unreleased

This version MUST NOT be tagged until every production-beta gate in the
operator and development documentation has passed, including native x86_64 and
AArch64 validation, a clean 24-hour soak, and independent security review.
