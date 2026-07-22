# One-command Node bootstrap

## Status and compatibility

This document defines the accepted v0.2 bootstrap invitation design. It is an
operator-facing delivery layer over the existing `ntip-enroll-v1` credential
and unchanged XKpsk1 enrollment exchange. Existing enrolled Nodes and already
issued internal credentials remain wire-compatible. New browser-driven Node
enrollment requires the management HTTPS endpoint.

The public setup material has two independently delivered parts:

- an eight-character locator drawn from
  `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`; and
- a 45-bit code from the same alphabet, rendered `XXX-XXX-XXX`.

The locator is intentionally public and may appear in the HTTPS access log.
The code, bootstrap root key, derived credential secret, and complete internal
credential must never appear in a database, audit row, log, command line,
environment, browser storage, route, snapshot, or telemetry payload.

## Trust and data flow

```text
superuser browser
  -> POST /api/v1/nodes/actions/bootstrap
       -> ntip-api authenticated IPC v2
            -> ntsrv serialized owner
                 -> one SQLite transaction: Node + PSK + invitation + audit

Node administrator
  -> pinned GET /enrollment/{locator}
       -> generated, locator-specific shell program
  -> code prompt on /dev/tty
  -> pinned POST /enrollment/v1/redeem
       -> ntip-api anonymous bounded admission
            -> ntsrv locator throttle + deterministic credential derivation
  -> ntcl bootstrap-import --stdin
       -> existing crash-recoverable Node transaction
  -> unchanged XKpsk1 enrollment
       -> consume PSK and invalidate invitation atomically
```

An operator-managed reverse proxy terminates TLS and forwards the whole origin
to the dashboard gateway. The gateway serves immutable, versioned Node archives
and routes script generation and redemption to the loopback-only API. The copied command
pins the configured leaf-key SPKI while also using `--insecure` so a raw-IP,
self-signed deployment can authenticate the exact intended key. Every curl
invocation forces HTTP/1.1 because the HTTP/3/GnuTLS combination described in
CVE-2025-13034 did not enforce the pin when combined with `--insecure`.
Certificate rotation therefore invalidates unused copied commands by design.

## Durable model and derivation

SQLite schema version 2 adds `enrollment_bootstraps`. Each row contains only:

- a permanently unique canonical locator;
- the associated Node ID and random 16-byte enrollment handle;
- a derivation version;
- creation, expiry, first-redemption, revocation, and consumption timestamps;
- bounded per-locator failed-attempt and cooldown state.

The row never contains the short code, encoded internal credential, derived
credential secret, or bootstrap key. The existing enrollment record retains
only the Noise PSK derived from the credential secret.

At startup, `ntsrv` derives an in-memory bootstrap root key from the Master
identity secret and public key using a versioned HKDF domain. Issuance draws a
fresh locator, handle, and code, then deterministically derives the internal
32-byte credential secret with a versioned HMAC domain over the canonical
locator, handle, and canonical unhyphenated code. `ntsrv` stores only the PSK
produced by the existing credential derivation. Redemption recomputes the same
secret and credential after a constant-time PSK comparison. Temporary keys,
codes, credentials, and intermediate MAC values are cleared before returning.

Invitation lifetime uses the effective default enrollment lifetime, capped at
24 hours. Locator uniqueness is permanent. Replacement atomically revokes an
unused predecessor and creates a new invitation. Node deletion, explicit
revocation, reset, expiry, and protocol consumption immediately invalidate
redemption. Restore revokes every restored unused bootstrap-linked enrollment
so database rollback cannot resurrect public setup material.

## Management contract

OpenAPI 1.1.0 adds these authenticated operations without changing the
inventory-only `POST /nodes` operation:

- `POST /nodes/actions/bootstrap` creates a Node and invitation atomically;
- `POST /nodes/{id}/enrollment-bootstrap` creates or replaces an invitation;
- `DELETE /nodes/{id}/enrollment-bootstrap` revokes it;
- `POST /nodes/{id}/actions/reset-enrollment` retires the enrolled identity and
  returns a new invitation; and
- `GET /enrollment/bootstrap-config` returns the non-secret installer origin
  and configured `sha256//...` SPKI pin.

Issuance is superuser-only and requires exact Origin, CSRF, idempotency, a
recent password reauthentication, and typed Node-name confirmation. Existing
resource actions additionally require a fresh ETag. An issuance response is:

```json
{
  "node": {},
  "bootstrap": {
    "bootstrapId": "ABCDEFGH",
    "secretCode": "ABC-DEF-GHJ",
    "expiresAt": "2026-07-22T19:00:00Z"
  }
}
```

Invitation responses are one-time management disclosures. Their idempotency
row stores only a consumed non-replayable marker. If delivery is lost, the
dashboard finds the committed Node by its unique requested name and requires
an explicit replacement. The removed long-credential management route and UI
are not compatibility surfaces; the internal credential parser and wire
exchange remain.

Local human administration writes the public locator, secret short code, and
expiry to an explicitly requested protected `--bootstrap-out FILE`; it never
prints the long internal credential or the short code to a terminal transcript.

## Public Bootstrap v1 contract

The public bootstrap interface is cookie-independent and separate from the
management OpenAPI document:

- `GET /enrollment/{bootstrapId}` returns a generated `text/x-shellscript`
  program for that public locator;
- `POST /enrollment/v1/redeem` accepts only strict JSON containing
  `bootstrapId` and `secretCode`; and
- `GET /enrollment/assets/{versioned-file}` is a dashboard-gateway-owned immutable static
  asset path.

Redemption returns strict JSON containing the bundle schema version, locator,
Node name, authoritative UDP endpoint, expiry, Master-authenticating internal
credential, and versioned archive metadata needed by the installer. It always
uses `Cache-Control: no-store`, rejects `Origin`, CORS, redirects, request
transfer encoding, unknown fields, oversized bodies, and non-JSON media types.
Unknown, invalid, expired, revoked, consumed, or locked invitations have one
indistinguishable public error envelope.

Admission is bounded at every layer: the dashboard gateway permits ten redemption requests per
minute per socket peer with burst five; `ntip-api` admits at most two anonymous
redemptions; `ntsrv` permits ten failed attempts per real locator within 15
minutes and then applies a 15-minute cooldown. Unknown locators use a bounded
in-memory throttle and never create rows.

## Installer and Node import contract

The generated shell program is definitions followed by a final `main` call;
truncation before `main` performs no mutation. It requires root, Bash, a
controlling terminal, Linux 6.1 or newer, systemd, TUN, and x86_64 or AArch64.
It recognizes supported package managers for ordinary missing prerequisites,
but never changes firewall, forwarding, NAT, or reverse-path filtering.

Every curl begins with `-q`, forces HTTP/1.1 and HTTPS, follows no redirect,
uses fixed connect/total timeouts, and enforces the same embedded SPKI pin. The
script verifies the architecture archive against a digest embedded in the
trusted generated script before extraction. It accepts only a fresh host, the
byte-identical packaged sample, or a resumable import for the same invitation;
it rejects a Master, active Node, identity, unrelated token/configuration,
mismatched binary, or occupied `ntip0`.

The code is read silently from `/dev/tty`. The locator and code appear only in
the strict POST body. Its response is piped directly to
`ntcl bootstrap-import --stdin`, which validates the complete bounded bundle
before mutation, holds the Node lifetime lock, verifies the embedded Master
key, and commits configuration, enrollment token, and non-secret locator using
the existing recoverable transaction. Re-import of the same ticket is
idempotent; another ticket or an enrolled identity is refused. The locator is
removed after authenticated enrollment completes.

Node-only release archives contain `ntcl`, its systemd unit, strict sample
configuration, Node installer/uninstaller, documentation, checksums, and SBOM.
They contain no `ntsrv`, Master state, API identity, or server unit. A separate
Master bootstrap-assets package contains both supported architecture archives
and a checksummed manifest referenced by strict API configuration.

Install that package on the Master only after the matching core and API
packages are present:

```sh
sudo ./scripts/install-bootstrap-assets.sh
```

The installer validates both architecture archives before mutation, installs
the strict manifest as `/etc/ntip/bootstrap-assets.json` owned by
`root:ntip-api` mode `0640`, and installs immutable public payloads under
`/usr/share/ntip/bootstrap-assets` as `root:root` mode `0644`. It retains older
versioned payloads during an upgrade so an already-disclosed, still-valid
command does not lose its immutable download target.

The dashboard reads those immutable files through its fixed
`bootstrap_assets_root`; it never reads the API manifest or writes the assets.
The external TLS reverse proxy forwards every path unchanged to the dashboard
gateway, which owns the strict locator, redemption, API, and asset routing.
Restrict the plain-HTTP gateway listener to the trusted proxy at the host or
provider firewall.

## Dashboard disclosure lifecycle

For a superuser, Add Node reauthenticates through `/auth/reauth`, immediately
clears the password field, and then submits the atomic provisioning request.
The success stage pins the immutable Node/VNR/address summary, installation
command, short code, and server expiry with independent copy controls and an
“I saved it securely” completion action. While the code is visible, Escape and
outside-click dismissal are disabled. “Discard and revoke” closes only after
the revocation succeeds.

Operators retain inventory-only creation and see an explicit superuser handoff.
Node detail offers generation, replacement, and reset-plus-generation rather
than credential download. Browser code holds disclosure values only in the
active component state, never in storage, routing, logs, telemetry, or request
snapshots, and clears references when the disclosure is completed or revoked.

## Verification gates

Schema/derivation/race tests, strict public HTTP tests, `ntcl` transaction
fault injection, two-architecture installer isolation, secret scans, dashboard
role/disclosure/accessibility journeys, deterministic archives, SBOM checks,
and unchanged v0.1 protocol enrollment are release gates. Deployment must
stage and validate the complete lockstep service/artifact set before stopping
the live services or resetting test state.
