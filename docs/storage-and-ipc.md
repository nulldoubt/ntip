# Storage and local IPC contracts

This document defines the clean-break v0.2 Master storage boundary, the
unchanged Node-local formats, and both local administration protocols. These
formats are not part of the UDP wire protocol. Existing v0.1 Nodes remain wire
compatible.

## Storage categories

| Category | Linux location | Ownership and mode |
| --- | --- | --- |
| Master bootstrap | `/etc/ntip/server.json` | `root:root 0644` |
| API bootstrap | `/etc/ntip/api.json` | `root:ntip-api 0640` |
| Bootstrap-assets manifest | `/etc/ntip/bootstrap-assets.json` | `root:ntip-api 0640` |
| Node bootstrap | `/etc/ntip/client.json` | `root:root 0644` |
| Immutable Node assets | `/usr/share/ntip/bootstrap-assets` | `root:root 0755`; files `0644` |
| Master state | `/var/lib/ntip/server` | `ntip:ntip 0700`; managed files `0600` |
| Node state | `/var/lib/ntip/client` | `ntip:ntip 0700`; managed files `0600` |
| Human IPC | `/run/ntip` | `root:ntip-admin 0770`; sockets `0660` |
| Typed service IPC | `/run/ntip-api` | `ntip:ntip-api 0750`; socket `0660` |

No bootstrap file contains an enrollment token, private identity, password, or
web-session token. The Node configuration contains the Master static public key
as its identity anchor. Protocol session keys, sequence counters, replay
windows, and receiver IDs remain memory-only.

## Strict configuration

All configuration JSON is UTF-8, bounded before allocation, rejects duplicate
and unknown fields, and requires the exact supported `schema_version`.

Master `server.json` schema 2 contains only:

| Field | Constraint |
| --- | --- |
| `schema_version` | exactly `2` |
| `listen_port` | nonzero UDP port; default `49152` |
| `tun_name` | 1–15 safe interface-name bytes; default `ntip0` |
| `service_socket_path` | absolute, normalized Unix socket path, at most 107 bytes |
| `public_udp_endpoint` | canonical externally reachable `host:port`; required |

Inner MTU, liveness thresholds, enrollment lifetime, traffic thresholds,
retention, and maximum Node capacity do not belong in `server.json`. They are
revisioned settings in SQLite. Supplying an old operational field is an error,
not an override.

API `api.json` schema 2 contains the canonical loopback bind address and port,
the same service socket path, one exact lowercase public HTTPS origin, worker
count, maximum connection count, validated `bootstrap_spki_pin`, and absolute
root-owned `bootstrap_manifest_path`. A hostname, wildcard, or routable bind is
rejected. Security policy and database paths are not configurable here. The
public UDP endpoint, HTTPS origin, pin, and manifest path are explicit
deployment authority and are never inferred from Host or forwarded headers.

Dashboard `dashboard.json` schema 2 contains the exact public plain-HTTP bind
`0.0.0.0`, a nonzero port (the packaged sample uses `443`), canonical loopback
`api_origin`, and fixed `/usr/share/ntip/bootstrap-assets` root. The dashboard
gateway starts the Next service on an ephemeral loopback port, proxies bounded
API/bootstrap requests to `ntip-api`, and reads only validated immutable asset
basenames. It has no database or Unix-socket authority. Operators must restrict
the cleartext listener to their trusted external TLS reverse proxy.

Node `client.json` remains schema 1 with `master`, `node`,
`master_public_key`, `tun_name`, and `inner_mtu`. The primary v0.2 path is
`ntcl bootstrap-import --stdin`: it validates the strict redemption bundle,
derives configuration from its internal enrollment credential, and commits the
configuration, token, and non-secret bootstrap locator through the recoverable
Node transaction described below. `ntcl config` retains the version-1
transaction only for an already-issued pending v0.1 credential.

## Master SQLite ownership

Fresh Masters create `/var/lib/ntip/server/ntip.sqlite3` only after acquiring
`state.lock`. `ntsrv` owns the only live SQLite connection. `ntip-api`, the
dashboard, Nodes, and external tools must never open the database.

The connection enforces:

- SQLite 3.53.3 from the pinned, checksummed amalgamation;
- WAL journal mode and `synchronous=FULL`;
- foreign keys, `secure_delete=ON`, and `trusted_schema=OFF`;
- prepared statements and strict tables;
- transactional migrations whose source and stored checksums must match;
- schema `PRAGMA user_version = 2`, with
  `0001_management_plane.sql` followed transactionally by
  `0002_enrollment_bootstraps.sql`.

The authoritative database stores inventory and enrollment; users,
tombstones, hash-only web sessions, and login throttles; immutable settings
snapshots; runtime transition events and connectivity results; append-only
audit entries, export receipts, and bounded idempotency records.

Enrollment rows retain a 32-byte derived PSK only while status is `unused`.
Consumption or revocation nulls it. Bootstrap rows retain a public locator,
random handle, lifecycle timestamps, and bounded throttle state, but never the
short code, bootstrap root key, derived credential secret, or encoded internal
credential. A valid redemption deterministically reconstructs the same internal
credential until protocol consumption, expiry, revocation, or lockout. Browser
session and CSRF tokens are stored only as hashes. Short codes, redemption
responses, and temporary passwords are explicitly excluded from logs; the
management surface discloses a short code only once.

### Transaction and publication rules

Inventory invariants are checked against a complete candidate projection. The
mutation, immutable audit entry, and one durable-generation increment commit in
one transaction. Only then may the serialized operator worker publish the
allocation-owned immutable topology and kernel-route projection to the
control/data plane. No second Store mutation is admitted until the ordered,
dedicated DATA-worker barrier acknowledges that exact generation. A capture
allocation failure stops the process before further mutation; restart rebuilds
the authoritative SQLite generation. Enrollment completion also persists
credential consumption and Node key binding before installing a live session.

Runtime observations use separate bounded paths. State transitions may
coalesce to the newest pending observation under pressure; committed mutations
and audit records may not be dropped. Runtime events default to 90-day
retention and completed connectivity checks to 30 days. Audit has no automatic
retention. A confirmed audit prefix prune requires recent password
reauthentication and an export receipt covering every deleted sequence.

Every idempotent POST first creates an actor-scoped reservation with internal
status `102`. For an audited operation, inserting its web audit row arms a one-
request SQLite commit hook. Immediately before that transaction commits, the
hook changes the same reservation to internal status `103`; the mutation,
audit row, and consumed marker therefore share one commit boundary. Failed
authentication is the deliberate exception: it explicitly arms the hook so
the throttle update and consumed marker commit atomically even when the attempt
does not create an audit row. The first lockout transition also records its
required security event.
The exact bounded response is attached in a later transaction. If response
attachment or delivery fails, status `103` prevents re-execution and a retry
returns a stable idempotency conflict. Startup removes only abandoned `102`
reservations and retains `103` rows. Neither internal status is emitted as an
HTTP response. A non-login replay also requires a currently valid session
before the reservation is read, so logout, expiry, and administrative
revocation remain authorization boundaries. A failed login's throttle update
and audit-visible security side effect commit before its exact bounded `401`
envelope is attached; retrying that login with the same idempotency key replays
the error without incrementing the failure count again. Successful login and
other one-time-secret responses are deliberately non-replayable.

### Legacy Master refusal

If no `ntip.sqlite3` exists, the presence of any object named `state.json`,
`enrollments.json`, or `transaction.pending` causes
`LegacyMasterStateUnsupported`. NTIP does not follow, import, rename, delete, or
reinterpret that object. Preserve the directory and use an explicitly reviewed
migration process outside v0.2 if its data is needed.

Once a valid v0.2 database exists, inert legacy files do not replace it. They
should still be preserved until the operator has verified the cutover and its
backups.

## Settings revisions

Each settings revision is an immutable full snapshot. `settings_state` points
to desired and effective revisions. Status is `pending_apply`, `active`,
`failed`, or `pending_restart`; rollback creates a new audited revision.

Live settings are inner MTU, heartbeat/suspect/offline thresholds, default
enrollment lifetime, traffic thresholds/hysteresis, and both retention periods.
Maximum Node capacity is restart-required. A live revision becomes effective
only after the kernel, control worker, and DATA worker acknowledge it. Failure
keeps the prior effective revision. A successful settings-only application
increments the shared durable generation before publishing configuration to
Nodes.

Node creation never applies a capacity increase early. Its admission bound is
the smaller of the constructed effective capacity and a non-failed desired
capacity while that revision is `pending_apply` or `pending_restart`. API and
human-CLI paths preflight that bound, and both inventory persistence paths
recheck it inside their `BEGIN IMMEDIATE` transaction. A pending reduction
therefore reserves its future capacity and cannot be overtaken by a later Node
create. A `failed` desired revision is immutable history and does not constrain
inventory or restore; the effective capacity remains authoritative.

The shared settings/contract bounds include a default enrollment lifetime of
60–2,592,000 seconds and traffic hysteresis of 1–3,600 seconds. OpenAPI, strict
request decoding, application validation, and the SQLite snapshot must agree;
generated-artifact or Zig conformance drift fails CI.

## Backup and restore contract

`ntsrv backup --output-dir DIR` uses SQLite's online backup API through the
serialized application service. `DIR` must already be a private `0700`
directory. The command creates, but never replaces, one standalone `0600`
snapshot named `ntip-backup-<unix-seconds>-<random>.sqlite3`. It validates
integrity and the current schema and emits no WAL, SHM, or journal sidecar.
Live copies advance 64 pages at a time, use bounded lock retries, and run the
same non-reentrant protocol/runtime checkpoint between steps; offline copies
need no live checkpoint.

`ntsrv restore --input FILE` is offline-only. It requires the lifetime lock,
rejects sidecars, symlinks, hard links, insecure modes, and a busy or changing
source, then validates the copied source before touching current state. It
checkpoints the current database into a private recoverable
`ntip-pre-restore-*.sqlite3`, revokes every session in the staged restore,
and appends the immutable restore audit entry in the same staged transaction.
Validation includes schema/integrity checks, reconstructing the inventory, and
checking the desired/effective settings pair plus restored Node capacity. Only
after validating that audited image again does it atomically replace
`ntip.sqlite3` and synchronize the directory.

Backups include the inventory, Master-side enrollment verifier state, users,
audit, settings, and the Master database identity relationships. They do not
include `identity.key` or `server.json`; protect and recover those alongside a
database backup as a coherent operator backup set. A restored web session is
never usable.

## Node-local persistence (unchanged)

Node `state.json` remains schema 1 and records generation, enrollment state,
Node ID, assigned address, and VNR. The ID/address/VNR are either all null or
all valid. During lost-ack recovery they may be staged while enrollment remains
`unenrolled`; `enrollment.token` remains until authenticated completion.

`generation` orders configuration within an authenticated transport session.
It is not a permanent anti-rollback counter: the first complete snapshot on a
fresh Noise session may install a coherent restored Master generation.

### Recoverable Node reconfiguration

`ntcl bootstrap-import --stdin` and the legacy-compatible `ntcl config` both
hold the Node `state.lock` and sync a private, checksummed
`reconfigure.pending` containing the complete strict client JSON and exact
internal enrollment credential. Bootstrap format 2 additionally includes the
non-secret eight-byte locator; legacy format 1 includes no locator. Recovery
rolls either fully validated intent forward idempotently:

1. install and sync `enrollment.token`;
2. install and sync `client.json` and its directory;
3. durably delete the old `identity.key`;
4. replace `state.json` with an empty unenrolled assignment;
5. install `bootstrap.id` for format 2, or remove it for legacy format 1; and
6. durably delete `reconfigure.pending`.

`ntcl up` recovers the intent before reading configuration or identity. A
malformed, oversized, corrupt, or newer intent fails closed.

The intent header is `NTIPCTXN` (8 bytes), format version (1 byte), marker
length/reserved bytes (3 bytes), and a big-endian `u32` config length. At most
1 MiB of JSON is followed by the 122-byte internal credential, an optional
eight-byte bootstrap locator in format 2, and a 32-byte BLAKE2s digest. Format
1 remains readable for interrupted v0.1-compatible reconfiguration.

### Binary secret container

`identity.key` and `enrollment.token` retain format version 1:

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `NTIPSECR` |
| 8 | 1 | format version `1` |
| 9 | 1 | kind: identity `1`, enrollment token `2` |
| 10 | 2 | payload length, big-endian |
| 12 | N | payload |
| 12+N | 32 | BLAKE2s-256 over header and payload |

The digest detects corruption; it is not encryption. Readers reject symlinks,
non-regular files, trailing bytes, unsupported versions/kinds, bad digests,
and permissive group/other mode bits.

## Human CLI IPC

The OS-authorized `ntsrv.sock` and `ntcl.sock` protocols remain CLI-shaped.
Each message is a four-byte big-endian length and at most 1,048,576 bytes of
strict JSON. A request contains protocol version, nonzero numeric request ID,
canonical dotted command, and the exact CLI `argv`; the response carries the
matching ID, stable exit code, result, or error. One request is processed per
connection.

Filesystem mode `0660 root:ntip-admin` authorizes access. At accept time the
daemon records Linux peer PID, UID, and primary GID for the local operation.
When `ntsrv` is stopped, a CLI command opens SQLite only while it owns the same
lifetime lock.

## Typed API service IPC

The service socket is distinct from human CLI IPC. It uses the same four-byte
big-endian length with nonzero frames capped at 1,048,576 bytes. The socket is
`0660 ntip:ntip-api`; before decoding a frame, `ntsrv` requires the peer UID to
equal the dedicated unprivileged `ntip-api` account through `SO_PEERCRED`.
Group membership alone is not accepted as the service identity. Startup also
rejects an `ntip-api` UID numerically equal to the `ntip` UID and rejects any
shared GID among `ntip`, `ntip-api`, and `ntip-admin`; account names cannot be
used as aliases to collapse these boundaries.

A strict protocol-version-1 request carries:

- a lowercase 32-character request ID and absolute deadline;
- a bounded operation name;
- anonymous, authenticated, or service actor context;
- optional ETag, idempotency key, recent-reauthentication timestamp, and typed
  confirmation;
- one object payload containing the independently revalidated HTTP projection.

Responses are ordered frames with a zero-based sequence. Exactly one final
success or stable error terminates the stream. Errors are always terminal.
Audit export is the sole public streaming operation; private and HTTP chunks
remain bounded and the connection closes if a terminal failure occurs after
public headers.

Error frames carry only bounded, code-specific public metadata. A stale
precondition includes the current strong ETag, while rate-limited and
unavailable responses include a positive bounded retry delay. The API maps
those fields to `ETag` on HTTP `412` and `Retry-After` on HTTP `429`/`503`;
missing or surplus metadata is rejected at the private protocol boundary.

Peer authentication does not make payload fields trusted. `ntsrv` independently
checks method, target, strict body/query shape, session hash, CSRF, exact Origin,
role, ETag, idempotency, recent reauthentication, and typed confirmation before
calling an application operation.

The serialized loop admits at most one management connection between complete
runtime checkpoints. Both local protocols retain one absolute monotonic 100 ms
deadline across a request's length prefix and body. Writes receive a fresh
absolute deadline for the whole human response prefix/body or for each typed
response-frame prefix/body; partial progress never refreshes it. Handler work
is outside those transport-phase deadlines.
Production Argon2 runs on the single bounded password worker with copied,
wiped inputs; while that worker runs, the owner advances protocol-critical
runtime and persistence work at most every 100 ms without accepting a nested
management request or retaining a SQLite transaction.

IPC protocol v2 also carries bootstrap issuance, replacement, revocation, and
anonymous redemption operations. Bootstrap responses remain bounded typed
objects. Issuance responses are marked non-replayable before they cross the
socket; neither the idempotency repository nor an IPC error may retain or echo
the code after the terminal response has been attempted.

SQLite schema 2 adds the bootstrap locator/handle/lifecycle/throttle table.
The short code, bootstrap root key, derived credential secret, and encoded long
credential are forbidden columns. Node creation plus invitation, replacement,
reset plus invitation, revocation, first successful redemption, and protocol
consumption update bootstrap/enrollment/audit state in one owner transaction.
Restore revokes every restored unused bootstrap-linked enrollment after
integrity and semantic validation and before service startup.
