# Storage and local IPC contracts

This document defines the v0.1 local formats. They are not part of the UDP wire
protocol, but production recovery and CLI compatibility depend on them.

## Storage categories

| Category | Linux location | Ownership and mode |
|---|---|---|
| human configuration | `/etc/ntip/*.json` | `root:root 0644` |
| server managed state | `/var/lib/ntip/server` | `ntip:ntip 0700`; files `0600` |
| client managed state | `/var/lib/ntip/client` | `ntip:ntip 0700`; files `0600` |
| runtime IPC and locks | `/run/ntip` | `root:ntip-admin 0770`; sockets `0660` |

No configuration file contains an enrollment token or private identity. The
client configuration contains the Master static public key as its identity
anchor. Session keys, sequence counters, replay windows, observed endpoints,
liveness, and traffic counters are memory-only.

## Strict JSON rules

All configuration/state JSON is UTF-8, bounded before allocation, and parsed
with these rules:

- duplicate or unknown fields are errors;
- `schema_version` is required and must equal the supported version;
- integer overflow, invalid enum spelling, noncanonical CIDR/address text, and
  inconsistent cross-references are errors;
- a newer schema is never treated as the current schema;
- managed writers produce two-space indentation and one final newline;
- corrupt or unsupported files fail closed and are never replaced with defaults.

Server state and enrollment files are capped at 16 MiB each. Client state and
configuration are capped at 1 MiB. These are parser bounds, not recommended
operating sizes.

## Configuration schema version 1

`server.json` fields are:

| Field | Type | Default/constraint |
|---|---|---|
| `schema_version` | integer | required, `1` |
| `listen_port` | integer | `49152`, nonzero |
| `tun_name` | string | `ntip0`, 1–15 safe interface-name bytes |
| `inner_mtu` | integer | `1380`, at least 576 |
| `heartbeat_idle_seconds` | integer | `15` |
| `suspect_after_seconds` | integer | `30` |
| `offline_after_seconds` | integer | `45` |
| `default_enrollment_lifetime_seconds` | integer | `86400`, nonzero |
| `maximum_nodes` | integer | `4096`, range 1–65536 |
| `traffic` | object | bounded telemetry thresholds below |

`heartbeat_idle_seconds < suspect_after_seconds < offline_after_seconds` is
required. The `traffic` object contains `cold_after_seconds` (30),
`hot_packets_per_second` (100000), `hot_bits_per_second` (1000000000),
`saturated_queue_percent` (80), and `hysteresis_seconds` (5).

`client.json` fields are:

| Field | Type | Constraint |
|---|---|---|
| `schema_version` | integer | required, `1` |
| `master` | string | IPv4, bracketed IPv6, or DNS name plus port |
| `node` | string | valid registered Node name |
| `master_public_key` | string | 64 lowercase hex characters, not all zero |
| `tun_name` | string | same constraints as server |
| `inner_mtu` | integer | same constraints as server |

`ntcl config` derives `master_public_key` from the enrollment credential and
writes the complete client configuration through the recoverable Node
reconfiguration transaction described below. Reconfiguring an enrolled Node
deletes its old private identity and assignment; the next `ntcl up` generates a
new identity for the new one-time enrollment.

## Server state schema version 1

`state.json` contains:

```json
{
  "schema_version": 1,
  "generation": 3,
  "vnrs": [
    { "name": "vnr0", "range": "10.1.0.0/24" }
  ],
  "nodes": [
    {
      "id": "00112233445566778899aabbccddeeff",
      "name": "node01",
      "vnr": "vnr0",
      "address": "10.1.0.2",
      "enrollment_state": "unenrolled",
      "public_key": null
    }
  ],
  "routes": [
    { "prefix": "192.168.178.0/24", "node": "node01" }
  ]
}
```

Node IDs are 16 raw random bytes represented as 32 lowercase hex characters;
public keys are 32 bytes represented as 64 lowercase hex characters. The
generation increases once per successful managed mutation and must never wrap.
The complete VNR/Node/route model is validated after parse.

`enrollments.json` is separately protected because a live derived PSK is
bearer-equivalent:

```json
{
  "schema_version": 1,
  "generation": 1,
  "records": [
    {
      "handle": "00112233445566778899aabbccddeeff",
      "node": "node01",
      "node_id": "01010101010101010101010101010101",
      "derived_psk": "64-lowercase-hex-characters",
      "created_at": 1779913600,
      "expires_at": 1780000000,
      "status": "unused"
    }
  ]
}
```

Each record is bound to both the human name and immutable Node UUID; the
creation timestamp must precede expiry. Status is `unused`, `consumed`, or
`revoked`. Consuming/revoking a record erases its PSK in managed state. The
enrollment registry and the public-key binding
are persisted as one logical enrollment transaction. NTIP first syncs a private,
checksummed `transaction.pending` intent containing both next generations, then
atomically replaces each authoritative file and durably removes the intent.
Startup while holding `state.lock` validates and rolls any surviving intent
forward. A malformed or newer intent fails closed and is never discarded.

## Client state schema version 1

Client `state.json` contains exactly:

```json
{
  "schema_version": 1,
  "generation": 4,
  "enrollment_state": "enrolled",
  "node_id": "01010101010101010101010101010101",
  "assigned_address": "10.1.0.2",
  "vnr_range": "10.1.0.0/24"
}
```

The Node ID, address, and VNR are either all null or all valid. An enrolled
state requires all three. The address must be a usable non-Master address in
the VNR. During the lost-ack-safe enrollment window, all three may be staged
while `enrollment_state` remains `unenrolled`; the enrollment token is retained
until authenticated completion.

`generation` records the last completely installed Master snapshot for
diagnostics and crash recovery. It is monotonic within an authenticated
transport session, not a permanent anti-rollback counter: after a fresh Noise
session, the first full snapshot may durably replace it with a lower value when
the operator has restored a coherent older Master backup. Transport keys and
the current receiver session prevent draining-session frames from exercising
that recovery rule.

### Recoverable Node reconfiguration

`ntcl config` is a multi-file identity transition, not an independent config
write. While holding `state.lock`, it first syncs `reconfigure.pending` with
mode `0600`. The bounded, checksummed binary intent contains format version 1,
the complete strictly validated client JSON, and the exact fixed-length
enrollment credential. It then rolls the intent forward in this order:

1. atomically install and sync `enrollment.token`;
2. atomically install and sync `client.json` and its parent directory;
3. durably delete any old `identity.key`;
4. atomically replace `state.json` with the empty unenrolled assignment; and
5. durably delete `reconfigure.pending`.

`ntcl up` acquires the same lock and recovers a surviving intent before reading
configuration, client state, or identity. Every step is idempotent, so repeated
power loss only repeats the roll-forward. A malformed, oversized, corrupt, or
newer intent fails closed and is never silently removed. This ordering ensures
that an old private identity can never be used with a replacement credential or
Master configuration.

The intent header is `NTIPCTXN` (8 bytes), version `1` (1 byte), three required
zero bytes, and a big-endian `u32` config length. It is followed by at most 1
MiB of config JSON, the 122-byte credential, and a 32-byte BLAKE2s digest over
the header and payload. Its maximum accepted size is 1,048,746 bytes. Because
the intent contains a bearer-equivalent credential, it is securely zeroed in
process buffers and must receive the same backup and access protection as
`enrollment.token`.

## Binary secret format version 1

`identity.key` and `enrollment.token` use this container:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | ASCII `NTIPSECR` |
| 8 | 1 | format version, `1` |
| 9 | 1 | kind: `1` identity, `2` enrollment token |
| 10 | 2 | payload length, big-endian |
| 12 | N | payload |
| 12+N | 32 | BLAKE2s-256 over header and payload |

An identity payload is exactly 32 bytes. An enrollment-token payload is 1 to
4096 bytes. The digest detects corruption and kind/length confusion; it is not
encryption or authentication. File ownership, `0600` mode, protected backups,
and the host filesystem provide secrecy. Readers reject symlinks, non-regular
files, trailing bytes, unsupported versions/kinds, bad digest, and permissive
group/other mode bits.

## Atomic mutation protocol

Offline commands and the daemon serialize a complete read-modify-write under an
exclusive state lock. A mutation:

1. opens and validates the current generation without following symlinks;
2. validates all requested domain invariants in memory;
3. creates a same-directory unique temporary regular file with `0600` mode;
4. writes the entire new representation and synchronizes the file;
5. atomically renames it over the target;
6. synchronizes the parent directory;
7. reports success only after step 6.

Failure before rename leaves the previous generation authoritative. Failure
after rename but before the caller receives success may leave the new generation
authoritative; idempotent retry reloads and inspects generation before acting.
Temporary files are cleaned only when their NTIP ownership is proven.

## Local IPC framing

IPC uses Unix-domain stream sockets. Each message is a four-byte big-endian
length followed by exactly that many UTF-8 JSON bytes. Length zero or greater
than 1,048,576 is rejected before body allocation. v0.1 clients send one request
and wait for one response; pipelining is not supported.

Request JSON is exactly:

```json
{
  "version": 1,
  "request_id": 42,
  "command": "node.show",
  "arguments": { "argv": ["node", "show", "node01", "--json"] }
}
```

Response JSON is exactly:

```json
{
  "version": 1,
  "request_id": 42,
  "ok": true,
  "exit_code": 0,
  "result": {},
  "error": null
}
```

Request IDs are nonzero. Commands are 1 to 128 lowercase ASCII letters, digits,
dots, underscores, or hyphens. `arguments` must be an object.

On failure, `ok` is false, `result` is null, and `error` is an object containing
stable machine-readable `code` and human-readable `message` strings. On
success, `error` is null and `result` is an object or null. The response request
ID must match. Request IDs are
unsigned 64-bit JSON integers; clients whose JSON runtime cannot exactly
represent all `u64` values must constrain their generated IDs to its exact range.

Commands use stable dotted names corresponding to public CLI operations, such
as `status`, `down`, `vnr.create`, `node.list`, `node.enrollment.reset`, and
`route.add`. `arguments` contains exactly one field, `argv`, whose value is the
complete public CLI argument array including global path overrides. The daemon
parses that array with the same strict parser used offline and rejects a request
whose dotted `command` does not match its canonical `argv`. Unknown or missing
fields are errors. Secrets are not returned through general status/list calls.

IPC exit codes are the public CLI codes: success 0, internal 1, usage/config 2,
conflict/not-found 3, daemon unavailable 4, and authentication/protocol 5. A
malformed frame closes the connection without processing a partial request.

At accept time, the daemon obtains and logs Linux peer PID, UID, and primary
GID for every accepted request. The kernel authorizes socket access through its
`0660 root:ntip-admin` filesystem permissions, including supplementary-group
membership; peer credentials provide an audit identity and are not a second
group-membership database. v0.1 exposes no network management endpoint.
