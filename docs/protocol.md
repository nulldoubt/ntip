# NTIP wire protocol version 1

Status: normative wire protocol version 1 for the NTIP `0.1.x` and `0.2.x`
lines. The current implementation is `0.2.0-dev`; v0.2 adds no wire change.

## 1. Conventions

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**,
and **MAY** describe interoperability and security requirements.

All integer fields are unsigned. Multi-byte integers use network byte order
(big-endian) unless a field explicitly says otherwise. Byte offsets begin at
zero. Receivers MUST reject non-canonical lengths and MUST NOT inspect bytes
beyond the received datagram.

NTIP version 1 carries IPv4 inner packets over IPv4 or IPv6 UDP. The default UDP
port is 49152 and the default inner MTU is 1380. One Node initiates every
handshake; the Master never initiates a handshake toward a Node.

Version 1 pins:

- [Noise Protocol Framework revision 34](https://noiseprotocol.org/noise.html);
- X25519 Diffie-Hellman;
- [ChaCha20-Poly1305](https://www.rfc-editor.org/rfc/rfc8439.html) AEAD with a
  16-byte authentication tag;
- BLAKE2s-256 as the Noise hash;
- HKDF-SHA256 for enrollment-credential PSK derivation.

There is no algorithm negotiation, downgrade path, FIPS suite, 0-RTT DATA, or
0-RTT administrative mutation.

## 2. Datagram header

Every NTIP UDP datagram starts with this 18-byte clear header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | major wire version, exactly `1` |
| 1 | 1 | packet type |
| 2 | 8 | handshake context or receiver session ID |
| 10 | 8 | handshake message index or transport sequence |

Packet types are:

| Value | Name | Payload |
|---:|---|---|
| `0x01` | ENROLLMENT_HANDSHAKE | XKpsk1 handshake envelope |
| `0x02` | SESSION_HANDSHAKE | IK handshake envelope |
| `0x03` | STATELESS_RETRY | opaque source-bound retry cookie |
| `0x10` | CONTROL | encrypted control frame |
| `0x11` | DATA | encrypted complete IPv4 packet |
| `0x12` | BATCHED_DATA | reserved; v0.1 MUST NOT emit it |

Unknown versions, unknown types, and `BATCHED_DATA` MUST be silently dropped
and counted. A response MUST NOT be generated for an unauthenticated malformed
packet.

For a handshake packet, bytes 2 through 9 identify the Node-allocated random,
nonzero handshake context and bytes 10 through 17 contain the zero-based Noise
message index. A retransmission uses the same context, index, and serialized
bytes. Enrollment accepts only indices 0 through 2, IK only 0 through 1, and
STATELESS_RETRY exactly 0 because it gates only the Node-initiated first message.

For CONTROL and DATA, bytes 2 through 9 contain the receiver's randomly
generated, nonzero session ID. A sender MUST use the receiver ID exchanged by
the handshake, not its own ID. Bytes 10 through 17 contain the shared
directional transport sequence number.

Session IDs MUST be generated with a cryptographically secure random source.
An implementation MUST reject a live-table collision and generate another ID;
it MUST NOT replace the existing session.

## 3. Enrollment credential

The human-transferable credential is exactly:

```text
ntip-enroll-v1.<base64url-no-padding(body)>
```

The decoded body is exactly 80 bytes:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 16 | random enrollment handle |
| 16 | 32 | random enrollment secret |
| 48 | 32 | Master X25519 static public key |

The unpadded base64url body is therefore exactly 107 characters and the full
credential exactly 122 characters.

Decoders MUST require the fixed prefix, base64url alphabet, omitted padding,
canonical encoding, and exact decoded length. All-zero handles, secrets, or
Master public keys MUST be rejected. X25519 all-zero shared secrets MUST be
rejected at every DH operation.

The 32-byte enrollment PSK is derived as:

```text
prk = HKDF-SHA256-Extract(salt = handle, IKM = secret)
info = ASCII("NTIP enrollment PSK v1") || master_public
psk = HKDF-SHA256-Expand(prk, info, 32)
```

The Master stores the handle, derived PSK, Node UUID, creation time, expiration
time, and used/revoked state. It MUST NOT store the raw secret. The stored PSK
is still bearer-equivalent and MUST be protected as a `0600` secret. The
default expiration is 24 hours after issue. Enrollment consumption and public
key binding MUST be one durable atomic mutation; concurrent use permits at most
one winner.

`renew` revokes any unused credential and creates another. `reset` revokes the
permanent Node public key, all live sessions, and any unused credential before
creating a replacement credential.

## 4. Noise handshakes

The exact Noise protocol names are:

```text
Noise_XKpsk1_25519_ChaChaPoly_BLAKE2s
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

The fixed NTIP prologue is 23 bytes:

```text
4e 54 49 50 00 01 00 || handshake_identity_context[16]
```

The seven-byte prefix represents `"NTIP"`, a zero separator, major version 1,
and protocol revision 0. The identity context is the enrollment handle for
XKpsk1 and the Node UUID for IK. Implementations use the standard Noise r34
state machine and MUST NOT add a custom `MixHash` step. Header fields are
validated by strict packet-type, attempt-context, and message-index state before
a Noise message is processed; identity semantics are bound by the 16-byte
prologue context and encrypted payload copies.

### 4.1 Handshake envelope and retry

Every ENROLLMENT_HANDSHAKE and SESSION_HANDSHAKE payload is:

```text
flags:u8 || identity_context[16] || optional_cookie[24] || noise_message
```

Only flag bit 0, `COOKIE_PRESENT`, is defined; all other bits MUST be zero. The
identity context is the enrollment handle for XKpsk1 and Node UUID for IK, and
MUST match the prologue context. A Node's initial request and all responder
messages use flags zero and omit the cookie. After a retry, the Node sets bit 0
and includes exactly the retry's 24 bytes. The standard Noise message is always
nonempty. The authenticated Noise payload MUST repeat identity where specified.

The Master MAY require a retry before allocating handshake state. A
STATELESS_RETRY uses the initiating outer handshake context and message index
and carries exactly:

```text
epoch:u64 || tag[16]
```

The retry tag is the first 16 bytes of HMAC-SHA256 under the current 32-byte
cookie key. Its input is exactly:

```text
ASCII("NTIP retry cookie v1")
|| source_binding[19]
|| outer_handshake_context:u64
|| identity_context[16]
|| epoch:u64
```

`source_binding` is family (`u8`, value 4 or 6), address (`16` bytes; IPv4 uses
the first four and zeroes the remaining 12), and UDP port (`u16`). Integers use
network byte order. An epoch lasts 120 seconds. The Master accepts only its
current epoch/key and immediately previous epoch/key, using constant-time tag
comparison. The cookie is a denial-of-service control, not Node authentication.

After a valid retry, the Node constructs one new first-message envelope that
echoes `epoch || tag`. Repeated sends of either the original envelope or the
cookie-bearing envelope MUST reuse identical serialized bytes. The schedule is
approximately 0.5, 1, 2, 4, and 8 seconds, after which the attempt fails and
normal reconnect backoff applies. The Master caches each serialized handshake
response for the bounded attempt lifetime and returns the identical bytes when
it receives a duplicate predecessor message; it MUST NOT generate another
ephemeral key or another ciphertext for a retransmission of that step.

### 4.2 XKpsk1 enrollment

The Node already knows the Master static public key and enrollment PSK from its
credential. It generates its permanent X25519 key pair locally before XKpsk1
and never transmits the private key.

The three Noise messages follow the revision-34 XK pattern with `psk1`:

```text
<- s
...
-> e, es, psk
<- e, ee
-> s, se
```

NTIP handshake payloads carried by Noise are fixed binary values:

- Message 0: Node receiver session ID (`u64`).
- Message 1: Master receiver session ID (`u64`), Node UUID (16 bytes), assigned
  IPv4 address (4 bytes), canonical VNR network (4 bytes), VNR prefix length
  (`u8`), and current configuration generation (`u64`). The payload is exactly
  41 bytes; the VNR prefix is `/1` through `/30`, the address must be a usable
  member of that VNR, and it must not be the first usable Master address.
- Message 2: Node UUID (16 bytes) echoed from message 1.

The Master MUST verify that the handle is live, the PSK validates, the echoed
UUID matches its enrollment record, and no public key was already bound. It
then durably consumes the credential and binds the Noise-authenticated Node
static public key before treating enrollment as complete.

The Node persists its generated identity before sending message 0. After it
authenticates message 1 and before sending message 2, it durably stages the Node
UUID, assigned address, and VNR while retaining the enrollment token and the
`unenrolled` marker. Only an authenticated ENROLLMENT_COMPLETE changes that
marker to `enrolled` and deletes the token. If that final acknowledgement is
lost after the Master commits, a restart first attempts IK using the staged UUID
and persisted identity. A Master that already bound the key accepts IK; after
authenticated session completion the Node finalizes the staged enrollment and
deletes the stale token. If no binding was committed, IK fails and the
still-unused credential may resume a fresh XK attempt. The Master MUST never
make a consumed credential reusable to repair a lost ack.

### 4.3 IK session and full rekey

Every reconnect and full rekey uses IK. The Node knows the Master static public
key; the Master has the Node public key bound by enrollment.

```text
<- s
...
-> e, es, s, ss
<- e, ee, se
```

The encrypted message payloads are:

- Message 0: Node UUID (16 bytes), Node receiver session ID (`u64`).
- Message 1: Master receiver session ID (`u64`) and current configuration
  generation (`u64`).

The Master MUST reject an unknown, revoked, or differently keyed Node UUID.
Neither an XKpsk1 nor IK result activates Master-to-Node DATA immediately.

### 4.4 Split and confirmation

Noise Split yields independent sending and receiving cipher states. NTIP treats
the initiator-to-responder output as Node-to-Master and the other output as
Master-to-Node. Implementations MUST NOT reuse a key in both directions.

The Node sends a CONTROL `SESSION_CONFIRM` as the first transport packet under
the new keys. Its payload is the final 32-byte Noise handshake hash. The Master
activates the new transmit session only after authenticating this frame and
matching the hash. It then sends `ENROLLMENT_COMPLETE` after XKpsk1, or begins
normal configuration synchronization after IK.

All session state is ephemeral. Restart requires a fresh IK handshake; sequence
numbers and replay windows MUST NOT be restored from disk.

## 5. Transport encryption and sequence numbers

The complete 18-byte header is AEAD associated data. The nonce is exactly:

```text
00 00 00 00 || little_endian(sequence:u64)
```

CONTROL and DATA share one monotonically increasing `u64` sequence space in
each direction. The first transport sequence is zero. A sequence is consumed
for every encryption attempt and MUST NOT be reused, including after a local
send error. The sender MUST stop before wraparound or a hard session limit.

The encrypted payload is `ciphertext || tag[16]`. DATA overhead is therefore
exactly 34 bytes: 18 header bytes plus the full 16-byte tag. Receivers MUST
authenticate before parsing plaintext or changing replay, endpoint, liveness,
or configuration state.

Malformed length, unknown session, bad tag, unsupported version, and replay are
silently dropped and counted. Only an authenticated peer may receive an
encrypted bounded ERROR frame.

## 6. Replay window

Each receive key has a 2048-sequence sliding bitmap and a highest-authenticated
sequence. Processing is:

1. Reject without decryption when a sequence is unambiguously older than the
   current 2048-packet window or already marked.
2. Authenticate into a scratch/reusable buffer without modifying the window.
3. On authentication success only, advance the highest sequence if necessary,
   clear positions that left the window, and mark the received sequence.

A forged far-future sequence MUST NOT advance the window. Concurrent delivery
to one receive key MUST be serialized by its owning data worker. Rekeyed old
and new receive keys maintain independent windows.

## 7. Control frames

One CONTROL transport packet contains exactly one control frame. The maximum
control plaintext is 1200 bytes. Every frame begins with this 16-byte header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | control version, exactly `1` |
| 1 | 1 | control type |
| 2 | 2 | payload length |
| 4 | 4 | request ID |
| 8 | 8 | configuration generation |

The packet plaintext length MUST equal `16 + payload_length`; the maximum
payload is 1184 bytes. Unknown control versions or types are rejected with an
encrypted ERROR only when safely authenticated and rate-limited.

Control types are:

| Value | Name | Payload |
|---:|---|---|
| `0x01` | ENROLLMENT_COMPLETE | Node UUID (16 bytes) |
| `0x02` | SESSION_CONFIRM | final Noise handshake hash (32 bytes) |
| `0x03` | HEARTBEAT | sender monotonic timestamp (`u64`) |
| `0x04` | HEARTBEAT_ACK | echoed timestamp (`u64`) |
| `0x10` | CONFIGURATION_BEGIN | described below |
| `0x11` | CONFIGURATION_CHUNK | described below |
| `0x12` | CONFIGURATION_ACK | BLAKE2s-256 snapshot hash (32 bytes) |
| `0x20` | PATH_CHALLENGE | random challenge (16 bytes) |
| `0x21` | PATH_RESPONSE | echoed challenge (16 bytes) |
| `0x30` | ROTATE_KEY | empty |
| `0x31` | GOODBYE | reason code (`u16`) |
| `0x7f` | ERROR | error code (`u16`) plus at most 256 UTF-8 bytes |

Request ID zero means no correlated response. A nonzero request ID is scoped to
one session and is echoed by the response. Repeating an idempotent request with
the same ID and content MUST NOT repeat its side effect. Configuration-related
frames carry the snapshot generation; unrelated frames use generation zero.

### 7.1 Configuration transfer

`CONFIGURATION_BEGIN` payload is:

```text
snapshot_hash[32] || total_length:u32 || chunk_count:u16
```

The hash is BLAKE2s-256 over the exact assembled snapshot. Total length and
chunk count MUST fit implementation limits established before allocation.

`CONFIGURATION_CHUNK` payload is:

```text
index:u16 || offset:u32 || nonempty_data
```

Chunk data is at most 1178 bytes. Indices start at zero. Chunks MUST be
non-overlapping, in bounds, match the announced count, and exactly cover the
snapshot; they MAY arrive out of order or be retransmitted. Each retransmission
uses a fresh transport sequence even though frame request ID, generation, and
content remain the same.

The Node parses a complete snapshot into a separate bounded structure, verifies
the hash and all route/address invariants, installs it atomically, then sends
`CONFIGURATION_ACK` with the same generation and hash. It MUST keep the prior
configuration if any check fails.

Generation ordering is scoped to the current authenticated transport session.
The first complete snapshot on every newly confirmed Noise session is applied
even if its generation is numerically lower than the Node's last durable
diagnostic value. This is required for coherent Master-state rollback and is
safe because frames from draining receive-only sessions are not eligible to
select the current configuration session. After that first install, lower
generations on the same session are stale and MUST be ignored.

The v0.1 snapshot begins with this fixed 64-byte header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | snapshot schema, exactly `1` |
| 2 | 2 | flags, exactly zero |
| 4 | 16 | Node UUID |
| 20 | 4 | assigned Node IPv4 address |
| 24 | 4 | own VNR canonical network |
| 28 | 1 | own VNR prefix length |
| 29 | 3 | reserved, zero |
| 32 | 4 | Master address in own VNR |
| 36 | 2 | inner MTU |
| 38 | 2 | heartbeat-idle seconds |
| 40 | 2 | suspect-after seconds |
| 42 | 2 | offline-after seconds |
| 44 | 2 | COLD-after seconds |
| 46 | 2 | traffic-state hysteresis seconds |
| 48 | 4 | HOT packets/second threshold |
| 52 | 8 | HOT bits/second threshold |
| 60 | 1 | SATURATED queue percentage |
| 61 | 1 | reserved, zero |
| 62 | 2 | route-entry count |

It is followed by exactly `route_count` eight-byte entries:

| Offset within entry | Size | Field |
|---:|---:|---|
| 0 | 4 | canonical IPv4 network |
| 4 | 1 | prefix length |
| 5 | 1 | kind: `0` VNR, `1` routed prefix |
| 6 | 2 | reserved, zero |

All fields use network byte order. At most 8192 route entries are accepted.
Entries are sorted first by ascending network integer, then ascending prefix
length, then kind; duplicates, overlap, unknown kinds, noncanonical networks,
and unsorted encodings are rejected. The list contains the reachable VNRs and
explicit prefixes distributed by the Master, excluding a prefix routed locally
behind this Node. It MUST include the own VNR as a kind-0 entry. The Master
address MUST be that VNR's first usable address; the assigned address MUST be a
different usable address. The header Node identity and own addressing MUST
match the authenticated session and enrollment record. MTU, timing, and traffic
thresholds MUST be nonzero and internally ordered as specified elsewhere.
Reserved fields permit no extension without a snapshot-schema revision.

## 8. DATA plaintext

DATA plaintext contains exactly one complete IPv4 packet, starting at the IPv4
version/IHL byte. A receiver validates before forwarding:

- version is 4 and IHL is at least 5;
- header length and IPv4 total length are internally consistent;
- total length equals the entire DATA plaintext length;
- total length does not exceed the negotiated inner MTU;
- the destination belongs to a local address or installed forwarding route;
- at the Master, the source belongs to the sending Node's assigned `/32` or one
  explicit routed prefix owned by that Node;
- at a Node, the source and destination are consistent with the installed
  centrally distributed routes and local-delivery model.

Unexpected IPv4 fragments are not reassembled by NTIP. v0.1 SHOULD reject
inner fragments at policy boundaries where safe forwarding cannot be proven.
NTIP never fragments DATA. Outer IPv4 uses DF; outer IPv6 relies on endpoints
and path-MTU signaling rather than router fragmentation. An unexpected
oversize send failure SHOULD synthesize an ICMPv4 Destination Unreachable,
Fragmentation Needed packet toward the inner sender.

The Master routes a valid destination through its immutable longest-prefix
snapshot. Equal-length ambiguity cannot exist because VNRs and routed prefixes
are globally non-overlapping. If the owner is offline, DATA is dropped and
counted without buffering.

## 9. Rekey and key lifetime

A Node starts a full IK handshake when either soft limit is reached:

- 60 minutes since successful session confirmation; or
- `2^32` sent transport datagrams in either direction.

The current session may continue while IK completes. A session MUST stop
sending and be discarded when either hard limit is reached:

- 24 hours since confirmation; or
- `2^40` sent transport datagrams in either direction.

After a new session is confirmed, the prior receive key and replay window MAY
accept in-flight packets for 30 seconds, but the old transmit key MUST NOT be
selected for new traffic. Old session identifiers and keys are zeroized and
removed after the drain interval.

## 10. Heartbeat and liveness

Any authenticated CONTROL or DATA packet proves receive liveness. After 15
seconds without outbound authenticated traffic, a peer sends HEARTBEAT with
bounded random jitter to avoid synchronized bursts. The recipient responds with
HEARTBEAT_ACK unless other authenticated traffic already provides the needed
response.

The Master marks a Node suspect after 30 seconds without authenticated inbound
traffic and offline after 45 seconds. The Node starts reconnect after 45
seconds. DATA sent toward an offline Node is dropped and counted. Timing is
measured with monotonic clocks; wall-clock changes MUST NOT invalidate a live
session.

## 11. Endpoint roaming

The Master records the source endpoint of authenticated packets. A packet from
a new endpoint creates or refreshes one candidate, but MUST NOT immediately
replace the committed endpoint.

The Master sends a fresh encrypted PATH_CHALLENGE with a fresh transport
sequence to the candidate endpoint. Only a matching, authenticated,
non-replayed PATH_RESPONSE from that same source commits the new endpoint.
Challenges expire, are bounded per Node, and are not accepted twice. Invalid or
replayed packets never create candidates or change liveness.

Until commit, normal Master transmission continues to the prior endpoint when
available. Authenticated inbound packets from the candidate may be processed,
but no unrelated outbound DATA is redirected there. If the old path is dead,
the Node continues authenticated traffic and challenge retransmission until the
candidate validates or the session reaches its liveness limit.

## 12. Error handling and counters

Required drop counters include malformed header, unsupported version/type,
unknown session, authentication failure, replay/too-old, malformed control,
malformed inner IPv4, oversize, source spoof, unknown destination, offline
destination, queue full, and UDP/TUN I/O failure. Counters are bounded integers
and wrap or saturate without affecting packet correctness.

Logs MUST NOT contain private keys, raw enrollment secrets or PSKs, complete
credentials, decrypted packet payloads, or authentication tags. Endpoint and
Node identifiers are operationally sensitive and SHOULD be minimized or
redacted at lower log levels.
