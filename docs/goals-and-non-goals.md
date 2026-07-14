# Goals and non-goals

## Purpose

NTIP is a centrally managed Layer-3 interconnect for operators who need to
place Nodes behind one authoritative Master and then use the host operating
system for routing, NAT, firewalling, load balancing, and private access.

The v0.1 objective is a real, encrypted, recoverable Linux implementation with
an intentionally portable fast path. It is acceptable for that implementation
to be slower than WireGuard. Correctness, bounded resource use, stable
contracts, and evidence-driven optimization come first.

## Goals

### Lightweight forwarding

- Carry exactly one complete IPv4 packet in each v0.1 DATA datagram.
- Keep ordinary packet handling to parse, session lookup, authentication,
  replay check, decrypt, ownership validation, forwarding lookup, and I/O.
- Perform no JSON parsing, persistence, unbounded allocation, formatted
  logging, or global locking in the DATA hot path.
- Reuse bounded packet buffers and drop traffic for offline destinations rather
  than retaining unbounded queues.

### Central authority with explicit identity

- Give every Node a persistent generated UUID, one registered public key, and
  one explicitly assigned VNR `/32` address.
- Keep identity, VNR address, current UDP endpoint, and optional routed prefixes
  as distinct concepts.
- Bind a locally generated Node key to its server-side record through a
  single-use, expiring enrollment credential.
- Treat the Master as authoritative for membership, address assignments,
  routes, liveness, session keys, and configuration generation.

### Linux-native integration

- Present ordinary Layer-3 packets through non-persistent TUN interfaces.
- Let Linux own forwarding, nftables, conntrack, NAT, policy routing, and load
  balancing.
- Detect and explain missing host prerequisites without silently changing
  forwarding, reverse-path filtering, firewall rules, or NAT policy.
- Use explicit routes and source ownership checks to stop a Node from claiming
  another Node or routed prefix.

### Secure operation and recovery

- Use fixed, reviewed primitives and fixed Noise patterns without negotiation.
- Reject replay, fail closed on corrupt/newer persistent state, and validate a
  changed endpoint before adopting it.
- Make successful administrative mutations durable before reporting success.
- Support deterministic installation, rollback, and uninstall while retaining
  persistent identity and managed state unless the operator explicitly removes
  them.

### Portable production-beta baseline

- Run on Linux kernel 6.1+ on native x86_64 and AArch64.
- Cross-build from the Apple Silicon development host and run platform-neutral
  tests there.
- Ship static-musl `ReleaseSafe` artifacts, checksums, an SPDX SBOM, and build
  provenance.
- Publish benchmark context and results without an unsupported speed claim.

## Non-goals for v0.1

NTIP v0.1 deliberately does not provide:

- Ethernet emulation, Layer 2 frames, ARP, broadcast, STP, or multicast-domain
  behavior;
- IPv6 inner packets or IPv6 VNRs;
- overlapping VNRs, automatic address allocation, or multi-VNR Nodes;
- multiple Masters, HA/failover, federation, or direct Node-to-Node transport;
- reliable or buffered DATA delivery;
- automatic firewall, NAT, load-balancer, forwarding, or sysctl management;
- cipher negotiation, AES/FIPS agility, post-quantum exchange, 0-RTT DATA, or
  0-RTT mutation;
- database-backed state, runtime config reload, a remote management API, or an
  exposed metrics server;
- multiqueue TUN, raw `recvmmsg`, per-core sharding, AF_XDP, DPDK, a kernel
  module, NUMA tuning, SmartNIC support, or hardware offload;
- Windows, macOS, Android, or BSD runtime support.

These exclusions are compatibility boundaries, not promises about later
versions. A future feature must justify its security, wire, and operational
cost independently.

## Production-beta definition

The `v0.1.0-beta.1` tag is permitted only after all of these are true:

1. Formatting, unit, negative, fuzz, integration, and version-consistency gates
   pass.
2. Namespace scenarios pass for Master-to-Node, Node-to-Node through the
   Master, routed-prefix traffic, NAT, roaming, restart, nftables denial, DNAT,
   load balancing, packet loss/reorder/duplication, and MTU failure.
3. Release artifacts execute natively on x86_64 and AArch64 Linux.
4. The hot path allocates nothing after initialization and malformed traffic
   cannot cause unbounded memory growth.
5. A 24-hour loss/reorder soak completes cleanly.
6. No critical or high-severity security finding remains unresolved.
7. Independent reviewers examine Noise state handling, replay logic, parsers,
   enrollment persistence, and endpoint migration.

Production-beta does not mean NTIP has outperformed WireGuard, and project
materials must not imply that claim without reproducible evidence.
