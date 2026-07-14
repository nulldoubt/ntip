# NTIP

NTIP (New Technology Internet Protocol) is a centrally managed, encrypted
Layer-3 interconnect for advanced operators. A central Master runs `ntsrv`;
each Node runs `ntcl` and receives an IPv4 address from a Virtual Network Range
(VNR). Ordinary routing, forwarding, nftables, conntrack, NAT, firewalling, and
load balancing remain Linux responsibilities.

NTIP is not intended to be another general-purpose VPN. Its design keeps the
wire protocol small, keeps idle Nodes cheap, separates control decisions from
packet forwarding, and leaves normal Layer-3 routing to the kernel.

> **Development status:** `0.1.0-dev`. The repository is being built toward a
> production-beta gate. Until the published release checklist is complete,
> NTIP must not be treated as independently reviewed or production-ready.

## v0.1 scope

- Linux 6.1+ on x86_64 and AArch64; macOS supports platform-neutral
  development and tests only.
- One authoritative Master, one VNR per Node, and Master-mediated Node-to-Node
  traffic.
- IPv4 inner packets over IPv4 or IPv6 UDP underlay.
- One non-persistent Layer-3 TUN interface named `ntip0` per machine.
- Multiple non-overlapping VNRs and explicit routed prefixes behind Nodes.
- One authenticated UDP association with logically separate CONTROL and DATA.
- Fixed Noise patterns and ChaCha20-Poly1305; no cipher negotiation.
- Portable single-queue implementation first. Adaptive traffic states are
  telemetry in v0.1, not wire-visible acceleration modes.

Layer 2, IPv6 VNRs, HA Masters, direct Node-to-Node transport, Windows/macOS
runtime support, AF_XDP, kernel modules, and built-in firewall/NAT policy are
explicitly deferred.

## Build

The required build toolchain is Zig 0.16.0. The Zig package has no third-party
modules or dynamically linked runtime libraries. Linux operation deliberately
depends on the host kernel, `iproute2`, and—when using packaged services—systemd;
nftables and conntrack remain optional operator-managed integrations.

```sh
zig build
zig build test
zig build cross
```

The cross-build gate produces static-musl `ReleaseSafe` binaries for
`x86_64-linux` and `aarch64-linux`. Linux integration tests require root and
network namespaces; see [Development and testing](docs/development.md).

## Operator workflow

On the Master:

```sh
ntsrv vnr create vnr0 10.1.0.0/24
ntsrv node create node01 --vnr vnr0 --addr 10.1.0.2 \
  --credential-out /root/node01.enrollment
ntsrv up
```

On the Node, transfer the credential over a separate protected channel:

```sh
ntcl config 203.0.113.10:49152 node01 \
  --credential-file /root/node01.enrollment
ntcl up
```

System services should run `up` in the foreground. `up -d` is intended for
manual operation. The complete installation, route, NAT, firewall, recovery,
and rollback procedures are in the [Operator guide](docs/operator-guide.md).

## Documentation

- [Goals and non-goals](docs/goals-and-non-goals.md)
- [Architecture](docs/architecture.md)
- [Normative wire protocol](docs/protocol.md)
- [Threat model](docs/threat-model.md)
- [Operator guide](docs/operator-guide.md)
- [Storage and local IPC contracts](docs/storage-and-ipc.md)
- [Development and testing](docs/development.md)
- [Benchmark methodology](docs/benchmark-methodology.md)
- [Security policy](SECURITY.md)

The wire specification uses the key words **MUST**, **MUST NOT**, **SHOULD**,
and **MAY** as normative requirements. Implementation behavior is not a
substitute for that specification.

## Security

NTIP handles long-lived identity material and bearer-equivalent enrollment
state. Do not paste credentials into issue reports or command lines. Prefer
`--credential-file`, `--credential-stdin`, or the hidden TTY prompt. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
