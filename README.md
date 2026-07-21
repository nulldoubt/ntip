# NTIP

NTIP (New Technology Internet Protocol) is a centrally managed, encrypted
Layer-3 interconnect for advanced operators. A central Master runs `ntsrv`;
each Node runs `ntcl` and receives an IPv4 address from a Virtual Network Range
(VNR). Ordinary routing, forwarding, nftables, conntrack, NAT, firewalling, and
load balancing remain Linux responsibilities.

NTIP is not intended to be another general-purpose VPN. Its design keeps the
wire protocol small, keeps idle Nodes cheap, separates control decisions from
packet forwarding, and leaves normal Layer-3 routing to the kernel.

> **Development status:** `0.2.0-dev`. The repository is implementing the
> clean-break v0.2 management plane.
> No release is production-ready until its published release checklist, native
> tests, soak, and independent review are complete.

## Protocol and platform baseline

- Linux 6.1+ on x86_64 and AArch64; macOS supports platform-neutral
  development and tests only.
- One authoritative Master, one VNR per Node, and Master-mediated Node-to-Node
  traffic.
- IPv4 inner packets over IPv4 or IPv6 UDP underlay.
- One non-persistent Layer-3 TUN interface named `ntip0` per machine.
- Multiple non-overlapping VNRs and explicit routed prefixes behind Nodes.
- One authenticated UDP association with logically separate CONTROL and DATA.
- Fixed Noise patterns and ChaCha20-Poly1305; no cipher negotiation.
- Portable single-queue implementation first. Adaptive traffic states remain
  telemetry, not wire-visible acceleration modes.

v0.2 does not change the Node wire protocol. Existing v0.1 Nodes enroll,
reconnect, receive complete configuration generations, and carry DATA exactly
as before. The clean break applies only to Master persistence and management:

- `ntsrv` is the only live owner of a private SQLite database;
- the existing OS-authorized human CLI socket remains CLI-shaped;
- an unprivileged, DB-free `ntip-api` serves bounded HTTP/1.1 on
  loopback and reaches `ntsrv` through a peer-authenticated typed Unix socket;
- OpenAPI under `packages/contracts` is the canonical dashboard contract;
- an optional Next.js App Router dashboard runs as a separate loopback-only
  Bun service and owns no database, state directory, or Unix socket access.

Production deployment requires an operator-managed same-origin HTTPS proxy.
Route pages to `ntip-dashboard` on loopback; route `/api/v1`, generated
installer scripts, and anonymous redemption directly to `ntip-api`; and serve
versioned Node-only archives from the root-owned bootstrap-assets directory.
Do not expose either loopback listener. Initial dashboard reads run server-side
against the loopback API; browser reads and mutations stay on same-origin
`/api/v1`. Authentication and authorization remain authoritative inside
`ntsrv`. Next has no `/api/v1` fallback rewrite: an absent or incorrect proxy
route fails visibly instead of using a build-time destination. The API, assets,
and HTTPS edge are mandatory for provisioning a new Node even when the
dashboard itself is not installed.

Layer 2, IPv6 VNRs, HA Masters, direct Node-to-Node transport, Windows/macOS
runtime support, AF_XDP, kernel modules, and built-in firewall/NAT policy are
explicitly deferred.

## Build

The required Zig toolchain is Zig 0.16.0. The Zig package has no third-party Zig
modules or dynamically linked runtime libraries. `ntsrv` statically includes
the pinned, checksummed SQLite amalgamation; `ntcl` and `ntip-api` remain
DB-free. Linux operation deliberately depends on the host kernel, `iproute2`,
and—when using packaged services—systemd; nftables and conntrack remain
optional operator-managed integrations.

```sh
zig build
zig build test
zig build cross-build
```

The cross-build gate produces static-musl `ReleaseSafe` binaries for
`x86_64-linux-musl` and `aarch64-linux-musl`. Linux integration tests require
root and network namespaces; see [Development and testing](docs/development.md).

The management contract workspace pins Bun 1.3.14:

```sh
bun install --frozen-lockfile
bun run contracts:validate
bun run contracts:check
bun run typecheck
bun run test
```

The dashboard uses Next.js 16.2.10 under that exact Bun runtime. There is no
Node.js production fallback:

```sh
bun run dashboard:lint
bun run dashboard:typecheck
bun run dashboard:test
bun run dashboard:build
bun run dashboard:runtime-smoke
bun run dashboard:e2e
```

`dashboard:dev` and `dashboard:build` execute Next with `bun --bun`.
`dashboard:start` validates loopback runtime configuration and imports the
generated standalone `server.js` directly under Bun. The separately packaged
service uses the same standalone entry through its strict JSON launcher.
Playwright exercises the browser through the same HTTPS origin and proxy split
used in production.

## Operator workflow

After installing the Master, API, bootstrap assets, dashboard, and same-origin
HTTPS edge, create a VNR and Node in the dashboard. A superuser reauthenticates
before the Node and its short-lived invitation commit atomically. The success
view discloses exactly one pinned installation command and a separate
`XXX-XXX-XXX` code.

On the Node, paste the displayed command and enter the code only when prompted
on its controlling terminal. The script verifies the configured HTTPS SPKI
pin, selects and verifies the architecture-matched Node-only archive, imports
the internal enrollment material without printing it, enables `ntcl`, and
waits boundedly for enrollment. It never changes firewall, forwarding, NAT, or
reverse-path-filter settings.

Local OS-authorized administration can create the same short invitation in a
protected JSON file when the dashboard is unavailable:

```sh
umask 077
ntsrv vnr create vnr0 10.1.0.0/24
ntsrv node create node01 --vnr vnr0 --addr 10.1.0.2 \
  --bootstrap-out /root/node01.bootstrap.json
```

The file contains the public locator, secret short code, and expiry—not the
122-character internal credential. Redemption still requires the configured
HTTPS service. Delete the file after the invitation is safely handed off.

System services should run `up` in the foreground. `up -d` is intended for
manual operation. The complete installation, route, NAT, firewall, recovery,
and rollback procedures are in the [Operator guide](docs/operator-guide.md).
Release assets include architecture-matched core, API, dashboard, and Node-only
archives plus one Master bootstrap-assets archive containing both Node
architectures and its checksummed manifest. Core, API, and Node targets are
static-musl `x86_64-linux-musl` or `aarch64-linux-musl`; dashboard targets are
glibc `x86_64-linux` or `aarch64-linux`. Install matching versions in core,
API, bootstrap-assets, dashboard order. The API artifact cannot replace the
core package; the dashboard bundles Bun 1.3.14 plus architecture-neutral Next
standalone output and cannot replace either lower layer. Neither service has
access to `/var/lib/ntip`. The Node-only archives deliberately contain no
Master or management-plane binary, identity, configuration, or unit.

## Documentation

- [Goals and non-goals](docs/goals-and-non-goals.md)
- [Architecture](docs/architecture.md)
- [v0.2 management-plane architecture](docs/management-plane.md)
- [One-command Node bootstrap](docs/node-bootstrap.md)
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

NTIP handles long-lived identity material, bearer-equivalent enrollment state,
short bootstrap codes, password verifiers, and opaque web sessions. Never put a
short code or redemption response in a command line, issue, chat, ticket, or
log. The one-line installer reads the code silently from `/dev/tty`. Legacy
`ntcl config` credential inputs exist only so an already-issued pending v0.1
credential can still enroll; v0.2 management never prints or downloads that
long credential. Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
