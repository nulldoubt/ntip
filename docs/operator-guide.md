# Operator guide

This guide targets Linux kernel 6.1 or newer on x86_64 or AArch64. Commands
assume root unless noted. NTIP v0.1 is production-beta software only after its
published release gates pass; start with an isolated Master and Node.

## 1. Installation

Verify the release archive before extracting it:

```sh
sha256sum --check ntip-v0.1.0-beta.1-x86_64-linux-musl.tar.gz.sha256
gh attestation verify ntip-v0.1.0-beta.1-x86_64-linux-musl.tar.gz \
  --repo OWNER/ntip
```

Inspect the archive plus the sibling `SHA256SUMS` and SPDX SBOM release assets,
the license, and operator documentation. From the extracted directory:

```sh
sudo ./scripts/install.sh
```

The installer creates:

- `/usr/bin/ntsrv` and `/usr/bin/ntcl`;
- the dedicated `ntip` service user and `ntip-admin` administrative group;
- `/etc/ntip` for non-secret configuration;
- `/var/lib/ntip/server` and `/var/lib/ntip/client` as private `0700`
  service-owned directories;
- `/run/ntip` at service start;
- hardened `ntsrv.service` and `ntcl.service` systemd units.

The runtime directory must permit `ntip-admin` members to reach the sockets and
the dropped `ntip` process to remove its own NTIP-owned socket. The bundled
self-managed service therefore uses `0770 root:ntip-admin`; persistent config,
state, and secret directories remain private.

The systemd process begins as `root:ntip-admin` with narrowly bounded startup
capabilities so it can enter the `0700 ntip:ntip` state directory and create
kernel/runtime resources. Before readiness and before creating threads, NTIP
drops to `ntip:ntip` and replaces its live capability sets with only
`CAP_NET_ADMIN`.

Add an operator to the administrative group only when they may reconfigure the
entire NTN:

```sh
sudo usermod -aG ntip-admin OPERATOR
```

The operator must start a new login session before the group applies.

## 2. Host prerequisites

Install `iproute2`, nftables when policy/NAT is needed, and systemd for packaged
service operation. Verify TUN support:

```sh
test -c /dev/net/tun
ip tuntap help >/dev/null
```

NTIP refuses to adopt an existing `ntip0`:

```sh
ip link show ntip0
```

If that command succeeds before NTIP starts, identify its owner. Do not delete
an operator interface merely to make NTIP start.

NTIP reports but never changes forwarding and reverse-path-filtering settings:

```sh
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
```

Enable forwarding only after reviewing firewall policy. Persist the setting in
the distribution's normal sysctl configuration; a one-time example is:

```sh
sysctl -w net.ipv4.ip_forward=1
```

Strict reverse-path filtering can reject valid asymmetric routed-prefix or NAT
paths. Adjust it only for interfaces and topologies that require the change.

The default UDP listener is port 49152 on IPv4 and IPv6. Permit that port in the
underlay firewall. Do not expose the local Unix sockets over a network.

If foreground startup reports `InsecureOwner`, verify numeric ownership rather
than weakening the check:

```sh
stat -c '%u:%g %U:%G %a %n' /var/lib/ntip/server /run/ntip
getent passwd ntip
getent group ntip-admin
```

The server state directory must be `0700 ntip:ntip`, while `/run/ntip` must be
`0770 root:ntip-admin`. Reinstall the packaged unit if systemd recreates the
runtime directory under a different group.

## 3. Files and permissions

```text
/etc/ntip/server.json                       0644 root:root
/etc/ntip/client.json                       0644 root:root

/var/lib/ntip/server/                       0700 ntip:ntip
  identity.key                              0600 ntip:ntip
  state.json                                0600 ntip:ntip
  enrollments.json                          0600 ntip:ntip

/var/lib/ntip/client/                       0700 ntip:ntip
  identity.key                              0600 ntip:ntip
  state.json                                0600 ntip:ntip
  enrollment.token                          0600 ntip:ntip

/run/ntip/                                  0770 root:ntip-admin
  ntsrv.sock                                0660 root:ntip-admin
  ntcl.sock                                 0660 root:ntip-admin
```

Configuration and state JSON are strictly parsed and schema-versioned.
Identity keys use a versioned binary secret format. Never edit machine-managed
state while a daemon is running. Corrupt or newer state causes startup to fail
closed; NTIP never replaces it with empty state.

The packaged `client.json` is an inert documentation sample with a placeholder
Master key. `ntcl config` replaces it using the authenticated key embedded in
the enrollment credential; do not start `ntcl` from the untouched sample.
Reconfiguration is a durable identity reset: it revokes the old local private
key and assignment, and the next `ntcl up` generates a fresh Node identity.

For tests or nonstandard installations, both executables accept global
`--config`, `--state-dir`, and `--runtime-dir` overrides. Keep secret paths on a
local filesystem that provides correct ownership, mode bits, atomic rename, and
`fsync` semantics.

## 4. Create the Master network

Stop the daemon before initial offline administration:

```sh
systemctl stop ntsrv
```

Create a VNR. `/24` is the recommended convention; canonical IPv4 unicast
ranges from `/1` through `/30` are supported:

```sh
ntsrv vnr create vnr0 10.1.0.0/24
```

The Master receives the first usable address, `10.1.0.1`. Public/non-private
space is allowed with a warning, but only use address space you control. Default,
loopback, link-local, multicast, non-canonical, and overlapping ranges are
rejected.

Create a Node with an explicit address and write the one-time credential to a
protected file:

```sh
umask 077
ntsrv node create node01 --vnr vnr0 --addr 10.1.0.2 \
  --expires 24h --credential-out /root/node01.enrollment
```

Transfer that file over a separate authenticated channel. The credential is a
bearer token until consumed or expired. Do not paste it into chat, tickets,
logs, or a command line.

Optional prefixes physically reachable behind a Node are explicit:

```sh
ntsrv route add 192.168.178.0/24 node01
```

They must be canonical and cannot overlap any VNR or other routed prefix.
Default-route advertisement is not supported. Node deletion fails while a route
depends on it; VNR deletion fails while a Node depends on it.

Review state before starting:

```sh
ntsrv vnr list
ntsrv node list
ntsrv route list
ntsrv status --json
```

## 5. Configure a Node

The `config` command writes configuration and enrollment material only; it does
not contact the Master:

```sh
ntcl config 203.0.113.10:49152 node01 \
  --credential-file /root/node01.enrollment
```

Endpoints may be IPv4, bracketed IPv6, or DNS with a port:

```text
203.0.113.10:49152
[2001:db8::10]:49152
master.example.net:49152
```

DNS selects an endpoint but does not authenticate the Master; the credential's
embedded Master public key does that. `--credential-stdin` and the hidden TTY
prompt are also safe ingestion paths. The positional credential form remains
compatible but prints a warning because shell history and process inspection
can expose it.

When reconfiguring an existing Node, first run `ntsrv node enrollment reset` on
the Master and use the newly issued credential. `ntcl config` then durably
installs that credential and public configuration, deletes the old local
private identity, and clears the old assignment as one recoverable operation.
If the host loses power, `ntcl up` completes the pending operation before it
loads any identity material. The new private identity is generated only on the
next `up`; the old key is never retained across reconfiguration.

On first `up`, the Node generates its permanent key locally and performs
single-use XKpsk1 enrollment. It durably stages the authenticated Node UUID,
address, and VNR before its final handshake message, then removes
`enrollment.token` only after authenticated completion. A restart with a staged
assignment tries IK first, which recovers safely if the Master's final
acknowledgement was lost. Established restarts use IK and always create fresh
session state.

## 6. Start, stop, and inspect

Systemd runs foreground mode. On a Master host, enable only `ntsrv`:

```sh
systemctl enable --now ntsrv
systemctl status ntsrv
journalctl -u ntsrv
```

On a Node host, enable only `ntcl`:

```sh
systemctl enable --now ntcl
systemctl status ntcl
journalctl -u ntcl
```

Do not start both roles on one host in v0.1: each role exclusively owns an
interface named `ntip0`.

Manual foreground operation is, on the corresponding Master or Node host:

```sh
ntsrv up
ntcl up
```

Manual daemon mode forks before threads, waits for a readiness result, drops to
the `ntip` account, and retains only `CAP_NET_ADMIN`:

```sh
ntsrv up -d
ntcl up -d
```

Control a live daemon through local IPC:

```sh
ntsrv status --json
ntsrv node list --json
ntcl status --json
ntsrv down
ntcl down
```

`SIGINT`, `SIGTERM`, `down`, and startup rollback remove only NTIP-owned runtime
resources. The non-persistent TUN disappears when its descriptor closes.

Exit codes are stable:

| Code | Meaning |
|---:|---|
| 0 | success |
| 1 | internal failure |
| 2 | usage or configuration error |
| 3 | conflict or not found |
| 4 | daemon unavailable |
| 5 | authentication or protocol failure |

## 7. Routing behavior

The Master `ntip0` contains every Master VNR address with its VNR prefix. Each
Node has its assigned address as `/32` and receives centrally generated routes
for VNRs and routed prefixes, excluding prefixes routed locally behind itself.

The Master enforces ingress source ownership: a Node may source only its `/32`
or a routed prefix explicitly assigned to it. VNRs share one route domain, so
Node-to-Node and cross-VNR traffic works through the Master unless nftables
denies it.

To route a LAN behind a Node, the Node's ordinary kernel needs forwarding and a
route to that LAN. LAN hosts also need a return route for NTIP VNRs via the Node,
or an operator-controlled SNAT rule on the Node. NTIP does not infer or manage
either choice.

## 8. nftables examples

These examples are policy templates, not commands NTIP executes. Adapt interface
names, addresses, IPv6 policy, and existing tables before applying them. Keep a
remote recovery path when changing firewall rules.

### Restrict cross-VNR traffic

```nft
table inet ntip_filter {
    chain forward {
        type filter hook forward priority filter; policy drop;

        ct state established,related accept
        iifname "ntip0" oifname "ntip0" ip saddr 10.1.0.0/24 \
            ip daddr 10.2.0.0/24 tcp dport 443 accept
    }
}
```

### DNAT a public service to one Node

```nft
table ip ntip_nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth0" tcp dport 443 dnat to 10.1.0.2:443
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "eth0" ip saddr 10.1.0.0/24 masquerade
    }
}
```

Add explicit filter-chain acceptance for the forwarded connection. Confirm the
Node service binds its NTIP address and that return routing passes through the
Master. NTIP preserves the original client source address: the Node accepts
IPv4 sources carried by its authenticated Master association, while its
destination policy still limits delivery to the Node's assigned address and
prefixes explicitly routed behind it. The strict source anti-spoofing rule is
applied in the opposite direction, when the Master receives DATA from a Node.
If an operator deliberately adds SNAT before `ntip0`, the Node naturally sees
the translated source instead.

### Distribute new TCP connections

```nft
table ip ntip_lb {
    map backends {
        type integer : ipv4_addr
        elements = { 0 : 10.1.0.2, 1 : 10.1.0.3 }
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        iifname "eth0" tcp dport 443 \
            dnat to numgen random mod 2 map @backends
    }
}
```

Conntrack keeps an established flow on its selected backend. This is not a
health checker: remove an unhealthy backend through the operator's normal
automation before directing new traffic to it.

## 9. Enrollment maintenance

Replace an unused credential:

```sh
ntsrv node enrollment renew node01
```

If the Node private key is lost or suspected compromised, reset the identity:

```sh
ntsrv node enrollment reset node01
```

Reset revokes the stored public key, active sessions, and unused credentials,
then creates a new one-time credential. Reconfigure the intended Node using the
new credential. A malicious old Node cannot reconnect after reset, but existing
kernel flows may fail and must be retried.

## 10. Backup and recovery

Stop the relevant daemon and snapshot the full identity/state set together:

```sh
systemctl stop ntsrv
tar --xattrs --acls -cpf /secure/ntip-server-backup.tar \
  /etc/ntip/server.json /var/lib/ntip/server
systemctl start ntsrv
```

Encrypt and access-limit the backup. Restoring only one file can split identity,
Node binding, and enrollment state. Restore the complete snapshot with original
ownership and mode bits while the daemon is stopped.

If startup reports corrupt or newer state:

1. Stop the daemon and preserve the failing files byte-for-byte.
2. Record the binary version and error without printing secrets.
3. Verify disk health and restore the most recent coherent snapshot.
4. Do not delete state and reinitialize unless intentionally rebuilding the
   entire NTN and re-enrolling every Node.

Master identity loss cannot be recovered from Nodes. Restore the Master backup
or rebuild the NTN and distribute new credentials. Node identity loss is
recovered with server-side enrollment reset.

## 11. Upgrade and rollback

Before an upgrade:

1. Read the changelog and state-schema notes.
2. Stop the daemon and take a coherent state snapshot.
3. Verify the new archive checksum and provenance.
4. Install the binary, start one Master/one Node, and inspect status/logs.
5. Expand to two Nodes and roaming, then routed-prefix/NAT, then scale.

Rollback stops the service, restores the prior binary and its matching state
snapshot, and starts it again. TUN teardown is automatic because the interface
is non-persistent. Nodes accept the restored Master's complete snapshot on the
new authenticated session even when its managed-state generation is lower than
the value they saw before rollback. Never run an older binary against a state
schema it does not understand.

## 12. Uninstall

```sh
sudo ./scripts/uninstall.sh
```

The uninstaller stops/disables services and removes installed binaries, units,
and NTIP-owned runtime files. It deliberately preserves `/etc/ntip`,
`/var/lib/ntip`, the `ntip` user, and `ntip-admin` group. Review and remove
persistent state manually only after retaining any required backup:

```sh
sudo rm -rf --one-file-system /etc/ntip /var/lib/ntip
```

That final deletion is irreversible and is never performed by the packaged
uninstaller.
