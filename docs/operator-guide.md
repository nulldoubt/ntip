# Operator guide

This guide targets Linux kernel 6.1 or newer on x86_64 or AArch64. Commands
assume root unless noted. The repository is implementing v0.2 while its binary
version remains pre-release. Existing v0.1 Nodes are wire compatible, but the
v0.2 Master database is a clean break. Start with an isolated Master and Node.

## 1. Installation

Verify the release archive before extracting it:

```sh
sha256sum --check ntip-vVERSION-x86_64-linux-musl.tar.gz.sha256
gh attestation verify ntip-vVERSION-x86_64-linux-musl.tar.gz \
  --repo OWNER/ntip
```

Inspect the archive plus the sibling `SHA256SUMS` and SPDX SBOM release assets,
the license, and operator documentation. From the extracted directory:

```sh
sudo ./scripts/install.sh
```

The installer creates:

- `/usr/bin/ntsrv` and `/usr/bin/ntcl`;
- dedicated `ntip` and `ntip-api` identities plus the `ntip-admin`
  administrative group;
- `/etc/ntip` for non-secret configuration;
- `/var/lib/ntip/server` and `/var/lib/ntip/client` as private `0700`
  service-owned directories;
- `/run/ntip` and the peer-authenticated `/run/ntip-api` seam;
- hardened `ntsrv.service` and `ntcl.service` systemd units.

The architecture-matched API archive is installed separately after
the same-version core package:

```sh
sha256sum --check ntip-api-vVERSION-x86_64-linux-musl.tar.gz.sha256
sudo ./scripts/install-api.sh
```

It installs only `ntip-api`, `/etc/ntip/api.json`, and its hardened unit. It
does not install or access Master state. New Node provisioning also requires
the matching bootstrap-assets package, dashboard gateway, and HTTPS edge; the API
unit deliberately will not start without its strict manifest. The core package
creates the dedicated UID/GID because `ntsrv` must authenticate that exact UID
with `SO_PEERCRED`.
The `ntip` and `ntip-api` UIDs must be numerically distinct, as must the
`ntip`, `ntip-api`, and `ntip-admin` GIDs. Both installers fail closed if
those names alias one another or if any trusted numeric ID has another
passwd/group alias.

Install the same-version Master bootstrap-assets package next. It contains both
Node CPU architectures, their checksum and SBOM sidecars, a strict manifest,
and an optional NGINX reference example; it never enables or rewrites NGINX:

```sh
sha256sum --check ntip-bootstrap-assets-vVERSION.tar.gz.sha256
tar -xzf ntip-bootstrap-assets-vVERSION.tar.gz
sudo ntip-bootstrap-assets-vVERSION/scripts/install-bootstrap-assets.sh
```

The installer places immutable versioned files under
`/usr/share/ntip/bootstrap-assets`, the API-readable manifest at
`/etc/ntip/bootstrap-assets.json`, and the proxy example under
`/usr/share/doc/ntip-bootstrap-assets`. Keep old immutable Node archives while
an invitation that names them may remain valid.

Install the optional dashboard only after the same-version core, API, and
bootstrap-assets packages:

```sh
sha256sum --check ntip-dashboard-vVERSION-x86_64-linux.tar.gz.sha256
sudo ./scripts/install-dashboard.sh
```

The dashboard package contains the architecture-matched Bun 1.3.14 runtime,
Next standalone application, `/etc/ntip/dashboard.json`, documentation, and
`ntip-dashboard.service`. It requires exact core/API/dashboard version equality
and creates an isolated `ntip-dashboard` identity with no supplementary groups.
It is installed but never enabled automatically. Its schema-2 sample binds a
plain-HTTP gateway on `0.0.0.0:443`; place that listener behind the configured
same-origin HTTPS reverse proxy and restrict access to the proxy at the host or
provider firewall. The gateway is not a TLS endpoint.

Core, API, and Node-only archives use static-musl `x86_64-linux-musl` or
`aarch64-linux-musl` targets. The bootstrap-assets package contains both
Node-only targets. Dashboard archives instead use glibc
`x86_64-linux` or `aarch64-linux`; select the same CPU architecture without the
`-musl` suffix. Bun's musl assets require a musl loader that is absent on the
supported Ubuntu/systemd deployment, so they must not be substituted.

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
stat -c '%u:%g %U:%G %a %n' \
  /var/lib/ntip/server /run/ntip /run/ntip-api
getent passwd ntip
getent passwd ntip-api
getent group ntip-admin
```

The server state directory must be `0700 ntip:ntip`, `/run/ntip` must be
`0770 root:ntip-admin`, and `/run/ntip-api` must be `0750 ntip:ntip-api`.
Reinstall the packaged units if systemd recreates a runtime directory with a
different owner or group.

## 3. Files and permissions

```text
/etc/ntip/server.json                       0644 root:root
/etc/ntip/client.json                       0644 root:root
/etc/ntip/api.json                          0640 root:ntip-api
/etc/ntip/bootstrap-assets.json             0640 root:ntip-api
/etc/ntip/dashboard.json                    0640 root:ntip-dashboard

/usr/share/ntip/bootstrap-assets/           0755 root:root
  ntip-node-vVERSION-*.tar.gz               0644 root:root
  *.tar.gz.sha256 / *.spdx.json             0644 root:root
/usr/share/doc/ntip-bootstrap-assets/
  ntip-nginx.conf.example                   0644 root:root

/usr/lib/ntip-dashboard/runtime/bun         0755 root:root
/usr/lib/ntip-dashboard/app/                read-only root:root

/var/lib/ntip/server/                       0700 ntip:ntip
  identity.key                              0600 ntip:ntip
  ntip.sqlite3                              0600 ntip:ntip
  ntip.sqlite3-wal                          0600 ntip:ntip (while live)
  ntip.sqlite3-shm                          0600 ntip:ntip (while live)
  state.lock                                private lifetime lock

/var/lib/ntip/client/                       0700 ntip:ntip
  identity.key                              0600 ntip:ntip
  state.json                                0600 ntip:ntip
  enrollment.token                          0600 ntip:ntip
  bootstrap.id                              0600 ntip:ntip (pending, non-secret)

/run/ntip/                                  0770 root:ntip-admin
  ntsrv.sock                                0660 root:ntip-admin
  ntcl.sock                                 0660 root:ntip-admin

/run/ntip-api/                              0750 ntip:ntip-api
  ntsrv-api.sock                            0660 ntip:ntip-api
```

Configuration JSON and SQLite migrations are strictly versioned. Identity keys
use a versioned binary secret format. Never edit the database or sidecars with
an external SQLite process. Corrupt, newer, or checksum-mismatched state causes
startup to fail closed; NTIP never replaces it with empty state.

There is no automatic legacy import. If a Master directory has `state.json`,
`enrollments.json`, or `transaction.pending` but no `ntip.sqlite3`, startup
returns `LegacyMasterStateUnsupported` and leaves every object untouched. Stop
and preserve that directory; do not rename the file merely to force creation of
an empty database.

The packaged `client.json` is an inert, byte-stable sample with a placeholder
Master key. The one-command installer accepts that exact sample and passes the
strict redemption bundle directly to `ntcl bootstrap-import --stdin`; do not
start `ntcl` from the untouched sample. Import durably installs the authenticated
Master configuration, enrollment token, and non-secret invitation locator as
one recoverable transition. The locator is removed after authenticated
enrollment. `ntcl config` remains only for an already-issued pending v0.1 long
credential; it is not the v0.2 provisioning path.

For tests or nonstandard installations, `ntsrv` and `ntcl` accept global
`--config`, `--state-dir`, and `--runtime-dir` overrides. Keep secret paths on a
local filesystem that provides correct ownership, mode bits, atomic rename, and
`fsync` semantics.

## 4. Create the Master network

Stop the daemon before initial offline administration:

```sh
systemctl stop ntsrv
```

The first successful Master command creates the v0.2 database only when the
state directory is private and contains no legacy Master JSON or transaction
intent. Offline commands hold the lifetime lock for the entire SQLite open.

Create a VNR. `/24` is the recommended convention; canonical IPv4 unicast
ranges from `/1` through `/30` are supported:

```sh
ntsrv vnr create vnr0 10.1.0.0/24
```

The Master receives the first usable address, `10.1.0.1`. Public/non-private
space is allowed with a warning, but only use address space you control. Default,
loopback, link-local, multicast, non-canonical, and overlapping ranges are
rejected.

The dashboard is the primary Node-creation surface. It atomically creates the
inventory row and short-lived invitation after superuser reauthentication, so
you may defer Node creation until the management services in section 6 are
ready. For local OS-authorized administration, create the same invitation in a
protected JSON file:

```sh
umask 077
ntsrv node create node01 --vnr vnr0 --addr 10.1.0.2 \
  --expires 24h --bootstrap-out /root/node01.bootstrap.json
```

The file contains only the public eight-character locator, secret short code,
and expiry. It never contains the internal 122-character enrollment
credential. Treat the short code as a bearer secret, transfer it separately
from the installer command, and delete the file after handoff. Redemption still
requires the configured HTTPS service and SPKI pin.

After the Node exists by either path, optional prefixes physically reachable
behind it are explicit:

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

If browser/API administration will be enabled, bootstrap the first superuser
while `ntsrv` is stopped. The command is Linux-root-only, succeeds only while no
user exists, and reads a 14–256-character UTF-8 password from standard input:

```sh
umask 077
sudo ntsrv user bootstrap admin --password-stdin \
  < /root/ntip-initial-admin.password
```

Delete the protected input file after verifying access. Do not pass the
password as an argument or retain it in shell history.

## 5. Bootstrap a Node

Complete the API, bootstrap-assets, HTTPS, and optional dashboard setup in
section 6 before provisioning a Node. In the dashboard, choose the VNR and
address, enter the exact Node name confirmation, and reauthenticate. Successful
creation shows one immutable summary, one pinned installation command, one
`XXX-XXX-XXX` code, and the server-authored expiry. Save the command and code
separately before acknowledging the disclosure.

On a fresh supported Linux Node, paste the command exactly as displayed. It
runs under `sudo`, downloads only over HTTPS with the configured SPKI pin and
HTTP/1.1, and prompts silently for the code through `/dev/tty`. The code never
appears in argv, the environment, or a URL. The installer then:

1. validates Linux 6.1+, systemd, TUN, and the supported CPU architecture;
2. downloads the manifest-selected Node-only archive without following a
   redirect and verifies its embedded SHA-256 digest;
3. pipes the strict redemption bundle directly to
   `ntcl bootstrap-import --stdin`;
4. enables and starts only `ntcl.service`; and
5. waits boundedly for enrollment, preserving state and printing diagnostic
   commands if the Node remains pending.

The authoritative UDP endpoint comes from `/etc/ntip/server.json` through the
validated redemption bundle. It may be IPv4, bracketed IPv6, or DNS with a
port. DNS selects an endpoint but does not authenticate the Master; the
credential inside the bundle embeds the Master public key, and the enrollment
handshake authenticates it.

An interrupted same-invitation import is idempotent. A different invitation,
an enrolled identity, unrelated local configuration/token, a running Master or
Node, a mismatched binary, or an occupied `ntip0` is refused rather than
overwritten. The non-secret `bootstrap.id` marker remains only while enrollment
is pending and is removed after authenticated completion.

`ntcl config --credential-file`, `--credential-stdin`, and its hidden TTY input
remain solely for a long credential already issued by a v0.1 Master. v0.2 never
prints or downloads a new long credential. A positional legacy credential is
still parsed for compatibility but warns because argv and shell history can
expose it.

On first `up`, the Node generates its permanent key locally and performs
single-use XKpsk1 enrollment. It durably stages the authenticated Node UUID,
address, and VNR before its final handshake message, then removes
`enrollment.token` only after authenticated completion. A restart with a staged
assignment tries IK first, which recovers safely if the Master's final
acknowledgement was lost. Established restarts use IK and always create fresh
session state.

## 6. Start, stop, and inspect

Systemd runs foreground mode. Before first Master startup, replace the sample
UDP endpoint with the one externally reachable endpoint that every Node must
use. It is deployment authority and is never inferred from HTTP Host,
forwarded headers, or a provider interface:

```json
{
  "schema_version": 2,
  "listen_port": 49152,
  "tun_name": "ntip0",
  "service_socket_path": "/run/ntip-api/ntsrv-api.sock",
  "public_udp_endpoint": "203.0.113.10:49152"
}
```

On the Master host, enable `ntsrv`:

```sh
systemctl enable --now ntsrv
systemctl status ntsrv
journalctl -u ntsrv
```

Prepare the public TLS certificate before configuring the API. Derive its SPKI
pin from the exact certificate the external reverse proxy will serve (the
private key is not needed on the Master):

```sh
openssl x509 -in /path/to/public-certificate.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary \
  | openssl base64 -A
```

Prefix the resulting Base64 text with `sha256//`. In `/etc/ntip/api.json`,
replace the invalid sample origin and pin with the exact lowercase HTTPS origin
users and Nodes will open. Do not include a path or trailing slash. Keep the
listener on canonical loopback and keep the manifest path absolute:

```json
{
  "schema_version": 2,
  "bind_address": "127.0.0.1",
  "port": 8787,
  "service_socket": "/run/ntip-api/ntsrv-api.sock",
  "public_https_origin": "https://ntip.example.com",
  "bootstrap_spki_pin": "sha256//BASE64_SHA256_OF_SPKI",
  "bootstrap_manifest_path": "/etc/ntip/bootstrap-assets.json",
  "workers": 4,
  "maximum_connections": 256
}
```

Confirm that the matching bootstrap-assets package from section 1 installed a
strict manifest before starting the API:

```sh
test -r /etc/ntip/bootstrap-assets.json
test -d /usr/share/ntip/bootstrap-assets
systemctl enable --now ntip-api
```

Then verify both local health states:

```sh
curl --fail http://127.0.0.1:8787/api/v1/health/live
curl --fail http://127.0.0.1:8787/api/v1/health/ready
journalctl -u ntip-api
```

Liveness proves only that the HTTP process responds. Readiness also requires
the typed `ntsrv` service socket. A missing Master returns `503`; `ntip-api`
never opens SQLite as a fallback.

Configure the dashboard's separate strict bootstrap. Its public listener is
plain HTTP; only the internal API remains on loopback. The bootstrap-assets root
is fixed and root-owned:

```json
{
  "schema_version": 2,
  "bind_address": "0.0.0.0",
  "port": 443,
  "api_origin": "http://127.0.0.1:8787",
  "bootstrap_assets_root": "/usr/share/ntip/bootstrap-assets"
}
```

Terminate public TLS in an operator-managed reverse proxy and forward the
entire origin without path rewriting to the dashboard gateway. The
browser-facing scheme, host, and optional port must equal
`public_https_origin` exactly. The gateway gives strict
installer/redeem/static routes priority over pages, bounds anonymous
redemption, proxies API traffic only to canonical loopback, and serves only
manifest-shaped immutable asset basenames. Do not expose `ntip-api`, and do not
use forwarded identity or client-IP headers for authorization or audit.
Preserve the original HTTP `Host` header and do not rewrite the browser's
`Origin`; the API compares the latter to the exact external HTTPS origin even
though the hop from the reverse proxy to the gateway is plain HTTP.

```text
https://ntip.example.com/* -> http://MASTER_ADDRESS:443/* -> ntip-dashboard gateway
```

Allow inbound TCP 443 only from the reverse proxy's address. Port 80 may be
used instead by changing `port`; never send credentials or enrollment traffic
to that cleartext listener except across a trusted private path. Start the
dashboard only after the API is ready and the proxy is configured:

```sh
systemctl enable --now ntip-dashboard
systemctl status ntip-dashboard
curl --fail http://127.0.0.1:443/login >/dev/null
journalctl -u ntip-dashboard
```

Initial authenticated page reads travel from the dashboard to the API through
`api_origin`; browser polling and mutations travel to same-origin `/api/v1`.
The page service owns no database, state directory, or Unix socket access. Its
systemd sandbox keeps config, application, and bootstrap assets read-only and
grants only `CAP_NET_BIND_SERVICE` for the low gateway port. It intentionally
omits `MemoryDenyWriteExecute=yes` because Bun's JavaScriptCore needs executable
JIT mappings.

On a Node host, enable only `ntcl`:

```sh
systemctl enable --now ntcl
systemctl status ntcl
journalctl -u ntcl
```

Do not start both protocol roles on one host: each role exclusively owns an
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
Management-triggered restart is available only under a configured service
manager: `ntsrv` commits audit and its idempotency result, arms the exact
decision, flushes the `202` response, then unwinds and exits with status 75,
which the packaged unit forces systemd to restart. If the peer disconnects
after the result commits, the armed operation still executes once; replay does
not trigger it again. A failure before that commit leaves no executable
decision. Shutdown unwinds cleanly and is not restarted. A manual foreground
launch reports restart unavailable.

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

Replace an unused invitation from the dashboard's Node detail view, or write the
replacement disclosure to a new protected local file:

```sh
umask 077
ntsrv node enrollment renew node01 \
  --bootstrap-out /root/node01-bootstrap-replacement.json
```

If the Node private key is lost or suspected compromised, reset the identity:

```sh
umask 077
ntsrv node enrollment reset node01 \
  --bootstrap-out /root/node01-bootstrap-reset.json
```

Both files contain the public locator, secret short code, and expiry only.
Replacement atomically revokes its unused predecessor. Reset revokes the stored
public key, active protocol sessions, prior invitation, and unused enrollment
state, then returns a fresh invitation. Run the newly generated pinned command
on the intended Node and type its new code. A malicious old Node cannot
reconnect after reset, but existing kernel flows may fail and must be retried.

## 10. Web administration security

The API is the documented dashboard contract, not a general automation promise.
Viewer, operator, and superuser roles are enforced inside `ntsrv`; proxy routing
or cookie presence never grants a role. All users may change their own password
and revoke their own other sessions. Account provisioning/reset returns a
temporary password once and forces a first-login change.

The dashboard verifies `/auth/me` for every protected layout. It displays
freshness and retains a visibly stale last-known-good view during bounded API
failures; it never invents unavailable hardware or software telemetry. Polling
pauses when the page is hidden or the browser is offline. The administration
surface supports keyboard operation, reduced motion, and a topology table
equivalent, but intentionally requires a viewport at least 1024 pixels wide.

The browser cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, host-only, and
contains a 256-bit opaque token whose hash alone is stored. Sessions slide for
30 idle minutes but never exceed 12 hours. Unsafe requests require the
session-bound CSRF header and exact configured Origin. Deletes, enrollment,
user privilege changes, settings, audit prune, restart, and shutdown also
require recent password reauthentication, a fresh ETag, and typed confirmation.

Treat audit export as sensitive infrastructure data. It streams with
`Cache-Control: no-store`; store it in a private destination. Pruning is never
automatic and is allowed only for an exported prefix covered by a durable
receipt. Runtime-event and completed-connectivity retention default to 90 and
30 days respectively.

## 11. Backup and recovery

Create a private destination once, then request an online standalone SQLite
snapshot while the service continues running:

```sh
install -d -o root -g ntip-admin -m 0700 /var/backups/ntip
ntsrv backup --output-dir /var/backups/ntip
```

The command prints the new `ntip-backup-*.sqlite3` path. It never replaces an
existing object, creates mode `0600`, validates schema and integrity, and emits
no WAL/SHM sidecars. A live backup copies a bounded 64 pages per step and
advances protocol/runtime work between steps; lock contention is retried only
within a fixed bound. Copy `/etc/ntip/server.json` and the Master `identity.key`
into the same encrypted, access-limited backup set. The database does not
contain the Master private identity.

The repository includes, but the installer does not install or enable, example
systemd backup units. To opt into a daily schedule after reviewing both files:

```sh
install -m 0644 /usr/share/doc/ntip/examples/systemd/ntip-online-backup.service \
  /etc/systemd/system/ntip-online-backup.service
install -m 0644 /usr/share/doc/ntip/examples/systemd/ntip-online-backup.timer \
  /etc/systemd/system/ntip-online-backup.timer
systemctl daemon-reload
systemctl enable --now ntip-online-backup.timer
```

There is no built-in schedule. Monitor timer failures and move completed
snapshots into the operator's encrypted retention system.

Restore is deliberately stopped-service-only. The source file and its parent
directory must be private, and the source must have no sidecars:

```sh
systemctl stop ntip-api ntsrv
ntsrv restore --input /secure/restore/ntip-backup-EXACT.sqlite3
systemctl start ntsrv
systemctl start ntip-api
```

Before replacement, NTIP validates the source and creates a private recoverable
`ntip-pre-restore-*.sqlite3` beside the live database. It validates again after
revoking every restored web session and unused bootstrap-linked enrollment,
atomically installs the image, and records the restore in audit. Every user
must log in again, and every unused restored invitation must be replaced.
Preserve the recoverable
copy until the restored Master has passed inventory, enrollment, protocol, and
backup verification.

If startup reports corrupt or newer state:

1. Stop the daemon and preserve the failing files byte-for-byte.
2. Record the binary version and error without printing secrets.
3. Verify disk health and restore the most recent coherent SQLite snapshot with
   the matching Master identity and bootstrap configuration.
4. Do not delete state and reinitialize unless intentionally rebuilding the
   entire NTN and re-enrolling every Node.

Master identity loss cannot be recovered from Nodes. Restore the Master backup
or rebuild the NTN and issue fresh bootstrap invitations. Node identity loss is
recovered with server-side enrollment reset plus a new invitation.

## 12. Upgrade and rollback

Before an upgrade:

1. Read the changelog and state-schema notes.
2. Take an online database backup, then stop `ntip-dashboard`, `ntip-api`,
   `ntsrv`, and `ntcl` as applicable.
3. Verify the new archive checksum and provenance.
4. Install the exact-version, architecture-matched core, API, bootstrap-assets,
   and dashboard archives in that order; start one Master/one Node and inspect
   status/logs.
5. Expand to two Nodes and roaming, then routed-prefix/NAT, then scale.

Rollback stops the dashboard, API, and Master services, restores the prior
binaries and their matching integrity-checked database/identity/config
snapshot, and starts them again. TUN teardown is automatic because the interface
is non-persistent. Nodes accept the restored Master's complete snapshot on the
new authenticated session even when its managed-state generation is lower than
the value they saw before rollback. Never run an older binary against a state
schema it does not understand.

## 13. Uninstall

```sh
sudo ./scripts/uninstall-dashboard.sh
sudo ./scripts/uninstall-bootstrap-assets.sh
sudo ./scripts/uninstall-api.sh
sudo ./scripts/uninstall.sh
```

The dashboard, bootstrap-assets, API, and core uninstallers stop/disable
dependent services as needed and remove their own binaries, assets, runtimes,
units, documentation, and NTIP-owned runtime files. The bootstrap-assets
uninstaller removes its manifest and immutable archive directory; replacing
those files while an invitation is live makes that invitation unusable. The
other uninstallers deliberately preserve `/etc/ntip`, `/var/lib/ntip`,
`/run/ntip-api`, and all service identities/groups. Review and remove persistent
state manually only after retaining any required backup:

```sh
sudo rm -rf --one-file-system /etc/ntip /var/lib/ntip
```

That final deletion is irreversible and is never performed by the packaged
uninstaller.
