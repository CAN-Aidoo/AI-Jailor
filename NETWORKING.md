# Networking — AI Jailer

## Overview

Network isolation is a critical layer of AI Jailer's security model. Every cell's network access is controlled at the hypervisor/host level, meaning even if the guest kernel is compromised, network restrictions cannot be bypassed from inside the cell.

## Network Architecture

```
                    Internet
                       │
                 ┌─────▼─────┐
                 │  Gateway   │
                 │  Router    │
                 └─────┬─────┘
                       │
              ┌────────┼────────┐
              │   Host Network  │
              │   10.0.0.0/16   │
              ├────────┬────────┤
              │        │        │
         ┌────▼──┐ ┌───▼───┐ ┌─▼──────┐
         │ TAP-1 │ │ TAP-2 │ │ TAP-N  │
         │       │ │       │ │        │
         │nftable│ │nftable│ │nftable │
         │ rules │ │ rules │ │ rules  │
         └───┬───┘ └───┬───┘ └───┬────┘
             │         │         │
         ┌───▼───┐ ┌───▼───┐ ┌──▼────┐
         │Cell 1 │ │Cell 2 │ │Cell N │
         │.5.23  │ │.5.24  │ │.5.25  │
         └───────┘ └───────┘ └───────┘
         10.100.x.x/24 per node
```

### IP Address Allocation

- Each node gets a /24 subnet from the platform's address space (e.g., 10.100.5.0/24).
- Each cell gets a unique IP from its node's subnet.
- IPs are allocated sequentially and recycled after cell destruction.
- Cells cannot discover other cells' IPs (no ARP, no broadcast).

### TAP Device Setup

For each cell, the node agent:

1. Creates a TAP device (e.g., `tap-cell_abc123`).
2. Assigns the host-side IP as the gateway for the cell's subnet.
3. Configures Firecracker to use the TAP device as the cell's network interface.
4. Applies nftables rules to the TAP device for policy enforcement.
5. Applies tc (traffic control) rules for bandwidth shaping.

### DNS Resolution

Cells do not have direct access to external DNS servers. All DNS resolution is mediated by the platform:

1. Cell's `/etc/resolv.conf` points to the host gateway IP as the nameserver.
2. Host runs a DNS proxy that receives queries from cells.
3. DNS proxy checks the cell's network policy for allowed domains.
4. If the domain is allowed, the query is forwarded to upstream DNS and the response returned.
5. If the domain is blocked, an NXDOMAIN response is returned.
6. All DNS queries (allowed and blocked) are logged as audit events.

This prevents DNS-based exfiltration (encoding data in DNS queries to unauthorized domains) and ensures that domain-level network policies are enforced even for IP-based connections (the cell can only resolve IPs for allowed domains).

## Network Policy Enforcement

### nftables Rule Generation

The Policy Engine translates high-level network policies into nftables rules applied per cell.

**Example Policy**:

```json
{
  "network_policy": {
    "default": "deny",
    "egress": [
      {
        "action": "allow",
        "destinations": [
          {"domain": "api.openai.com"},
          {"domain": "api.anthropic.com"}
        ],
        "protocols": ["tcp"],
        "ports": [443]
      },
      {
        "action": "allow",
        "destinations": [
          {"domain": "pypi.org"},
          {"domain": "files.pythonhosted.org"}
        ],
        "protocols": ["tcp"],
        "ports": [443]
      }
    ]
  }
}
```

**Generated nftables Rules**:

```nft
table inet cell_abc123 {
    set allowed_ips {
        type ipv4_addr
        flags interval
        # Populated dynamically by DNS proxy
        # api.openai.com resolved IPs
        # api.anthropic.com resolved IPs
        # pypi.org resolved IPs
        # files.pythonhosted.org resolved IPs
    }

    chain egress {
        type filter hook forward priority 0; policy drop;

        # Allow established/related connections
        ct state established,related accept

        # Allow DNS to host gateway (for resolution)
        iifname "tap-cell_abc123" ip daddr 10.100.5.1 udp dport 53 accept

        # Allow HTTPS to approved destinations
        iifname "tap-cell_abc123" ip daddr @allowed_ips tcp dport 443 accept

        # Log and drop everything else
        iifname "tap-cell_abc123" log prefix "CELL_BLOCKED: " drop
    }

    chain ingress {
        type filter hook forward priority 0; policy drop;

        # Allow established/related connections (responses)
        ct state established,related accept

        # Drop all unsolicited inbound
        oifname "tap-cell_abc123" drop
    }
}
```

### Dynamic IP Set Updates

When the DNS proxy resolves a domain for a cell, it:

1. Resolves the domain to its current IP addresses.
2. Adds the resolved IPs to the cell's nftables IP set.
3. Sets a TTL on the IP set entries matching the DNS TTL.
4. Expired entries are automatically removed.

This ensures that cells can only reach allowed domains even as those domains' IPs change, and that stale IP entries don't accumulate.

### Policy Hot-Update

Network policies can be updated on running cells:

1. API receives policy update request.
2. Policy Engine compiles new effective policy.
3. New nftables rules generated.
4. Old rules atomically replaced with new rules (`nft -f` for atomic ruleset replacement).
5. Existing established connections that violate the new policy are terminated.
6. Audit event logged for policy change.

## Traffic Shaping

### Bandwidth Limits

tc (traffic control) rules applied to each cell's TAP device:

**Egress** (cell → internet):

```bash
# HTB (Hierarchical Token Bucket) for egress shaping
tc qdisc add dev tap-cell_abc123 root handle 1: htb default 10
tc class add dev tap-cell_abc123 parent 1: classid 1:10 htb \
    rate 100mbit \      # Guaranteed rate
    ceil 200mbit \      # Burst ceiling
    burst 15k
```

**Ingress** (internet → cell):

```bash
# Ingress policing
tc qdisc add dev tap-cell_abc123 handle ffff: ingress
tc filter add dev tap-cell_abc123 parent ffff: protocol ip \
    u32 match u32 0 0 \
    police rate 100mbit burst 15k drop
```

### Connection Limits

nftables connection tracking limits prevent connection floods:

```nft
# Max 100 concurrent connections per cell
ct count over 100 drop

# Max 20 new connections per second
limit rate 20/second burst 5 packets accept
```

## Cell-to-Cell Communication

By default, cells cannot communicate with each other. For use cases that require inter-cell communication (e.g., multi-agent systems), explicit configuration is required:

> **Status: design sketch, not implemented.** Nothing in `src/` implements `cell_links` or IP-level connectivity between cells, and the implemented firewall drops all cell-to-cell forwarding (see "Host enforcement" below). The implemented way for two cells to exchange data is a consented, relayed **peer link**; see "Peer links and the PSI example" at the end of this file and PEER_LINKS.md.

### Linked Cells

```json
{
  "cell_links": [
    {
      "from_cell": "cell_abc",
      "to_cell": "cell_def",
      "protocol": "tcp",
      "ports": [8080],
      "bidirectional": false
    }
  ]
}
```

When cell links are configured:

1. Both cells' nftables rules are updated to allow traffic between their IPs on specified ports.
2. DNS entries are created so cells can resolve each other by name (e.g., `cell-def.internal`).
3. All inter-cell traffic is logged as audit events.
4. Links are destroyed when either cell is destroyed.

### Network Namespaces for Linked Cells

For complex multi-agent setups, linked cells can be placed in a shared network namespace with internal-only connectivity:

```
┌──────────────────────────────────┐
│     Shared Network (VXLAN)       │
│     172.16.0.0/24                │
│                                  │
│  ┌────────┐  ┌────────┐         │
│  │ Cell A │──│ Cell B │         │
│  │ .0.10  │  │ .0.11  │         │
│  └────┬───┘  └────┬───┘         │
│       │            │             │
│  ┌────▼────────────▼───┐        │
│  │  Internal Router     │        │
│  │  (controlled egress) │        │
│  └──────────┬──────────┘        │
└─────────────┼───────────────────┘
              │ Only Cell A has internet access
              ▼
           Internet
```

## Egress Proxy (Optional)

For tenants requiring advanced egress control:

### Forward Proxy

An optional HTTP/HTTPS forward proxy can be placed between cells and the internet:

- Full URL logging (not just IP/port).
- Request/response header inspection.
- Content-type filtering (e.g., block binary downloads).
- Data loss prevention (DLP) pattern matching on outbound data.
- Certificate inspection (MITM for HTTPS traffic with tenant consent).

### Proxy Configuration

When enabled, cells are configured to route all HTTP/HTTPS traffic through the proxy:

```
HTTP_PROXY=http://10.100.5.1:3128
HTTPS_PROXY=http://10.100.5.1:3128
NO_PROXY=localhost,127.0.0.1
```

## IPv6 Support

- Internal networking uses IPv4 only (simplicity for MVP).
- Egress to IPv6 destinations supported via NAT64 on the gateway.
- Full IPv6 internal networking planned for future release.

## Network Monitoring

### Per-Cell Network Metrics

Collected every 10 seconds:

- Bytes sent/received
- Packets sent/received
- Active connections (by protocol)
- New connections/second
- Blocked connection attempts
- DNS queries (allowed/blocked)

### Network Anomaly Detection

Heuristic-based detection for:

- **Unusual egress volume**: Cell sending significantly more data than its historical baseline.
- **Port scanning**: Cell attempting connections to many different ports.
- **DNS tunneling**: High volume of DNS queries with unusual query patterns (long subdomains, encoded-looking names).
- **Beacon behavior**: Periodic connections to the same destination at regular intervals (potential C2 communication).

Anomalies are logged as audit events with severity "warning" and optionally trigger webhook notifications.

## Host enforcement (implemented): `src/aijailer/netpolicy/`

Per cell: one TAP, one /30 (host `.1`, guest `.2`), no default route, no host forwarding.
Static nftables table `inet aijailer` (hooks at priority -100), filtering by interface-name
prefix `aj*` so an unregistered or stale cell interface is **denied, never open**:

| hook | rule |
|---|---|
| input from `aj*` | accept only `(iface, guest_ip, host_ip, broker_port)` (rate-limited `ct new`); everything else counted + rate-limited log + drop (spoofed source, IPv6, ICMP, UDP, every other host service) |
| forward | drop anything from or to `aj*` (no internet, no cell-to-cell, no inbound) |
| output | drop NEW connections from the host into `aj*` |

The broker listens per cell on `host_ip:broker_port` (`agentsec/proxy.py`); cell identity is the listener,
not a source address. Cell-side config: static IP via kernel cmdline, `http_proxy=http://<host_ip>:<port>`.
Verified with real packets in network namespaces (`tests/netpolicy/`).

### Lifecycle (implemented in `CellService` + `netpolicy/cell_network.py`)

| event | network action |
|---|---|
| create | firewall entry -> TAP + address + sysctl hardening -> per-cell proxy -> **then** boot VM with NIC, static `ip=` and `http_proxy` env. Any failure: undo in reverse, no VM is booted |
| stop / destroy | revoke firewall -> stop proxy -> delete TAP -> release /30 (address stays reserved if a step failed) |
| start (from stopped) | rebuild as for create |
| pause / resume | unchanged (VM frozen, link kept) |
| service start | install ruleset; refuse to start if it fails; watchdog verifies/repairs |

`NETWORK_ENFORCEMENT=auto|required|off`: engines that attach a NIC (Firecracker) can never run with `off`.
The simulated engine has no NIC and gets none. Egress comes from the cell's network policy
(domains and single IPs over TCP; CIDR/UDP rules are skipped and reported, never widened).

### Per-cell namespace (jailer `--netns`)

```
 root netns                         cell netns /run/netns/aj<id>  (jailer --netns)
 aj<id> host_ip  <-- veth pair -->  vc0 --[ br0 ]-- tap0 <--> Firecracker/guest
```
The VMM runs inside its own namespace and sees only `tap0`, the bridge and the veth peer: a compromised VMM
has no route to host services, other cells' links or the internet. The bridge makes guest NIC and host veth one
L2 segment, so the firewall (`iifname "aj*"`, guest/host /30, source match) and the broker apply unchanged.
`setup_link` waits until both veth ends are operationally UP (carrier changes are applied asynchronously, up to
~1 s, and the bridge will not forward until then), recovers a stale namespace left by a crash, and rolls back
completely on any failure. TAP is persistent and owned by the jailer uid so Firecracker attaches unprivileged.

### Bandwidth shaping (`netpolicy/shaping.py`)

Both limits are **egress** shapers (they queue, so TCP backs off on delay rather than loss):

| direction | where | note |
|---|---|---|
| download (host -> guest) | host veth `aj<id>` egress | root namespace |
| upload (guest -> host) | `vc0` egress inside the cell namespace | outside the guest, unreachable from it |

`tbf`, burst = 100 ms of traffic (min 32 KiB), queue bounded by 50 ms latency. Range 64 kbit/s to 10 Gbit/s,
`None` = unlimited per direction. `cell.network_bandwidth_mbps` is applied symmetrically at provisioning;
if shaping fails the whole network is rolled back. Because the broker is the cell's only path off the box,
bounding this link bounds the cell's total network use. Applied with netlink (no `tc` binary).

### Reconciliation (`netpolicy/reconciler.py`)

Every `RECONCILE_INTERVAL_SECONDS` (30, +/-10 % jitter) and once **before the service takes traffic**:

| kernel (`aj<12 hex>`) | DB status | action |
|---|---|---|
| present, registered here | ready/running/paused | keep (flag `broken` if veth/namespace vanished -> cell marked `error`) |
| present, not registered | ready/running/paused | **adopt** (restart recovery): rebuild registry from the veth address, re-grant firewall tuple, restart proxy, re-assert bandwidth |
| present | creating/stopping/destroying | never touched; after `RECONCILE_STUCK_SECONDS` (600) the cell is marked `error` and the network is cleaned |
| present, registered here | anything else | delete once older than `RECONCILE_GRACE_SECONDS` (120; the DB commit can lag provisioning) |
| present, not registered | anything else / unknown | delete (orphan) |

Safety: unreadable DB -> no changes; a sweep removing more than 5 networks **and** more than half of everything present aborts
(`aborted` in the report, logged); names not matching `^aj[0-9a-f]{12}$` are never touched, even if the scanner returns
them; subnets of resources we cannot adopt stay reserved so a new cell can never share a /30 with them.
After a restart the freshly installed ruleset has no tuples, so cells are cut off (fail closed) until the first sweep adopts them.

Changing limits at runtime (`PUT /v1/cells/{id}/bandwidth`): applied to the kernel first, then persisted, so a failed apply
never leaves the database claiming a limit the cell does not have. If the persist fails after a successful apply, or anyone
alters the qdiscs by hand, the reconciler compares `read_shaping` with the database every sweep and restores the database's
value (`shaping_repaired` in the sweep report). The database is the single source of truth.

### Engine-side reconciliation (`FirecrackerEngine.reconcile`)

Jailed VMMs outlive the control plane, but the engine's in-memory `_vms` does not. The same reconciler pass
(after the network sweep, same DB snapshot) therefore also compares the **host's VMMs and jails** with the cells the
database calls live. Identity comes only from what we can prove: a jail directory named exactly `<uuid>` under
`<JAILER_CHROOT_BASE>/<exec name>/`, and a process whose `argv[0]` is the Firecracker binary with `--id <uuid>`
(pid reuse cannot fool it: the argv is re-checked before every kill). Anything else is never touched.

| Found | DB says | Action |
|---|---|---|
| VMM (+jail) | live, VMM answers (API state + agent ping) | **adopted**: handle rebuilt with the cell's env (DB environment + proxy env) |
| VMM | live, no answer / not started | reported `unresponsive`, cell marked `error`; reaped as an orphan next pass |
| nothing running | live | reported `dead`, cell marked `error`, jail removed |
| managed VMM exited | live | same as dead |
| VMM and/or jail/cgroup | not live (stopped-in-DB, error, destroyed, unknown) | SIGKILL, wait, remove jail + cgroup |
| anything | creating/stopping/destroying, or `create_vm` in flight here | never touched |
| jail younger than `RECONCILE_GRACE_SECONDS` | not live | skipped (may be another process's launch) |

A STOPPED VM this process still manages is kept until `destroy_cell`. Removing more than 5 VMs that are also more than
half of everything present aborts the pass (a bad DB read must not look like a mass leak). Verified against the real jailer +
Firecracker (`tests/engine/test_real_jailer.py`): a fresh engine finds the VMM from its argv, refuses to adopt one that never
started, and kills it and removes its jail once the cell is not live. Not verified without KVM: adopting a *running* guest
(agent ping over vsock). `restore_vm` remains unimplemented.

### Peer links and the PSI example (implemented)

A peer link (PEER_LINKS.md) gives two consenting cells an encrypted channel **without any packet ever
flowing between them**. The reference PSI workload (`examples/psi/`) is the worked example. At the network
layer:

    cell A: psi.py ──127.0.0.1:P──> aijailer-peer ──TCP──> host_ip:broker_port ─┐
                                                                                ├─ CellProxy ─ PeerHub ─ CellProxy
    cell B: psi.py ──127.0.0.1:P──> aijailer-peer ──TCP──> host_ip:broker_port ─┘      (inside the host process)

- **Same single allowed destination.** Each cell connects only to its own `host_ip:broker_port`, the one
  destination the `aj*` input rule already accepts. There are **no new nftables rules, no new ports and no
  new listeners**; `forward` still drops everything from or to `aj*`. Cells still cannot reach each other's
  IPs. The relay pairs two connections inside the host process.
- **Identity is the listener**, as for all broker traffic: a cell can only attach as itself.
- **The name is never resolved.** The workload sends `CONNECT <link-id>.peer.aijailer.invalid:443` to the
  proxy; `.invalid` is reserved and has no DNS entry. The proxy diverts it before DNS resolution and before
  the egress allowlist, so neither DNS policy nor allowlists apply to it (and none are needed). The egress
  broker's content and credential checks do not see the traffic, which is end-to-end TLS 1.3 between the
  cells (see SECURITY_MODEL.md, "Peer links and the PSI example workload").
- **Environment.** When `PEER_ATTESTATION_SECRET` is set the cell also receives
  `AIJAILER_PEER_ATTEST_PUBKEY` next to the usual proxy variables; `NO_PROXY` and `no_proxy` are
  `127.0.0.1,localhost`, so loopback stays local (a proxy-aware client would otherwise send even
  `http://127.0.0.1:PORT/` to the broker, which refuses it); nothing else is configured to bypass the proxy,
  and what a cell can reach is enforced by the nftables rules, not by these variables.
- **Accounting.** The session crosses the cell's TAP like all other traffic, so by construction the cell's tc
  shaping and the broker-port connection-rate rule apply to it. I have not tested peer traffic under shaping.
  Sessions are bounded by the relay itself: lifetime (default 1 h), idle time (5 min) and bytes (1 GiB), and are
  cut at once when the link is revoked or either cell loses its network. Each session is one `network`
  audit event with the bytes moved each way.

**What PSI adds at the network layer: nothing.** `psi.py` talks to `aijailer-peer` over **loopback inside the
guest** (`--connect 127.0.0.1:P`), and the only traffic that leaves the cell is the helper's TLS stream to the
host proxy described above. The PSI frames are about 256 bytes per element, so the relay byte counts roughly
reveal set sizes to anyone who can read the audit log.

**Guest requirement: loopback must be up.** The local hand-off between `psi.py` and `aijailer-peer` needs the
guest's `lo` interface to be up. A freshly booted kernel starts with `lo` down, and the boot arguments
configure only `eth0` (`ip=<guest>::<host>:<mask>::eth0:off`), so a TCP connection to `127.0.0.1` fails
with `Network is unreachable`. The guest init (`guest-agent/init_linux.go`, `setupInit`) therefore brings
`lo` up with an ioctl (`bringUpLoopback`; no `ip` binary needed in the image). Verified: unit tests in a fresh
network namespace (loopback unreachable before, reachable after, idempotent, and an error is reported when
the ioctl is not permitted); and the real agent binary run as PID 1 in fresh PID, mount and network
namespaces inside the guest rootfs, where a workload running as the unprivileged `agent` user could connect
to `127.0.0.1`, whereas the agent built from the commit before the change reproduced `Network is
unreachable`. The helper's `--stdio` mode never needed loopback.

**Verified / not verified.** Verified: the relay path with real sockets through the real proxy and hub, and PSI
end to end over it (host network; also with both programs running in the guest rootfs's userland as the
unprivileged `agent` user, in a chroot, which shares the host's network and has no firewall). Not verified: a
booted Firecracker cell, the nftables rules in front of a real peer session, shaping of peer traffic, and
loopback inside a real guest.
