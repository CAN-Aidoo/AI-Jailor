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
