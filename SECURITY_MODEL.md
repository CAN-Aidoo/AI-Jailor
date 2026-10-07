# Security Model — AI Jailer

## Security Philosophy

AI Jailer's entire value proposition is security. Every architectural decision is made with the assumption that the code running inside cells is actively hostile. The security model is built on three axioms:

1. **All agent code is untrusted.** No assumptions about intent or safety.
2. **Isolation failures are existential.** A single cell escape would destroy product credibility.
3. **Defense in depth is mandatory.** No single layer is trusted to hold alone.

## Threat Model

### Threat Actors

| Actor | Motivation | Capability |
|---|---|---|
| Malicious AI Agent | Hallucinated or injected malicious instructions | Arbitrary code execution within cell |
| Prompt Injection Attacker | Exploit agents to access infrastructure | Indirect — operates through the AI agent |
| Malicious Tenant | Abuse platform to attack other tenants or the internet | Legitimate API access + arbitrary code in cells |
| Sophisticated Adversary | Escape cell to access host or other cells | Deep kernel/hypervisor exploitation knowledge |
| Insider Threat | Platform operator with privileged access | Administrative credentials, host access |

### Threat Categories and Mitigations

#### T1: Cell Escape (Guest → Host)

**Threat**: Code inside a cell exploits a vulnerability to gain access to the host system.

**Attack Vectors**:
- KVM/hypervisor vulnerability (e.g., VENOM, CVE-2020-2732)
- Firecracker VMM bug allowing host memory access
- virtio device driver vulnerability
- vsock protocol exploitation

**Mitigations**:
- KVM provides hardware-enforced boundary (Intel VT-x / AMD-V ring separation)
- Firecracker written in Rust (memory-safe, eliminates entire classes of VMM bugs)
- Firecracker's minimal device model (only virtio-net, virtio-block, virtio-vsock, serial — no USB, no PCI, no GPU)
- Firecracker jailer: chroot + seccomp + cgroups + namespaces wrapping the VMM process itself
- Guest kernel is read-only and custom-built (no unnecessary modules)
- Regular Firecracker updates and security patches
- Host kernel hardened with all mitigations enabled (KPTI, Spectre mitigations, etc.)

**Detection**:
- Host-level intrusion detection (AIDE, OSSEC)
- Anomalous Firecracker process behavior monitoring
- Network traffic from Firecracker process to unexpected destinations

#### T2: Cell-to-Cell Attack (Guest → Guest)

**Threat**: Code in one cell accesses data or disrupts operation of another cell.

**Attack Vectors**:
- Shared host resources (CPU cache side-channels, Spectre/Meltdown)
- Network-based attacks if cells share a network segment
- Storage-based attacks via shared filesystem layers

**Mitigations**:
- No shared kernel between cells (each has its own)
- No shared memory between cells (separate EPT page tables)
- No cell-to-cell network by default (cells cannot discover each other's IPs). The one explicit exception is a consented peer link, which is never IP connectivity between cells; see "Peer links and the PSI example workload"
- Each cell's TAP device has isolated nftables rules
- Separate block devices per cell (no shared storage)
- Base images are read-only — no write contamination between cells
- CPU cache side-channel mitigations: separate physical cores for high-security tenants (dedicated tier)
- Spectre mitigations enabled in host kernel

**Detection**:
- Network traffic between cell IP ranges triggers immediate alert
- Cross-cell file access attempts logged and alerted

#### T3: Resource Exhaustion (Denial of Service)

**Threat**: A cell consumes excessive resources, degrading service for other cells or the platform.

**Attack Vectors**:
- CPU-intensive computation (crypto mining, fork bombs)
- Memory exhaustion (allocation until OOM)
- Disk fill attacks (write until storage full)
- Network flooding (bandwidth exhaustion, SYN floods)
- Process/thread bombs inside the guest

**Mitigations**:
- CPU: cgroup CPU quotas enforce per-cell limits. No cell can exceed its allocation.
- Memory: Fixed memory allocation per cell. No overcommit. OOM killer configured to kill the cell's processes first.
- Disk: Overlay filesystem size limits. Persistent volume size limits. Quota enforcement via ext4 project quotas.
- Network: tc rate limiting on TAP device. Connection count limits in nftables.
- Processes: PID limit inside the guest kernel (max_pids). ulimit enforcement.
- API: Per-tenant rate limiting prevents API-level DoS.

**Detection**:
- Real-time resource usage monitoring per cell
- Alerts when usage exceeds 80% of limits
- Automatic cell suspension when hard limits hit

#### T4: Data Exfiltration

**Threat**: Agent code extracts sensitive data from the cell or platform and sends it to an external destination.

**Attack Vectors**:
- HTTP requests to attacker-controlled servers
- DNS exfiltration (encoding data in DNS queries)
- Covert channels (timing-based, storage-based)

**Mitigations**:
- Network policies restrict outbound connections to explicitly allowed domains/IPs
- DNS resolution controlled by host — only allowed domains resolve
- All network traffic logged with destination, protocol, and bytes transferred
- DNS query logging captures all resolution attempts (including failed/blocked)
- Egress bandwidth limits prevent bulk data exfiltration
- No direct internet access by default — explicit opt-in per cell

**Detection**:
- Anomalous egress traffic volume alerts
- DNS query pattern analysis
- Connections to known-bad IPs/domains (threat intelligence integration)

#### T5: Secrets Exposure

**Threat**: API keys, tokens, or other secrets injected into cells are exposed or stolen.

**Attack Vectors**:
- Agent code reads environment variables and sends them to external services
- Secrets persisted to disk inside the cell
- Secrets leaked via stdout/stderr in logs
- Memory dump of cell captures secrets

**Mitigations**:
- Secrets injected via dedicated vsock channel, not environment variables (optional enhanced mode)
- Secret values redacted in audit logs (pattern-based detection and masking)
- Optional: secrets delivered as short-lived, single-use tokens that expire after first use
- Persistent volumes can be encrypted at rest with per-cell keys
- Snapshot encryption ensures secrets in memory snapshots are protected

**Detection**:
- Pattern matching on outbound network traffic for secret-like strings
- Audit log analysis for secret access patterns
- Alert on secrets appearing in command output

#### T6: Supply Chain Attack

**Threat**: Malicious packages installed inside cells compromise the agent or exfiltrate data.

**Attack Vectors**:
- Agent installs a malicious pip/npm package
- Compromised base image
- Typosquatting attack on package names

**Mitigations**:
- Base images built from verified sources, scanned for vulnerabilities
- Optional: package installation restricted to allow-listed packages
- Network policies can restrict access to package registries
- Image signing and verification (cosign/Notary)

**Detection**:
- Package installation events logged in audit trail
- Vulnerability scanning of installed packages (on-demand)

#### T7: Platform Infrastructure Attack

**Threat**: Attack on AI Jailer's own infrastructure (API, databases, control plane).

**Attack Vectors**:
- API vulnerability exploitation
- SQL injection, SSRF, authentication bypass
- Compromise of administrative credentials
- Supply chain attack on platform dependencies

**Mitigations**:
- API input validation via Pydantic (type-safe, schema-enforced)
- Parameterized queries only (no dynamic SQL)
- mTLS between internal services
- Secret rotation and vault-based credential management
- Regular dependency auditing and updates
- Least-privilege access for all service accounts
- Administrative actions require MFA and are logged

**Detection**:
- API anomaly detection (unusual request patterns)
- Authentication failure monitoring
- Infrastructure change monitoring

## Peer links and the PSI example workload

A peer link (PEER_LINKS.md) lets two specific cells exchange data through the platform. It is a deliberate,
narrow exception to T2 (no cell-to-cell network) and it is also a data channel, so it belongs in the T4
analysis. The reference PSI workload (`examples/psi/`) is the worked example of using it.

### What the exception is, and is not

- **Not IP connectivity.** Cells still cannot see or address each other. Each cell opens a CONNECT to a
  reserved name on its *own* proxy; the platform relay pairs the two sides. nftables isolation is unchanged.
- **Consent from both owners**, re-checked on every connection (link active, unexpired, both cells running,
  both still owned by the agreed tenants). Either party can revoke at any time and a live session is cut at
  once. Links between two cells of one tenant need no second consent. A link is revoked automatically when
  either cell stops or is destroyed.
- **Bounded**: one open link per cell pair, a per-tenant limit on open links, and per-session lifetime, idle
  and byte limits (defaults: 1 hour, 5 minutes, 1 GiB).
- **Audited** on both tenants' hash chains: the link lifecycle, and one network event per session with the
  bytes moved each way.

### Residual risks

| Risk | Detail | Mitigation |
|---|---|---|
| Exfiltration to the peer | A peer link is an opaque channel. A compromised or malicious cell can send anything to the peer cell, and the egress broker's content and credential checks do not see it. | The peer's owner has consented to receive from that cell; the link is scoped to one cell pair, time-limited, byte-capped and revocable. Do not link a cell that holds data it must never release. |
| Platform man-in-the-middle | Identity rests on the platform's signed attestation. A compromised platform could attest a certificate it controls. | Pin the peer's certificate hash out of band (`aijailer-peer --identity-file`, `--pin`). The platform then cannot impersonate either side. |
| Operator visibility | The operator sees who connects to whom, when, and how many bytes; it can deny service. | Stated trust model: the operator is trusted for availability and metadata, not for the content of the exchange. The operator can still read cell memory (T7). |
| Peer misbehaviour | The link authenticates the peer; it does not make the peer honest. | Application-level protocol design (see below). |
| Local socket takeover | `aijailer-peer --listen` serves one local TCP connection and does not authenticate it: the first process in the cell to connect becomes the channel's endpoint, and any process in the cell can reach it. | The link authenticates the *cell*, not processes inside it, so this is within the trust model. Bind `127.0.0.1` only, start the workload right after the helper's `listening` event, or use `--stdio` from a parent process (no listening socket). Do not put mutually untrusting workloads in one cell that shares a peer link. |

### Loopback inside the cell

The guest init brings the cell's loopback interface up (`bringUpLoopback`, `guest-agent/init_linux.go`); a
freshly booted kernel starts with `lo` down, which made `127.0.0.1` unreachable and broke the local hand-off
to `aijailer-peer` (see NETWORKING.md). Turning it on is a deliberate, small change to what code inside a cell
can do, so its security effect is stated here.

- **No new host-facing surface.** Loopback traffic stays inside the guest kernel. It never crosses the TAP, so
  it is invisible to the host's nftables rules, which filter the cell's `aj*` interface and are unchanged. A
  service bound to `127.0.0.1` is not reachable from outside the cell.
- **Not a trust boundary.** Processes in a cell share one trust domain, and the untrusted agent code is the
  workload itself. With loopback up it can run local servers and talk to other processes in its own cell, and it
  can connect to the peer helper's local socket (see "Residual risks"). It could already share data between its
  own processes through files, pipes and sockets; loopback adds no capability that crosses the cell boundary.
- **The workload cannot control the interface.** It runs as a non-root user with `no_new_privs`, so it cannot
  reconfigure interfaces. Checked: as the unprivileged `agent` uid (3000) in the guest rootfs, `lo` reads as up
  and an attempt to bring it down fails with `EPERM`.
- **Fails closed.** If bringing `lo` up fails, the init logs it and carries on; localhost then stays unreachable
  and local helpers break loudly (`Network is unreachable`). It never widens access.
- **Not audited.** Loopback traffic between processes in a cell is not logged or visible to the platform, like
  other intra-cell activity. Only what leaves the cell (through the broker or a peer link) is audited.
- **Guest kernel surface.** Loopback TCP uses the same in-guest network stack that `eth0` already exposes to the
  workload, so it should add no new kernel code path of note (reasoning, not measured); guest-kernel exploitation remains covered by T1.

### PSI workload

`psi.py` computes a two-party private set intersection over the link: the receiver learns which of its items
the sender also has, the sender learns only the receiver's set size, and neither learns the other's other
items. The platform never sees items, blinded values or the result; they are inside end-to-end TLS 1.3.

Security properties and limits of the demo (full list in `examples/psi/README.md`):
- **Semi-honest only.** A malicious sender can lie about its set or the results; nothing proves it used the
  set it claims. Do not treat the output as authenticated against a hostile peer.
- **Low-entropy identifiers can be enumerated.** The receiver may submit any items, so with phone numbers,
  e-mail addresses or small ID ranges it can test every candidate and learn the sender's whole set. This is
  inherent to PSI. Use high-entropy identifiers or restrict what each side may submit.
- **Hostile input is handled safely**: every received element must be a quadratic residue other than 1 and
  p-1 (rejects small-subgroup elements that could leak key bits), counts are bounded before allocation, and
  malformed or truncated frames end the run with an error.
- **Sizes leak** to both parties and, through relay byte counts in the audit log, approximately to the
  operator and auditors (the frames are about 256 bytes per element). Pad the sets if this matters.
- Not constant-time, pure-Python, and demo-grade (about 0.1 s per item pair). For production use a reviewed
  PSI library.

### What has and has not been verified

Verified: protocol and hostile-input tests (eight deliberately broken variants are each caught); the whole
stack (PSI, `aijailer-peer`, the real proxy and relay, mutual TLS); and a run with both programs executing
in the guest rootfs's userland as the unprivileged `agent` user. That last run was a chroot, not a booted
cell: no microVM boundary, guest agent, seccomp or egress firewall was involved.
For loopback: unit tests in a fresh network namespace, the real agent run as PID 1 in fresh PID, mount and
network namespaces inside the guest rootfs, and the `EPERM` check as uid 3000 (a plain uid check, not under the
agent's full hardening).
Not verified: peer links, PSI or the loopback change inside a real Firecracker cell (no KVM was available; a fresh
network namespace is assumed to mirror a freshly booted kernel's `lo` state), the claim that loopback adds no
notable guest-kernel surface (reasoning, not measured), and the PostgreSQL paths of the peer-link lifecycle.

## Security Policy Framework

### Policy Levels

```
┌─────────────────────────────────────┐
│  Level 4: Maximum Containment       │
│  No network, no filesystem writes,  │
│  minimal syscalls, full audit       │
├─────────────────────────────────────┤
│  Level 3: Restricted (Default)      │
│  Allowed domains only, limited FS,  │
│  standard syscall filter, audit     │
├─────────────────────────────────────┤
│  Level 2: Standard                  │
│  Internet access, full FS, relaxed  │
│  syscalls, audit                    │
├─────────────────────────────────────┤
│  Level 1: Permissive                │
│  Full internet, full FS, minimal    │
│  syscall filtering, audit           │
└─────────────────────────────────────┘
```

### Network Policy Specification

```yaml
network_policy:
  default: deny                    # deny all by default
  egress:
    - action: allow
      destinations:
        - domain: "api.openai.com"
        - domain: "*.github.com"
        - cidr: "10.0.0.0/8"      # internal services
      protocols: [tcp]
      ports: [443, 80]
    - action: allow
      destinations:
        - domain: "pypi.org"
        - domain: "registry.npmjs.org"
      protocols: [tcp]
      ports: [443]
      comment: "Package registries"
  ingress:
    - action: deny                 # no inbound connections
  dns:
    allowed_resolvers: ["10.0.0.53"]  # platform DNS only
    log_all_queries: true
```

### Syscall Policy Specification

```yaml
syscall_policy:
  default: allow                    # allow by default, block dangerous ones
  blocked:
    - name: mount                   # no mounting filesystems
    - name: umount2
    - name: pivot_root
    - name: kexec_load             # no loading new kernels
    - name: kexec_file_load
    - name: reboot
    - name: swapon
    - name: swapoff
    - name: ptrace                  # no debugging other processes
    - name: process_vm_readv
    - name: process_vm_writev
    - name: init_module            # no loading kernel modules
    - name: finit_module
    - name: delete_module
    - name: bpf                    # no eBPF programs
    - name: userfaultfd            # exploit primitive
  logged:
    - name: execve                 # log all program executions
    - name: connect                # log all network connections
    - name: open                   # log all file opens
    - name: unlink                 # log all file deletions
```

### Filesystem Policy Specification

```yaml
filesystem_policy:
  root: read_only                   # base image is read-only
  paths:
    - path: /tmp
      mode: read_write
      size_limit: 500MB
    - path: /home/agent
      mode: read_write
      size_limit: 1GB
    - path: /data
      mode: read_write              # persistent volume
    - path: /etc/passwd
      mode: read_only               # can read but not modify
    - path: /etc/shadow
      mode: deny                    # cannot access
    - path: /proc/self
      mode: read_only
    - path: /proc
      mode: deny                    # no access to other process info
```

## Compliance Mapping

### SOC 2 Type II

| SOC 2 Criteria | AI Jailer Control |
|---|---|
| CC6.1: Logical access security | API key auth, RBAC, tenant isolation |
| CC6.2: System component security | MicroVM isolation, hardened kernels |
| CC6.3: External threats | Network policies, intrusion detection |
| CC7.1: Monitoring | Audit pipeline, real-time alerting |
| CC7.2: Incident management | Automated cell containment, audit trails |
| CC8.1: Change management | Immutable infrastructure, image versioning |

### HIPAA

| HIPAA Requirement | AI Jailer Control |
|---|---|
| Access controls (164.312(a)) | RBAC, tenant isolation, API authentication |
| Audit controls (164.312(b)) | Complete audit logging with tamper evidence |
| Integrity controls (164.312(c)) | Read-only base images, cryptographic hash chains |
| Transmission security (164.312(e)) | TLS 1.3, encrypted vsock |
| Encryption at rest | AES-256 for persistent volumes and snapshots |

## Incident Response

### Automated Responses

| Trigger | Automated Action |
|---|---|
| Cell escape detection | Immediate cell destruction, node quarantine, alert to security team |
| Resource limit exceeded | Cell suspended, tenant notified |
| Security policy violation | Event logged, configurable (alert / suspend / destroy) |
| Audit pipeline failure | Events buffered locally, cells continue, alert to ops |
| Authentication failure (>10 in 1min) | IP/API key temporary block, alert to tenant admin |

### Manual Response Procedures

- **Cell Escape Confirmed**: Destroy all cells on affected node. Forensic capture of node state. Rotate all credentials. Notify affected tenants. Post-mortem analysis.
- **Data Breach Confirmed**: Identify scope of exposed data. Notify affected tenants within 24 hours. Engage legal/compliance. Full audit trail review.
- **Platform Compromise**: Rotate all internal credentials. Redeploy all control plane components from known-good state. Review all recent administrative actions.

## Security Testing Requirements

- **Penetration Testing**: Quarterly third-party pen test focused on cell escape, cross-tenant access, and API vulnerabilities.
- **Red Team Exercise**: Semi-annual red team exercise simulating a sophisticated attacker with code execution inside a cell.
- **Vulnerability Scanning**: Continuous scanning of base images, host OS, and platform dependencies.
- **Fuzzing**: Continuous fuzzing of vsock protocol handler, API endpoints, and policy compiler.
- **Chaos Engineering**: Regular failure injection to validate security controls under degraded conditions.
