# MicroVM Engine Specification — AI Jailer

## Overview

The MicroVM Engine is the core isolation layer of AI Jailer. It manages the lifecycle of lightweight virtual machines that provide hardware-level isolation for every agent session. Each cell is a dedicated microVM with its own Linux kernel, making container-escape attacks irrelevant.

## Why MicroVMs Over Containers

| Concern | Docker Container | MicroVM (Firecracker) |
|---|---|---|
| Kernel | Shared with host | Dedicated per cell |
| Escape attack surface | Large (shared kernel, cgroups, namespaces) | Minimal (KVM hypervisor boundary) |
| Boot time | ~500ms | ~125ms |
| Memory overhead | ~10MB | ~5MB (Firecracker) |
| Syscall filtering | seccomp-bpf on shared kernel | Runs its own kernel; host sees only hypercalls |
| Network isolation | Network namespaces (bypassable) | Virtual NIC managed by hypervisor |
| Storage isolation | Overlay filesystem (shared underlying FS) | Dedicated block device |
| Compliance story | "It's isolated by Linux namespaces" | "It's a separate machine" |

## Firecracker as Primary VMM

### Why Firecracker

- Built by AWS for Lambda and Fargate. Battle-tested at massive scale.
- Boots a VM in ~125ms with ~5MB memory overhead.
- Minimal device model reduces attack surface (no USB, no GPU passthrough, no PCI — just virtio-net, virtio-block, and serial).
- KVM-based: leverages hardware virtualization (Intel VT-x / AMD-V).
- Written in Rust: memory-safe, no buffer overflows in the VMM itself.
- REST API for VM management — programmatic control over every aspect.

### Firecracker Limitations and Mitigations

| Limitation | Mitigation |
|---|---|
| Linux host only | Deploy on Linux servers (not a constraint for server infrastructure) |
| No GPU passthrough | Out of scope for MVP. Future: VFIO passthrough or sidecar GPU proxy |
| No live migration | Snapshot/restore serves the same use case for our workload |
| x86_64 and aarch64 only | Sufficient for all target workloads |
| No nested virtualization | Agents don't need to run VMs inside VMs |

### Kata Containers as Fallback VMM

Kata Containers serve as a secondary VMM for environments where Firecracker is impractical:

- Kubernetes-native integration via containerd shim.
- Supports more device types (useful for future GPU workloads).
- Higher overhead (~50MB per VM, ~300ms boot) but more flexible.
- Used when deploying AI Jailer inside existing Kubernetes clusters where Firecracker's bare-metal requirements are impractical.

## Cell Architecture

### What's Inside a Cell

```
┌───────────────────────────────────────────┐
│              MicroVM (Cell)                │
│                                           │
│  ┌──────────────────────────────────────┐ │
│  │         Guest Linux Kernel           │ │
│  │      (minimal, hardened, 5.10+)      │ │
│  └──────────────────────────────────────┘ │
│                                           │
│  ┌──────────────────────────────────────┐ │
│  │          Cell Agent (init)           │ │
│  │  - vsock listener                    │ │
│  │  - command executor                  │ │
│  │  - file transfer handler             │ │
│  │  - event reporter                    │ │
│  │  - health heartbeat                  │ │
│  └──────────────────────────────────────┘ │
│                                           │
│  ┌──────────────────────────────────────┐ │
│  │         Root Filesystem              │ │
│  │  ┌─────────┐  ┌──────────────────┐  │ │
│  │  │ Base    │  │ Overlay (R/W)    │  │ │
│  │  │ Image   │  │ Agent workspace  │  │ │
│  │  │ (R/O)   │  │ Installed pkgs   │  │ │
│  │  └─────────┘  └──────────────────┘  │ │
│  └──────────────────────────────────────┘ │
│                                           │
│  ┌────────────┐  ┌────────────────────┐  │
│  │ Persistent │  │ virtio-net NIC     │  │
│  │ Volume     │  │ (host-managed)     │  │
│  │ (/data)    │  │                    │  │
│  └────────────┘  └────────────────────┘  │
└───────────────────────────────────────────┘
         │              │
    ┌────▼────┐   ┌─────▼─────┐
    │ Block   │   │ TAP device│
    │ Storage │   │ + nftables│
    └─────────┘   └───────────┘
         Host
```

### Guest Kernel

- Minimal custom-built Linux kernel (5.10 LTS or 6.1 LTS).
- Only drivers needed: virtio-block, virtio-net, virtio-vsock, ext4.
- All unnecessary modules stripped out to reduce attack surface.
- Kernel hardening: KASLR, SMEP, SMAP, stack protector, read-only after init.
- Boot time contribution: ~30ms.

### Cell Agent

The Cell Agent is the only user-space process that starts automatically inside the cell. It is the bridge between the host and the guest.

**Responsibilities**:

- **Command Execution**: Receives commands via vsock, executes in a controlled shell, returns results.
- **File Transfer**: Handles file uploads/downloads between host and guest via vsock.
- **Event Reporting**: Reports file access, process creation, and network events back to host.
- **Health Heartbeat**: Sends periodic heartbeat to host. Missed heartbeats trigger cell health alerts.
- **Environment Setup**: Configures environment variables, working directory, and user context before command execution.
- **Graceful Shutdown**: Handles SIGTERM by cleaning up running processes and flushing event buffers.

**Implementation**: Single statically-linked binary (written in Go or Rust) that runs as PID 1 (init process) inside the guest.

**Communication**: All host-guest communication uses vsock (virtio-vsock). No network-based communication between host and guest agent. vsock is hypervisor-mediated, adding no network attack surface.

### Root Filesystem

**Base Images**: Pre-built, read-only root filesystem images optimized for common agent workloads:

| Image | Contents | Size |
|---|---|---|
| `base-minimal` | Alpine Linux, bash, curl, git | ~50MB |
| `base-python` | base-minimal + Python 3.11, pip, common libs | ~200MB |
| `base-node` | base-minimal + Node.js 20, npm | ~150MB |
| `base-full` | Ubuntu 22.04, Python, Node, Go, Rust, Java | ~800MB |
| `base-data` | base-python + pandas, numpy, scipy, jupyter | ~500MB |

**Overlay Filesystem**: Each cell gets a writable overlay on top of the read-only base image. Changes are isolated to the cell and discarded on destruction (unless persistent volume is configured).

**Custom Images**: Tenants can build custom base images using a Dockerfile-like specification. Custom images are stored in the platform's image registry and scanned for vulnerabilities before use.

### Persistent Volume

- Optional ext4-formatted block device mounted at `/data` inside the cell.
- Backed by host block storage (LVM thin provisioning).
- Survives cell stop/start. Destroyed only when explicitly deleted or cell is destroyed with `destroy_persistent=true`.
- Size specified at cell creation. Can be resized on a stopped cell.

### Networking

- Each cell gets a virtio-net NIC connected to a TAP device on the host.
- Host-side nftables rules enforce the cell's network policy.
- Each cell gets a unique internal IP from a private subnet.
- No direct cell-to-cell networking by default. Cells can only reach the internet or specified internal services through the host's network stack.
- DNS resolution controlled by the host — can be restricted to specific domains.

## MicroVM Lifecycle Operations

### Boot Sequence

```
1. API receives "create cell" request
2. Session Manager selects target node
3. Node agent pulls base image (if not cached)
4. Firecracker process starts with cell configuration:
   - kernel image path
   - root filesystem (base image + overlay)
   - vsock device (CID assigned)
   - network interface (TAP device created)
   - resource limits (CPU, memory)
   - boot args (Cell Agent config)
5. Firecracker boots guest kernel (~30ms)
6. Guest kernel starts Cell Agent as init (~50ms)
7. Cell Agent establishes vsock connection to host (~10ms)
8. Cell Agent sends "ready" signal
9. Session Manager marks cell as "ready"
Total: ~125ms cold start
```

### Warm Pool

For sub-50ms starts, the Warm Pool Manager pre-boots cells:

```
1. Maintain a pool of N pre-booted cells per base image
2. Cells are booted, Cell Agent is ready, but no tenant context assigned
3. On "create cell" request, assign a warm cell instead of booting fresh
4. Apply tenant-specific configuration (env vars, network policy, persistent volume)
5. Total: ~30-50ms from API call to ready
```

Pool sizing is dynamic based on demand patterns per base image.

### Snapshot

```
1. API receives "snapshot cell" request
2. Cell Agent flushes all buffers and syncs filesystems
3. Firecracker pauses the VM (all vCPUs halted)
4. Firecracker creates memory snapshot (full guest memory dump)
5. Host copies overlay filesystem state
6. Host copies persistent volume state (if any)
7. All artifacts uploaded to object storage as a snapshot bundle
8. Firecracker resumes the VM (or keeps paused per request)
9. Snapshot metadata recorded in PostgreSQL
```

### Restore

```
1. API receives "restore cell" request with snapshot ID
2. Session Manager selects target node
3. Snapshot bundle downloaded from object storage to node
4. Firecracker process starts with snapshot configuration:
   - Memory snapshot file
   - Disk snapshot files
   - Same vCPU and memory configuration as original
5. Firecracker restores VM state from snapshot
6. Cell Agent reconnects vsock (detects restore via timestamp check)
7. Cell is in the exact state it was when snapshot was taken
Total: ~50-200ms depending on snapshot size
```

### Destruction

```
1. API receives "destroy cell" request
2. Session Manager sends stop signal to node agent
3. Node agent sends SIGTERM to Firecracker process
4. Firecracker sends shutdown signal to guest (if responsive)
5. Grace period (5s default)
6. Firecracker process killed (SIGKILL)
7. TAP device removed
8. Overlay filesystem removed
9. Persistent volume: retained (default) or destroyed (if requested)
10. All metadata marked as destroyed
11. Audit event logged
```

## Resource Management at the VM Level

### CPU Allocation

- Firecracker supports CPU throttling via `--cpus` (vCPU count) and `--cpu-template` for clock speed.
- Host-level cgroups limit the Firecracker process to its allocated CPU share.
- CPU overcommit ratio configurable per node (default: 2:1 for standard tier, 1:1 for dedicated tier).

### Memory Allocation

- Firecracker sets guest memory at boot time (e.g., 256MB, 512MB, 1GB, 2GB, 4GB, 8GB).
- Memory balloon device allows dynamic memory adjustment without restart.
- Host OOM killer configured to kill Firecracker processes before system-critical processes.
- No memory overcommit — allocated memory is reserved.

### Disk I/O

- Rate-limited via cgroups v2 IO controller on the host.
- Limits expressed as IOPS and bandwidth (MB/s).
- Prevents noisy-neighbor problems on shared storage.

### Network Bandwidth

- tc (traffic control) applied to the TAP device.
- Ingress and egress bandwidth limits independently configurable.
- Burst allowances for short traffic spikes.

## Security Hardening

### Host-Level

- Firecracker runs as a non-root user with minimal capabilities.
- Each Firecracker process runs in its own cgroup, PID namespace, and mount namespace (defense in depth on top of KVM isolation).
- jailer utility (Firecracker's built-in sandboxing) applied to every instance.
- Seccomp profile limits Firecracker's own syscalls to only what it needs.
- SELinux or AppArmor profile on the Firecracker process.

### Guest-Level

- Read-only root filesystem (changes go to overlay).
- No SUID binaries in base images.
- Capability-based access control (no unnecessary capabilities).
- Default seccomp profile inside guest blocks dangerous syscalls.
- No access to host devices, /proc/host, or /sys/host.

### Hypervisor-Level

- KVM provides hardware-enforced boundary (ring -1 isolation).
- No shared memory between VMs (each VM has its own EPT/NPT page tables).
- No shared kernel between VMs (each boots its own kernel image).
- Minimal device model (virtio only) reduces VMM attack surface.

## Monitoring and Health

### Cell Health Checks

- Cell Agent sends heartbeat every 5 seconds via vsock.
- Missed heartbeats (3 consecutive) trigger health alert.
- 10 consecutive misses trigger automatic cell restart (configurable).
- Health status exposed via API and metrics.

### Node Health Checks

- Node agent reports capacity, running cells, resource usage every 10 seconds.
- Session Manager removes unhealthy nodes from placement pool.
- Cells on failed nodes marked as "lost" — restore from last snapshot offered.

### Metrics Collected

- Per cell: CPU usage, memory usage, disk I/O, network I/O, uptime, command count.
- Per node: Total capacity, used capacity, cell count, Firecracker process count.
- Per cluster: Total cells, total nodes, warm pool fill rate, snapshot storage used.
