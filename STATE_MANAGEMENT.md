# State Management — AI Jailer

## Overview

State management is what separates AI Jailer from ephemeral sandboxing solutions. AI agents need to install dependencies, build context, create files, and maintain working state across multiple interactions. AI Jailer treats state as a first-class concern with three tiers: ephemeral, persistent, and snapshot.

## State Tiers

### Tier 1: Ephemeral State

**What**: Everything inside the cell's root filesystem overlay, process memory, and temporary files.

**Lifecycle**: Created when cell starts. Destroyed when cell is destroyed.

**Survives**:
- Nothing. Lost on cell destruction.
- Pause/resume retains ephemeral state (VM frozen in memory).

**Use Cases**: Package installation caches, temporary build artifacts, runtime process state.

**Implementation**: Copy-on-write overlay filesystem (overlayfs or device-mapper thin snapshot) on top of the read-only base image. The overlay is stored on the node's local SSD for maximum I/O performance.

### Tier 2: Persistent State

**What**: A dedicated block storage volume mounted inside the cell.

**Lifecycle**: Created with the cell (or independently). Survives cell stop/start cycles. Destroyed only when explicitly deleted.

**Survives**:
- Cell stop and restart.
- Cell image upgrade (new base image, same persistent volume).
- Node migration (volume detached from old node, attached to new node).

**Use Cases**: Agent workspace files, generated code, databases, project artifacts, anything the agent creates that must persist.

**Implementation**: Thin-provisioned LVM volume (ext4 formatted) on the node's storage pool. For node migration, data is replicated via block-level copy to the target node before cell starts there.

**Configuration at Cell Creation**:

```json
{
  "persistent_volume": {
    "size_mb": 10240,
    "mount_path": "/data",
    "encrypted": true,
    "backup_enabled": true,
    "backup_schedule": "daily"
  }
}
```

### Tier 3: Snapshot State

**What**: A complete point-in-time capture of the entire cell — memory, CPU registers, disk state, network state, everything.

**Lifecycle**: Created on demand or on schedule. Stored in object storage. Retained per policy.

**Survives**: Everything. A snapshot can recreate the exact cell state on any compatible node at any future time.

**Use Cases**: Checkpointing before risky operations, creating reusable environments, disaster recovery, cloning cells.

**Implementation**: Firecracker's snapshot API captures full VM state. Combined with disk image copy and persistent volume snapshot for a complete bundle.

## Persistent Volume Operations

### Creation

```
1. API receives cell creation request with persistent_volume config
2. Session Manager selects target node with sufficient storage
3. Node agent creates thin-provisioned LVM volume
4. Volume formatted as ext4 with project quotas enabled
5. Volume encrypted with dm-crypt (LUKS) using per-volume key
6. Encryption key stored in Vault, referenced by volume ID
7. Volume mounted inside cell at specified mount_path
8. Volume metadata recorded in PostgreSQL
```

### Resize

Only supported on stopped cells.

```
1. API receives resize request
2. Cell must be in "stopped" status
3. Node agent extends LVM logical volume
4. Node agent runs resize2fs to extend ext4 filesystem
5. Volume metadata updated
6. Cell can now be started with larger volume
```

### Detach / Reattach

For migrating cells between nodes or upgrading base images.

```
1. Cell stopped
2. Volume unmounted from cell
3. Volume data synced to object storage (or block-level copy to new node)
4. New cell created on target node
5. Volume data restored on target node
6. Volume mounted in new cell
```

### Encryption

All persistent volumes are encrypted at rest by default.

- **Algorithm**: AES-256-XTS via dm-crypt (LUKS2 format).
- **Key Management**: Per-volume encryption keys stored in HashiCorp Vault (or AWS KMS for cloud deployments).
- **Key Rotation**: Supported via LUKS2 key slot rotation without re-encrypting the entire volume.
- **Key Deletion**: When a volume is destroyed, the encryption key is deleted from Vault, making the data cryptographically unrecoverable.

## Snapshot Operations

### Create Snapshot

```
                Cell (Running)
                     │
         ┌───────────┼───────────┐
         │           │           │
    ┌────▼────┐ ┌────▼────┐ ┌───▼────┐
    │ Memory  │ │  Root   │ │Persist.│
    │ Snapshot│ │  Disk   │ │ Volume │
    │         │ │ Snapshot│ │Snapshot│
    └────┬────┘ └────┬────┘ └───┬────┘
         │           │          │
         └─────┬─────┘──────────┘
               │
        ┌──────▼──────┐
        │  Snapshot    │
        │  Bundle      │
        │  (Object     │
        │   Storage)   │
        └──────────────┘
```

**Detailed Flow**:

1. **Pre-snapshot hook**: Cell Agent flushes all filesystem buffers (`sync`), flushes application buffers if configured.
2. **VM pause**: Firecracker pauses all vCPUs. The VM is frozen mid-execution.
3. **Memory capture**: Firecracker dumps guest memory to a file on the host.
4. **Disk capture**: The root filesystem overlay is snapshotted (LVM snapshot of the overlay device).
5. **Persistent volume capture**: If present, the persistent volume is snapshotted (LVM snapshot).
6. **Metadata capture**: Cell configuration, environment variables, network config, security policy, and tags are serialized to JSON.
7. **Bundle creation**: All artifacts are compressed and uploaded to object storage as a single snapshot bundle.
8. **VM resume**: Firecracker resumes vCPUs. The cell continues from exactly where it was.
9. **Metadata recording**: Snapshot metadata stored in PostgreSQL.

**Snapshot Bundle Contents**:

```
snapshot_bundle/
├── metadata.json          # Cell config, policy, environment
├── memory.snap            # Full guest memory dump
├── rootfs.img             # Root filesystem overlay (compressed)
├── persistent_volume.img  # Persistent volume (compressed, if present)
└── manifest.json          # Bundle manifest with checksums
```

### Restore from Snapshot

1. **Node selection**: Session Manager selects a target node with sufficient resources.
2. **Bundle download**: Snapshot bundle downloaded from object storage to the target node.
3. **Integrity check**: Checksums in manifest verified against actual file hashes.
4. **Volume preparation**: Root filesystem overlay and persistent volume images restored to node storage.
5. **VM creation**: Firecracker process started with snapshot restore configuration.
6. **State restoration**: Firecracker loads memory snapshot, attaches disk images.
7. **Network setup**: TAP device created, nftables rules applied per original network policy.
8. **Cell Agent reconnection**: Cell Agent inside the guest detects restore (vsock reconnect) and re-establishes communication with the host.
9. **Status update**: Cell status set to "running" (restored in the exact state it was paused).

### Clone from Snapshot

Same as restore, but creates a new cell with a new ID. The cloned cell gets:

- New cell ID
- New internal IP
- New vsock CID
- Same persistent volume contents (independent copy)
- Optionally different resource limits or security policy

### Snapshot Scheduling

Tenants can configure automatic snapshots:

```json
{
  "snapshot_schedule": {
    "enabled": true,
    "interval": "6h",
    "retention_count": 4,
    "retention_days": 7,
    "pre_snapshot_command": "pg_dump -f /data/backup.sql"
  }
}
```

The pre_snapshot_command allows tenants to flush application-level state (e.g., database dump) before the snapshot is taken.

### Snapshot Retention Policies

| Policy | Behavior |
|---|---|
| **count-based** | Keep the N most recent snapshots. Delete older ones. |
| **age-based** | Keep snapshots younger than N days. Delete older ones. |
| **combined** | Keep at least N snapshots AND any snapshot younger than M days. |
| **permanent** | Never auto-delete. Manual deletion only. |

## Warm Pool State Management

The warm pool pre-boots cells for fast startup but needs careful state management:

### Pool Lifecycle

```
1. Warm Pool Manager creates cells with base image
2. Cells boot, Cell Agent starts, cell reaches "ready" state
3. Cell placed in warm pool (no tenant assignment)
4. When a "create cell" request comes in with warm_pool=true:
   a. Cell removed from warm pool
   b. Tenant context applied (env vars, security policy, persistent volume)
   c. Cell Agent configured with tenant settings
   d. Cell transitions to "running"
5. Warm Pool Manager creates a replacement cell to maintain pool size
```

### Pool Sizing Strategy

- Pool size per image = `max(min_pool_size, avg_hourly_demand * 1.2)`
- Demand tracked over rolling 7-day window
- Pool sizes adjusted every 15 minutes
- Floor of 2 cells per active image (always have warm cells available)
- Ceiling configurable per deployment (total warm cells across all images)

### Stale Cell Management

Warm cells that sit unused for too long are recycled:

- After 30 minutes in the pool, a cell is destroyed and replaced with a fresh one.
- This prevents state drift and ensures warm cells have clean, up-to-date configurations.

## Data Consistency Guarantees

### Cell Metadata

- PostgreSQL provides ACID guarantees for all cell metadata operations.
- Cell status transitions are protected by row-level locks to prevent race conditions.
- Status transition validation ensures only valid transitions occur (e.g., can't go from "destroyed" to "running").

### Snapshot Consistency

- VM is paused during snapshot to ensure memory and disk are consistent.
- No partial snapshots — if any component fails, the entire snapshot is rolled back.
- Snapshot bundle checksums verified on every restore.

### Persistent Volume Consistency

- LVM snapshots provide crash-consistent disk images.
- Pre-snapshot `sync` ensures filesystem buffers are flushed.
- Optional pre-snapshot commands allow application-level consistency (database dumps, etc.).

## Disaster Recovery

### Cell Loss (Node Failure)

```
1. Node heartbeat missed (3 consecutive)
2. All cells on the node marked as "lost"
3. For each lost cell:
   a. If latest snapshot exists: offer restore on a healthy node
   b. If persistent volume was replicated: restore volume on new node
   c. If neither: cell data is lost (ephemeral by nature)
4. Tenant notified via webhook with affected cell list
5. Node quarantined for investigation
```

### Object Storage Failure

- Snapshots stored with replication factor 3 (erasure coding for large objects).
- Cross-region replication for enterprise tier.
- Snapshot metadata in PostgreSQL allows discovery even if object storage listing is unavailable.

### Database Failure

- PostgreSQL configured with synchronous replication to standby.
- Point-in-time recovery enabled (WAL archiving).
- Redis cluster with sentinel for automatic failover.
- Running cells continue operating during database outage (in-memory state sufficient for execution).
- Cell creation, destruction, and snapshot operations blocked during database outage.
