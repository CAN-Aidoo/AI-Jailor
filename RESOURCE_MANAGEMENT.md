# Resource Management — AI Jailer

## Overview

Resource management serves two purposes: preventing cells from impacting each other (isolation) and tracking consumption for billing (metering). Every resource a cell consumes is both limited and measured.

## Resource Types and Enforcement

### CPU

**Enforcement Mechanism**: cgroups v2 CPU controller on the Firecracker process.

| Parameter | Control | Granularity |
|---|---|---|
| vCPU count | Firecracker boot config | Per cell |
| CPU quota | `cpu.max` (period/quota) | Per cell, per 100ms period |
| CPU weight | `cpu.weight` | Per cell (relative priority) |

**Overcommit**: Default 2:1 ratio (a 64-core node can host cells claiming 128 total vCPUs). This works because most agent workloads are bursty. Dedicated tier runs at 1:1 (no overcommit).

**Burst Handling**: CPU weight allows cells to use idle CPU beyond their quota, but they are always throttled back to their guaranteed allocation when contention occurs.

### Memory

**Enforcement Mechanism**: Firecracker VM memory allocation + cgroups v2 memory controller.

| Parameter | Control | Granularity |
|---|---|---|
| Memory size | Firecracker boot config | Per cell, fixed at creation |
| Memory limit | `memory.max` | Hard ceiling, OOM if exceeded |
| Swap | Disabled | N/A |

**No Overcommit**: Memory is reserved at cell creation. If a node doesn't have enough free memory, the cell is placed on a different node.

**OOM Behavior**: When a cell exceeds its memory limit, the OOM killer inside the guest kernel kills the offending process. The cell itself continues running. If the Cell Agent is killed, the cell is marked as unhealthy.

### Disk

**Enforcement Mechanism**: LVM thin provisioning + ext4 project quotas.

| Parameter | Control | Granularity |
|---|---|---|
| Root overlay size | LVM thin volume limit | Per cell |
| Persistent volume size | LVM thin volume limit | Per cell |
| IOPS limit | cgroups v2 io controller (`io.max`) | Per cell |
| Bandwidth limit | cgroups v2 io controller (`io.max`) | Per cell |

**Thin Provisioning**: Disk space is allocated on demand. A cell configured with 10GB disk doesn't consume 10GB on the host until it actually writes 10GB. This enables higher density.

**Quota Enforcement**: When a cell's disk usage hits its limit, further writes fail with ENOSPC inside the cell. The cell is not killed.

### Network

**Enforcement Mechanism**: tc (traffic control) on the TAP device + nftables connection limits.

| Parameter | Control | Granularity |
|---|---|---|
| Egress bandwidth | tc HTB (Hierarchical Token Bucket) | Per cell |
| Ingress bandwidth | tc ingress policing | Per cell |
| Concurrent connections | nftables connlimit | Per cell |
| New connections/second | nftables rate limit | Per cell |
| Total egress bytes | Metered (alert/cap based) | Per cell, per billing period |

**Burst Allowance**: Bandwidth shaping allows short bursts (e.g., downloading a large file) while enforcing average rate over time.

### Process Limits

**Enforcement Mechanism**: Guest kernel configuration.

| Parameter | Control | Granularity |
|---|---|---|
| Max processes | `kernel.pid_max` in guest | Per cell |
| Max open files | `ulimit -n` in guest | Per cell |
| Max file size | `ulimit -f` in guest | Per cell |

## Resource Quotas (Tenant-Level)

Beyond per-cell limits, tenant-level quotas prevent a single tenant from consuming a disproportionate share of platform resources.

| Quota | Free | Starter | Pro | Enterprise |
|---|---|---|---|---|
| Max concurrent cells | 3 | 10 | 100 | Custom |
| Max vCPUs (total) | 4 | 20 | 200 | Custom |
| Max memory GB (total) | 4 | 20 | 200 | Custom |
| Max persistent storage GB | 10 | 50 | 500 | Custom |
| Max snapshots | 10 | 100 | 1000 | Custom |
| Max API calls/min | 60 | 300 | 1000 | Custom |

## Metering Architecture

### Collection

```
┌─────────────────────────────────────────────────┐
│                Cell Node                         │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │  Resource Collector (per node)            │   │
│  │  - Reads cgroup stats every 10 seconds    │   │
│  │  - Reads tc stats every 10 seconds        │   │
│  │  - Reads LVM usage every 60 seconds       │   │
│  │  - Aggregates per-cell metrics            │   │
│  └──────────────────┬───────────────────────┘   │
│                     │                            │
│  ┌──────────────────▼───────────────────────┐   │
│  │  Local Buffer (in-memory ring buffer)     │   │
│  │  - 10-minute retention                    │   │
│  │  - Survives collector restart             │   │
│  └──────────────────┬───────────────────────┘   │
└─────────────────────┼───────────────────────────┘
                      │ Push every 10s
                      ▼
              ┌───────────────┐
              │  TimescaleDB   │
              │  (raw metrics) │
              └───────┬───────┘
                      │ Continuous aggregate
                      ▼
              ┌───────────────┐
              │ Hourly Usage   │
              │ (billing view) │
              └───────┬───────┘
                      │
                      ▼
              ┌───────────────┐
              │ Cost Calculator│
              │ (pricing plan  │
              │  × usage)      │
              └───────────────┘
```

### Metrics Collected

Every 10 seconds, per cell:

```json
{
  "timestamp": "2025-01-15T10:30:10Z",
  "cell_id": "cell_abc123",
  "tenant_id": "ten_xyz789",
  "cpu": {
    "usage_ns": 1500000000,
    "throttled_ns": 200000000,
    "periods": 100,
    "throttled_periods": 5
  },
  "memory": {
    "usage_bytes": 536870912,
    "cache_bytes": 134217728,
    "rss_bytes": 402653184,
    "swap_bytes": 0,
    "oom_kills": 0
  },
  "disk": {
    "read_bytes": 10485760,
    "write_bytes": 5242880,
    "read_iops": 150,
    "write_iops": 75,
    "usage_bytes": 2147483648
  },
  "network": {
    "rx_bytes": 1048576,
    "tx_bytes": 524288,
    "rx_packets": 1024,
    "tx_packets": 512,
    "connections_active": 5
  },
  "processes": {
    "count": 12,
    "threads": 45
  }
}
```

### Billable Units

Raw metrics are converted into billable units:

| Billable Unit | Calculation | Precision |
|---|---|---|
| CPU core-seconds | avg(cpu_usage_ns) / 1e9 × interval_seconds | 0.001 |
| Memory GB-seconds | avg(memory_usage_bytes) / (1024³) × interval_seconds | 0.001 |
| Storage GB-hours | avg(disk_usage_bytes) / (1024³) × interval_hours | 0.01 |
| Network egress GB | sum(network_tx_bytes) / (1024³) | 0.001 |
| Snapshot storage GB-hours | sum(snapshot_sizes) / (1024³) × retention_hours | 0.01 |
| API calls | count of API requests | 1 |

### Billing Periods

- Metered continuously (10-second granularity).
- Aggregated to hourly for billing (continuous aggregate in TimescaleDB).
- Invoiced monthly (sum of hourly usage × unit prices).
- Real-time usage available via API for dashboards.

## Cost Controls

### Spending Alerts

Tenants configure alerts at percentage thresholds of their budget:

```json
{
  "spending_alerts": [
    { "threshold_percent": 50, "channel": "webhook" },
    { "threshold_percent": 80, "channel": "webhook" },
    { "threshold_percent": 95, "channel": "webhook" },
    { "threshold_percent": 100, "channel": "webhook", "action": "alert_only" }
  ]
}
```

### Spending Caps

Hard spending limits that automatically stop cells when reached:

```json
{
  "spending_cap": {
    "monthly_limit_cents": 50000,
    "action_on_cap": "stop_all_cells",
    "grace_period_minutes": 30
  }
}
```

**Cap Enforcement Flow**:

1. Cost Calculator detects tenant spending has reached cap.
2. Grace period starts (configurable, default 30 minutes).
3. Webhook notification sent immediately.
4. If spending cap not increased within grace period, all tenant cells are stopped (not destroyed).
5. API calls that would create new cells or resume stopped cells are rejected with `spending_cap_reached`.
6. Audit logs and metering continue to function.

### Per-Cell Cost Tracking

Each cell's resource consumption is tracked individually, allowing tenants to identify expensive cells:

```
GET /v1/usage?group_by=cell&start_time=...&end_time=...&sort_by=cost_desc&limit=10
```

Returns the top 10 most expensive cells with breakdown by resource type.

## Monitoring and Observability

### Prometheus Metrics Endpoint

Exposed at `/metrics` on the API gateway:

```
# Cell metrics
aijailer_cells_total{tenant="ten_xyz",status="running"} 15
aijailer_cells_total{tenant="ten_xyz",status="paused"} 3
aijailer_cell_cpu_usage_seconds_total{cell="cell_abc"} 12345.6
aijailer_cell_memory_usage_bytes{cell="cell_abc"} 536870912
aijailer_cell_network_tx_bytes_total{cell="cell_abc"} 1073741824

# Node metrics
aijailer_node_cells_running{node="node-01"} 45
aijailer_node_capacity_vcpus{node="node-01"} 64
aijailer_node_available_vcpus{node="node-01"} 19

# Platform metrics
aijailer_api_requests_total{endpoint="/v1/cells",method="POST"} 5678
aijailer_api_latency_seconds{endpoint="/v1/cells/exec",quantile="0.95"} 0.087
aijailer_warm_pool_size{image="base-python"} 5
aijailer_snapshot_storage_bytes_total 10737418240
```

### Grafana Dashboards

Pre-built dashboards for:

- **Platform Overview**: Total cells, API throughput, error rates, node health.
- **Tenant View**: Per-tenant cell count, resource usage, spending, top cells.
- **Cell Detail**: Individual cell CPU, memory, disk, network over time.
- **Node Health**: Per-node capacity, utilization, cell density, I/O patterns.
- **Audit Pipeline**: Event throughput, processing lag, buffer depth.
- **Cost Tracking**: Spending by tenant, by resource type, daily/monthly trends.

### Alert Rules

| Alert | Condition | Severity | Action |
|---|---|---|---|
| Node Overcommit | Node CPU > 90% sustained 5min | Warning | Scale out |
| Node Full | Node < 10% free capacity | Critical | Drain node, scale out |
| Cell OOM | OOM kill inside cell | Warning | Notify tenant |
| API Latency | p99 > 500ms for 5min | Warning | Investigate |
| Audit Pipeline Lag | Consumer lag > 1000 events | Warning | Scale consumers |
| Snapshot Storage > 80% | Storage pool nearing capacity | Warning | Notify ops, expand storage |
