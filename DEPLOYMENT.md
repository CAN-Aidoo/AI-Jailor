# Deployment Architecture — AI Jailer

## Deployment Models

AI Jailer supports three deployment models:

### 1. SaaS (Managed Cloud)

AI Jailer hosts and operates the entire platform. Tenants interact via API only.

- **Infrastructure**: AI Jailer-operated bare-metal servers in colocation facilities and/or cloud VMs with nested virtualization.
- **Management**: AI Jailer team handles all infrastructure operations, updates, and scaling.
- **Isolation**: Multi-tenant with hypervisor-level isolation between all cells. Dedicated nodes available for enterprise tier.
- **Target**: Startups, SMBs, teams that want zero infrastructure overhead.

### 2. Dedicated Cloud

AI Jailer operates a dedicated cluster for a single tenant within a cloud region of their choice.

- **Infrastructure**: Cloud VMs (metal instances preferred) in the tenant's preferred region.
- **Management**: AI Jailer team manages operations. Tenant has visibility via dashboards and audit logs.
- **Isolation**: Single-tenant cluster. No shared infrastructure with other tenants.
- **Target**: Enterprise customers with data residency requirements or strict isolation needs.

### 3. Self-Hosted (On-Premise)

Tenant deploys AI Jailer in their own infrastructure.

- **Infrastructure**: Tenant-provided bare-metal servers or VMs with KVM support.
- **Management**: Tenant operates. AI Jailer provides documentation, Helm charts, and support.
- **Isolation**: Fully within the tenant's network perimeter.
- **Target**: Enterprises with air-gapped environments, government, healthcare.

## Infrastructure Requirements

### Cell Nodes (Data Plane)

Cell nodes run Firecracker microVMs. They need:

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 16 cores, Intel VT-x or AMD-V | 64+ cores, modern Xeon/EPYC |
| Memory | 32 GB | 128+ GB |
| Storage | 500 GB NVMe SSD | 2+ TB NVMe SSD (RAID-1) |
| Network | 1 Gbps | 10+ Gbps |
| OS | Ubuntu 22.04 LTS (kernel 5.15+) | Ubuntu 24.04 LTS (kernel 6.8+) |
| KVM | Required (`/dev/kvm` accessible) | — |

**Key Requirement**: KVM must be available. This means either bare-metal servers or cloud instances that support nested virtualization (AWS `.metal` instances, GCP N2 with nested virt, Azure DCv2).

### Control Plane Nodes

Control plane services run in Kubernetes. Standard compute nodes:

| Requirement | Minimum | Recommended |
|---|---|---|
| CPU | 4 cores per node, 3 nodes | 8 cores per node, 5 nodes |
| Memory | 16 GB per node | 32 GB per node |
| Storage | 100 GB SSD | 200 GB SSD |
| Network | 1 Gbps | 10 Gbps |

### Database Infrastructure

| Service | Minimum | Recommended |
|---|---|---|
| PostgreSQL | 2 vCPU, 8 GB RAM, 100 GB SSD | 8 vCPU, 32 GB RAM, 500 GB SSD, streaming replica |
| Redis | 2 vCPU, 4 GB RAM | 4 vCPU, 16 GB RAM, sentinel cluster (3 nodes) |
| Kafka | 3 brokers, 4 vCPU, 8 GB RAM each | 5 brokers, 8 vCPU, 32 GB RAM each |
| ClickHouse | 4 vCPU, 16 GB RAM, 500 GB SSD | 8 vCPU, 64 GB RAM, 2 TB SSD, 2-node replica |
| TimescaleDB | 2 vCPU, 8 GB RAM, 200 GB SSD | 4 vCPU, 16 GB RAM, 500 GB SSD |
| MinIO / S3 | 4 nodes, 4 drives each | 8 nodes, 8 drives each (erasure coding) |

## Kubernetes Deployment

### Control Plane Services

All control plane services are deployed as Kubernetes Deployments with horizontal pod autoscaling.

```yaml
# Namespace structure
namespaces:
  - aijailer-system      # Core platform services
  - aijailer-monitoring  # Prometheus, Grafana, alerting
  - aijailer-data        # Database operators and stateful services
```

### Service Topology

```yaml
# API Gateway
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api-gateway
  namespace: aijailer-system
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
        - name: api-gateway
          resources:
            requests:
              cpu: 500m
              memory: 512Mi
            limits:
              cpu: 2000m
              memory: 2Gi
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            periodSeconds: 10

# Horizontal Pod Autoscaler
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: api-gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: api-gateway
  minReplicas: 3
  maxReplicas: 20
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

### Service Dependencies

```
api-gateway
├── session-manager
│   ├── PostgreSQL (cell metadata)
│   ├── Redis (session registry, warm pool)
│   └── Node Agent (cell lifecycle)
├── execution-engine
│   └── Node Agent (command execution via vsock)
├── policy-engine
│   └── PostgreSQL (policy store)
├── state-store
│   ├── PostgreSQL (snapshot metadata)
│   └── MinIO/S3 (snapshot blobs)
├── audit-pipeline
│   ├── Kafka (event transport)
│   └── ClickHouse (event storage)
└── resource-governor
    ├── TimescaleDB (metering data)
    └── Redis (real-time usage cache)
```

## Node Agent

The Node Agent runs on every cell node (outside Kubernetes). It is the bridge between the control plane and the data plane.

### Responsibilities

- Receive cell lifecycle commands from Session Manager.
- Manage Firecracker processes (start, stop, snapshot, restore).
- Create/configure TAP devices and nftables rules.
- Manage LVM volumes for cell storage.
- Collect resource metrics from cgroups.
- Buffer audit events for Kafka publishing.
- Report node health and capacity to Session Manager.

### Deployment

- Installed as a systemd service on each cell node.
- Auto-updates via a pull-based mechanism (checks for new versions periodically).
- Communicates with control plane via mTLS-authenticated gRPC.
- Survives control plane outages (running cells continue, new cell creation paused).

### Configuration

```yaml
# /etc/aijailer/node-agent.yaml
control_plane:
  endpoint: "grpcs://control.aijailer.internal:9090"
  tls:
    cert: "/etc/aijailer/tls/node.crt"
    key: "/etc/aijailer/tls/node.key"
    ca: "/etc/aijailer/tls/ca.crt"

node:
  id: "auto"  # Generated on first boot
  region: "us-east-1"
  zone: "us-east-1a"
  labels:
    tier: "standard"

firecracker:
  binary: "/usr/local/bin/firecracker"
  jailer_binary: "/usr/local/bin/jailer"
  kernel_image: "/var/lib/aijailer/kernels/vmlinux-5.10"
  base_images_dir: "/var/lib/aijailer/images"

storage:
  volume_group: "aijailer-vg"  # LVM volume group for cell storage
  thin_pool: "aijailer-pool"

networking:
  cell_subnet: "10.100.5.0/24"
  gateway_ip: "10.100.5.1"
  dns_proxy_port: 53

metrics:
  collection_interval: "10s"
  kafka_brokers: ["kafka-1:9092", "kafka-2:9092", "kafka-3:9092"]

warm_pool:
  enabled: true
  max_cells: 20
  stale_timeout: "30m"
```

## Image Management

### Base Image Distribution

Base images are stored in an internal image registry (MinIO-backed OCI registry or direct object storage).

**Image Distribution Flow**:

```
1. Image built in CI/CD pipeline
2. Image scanned for vulnerabilities
3. Image signed with cosign
4. Image pushed to registry
5. Node agents pull images on demand (with caching)
6. Images cached locally on each node (LRU eviction)
```

### Image Cache

Each node maintains a local image cache:

- Images stored on the node's SSD.
- LRU eviction when cache exceeds 80% of allocated space.
- Frequently used images (base-python, base-node) are pinned and never evicted.
- Cache hit avoids network transfer and enables faster cell creation.

## Scaling Strategy

### Horizontal Scaling

| Component | Scaling Trigger | Scaling Action |
|---|---|---|
| API Gateway | CPU > 70% | Add pods (K8s HPA) |
| Session Manager | Request queue depth | Add pods |
| Execution Engine | Concurrent execution count | Add pods |
| Audit Pipeline | Kafka consumer lag > 1000 | Add consumer pods |
| Cell Nodes | Available capacity < 20% | Add nodes (cluster autoscaler or manual) |
| Kafka | Partition lag | Add brokers, rebalance |
| ClickHouse | Query latency | Add replicas |

### Cell Node Auto-Scaling

For cloud deployments, cell nodes can be auto-scaled:

1. Session Manager reports cluster-wide available capacity to scaling controller.
2. If available capacity drops below 20%, scaling controller provisions new cell nodes.
3. New nodes join the cluster after Node Agent installation and health check.
4. If available capacity exceeds 60% for 30+ minutes, excess nodes are drained and terminated.
5. Draining: running cells on the node are migrated (snapshot → restore on different node) before termination.

### Capacity Planning

**Cells per node** (rough guide based on 64-core, 128GB RAM node):

| Cell Size | Cells per Node | Total with 2:1 CPU Overcommit |
|---|---|---|
| 1 vCPU, 256MB | ~400 | ~500 |
| 2 vCPU, 512MB | ~200 | ~250 |
| 2 vCPU, 1GB | ~100 | ~128 |
| 4 vCPU, 2GB | ~50 | ~64 |
| 8 vCPU, 4GB | ~25 | ~32 |

## High Availability

### Control Plane HA

- All control plane services run with minimum 3 replicas across availability zones.
- PostgreSQL: Primary + synchronous standby + async standby.
- Redis: 3-node sentinel cluster.
- Kafka: 3+ brokers with replication factor 3.
- ClickHouse: 2+ replicas with ReplicatedMergeTree.

### Data Plane HA

- Cell nodes are distributed across availability zones.
- Node failure affects only cells on that node.
- Cells with snapshots can be restored on healthy nodes.
- Warm pool cells distributed across nodes for redundancy.

### DNS and Load Balancing

- API traffic enters through a cloud load balancer (AWS ALB, GCP GLB) or self-hosted HAProxy.
- Health checks on API gateway pods determine routing.
- WebSocket connections are sticky to a specific pod for the duration of the session.

## Secrets Management

### Platform Secrets

- All platform credentials stored in HashiCorp Vault.
- Database passwords, API signing keys, TLS certificates.
- Auto-rotation on configurable schedules.
- Kubernetes pods retrieve secrets via Vault Agent sidecar.

### Tenant Secrets

- Tenant API keys hashed with SHA-256 before storage.
- Cell environment variables containing secrets are encrypted in PostgreSQL.
- Secrets passed to cells via vsock (not visible in Firecracker process args).
- Per-cell encryption keys stored in Vault, destroyed when cell is destroyed.

## Upgrade Strategy

### Zero-Downtime Deployments

**Control Plane**: Rolling updates via Kubernetes. New pods start, pass health checks, then old pods are terminated.

**Node Agent**: Rolling update across nodes. One node at a time:
1. Node marked as "draining" (no new cells placed).
2. Running cells continue (existing agent keeps running).
3. New agent binary deployed.
4. Agent restarted (sub-second; running Firecracker processes are unaffected).
5. Node marked as "active."

**Cell Agent**: Updated only when new cells are created. Running cells keep their existing Cell Agent version. For critical security patches, cells can be force-restarted to pick up the new agent.

**Base Images**: New image versions are published alongside old ones. Existing cells continue using their original image. New cells use the latest version by default.

### Database Migrations

- Managed by Alembic (Python) or golang-migrate (Go).
- All migrations are backward-compatible (add columns nullable, backfill, then enforce).
- Migration applied before new code deploys (database-first, code-second).
- Rollback: deploy previous code version (no reverse migrations needed if forward-compatible).

## Monitoring and Alerting

### Monitoring Stack

- **Prometheus**: Metrics collection from all components.
- **Grafana**: Dashboards and visualization.
- **Alertmanager**: Alert routing to PagerDuty/OpsGenie/Slack.
- **Loki**: Log aggregation from all components.
- **Jaeger**: Distributed tracing (OpenTelemetry).

### Critical Alerts

| Alert | Condition | Response |
|---|---|---|
| Control Plane Down | API returns 5xx > 1% for 5 min | Page on-call |
| Node Unreachable | Node heartbeat missed 3x | Auto-drain, page on-call |
| Database Failover | Primary DB unavailable | Auto-failover, notify on-call |
| Kafka Lag Critical | Consumer lag > 10,000 events | Scale consumers, page on-call |
| Cell Escape Detected | Host IDS alert from cell node | Auto-quarantine, page security |
| Storage Full | Any storage pool > 90% | Notify ops, block new allocations |
| Certificate Expiry | TLS cert expires in < 30 days | Notify ops |

## Backup Strategy

| Data | Backup Method | Frequency | Retention | RTO |
|---|---|---|---|---|
| PostgreSQL | WAL archiving + base backup | Continuous / Daily | 30 days | < 1 hour |
| ClickHouse | Partition backup to S3 | Daily | Per compliance | < 4 hours |
| MinIO (snapshots) | Cross-region replication | Continuous | Per policy | N/A (replicated) |
| Redis | RDB snapshots | Hourly | 24 hours | < 5 minutes |
| Kafka | Topic replication (built-in) | Continuous | Per topic config | N/A (replicated) |
| Node Agent config | Git repository | On change | Unlimited | < 15 minutes |
| TLS certificates | Vault backup | On change | Unlimited | < 30 minutes |
