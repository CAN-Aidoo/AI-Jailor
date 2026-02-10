# System Architecture — AI Jailer

## Architecture Overview

AI Jailer is structured as a modular system with six core subsystems, each responsible for a distinct concern. The subsystems communicate through well-defined internal APIs and a shared event bus.

```
                          ┌──────────────┐
                          │   Clients    │
                          │ SDK / CLI /  │
                          │  Dashboard   │
                          └──────┬───────┘
                                 │
                          ┌──────▼───────┐
                          │  API Gateway │
                          │  (FastAPI +  │
                          │   gRPC)      │
                          └──────┬───────┘
                                 │
                 ┌───────────────┼───────────────┐
                 │               │               │
          ┌──────▼──────┐ ┌─────▼──────┐ ┌──────▼──────┐
          │   Session   │ │  Execution │ │   Policy    │
          │   Manager   │ │   Engine   │ │   Engine    │
          └──────┬──────┘ └─────┬──────┘ └──────┬──────┘
                 │               │               │
          ┌──────▼───────────────▼───────────────▼──────┐
          │              MicroVM Engine                  │
          │         (Firecracker / Kata VMM)             │
          ├─────────┬─────────┬─────────┬───────────────┤
          │ Cell A  │ Cell B  │ Cell C  │  ...Cell N    │
          └─────────┴─────────┴─────────┴───────────────┘
                 │               │               │
          ┌──────▼──────┐ ┌─────▼──────┐ ┌──────▼──────┐
          │    State    │ │   Audit    │ │  Resource   │
          │    Store    │ │  Pipeline  │ │  Governor   │
          └─────────────┘ └────────────┘ └─────────────┘
```

## Subsystem Descriptions

### 1. API Gateway

**Responsibility**: All external communication. Authentication, rate limiting, request routing, protocol translation.

**Components**:

- **REST API Server** (FastAPI): Primary interface for cell management, execution, and queries. OpenAPI spec auto-generated.
- **gRPC Server**: High-performance interface for execution-heavy workloads and SDK communication.
- **WebSocket Server**: Real-time bidirectional communication for interactive terminal sessions and live log streaming.
- **Auth Middleware**: Validates API keys, JWT tokens, and mTLS certificates. Resolves tenant context.
- **Rate Limiter**: Per-tenant, per-endpoint rate limiting using Redis-backed sliding window algorithm.
- **Request Router**: Routes validated requests to the appropriate subsystem.

**Key Design Decisions**:

- FastAPI chosen for async performance, automatic OpenAPI docs, and Pydantic validation.
- gRPC added for SDK-to-server communication where type safety and performance matter.
- WebSocket kept separate from REST to allow independent scaling of interactive sessions.
- Auth is extracted as middleware, not embedded in handlers, to ensure consistent enforcement.

### 2. Session Manager

**Responsibility**: Cell lifecycle management, placement decisions, health monitoring.

**Components**:

- **Lifecycle Controller**: State machine managing cell transitions (creating → ready → running → paused → stopped → destroyed).
- **Placement Scheduler**: Decides which physical node hosts a new cell based on resource availability, affinity rules, and tenant isolation requirements.
- **Health Monitor**: Periodic health checks on all active cells. Detects hung, crashed, or zombie cells.
- **Warm Pool Manager**: Maintains a pool of pre-booted cells for sub-50ms startup times.
- **Session Registry**: In-memory (Redis-backed) registry of all active sessions with metadata.

**State Machine**:

```
                    ┌──────────┐
         ┌────────►│ Creating │
         │         └────┬─────┘
         │              │ image pulled, VM allocated
    API: create         ▼
         │         ┌──────────┐
         │         │  Ready   │
         │         └────┬─────┘
         │              │ API: start
         │              ▼
         │         ┌──────────┐ ◄────── API: resume
         │    ┌───►│ Running  │────┐
         │    │    └──┬───┬───┘    │
         │    │       │   │        │ API: pause
         │    │       │   │        ▼
         │    │       │   │   ┌──────────┐
         │    │       │   │   │  Paused  │
         │    │       │   │   └──────────┘
         │    │       │   │
         │    │       │   └──── API: stop
         │    │       │              │
         │    │       │              ▼
         │    │       │         ┌──────────┐
         │    │       │         │ Stopped  │
         │    │       │         └────┬─────┘
         │    │       │              │ API: destroy
         │    │       │              ▼
         │    │       │         ┌───────────┐
         │    │       └────────►│ Destroyed │
         │    │                 └───────────┘
         │    │
         │    └──── API: restart (stop + start)
         │
    (any state)──── API: destroy ────► Destroyed
```

**Placement Strategy**:

- **Bin Packing**: Default strategy. Pack cells densely on nodes to minimize infrastructure cost.
- **Spread**: For high-availability tenants. Distribute cells across nodes/racks/zones.
- **Dedicated**: For compliance tenants. Cells run on nodes reserved for a single tenant.
- **Affinity/Anti-Affinity**: Co-locate or separate specific cells based on labels.

### 3. Execution Engine

**Responsibility**: Running commands, scripts, and interactive sessions inside cells.

**Components**:

- **Command Executor**: Sends commands to a cell's agent process via vsock (VM socket). Captures stdout, stderr, exit code.
- **Script Runner**: Writes multi-line scripts to cell filesystem, then invokes the appropriate interpreter.
- **Terminal Proxy**: Bridges WebSocket connections from clients to PTY sessions inside cells.
- **File Transfer Agent**: Handles upload/download of files to/from cell filesystems via the vsock channel.
- **Timeout Enforcer**: Kills commands that exceed their specified timeout.

**Execution Flow**:

```
Client → API Gateway → Execution Engine → vsock → Cell Agent → Shell/Interpreter
                                                        │
                                          stdout/stderr ◄┘
                                                │
                              Audit Pipeline ◄───┘ (execution events)
```

**Cell Agent**: A lightweight process running inside each cell that:
- Listens on vsock for commands from the host.
- Executes commands in a controlled shell environment.
- Streams stdout/stderr back to the host.
- Reports file access events to the host.
- Manages environment variables and working directory.
- Handles graceful shutdown signals.

### 4. Policy Engine

**Responsibility**: Define, store, merge, and enforce security policies for cells.

**Components**:

- **Policy Store**: CRUD for security policy definitions. Stores policies as versioned, immutable documents.
- **Policy Compiler**: Merges multiple policies for a cell into a single effective policy. Resolves conflicts using most-restrictive-wins semantics.
- **Network Policy Enforcer**: Translates network policies into nftables rules applied to the cell's network namespace.
- **Syscall Policy Enforcer**: Translates syscall policies into seccomp-bpf profiles loaded into the microVM.
- **Filesystem Policy Enforcer**: Translates filesystem policies into mount options and overlay configurations.
- **Policy Validator**: Validates policy definitions against the schema and checks for logical contradictions.

**Policy Hierarchy**:

```
Platform Default Policy (most permissive baseline)
    └─► Tenant Default Policy (tenant-wide restrictions)
        └─► Cell Policy (cell-specific rules)
            └─► Effective Policy (compiled, most-restrictive-wins)
```

**Policy Hot-Update**: Certain policy types support modification on running cells:
- Network policies: Yes (nftables rules updated in-place).
- Resource limits: Yes (cgroup limits adjusted).
- Syscall policies: No (requires cell restart — seccomp is applied at process start).
- Filesystem policies: No (requires cell restart — mount configuration is set at boot).

### 5. State Store

**Responsibility**: Persistent storage for cell filesystems, snapshots, and metadata.

**Components**:

- **Persistent Volume Manager**: Manages block storage volumes that persist across cell restarts.
- **Snapshot Engine**: Creates, stores, and restores full VM snapshots (memory + disk).
- **Object Store Client**: Interface to MinIO/S3 for storing snapshots and exported data.
- **Metadata Store**: PostgreSQL-backed storage for cell metadata, policy definitions, tenant data.
- **Garbage Collector**: Removes expired snapshots and orphaned storage per retention policies.

**Storage Layers**:

| Layer | Technology | Contents | Lifecycle |
|---|---|---|---|
| Ephemeral | Cell's root filesystem (overlay) | Temporary files, package installs, runtime state | Destroyed with cell |
| Persistent | Block volume (ext4) | Agent workspaces, generated artifacts, databases | Survives cell restart |
| Snapshot | Object storage blob | Full VM state (memory + disk image) | Retention policy |
| Metadata | PostgreSQL row | Cell config, policies, tags, ownership | Survives cell destruction |

### 6. Audit Pipeline

**Responsibility**: Capture, transport, store, and query audit events from all cells and system components.

**Components**:

- **Event Collector**: Receives events from cell agents, policy enforcers, and system components via structured logging.
- **Event Bus**: Kafka topic per event category for durable, ordered event transport.
- **Event Processor**: Enriches events with tenant context, cell metadata, and derived fields.
- **Audit Store**: ClickHouse for high-throughput analytical queries over audit data.
- **Query API**: Search and filter audit logs by any dimension.
- **Export Service**: Generate compliance reports and export logs to external SIEMs.
- **Integrity Verifier**: Cryptographic hash chain over audit entries to detect tampering.

**Event Flow**:

```
Cell Agent ──────┐
Policy Enforcer ─┼──► Event Collector ──► Kafka ──► Event Processor ──► ClickHouse
API Gateway ─────┤                                        │
Session Manager ─┘                                        ▼
                                                   Integrity Chain
                                                   (append-only log)
```

### 7. Resource Governor

**Responsibility**: Enforce resource limits, meter usage, manage cost controls.

**Components**:

- **Quota Enforcer**: Sets and enforces cgroup limits on microVMs (CPU, memory, disk I/O, network bandwidth).
- **Usage Meter**: Collects real-time resource consumption data from cells via cgroup stats.
- **Cost Calculator**: Converts raw resource consumption into billable units using the tenant's pricing plan.
- **Alert Manager**: Fires alerts when usage approaches limits or spending thresholds.
- **Spending Cap Enforcer**: Hard-stops cells when a tenant's spending cap is reached.
- **Metrics Exporter**: Exports usage data to TimescaleDB and Prometheus.

## Cross-Cutting Concerns

### Authentication & Authorization

**Auth Flow**:

```
Request → API Key/JWT validation → Tenant resolution → RBAC check → Handler
```

**Roles**:
- **Owner**: Full access to tenant's cells, policies, logs, settings, billing.
- **Admin**: Manage cells, policies, logs. Cannot modify billing or delete tenant.
- **Operator**: Create/start/stop cells, execute commands. Cannot modify policies.
- **Viewer**: Read-only access to cell status, logs, metrics.
- **Auditor**: Read-only access to audit logs and compliance reports. No cell management.

### Observability

- **Metrics**: Prometheus-format metrics from all components. Grafana dashboards.
- **Tracing**: OpenTelemetry distributed traces. Every request gets a trace ID that follows through all subsystems.
- **Logging**: Structured JSON logs from all components. Shipped to centralized logging.
- **Alerting**: PagerDuty/OpsGenie integration for infrastructure alerts. Tenant-facing alerts via webhooks.

### Error Handling Strategy

- **Cell crashes**: Detected by Health Monitor. Cell state set to "stopped". Audit event logged. Tenant notified via webhook.
- **Node failures**: All cells on the node are marked as lost. If snapshot exists, cells can be restored on a healthy node.
- **Audit pipeline lag**: Cells continue running. Events buffered on the node's local disk. Catch-up processing when pipeline recovers.
- **Database unavailability**: API returns 503 for state-dependent operations. Running cells continue unaffected.
- **Storage failures**: Cell creation blocked if persistent storage is unavailable. Running cells with ephemeral storage continue.

## Deployment Topology

```
┌────────────────────────────────────────────────┐
│                Control Plane                    │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐ │
│  │ API GW   │ │ Session  │ │  Policy Engine │ │
│  │ (3 pods) │ │ Manager  │ │  (2 pods)      │ │
│  │          │ │ (3 pods) │ │                │ │
│  └──────────┘ └──────────┘ └────────────────┘ │
│  ┌──────────┐ ┌──────────┐ ┌────────────────┐ │
│  │ Audit    │ │ Resource │ │  State Store   │ │
│  │ Pipeline │ │ Governor │ │  (2 pods)      │ │
│  │ (3 pods) │ │ (2 pods) │ │                │ │
│  └──────────┘ └──────────┘ └────────────────┘ │
├────────────────────────────────────────────────┤
│                 Data Plane                      │
│  ┌────────────────────────────────────────────┐│
│  │ Cell Node 1     Cell Node 2    Cell Node N ││
│  │ ┌──┐┌──┐┌──┐  ┌──┐┌──┐┌──┐  ┌──┐┌──┐    ││
│  │ │VM││VM││VM│  │VM││VM││VM│  │VM││VM│    ││
│  │ └──┘└──┘└──┘  └──┘└──┘└──┘  └──┘└──┘    ││
│  └────────────────────────────────────────────┘│
├────────────────────────────────────────────────┤
│              Shared Services                    │
│  PostgreSQL  Redis  Kafka  ClickHouse  MinIO   │
│  TimescaleDB                                    │
└────────────────────────────────────────────────┘
```

**Control Plane**: Stateless services deployed in Kubernetes. Horizontally scalable.

**Data Plane**: Bare-metal or VM nodes running the Firecracker VMM. Each node runs a local agent that communicates with the Session Manager. Not in Kubernetes (microVMs manage their own isolation).

**Shared Services**: Managed databases and message queues. Can be self-hosted or cloud-managed depending on deployment model.
