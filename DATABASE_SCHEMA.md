# Database Schema — AI Jailer

## Database Architecture

AI Jailer uses multiple database technologies, each chosen for its specific strengths:

| Database | Purpose | Data |
|---|---|---|
| **PostgreSQL** | Relational metadata | Tenants, cells, policies, snapshots, API keys |
| **Redis** | Session state, caching | Active cell registry, rate limiting, warm pool |
| **ClickHouse** | Audit log analytics | All audit events, query and compliance reporting |
| **TimescaleDB** | Time-series metrics | Resource usage metering, billing data |

## PostgreSQL Schema

### Tenants

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(63) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'deactivated')),
    tier VARCHAR(20) NOT NULL DEFAULT 'starter'
        CHECK (tier IN ('free', 'starter', 'pro', 'enterprise')),

    -- Limits
    max_concurrent_cells INTEGER NOT NULL DEFAULT 10,
    max_persistent_storage_gb INTEGER NOT NULL DEFAULT 50,
    max_snapshot_count INTEGER NOT NULL DEFAULT 100,
    max_snapshots_per_cell INTEGER NOT NULL DEFAULT 10,
    max_snapshot_storage_per_cell_gb INTEGER NOT NULL DEFAULT 10,
    max_snapshot_storage_gb INTEGER NOT NULL DEFAULT 50,  -- total snapshot bytes
    spending_cap_cents INTEGER,  -- NULL = no cap

    -- Settings
    default_security_policy_id UUID REFERENCES security_policies(id),
    webhook_secret VARCHAR(255),

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_status ON tenants(status);
```

### Users

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'operator'
        CHECK (role IN ('owner', 'admin', 'operator', 'viewer', 'auditor')),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'deactivated')),
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_email ON users(email);
```

### API Keys

```sql
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    created_by UUID NOT NULL REFERENCES users(id),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,  -- SHA-256 hash of the key
    key_prefix VARCHAR(12) NOT NULL,        -- "aj_live_xxxx" for identification
    role VARCHAR(20) NOT NULL DEFAULT 'operator'
        CHECK (role IN ('owner', 'admin', 'operator', 'viewer', 'auditor')),
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Rate limit overrides
    rate_limit_per_minute INTEGER
);

CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_prefix ON api_keys(key_prefix);
```

### Cells

```sql
CREATE TABLE cells (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255),
    status VARCHAR(20) NOT NULL DEFAULT 'creating'
        CHECK (status IN (
            'creating', 'ready', 'running', 'paused',
            'stopping', 'stopped', 'destroying', 'destroyed', 'error'
        )),
    error_message TEXT,

    -- Configuration
    image VARCHAR(255) NOT NULL,
    custom_image_id UUID REFERENCES custom_images(id),

    -- Resources
    vcpus INTEGER NOT NULL DEFAULT 1,
    memory_mb INTEGER NOT NULL DEFAULT 512,
    disk_mb INTEGER NOT NULL DEFAULT 2048,
    network_bandwidth_mbps INTEGER NOT NULL DEFAULT 100,

    -- Security
    security_policy_id UUID NOT NULL REFERENCES security_policies(id),
    effective_policy JSONB,  -- Compiled effective policy snapshot

    -- Networking
    node_id UUID REFERENCES nodes(id),
    internal_ip INET,

    -- Environment
    environment JSONB DEFAULT '{}',
    working_directory VARCHAR(1024) DEFAULT '/home/agent',

    -- Persistent volume
    persistent_volume_id UUID REFERENCES persistent_volumes(id),

    -- Tags
    tags JSONB DEFAULT '{}',

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at TIMESTAMPTZ,
    paused_at TIMESTAMPTZ,
    stopped_at TIMESTAMPTZ,
    destroyed_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cells_tenant ON cells(tenant_id);
CREATE INDEX idx_cells_status ON cells(tenant_id, status);
CREATE INDEX idx_cells_node ON cells(node_id);
CREATE INDEX idx_cells_tags ON cells USING GIN(tags);
CREATE INDEX idx_cells_created ON cells(tenant_id, created_at DESC);
```

### Security Policies

```sql
CREATE TABLE security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id),  -- NULL = platform-level policy
    name VARCHAR(255) NOT NULL,
    description TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'deprecated', 'archived')),

    -- Policy definitions (each is a JSONB document)
    network_policy JSONB NOT NULL DEFAULT '{"default": "deny"}',
    filesystem_policy JSONB NOT NULL DEFAULT '{}',
    syscall_policy JSONB NOT NULL DEFAULT '{}',
    resource_policy JSONB NOT NULL DEFAULT '{}',
    capability_policy JSONB NOT NULL DEFAULT '{}',

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

CREATE INDEX idx_policies_tenant ON security_policies(tenant_id);
CREATE INDEX idx_policies_status ON security_policies(tenant_id, status);
CREATE UNIQUE INDEX idx_policies_name_version
    ON security_policies(tenant_id, name, version);
```

### Snapshots

```sql
CREATE TABLE snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    cell_id UUID NOT NULL REFERENCES cells(id),
    name VARCHAR(255),
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'creating'
        CHECK (status IN ('creating', 'available', 'restoring', 'failed', 'expired')),
    error_message TEXT,

    -- Storage references
    memory_snapshot_key VARCHAR(1024),     -- Object storage key for memory dump
    disk_snapshot_key VARCHAR(1024),       -- Object storage key for disk image
    persistent_volume_snapshot_key VARCHAR(1024),

    -- Size tracking
    memory_size_bytes BIGINT,
    disk_size_bytes BIGINT,
    total_size_bytes BIGINT,

    -- Cell configuration at time of snapshot (for restore)
    cell_config JSONB NOT NULL,  -- Full cell configuration for recreation

    -- Retention
    retention_policy VARCHAR(20) DEFAULT 'standard'
        CHECK (retention_policy IN ('standard', 'extended', 'permanent')),
    expires_at TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_snapshots_cell ON snapshots(cell_id);
CREATE INDEX idx_snapshots_tenant ON snapshots(tenant_id);
CREATE INDEX idx_snapshots_status ON snapshots(status);
CREATE INDEX idx_snapshots_expires ON snapshots(expires_at)
    WHERE expires_at IS NOT NULL;
```

### Persistent Volumes

```sql
CREATE TABLE persistent_volumes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    cell_id UUID REFERENCES cells(id),
    status VARCHAR(20) NOT NULL DEFAULT 'creating'
        CHECK (status IN ('creating', 'available', 'attached', 'detaching', 'destroyed')),

    -- Storage
    size_mb INTEGER NOT NULL,
    used_mb INTEGER DEFAULT 0,
    node_id UUID REFERENCES nodes(id),
    host_path VARCHAR(1024),

    -- Encryption
    encrypted BOOLEAN NOT NULL DEFAULT true,
    encryption_key_id VARCHAR(255),

    -- Metadata
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_volumes_tenant ON persistent_volumes(tenant_id);
CREATE INDEX idx_volumes_cell ON persistent_volumes(cell_id);
```

### Nodes

```sql
CREATE TABLE nodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'draining', 'maintenance', 'offline', 'quarantined')),

    -- Capacity
    total_vcpus INTEGER NOT NULL,
    total_memory_mb INTEGER NOT NULL,
    total_disk_mb INTEGER NOT NULL,
    available_vcpus INTEGER NOT NULL,
    available_memory_mb INTEGER NOT NULL,
    available_disk_mb INTEGER NOT NULL,
    max_cells INTEGER NOT NULL,
    running_cells INTEGER NOT NULL DEFAULT 0,

    -- Network
    internal_ip INET NOT NULL,
    cell_subnet CIDR NOT NULL,

    -- Metadata
    region VARCHAR(50),
    zone VARCHAR(50),
    labels JSONB DEFAULT '{}',

    -- Health
    last_heartbeat_at TIMESTAMPTZ,
    agent_version VARCHAR(50),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_nodes_status ON nodes(status);
CREATE INDEX idx_nodes_region ON nodes(region, zone);
CREATE INDEX idx_nodes_capacity ON nodes(available_vcpus, available_memory_mb)
    WHERE status = 'active';
```

### Custom Images

```sql
CREATE TABLE custom_images (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name VARCHAR(255) NOT NULL,
    tag VARCHAR(128) NOT NULL DEFAULT 'latest',
    status VARCHAR(20) NOT NULL DEFAULT 'building'
        CHECK (status IN ('building', 'scanning', 'available', 'failed', 'deprecated')),
    base_image VARCHAR(255) NOT NULL,

    -- Build
    build_spec JSONB NOT NULL,  -- Dockerfile-like specification
    build_log TEXT,

    -- Storage
    image_key VARCHAR(1024),  -- Object storage key
    image_size_bytes BIGINT,

    -- Security
    vulnerability_scan JSONB,
    scan_passed BOOLEAN,
    signed BOOLEAN DEFAULT false,
    signature VARCHAR(512),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(tenant_id, name, tag)
);

CREATE INDEX idx_images_tenant ON custom_images(tenant_id);
CREATE INDEX idx_images_status ON custom_images(status);
```

### Webhooks

```sql
CREATE TABLE webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    url VARCHAR(2048) NOT NULL,
    secret_hash VARCHAR(64) NOT NULL,
    events TEXT[] NOT NULL,  -- Array of event types
    status VARCHAR(20) NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'paused', 'disabled')),

    -- Delivery tracking
    last_delivery_at TIMESTAMPTZ,
    last_delivery_status INTEGER,  -- HTTP status code
    consecutive_failures INTEGER DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_webhooks_tenant ON webhooks(tenant_id);
CREATE INDEX idx_webhooks_status ON webhooks(tenant_id, status);
```

### Executions

```sql
CREATE TABLE executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cell_id UUID NOT NULL REFERENCES cells(id),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    status VARCHAR(20) NOT NULL DEFAULT 'running'
        CHECK (status IN ('running', 'completed', 'failed', 'timeout', 'cancelled')),

    -- Execution details
    command TEXT NOT NULL,
    interpreter VARCHAR(255),
    working_directory VARCHAR(1024),
    user_context VARCHAR(63) DEFAULT 'agent',
    environment JSONB DEFAULT '{}',  -- variable NAMES only; every value is stored as "[redacted]"

    -- Results
    exit_code INTEGER,
    stdout TEXT,
    stderr TEXT,

    -- Resource usage
    cpu_ms BIGINT,
    memory_peak_mb INTEGER,

    -- Timing
    timeout_seconds INTEGER,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    duration_ms INTEGER,

    -- API context
    api_key_id UUID REFERENCES api_keys(id),
    request_id VARCHAR(64)
);

CREATE INDEX idx_executions_cell ON executions(cell_id);
CREATE INDEX idx_executions_tenant ON executions(tenant_id, started_at DESC);
CREATE INDEX idx_executions_status ON executions(cell_id, status);
```

## ClickHouse Schema (Audit Events)

```sql
CREATE TABLE audit_events (
    event_id UUID,
    tenant_id UUID,
    cell_id UUID,
    event_type Enum8(
        'execution' = 1,
        'file_access' = 2,
        'network' = 3,
        'lifecycle' = 4,
        'policy_violation' = 5,
        'api_call' = 6,
        'resource_alert' = 7
    ),
    severity Enum8('info' = 1, 'warning' = 2, 'critical' = 3),
    timestamp DateTime64(3),
    details String,              -- JSON string with event-specific details
    source_ip IPv4,
    api_key_id Nullable(UUID),
    request_id Nullable(String),

    -- Hash chain for tamper evidence
    previous_hash String,
    event_hash String
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, cell_id, timestamp)
TTL timestamp + INTERVAL 365 DAY;

-- Materialized view for policy violation counts
CREATE MATERIALIZED VIEW policy_violations_hourly
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, cell_id, hour, violation_type)
AS SELECT
    tenant_id,
    cell_id,
    toStartOfHour(timestamp) AS hour,
    JSONExtractString(details, 'violation_type') AS violation_type,
    count() AS violation_count
FROM audit_events
WHERE event_type = 'policy_violation'
GROUP BY tenant_id, cell_id, hour, violation_type;
```

## TimescaleDB Schema (Metering)

```sql
CREATE TABLE resource_usage (
    time TIMESTAMPTZ NOT NULL,
    tenant_id UUID NOT NULL,
    cell_id UUID NOT NULL,
    cpu_cores_used DOUBLE PRECISION,
    memory_mb_used DOUBLE PRECISION,
    disk_read_bytes BIGINT,
    disk_write_bytes BIGINT,
    network_rx_bytes BIGINT,
    network_tx_bytes BIGINT,
    active_processes INTEGER
);

SELECT create_hypertable('resource_usage', 'time');

CREATE INDEX idx_usage_tenant ON resource_usage(tenant_id, time DESC);
CREATE INDEX idx_usage_cell ON resource_usage(cell_id, time DESC);

-- Continuous aggregate for hourly billing
CREATE MATERIALIZED VIEW usage_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS hour,
    tenant_id,
    cell_id,
    AVG(cpu_cores_used) * 3600 AS cpu_core_seconds,
    AVG(memory_mb_used) / 1024 * 3600 AS memory_gb_seconds,
    SUM(network_tx_bytes) / (1024*1024*1024.0) AS network_egress_gb
FROM resource_usage
GROUP BY hour, tenant_id, cell_id;
```

## Redis Data Structures

### Active Cell Registry

```
Key: cell:{cell_id}
Type: Hash
Fields:
  tenant_id: UUID
  status: running|paused|etc
  node_id: UUID
  internal_ip: IP address
  created_at: ISO timestamp
  vcpus: integer
  memory_mb: integer
TTL: None (removed on cell destruction)
```

### Rate Limiting

```
Key: ratelimit:{tenant_id}:{endpoint}:{window}
Type: Sorted Set (sliding window)
Members: request timestamps
TTL: Window duration + buffer
```

### Warm Pool

```
Key: warmpool:{image_name}
Type: List
Members: cell_id values of pre-booted cells
```

### Session Locks

```
Key: lock:cell:{cell_id}
Type: String (Redlock pattern)
Value: Lock holder ID
TTL: 30 seconds (auto-renewed)
```

## Data Retention Policies

| Data Type | Default Retention | Enterprise Retention |
|---|---|---|
| Cell metadata (destroyed) | 90 days | 2 years |
| Executions | 30 days | 1 year |
| Audit events | 1 year | 7 years (compliance) |
| Resource usage (raw) | 7 days | 90 days |
| Resource usage (hourly) | 1 year | 7 years |
| Snapshots | Per policy (30 days default) | Configurable |
| Webhook delivery logs | 7 days | 30 days |

## Migration Strategy

All schema changes managed via Alembic (SQLAlchemy migrations):

- Migrations are forward-only (no rollback scripts — always write compensating migrations).
- Every migration is tested against a production-like dataset before deployment.
- Zero-downtime migrations only (no table locks on large tables).
- New columns added as nullable first, backfilled, then made non-nullable.

### audit_events / audit_checkpoints (migration 007)

`audit_events(id, tenant_id, cell_id, seq, event_type, severity, timestamp, details, source_ip, api_key_id, request_id,
previous_hash, event_hash)` with `UNIQUE (tenant_id, cell_id, seq)`; `audit_checkpoints(id, tenant_id, cell_id, length, head,
key_id, envelope, created_at)`. Append-only (PostgreSQL triggers reject UPDATE/DELETE). See AUDIT_SYSTEM.md.


### peer_links (migration 008)

One row per consented cell-to-cell link: `id`, `initiator_tenant_id`/`initiator_cell_id`,
`responder_tenant_id`/`responder_cell_id`, `status` (`pending`|`active`|`revoked`, check-constrained),
`purpose` (<= 64), `created_at`, `accepted_at`, `expires_at`, `revoked_at`, `revoked_by_tenant_id`.
Check: initiator and responder cells differ. Indexes on both tenants and both cells. Expiry is evaluated
at read time and at every relay attach; there is no cleanup dependency. See PEER_LINKS.md.

### executions.environment redaction (migration 009)

Data-only, no schema change. Rewrites every existing `executions.environment` to the variable names with each
value replaced by `[redacted]`, matching what the service now stores. Rows that are empty, NULL, not a JSON
object, or already redacted are skipped, so it can run twice. It works in batches of 1000 by primary key and
uses plain SELECT/UPDATE (no Postgres-only SQL), one UPDATE per row that needs it.

- **Irreversible.** The old values are overwritten and `downgrade` is a no-op. Back up first if you need them.
- **It does not purge copies.** Backups, replicas and WAL made before the upgrade still hold the old values, as
  do `Cell.environment` (a separate store, unchanged) and the command text and output of past runs.
- The values may already have been exposed to whoever could read the table; if they were real credentials,
  rotating them is the actual fix. Running the migration only stops the table holding them from now on.

### Private set intersection (no schema)

The reference PSI workload (`examples/psi/`, see PEER_LINKS.md) adds **no tables, columns or migrations**
and the platform stores none of its data. Items, blinded values and the computed intersection exist only in
the memory of the two cells; the relay carries them inside TLS it cannot read, and nothing is persisted.

What the platform database does hold when PSI runs is the ordinary peer-link record, and nothing PSI-specific:
- the `peer_links` row above (which two cells, which tenants, `purpose`, lifetime, status);
- hash-chained `audit_events` on both tenants' chains: the link lifecycle (`peer_link_proposed`,
  `peer_link_requested`, `peer_link_accepted`, `peer_link_revoked`) and one `network` event per relay session
  with `decision`, `reason`, `role`, `peer_link`, `session_id` and the bytes moved in each direction.

Byte counts are the one thing that reveals anything about the exchange: the PSI frames are about 256 bytes
per element (`API_DOCUMENTATION.md` has the layout), so anyone who can read the audit log can roughly estimate
how many items each side submitted (from the bytes in each direction, plus a small fixed TLS overhead). The
two parties already learn each other's set sizes in the protocol; the point is that the operator and
auditors can too. Pad the sets with dummy items if that matters for your use.
