# Audit System — AI Jailer

## Purpose

The audit system is AI Jailer's compliance backbone. It captures, transports, stores, and queries a tamper-evident record of every action taken inside every cell and every API call made against the platform. This system is what makes the difference between "we think it's secure" and "we can prove it's secure."

## Event Taxonomy

### Event Types

#### 1. Execution Events

Captured when commands or scripts are executed inside a cell.

```json
{
  "event_type": "execution",
  "severity": "info",
  "details": {
    "execution_id": "exec_789xyz",
    "command": "pip install requests",
    "interpreter": "/usr/bin/bash",
    "user": "agent",
    "working_directory": "/data/project",
    "exit_code": 0,
    "duration_ms": 3400,
    "cpu_ms": 2100,
    "memory_peak_mb": 128
  }
}
```

#### 2. File Access Events

Captured when files are read, written, created, or deleted inside a cell.

```json
{
  "event_type": "file_access",
  "severity": "info",
  "details": {
    "operation": "write",
    "path": "/data/project/main.py",
    "size_bytes": 2048,
    "permissions": "0644",
    "process": "python3",
    "pid": 42
  }
}
```

#### 3. Network Events

Captured for every network connection attempt (allowed and denied).

```json
{
  "event_type": "network",
  "severity": "warning",
  "details": {
    "action": "blocked",
    "direction": "egress",
    "protocol": "tcp",
    "destination_ip": "203.0.113.50",
    "destination_domain": "evil-server.com",
    "destination_port": 443,
    "source_port": 49152,
    "bytes_sent": 0,
    "bytes_received": 0,
    "reason": "domain_not_in_allowlist"
  }
}
```

#### 4. Lifecycle Events

Captured for cell state transitions.

```json
{
  "event_type": "lifecycle",
  "severity": "info",
  "details": {
    "action": "started",
    "previous_status": "ready",
    "new_status": "running",
    "trigger": "api_call",
    "api_key_id": "key_abc123",
    "boot_time_ms": 125
  }
}
```

#### 5. Policy Violation Events

Captured when a security policy blocks an action.

```json
{
  "event_type": "policy_violation",
  "severity": "critical",
  "details": {
    "violation_type": "syscall_blocked",
    "syscall": "ptrace",
    "process": "suspicious_binary",
    "pid": 87,
    "policy_id": "pol_restrictive",
    "action_taken": "blocked"
  }
}
```

#### 6. API Call Events

Captured for every API call made against the platform.

```json
{
  "event_type": "api_call",
  "severity": "info",
  "details": {
    "method": "POST",
    "endpoint": "/v1/cells/cell_abc/exec",
    "status_code": 200,
    "response_time_ms": 342,
    "api_key_id": "key_abc123",
    "ip_address": "198.51.100.10",
    "user_agent": "aijailer-python-sdk/1.0.0"
  }
}
```

#### 7. Resource Alert Events

Captured when resource usage exceeds thresholds.

```json
{
  "event_type": "resource_alert",
  "severity": "warning",
  "details": {
    "resource": "memory",
    "current_value_mb": 920,
    "limit_mb": 1024,
    "percentage": 89.8,
    "threshold": 80,
    "alert_type": "threshold_exceeded"
  }
}
```

## Event Collection Architecture

### Collection Points

```
┌─────────────────────────────────────────────────────┐
│                     Cell (Guest)                     │
│  ┌───────────────────────────────────────────┐      │
│  │  Cell Agent                                │      │
│  │  ├── Execution monitor (captures commands) │      │
│  │  ├── File watcher (inotify-based)         │      │
│  │  └── Process monitor (captures fork/exec)  │      │
│  └──────────────────┬────────────────────────┘      │
│                     │ vsock                          │
└─────────────────────┼───────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────┐
│                   Host (Node Agent)                  │
│  ┌──────────────────────────────────────────┐       │
│  │  Network monitor (nftables log)           │       │
│  │  Resource monitor (cgroup stats)          │       │
│  │  Hypervisor event monitor                 │       │
│  └──────────────────┬───────────────────────┘       │
│                     │                                │
│  ┌──────────────────▼───────────────────────┐       │
│  │  Local Event Buffer                       │       │
│  │  (Disk-backed queue, survives restarts)   │       │
│  └──────────────────┬───────────────────────┘       │
└─────────────────────┼───────────────────────────────┘
                      │ TCP/TLS
                      ▼
              ┌───────────────┐
              │  Kafka Cluster │
              └───────┬───────┘
                      │
              ┌───────▼───────┐
              │ Event Processor│
              │  (enrich,     │
              │   hash chain, │
              │   route)      │
              └───────┬───────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
    ┌──────────┐ ┌─────────┐ ┌─────────┐
    │ClickHouse│ │ Webhook │ │  SIEM   │
    │ (store)  │ │ Dispatch│ │ Forward │
    └──────────┘ └─────────┘ └─────────┘
```

### Event Flow Details

1. **Capture**: Events generated at the source (Cell Agent, nftables, cgroup monitor, API gateway).
2. **Buffer**: Events written to local disk-backed buffer on the node. This ensures no event loss if Kafka is temporarily unavailable.
3. **Transport**: Events published to Kafka topics, partitioned by tenant_id for ordering guarantees.
4. **Process**: Event Processor consumes from Kafka, enriches events with metadata (tenant name, cell name, policy details), computes hash chain, and routes to destinations.
5. **Store**: Events written to ClickHouse for long-term storage and analytical queries.
6. **Notify**: Policy violation and alert events trigger webhook dispatch.
7. **Forward**: Events optionally forwarded to external SIEMs (Splunk, Datadog, Elastic).

### Kafka Topic Design

| Topic | Partition Key | Contents |
|---|---|---|
| `events.raw` | tenant_id | All raw events from nodes |
| `events.processed` | tenant_id | Enriched events |
| `events.violations` | tenant_id | Policy violations (high priority) |
| `events.alerts` | tenant_id | Resource alerts |
| `webhooks.dispatch` | webhook_id | Webhook delivery queue |

## Tamper Evidence

### Hash Chain

Every audit event is linked to its predecessor via a cryptographic hash chain, making it impossible to delete or modify events without detection.

**Chain Structure**:

```
Event N:
  event_hash = SHA-256(event_id + tenant_id + cell_id + event_type +
                       timestamp + details_json + previous_hash)
  previous_hash = Event N-1's event_hash

Event N+1:
  previous_hash = Event N's event_hash
  event_hash = SHA-256(...)
```

**Chain Scoping**: One chain per (tenant_id, cell_id) pair. This allows parallel chain computation across cells while maintaining per-cell integrity.

**Chain Verification**: An integrity verification job runs hourly, walking the hash chain for each active cell and reporting any gaps or mismatches. Results logged and alerted.

### Append-Only Storage

- ClickHouse configured with `readonly` mode for the audit event tables via access control.
- No UPDATE or DELETE operations permitted on audit tables.
- Retention is handled by TTL-based partition drops (entire time partitions, not individual rows).

## Query API

### Full-Text Search

The audit query API supports searching across event details:

```
GET /v1/audit/events?q=ptrace&cell_id=cell_abc&start_time=2025-01-01T00:00:00Z&end_time=2025-01-31T23:59:59Z
```

### Aggregation Queries

```
GET /v1/audit/summary?cell_id=cell_abc&start_time=...&end_time=...&group_by=event_type
```

Response:

```json
{
  "data": {
    "groups": [
      { "event_type": "execution", "count": 1234 },
      { "event_type": "file_access", "count": 5678 },
      { "event_type": "network", "count": 890 },
      { "event_type": "policy_violation", "count": 3 }
    ]
  }
}
```

### Timeline View

```
GET /v1/audit/timeline?cell_id=cell_abc&start_time=...&end_time=...&interval=1m
```

Returns event counts bucketed by time interval for visualization.

## Compliance Reporting

### Pre-Built Reports

| Report | Description | Format |
|---|---|---|
| Cell Activity Report | All events for a specific cell in a time range | PDF, JSON, CSV |
| Security Violations Report | All policy violations with details and context | PDF, JSON |
| Access Audit Report | All API calls and authentication events | PDF, JSON, CSV |
| Resource Consumption Report | Detailed resource usage per cell/tenant | PDF, JSON, CSV |
| Data Access Report | All file access events showing what data was touched | PDF, JSON, CSV |

### SIEM Integration

Events can be forwarded in real-time to external SIEM systems:

**Supported Formats**:
- Splunk HEC (HTTP Event Collector)
- Datadog Logs API
- Elastic Common Schema (ECS)
- Generic webhook (JSON)
- Syslog (RFC 5424)

**Configuration**:

```json
{
  "siem_integration": {
    "type": "splunk_hec",
    "endpoint": "https://splunk.company.com:8088/services/collector",
    "token": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "index": "aijailer_audit",
    "events": ["policy_violation", "network", "execution"],
    "min_severity": "warning"
  }
}
```

## Secret Redaction

The audit pipeline automatically redacts sensitive values from event details before storage:

**Patterns Detected and Redacted**:
- API keys (matching patterns: `sk-*`, `pk-*`, `aj_*`, Bearer tokens)
- AWS credentials (matching `AKIA*`, `aws_secret_access_key`)
- Private keys (matching `-----BEGIN * PRIVATE KEY-----`)
- Connection strings (password components)
- JWT tokens (matching `eyJ*`)
- Custom patterns (configurable per tenant)

**Redaction Format**: Sensitive values replaced with `[REDACTED:type]` (e.g., `[REDACTED:api_key]`).

**Original values are never stored.** Redaction happens in the Event Processor before events reach ClickHouse.

## Resilience

### Guaranteed Delivery

- Events buffered on node local disk before Kafka publish.
- Kafka configured with `acks=all` and replication factor 3.
- Event Processor uses consumer group with manual offset commits (no at-most-once).
- ClickHouse writes use async insert with retry on failure.

### Degraded Mode

If the Kafka cluster is unavailable:
1. Events continue to be captured and buffered on node local disk.
2. Cells continue to run normally (audit is observability, not enforcement).
3. Buffer capacity: 24 hours of events per node at maximum throughput.
4. When Kafka recovers, buffered events are published in order.
5. Alert triggered after 5 minutes of Kafka unavailability.

### No Event Gaps

The hash chain verification process detects any gaps in the event stream. If a gap is detected:
1. Alert raised to operations.
2. Gap metadata recorded (which events are missing, time range).
3. Recovery attempted from node-local buffers if available.
4. Compliance reports for the affected time range flagged with a gap warning.

## Current implementation: database-backed log (what actually runs today)

The Kafka -> ClickHouse pipeline above is the target architecture. Today the audit log is written **directly to the
application database** by `AuditService` (`services/audit_service.py`) through a pluggable store
(`services/audit_store.py`):

| `AUDIT_BACKEND` | Behaviour |
|---|---|
| `auto` (default) | `memory` when `AIJAILER_ENV=dev`, otherwise `db` |
| `db` | `audit_events` + `audit_checkpoints` tables (migration `007_audit_log`) |
| `memory` | volatile; history is lost on restart (a warning is logged outside dev; `durable: false` in API responses) |

**Chains.** One hash chain per (tenant, cell); non-cell events (secrets, quota changes) use the nil cell id. Each event
hashes every field plus its predecessor's hash, and has a per-chain `seq`. `UNIQUE (tenant_id, cell_id, seq)` is the write
lock: two writers extending the same head cannot both succeed, the loser re-reads the head and retries (so concurrent
writers never fork or lose a chain). Each append is its own short transaction on its own session, so an audit record
survives a request that later rolls back, and never depends on one. A failed append raises: the operation that needed
the record is not silently unaudited.

**Append-only.** On PostgreSQL the migration installs `BEFORE UPDATE OR DELETE` triggers that reject any change to
`audit_events` and `audit_checkpoints`, even from the application role. Retention or erasure therefore needs a deliberate
privileged procedure (disable the trigger, re-anchor the chain, record that you did). *Not exercised by the test suite*
(SQLite has no such triggers); verify on your Postgres.

**Checkpoints.** A bare hash chain cannot see tail truncation or a consistent rebuild of the whole chain. A background task
(`AUDIT_CHECKPOINT_INTERVAL_SECONDS`, default 300, plus a final pass on clean shutdown) signs (head hash, length) with
Ed25519 (DSSE/in-toto) for every chain that grew and stores it. `verify` checks every link, every hash, and that each
checkpoint's head is still at its position. Deleting head or middle rows, editing any field, truncating after a checkpoint
and rebuilding consistently are all detected (tests); events written after the last checkpoint can still be truncated
undetected, bounded by the interval.

**Signing key.** `AUDIT_SIGNING_SECRET` derives the key (HKDF). It is **required** with the database backend outside dev:
an ephemeral key would orphan every earlier checkpoint on restart and silently disable truncation detection (startup
fails instead). Checkpoints signed by a different key (after rotating the secret) are reported as
`checkpoints_unverifiable`, not trusted and not counted as tampering; anyone who holds the signing secret AND database
write access can forge history, so keep the secret out of the database's reach (secret manager / KMS).

**Limits.** Verification streams a chain in pages of 5000 but is O(chain length). Per-event writes are the default for
anything that must survive a crash; see group commit below for high-volume events.

### Durability levels and group commit

Three ways to record an event, chosen by the caller (strongest last in the table's reading order of guarantees):

| | `submit_event(...)` | `record_event(...)` (default) | `record_event(..., session=db)` |
|---|---|---|---|
| Returns | immediately (sync, no await); `False` if dropped | after its own commit; the stored event | after the insert in the caller's transaction |
| Durable | **no** (lost on a crash, batched) | yes, on its own | exactly when the caller commits |
| Atomic with the change it describes | no | **no**: a later rollback leaves the event, a failed audit write after the change leaves it unaudited | **yes**: both commit or both roll back |
| Use for | per-request network decisions (the proxy sink) | lifecycle, secrets: anything that must survive a crash | changes whose record must never disagree with reality: **tenant quota overrides** |

Transactional mode (`session=`): the event is inserted inside a SAVEPOINT in the caller's transaction, so losing the
(tenant, cell, seq) race to another writer retries only that insert and keeps the caller's other work. The caller must
commit before reporting success (the admin routes do, so a `200` means durable). Only the database backend can do this;
the memory backend accepts the argument and ignores it. A caller that holds a row lock (the quota change holds the tenant
row) holds it until commit, which is the intended serialisation. Not exercised against PostgreSQL by the test suite.

Concurrency is tested by invariants, not timing (`tests/api/test_quota_concurrency.py`): 40 random concurrent PATCH/DELETEs
must replay, in audit order from the defaults, to exactly the stored limits with every event's `from` equal to the state at
that point (no lost update, no change based on a stale read, no unrecorded change); 30 writers to one field leave a single
linear chain of values; quota events and other writers on the same chain lose nothing and leave `seq` gap-free; and while an
operator lowers a limit, parallel snapshot creations never exceed the limit in force and leave no dangling reservation.
SQLite has no row locks, so those tests run every transaction as `BEGIN IMMEDIATE` (a coarser, database-wide stand-in for
the tenant row's `FOR UPDATE`): they verify the logic built on top of the lock, not the PostgreSQL lock itself.

#### Group commit (batched writes)

`submit_event` queues the event; a background writer commits everything pending in **one transaction** (all chains in
one commit) once `AUDIT_BATCH_MAX_EVENTS` (200) are queued or `AUDIT_BATCH_MAX_DELAY_MS` (500) after the oldest. The
event keeps the time it *happened*. Measured on SQLite (WAL, local disk, 2000 events over 20 chains): 316 events/s with a
commit per event vs ~6000 events/s with group commit (callers blocked ~6 us per event). PostgreSQL over a network was not
measured; the gain there comes from the same place (one round trip and one fsync per batch instead of per event).

What it trades away, deliberately and visibly:
* **Crash window.** A hard crash loses what is still queued (at most the delay). A clean shutdown drains the queue
  (`close()`, before the final checkpoint pass).
* **Backpressure = drop, never block.** The queue is bounded (`AUDIT_BATCH_QUEUE_MAX`, 10000). When full, the *newest*
  events are dropped, counted (`aijailer_audit_events_dropped_total`), logged, and the next write adds an
  `audit_events_dropped` marker (critical, with the count) **to the affected chain**: a gap is part of the signed record,
  never silent. Alert: `AuditEventsDropped`.
* **Database outage.** The batch stays queued (up to the bound) and is retried with backoff; counters
  `..._flush_failures_total` and alert `AuditBatchWritesFailing`/`AuditBatchBacklog` say so.
* **Order.** Within a chain, order is submission order. A durable `record_event` flushes the queue first, so a chain never
  reorders what happened; `query_events`, `verify` and `checkpoint` flush first too (read-your-writes in-process).
  Other processes see an event only after its flush.
* **Atomicity.** A batch is all-or-nothing; on a sequence conflict with another writer the whole batch is rebuilt on the
  new heads and retried.

