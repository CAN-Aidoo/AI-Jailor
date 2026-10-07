# API Documentation — AI Jailer

## API Overview

AI Jailer exposes three API interfaces:

1. **REST API** (primary): Cell management, execution, policies, audit queries. OpenAPI 3.1 spec.
2. **gRPC API**: High-performance execution and streaming. Used by SDKs.
3. **WebSocket API**: Interactive terminal sessions and live log streaming.

Base URL: `https://api.aijailer.com/v1`

## Authentication

All API requests require authentication via one of:

- **API Key**: `Authorization: Bearer aj_live_xxxxxxxxxxxx` — for server-to-server integration.
- **JWT Token**: Short-lived token obtained via OAuth2 flow — for dashboard and CLI.
- **mTLS**: Mutual TLS with client certificate — for enterprise integrations.

API keys are scoped to a tenant and carry an associated role (owner, admin, operator, viewer, auditor).

## Common Response Format

All responses follow a consistent envelope:

```json
{
  "data": { ... },
  "meta": {
    "request_id": "req_abc123",
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

Error responses:

```json
{
  "error": {
    "code": "cell_not_found",
    "message": "Cell with ID 'cell_xyz' does not exist or is not accessible.",
    "details": { ... }
  },
  "meta": {
    "request_id": "req_abc123",
    "timestamp": "2025-01-15T10:30:00Z"
  }
}
```

## REST API Endpoints

---

### Cells

#### POST /v1/cells

Create a new cell.

**Request Body**:

```json
{
  "name": "my-agent-session",
  "image": "base-python",
  "resources": {
    "vcpus": 2,
    "memory_mb": 1024,
    "disk_mb": 5120,
    "network_bandwidth_mbps": 100
  },
  "security_policy_id": "pol_restrictive_default",
  "environment": {
    "OPENAI_API_KEY": "sk-...",
    "WORKSPACE": "/data/project"
  },
  "persistent_volume": {
    "size_mb": 10240,
    "mount_path": "/data"
  },
  "tags": {
    "agent": "code-reviewer",
    "project": "backend-api"
  },
  "auto_start": true,
  "warm_pool": true
}
```

**Response** (201 Created):

```json
{
  "data": {
    "id": "cell_abc123def456",
    "name": "my-agent-session",
    "status": "running",
    "image": "base-python",
    "resources": { ... },
    "security_policy_id": "pol_restrictive_default",
    "persistent_volume": {
      "id": "vol_xyz789",
      "size_mb": 10240,
      "mount_path": "/data"
    },
    "network": {
      "internal_ip": "10.100.5.23"
    },
    "tags": { ... },
    "created_at": "2025-01-15T10:30:00Z",
    "started_at": "2025-01-15T10:30:00.125Z"
  }
}
```

#### GET /v1/cells

List cells for the authenticated tenant.

**Query Parameters**:
- `status` (optional): Filter by status (running, paused, stopped, etc.)
- `tag` (optional, repeatable): Filter by tag (key=value)
- `limit` (optional, default 50, max 200)
- `cursor` (optional): Pagination cursor

#### GET /v1/cells/{cell_id}

Get cell details.

#### POST /v1/cells/{cell_id}/start

Start a stopped or ready cell.

#### POST /v1/cells/{cell_id}/stop

Stop a running cell. Persistent state is retained.

**Request Body** (optional):

```json
{
  "grace_period_seconds": 10
}
```

#### POST /v1/cells/{cell_id}/pause

Pause a running cell. Full VM state frozen in memory.

#### POST /v1/cells/{cell_id}/resume

Resume a paused cell.

#### DELETE /v1/cells/{cell_id}

Destroy a cell.

**Query Parameters**:
- `destroy_persistent` (optional, default false): Also destroy persistent volume.

---

### Execution

#### POST /v1/cells/{cell_id}/exec

Execute a command in a cell.

**Request Body**:

```json
{
  "command": "python3 -c \"print('hello world')\"",
  "timeout_seconds": 30,
  "user": "agent",
  "working_directory": "/data/project",
  "environment": {
    "DEBUG": "true"
  },
  "stream": false
}
```

**Response** (200 OK, non-streaming):

```json
{
  "data": {
    "execution_id": "exec_789xyz",
    "exit_code": 0,
    "stdout": "hello world\n",
    "stderr": "",
    "duration_ms": 142,
    "resource_usage": {
      "cpu_ms": 85,
      "memory_peak_mb": 45
    }
  }
}
```

**Response** (200 OK, streaming — `stream: true`):

Server-Sent Events stream:

```
event: stdout
data: {"text": "hello world\n"}

event: stderr
data: {"text": ""}

event: exit
data: {"exit_code": 0, "duration_ms": 142}
```

#### POST /v1/cells/{cell_id}/exec/script

Execute a multi-line script.

**Request Body**:

```json
{
  "script": "#!/usr/bin/env python3\nimport os\nprint(os.listdir('/data'))",
  "interpreter": "/usr/bin/python3",
  "timeout_seconds": 60,
  "stream": true
}
```

#### POST /v1/cells/{cell_id}/exec/cancel/{execution_id}

Cancel a running execution.

---

### File Operations

#### POST /v1/cells/{cell_id}/files/upload

Upload a file to a cell.

**Request**: Multipart form data.
- `path`: Destination path inside cell.
- `file`: File content.
- `mode` (optional): File permissions (e.g., "0644").

#### GET /v1/cells/{cell_id}/files/download

Download a file from a cell.

**Query Parameters**:
- `path`: Source path inside cell.

**Response**: File content with appropriate Content-Type.

#### GET /v1/cells/{cell_id}/files/list

List files in a directory inside a cell.

**Query Parameters**:
- `path`: Directory path (default: "/").
- `recursive` (optional, default false).

**Response**:

```json
{
  "data": {
    "path": "/data/project",
    "entries": [
      {
        "name": "main.py",
        "type": "file",
        "size": 1234,
        "modified_at": "2025-01-15T10:35:00Z",
        "permissions": "0644"
      },
      {
        "name": "tests",
        "type": "directory",
        "modified_at": "2025-01-15T10:34:00Z",
        "permissions": "0755"
      }
    ]
  }
}
```

---

### Snapshots

#### POST /v1/cells/{cell_id}/snapshots

Snapshot a `ready`/`running`/`paused` cell (memory + VM state + disk; the guest is paused briefly and resumed).
The bundle is stored under `SNAPSHOT_DIR/<tenant>/<snapshot>` with a sha256 per file. Backends without snapshot
support answer `501 snapshot_unsupported`; other failures `502 snapshot_failed` (no snapshot row is kept).

**Request Body**:

```json
{
  "name": "after-setup",
  "description": "Cell state after environment setup and dependency install"
}
```

**Response** (202 Accepted):

```json
{
  "data": {
    "id": "snap_abc123",
    "cell_id": "cell_abc123def456",
    "name": "after-setup",
    "status": "available",
    "total_size_bytes": 268435456,
    "created_at": "2025-01-15T10:40:00Z"
  }
}
```

**Quotas**: each tenant has `max_snapshot_count`, `max_snapshots_per_cell` (default 10), `max_snapshot_storage_per_cell_gb` (default 10) and
`max_snapshot_storage_gb` (tenant total bytes, since memory dumps dominate; the per-cell limits stop one cell or agent
loop taking the whole allowance). All four are checked, and the slot reserved, before the guest is touched; exceeding either answers
`429 resource_limit_exceeded` (`snapshots` / `snapshots_per_cell` / `snapshot_storage_per_cell` / `snapshot_storage`). A cell whose memory + disk
alone exceed its per-cell size limit can never be snapshotted (the reservation is an upper bound). A snapshot being created counts at an upper-bound
estimate (memory + configured disk) until its real size is known; a failed one gives its reservation back, and one stuck
in `creating` longer than `RECONCILE_STUCK_SECONDS` (owner died) is expired so a crash cannot wedge the quota.

#### GET /metrics (operator, Prometheus)

Disabled (404) unless `METRICS_TOKEN` is set; then requires `Authorization: Bearer <METRICS_TOKEN>` (401 otherwise).
Not tenant-scoped: it exports every active tenant, so scrape it from your monitoring network only.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `aijailer_snapshot_quota_used` | gauge | `tenant`, `quota` | In use: snapshots (count quotas) or bytes (storage quotas); the per-cell quotas report the tenant's **fullest cell** |
| `aijailer_snapshot_quota_limit` | gauge | `tenant`, `quota` | The limit, same units |
| `aijailer_snapshot_quota_denied_total` | counter | `tenant`, `quota` | Creations refused because that quota was reached (per process; resets on restart) |

`quota` is one of `snapshots`, `snapshot_storage`, `snapshots_per_cell`, `snapshot_storage_per_cell`. Counting follows
the enforcement rules exactly (in-flight counts, failed/stuck do not), so `used / limit >= 1` is the condition that starts
refusing requests. Example alert: `max by (tenant, quota) (aijailer_snapshot_quota_used / aijailer_snapshot_quota_limit) > 0.9`.
Cardinality is tenants x 4 quotas; there is deliberately no per-cell label.

#### Operator API: per-tenant quota overrides (`/v1/admin/tenants/{tenant_id}/quotas`)

Platform-operator only, authenticated by `Authorization: Bearer <ADMIN_TOKEN>`, **not** by tenant API keys (a tenant's
own owner/admin must not be able to raise the limits that bound them; their keys get 401). Disabled (404) when
`ADMIN_TOKEN` is unset; hidden from the OpenAPI schema. Unknown tenant: `404 tenant_not_found`.

- `GET` returns `limits`, platform `defaults`, `usage` (snapshots, bytes), `over_limit` and `warnings`.
- `PATCH` changes any subset of `max_snapshot_count` (default 100), `max_snapshots_per_cell` (10),
  `max_snapshot_storage_gb` (50), `max_snapshot_storage_per_cell_gb` (10). Strict integers 0..1,000,000 (storage
  0..10,000,000, a typo guard); `0` forbids new snapshots; unknown fields, nulls, strings, floats and booleans are
  rejected (400/422) and change nothing. Effective on the next request, and the metrics follow on the next scrape.
- `DELETE` resets all four to the defaults.
- `GET .../quotas/audit` is the change history, newest first: `events[]` with `id`, `timestamp` (UTC), `action`
  (`quota_override_set` / `quota_override_reset`), `actor`, `from`/`to` (only the fields that changed) and the
  `previous_hash`/`event_hash` chain links. Query: `limit` (1-500, default 50), `before` (exclusive ISO timestamp; pass the
  previous page's `next_before`, which is `null` on the last page) and `action`. The tenant's hash-chained audit log is
  verified on every call: `chain_intact: false` means the stored history was altered or truncated and the entries must not
  be trusted. `durable: false` means the audit store is in-memory (`AUDIT_BACKEND=memory`, the default in dev), so history from before the
  last restart is not available; with the database backend (the default outside dev, see AUDIT_SYSTEM.md) it is `true`. Pages use the timestamp as a cursor, so events written in the same
  microsecond could straddle a page boundary.

Lowering a limit below current usage is allowed: existing snapshots stay, new ones get 429 until usage drops (reported
in `over_limit`). Per-cell limits above the tenant totals are allowed but listed in `warnings` (the totals win).
Every change is audited (action `quota_override_set` / `quota_override_reset`, severity warning, with the before/after
values); no-op requests are not. Changes take the same tenant row lock as snapshot reservations, so they cannot
interleave with one.

**Durability.** The new limits and their audit record are written in **one database transaction** and committed
*before* the response is sent: a `200` means both are durable; any failure (including a failed commit) returns an error
with neither applied, so there is never a change without its record, or a record of a change that did not happen. With
`AUDIT_BACKEND=memory` (dev) the audit event cannot join the transaction and is not durable (`durable: false`).

#### GET /v1/snapshots/quota

`{"data": {"count": 3, "max_count": 100, "bytes_used": 1073741824, "max_bytes": 53687091200}}`
Add `?cell_id=<id>` to also get `cell_count`, `max_per_cell`, `cell_bytes` and `max_bytes_per_cell` for that cell (404 for a cell that is not yours).

#### DELETE /v1/snapshots/{snapshot_id}

Delete a snapshot and its stored data (204); frees quota. `409 snapshot_not_available` while it is still being created.
`500 snapshot_delete_failed` (row kept, so the storage stays accounted) if the files could not be removed.

#### GET /v1/cells/{cell_id}/snapshots

List snapshots for a cell.

#### POST /v1/cells/{cell_id}/restore

Restore the cell from one of **its own** snapshots. **Destructive and synchronous**: the cell's current VM (and
everything done in it since the snapshot) is replaced; the response is the final status (`running`).

```json
{ "snapshot_id": "snap_abc123" }
```

- The guest keeps its saved network address, so the snapshot's /30 must be free: otherwise `409 snapshot_address_in_use`.
- The cell's **current** security policy, bandwidth and environment are kept (restoring never resurrects an older, looser policy).
- Checked before anything is destroyed: snapshot exists / is `available` / belongs to this cell (`400 snapshot_cell_mismatch`),
  cell state (`409`), address, bundle integrity (`422 snapshot_corrupt`).
- If the restore itself fails after the old VM was replaced, the cell is left in `error` (`502 restore_failed`).
- Restored guests resume with their saved RNG state; established vsock connections are reset.

#### POST /v1/snapshots/{snapshot_id}/clone

Create a new cell from a snapshot. The clone keeps the snapshot's machine (`resources` is rejected: `400 invalid_clone`)
and its guest address, so it only works while no other cell holds that address (typically after the source cell is
gone; otherwise `409 snapshot_address_in_use`). `security_policy_id` defaults to the source cell's policy and must still
be usable. A clone shares the snapshot's saved RNG state: do not treat clones as independent for keys or nonces.
Returns `201` with the new cell's `id` and `status` (`error` if the restore failed).

**Request Body** (`resources` shown for completeness; it must be omitted):

```json
{
  "name": "cloned-session",
  "resources": { ... },
  "security_policy_id": "pol_custom"
}
```

---

### Security Policies

#### POST /v1/policies

Create a security policy.

**Request Body**:

```json
{
  "name": "restricted-web-access",
  "description": "Allow only specific API endpoints",
  "network": {
    "default": "deny",
    "egress": [
      {
        "action": "allow",
        "destinations": [
          { "domain": "api.openai.com" },
          { "domain": "api.anthropic.com" }
        ],
        "protocols": ["tcp"],
        "ports": [443]
      }
    ]
  },
  "resources": {
    "max_vcpus": 2,
    "max_memory_mb": 2048,
    "max_disk_mb": 10240,
    "max_pids": 256,
    "max_open_files": 1024
  },
  "filesystem": {
    "writable_paths": ["/tmp", "/home/agent", "/data"],
    "denied_paths": ["/etc/shadow", "/root"]
  },
  "syscalls": {
    "blocked": ["mount", "ptrace", "kexec_load", "bpf"]
  }
}
```

#### GET /v1/policies

List policies.

#### GET /v1/policies/{policy_id}

Get policy details.

#### PUT /v1/policies/{policy_id}

Update a policy. Creates a new version (policies are immutable; updates create a new version).

#### DELETE /v1/policies/{policy_id}

Deactivate a policy. Cells using it continue with the last active version.

---

### Audit Logs

#### GET /v1/audit/events

Query audit events.

**Query Parameters**:
- `cell_id` (optional): Filter by cell.
- `event_type` (optional): Filter by type (execution, file_access, network, lifecycle, policy_violation).
- `severity` (optional): Filter by severity (info, warning, critical).
- `start_time` (required): Start of time range (ISO 8601).
- `end_time` (required): End of time range (ISO 8601).
- `limit` (optional, default 100, max 1000).
- `cursor` (optional): Pagination cursor.

**Response**:

```json
{
  "data": {
    "events": [
      {
        "id": "evt_abc123",
        "cell_id": "cell_abc123def456",
        "event_type": "execution",
        "severity": "info",
        "timestamp": "2025-01-15T10:35:00.123Z",
        "details": {
          "command": "pip install requests",
          "exit_code": 0,
          "duration_ms": 3400
        }
      },
      {
        "id": "evt_def456",
        "cell_id": "cell_abc123def456",
        "event_type": "network",
        "severity": "warning",
        "timestamp": "2025-01-15T10:35:05.456Z",
        "details": {
          "action": "blocked",
          "destination": "evil-server.com",
          "port": 443,
          "protocol": "tcp",
          "reason": "domain not in allow list"
        }
      }
    ],
    "next_cursor": "cur_xyz789"
  }
}
```

#### GET /v1/audit/export

Export audit logs for compliance reporting.

**Query Parameters**:
- `cell_id` (optional)
- `start_time` (required)
- `end_time` (required)
- `format`: "json" or "csv"

**Response**: File download (Content-Disposition: attachment).

---

### Usage & Metering

#### GET /v1/usage

Get usage summary for the authenticated tenant.

**Query Parameters**:
- `start_time` (required)
- `end_time` (required)
- `granularity` (optional): "hourly", "daily", "monthly"
- `group_by` (optional): "cell", "image", "tag"

**Response**:

```json
{
  "data": {
    "period": {
      "start": "2025-01-01T00:00:00Z",
      "end": "2025-01-31T23:59:59Z"
    },
    "totals": {
      "cpu_core_seconds": 1234567,
      "memory_gb_seconds": 9876543,
      "storage_gb_hours": 54321,
      "network_egress_gb": 12.5,
      "api_calls": 45678,
      "cell_count": 89,
      "snapshot_count": 23
    }
  }
}
```

---

### Webhooks

#### POST /v1/webhooks

Register a webhook endpoint.

**Request Body**:

```json
{
  "url": "https://my-service.com/webhooks/aijailer",
  "events": [
    "cell.created",
    "cell.stopped",
    "cell.destroyed",
    "policy.violation",
    "spending.threshold"
  ],
  "secret": "whsec_xxxxxxxxxxxxxxxx"
}
```

**Webhook Payload**:

```json
{
  "id": "whk_abc123",
  "event": "policy.violation",
  "timestamp": "2025-01-15T10:35:05.456Z",
  "data": {
    "cell_id": "cell_abc123def456",
    "violation_type": "network_blocked",
    "details": {
      "destination": "evil-server.com",
      "port": 443
    }
  },
  "signature": "sha256=xxxxx"
}
```

---

## gRPC API

The gRPC API mirrors the REST API with the following service definitions:

```protobuf
service CellService {
  rpc CreateCell(CreateCellRequest) returns (Cell);
  rpc GetCell(GetCellRequest) returns (Cell);
  rpc ListCells(ListCellsRequest) returns (ListCellsResponse);
  rpc StartCell(CellActionRequest) returns (Cell);
  rpc StopCell(StopCellRequest) returns (Cell);
  rpc PauseCell(CellActionRequest) returns (Cell);
  rpc ResumeCell(CellActionRequest) returns (Cell);
  rpc DestroyCell(DestroyCellRequest) returns (Empty);
}

service ExecutionService {
  rpc Execute(ExecuteRequest) returns (ExecuteResponse);
  rpc ExecuteStream(ExecuteRequest) returns (stream ExecuteEvent);
  rpc CancelExecution(CancelRequest) returns (Empty);
}

service FileService {
  rpc Upload(stream FileChunk) returns (UploadResponse);
  rpc Download(DownloadRequest) returns (stream FileChunk);
  rpc ListFiles(ListFilesRequest) returns (ListFilesResponse);
}

service TerminalService {
  rpc OpenTerminal(OpenTerminalRequest) returns (stream TerminalEvent);
  rpc SendInput(stream TerminalInput) returns (Empty);
}
```

## WebSocket API

### Interactive Terminal

**Endpoint**: `wss://api.aijailer.com/v1/cells/{cell_id}/terminal`

**Connection**: Standard WebSocket upgrade with API key in header or query parameter.

**Client → Server Messages**:

```json
{ "type": "input", "data": "ls -la\n" }
{ "type": "resize", "cols": 120, "rows": 40 }
{ "type": "ping" }
```

**Server → Client Messages**:

```json
{ "type": "output", "data": "total 24\ndrwxr-xr-x ..." }
{ "type": "exit", "code": 0 }
{ "type": "error", "message": "Cell is not running" }
{ "type": "pong" }
```

### Live Log Streaming

**Endpoint**: `wss://api.aijailer.com/v1/cells/{cell_id}/logs`

**Query Parameters**:
- `event_types`: Comma-separated list of event types to stream.
- `severity_min`: Minimum severity level.

**Server → Client Messages**:

```json
{
  "type": "audit_event",
  "event": {
    "id": "evt_abc123",
    "event_type": "execution",
    "severity": "info",
    "timestamp": "2025-01-15T10:35:00.123Z",
    "details": { ... }
  }
}
```

## Rate Limits

| Tier | API Calls/min | Cell Creates/min | Executions/min |
|---|---|---|---|
| Free | 60 | 5 | 30 |
| Starter | 300 | 20 | 150 |
| Pro | 1000 | 100 | 500 |
| Enterprise | Custom | Custom | Custom |

Rate limit headers returned on every response:

```
X-RateLimit-Limit: 300
X-RateLimit-Remaining: 287
X-RateLimit-Reset: 1705312260
```

## Error Codes

| Code | HTTP Status | Description |
|---|---|---|
| `cell_not_found` | 404 | Cell does not exist or is not accessible |
| `cell_not_running` | 409 | Operation requires a running cell |
| `cell_limit_exceeded` | 429 | Tenant has reached maximum concurrent cells |
| `execution_timeout` | 408 | Command exceeded its timeout |
| `policy_violation` | 403 | Action blocked by security policy |
| `resource_limit_exceeded` | 429 | Cell or tenant resource quota exceeded |
| `snapshot_failed` | 502 | Snapshot creation failed |
| `tenant_not_found` | 404 | Operator API: no such tenant |
| `invalid_quota` | 400 | Operator API: invalid quota change (nothing applied) |
| `snapshot_delete_failed` | 500 | Snapshot files could not be removed (row kept) |
| `snapshot_unsupported` | 501 | The isolation backend cannot snapshot |
| `snapshot_not_found` | 404 | No such snapshot for this tenant |
| `snapshot_not_available` | 409 | Snapshot is not in `available` state |
| `snapshot_address_in_use` | 409 | The snapshot's guest address is held by another cell |
| `snapshot_cell_mismatch` | 400 | Snapshot belongs to a different cell (use clone) |
| `snapshot_corrupt` | 422 | Snapshot data is missing or fails its checksums |
| `restore_failed` | 502 | Restore failed after the old VM was replaced; cell is `error` |
| `invalid_clone` | 400 | Clone request tried to change the snapshot's resources |
| `image_not_found` | 404 | Specified base image does not exist |
| `invalid_policy` | 400 | Policy definition is invalid |
| `spending_cap_reached` | 402 | Tenant spending cap exceeded |
| `rate_limited` | 429 | Too many requests |
| `unauthorized` | 401 | Invalid or missing authentication |
| `forbidden` | 403 | Insufficient permissions for this action |


## Secrets (`/v1/secrets`)

Write-only credentials the egress broker injects into outbound requests, so a cell never holds them.
Roles: owner/admin write; owner/admin/auditor read metadata. Values are never returned.

```
POST   /v1/secrets        {"name":"gh","value":"ghp_...","hosts":["api.github.com"],"expires_at":null}
GET    /v1/secrets        metadata list
GET    /v1/secrets/{name} metadata
PUT    /v1/secrets/{name} {"value":"..."} (rotate) and/or {"hosts":[...]} / {"expires_at":...} / {"clear_expiry":true}
DELETE /v1/secrets/{name}
```

Response (`value` is never present): `name, version, hosts, expires_at, created_at, updated_at, rotated_at, placeholder`.
Inside a cell, send the placeholder instead of the secret, e.g. through the cell's `http_proxy`:
`GET http://api.github.com/user` with header `Authorization: Bearer {{secret:gh}}`.
`hosts` are exact names, `*.suffix` (two or more labels after `*.`) or IPv4 literals; a secret is only ever sent to them.
Changes apply to running cells immediately. Errors: 400 `invalid_secret`, 404 `secret_not_found`, 409 `secret_conflict`,
429 `secret_limit` (100 per tenant), 503 `secret_store_unavailable` (no `SECRETS_MASTER_KEYS`).


## Cell bandwidth (`/v1/cells/{id}/bandwidth`)

```
GET    /v1/cells/{id}/bandwidth   configured (database) and enforced (kernel read-back) limits
PUT    /v1/cells/{id}/bandwidth   {"down_kbit": 4000, "up_kbit": 16000}   owner/admin
DELETE /v1/cells/{id}/bandwidth   drop the override, back to resources.network_bandwidth_mbps   owner/admin
```

`down_kbit` is host -> guest, `up_kbit` is guest -> host. Both are required integers; `null` (unlimited) is rejected.
Range: 64 kbit/s up to `MAX_CELL_BANDWIDTH_MBPS` (default 10000, also applied when creating a cell).
Running/paused/ready cells are changed immediately; stopped cells keep the override for their next start;
creating/stopping/destroying/destroyed/error cells return 409.
Response: `{configured: {down_kbit, up_kbit}, source: "default"|"override", enforced: {...}|null, min_kbit, max_kbit}`
(`enforced` is null when the cell currently has no network). Errors: 400 `invalid_bandwidth`, 404, 409 `invalid_state_transition`,
502 `bandwidth_apply_failed` (nothing was persisted), 503 `cell_network_unavailable`.

## Peer links (`/v1/peer-links`)

Attested, end-to-end encrypted cell-to-cell channels with two-sided consent. Full description, wire
protocol and threat model: PEER_LINKS.md. All routes need `PEER_ATTESTATION_SECRET` (else 503
`peer_links_disabled`). Writers: owner/admin; readers: owner/admin/auditor.

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/peer-links` | body `{cell_id, peer_cell_id, ttl_seconds?, purpose?}`; 201; `pending` unless both cells are yours |
| GET | `/v1/peer-links` | links you are a party to; `?include_inactive=true` adds revoked/expired |
| GET | `/v1/peer-links/{id}` | 404 for non-parties |
| POST | `/v1/peer-links/{id}/accept` | responder cell's tenant only |
| DELETE | `/v1/peer-links/{id}` | either party; cuts a live session |
| GET | `/v1/peer-links/attestation-key` | platform Ed25519 public key (base64 raw) |

Error codes: `peer_link_not_found` 404, `peer_link_invalid` 400, `peer_link_conflict` 409,
`peer_link_limit` 429, `peer_links_disabled` 503.

### Example workload: private set intersection (no platform endpoints)

PSI adds **no REST routes and no platform state**. The platform only provides the peer link above; the
computation is the reference program `examples/psi/psi.py` (see `examples/psi/README.md` and the
"Example workload" section of PEER_LINKS.md), which runs inside the two cells and talks to its peer through
`aijailer-peer` on a local socket. To use it: propose and accept a peer link, read `link_id` from the
response, then start `aijailer-peer --link <link_id> --listen 127.0.0.1:7000` and `psi.py ... --context
<link_id> --connect 127.0.0.1:7000` in each cell.

The wire format between the two `psi.py` processes (carried inside the link's TLS, never seen by the
platform in the clear) is a sequence of frames: `version (1 byte, =1) | kind (1 byte) | count (4 bytes,
big-endian) | count x 256-byte big-endian group elements`.

| Kind | Name | Direction | Count must be |
|---|---|---|---|
| 1 | blinded items | receiver -> sender | at most the item limit |
| 2 | doubly blinded items | sender -> receiver | exactly the number of items the receiver sent |
| 3 | sender's blinded set | sender -> receiver | at most the item limit |

Every element must be a quadratic residue in the RFC 3526 2048-bit group other than 1 and p-1; a frame
with a wrong version or kind, an over-limit or mismatched count, an invalid element or a truncated body
ends the run with a `psi_error` status line and exit code 1. The item limit defaults to 50,000
(`--max-items`). Command-line exit codes: 0 success, 1 protocol or I/O error. Status goes to stderr as JSON
(`psi_done` with set sizes, plus `intersection` on the receiver, or `psi_error`); the receiver prints the
intersection to stdout, one item per line.

Limits: semi-honest security only, demo-grade, about 0.1 s per item pair. See the README for what it does
not protect (notably, low-entropy identifiers can be enumerated by the receiver).
