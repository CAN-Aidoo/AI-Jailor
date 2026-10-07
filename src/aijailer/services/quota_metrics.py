"""Snapshot quota usage as Prometheus metrics (operator-facing; tenants use /v1/snapshots/quota).

Gauges are computed from the database on scrape with exactly the counting rules the quota check
uses (in-flight rows count, stuck/failed rows do not), so an alert on used/limit fires on the
same condition that starts refusing requests. Cardinality is bounded: per tenant and quota, never
per cell; the per-cell quotas export the FULLEST cell (that is the one that hits the limit).
Denials are an in-process counter (resets on restart; with several workers each reports its own
and Prometheus sums them)."""

import threading
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core import promtext
from aijailer.core.config import get_settings
from aijailer.models.snapshot import Snapshot
from aijailer.models.tenant import Tenant

_GIB = 1 << 30
QUOTAS = ("snapshots", "snapshot_storage", "snapshots_per_cell", "snapshot_storage_per_cell")

_denied: Counter[tuple[str, str]] = Counter()
_lock = threading.Lock()


def record_denial(tenant_id, quota: str) -> None:
    with _lock:
        _denied[(str(tenant_id), quota)] += 1


def reset_denials() -> None:                    # tests
    with _lock:
        _denied.clear()


async def collect(db: AsyncSession) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=get_settings().reconcile_stuck_seconds)
    counted = (Snapshot.status == "available") | (
        (Snapshot.status == "creating") & (Snapshot.created_at >= cutoff))
    per_cell = (await db.execute(
        select(Snapshot.tenant_id, Snapshot.cell_id, func.count(),
               func.coalesce(func.sum(Snapshot.total_size_bytes), 0))
        .where(counted).group_by(Snapshot.tenant_id, Snapshot.cell_id))).all()
    tot: dict = {}      # tenant -> [count, bytes, max cell count, max cell bytes]
    for tid, _cid, n, b in per_cell:
        t = tot.setdefault(tid, [0, 0, 0, 0])
        t[0] += n
        t[1] += int(b)
        t[2] = max(t[2], n)
        t[3] = max(t[3], int(b))
    tenants = (await db.execute(select(Tenant).where(Tenant.status == "active"))).scalars().all()
    used, limit = [], []
    for t in tenants:
        c = tot.get(t.id, [0, 0, 0, 0])
        rows = (
            ("snapshots", c[0], t.max_snapshot_count),
            ("snapshot_storage", c[1], t.max_snapshot_storage_gb * _GIB),
            ("snapshots_per_cell", c[2], t.max_snapshots_per_cell),
            ("snapshot_storage_per_cell", c[3], t.max_snapshot_storage_per_cell_gb * _GIB),
        )
        for quota, u, lim in rows:
            lab = {"tenant": str(t.id), "quota": quota}
            used.append((lab, u))
            limit.append((lab, lim))
    with _lock:
        denied = [({"tenant": tid, "quota": q}, n) for (tid, q), n in sorted(_denied.items())]
    return promtext.render([
        ("aijailer_snapshot_quota_used", "gauge",
         "Snapshot quota in use. Count quotas in snapshots, storage quotas in bytes; the per-cell "
         "quotas report the fullest cell of the tenant.", used),
        ("aijailer_snapshot_quota_limit", "gauge",
         "Snapshot quota limit (same units and labels as aijailer_snapshot_quota_used).", limit),
        ("aijailer_snapshot_quota_denied_total", "counter",
         "Snapshot creations refused because a quota was reached (per process).", denied),
    ])
