"""Operator-managed snapshot quota limits for a tenant.

The limits live on the tenant row (see models/tenant.py) and are enforced by SnapshotService. This
service is the only writer: validated partial updates, reset to defaults, an audit record of every
change (before/after), and the tenant row lock so a change cannot interleave with a snapshot
reservation that is reading the limits."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.exceptions import AiJailerError
from aijailer.models.audit import EventType, Severity
from aijailer.models.tenant import Tenant
from aijailer.services.audit_service import get_audit_service
from aijailer.services.snapshot_service import SnapshotService

NIL = uuid.UUID(int=0)

# field -> (default, maximum). Defaults mirror the Tenant column defaults (a test keeps them equal).
# Maximums are sanity bounds against typos (an extra zero), not product limits.
FIELDS: dict[str, tuple[int, int]] = {
    "max_snapshot_count": (100, 1_000_000),
    "max_snapshots_per_cell": (10, 1_000_000),
    "max_snapshot_storage_gb": (50, 10_000_000),
    "max_snapshot_storage_per_cell_gb": (10, 10_000_000),
}
DEFAULTS = {k: v[0] for k, v in FIELDS.items()}


@dataclass(frozen=True)
class QuotaState:
    limits: dict[str, int]
    defaults: dict[str, int]
    usage: dict
    over_limit: list[str]        # quotas whose current usage already exceeds the (lowered) limit
    warnings: list[str]


def _err(message: str, code: str) -> AiJailerError:
    return AiJailerError(message, code=code)


def validate(changes: dict) -> dict[str, int]:
    if not changes:
        raise _err("no quota fields given", "invalid_quota")
    out = {}
    for k, v in changes.items():
        if k not in FIELDS:
            raise _err(f"unknown quota field '{k}'", "invalid_quota")
        hi = FIELDS[k][1]
        if isinstance(v, bool) or not isinstance(v, int) or not (0 <= v <= hi):
            raise _err(f"{k} must be an integer between 0 and {hi} (0 forbids new snapshots)",
                       "invalid_quota")
        out[k] = v
    return out


class TenantQuotaService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.audit = get_audit_service()

    async def _tenant(self, tenant_id: uuid.UUID, lock: bool = False) -> Tenant:
        q = select(Tenant).where(Tenant.id == tenant_id)
        t = (await self.db.execute(q.with_for_update() if lock else q)).scalar_one_or_none()
        if t is None:
            raise _err(f"Tenant '{tenant_id}' does not exist.", "tenant_not_found")
        return t

    async def _state(self, t: Tenant) -> QuotaState:
        limits = {k: getattr(t, k) for k in FIELDS}
        q = await SnapshotService(self.db).quota(t.id)
        usage = {"snapshots": q.count, "snapshot_bytes": q.bytes_used}
        over = []
        if q.count > limits["max_snapshot_count"]:
            over.append("max_snapshot_count")
        if q.bytes_used > limits["max_snapshot_storage_gb"] * (1 << 30):
            over.append("max_snapshot_storage_gb")
        warnings = []
        if limits["max_snapshots_per_cell"] > limits["max_snapshot_count"]:
            warnings.append("max_snapshots_per_cell exceeds max_snapshot_count: the tenant total "
                            "is what limits a single cell")
        if limits["max_snapshot_storage_per_cell_gb"] > limits["max_snapshot_storage_gb"]:
            warnings.append("max_snapshot_storage_per_cell_gb exceeds max_snapshot_storage_gb: "
                            "the tenant total is what limits a single cell")
        return QuotaState(limits, dict(DEFAULTS), usage, over, warnings)

    async def get(self, tenant_id: uuid.UUID) -> QuotaState:
        return await self._state(await self._tenant(tenant_id))

    async def update(self, tenant_id: uuid.UUID, changes: dict, actor: str = "operator") -> QuotaState:
        """Partial update. Lowering a limit below current usage is allowed: existing snapshots
        stay, new ones are refused until usage drops (reported in ``over_limit``)."""
        new = validate(changes)
        t = await self._tenant(tenant_id, lock=True)
        return await self._apply(t, new, actor, "quota_override_set")

    async def reset(self, tenant_id: uuid.UUID, actor: str = "operator") -> QuotaState:
        t = await self._tenant(tenant_id, lock=True)
        return await self._apply(t, dict(DEFAULTS), actor, "quota_override_reset")

    async def _apply(self, t: Tenant, new: dict[str, int], actor: str, action: str) -> QuotaState:
        before = {k: getattr(t, k) for k in new}
        changed = {k: v for k, v in new.items() if before[k] != v}
        for k, v in changed.items():
            setattr(t, k, v)
        await self.db.flush()
        if changed:
            # Inside THIS transaction (which also holds the tenant row lock): the new limits and
            # the record of who set them commit together or not at all. The caller must commit
            # before reporting success (the admin routes do).
            await self.audit.record_event(
                tenant_id=t.id, cell_id=NIL, event_type=EventType.LIFECYCLE,
                severity=Severity.WARNING,
                details={"action": action, "actor": actor,
                         "from": {k: before[k] for k in changed}, "to": changed},
                session=self.db)
        return await self._state(t)

    # ------------------------------------------------------------------ history
    ACTIONS = ("quota_override_set", "quota_override_reset")

    async def history(self, tenant_id: uuid.UUID, limit: int = 50, before: datetime | None = None,
                      action: str | None = None) -> dict:
        """Quota override changes, newest first, from the tenant's audit chain.

        ``before`` is an exclusive upper bound (pass the previous page's ``next_before``). The
        chain is verified on every call: ``chain_intact`` false means the stored history was
        altered or truncated and the entries cannot be trusted. ``durable`` is false while the
        audit store is in-memory: history older than the last restart is not available."""
        if action is not None and action not in self.ACTIONS:
            raise _err(f"action must be one of {', '.join(self.ACTIONS)}", "invalid_quota")
        await self._tenant(tenant_id)
        end = None
        if before is not None:       # events carry naive UTC timestamps
            end = before.astimezone(UTC).replace(tzinfo=None) if before.tzinfo else before
        events = await self.audit.query_events(
            tenant_id, cell_id=NIL, event_type=EventType.LIFECYCLE, end_time=end, limit=10**9)
        wanted = (action,) if action else self.ACTIONS
        events = [e for e in events if e.details.get("action") in wanted]
        if end is not None:
            events = [e for e in events if e.timestamp < end]            # exclusive
        page, more = events[:limit], len(events) > limit
        return {
            "events": [{
                "id": str(e.id), "timestamp": e.timestamp.isoformat() + "Z",
                "action": e.details["action"], "actor": e.details.get("actor"),
                "from": e.details.get("from"), "to": e.details.get("to"),
                "previous_hash": e.previous_hash, "event_hash": e.event_hash} for e in page],
            "next_before": page[-1].timestamp.isoformat() + "Z" if more else None,
            "chain_intact": await self.audit.verify_chain(tenant_id, NIL),
            "durable": bool(getattr(self.audit, "durable", False)),
        }
