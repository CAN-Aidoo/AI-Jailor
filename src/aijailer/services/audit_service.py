"""Audit event collection and query service.

In production, events flow through Kafka to ClickHouse. For the MVP,
events are stored in an in-memory list with optional PostgreSQL fallback.
"""

import asyncio
import hashlib
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from pydantic_core import to_jsonable_python

from aijailer.models.audit import AuditEvent, EventType, Severity
from aijailer.services.attestation import (
    Ed25519Signer,
    Signer,
    canonical_json,
    make_statement,
    sign_statement,
    verify_envelope,
)
from aijailer.services.audit_batcher import AuditBatcher
from aijailer.services.audit_store import AuditStore, CheckpointRecord, MemoryAuditStore

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    length: int
    checkpoints_checked: int
    checkpoints_unverifiable: int      # signed by a key this process does not hold: not trusted, not failed
    problem: str = ""


class AuditService:
    """Hash-chained audit events (one chain per tenant+cell) with signed checkpoints.

    Storage is pluggable: in-memory for dev/tests, the database for real deployments."""

    def __init__(self, signer: Signer | None = None, store: AuditStore | None = None,
                 batch_max_events: int = 200, batch_max_delay: float = 0.5,
                 batch_queue_max: int = 10_000) -> None:
        self._store: AuditStore = store or MemoryAuditStore()
        self._events = getattr(self._store, "events", None)   # memory backend only (tests)
        self._signer = signer or Ed25519Signer.generate()
        self._batch_cfg = (batch_max_events, batch_max_delay, batch_queue_max)
        self._batcher: AuditBatcher | None = None

    @property
    def durable(self) -> bool:
        return bool(self._store.durable)

    @property
    def public_key(self):
        return self._signer.public_key

    @staticmethod
    def _compute_hash(event: AuditEvent, previous_hash: str) -> str:
        """Hash EVERY field (details, severity, actor...) so any edit is detectable."""
        body = event.model_dump(mode="json", exclude={"event_hash"})
        body["previous_hash"] = previous_hash
        return hashlib.sha256(canonical_json(body)).hexdigest()

    # ------------------------------------------------------------------ checkpoints
    async def checkpoint(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> dict:
        """Sign (head hash, length) so deletion of recent events is detectable.

        A bare hash chain cannot detect truncation or a full rebuild by someone
        with write access; a signed checkpoint held elsewhere (like a
        transparency-log signed tree head) can.
        """
        key = f"{tenant_id}:{cell_id}"
        await self.flush()
        n, head = await self._store.head(tenant_id, cell_id)
        statement = make_statement(
            f"audit-chain/{key}", head.ljust(64, "0"),
            "https://aijailer.dev/attestation/audit-checkpoint/v1",
            {"chain": key, "length": n, "head": head},
        )
        cp = sign_statement(statement, self._signer)
        await self._store.add_checkpoint(
            tenant_id, cell_id, CheckpointRecord(n, head, self._signer.keyid, cp))
        return cp

    async def checkpoint_due(self, since: datetime | None = None) -> int:
        """Checkpoint every chain that has grown since its last checkpoint. Returns how many."""
        done = 0
        for tenant_id, cell_id in await self._store.advanced_chains(since):
            try:
                await self.checkpoint(tenant_id, cell_id)
                done += 1
            except Exception:
                logger.exception("audit.checkpoint_failed", tenant_id=str(tenant_id),
                                 cell_id=str(cell_id))
        return done

    # ------------------------------------------------------------------ write / read
    def _builder(self, tenant_id, cell_id, event_type, severity, details, source_ip,
                 api_key_id, request_id):
        # What is hashed must equal what is stored and read back: normalise details to plain
        # JSON now (UUIDs, datetimes... exactly as model_dump(mode="json") would). The timestamp
        # is when the thing HAPPENED, fixed here even if the write is batched.
        base = dict(
            id=uuid.uuid4(), timestamp=datetime.now(UTC).replace(tzinfo=None),
            tenant_id=tenant_id, cell_id=cell_id, event_type=event_type, severity=severity,
            details=to_jsonable_python(details or {}), source_ip=source_ip,
            api_key_id=api_key_id, request_id=request_id)

        def build(previous_hash: str) -> AuditEvent:
            event = AuditEvent(**base, previous_hash=previous_hash)
            event.event_hash = self._compute_hash(event, previous_hash)
            return event
        return build

    async def record_event(
        self,
        tenant_id: uuid.UUID,
        cell_id: uuid.UUID,
        event_type: EventType,
        severity: Severity = Severity.INFO,
        details: dict | None = None,
        source_ip: str | None = None,
        api_key_id: uuid.UUID | None = None,
        request_id: str | None = None,
        session=None,
    ) -> AuditEvent:
        """Record a new audit event with hash chain integrity.

        Three durability levels, strongest last:
          * ``submit_event``: queued, lost on a crash (high-volume events only);
          * ``record_event(...)``: committed on its own before this returns, so it survives a
            crash, but is independent of the caller's transaction (a later rollback leaves the
            event behind; a failed audit write after the change leaves the change unaudited);
          * ``record_event(..., session=db)``: written INSIDE the caller's transaction, so the
            event and the change it describes commit or roll back together. Durable exactly when
            the caller commits (commit before reporting success). Use for changes whose audit
            record must never disagree with reality (quota overrides)."""
        build = self._builder(tenant_id, cell_id, event_type, severity, details, source_ip,
                              api_key_id, request_id)
        if self._batcher is not None and self._batcher.pending:
            await self._batcher.flush()      # keep this chain in the order things happened
        if session is not None:
            return await self._store.append_in_session(session, tenant_id, cell_id, build)
        return await self._store.append(tenant_id, cell_id, build)

    # ------------------------------------------------------------------ batched path
    @property
    def batcher(self) -> AuditBatcher:
        if self._batcher is None:
            n, delay, qmax = self._batch_cfg

            def marker(t, c, count):
                return self._builder(t, c, EventType.RESOURCE_ALERT, Severity.CRITICAL,
                                     {"action": "audit_events_dropped", "count": count,
                                      "reason": "batch queue full"}, None, None, None)
            self._batcher = AuditBatcher(self._store.append_batch, marker, n, delay, qmax)
        return self._batcher

    def submit_event(
        self,
        tenant_id: uuid.UUID,
        cell_id: uuid.UUID,
        event_type: EventType,
        severity: Severity = Severity.INFO,
        details: dict | None = None,
        source_ip: str | None = None,
        api_key_id: uuid.UUID | None = None,
        request_id: str | None = None,
    ) -> bool:
        """Queue an event for group commit. Synchronous and non-blocking (safe in callbacks).

        NOT durable on return: a hard crash loses up to the batch delay of events, and a full
        queue drops the newest (recorded as an ``audit_events_dropped`` gap marker). Use only for
        high-volume, individually low-stakes events (per-request network decisions). Needs a
        running event loop. Returns False if the event was dropped."""
        build = self._builder(tenant_id, cell_id, event_type, severity, details, source_ip,
                              api_key_id, request_id)
        return self.batcher.submit(tenant_id, cell_id, build)

    async def flush(self) -> None:
        """Write everything submitted so far."""
        if self._batcher is not None:
            await self._batcher.flush()

    async def close(self) -> None:
        if self._batcher is not None:
            await self._batcher.close()

    def prometheus_families(self) -> list:
        m = self.batch_metrics()
        b = self._batcher
        cap = b.queue_max if b else self._batch_cfg[2]
        return [
            ("aijailer_audit_batch_pending", "gauge",
             "Audit events queued for group commit, not yet written.", [({}, m["pending"])]),
            ("aijailer_audit_batch_queue_capacity", "gauge",
             "Capacity of the audit batch queue (AUDIT_BATCH_QUEUE_MAX).", [({}, cap)]),
            ("aijailer_audit_events_dropped_total", "counter",
             "Audit events dropped because the batch queue was full (a gap marker is in the chain).",
             [({}, m["dropped_total"])]),
            ("aijailer_audit_batch_flush_failures_total", "counter",
             "Audit batch writes that failed (the batch is kept and retried).",
             [({}, m["flush_failures_total"])]),
            ("aijailer_audit_batch_events_flushed_total", "counter",
             "Audit events written through group commit.", [({}, m["flushed_total"])]),
        ]

    def batch_metrics(self) -> dict:
        b = self._batcher
        return {"pending": b.pending if b else 0, "dropped_total": b.dropped_total if b else 0,
                "flushed_total": b.flushed_total if b else 0,
                "flushes_total": b.flushes_total if b else 0,
                "flush_failures_total": b.flush_failures_total if b else 0}

    async def query_events(
        self,
        tenant_id: uuid.UUID,
        cell_id: uuid.UUID | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events (newest first) with filters."""
        await self.flush()                   # see what this process has submitted
        return await self._store.query(
            tenant_id, cell_id, event_type, severity, start_time, end_time, limit)

    # ------------------------------------------------------------------ verification
    async def verify(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> ChainReport:
        """Verify chain integrity AND consistency with every signed checkpoint."""
        await self.flush()
        cps = await self._store.checkpoints(tenant_id, cell_id)
        mine = [c for c in cps if c.key_id == self._signer.keyid]
        wanted = {c.length for c in mine if c.length > 0}
        at: dict[int, str] = {}
        prev_hash, n = "", 0
        async for page in self._store.chain(tenant_id, cell_id):
            for event in page:
                if event.previous_hash != prev_hash:
                    return ChainReport(False, n, 0, 0, f"broken link at event {n + 1}")
                if event.event_hash != self._compute_hash(event, prev_hash):
                    return ChainReport(False, n, 0, 0, f"event {n + 1} was modified")
                prev_hash = event.event_hash
                n += 1
                if n in wanted:
                    at[n] = prev_hash
        for cp in mine:
            stmt = verify_envelope(cp.envelope, self.public_key)
            if stmt is None:
                return ChainReport(False, n, 0, 0, "a checkpoint signature is invalid")
            pred = stmt["predicate"]
            if pred["length"] > n:
                return ChainReport(False, n, 0, 0, "events were deleted after a checkpoint")
            if pred["length"] and at.get(pred["length"]) != pred["head"]:
                return ChainReport(False, n, 0, 0, "history before a checkpoint was rewritten")
        return ChainReport(True, n, len(mine), len(cps) - len(mine))

    async def verify_chain(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> bool:
        return (await self.verify(tenant_id, cell_id)).ok


class AuditCheckpointer:
    """Background task: periodically checkpoint every chain that grew."""

    def __init__(self, service: AuditService, interval: float) -> None:
        self._svc, self._interval = service, interval
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self._since: datetime | None = None

    async def run_once(self) -> int:
        started = datetime.now(UTC).replace(tzinfo=None)
        n = await self._svc.checkpoint_due(self._since)
        # next pass only needs chains with events since (a pass-length of slack included)
        self._since = started.replace(microsecond=0) - timedelta(seconds=5)
        return n

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:
                logger.exception("audit.checkpointer_failed")
            try:
                await asyncio.wait_for(self._stop.wait(), self._interval)
            except TimeoutError:
                pass

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
        try:                                   # final pass so a clean shutdown leaves no gap
            await self._svc.checkpoint_due(None)
        except Exception:
            logger.exception("audit.final_checkpoint_failed")


class AuditConfigError(RuntimeError):
    """The audit log is misconfigured in a way that would silently weaken it."""


def _batch_kwargs(s) -> dict:
    if s.audit_batch_max_events < 1 or s.audit_batch_queue_max < s.audit_batch_max_events \
            or s.audit_batch_max_delay_ms < 1:
        raise AuditConfigError("AUDIT_BATCH_* must be positive and QUEUE_MAX >= MAX_EVENTS")
    return {"batch_max_events": s.audit_batch_max_events,
            "batch_max_delay": s.audit_batch_max_delay_ms / 1000.0,
            "batch_queue_max": s.audit_batch_queue_max}


def build_audit_service() -> AuditService:
    """Pick the backend from settings. Outside dev the audit log is durable (database) by default,
    and a database-backed log REQUIRES a configured signing secret: with an ephemeral key every
    restart would orphan all earlier checkpoints, silently disabling truncation detection."""
    from aijailer.core.config import get_settings

    s = get_settings()
    backend = s.audit_backend
    if backend not in ("auto", "memory", "db"):
        raise AuditConfigError(f"invalid AUDIT_BACKEND {backend!r} (auto|memory|db)")
    if backend == "auto":
        backend = "memory" if s.environment == "dev" else "db"
    signer = (Ed25519Signer.from_secret(s.audit_signing_secret)
              if s.audit_signing_secret else None)
    if backend == "memory":
        if s.environment != "dev":
            logger.warning("audit.volatile_backend", note="audit history is lost on restart")
        return AuditService(signer=signer, **_batch_kwargs(s))
    if signer is None:
        if s.environment != "dev":
            raise AuditConfigError(
                "AUDIT_SIGNING_SECRET is required for the database audit log outside dev")
        logger.warning("audit.ephemeral_signing_key",
                       note="checkpoints will not verify after a restart (dev only)")
    from aijailer.db.base import async_session_factory
    from aijailer.services.audit_store import DbAuditStore

    return AuditService(signer=signer, store=DbAuditStore(async_session_factory),
                        **_batch_kwargs(s))


# Process-wide instance
_audit_service: AuditService | None = None


def get_audit_service() -> AuditService:
    global _audit_service
    if _audit_service is None:
        _audit_service = build_audit_service()
    return _audit_service


def reset_audit_service() -> None:             # tests
    global _audit_service
    _audit_service = None
