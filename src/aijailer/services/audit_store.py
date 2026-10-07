"""Storage backends for the audit log (hashing, signing and verification live in AuditService).

``MemoryAuditStore`` is the dev/test backend (lost on restart). ``DbAuditStore`` keeps events in
``audit_events`` (one hash chain per tenant+cell, ``seq`` unique per chain) and signed checkpoints
in ``audit_checkpoints``; every write is its own short transaction on its own session, so an audit
record survives a request that later rolls back and never rides on a request's transaction."""

import asyncio
import random
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError

from aijailer.models.audit import AuditEvent, EventType, Severity
from aijailer.models.audit_log import AuditCheckpointRow, AuditEventRow


class AuditWriteError(RuntimeError):
    """The event could not be appended (e.g. persistent contention on one chain)."""


@dataclass(frozen=True)
class CheckpointRecord:
    length: int
    head: str
    key_id: str
    envelope: dict


class AuditStore(Protocol):
    durable: bool

    async def append(self, tenant_id: uuid.UUID, cell_id: uuid.UUID,
                     build: Callable[[str], AuditEvent]) -> AuditEvent: ...
    async def append_batch(self, items: list[tuple[uuid.UUID, uuid.UUID, Callable[[str], AuditEvent]]]
                           ) -> list[AuditEvent]: ...
    async def query(self, tenant_id: uuid.UUID, cell_id: uuid.UUID | None, event_type,
                    severity, start_time: datetime | None, end_time: datetime | None,
                    limit: int) -> list[AuditEvent]: ...
    def chain(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> AsyncIterator[list[AuditEvent]]: ...
    async def head(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> tuple[int, str]: ...
    async def add_checkpoint(self, tenant_id: uuid.UUID, cell_id: uuid.UUID,
                             rec: CheckpointRecord) -> None: ...
    async def checkpoints(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> list[CheckpointRecord]: ...
    async def advanced_chains(self, since: datetime | None) -> list[tuple[uuid.UUID, uuid.UUID]]: ...


def _naive_utc(dt: datetime | None) -> datetime | None:
    if dt is not None and dt.tzinfo is not None:
        return dt.astimezone(UTC).replace(tzinfo=None)
    return dt


def _plain(v) -> str | None:
    return None if v is None else str(getattr(v, "value", v))


class MemoryAuditStore:
    durable = False

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []
        self._last_hash: dict[tuple, str] = {}
        self._cps: dict[tuple, list[CheckpointRecord]] = {}

    async def append(self, tenant_id, cell_id, build):
        key = (tenant_id, cell_id)
        event = build(self._last_hash.get(key, ""))
        self._last_hash[key] = event.event_hash
        self.events.append(event)
        return event

    async def append_batch(self, items):
        return [await self.append(t, c, b) for t, c, b in items]

    async def query(self, tenant_id, cell_id, event_type, severity, start_time, end_time, limit):
        results = []
        for event in reversed(self.events):
            if event.tenant_id != tenant_id:
                continue
            if cell_id and event.cell_id != cell_id:
                continue
            if event_type and event.event_type != event_type:
                continue
            if severity and event.severity != severity:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return results

    async def chain(self, tenant_id, cell_id):
        yield [e for e in self.events if e.tenant_id == tenant_id and e.cell_id == cell_id]

    async def head(self, tenant_id, cell_id):
        n = sum(1 for e in self.events if e.tenant_id == tenant_id and e.cell_id == cell_id)
        return n, self._last_hash.get((tenant_id, cell_id), "")

    async def add_checkpoint(self, tenant_id, cell_id, rec):
        self._cps.setdefault((tenant_id, cell_id), []).append(rec)

    async def checkpoints(self, tenant_id, cell_id):
        return list(self._cps.get((tenant_id, cell_id), []))

    async def advanced_chains(self, since):
        out = []
        for key in {(e.tenant_id, e.cell_id) for e in self.events}:
            n, _ = await self.head(*key)
            last = max((c.length for c in self._cps.get(key, [])), default=0)
            if n > last:
                out.append(key)
        return out


class DbAuditStore:
    durable = True
    PAGE = 5000
    ATTEMPTS = 12

    def __init__(self, session_factory) -> None:
        self._sf = session_factory

    @staticmethod
    def _to_event(r: AuditEventRow) -> AuditEvent:
        return AuditEvent(
            id=r.id, tenant_id=r.tenant_id, cell_id=r.cell_id, event_type=EventType(r.event_type),
            severity=Severity(r.severity), timestamp=r.timestamp, details=r.details,
            source_ip=r.source_ip, api_key_id=r.api_key_id, request_id=r.request_id,
            previous_hash=r.previous_hash, event_hash=r.event_hash)

    async def append(self, tenant_id, cell_id, build):
        return (await self.append_batch([(tenant_id, cell_id, build)]))[0]

    async def append_batch(self, items):
        """Append many events in ONE transaction (one commit instead of one per event).

        Items of the same chain are chained in the order given; items of different chains are
        independent. Per chain: read the head, build each event on its predecessor, insert at
        head+1.... The unique (tenant, cell, seq) constraint is the lock: a concurrent writer that
        extended any of these heads makes the commit fail as a whole (nothing is written) and
        the batch is rebuilt on the new heads and retried. All-or-nothing."""
        for attempt in range(self.ATTEMPTS):
            async with self._sf() as s:
                heads: dict[tuple, tuple[int, str]] = {}
                built: list[AuditEvent] = []
                for tenant_id, cell_id, build in items:
                    key = (tenant_id, cell_id)
                    if key not in heads:
                        last = (await s.execute(
                            select(AuditEventRow.seq, AuditEventRow.event_hash)
                            .where(AuditEventRow.tenant_id == tenant_id,
                                   AuditEventRow.cell_id == cell_id)
                            .order_by(AuditEventRow.seq.desc()).limit(1))).first()
                        heads[key] = (last[0], last[1]) if last else (0, "")
                    seq, prev = heads[key]
                    e = build(prev)
                    heads[key] = (seq + 1, e.event_hash)
                    built.append(e)
                    s.add(AuditEventRow(
                        id=e.id, tenant_id=e.tenant_id, cell_id=e.cell_id, seq=seq + 1,
                        event_type=_plain(e.event_type), severity=_plain(e.severity),
                        timestamp=e.timestamp, details=e.details, source_ip=e.source_ip,
                        api_key_id=e.api_key_id, request_id=e.request_id,
                        previous_hash=e.previous_hash, event_hash=e.event_hash))
                try:
                    await s.commit()
                    return built
                except IntegrityError:
                    await s.rollback()
                except OperationalError as exc:        # SQLite writer lock; PG never lands here
                    await s.rollback()
                    if "locked" not in str(exc).lower():
                        raise
            await asyncio.sleep(random.uniform(0, 0.005 * (attempt + 1)))
        raise AuditWriteError("could not append to the audit chain (contention)")

    async def query(self, tenant_id, cell_id, event_type, severity, start_time, end_time, limit):
        q = select(AuditEventRow).where(AuditEventRow.tenant_id == tenant_id)
        if cell_id:
            q = q.where(AuditEventRow.cell_id == cell_id)
        if event_type:
            q = q.where(AuditEventRow.event_type == _plain(event_type))
        if severity:
            q = q.where(AuditEventRow.severity == _plain(severity))
        if start_time:
            q = q.where(AuditEventRow.timestamp >= _naive_utc(start_time))
        if end_time:
            q = q.where(AuditEventRow.timestamp <= _naive_utc(end_time))
        q = q.order_by(AuditEventRow.timestamp.desc(), AuditEventRow.seq.desc()).limit(limit)
        async with self._sf() as s:
            return [self._to_event(r) for r in (await s.execute(q)).scalars()]

    async def chain(self, tenant_id, cell_id):
        after = 0
        while True:
            async with self._sf() as s:
                rows = (await s.execute(
                    select(AuditEventRow).where(
                        AuditEventRow.tenant_id == tenant_id, AuditEventRow.cell_id == cell_id,
                        AuditEventRow.seq > after).order_by(AuditEventRow.seq).limit(self.PAGE)
                )).scalars().all()
            if not rows:
                return
            after = rows[-1].seq
            # A deleted row cannot pass silently: the verifier checks every previous_hash link
            # (head deletion, middle deletion) and signed checkpoints (tail deletion).
            yield [self._to_event(r) for r in rows]
            if len(rows) < self.PAGE:
                return

    async def head(self, tenant_id, cell_id):
        async with self._sf() as s:
            row = (await s.execute(
                select(AuditEventRow.seq, AuditEventRow.event_hash)
                .where(AuditEventRow.tenant_id == tenant_id, AuditEventRow.cell_id == cell_id)
                .order_by(AuditEventRow.seq.desc()).limit(1))).first()
        return (row[0], row[1]) if row else (0, "")

    async def add_checkpoint(self, tenant_id, cell_id, rec):
        async with self._sf() as s:
            s.add(AuditCheckpointRow(
                id=uuid.uuid4(), tenant_id=tenant_id, cell_id=cell_id, length=rec.length,
                head=rec.head, key_id=rec.key_id, envelope=rec.envelope))
            await s.commit()

    async def checkpoints(self, tenant_id, cell_id):
        async with self._sf() as s:
            rows = (await s.execute(
                select(AuditCheckpointRow).where(
                    AuditCheckpointRow.tenant_id == tenant_id, AuditCheckpointRow.cell_id == cell_id)
                .order_by(AuditCheckpointRow.length))).scalars().all()
        return [CheckpointRecord(r.length, r.head, r.key_id, r.envelope) for r in rows]

    async def advanced_chains(self, since):
        ev = select(AuditEventRow.tenant_id, AuditEventRow.cell_id,
                    func.max(AuditEventRow.seq).label("n"))
        if since is not None:
            ev = ev.where(AuditEventRow.timestamp >= _naive_utc(since))
        ev = ev.group_by(AuditEventRow.tenant_id, AuditEventRow.cell_id)
        cp = select(AuditCheckpointRow.tenant_id, AuditCheckpointRow.cell_id,
                    func.max(AuditCheckpointRow.length).label("n")).group_by(
            AuditCheckpointRow.tenant_id, AuditCheckpointRow.cell_id)
        async with self._sf() as s:
            chains = (await s.execute(ev)).all()
            done = {(t, c): n for t, c, n in (await s.execute(cp)).all()}
        return [(t, c) for t, c, n in chains if n > done.get((t, c), 0)]
