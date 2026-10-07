"""Group commit for audit events: fewer transactions, same chain guarantees, no silent gaps."""

import asyncio
import time
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aijailer.db.base import Base
from aijailer.models.audit import EventType, Severity
from aijailer.models.audit_log import AuditCheckpointRow, AuditEventRow
from aijailer.services.attestation import Ed25519Signer
from aijailer.services.audit_service import AuditService, _batch_kwargs, AuditConfigError
from aijailer.services.audit_store import DbAuditStore

pytestmark = pytest.mark.asyncio


class SpyStore(DbAuditStore):
    def __init__(self, sf):
        super().__init__(sf)
        self.batches: list[int] = []
        self.fail_next = 0

    async def append_batch(self, items):
        if self.fail_next:
            self.fail_next -= 1
            raise ConnectionError("database unavailable")
        self.batches.append(len(items))
        return await super().append_batch(items)


@pytest.fixture
async def sf(tmp_path):
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/b.db", connect_args={"timeout": 30})
    async with eng.begin() as c:
        await c.run_sync(lambda s: Base.metadata.create_all(
            s, tables=[AuditEventRow.__table__, AuditCheckpointRow.__table__]))
    yield async_sessionmaker(eng, expire_on_commit=False)
    await eng.dispose()


def svc(sf, **kw):
    store = SpyStore(sf)
    return AuditService(signer=Ed25519Signer.from_secret("k"), store=store, **kw), store


def sub(s, t, c, i, **kw):
    return s.submit_event(t, c, EventType.NETWORK, details={"i": i}, **kw)


async def test_many_events_become_one_transaction_and_the_chains_verify(sf):
    s, store = svc(sf, batch_max_events=500, batch_max_delay=5)
    chains = [(uuid.uuid4(), uuid.uuid4()) for _ in range(50)]
    for i in range(300):
        t, c = chains[i % 50]
        assert sub(s, t, c, i)
    assert s.batch_metrics()["pending"] == 300 and store.batches == []      # nothing written yet
    await s.flush()
    assert store.batches == [300]                                           # ONE commit for all
    for t, c in chains:
        assert (await s.verify(t, c)).length == 6 and (await s.verify(t, c)).ok
    m = s.batch_metrics()
    assert (m["pending"], m["flushed_total"], m["flushes_total"]) == (0, 300, 1)


async def test_per_chain_order_is_the_submission_order(sf):
    s, _ = svc(sf, batch_max_delay=5)
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(40):
        sub(s, t, c, i)
    await s.flush()
    got = [e.details["i"] for e in reversed(await s.query_events(t, c, limit=100))]
    assert got == list(range(40))


async def test_a_batch_is_written_when_full_and_otherwise_after_the_delay(sf):
    s, store = svc(sf, batch_max_events=5, batch_max_delay=0.4)
    t, c = uuid.uuid4(), uuid.uuid4()
    t0 = time.monotonic()
    for i in range(5):
        sub(s, t, c, i)
    while store.batches == [] and time.monotonic() - t0 < 2:
        await asyncio.sleep(0.01)
    assert store.batches == [5] and time.monotonic() - t0 < 0.35          # size trigger, not delay
    sub(s, t, c, 99)
    await asyncio.sleep(0.1)
    assert s.batch_metrics()["pending"] == 1                              # waiting for the delay
    await asyncio.sleep(0.6)
    assert s.batch_metrics()["pending"] == 0 and store.batches == [5, 1]


async def test_a_durable_event_flushes_earlier_batched_ones_first(sf):
    s, _ = svc(sf, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    sub(s, t, c, 1)
    sub(s, t, c, 2)
    await s.record_event(t, c, EventType.LIFECYCLE, details={"i": 3})
    sub(s, t, c, 4)
    await s.flush()
    # CHAIN order (seq), not timestamp order: the hash chain must reflect what happened when
    async with sf() as sess:
        rows = (await sess.execute(text("select details from audit_events order by seq"))).scalars()
        order = [(d if isinstance(d, dict) else __import__("json").loads(d)) for d in rows]
    assert [list(d.values())[0] for d in order] == [1, 2, 3, 4]
    assert (await s.verify(t, c)).ok


async def test_the_timestamp_is_when_it_happened_not_when_it_was_written(sf):
    s, _ = svc(sf, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    sub(s, t, c, 1)
    await asyncio.sleep(0.3)
    written = time.time()
    await s.flush()
    (e,) = await s.query_events(t, c)
    from datetime import UTC
    assert written - e.timestamp.replace(tzinfo=UTC).timestamp() >= 0.25


async def test_queries_see_events_this_process_just_submitted(sf):
    s, _ = svc(sf, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    sub(s, t, c, 1)
    assert len(await s.query_events(t, c)) == 1                           # no explicit flush needed


async def test_a_full_queue_drops_the_newest_and_leaves_an_explicit_gap_marker(sf):
    s, _ = svc(sf, batch_max_events=3, batch_queue_max=3, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    results = [sub(s, t, c, i) for i in range(10)]
    assert results == [True] * 3 + [False] * 7
    assert s.batch_metrics()["dropped_total"] == 7
    await s.flush()
    evs = list(reversed(await s.query_events(t, c, limit=50)))
    assert [e.details.get("i") for e in evs if "i" in e.details] == [0, 1, 2]
    (marker,) = [e for e in evs if e.details.get("action") == "audit_events_dropped"]
    assert marker.details["count"] == 7 and marker.severity == Severity.CRITICAL
    assert (await s.verify(t, c)).ok                                      # the gap is in the signed chain


async def test_database_outage_keeps_the_batch_and_retries_without_loss_or_duplicates(sf):
    s, store = svc(sf, batch_max_events=100, batch_max_delay=0.05)
    s.batcher._retry_delay = 0.05
    store.fail_next = 2
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(10):
        sub(s, t, c, i)
    deadline = time.monotonic() + 5
    while s.batch_metrics()["pending"] and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    sub(s, t, c, 10)                                                      # arrives after the failures
    await s.flush()
    got = [e.details["i"] for e in reversed(await s.query_events(t, c, limit=50))]
    assert got == list(range(11))
    assert s.batch_metrics()["flush_failures_total"] == 2 and (await s.verify(t, c)).ok


async def test_a_failed_flush_raises_to_an_explicit_flush_and_keeps_the_events(sf):
    s, store = svc(sf, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    sub(s, t, c, 1)
    store.fail_next = 1
    with pytest.raises(ConnectionError):
        await s.flush()
    assert s.batch_metrics()["pending"] == 1
    await s.flush()
    assert len(await s.query_events(t, c)) == 1


async def test_drop_counters_survive_a_failed_flush(sf):
    s, store = svc(sf, batch_max_events=2, batch_queue_max=2, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(5):
        sub(s, t, c, i)
    store.fail_next = 1
    with pytest.raises(ConnectionError):
        await s.flush()
    await s.flush()
    evs = await s.query_events(t, c, limit=50)
    assert [e.details["count"] for e in evs if e.details.get("action") == "audit_events_dropped"] == [3]
    assert sorted(e.details["i"] for e in evs if "i" in e.details) == [0, 1]


async def test_close_drains_the_queue_then_refuses_new_events(sf):
    s, _ = svc(sf, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(7):
        sub(s, t, c, i)
    await s.close()
    async with sf() as sess:                    # straight from the table: not via a flushing query
        assert (await sess.execute(text("select count(*) from audit_events"))).scalar() == 7
    assert sub(s, t, c, 99) is False


async def test_batched_and_durable_writers_race_on_one_chain_without_loss(sf):
    s, _ = svc(sf, batch_max_events=7, batch_max_delay=0.01)
    t, c = uuid.uuid4(), uuid.uuid4()

    async def durable(i):
        await s.record_event(t, c, EventType.LIFECYCLE, details={"d": i})
    tasks = [asyncio.create_task(durable(i)) for i in range(15)]
    for i in range(60):
        sub(s, t, c, i)
        if i % 10 == 0:
            await asyncio.sleep(0.005)
    await asyncio.gather(*tasks)
    await s.flush()
    evs = await s.query_events(t, c, limit=200)
    assert len(evs) == 75
    assert sorted(e.details["i"] for e in evs if "i" in e.details) == list(range(60))
    assert sorted(e.details["d"] for e in evs if "d" in e.details) == list(range(15))
    async with sf() as sess:
        seqs = sorted((await sess.execute(text("select seq from audit_events"))).scalars())
    assert seqs == list(range(1, 76)) and (await s.verify(t, c)).ok


async def test_the_proxy_audit_sink_uses_the_batched_path(monkeypatch):
    from aijailer.netpolicy import runtime
    calls = []

    class Fake:
        def submit_event(self, **kw):
            calls.append(kw)

        async def record_event(self, **kw):
            raise AssertionError("per-request decisions must not do a synchronous write")
    from aijailer.services import audit_service
    monkeypatch.setattr(audit_service, "get_audit_service", lambda: Fake())
    cell, tenant = uuid.uuid4(), uuid.uuid4()
    runtime.remember_tenant(cell, tenant)
    runtime._audit_sink(cell, {"decision": "deny", "host": "x"})
    runtime._audit_sink(cell, {"decision": "allow", "host": "y"})
    runtime._audit_sink(uuid.uuid4(), {"decision": "allow"})              # unknown cell: ignored
    assert [(k["severity"], k["event_type"]) for k in calls] == [
        (Severity.WARNING, EventType.NETWORK), (Severity.INFO, EventType.NETWORK)]


async def test_batch_config_is_validated(monkeypatch):
    from aijailer.core.config import get_settings
    monkeypatch.setenv("AUDIT_BATCH_MAX_EVENTS", "100")
    monkeypatch.setenv("AUDIT_BATCH_QUEUE_MAX", "50")                     # smaller than a batch
    with pytest.raises(AuditConfigError):
        _batch_kwargs(get_settings())
    monkeypatch.setenv("AUDIT_BATCH_QUEUE_MAX", "5000")
    monkeypatch.setenv("AUDIT_BATCH_MAX_DELAY_MS", "250")
    assert _batch_kwargs(get_settings()) == {
        "batch_max_events": 100, "batch_max_delay": 0.25, "batch_queue_max": 5000}


async def test_memory_backend_batches_too_so_dev_behaves_like_prod():
    s = AuditService(batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(5):
        sub(s, t, c, i)
    assert s._events == []                                                # queued, not yet written
    assert len(await s.query_events(t, c)) == 5 and (await s.verify(t, c)).ok


async def test_batch_metrics_are_exported_with_the_right_names_and_values(sf):
    from aijailer.core import promtext
    s, _ = svc(sf, batch_max_events=2, batch_queue_max=2, batch_max_delay=60)
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(5):
        sub(s, t, c, i)
    text_ = promtext.render(s.prometheus_families())
    assert "aijailer_audit_batch_pending 2\n" in text_
    assert "aijailer_audit_batch_queue_capacity 2\n" in text_
    assert "aijailer_audit_events_dropped_total 3\n" in text_
    assert "# TYPE aijailer_audit_events_dropped_total counter" in text_
    await s.flush()
    text_ = promtext.render(s.prometheus_families())
    assert "aijailer_audit_batch_pending 0\n" in text_
    assert "aijailer_audit_batch_events_flushed_total 3\n" in text_       # 2 events + 1 gap marker
