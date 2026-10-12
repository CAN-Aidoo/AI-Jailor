"""Appenders to ONE audit chain on a real PostgreSQL.

The chain is (tenant, cell) with a unique `seq`; writers used to race on that constraint and retry with a tiny
back-off, so with enough concurrent writers an unlucky one could lose every round and fail with
`AuditWriteError: ... (contention)` (about 1 run in 30 in the quota concurrency test). The store now takes a
transaction-scoped advisory lock per chain on PostgreSQL, so writers queue instead of colliding.

These tests set ATTEMPTS = 1: with the old optimistic scheme a collision then fails the write for certain, so a
pass here means collisions no longer happen, not that the retry budget happened to be enough.
"""
import asyncio
import uuid

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aijailer.db.base import Base
from aijailer.models.audit import EventType, Severity
from aijailer.models.audit_log import AuditCheckpointRow, AuditEventRow
from aijailer.services.attestation import Ed25519Signer
from aijailer.services.audit_service import AuditService
from aijailer.services.audit_store import DbAuditStore
from tests.pgmigrate import admin_url  # noqa: F401  (fixture: skips without a PostgreSQL)
from tests import pgserver


@pytest.fixture
async def sf(admin_url):
    url = await pgserver.new_database("audit_chain")
    eng = create_async_engine(url, pool_size=30, max_overflow=60)
    async with eng.begin() as c:
        await c.run_sync(lambda s: Base.metadata.create_all(
            s, tables=[AuditEventRow.__table__, AuditCheckpointRow.__table__]))
    yield async_sessionmaker(eng, expire_on_commit=False)
    await eng.dispose()
    await pgserver.drop_database(url)


def service(sf, attempts=1):
    store = DbAuditStore(sf)
    store.ATTEMPTS = attempts
    return AuditService(signer=Ed25519Signer.from_secret("k"), store=store), store


async def seqs(sf, t, c):
    async with sf() as s:
        return sorted((await s.execute(sa.select(AuditEventRow.seq).where(
            AuditEventRow.tenant_id == t, AuditEventRow.cell_id == c))).scalars())


async def test_concurrent_standalone_appends_to_one_chain_all_succeed_on_the_first_attempt(sf):
    svc, _ = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()
    await asyncio.gather(*[svc.record_event(t, c, EventType.SECRET, details={"i": i}) for i in range(40)])
    assert await seqs(sf, t, c) == list(range(1, 41))
    assert (await svc.verify(t, c)).ok


async def test_concurrent_in_transaction_appends_to_one_chain_all_succeed_on_the_first_attempt(sf):
    svc, _ = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()

    async def one(i):
        async with sf() as s:
            await svc.record_event(t, c, EventType.LIFECYCLE, details={"i": i}, session=s)
            await s.commit()
    await asyncio.gather(*[one(i) for i in range(40)])
    assert await seqs(sf, t, c) == list(range(1, 41))
    assert (await svc.verify(t, c)).ok


async def test_mixed_in_transaction_and_standalone_writers_lose_nothing(sf):
    svc, _ = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()

    async def in_tx(i):
        async with sf() as s:
            await svc.record_event(t, c, EventType.LIFECYCLE, details={"tx": i}, session=s)
            await s.commit()
    await asyncio.gather(*[in_tx(i) for i in range(20)],
                         *[svc.record_event(t, c, EventType.SECRET, details={"own": i}) for i in range(20)])
    assert await seqs(sf, t, c) == list(range(1, 41))
    assert (await svc.verify(t, c)).ok


async def test_a_rolled_back_in_transaction_append_releases_the_chain(sf):
    """The advisory lock is transaction-scoped: rolling back frees the chain for the next writer."""
    svc, _ = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()
    async with sf() as s:
        await svc.record_event(t, c, EventType.LIFECYCLE, details={"i": "doomed"}, session=s)
        await s.rollback()
    await asyncio.wait_for(svc.record_event(t, c, EventType.SECRET, details={"i": "after"}), 5)
    assert await seqs(sf, t, c) == [1] and (await svc.verify(t, c)).ok


async def test_batches_over_the_same_chains_in_opposite_orders_do_not_deadlock(sf):
    """append_batch takes the chain locks in one global order; opposite orders would deadlock."""
    svc, store = service(sf, attempts=3)
    a, b = (uuid.uuid4(), uuid.uuid4()), (uuid.uuid4(), uuid.uuid4())

    async def batch(order):
        items = [(k[0], k[1], svc._builder(k[0], k[1], EventType.NETWORK, Severity.INFO, {"k": 1},
                                           None, None, None)) for k in order]      # fresh event ids each time
        await store.append_batch(items)
    for _ in range(15):
        await asyncio.gather(batch([a, b]), batch([b, a]), batch([a, b]), batch([b, a]))
    assert len(await seqs(sf, *a)) == 60 and len(await seqs(sf, *b)) == 60

