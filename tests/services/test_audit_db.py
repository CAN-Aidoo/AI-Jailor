"""Database-backed audit log: persistence, chain integrity through the DB, concurrency, tamper and
truncation detection, checkpoints across restarts, configuration rules."""

import asyncio
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aijailer.db.base import Base
from aijailer.models.audit import EventType
from aijailer.models.audit_log import AuditCheckpointRow, AuditEventRow
from aijailer.services.attestation import Ed25519Signer
from aijailer.services.audit_service import (
    AuditCheckpointer,
    AuditConfigError,
    AuditService,
    build_audit_service,
)
from aijailer.services.audit_store import DbAuditStore

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def sf(tmp_path):
    # A FILE database: several real connections, like production (the in-memory test DB shares one).
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/audit.db", connect_args={"timeout": 30})
    async with eng.begin() as c:
        await c.run_sync(lambda sync: Base.metadata.create_all(
            sync, tables=[AuditEventRow.__table__, AuditCheckpointRow.__table__]))
    yield async_sessionmaker(eng, expire_on_commit=False)
    await eng.dispose()


def service(sf, signer=None):
    return AuditService(signer=signer or Ed25519Signer.from_secret("k"), store=DbAuditStore(sf))


async def fill(svc, n=5, t=None, c=None):
    t, c = t or uuid.uuid4(), c or uuid.uuid4()
    for i in range(n):
        await svc.record_event(t, c, EventType.EXECUTION, details={"i": i})
    return t, c


async def test_events_roundtrip_with_awkward_details_and_the_chain_still_verifies(sf):
    svc = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()
    odd = {"uuid": uuid.uuid4(), "when": datetime(2026, 1, 2, 3, 4, 5, 678901, tzinfo=UTC),
           "nested": {"a": [1, 2.5, None, True], "ünï": "çödé"}, "big": 2**53, "f": 0.1 + 0.2}
    sent = await svc.record_event(t, c, EventType.POLICY_VIOLATION, details=odd,
                                  source_ip="10.0.0.1", api_key_id=uuid.uuid4(), request_id="r-1")
    (got,) = await svc.query_events(t, c)
    assert got.event_hash == sent.event_hash and got.details == sent.details
    assert got.timestamp == sent.timestamp and got.severity == sent.severity
    assert got.details["uuid"] == str(odd["uuid"])               # normalised to what was hashed
    assert (await svc.verify(t, c)).ok


async def test_survives_a_restart_and_the_chain_continues(sf):
    t, c = await fill(service(sf), 3)
    reborn = service(sf)                                          # new process, same database
    assert len(await reborn.query_events(t, c)) == 3
    last = (await reborn.query_events(t, c, limit=1))[0]
    nxt = await reborn.record_event(t, c, EventType.NETWORK)
    assert nxt.previous_hash == last.event_hash
    assert (await reborn.verify(t, c)).length == 4


async def test_concurrent_writers_on_one_chain_lose_nothing_and_keep_it_linear(sf):
    svc = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()
    await asyncio.gather(*[svc.record_event(t, c, EventType.EXECUTION, details={"i": i})
                           for i in range(25)])
    async with sf() as s:
        seqs = sorted((await s.execute(text("select seq from audit_events"))).scalars())
    assert seqs == list(range(1, 26))
    assert sorted(e.details["i"] for e in await svc.query_events(t, c, limit=100)) == list(range(25))
    assert (await svc.verify(t, c)).ok


async def test_chains_are_independent_and_queries_tenant_scoped(sf):
    svc = service(sf)
    t, c1 = await fill(svc, 2)
    c2 = uuid.uuid4()
    await fill(svc, 3, t, c2)
    other, _ = await fill(svc, 4)
    assert len(await svc.query_events(t, c1)) == 2 and len(await svc.query_events(t, c2)) == 3
    assert len(await svc.query_events(t)) == 5 and len(await svc.query_events(other)) == 4
    assert (await svc.query_events(t, c2))[0].previous_hash != ""
    kinds = await svc.query_events(t, event_type="network"), await svc.query_events(t, event_type="execution", limit=2)
    assert kinds[0] == [] and len(kinds[1]) == 2


async def test_time_filters_and_severity(sf):
    svc = service(sf)
    t, c = await fill(svc, 3)
    now = datetime.now(UTC)
    assert len(await svc.query_events(t, start_time=now.replace(year=2000))) == 3   # aware input ok
    assert await svc.query_events(t, start_time=now.replace(year=2100)) == []
    assert await svc.query_events(t, end_time=now.replace(year=2000)) == []
    assert await svc.query_events(t, severity="critical") == []


async def test_tampering_is_detected(sf):
    svc = service(sf)
    t, c = await fill(svc, 5)
    async with sf() as s:                                           # attacker with DB write access
        await s.execute(update(AuditEventRow).where(AuditEventRow.seq == 3).values(details={"i": 999}))
        await s.commit()
    r = await svc.verify(t, c)
    assert not r.ok and "modified" in r.problem


async def test_deleting_head_or_middle_rows_is_detected(sf):
    svc = service(sf)
    for seq in (1, 3):
        t, c = await fill(svc, 5)
        async with sf() as s:
            await s.execute(delete(AuditEventRow).where(
                AuditEventRow.tenant_id == t, AuditEventRow.cell_id == c, AuditEventRow.seq == seq))
            await s.commit()
        assert not (await svc.verify(t, c)).ok, seq


async def test_tail_truncation_needs_a_checkpoint_and_is_then_detected(sf):
    svc = service(sf)
    t, c = await fill(svc, 5)
    await svc.checkpoint(t, c)
    async with sf() as s:
        await s.execute(delete(AuditEventRow).where(
            AuditEventRow.tenant_id == t, AuditEventRow.seq >= 4))
        await s.commit()
    r = await svc.verify(t, c)
    assert not r.ok and "deleted after a checkpoint" in r.problem


async def test_consistent_rebuild_of_the_whole_chain_is_detected_by_the_checkpoint(sf):
    svc = service(sf)
    t, c = await fill(svc, 4)
    await svc.checkpoint(t, c)
    async with sf() as s:
        rows = (await s.execute(AuditEventRow.__table__.select().where(
            AuditEventRow.tenant_id == t).order_by(AuditEventRow.seq))).all()
    # rewrite event 2 and recompute every later hash consistently
    prev, evs = "", await svc.query_events(t, c, limit=10)
    evs = list(reversed(evs))
    evs[1].details["i"] = 42
    async with sf() as s:
        for r_, e in zip(rows, evs, strict=True):
            e.previous_hash = prev
            e.event_hash = svc._compute_hash(e, prev)
            prev = e.event_hash
            await s.execute(update(AuditEventRow).where(AuditEventRow.id == e.id).values(
                details=e.details, previous_hash=e.previous_hash, event_hash=e.event_hash))
        await s.commit()
    r = await svc.verify(t, c)
    assert not r.ok and "rewritten" in r.problem


async def test_checkpoints_persist_and_verify_after_restart_with_the_same_key(sf):
    t, c = await fill(service(sf), 3)
    await service(sf).checkpoint(t, c)
    reborn = service(sf)
    await reborn.record_event(t, c, EventType.EXECUTION)
    r = await reborn.verify(t, c)
    assert r.ok and r.checkpoints_checked == 1 and r.checkpoints_unverifiable == 0


async def test_checkpoints_from_another_key_are_reported_not_trusted(sf):
    t, c = await fill(service(sf), 3)
    await service(sf).checkpoint(t, c)
    stranger = service(sf, Ed25519Signer.from_secret("another"))
    r = await stranger.verify(t, c)
    assert r.ok and r.checkpoints_checked == 0 and r.checkpoints_unverifiable == 1


async def test_a_forged_checkpoint_under_our_key_id_fails(sf):
    svc = service(sf)
    t, c = await fill(svc, 3)
    await svc.checkpoint(t, c)
    async with sf() as s:
        cp = (await s.execute(AuditCheckpointRow.__table__.select())).first()
    env = dict(cp.envelope)
    env["signatures"] = [{"keyid": env["signatures"][0]["keyid"], "sig": "AAAA"}]
    async with sf() as s:
        await s.execute(update(AuditCheckpointRow).where(AuditCheckpointRow.id == cp.id).values(envelope=env))
        await s.commit()
    r = await svc.verify(t, c)
    assert not r.ok and "signature" in r.problem


async def test_checkpoint_due_only_covers_chains_that_grew(sf):
    svc = service(sf)
    t, c = await fill(svc, 2)
    _, c2 = await fill(svc, 2, t)
    assert await svc.checkpoint_due() == 2
    assert await svc.checkpoint_due() == 0
    await svc.record_event(t, c, EventType.EXECUTION)
    assert await svc.checkpoint_due() == 1
    cp = AuditCheckpointer(svc, 3600)
    assert await cp.run_once() == 0
    await svc.record_event(t, c2, EventType.EXECUTION)
    assert await cp.run_once() == 1 and await cp.run_once() == 0


async def test_the_audit_record_does_not_ride_on_the_callers_transaction(sf):
    svc = service(sf)
    t, c = uuid.uuid4(), uuid.uuid4()
    async with sf() as request_session:
        await request_session.execute(text("select 1"))
        await svc.record_event(t, c, EventType.LIFECYCLE, details={"action": "restored"})
        await request_session.rollback()                         # the request later fails
    assert len(await svc.query_events(t, c)) == 1


async def test_configuration_rules(monkeypatch):
    for k in ("AUDIT_BACKEND", "AUDIT_SIGNING_SECRET", "AIJAILER_ENV"):
        monkeypatch.delenv(k, raising=False)
    assert not build_audit_service().durable                     # dev default: memory
    monkeypatch.setenv("AUDIT_BACKEND", "db")
    assert build_audit_service().durable                         # dev + db: ephemeral key allowed
    monkeypatch.setenv("AIJAILER_ENV", "production")
    with pytest.raises(AuditConfigError, match="AUDIT_SIGNING_SECRET"):
        build_audit_service()                                    # prod + db without a secret
    monkeypatch.delenv("AUDIT_BACKEND")
    with pytest.raises(AuditConfigError):
        build_audit_service()                                    # prod default is db: same rule
    monkeypatch.setenv("AUDIT_SIGNING_SECRET", "s3cret")
    assert build_audit_service().durable
    monkeypatch.setenv("AUDIT_BACKEND", "bogus")
    with pytest.raises(AuditConfigError, match="AUDIT_BACKEND"):
        build_audit_service()
    a = Ed25519Signer.from_secret("s3cret").keyid
    monkeypatch.setenv("AUDIT_BACKEND", "memory")
    assert build_audit_service()._signer.keyid == a              # same secret => same key


def test_migration_follows_006_and_matches_the_models():
    import importlib.util
    import pathlib
    p = pathlib.Path(__file__).resolve().parents[2] / "migrations/versions/007_audit_log.py"
    spec = importlib.util.spec_from_file_location("m007", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.down_revision == "006_snapshot_storage_per_cell"
    src = p.read_text()
    for table in (AuditEventRow.__table__, AuditCheckpointRow.__table__):
        for col in table.columns:
            assert f'"{col.name}"' in src, (table.name, col.name)
    assert "BEFORE UPDATE OR DELETE" in src and "uq_audit_chain_seq" in src


async def test_checkpointer_loop_and_final_pass_on_shutdown(sf):
    svc = service(sf)
    t, c = await fill(svc, 2)
    cp = AuditCheckpointer(svc, 0.05)
    cp.start()
    await asyncio.sleep(0.3)                                      # loop pass checkpoints the chain
    assert len(await svc._store.checkpoints(t, c)) == 1
    await svc.record_event(t, c, EventType.EXECUTION)             # written after the last pass
    await cp.stop()                                               # clean shutdown leaves no gap
    cps = await svc._store.checkpoints(t, c)
    assert [x.length for x in cps][-1] == 3 and (await svc.verify(t, c)).ok


async def test_the_nil_cell_id_used_for_non_cell_events_roundtrips(sf):
    """uuid.UUID(int=0) is all digits; SQLite's NUMERIC affinity once turned it into the int 0."""
    svc = service(sf)
    t, nil = uuid.uuid4(), uuid.UUID(int=0)
    await svc.record_event(t, nil, EventType.SECRET, details={"action": "created"})
    (e,) = await svc.query_events(t, nil)
    assert e.cell_id == nil and (await svc.verify(t, nil)).ok
