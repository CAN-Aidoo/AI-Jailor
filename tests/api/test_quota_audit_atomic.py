"""Quota changes and their audit record are ONE transaction: both durable, or neither.

Needs a file-backed SQLite database (several real connections, real transactions); the shared
in-memory test database funnels every session through one connection and would hide the very
behaviour under test."""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aijailer.api.app import create_app
from aijailer.db.base import Base, get_db
from aijailer.models.audit import EventType
from aijailer.models.tenant import Tenant
from aijailer.services import audit_service as asv
from aijailer.services.attestation import Ed25519Signer
from aijailer.services.audit_store import DbAuditStore
from aijailer.services.tenant_quota import DEFAULTS, NIL, TenantQuotaService

OP = {"Authorization": "Bearer op-secret"}


class FlakyCommitSession(AsyncSession):
    """commit() fails when armed, standing in for a database error at the moment of truth."""
    fail_commits = 0

    async def commit(self):
        if FlakyCommitSession.fail_commits:
            FlakyCommitSession.fail_commits -= 1
            raise RuntimeError("commit failed")
        await super().commit()


@pytest.fixture
async def world(tmp_path, monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "op-secret")
    FlakyCommitSession.fail_commits = 0
    eng = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/q.db", connect_args={"timeout": 30})
    async with eng.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    sf = async_sessionmaker(eng, expire_on_commit=False, class_=FlakyCommitSession)
    store = DbAuditStore(sf)
    audit = asv.AuditService(signer=Ed25519Signer.from_secret("k"), store=store)
    monkeypatch.setattr(asv, "_audit_service", audit)
    async with sf() as s:
        t = Tenant(name="t", slug=f"t-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                   max_concurrent_cells=5)
        s.add(t)
        await s.commit()
        tid = t.id

    app = create_app()

    async def override():
        async with sf() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise
    app.dependency_overrides[get_db] = override
    client = AsyncClient(transport=ASGITransport(app=app, raise_app_exceptions=False),
                         base_url="http://t")
    yield sf, audit, store, tid, client
    await client.aclose()
    await eng.dispose()


async def limits(sf, tid):
    async with sf() as s:
        t = (await s.execute(select(Tenant).where(Tenant.id == tid))).scalar_one()
        return t.max_snapshot_count


async def audit_rows(sf, tid):
    async with sf() as s:
        return (await s.execute(text("select count(*) from audit_events where tenant_id = :t"),
                                {"t": tid.hex})).scalar()


@pytest.mark.asyncio
async def test_rollback_discards_both_the_change_and_its_audit_record(world):
    sf, audit, store, tid, _ = world
    async with sf() as s:
        await TenantQuotaService(s).update(tid, {"max_snapshot_count": 7})
        await s.rollback()                                    # the caller's transaction fails
    assert await limits(sf, tid) == DEFAULTS["max_snapshot_count"]
    assert await audit_rows(sf, tid) == 0                     # no phantom "it changed" record


@pytest.mark.asyncio
async def test_commit_makes_both_durable_and_the_chain_verifies(world):
    sf, audit, store, tid, _ = world
    async with sf() as s:
        await TenantQuotaService(s).update(tid, {"max_snapshot_count": 7})
        await s.commit()
    assert await limits(sf, tid) == 7 and await audit_rows(sf, tid) == 1
    (e,) = await audit.query_events(tid, NIL, event_type=EventType.LIFECYCLE)
    assert e.details["to"] == {"max_snapshot_count": 7} and (await audit.verify(tid, NIL)).ok


@pytest.mark.asyncio
async def test_an_audit_write_failure_aborts_the_change(world, monkeypatch):
    sf, audit, store, tid, _ = world

    async def boom(*a, **k):
        raise RuntimeError("audit store down")
    monkeypatch.setattr(store, "append_in_session", boom)
    async with sf() as s:
        with pytest.raises(RuntimeError):
            await TenantQuotaService(s).update(tid, {"max_snapshot_count": 7})
        await s.rollback()
    assert await limits(sf, tid) == DEFAULTS["max_snapshot_count"]       # unaudited change refused


@pytest.mark.asyncio
async def test_losing_the_sequence_race_retries_the_insert_and_keeps_the_callers_work(world):
    """Another writer extended the chain between our head read and our insert."""
    sf, audit, store, tid, _ = world
    await audit.record_event(tid, NIL, EventType.SECRET, details={"action": "created"})   # seq 1
    real = DbAuditStore._read_head
    calls = []

    async def stale_first(s, t, c):
        calls.append(1)
        return (0, "") if len(calls) == 1 else await real(s, t, c)      # first read is out of date
    store._read_head = stale_first                                        # type: ignore[method-assign]
    async with sf() as s:
        await TenantQuotaService(s).update(tid, {"max_snapshot_count": 9})
        await s.commit()
    assert len(calls) == 2                                                # retried once
    assert await limits(sf, tid) == 9                                     # the UPDATE survived the savepoint
    assert await audit_rows(sf, tid) == 2 and (await audit.verify(tid, NIL)).ok


@pytest.mark.asyncio
async def test_api_commit_failure_means_no_change_no_audit_and_no_success_response(world):
    sf, audit, store, tid, client = world
    FlakyCommitSession.fail_commits = 1                                   # the route's own commit()
    r = await client.patch(f"/v1/admin/tenants/{tid}/quotas", headers=OP,
                           json={"max_snapshot_count": 7})
    assert r.status_code == 500
    FlakyCommitSession.fail_commits = 0
    assert await limits(sf, tid) == DEFAULTS["max_snapshot_count"] and await audit_rows(sf, tid) == 0
    hist = (await client.get(f"/v1/admin/tenants/{tid}/quotas/audit", headers=OP)).json()["data"]
    assert hist["events"] == []
    # and the same request succeeds once the database is healthy
    ok = await client.patch(f"/v1/admin/tenants/{tid}/quotas", headers=OP, json={"max_snapshot_count": 7})
    assert ok.status_code == 200 and await limits(sf, tid) == 7 and await audit_rows(sf, tid) == 1


@pytest.mark.asyncio
async def test_a_success_response_means_the_change_and_audit_are_already_committed(world):
    sf, audit, store, tid, client = world
    r = await client.patch(f"/v1/admin/tenants/{tid}/quotas", headers=OP, json={"max_snapshot_count": 5})
    assert r.status_code == 200
    # read through a brand-new connection: committed, not just visible inside the request's session
    assert await limits(sf, tid) == 5 and await audit_rows(sf, tid) == 1
    d = await client.delete(f"/v1/admin/tenants/{tid}/quotas", headers=OP)
    assert d.status_code == 200 and await limits(sf, tid) == DEFAULTS["max_snapshot_count"]
    assert await audit_rows(sf, tid) == 2
    hist = (await client.get(f"/v1/admin/tenants/{tid}/quotas/audit", headers=OP)).json()["data"]
    assert [e["action"] for e in hist["events"]] == ["quota_override_reset", "quota_override_set"]
    assert hist["chain_intact"] is True and hist["durable"] is True


@pytest.mark.asyncio
async def test_a_noop_change_writes_nothing_and_the_memory_backend_still_works(world, monkeypatch):
    sf, audit, store, tid, _ = world
    async with sf() as s:
        await TenantQuotaService(s).update(tid, {"max_snapshot_count": DEFAULTS["max_snapshot_count"]})
        await s.commit()
    assert await audit_rows(sf, tid) == 0
    # memory backend: no transaction to join, the session argument is accepted and ignored
    mem = asv.AuditService()
    monkeypatch.setattr(asv, "_audit_service", mem)
    async with sf() as s:
        await TenantQuotaService(s).update(tid, {"max_snapshot_count": 3})
        await s.commit()
    assert len(await mem.query_events(tid, NIL)) == 1
