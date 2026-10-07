"""Concurrent quota changes: no lost update, no torn history, no over-admission.

The tests fire many requests at once and check INVARIANTS (linearizability of the audit history,
conservation of the snapshot count), never timing.

Stand-in for PostgreSQL: SQLite has no row locks, so the test database begins every transaction with
``BEGIN IMMEDIATE`` (the recipe from the SQLAlchemy docs), which serialises writers the way the
tenant row's ``SELECT ... FOR UPDATE`` does in production, only coarser (whole database). That
checks the logic that sits on top of the lock (read-before-write under the lock, audit event in the
same transaction, reserve-then-commit for snapshots). It does NOT prove the Postgres lock itself;
`test_update_takes_the_tenant_row_lock` asserts the statement that requests it."""

import asyncio
import hashlib
import random
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from aijailer.api.app import create_app
from aijailer.db.base import Base, get_db
from aijailer.models.tenant import ApiKey, Tenant
from aijailer.services import audit_service as asv
from aijailer.services.attestation import Ed25519Signer
from aijailer.services.audit_store import DbAuditStore
from aijailer.services.tenant_quota import DEFAULTS, FIELDS, NIL

OP = {"Authorization": "Bearer op-secret"}
KEY = "aj_test_concurrent_1"
TENANT_AUTH = {"Authorization": f"Bearer {KEY}"}


async def _build(tmp_path, monkeypatch, audit_kind):
    """App sessions use the BEGIN IMMEDIATE engine. The audit store gets its OWN plain engine (WAL):
    on SQLite the write lock is database-wide, so a store session opened while a request holds it
    would wait on the request that is waiting for it. On PostgreSQL those touch different rows and
    never block each other, so this is emulation plumbing, not application behaviour."""
    monkeypatch.setenv("ADMIN_TOKEN", "op-secret")
    path = f"sqlite+aiosqlite:///{tmp_path}/c.db"
    eng = create_async_engine(path, connect_args={"timeout": 60})

    @event.listens_for(eng.sync_engine, "connect")
    def _no_implicit_begin(dbapi_connection, _):
        dbapi_connection.isolation_level = None            # we issue BEGIN ourselves

    @event.listens_for(eng.sync_engine, "begin")
    def _begin_immediate(conn):
        conn.exec_driver_sql("BEGIN IMMEDIATE")            # take the write lock up front

    async with eng.begin() as c:
        await c.run_sync(Base.metadata.create_all)
        await c.exec_driver_sql("PRAGMA journal_mode=WAL")
    sf = async_sessionmaker(eng, expire_on_commit=False)
    audit_eng = create_async_engine(path, connect_args={"timeout": 60})
    if audit_kind == "db":
        audit = asv.AuditService(signer=Ed25519Signer.from_secret("k"),
                                 store=DbAuditStore(async_sessionmaker(audit_eng, expire_on_commit=False)))
    else:
        audit = asv.AuditService()                         # in-memory: no DB writes of its own
    monkeypatch.setattr(asv, "_audit_service", audit)
    async with sf() as s:
        t = Tenant(name="t", slug=f"t-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                   max_concurrent_cells=50)
        s.add(t)
        await s.flush()
        s.add(ApiKey(tenant_id=t.id, created_by=t.id, name="k",
                     key_hash=hashlib.sha256(KEY.encode()).hexdigest(), key_prefix="aj_test_conc",
                     role="admin", status="active"))
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
                         base_url="http://t", timeout=120)
    return sf, audit, tid, client, (eng, audit_eng)


@pytest.fixture
async def world(tmp_path, monkeypatch):
    """Quota changes with the database audit log."""
    sf, audit, tid, client, engines = await _build(tmp_path, monkeypatch, "db")
    yield sf, audit, tid, client
    await client.aclose()
    for e in engines:
        await e.dispose()


@pytest.fixture
async def world_mem(tmp_path, monkeypatch):
    """Snapshot admission under concurrent limit changes (in-memory audit log, see _build)."""
    sf, audit, tid, client, engines = await _build(tmp_path, monkeypatch, "memory")
    yield sf, audit, tid, client
    await client.aclose()
    for e in engines:
        await e.dispose()


def qurl(tid):
    return f"/v1/admin/tenants/{tid}/quotas"


async def history_oldest_first(client, tid):
    d = (await client.get(qurl(tid) + "/audit?limit=500", headers=OP)).json()["data"]
    assert d["next_before"] is None and d["chain_intact"] is True
    return list(reversed(d["events"]))


def random_ops(seed, n):
    rng = random.Random(seed)
    fields = list(FIELDS)
    ops = []
    for _ in range(n):
        if rng.random() < 0.15:
            ops.append(("DELETE", None))
        else:
            ks = rng.sample(fields, rng.choice([1, 1, 2, 3]))
            ops.append(("PATCH", {k: rng.randint(1, 9) for k in ks}))     # small range: some no-ops
    return ops


@pytest.mark.asyncio
@pytest.mark.parametrize("seed", [1, 2, 3])
async def test_concurrent_mixed_changes_are_linearizable(world, seed):
    """Replay the audit history in order against the defaults: every event's `from` must equal the
    state at that point (no write was based on a stale read), and the replayed result must equal
    what the database holds (no update was lost or applied but unrecorded)."""
    sf, audit, tid, client = world
    ops = random_ops(seed, 40)

    async def run(op):
        method, body = op
        if method == "DELETE":
            return await client.delete(qurl(tid), headers=OP)
        return await client.patch(qurl(tid), headers=OP, json=body)
    responses = await asyncio.gather(*[run(o) for o in ops])
    assert {r.status_code for r in responses} == {200}, [r.text for r in responses if r.status_code != 200]

    final = (await client.get(qurl(tid), headers=OP)).json()["data"]["limits"]
    events = await history_oldest_first(client, tid)
    assert events, "40 random changes produced no audit event at all"
    state = dict(DEFAULTS)
    for e in events:
        for k, was in (e["from"] or {}).items():
            assert state[k] == was, f"event based on a stale read: {k} was {state[k]}, event says {was}"
        state.update(e["to"])
    assert state == final                                    # nothing lost, nothing unrecorded
    # only real changes are recorded, and the chain is gap-free and verifies
    assert all(e["from"] != e["to"] for e in events)
    assert (await audit.verify(tid, NIL)).ok
    async with sf() as s:
        seqs = sorted((await s.execute(text("select seq from audit_events"))).scalars())
    assert seqs == list(range(1, len(seqs) + 1))


@pytest.mark.asyncio
async def test_concurrent_writers_to_the_same_field_leave_one_of_the_values_and_a_consistent_trail(world):
    sf, audit, tid, client = world
    values = list(range(1, 31))
    rs = await asyncio.gather(*[client.patch(qurl(tid), headers=OP, json={"max_snapshot_count": v})
                                for v in values])
    assert {r.status_code for r in rs} == {200}
    final = (await client.get(qurl(tid), headers=OP)).json()["data"]["limits"]["max_snapshot_count"]
    events = await history_oldest_first(client, tid)
    assert final in values and events[-1]["to"] == {"max_snapshot_count": final}      # last write wins
    # a single linear chain of values: each change starts from where the previous one ended
    assert events[0]["from"] == {"max_snapshot_count": DEFAULTS["max_snapshot_count"]}
    for prev, cur in zip(events, events[1:], strict=False):
        assert cur["from"] == prev["to"]
    assert sorted(e["to"]["max_snapshot_count"] for e in events) == sorted(
        v for v in values if v != DEFAULTS["max_snapshot_count"])                      # every write recorded once


@pytest.mark.asyncio
async def test_quota_changes_and_other_writers_on_the_same_audit_chain_lose_nothing(world):
    """Quota events join the caller's transaction; secret-style events commit on their own. Both
    extend the tenant's nil-cell chain at the same time."""
    from aijailer.models.audit import EventType
    sf, audit, tid, client = world

    async def other(i):
        await audit.record_event(tid, NIL, EventType.SECRET, details={"action": "created", "i": i})
    quota = [client.patch(qurl(tid), headers=OP, json={"max_snapshot_count": 200 + i}) for i in range(15)]
    rs = await asyncio.gather(*quota, *[other(i) for i in range(15)])
    assert {getattr(r, "status_code", 200) for r in rs} == {200}
    assert (await audit.verify(tid, NIL)).ok
    async with sf() as s:
        n = (await s.execute(text("select count(*) from audit_events"))).scalar()
        seqs = sorted((await s.execute(text("select seq from audit_events"))).scalars())
    assert n == 30 and seqs == list(range(1, 31))
    assert len([e for e in await history_oldest_first(client, tid)]) == 15          # quota history unaffected by the others


@pytest.mark.asyncio
async def test_snapshots_are_never_admitted_beyond_the_limit_while_it_is_being_lowered(world_mem):
    """Reserve-then-commit under concurrency: with the limit at 6 and many parallel creations, at
    most 6 succeed even while an operator lowers the limit mid-flight; everything else is a clean 429."""
    sf, audit, tid, client = world_mem
    await client.patch(qurl(tid), headers=OP, json={
        "max_snapshot_count": 6, "max_snapshots_per_cell": 1000,
        "max_snapshot_storage_gb": 100000, "max_snapshot_storage_per_cell_gb": 100000})
    cell = (await client.post("/v1/cells", headers=TENANT_AUTH,
                              json={"name": "c", "image": "base-python"})).json()["data"]["id"]

    async def snap():
        return await client.post(f"/v1/cells/{cell}/snapshots", headers=TENANT_AUTH, json={})

    async def lower():
        await asyncio.sleep(0.02)
        return await client.patch(qurl(tid), headers=OP, json={"max_snapshot_count": 3})
    results = await asyncio.gather(*[snap() for _ in range(24)], lower())
    snaps, lowered = results[:-1], results[-1]
    assert lowered.status_code == 200
    codes = [r.status_code for r in snaps]
    assert set(codes) <= {202, 429}, codes                    # no 500s, no half-states
    ok = codes.count(202)
    assert 1 <= ok <= 6                                        # never above the limit that was in force
    q = (await client.get("/v1/snapshots/quota", headers=TENANT_AUTH)).json()["data"]
    assert q["count"] == ok and q["max_count"] == 3            # what we admitted is what exists
    # whatever the interleaving, the lowered limit now governs: one more is refused iff already at/over it
    more = await client.post(f"/v1/cells/{cell}/snapshots", headers=TENANT_AUTH, json={})
    assert (more.status_code == 429) == (ok >= 3)
    async with sf() as s:
        stuck = (await s.execute(text("select count(*) from snapshots where status = 'creating'"))).scalar()
    assert stuck == 0                                          # no reservation left dangling


@pytest.mark.asyncio
async def test_parallel_changes_to_different_tenants_do_not_interfere(world):
    sf, audit, tid, client = world
    async with sf() as s:
        others = []
        for i in range(4):
            t = Tenant(name=f"o{i}", slug=f"o{i}-{uuid.uuid4().hex[:5]}", status="active", tier="pro",
                       max_concurrent_cells=5)
            s.add(t)
            others.append(t)
        await s.commit()
        ids = [t.id for t in others]
    reqs = [client.patch(qurl(t), headers=OP, json={"max_snapshot_count": 10 + j})
            for j, t in enumerate(ids) for _ in range(5)] + [
        client.patch(qurl(tid), headers=OP, json={"max_snapshot_count": 77})]
    rs = await asyncio.gather(*reqs)
    assert {r.status_code for r in rs} == {200}
    for j, t in enumerate(ids):
        assert (await client.get(qurl(t), headers=OP)).json()["data"]["limits"]["max_snapshot_count"] == 10 + j
        ev = await history_oldest_first(client, t)
        assert len(ev) == 1 and ev[0]["to"] == {"max_snapshot_count": 10 + j}      # 5 identical writes = 1 change
    assert (await client.get(qurl(tid), headers=OP)).json()["data"]["limits"]["max_snapshot_count"] == 77
