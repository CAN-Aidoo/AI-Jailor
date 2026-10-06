"""NetworkReconciler: DB -> sweep inputs, fail-static behaviour, loop resilience."""

import asyncio
import uuid

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker

from aijailer.models.cell import Cell
from aijailer.models.tenant import Tenant
from aijailer.netpolicy.cell_network import SweepReport
from aijailer.netpolicy.reconciler import NetworkReconciler


class FakeNet:
    def __init__(self):
        self.calls, self.report, self.raise_exc = [], SweepReport(), None

    async def sweep(self, live, protected, grace):
        self.calls.append((live, protected, grace))
        if self.raise_exc:
            raise self.raise_exc
        return self.report


@pytest.fixture
async def world(db_engine, db_session):
    tenant = Tenant(name="t", slug=f"t-{uuid.uuid4().hex[:6]}", status="active", tier="pro")
    db_session.add(tenant)
    await db_session.commit()
    ids = {}
    for status in ("creating", "ready", "running", "paused", "stopping", "stopped",
                   "destroying", "destroyed", "error"):
        c = Cell(tenant_id=tenant.id, name=status, image="i", status=status,
                 security_policy_id=tenant.id, network_bandwidth_mbps=25,
                 effective_policy={"network": {"egress": [{"destinations": [{"domain": "a.test"}]}]}}
                 if status == "running" else None)
        db_session.add(c)
        await db_session.flush()
        ids[status] = c.id
    await db_session.commit()
    return async_sessionmaker(db_engine, expire_on_commit=False), ids, tenant


@pytest.mark.asyncio
async def test_status_classification_and_cell_details(world):
    sessions, ids, tenant = world
    net = FakeNet()
    await NetworkReconciler(net, sessions, grace=77).run_once()
    live, protected, grace = net.calls[0]
    assert set(live) == {ids["ready"], ids["running"], ids["paused"]}
    assert protected == {ids["creating"], ids["stopping"], ids["destroying"]}
    assert grace == 77
    lc = live[ids["running"]]
    assert lc.tenant_id == tenant.id and lc.bandwidth_mbps == 25
    assert lc.network_policy == {"egress": [{"destinations": [{"domain": "a.test"}]}]}
    # stopped / destroyed / error cells are neither live nor protected -> must have no network
    for s in ("stopped", "destroyed", "error"):
        assert ids[s] not in live and ids[s] not in protected


@pytest.mark.asyncio
async def test_unreadable_database_changes_nothing(world):
    sessions, _, _ = world
    net = FakeNet()

    def broken():
        raise ConnectionError("db down")
    r = NetworkReconciler(net, broken)
    assert await r.run_once() is None
    assert net.calls == [] and r.failures == 1  # fail static: no sweep, no deletions


@pytest.mark.asyncio
async def test_broken_cells_are_marked_error_only_if_live(world):
    sessions, ids, _ = world
    net = FakeNet()
    net.report = SweepReport(broken=[ids["running"], ids["stopped"]])
    await NetworkReconciler(net, sessions).run_once()
    async with sessions() as db:
        running = await db.get(Cell, ids["running"])
        stopped = await db.get(Cell, ids["stopped"])
    assert running.status == "error" and "reconciler" in running.error_message
    assert stopped.status == "stopped"  # never resurrect/overwrite a non-live cell


@pytest.mark.asyncio
async def test_loop_survives_failures_and_stops_cleanly(world):
    sessions, _, _ = world
    net = FakeNet()
    r = NetworkReconciler(net, sessions, interval=0.01)
    net.raise_exc = RuntimeError("sweep exploded")
    await r.start(initial_pass=False)
    await asyncio.sleep(0.15)
    net.raise_exc = None
    n_before = len(net.calls)
    await asyncio.sleep(0.15)
    await r.stop()
    assert r.failures >= 2                       # exploded repeatedly, loop kept going
    assert len(net.calls) > n_before             # and recovered once the sweep worked
    done = len(net.calls)
    await asyncio.sleep(0.1)
    assert len(net.calls) == done                # stopped means stopped


@pytest.mark.asyncio
async def test_initial_pass_completes_before_start_returns(world):
    sessions, _, _ = world
    net = FakeNet()
    r = NetworkReconciler(net, sessions, interval=3600)
    await r.start(initial_pass=True)
    assert len(net.calls) == 1 and r.last_report is net.report
    await r.stop()


@pytest.mark.asyncio
async def test_on_report_callback_receives_each_report(world):
    sessions, _, _ = world
    seen = []
    net = FakeNet()
    r = NetworkReconciler(net, sessions, on_report=seen.append)
    await r.run_once()
    await r.run_once()
    assert seen == [net.report, net.report]


@pytest.mark.asyncio
async def test_runtime_starts_reconciler_inline_and_stops_it(world, monkeypatch):
    from aijailer.netpolicy import runtime
    from aijailer.netpolicy.cell_network import CellNetwork
    from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager

    class Runner:
        async def run(self, script, check_only=False):
            return ""

    class Links:
        async def setup(self, cell): ...
        async def teardown(self, ifname): ...
        async def set_bandwidth(self, cell, bw): ...

    from aijailer.netpolicy import discovery
    sessions, ids, _ = world
    net = CellNetwork(NetPolicyManager(runner=Runner(), allocator=NetAllocator("10.8.0.0/24")),
                      Links(), scan=lambda: discovery.HostNetState())
    monkeypatch.setattr(runtime, "get_cell_network", lambda: net)

    class Eng:
        needs_network = True

    rt = await runtime.start_network_runtime(Eng(), interval=0.01, session_factory=sessions)
    assert rt.reconciler is not None and rt.reconciler.runs >= 1  # ran before 'serving'
    await rt.stop()


@pytest.mark.asyncio
async def test_stuck_in_flight_cells_lose_protection_and_are_marked_error(world):
    from datetime import UTC, datetime, timedelta

    sessions, ids, _ = world
    async with sessions() as db:
        old = datetime.now(UTC) - timedelta(hours=2)
        for status in ("creating", "destroying"):
            cell = await db.get(Cell, ids[status])
            cell.updated_at = old
        await db.commit()
    net = FakeNet()
    await NetworkReconciler(net, sessions, stuck_after=600).run_once()
    _, protected, _ = net.calls[0]
    assert ids["creating"] not in protected and ids["destroying"] not in protected
    assert ids["stopping"] in protected                      # recent: still protected
    async with sessions() as db:
        assert (await db.get(Cell, ids["creating"])).status == "error"
        assert "stuck in 'creating'" in (await db.get(Cell, ids["creating"])).error_message
        assert (await db.get(Cell, ids["destroying"])).status == "error"
        assert (await db.get(Cell, ids["stopping"])).status == "stopping"
