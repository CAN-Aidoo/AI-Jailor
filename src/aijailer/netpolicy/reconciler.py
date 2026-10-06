"""Periodic job: make host networking match the database (and survive restarts).

Each run reads the cells table, then calls ``CellNetwork.sweep``:
  live      ready / running / paused    -> a network must exist (adopted if the kernel still has it)
  protected creating / stopping / destroying -> in flight, never touched
  anything else (stopped, destroyed, error, unknown) -> must have no network

Fail-static rules: if the database cannot be read, NOTHING is changed (an outage must not look
like "no cells exist"); one bad run never stops the loop; a sweep that would remove most of the
host's networks aborts (see ``MASS_REMOVAL_*``). Cells reported broken (live per the DB but with
an unusable network) are marked ``error`` so they are not left looking healthy.
"""

import asyncio
import random
import uuid
from datetime import UTC, datetime
from collections.abc import Awaitable, Callable

import structlog
from sqlalchemy import select

from aijailer.models.cell import Cell
from aijailer.netpolicy.cell_network import CellNetwork, LiveCell, SweepReport

logger = structlog.get_logger(__name__)

LIVE_STATUSES = ("ready", "running", "paused")
PROTECTED_STATUSES = ("creating", "stopping", "destroying")


class NetworkReconciler:
    def __init__(self, network: CellNetwork, session_factory: Callable,
                 interval: float = 30.0, grace: float = 120.0, stuck_after: float = 600.0,
                 on_report: Callable[[SweepReport], Awaitable[None] | None] | None = None) -> None:
        self._net, self._sessions = network, session_factory
        self._interval, self._grace, self._on_report = interval, grace, on_report
        self._stuck_after = stuck_after
        self._stop = asyncio.Event()
        self._task: asyncio.Task | None = None
        self.last_report: SweepReport | None = None
        self.runs = 0
        self.failures = 0

    async def _read_cells(self):
        """Returns (live, protected, stuck). An in-flight status that has not changed for
        ``stuck_after`` seconds means the process that owned the operation died: such a cell is
        no longer protected (its network gets cleaned up) and is marked ``error``."""
        live: dict[uuid.UUID, LiveCell] = {}
        protected: set[uuid.UUID] = set()
        stuck: dict[uuid.UUID, str] = {}
        now = datetime.now(UTC)
        async with self._sessions() as db:
            rows = await db.execute(select(
                Cell.id, Cell.tenant_id, Cell.status, Cell.effective_policy,
                Cell.network_bandwidth_mbps, Cell.updated_at))
            for cid, tenant, status, policy, mbps, updated in rows:
                if status in LIVE_STATUSES:
                    live[cid] = LiveCell(tenant, (policy or {}).get("network"), mbps)
                elif status in PROTECTED_STATUSES:
                    if updated is not None and updated.tzinfo is None:
                        updated = updated.replace(tzinfo=UTC)  # SQLite returns naive UTC
                    if updated is not None and (now - updated).total_seconds() > self._stuck_after:
                        stuck[cid] = status
                    else:
                        protected.add(cid)
        return live, protected, stuck

    async def _mark_broken(self, cell_ids: list[uuid.UUID],
                           stuck: dict[uuid.UUID, str] | None = None) -> None:
        async with self._sessions() as db:
            for cid in cell_ids:
                cell = await db.get(Cell, cid)
                if cell is not None and cell.status in LIVE_STATUSES:
                    cell.status = "error"
                    cell.error_message = "network lost or unrecoverable (reconciler)"
            for cid, was in (stuck or {}).items():
                cell = await db.get(Cell, cid)
                if cell is not None and cell.status == was:  # not changed under us
                    cell.status = "error"
                    cell.error_message = f"stuck in '{was}' (owner process died; reconciler)"
            await db.commit()

    async def run_once(self) -> SweepReport | None:
        """One reconciliation pass. Returns None (and changes nothing) if the DB is unreadable."""
        self.runs += 1
        try:
            live, protected, stuck = await self._read_cells()
        except Exception as exc:
            self.failures += 1
            logger.error("netpolicy.reconcile.db_unreadable", error=str(exc))
            return None
        report = await self._net.sweep(live, protected, self._grace)
        self.last_report = report
        if report.broken or stuck:
            try:
                await self._mark_broken(report.broken, stuck)
            except Exception as exc:
                report.errors.append(f"mark broken: {exc}")
        if report.aborted or report.errors:
            logger.error("netpolicy.reconcile.problem", aborted=report.aborted,
                         errors=report.errors)
        if report.changed:
            logger.warning("netpolicy.reconcile.changed", adopted=len(report.adopted),
                           stale=len(report.stale_removed), orphans=report.orphans_removed,
                           broken=[str(c) for c in report.broken])
        if self._on_report is not None:
            res = self._on_report(report)
            if asyncio.iscoroutine(res):
                await res
        return report

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self.run_once()
            except Exception:  # never let the loop die
                self.failures += 1
                logger.exception("netpolicy.reconcile.crashed")
            try:  # jitter avoids synchronized sweeps across nodes
                await asyncio.wait_for(self._stop.wait(),
                                       self._interval * random.uniform(0.9, 1.1))
            except TimeoutError:
                pass

    async def start(self, initial_pass: bool = True) -> None:
        """Run one pass inline first (adopts surviving networks BEFORE the service takes
        traffic), then keep sweeping in the background."""
        if initial_pass:
            await self.run_once()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        if self._task:
            await self._task
