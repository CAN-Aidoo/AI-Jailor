"""Process-wide CellNetwork wiring (settings -> manager, link ops, audit)."""

import asyncio
import uuid

from aijailer.core.config import get_settings
from aijailer.models.audit import EventType, Severity
from aijailer.netpolicy.cell_network import CellNetwork, NetnsLinkOps
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager

_network: CellNetwork | None = None
_tenant_of: dict[uuid.UUID, uuid.UUID] = {}


def remember_tenant(cell_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    _tenant_of[cell_id] = tenant_id


def _audit_sink(cell_id: uuid.UUID, event: dict) -> None:
    """Proxy decisions -> audit chain. Sync callback from the proxy, one call per request: queued
    for group commit (see AuditService.submit_event for what that trades away)."""
    tenant = _tenant_of.get(cell_id)
    if tenant is None:
        return
    from aijailer.services.audit_service import get_audit_service
    denied = event.get("decision") != "allow"
    get_audit_service().submit_event(
        tenant_id=tenant, cell_id=cell_id, event_type=EventType.NETWORK,
        severity=Severity.WARNING if denied else Severity.INFO, details=event)


def network_required(engine) -> bool:
    """Decide whether this engine's cells must have enforced networking. Fail closed:
    an engine that attaches a NIC can never run without it."""
    mode = get_settings().network_enforcement
    if mode not in ("auto", "required", "off"):
        raise ValueError(f"invalid NETWORK_ENFORCEMENT {mode!r}")
    if engine.needs_network:
        if mode == "off":
            raise RuntimeError("NETWORK_ENFORCEMENT=off is not allowed with a NIC-attaching engine")
        return True
    if mode == "required":
        raise RuntimeError(f"NETWORK_ENFORCEMENT=required but {type(engine).__name__} "
                           "cannot be firewalled")
    return False


def peek_cell_network() -> CellNetwork | None:
    """The singleton if it exists; never creates it (used by change hooks)."""
    return _network


def get_cell_network() -> CellNetwork:
    global _network
    if _network is None:
        from aijailer.db.base import async_session_factory
        from aijailer.secretstore.runtime import DbSecretProvider
        s = get_settings()
        mgr = NetPolicyManager(allocator=NetAllocator(s.cell_net_pool), broker_port=s.broker_port)
        _network = CellNetwork(mgr, NetnsLinkOps(s.jailer_uid, s.jailer_gid), audit=_audit_sink,
                               secrets=DbSecretProvider(async_session_factory))
    return _network


class NetworkRuntime:
    """Startup/shutdown of host enforcement: install the ruleset (fail closed), watch it, and
    periodically reconcile host networking with the database."""

    def __init__(self, stop: asyncio.Event, task: asyncio.Task, reconciler=None) -> None:
        self._stop, self._task, self.reconciler = stop, task, reconciler

    async def stop(self) -> None:
        if self.reconciler is not None:
            await self.reconciler.stop()
        self._stop.set()
        await self._task


async def start_network_runtime(engine, interval: float = 5.0,
                                 session_factory=None) -> NetworkRuntime | None:
    """Returns None for engines with no NIC. Raises if the ruleset cannot be installed, so the
    service refuses to start rather than serve cells without a firewall."""
    import structlog

    from aijailer.netpolicy.nft import watchdog

    if not network_required(engine):
        return None
    net = get_cell_network()
    await net.manager.install()
    log = structlog.get_logger("aijailer.netpolicy")

    def on_drift(drift: list[str]) -> None:
        # Drift means cell filtering was removed or altered (already repaired by enforce()).
        log.error("netpolicy.drift_repaired", drift=drift)

    stop = asyncio.Event()
    task = asyncio.create_task(watchdog(net.manager, interval, on_drift, stop))
    reconciler = None
    if session_factory is not None:
        from aijailer.netpolicy.reconciler import NetworkReconciler
        s = get_settings()
        reconciler = NetworkReconciler(net, session_factory, s.reconcile_interval_seconds,
                                       s.reconcile_grace_seconds, s.reconcile_stuck_seconds,
                                       engine=engine)
        # Inline first pass: adopt networks that survived a restart before taking traffic.
        await reconciler.start(initial_pass=True)
    return NetworkRuntime(stop, task, reconciler)
