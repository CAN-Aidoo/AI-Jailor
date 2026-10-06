"""Process-wide CellNetwork wiring (settings -> manager, link ops, audit)."""

import asyncio
import uuid

from aijailer.core.config import get_settings
from aijailer.models.audit import EventType, Severity
from aijailer.netpolicy.cell_network import CellNetwork, TapLinkOps
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager

_network: CellNetwork | None = None
_tenant_of: dict[uuid.UUID, uuid.UUID] = {}
_bg: set[asyncio.Task] = set()


def remember_tenant(cell_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
    _tenant_of[cell_id] = tenant_id


def _audit_sink(cell_id: uuid.UUID, event: dict) -> None:
    """Proxy decisions -> audit chain. Sync callback from the proxy; schedule the write."""
    tenant = _tenant_of.get(cell_id)
    if tenant is None:
        return
    from aijailer.services.audit_service import get_audit_service
    denied = event.get("decision") != "allow"
    task = asyncio.get_running_loop().create_task(get_audit_service().record_event(
        tenant_id=tenant, cell_id=cell_id, event_type=EventType.NETWORK,
        severity=Severity.WARNING if denied else Severity.INFO, details=event))
    _bg.add(task)
    task.add_done_callback(_bg.discard)


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


def get_cell_network() -> CellNetwork:
    global _network
    if _network is None:
        s = get_settings()
        mgr = NetPolicyManager(allocator=NetAllocator(s.cell_net_pool), broker_port=s.broker_port)
        _network = CellNetwork(mgr, TapLinkOps(s.jailer_uid, s.jailer_gid), audit=_audit_sink)
    return _network


class NetworkRuntime:
    """Startup/shutdown of host enforcement: install the ruleset (fail closed) and watch it."""

    def __init__(self, stop: asyncio.Event, task: asyncio.Task) -> None:
        self._stop, self._task = stop, task

    async def stop(self) -> None:
        self._stop.set()
        await self._task


async def start_network_runtime(engine, interval: float = 5.0) -> NetworkRuntime | None:
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
    return NetworkRuntime(stop, task)
