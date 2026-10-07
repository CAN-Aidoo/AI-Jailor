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


_peer_hub = None


def get_peer_hub():
    """The process-wide peer relay, or None when peer links are not configured
    (PEER_ATTESTATION_SECRET unset). The hub's signing key never leaves this process; cells only
    ever receive the public half."""
    global _peer_hub
    s = get_settings()
    if not s.peer_attestation_secret:
        return None
    if _peer_hub is None:
        from aijailer.peerlink.hub import PeerHub
        from aijailer.peerlink.service import authorize_attach
        from aijailer.services.attestation import Ed25519Signer
        _peer_hub = PeerHub(
            authorize_attach, Ed25519Signer.from_secret(s.peer_attestation_secret),
            wait_seconds=s.peer_wait_seconds, session_seconds=s.peer_session_max_seconds,
            idle_seconds=s.peer_session_idle_seconds, max_bytes=s.peer_session_max_bytes)
    return _peer_hub


def peer_public_key_b64() -> str | None:
    """The platform's peer-attestation public key (raw 32 bytes, base64): injected into every cell
    as AIJAILER_PEER_ATTEST_PUBKEY so a cell can verify attestations without trusting the network."""
    import base64

    from cryptography.hazmat.primitives import serialization
    hub = get_peer_hub()
    if hub is None:
        return None
    raw = hub._signer.public_key.public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def get_cell_network() -> CellNetwork:
    global _network
    if _network is None:
        from aijailer.agentsec.proxy import CellProxy
        from aijailer.db.base import async_session_factory
        from aijailer.secretstore.runtime import DbSecretProvider
        s = get_settings()
        mgr = NetPolicyManager(allocator=NetAllocator(s.cell_net_pool), broker_port=s.broker_port)
        hub, pub = get_peer_hub(), peer_public_key_b64()
        kwargs = {}
        if hub is not None:
            kwargs = dict(
                proxy_factory=lambda *a, **k: CellProxy(*a, peer_hub=hub, **k),
                extra_env={"AIJAILER_PEER_ATTEST_PUBKEY": pub})
        _network = CellNetwork(mgr, NetnsLinkOps(s.jailer_uid, s.jailer_gid), audit=_audit_sink,
                               secrets=DbSecretProvider(async_session_factory), **kwargs)
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
