"""Per-cell network lifecycle: firewall entry + TAP link + egress proxy, as one unit.

Invariants (each tested):
* Fail closed: if ANY step of provisioning fails, everything already done is undone
  and the error propagates, so the cell is never started with a half-built network.
* Revoke first: teardown removes the firewall permission before anything else, and the
  cell's /30 is only released for reuse after the TAP is gone.
* Idempotent: ``deprovision`` of an unknown or already-removed cell is a no-op, and a
  failure in one teardown step never skips the others (errors are collected).
* No leaks: ``reconcile`` removes networks for cells the database no longer considers live.
"""

import asyncio
import ipaddress
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

import structlog

from aijailer.agentsec.egress import EgressBroker, EgressRule, SecretBinding
from aijailer.agentsec.proxy import CellProxy
from aijailer.netpolicy.nft import CellNet, LinkInfo, NetPolicyManager
from aijailer.netpolicy.shaping import Bandwidth

logger = structlog.get_logger(__name__)


class SecretProvider(Protocol):
    def secrets_for(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> list[SecretBinding]: ...


class NoSecrets:
    def secrets_for(self, tenant_id, cell_id) -> list[SecretBinding]:
        return []


class LinkOps(Protocol):
    async def setup(self, cell: CellNet) -> LinkInfo | None: ...
    async def teardown(self, ifname: str) -> None: ...
    async def set_bandwidth(self, cell: CellNet, bw: Bandwidth) -> None: ...


class NetnsLinkOps:
    """Production link plumbing: per-cell netns + TAP (owned by the jailer user) + veth."""

    def __init__(self, uid: int, gid: int) -> None:
        self._uid, self._gid = uid, gid

    async def setup(self, cell: CellNet) -> LinkInfo:
        from aijailer.netpolicy.link import asetup_link
        return await asetup_link(cell, self._uid, self._gid)

    async def teardown(self, ifname: str) -> None:
        from aijailer.netpolicy.link import ateardown_link
        await ateardown_link(ifname)

    async def set_bandwidth(self, cell: CellNet, bw: Bandwidth) -> None:
        import asyncio

        from aijailer.netpolicy.link import netns_name
        from aijailer.netpolicy.shaping import apply_shaping
        await asyncio.to_thread(apply_shaping, cell.ifname, netns_name(cell), bw)


TapLinkOps = NetnsLinkOps  # backwards-compatible name


def broker_from_policy(network_policy: dict | None, secrets: list[SecretBinding],
                       resolver=None) -> tuple[EgressBroker, list[str]]:
    """Translate a stored network policy into broker rules.

    Only constructs we can enforce exactly are translated: domain names (exact or
    ``*.suffix``) and single IPs, over TCP. CIDR ranges, non-tcp protocols and
    non-allow actions are SKIPPED (which can only make the policy stricter) and reported.
    Default is always deny, whatever the policy says.
    """
    rules: list[EgressRule] = []
    private: list[str] = []
    skipped: list[str] = []
    for i, rule in enumerate((network_policy or {}).get("egress", [])):
        if rule.get("action", "allow") != "allow":
            continue
        if "tcp" not in [p.lower() for p in rule.get("protocols", ["tcp"])]:
            skipped.append(f"egress[{i}]: only tcp is supported")
            continue
        ports = tuple(int(p) for p in rule.get("ports", [443]))
        for dest in rule.get("destinations", []):
            host = dest.get("domain") or dest.get("ip")
            if not host:
                continue
            if dest.get("ip") and "/" in str(dest["ip"]):
                skipped.append(f"egress[{i}]: CIDR {dest['ip']} not supported (use single IPs)")
                continue
            if dest.get("ip"):
                try:
                    ip = ipaddress.ip_address(dest["ip"])
                except ValueError:
                    skipped.append(f"egress[{i}]: invalid ip {dest['ip']!r}")
                    continue
                if not ip.is_global:  # explicit single internal IP: allow exactly that host
                    private.append(f"{ip}/{'32' if ip.version == 4 else '128'}")
            rules.append(EgressRule(host, ports=ports))
    return EgressBroker(rules, secrets, resolver=resolver, allow_private_cidrs=private), skipped


@dataclass
class Provisioned:
    net: CellNet
    link: LinkInfo | None
    proxy_url: str
    env: dict = field(default_factory=dict)
    skipped_rules: list[str] = field(default_factory=list)


class CellNetwork:
    def __init__(self, manager: NetPolicyManager, link_ops: LinkOps,
                 secrets: SecretProvider | None = None,
                 audit: Callable[[uuid.UUID, dict], None] | None = None,
                 proxy_factory: Callable[..., CellProxy] = CellProxy, resolver=None) -> None:
        self._resolver = resolver
        self._mgr, self._links = manager, link_ops
        self._secrets = secrets or NoSecrets()
        self._audit = audit
        self._proxy_factory = proxy_factory
        self._proxies: dict[uuid.UUID, CellProxy] = {}
        self._tenants: dict[uuid.UUID, uuid.UUID] = {}
        self._links_up: set[uuid.UUID] = set()
        self._nets: dict[uuid.UUID, CellNet] = {}
        self._lock = asyncio.Lock()

    @property
    def manager(self) -> NetPolicyManager:
        return self._mgr

    @property
    def provisioned(self) -> set[uuid.UUID]:
        return set(self._proxies)

    async def provision(self, cell_id: uuid.UUID, tenant_id: uuid.UUID,
                        network_policy: dict | None,
                        bandwidth: Bandwidth | None = None) -> Provisioned:
        async with self._lock:
            if cell_id in self._proxies:
                raise RuntimeError(f"network for cell {cell_id} already provisioned")
            broker, skipped = broker_from_policy(
                network_policy, self._secrets.secrets_for(tenant_id, cell_id), self._resolver)
            net = None
            try:
                net = await self._mgr.register(cell_id)
                link = await self._links.setup(net)
                self._links_up.add(cell_id)
                # A cell never runs without its bandwidth limit: failure rolls everything back.
                if bandwidth is not None:
                    await self._links.set_bandwidth(net, bandwidth)
                    self._nets[cell_id] = net
                sink = (lambda ev, c=cell_id: self._audit(c, ev)) if self._audit else None
                proxy = self._proxy_factory(str(cell_id), str(net.host_ip), net.broker_port,
                                            broker, audit=sink)
                await proxy.start()
            except BaseException:
                await self._teardown(cell_id, proxy=None)
                raise
            self._proxies[cell_id] = proxy
            self._tenants[cell_id] = tenant_id
            url = f"http://{net.host_ip}:{net.broker_port}"
            logger.info("cell.network.provisioned", cell_id=str(cell_id), ifname=net.ifname,
                        guest_ip=str(net.guest_ip), skipped=skipped)
            env = {"http_proxy": url, "HTTP_PROXY": url, "https_proxy": url, "HTTPS_PROXY": url,
                   "NO_PROXY": ""}
            return Provisioned(net, link, url, env, skipped)

    async def set_bandwidth(self, cell_id: uuid.UUID, bandwidth: Bandwidth) -> None:
        """Hot-update a running cell's limits (resource limits are adjustable without restart)."""
        async with self._lock:
            net = self._nets.get(cell_id) or next(
                (c for c in self._mgr.cells if c.cell_id == cell_id), None)
            if net is None or cell_id not in self._proxies:
                raise LookupError(f"no provisioned network for cell {cell_id}")
            await self._links.set_bandwidth(net, bandwidth)
            self._nets[cell_id] = net

    async def deprovision(self, cell_id: uuid.UUID) -> list[str]:
        """Returns the list of errors encountered (empty on a clean teardown)."""
        async with self._lock:
            return await self._teardown(cell_id, self._proxies.pop(cell_id, None))

    async def _teardown(self, cell_id: uuid.UUID, proxy: CellProxy | None) -> list[str]:
        errors: list[str] = []

        async def step(name, coro):
            try:
                await coro
            except Exception as exc:  # keep going: a stuck step must not strand the rest
                errors.append(f"{name}: {exc}")
                logger.error("cell.network.teardown_step_failed", step=name,
                             cell_id=str(cell_id), error=str(exc))

        # 1. Revoke firewall permission FIRST (reachability ends immediately).
        revoked = None
        try:
            revoked = await self._mgr.revoke(cell_id)
        except Exception as exc:
            errors.append(f"revoke: {exc}")
        # 2. Stop the proxy, 3. delete the TAP, 4. only then free the address.
        if proxy is not None:
            await step("proxy", proxy.stop())
        link_name = revoked.ifname if revoked else None
        if link_name is None and cell_id in self._links_up:
            from aijailer.netpolicy.nft import ifname_for
            link_name = ifname_for(cell_id)
        if link_name and cell_id in self._links_up:
            await step("link", self._links.teardown(link_name))
            self._links_up.discard(cell_id)
        if not errors:
            await step("release", self._mgr.release(cell_id))
        # On error the /30 stays reserved: leaking an address is safer than reusing a
        # subnet that may still be attached to a live interface.
        self._tenants.pop(cell_id, None)
        self._nets.pop(cell_id, None)
        return errors

    async def reconcile(self, live_cells: set[uuid.UUID]) -> list[uuid.UUID]:
        """Tear down networks of cells that are no longer live (crash/partial-commit leaks)."""
        async with self._lock:
            stale = [c for c in list(self._proxies) if c not in live_cells]
            for cid in stale:
                await self._teardown(cid, self._proxies.pop(cid))
            return stale
