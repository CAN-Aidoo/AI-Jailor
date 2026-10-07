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
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

import structlog

from aijailer.agentsec.egress import EgressBroker, EgressRule, SecretBinding
from aijailer.agentsec.proxy import CellProxy
from aijailer.netpolicy import discovery
from aijailer.netpolicy.nft import CellNet, LinkInfo, NetPolicyManager, ifname_for
from aijailer.netpolicy.shaping import Bandwidth

logger = structlog.get_logger(__name__)


class SecretProvider(Protocol):
    async def secrets_for(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> list[SecretBinding]: ...


class NoSecrets:
    async def secrets_for(self, tenant_id, cell_id) -> list[SecretBinding]:
        return []


class LinkOps(Protocol):
    async def setup(self, cell: CellNet) -> LinkInfo | None: ...
    async def teardown(self, ifname: str) -> None: ...
    async def set_bandwidth(self, cell: CellNet, bw: Bandwidth) -> None: ...
    async def get_bandwidth(self, cell: CellNet) -> Bandwidth: ...


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
        from aijailer.netpolicy.link import netns_name
        from aijailer.netpolicy.shaping import apply_shaping
        await asyncio.to_thread(apply_shaping, cell.ifname, netns_name(cell), bw)

    async def get_bandwidth(self, cell: CellNet) -> Bandwidth:
        from aijailer.netpolicy.link import netns_name
        from aijailer.netpolicy.shaping import read_shaping
        return await asyncio.to_thread(read_shaping, cell.ifname, netns_name(cell))


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


@dataclass(frozen=True)
class LiveCell:
    """What the database says about a cell that should have a network."""

    tenant_id: uuid.UUID
    network_policy: dict | None = None
    # The limits this cell must have, from the DB. None => leave shaping alone.
    bandwidth: Bandwidth | None = None


@dataclass
class SweepReport:
    kept: list[uuid.UUID] = field(default_factory=list)
    adopted: list[uuid.UUID] = field(default_factory=list)
    stale_removed: list[uuid.UUID] = field(default_factory=list)
    orphans_removed: list[str] = field(default_factory=list)
    shaping_repaired: list[uuid.UUID] = field(default_factory=list)  # kernel limits != DB
    broken: list[uuid.UUID] = field(default_factory=list)   # live per DB but network unusable
    errors: list[str] = field(default_factory=list)
    aborted: str | None = None

    @property
    def changed(self) -> bool:
        return bool(self.adopted or self.stale_removed or self.orphans_removed or self.broken
                    or self.shaping_repaired)


# Refuse to remove more than this many networks in one sweep when it is also more than half of
# everything present: the likelier explanation is a bad/empty database read, not a mass leak.
MASS_REMOVAL_MIN = 5
MASS_REMOVAL_FRACTION = 0.5


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
                 proxy_factory: Callable[..., CellProxy] = CellProxy, resolver=None,
                 scan: Callable[[], discovery.HostNetState] = discovery.scan_host,
                 clock: Callable[[], float] = time.monotonic,
                 extra_env: dict | None = None) -> None:
        self._extra_env = dict(extra_env or {})     # platform-owned env every cell gets (merged last)
        self._scan, self._clock = scan, clock
        self._since: dict[uuid.UUID, float] = {}
        self._resolver = resolver
        self._mgr, self._links = manager, link_ops
        self._secrets = secrets or NoSecrets()
        self._audit = audit
        self._proxy_factory = proxy_factory
        self._proxies: dict[uuid.UUID, CellProxy] = {}
        self._tenants: dict[uuid.UUID, uuid.UUID] = {}
        self._links_up: set[uuid.UUID] = set()
        self._nets: dict[uuid.UUID, CellNet] = {}
        self._policies: dict[uuid.UUID, dict | None] = {}
        self._lock = asyncio.Lock()

    @property
    def manager(self) -> NetPolicyManager:
        return self._mgr

    @property
    def provisioned(self) -> set[uuid.UUID]:
        return set(self._proxies)

    def subnet_of(self, cell_id: uuid.UUID) -> str | None:
        net = self._nets.get(cell_id)
        return str(net.network) if net is not None else None

    def subnet_available(self, cell_id: uuid.UUID, subnet: str) -> bool:
        return self._mgr.subnet_available(cell_id, subnet)

    async def provision(self, cell_id: uuid.UUID, tenant_id: uuid.UUID,
                        network_policy: dict | None,
                        bandwidth: Bandwidth | None = None,
                        subnet: str | None = None) -> Provisioned:
        async with self._lock:
            if cell_id in self._proxies:
                raise RuntimeError(f"network for cell {cell_id} already provisioned")
            broker, skipped = broker_from_policy(
                network_policy, await self._secrets.secrets_for(tenant_id, cell_id),
                self._resolver)
            net = None
            try:
                net = await self._mgr.register(cell_id, subnet=subnet)
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
            self._policies[cell_id] = network_policy
            self._since[cell_id] = self._clock()
            url = self._proxy_url(net)
            logger.info("cell.network.provisioned", cell_id=str(cell_id), ifname=net.ifname,
                        guest_ip=str(net.guest_ip), skipped=skipped)
            return Provisioned(net, link, url, self._proxy_env(url), skipped)

    @staticmethod
    def _proxy_url(net: CellNet) -> str:
        return f"http://{net.host_ip}:{net.broker_port}"

    def _proxy_env(self, url: str) -> dict:
        return {"http_proxy": url, "HTTP_PROXY": url, "https_proxy": url, "HTTPS_PROXY": url,
                "NO_PROXY": "", **self._extra_env}

    def env_for(self, cell_id: uuid.UUID) -> dict:
        """The platform-injected guest environment of a provisioned cell ({} if none); lets a
        re-adopted VM get the same proxy settings it was created with."""
        net = self._nets.get(cell_id)
        return self._proxy_env(self._proxy_url(net)) if net is not None else {}

    async def refresh_secrets(self, tenant_id: uuid.UUID | None = None,
                              fail_closed: bool = False) -> int:
        """Rebuild running cells' brokers from the current secret store (all cells, or one
        tenant's). Called on every secret write so a rotation or revocation takes effect for
        requests that start after this returns.

        ``fail_closed``: if the store cannot be read, install a broker with NO secrets rather than
        keep serving a possibly-revoked one (used for change-triggered refreshes). Periodic
        refreshes keep the existing broker on failure so an outage does not break every cell.
        Returns the number of cells updated."""
        async with self._lock:
            return await self._refresh_locked(tenant_id, fail_closed)

    async def _refresh_locked(self, tenant_id: uuid.UUID | None, fail_closed: bool) -> int:
        n = 0
        # Secrets are per tenant: resolve (DB read + key-service unwraps) once per tenant per
        # refresh, not once per cell. A failure is remembered too, so an outage costs one attempt.
        resolved: dict[uuid.UUID, list[SecretBinding] | Exception] = {}
        for cid, proxy in list(self._proxies.items()):
            tid = self._tenants.get(cid)
            if tid is None or (tenant_id is not None and tid != tenant_id):
                continue
            if tid not in resolved:
                try:
                    resolved[tid] = await self._secrets.secrets_for(tid, cid)
                except Exception as exc:
                    resolved[tid] = exc
            secrets = resolved[tid]
            if isinstance(secrets, Exception):
                logger.error("cell.network.secret_refresh_failed", cell_id=str(cid),
                             error=str(secrets), fail_closed=fail_closed)
                if not fail_closed:
                    continue
                secrets = []
            broker, _ = broker_from_policy(self._policies.get(cid), secrets, self._resolver)
            proxy.replace_broker(broker)
            n += 1
        return n

    async def get_bandwidth(self, cell_id: uuid.UUID) -> Bandwidth | None:
        """What the kernel is enforcing for this cell right now (None if no network)."""
        async with self._lock:
            net = self._nets.get(cell_id)
            if net is None or cell_id not in self._proxies:
                return None
            return await self._links.get_bandwidth(net)

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
        self._since.pop(cell_id, None)
        self._policies.pop(cell_id, None)
        return errors

    async def reconcile(self, live_cells: set[uuid.UUID]) -> list[uuid.UUID]:
        """In-memory only: tear down networks of cells that are no longer live. Prefer
        ``sweep``, which also finds leaks the process has no memory of."""
        async with self._lock:
            stale = [c for c in list(self._proxies) if c not in live_cells]
            for cid in stale:
                await self._teardown(cid, self._proxies.pop(cid))
            return stale

    # ------------------------------------------------------------------ sweep
    async def sweep(self, live: dict[uuid.UUID, LiveCell], protected: set[uuid.UUID],
                    grace: float = 120.0) -> SweepReport:
        """Make the host match the database, including after a crash or restart.

        * known + live            -> keep (flag ``broken`` if its kernel resources vanished)
        * known + not live        -> tear down (once older than ``grace``)
        * unknown + live          -> ADOPT: rebuild registry, firewall tuple, proxy and shaping
                                     from what the kernel still holds (a restart empties our memory
                                     but leaves running cells' links in place)
        * unknown + not live      -> orphan: delete veth + namespace
        * ``protected`` cells (creating/stopping/destroying) are never touched.
        Anything that does not match ``aj<12 hex>`` is never touched. A sweep that would remove a
        suspiciously large share of everything aborts without changing anything.
        """
        report = SweepReport()
        async with self._lock:
            state = await asyncio.to_thread(self._scan)
            by_prefix: dict[str, uuid.UUID | None] = {}
            for cid in {*live, *protected, *self._proxies}:
                p = cid.hex[:12]
                by_prefix[p] = None if p in by_prefix else cid  # None => ambiguous, skip
            unknown = object()
            # Re-filter here: never delete anything whose name we did not generate, whatever
            # the scanner returned.
            names = {n for n in (state.names | {ifname_for(c) for c in self._proxies})
                     if discovery.is_cell_name(n)}

            stale: list[uuid.UUID] = []
            orphans: list[str] = []
            adopt: list[uuid.UUID] = []
            now = self._clock()
            for name in sorted(names):
                cid = by_prefix.get(discovery.prefix_of(name), unknown)
                if cid is None:
                    report.errors.append(f"{name}: ambiguous cell id prefix, left alone")
                    continue
                if cid is not unknown and cid in protected:
                    continue
                if cid is not unknown and cid in self._proxies:
                    if cid in live:
                        if name in state.veths and name in state.netns:
                            report.kept.append(cid)
                        else:
                            report.broken.append(cid)
                    elif now - self._since.get(cid, 0.0) >= grace:
                        stale.append(cid)
                elif cid is not unknown and cid in live:
                    adopt.append(cid)
                else:
                    orphans.append(name)

            removals = len(stale) + len(orphans)
            if removals > MASS_REMOVAL_MIN and removals > MASS_REMOVAL_FRACTION * len(names):
                report.aborted = (f"refusing to remove {removals} of {len(names)} networks in one "
                                  "sweep (database read looks wrong?)")
                return report

            for cid in adopt:
                await self._adopt(cid, live[cid], state, report)
            for cid in stale:
                errs = await self._teardown(cid, self._proxies.pop(cid))
                report.errors.extend(errs)
                report.stale_removed.append(cid)
            for name in orphans:
                try:
                    await self._links.teardown(name)
                    for rid in self._mgr.revoked_ids():
                        if ifname_for(rid) == name:
                            await self._mgr.release(rid)
                    report.orphans_removed.append(name)
                except Exception as exc:
                    report.errors.append(f"orphan {name}: {exc}")
            # Subnets still occupied by resources we do not own (in-flight/unadoptable) must
            # not be handed to a new cell: that would put two interfaces on one /30.
            gone = set(report.orphans_removed) | {ifname_for(c) for c in report.stale_removed}
            mine = {ifname_for(c) for c in self._proxies}
            self._mgr.set_external({
                ipaddress.ip_network(f"{a[0]}/{a[1]}", strict=False)
                for n, a in state.veths.items()
                if a is not None and discovery.is_cell_name(n) and n not in gone | mine})
            # Shaping drift: someone cleared/changed a qdisc, or a DB write succeeded after the
            # kernel apply failed (or the reverse). The DB is the source of truth.
            for cid in report.kept:
                want = live[cid].bandwidth
                net = self._nets.get(cid)
                if want is None or net is None:
                    continue
                try:
                    if await self._links.get_bandwidth(net) != want:
                        await self._links.set_bandwidth(net, want)
                        report.shaping_repaired.append(cid)
                except Exception as exc:
                    report.errors.append(f"shaping check {cid}: {exc}")
            # Eventual consistency for secret changes made while a node was unreachable.
            await self._refresh_locked(None, fail_closed=False)
            return report

    async def _adopt(self, cid: uuid.UUID, lc: LiveCell, state: discovery.HostNetState,
                     report: SweepReport) -> None:
        name = ifname_for(cid)
        addr = state.veths.get(name)
        net = None
        try:
            if name not in state.veths or name not in state.netns or addr is None:
                raise RuntimeError("incomplete network (veth/namespace/address missing)")
            host_ip, prefix = addr
            if prefix != 30:
                raise RuntimeError(f"unexpected prefix /{prefix}")
            hosts = list(ipaddress.ip_network(f"{host_ip}/{prefix}", strict=False).hosts())
            guest_ip = next(h for h in hosts if h != host_ip)
            net = CellNet(cid, name, host_ip, guest_ip, 30, self._mgr.broker_port)
            await self._mgr.adopt(net)
            self._links_up.add(cid)
            broker, skipped = broker_from_policy(
                lc.network_policy, await self._secrets.secrets_for(lc.tenant_id, cid),
                self._resolver)
            if lc.bandwidth is not None:  # re-assert the limit: do not trust what survived
                await self._links.set_bandwidth(net, lc.bandwidth)
            sink = (lambda ev, c=cid: self._audit(c, ev)) if self._audit else None
            proxy = self._proxy_factory(str(cid), str(net.host_ip), net.broker_port, broker,
                                        audit=sink)
            await proxy.start()
        except BaseException as exc:
            if isinstance(exc, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                raise
            logger.error("cell.network.adopt_failed", cell_id=str(cid), error=str(exc))
            await self._teardown(cid, None)
            try:
                await self._links.teardown(name)  # remove remnants; the cell must be re-provisioned
            except Exception as e2:
                report.errors.append(f"adopt cleanup {name}: {e2}")
            report.broken.append(cid)
            report.errors.append(f"adopt {cid}: {exc}")
            return
        self._proxies[cid] = proxy
        self._tenants[cid] = lc.tenant_id
        self._policies[cid] = lc.network_policy
        self._nets[cid] = net
        self._since[cid] = self._clock()
        report.adopted.append(cid)
        logger.info("cell.network.adopted", cell_id=str(cid), ifname=name, skipped=skipped)
