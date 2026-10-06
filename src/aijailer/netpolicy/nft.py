"""nftables enforcement: a cell can reach its egress broker and nothing else.

Topology (per cell): ``tap<id>`` <-> host, a /30 link. Guest = .2, host = .1.
The cell has no default route to the world and the host does NOT forward for
it, so the broker is not merely the *preferred* path, it is the only one.
nftables then makes that structural property robust against misconfiguration
(someone enabling ip_forward, a host service listening on 0.0.0.0, a spoofed
source address, IPv6, cell-to-cell traffic):

  input    from a cell iface: accept ONLY (iface, guest_ip, host_ip, broker_port).
           Everything else, including spoofed sources, IPv6, ICMP and every other
           host service, is dropped (default deny, counted, rate-limited log).
  forward  nothing from or to a cell iface is ever forwarded (no internet, no
           cell-to-cell, no inbound).
  output   the host never opens NEW connections into a cell (replies are
           allowed via conntrack).

The ruleset is static; per-cell state lives in two sets, so (un)registering a
cell is one atomic element add/delete. Every value that reaches nft is
validated and rendered by this module, never interpolated from callers.
"""

import asyncio
import ipaddress
import json
import re
import uuid
from dataclasses import dataclass
from typing import Protocol

TABLE = "aijailer"
FAMILY = "inet"
# Filtering is by interface-NAME PREFIX, not by set membership: an interface that is
# unregistered (or never registered) is still a cell interface and is default-denied.
# Set membership would fail OPEN the moment a cell is removed.
IF_PREFIX = "aj"
_IFNAME = re.compile(r"^[A-Za-z0-9_-]{1,15}$")


class NftError(RuntimeError):
    pass


class NftRunner(Protocol):
    async def run(self, script: str, check_only: bool = False) -> str: ...


class SubprocessNft:
    def __init__(self, binary: str = "nft") -> None:
        self._bin = binary

    async def run(self, script: str, check_only: bool = False) -> str:
        args = [self._bin, *(["-c"] if check_only else []), "-f", "-"]
        proc = await asyncio.create_subprocess_exec(
            *args, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate(script.encode())
        if proc.returncode != 0:
            raise NftError(err.decode().strip() or f"nft exited {proc.returncode}")
        return out.decode()

    async def list_json(self) -> dict:
        proc = await asyncio.create_subprocess_exec(
            self._bin, "-j", "list", "table", FAMILY, TABLE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await proc.communicate()
        if proc.returncode != 0:
            raise NftError(err.decode().strip())
        return json.loads(out)


@dataclass(frozen=True)
class CellNet:
    cell_id: uuid.UUID
    ifname: str
    host_ip: ipaddress.IPv4Address
    guest_ip: ipaddress.IPv4Address
    prefix: int
    broker_port: int

    def __post_init__(self) -> None:
        if not _IFNAME.match(self.ifname) or not self.ifname.startswith(IF_PREFIX):
            raise ValueError(f"invalid interface name {self.ifname!r}")
        if not (1 <= self.broker_port <= 65535):
            raise ValueError("invalid broker port")
        if self.host_ip == self.guest_ip:
            raise ValueError("host and guest address must differ")
        net = ipaddress.ip_network(f"{self.host_ip}/{self.prefix}", strict=False)
        if self.guest_ip not in net:
            raise ValueError("guest address outside the link subnet")

    @property
    def network(self) -> str:
        return str(ipaddress.ip_network(f"{self.host_ip}/{self.prefix}", strict=False))


@dataclass(frozen=True)
class LinkInfo:
    """Where the VMM must attach: the TAP's name and the network namespace it lives in."""

    tap_name: str
    netns_path: str


def base_ruleset() -> str:
    """Static ruleset. Atomic: delete+recreate in one transaction."""
    return f"""add table {FAMILY} {TABLE}
delete table {FAMILY} {TABLE}
table {FAMILY} {TABLE} {{
  set broker {{
    type ifname . ipv4_addr . ipv4_addr . inet_service
  }}
  chain input {{
    type filter hook input priority -100; policy accept;
    iifname "{IF_PREFIX}*" jump from_cell
  }}
  chain from_cell {{
    iifname . ip saddr . ip daddr . tcp dport @broker ct state new limit rate over 200/second counter drop
    iifname . ip saddr . ip daddr . tcp dport @broker accept
    limit rate 5/second log prefix "aj-cell-drop " level warn
    counter drop
  }}
  chain forward {{
    type filter hook forward priority -100; policy accept;
    iifname "{IF_PREFIX}*" counter drop
    oifname "{IF_PREFIX}*" counter drop
  }}
  chain output {{
    type filter hook output priority -100; policy accept;
    oifname "{IF_PREFIX}*" ct state new counter drop
  }}
}}
"""


def _elements(cells: list[CellNet]) -> str:
    if not cells:
        return ""
    tuples = ", ".join(
        f'"{c.ifname}" . {c.guest_ip} . {c.host_ip} . {c.broker_port}' for c in cells)
    return f"add element {FAMILY} {TABLE} broker {{ {tuples} }}\n"


def full_ruleset(cells: list[CellNet]) -> str:
    return base_ruleset() + _elements(cells)


def _del_elements(c: CellNet) -> str:
    return (f'delete element {FAMILY} {TABLE} broker {{ "{c.ifname}" . {c.guest_ip} . '
            f"{c.host_ip} . {c.broker_port} }}\n")


class NetAllocator:
    """Hands out one /30 per cell from a pool (default 10.200.0.0/16 -> 16384 cells/node)."""

    def __init__(self, pool: str = "10.200.0.0/16") -> None:
        net = ipaddress.ip_network(pool)
        if not isinstance(net, ipaddress.IPv4Network) or net.prefixlen > 30:
            raise ValueError("pool must be an IPv4 network containing at least one /30")
        self._subnets = net.subnets(new_prefix=30)
        self._free: list = []
        self._used: dict[uuid.UUID, ipaddress.IPv4Network] = {}

    def allocate(self, cell_id: uuid.UUID) -> ipaddress.IPv4Network:
        if cell_id in self._used:
            return self._used[cell_id]
        if self._free:
            sn = self._free.pop()
        else:
            try:
                sn = next(self._subnets)
            except StopIteration:
                raise NftError("cell address pool exhausted") from None
        self._used[cell_id] = sn
        return sn

    def release(self, cell_id: uuid.UUID) -> None:
        sn = self._used.pop(cell_id, None)
        if sn is not None:
            self._free.append(sn)


def ifname_for(cell_id: uuid.UUID) -> str:
    return "aj" + cell_id.hex[:12]  # 14 chars, under IFNAMSIZ


class NetPolicyManager:
    """Registers cells with the host firewall. The registry is the source of truth;
    ``sync``/``verify`` repair or detect drift if someone edits the live ruleset."""

    def __init__(self, runner: NftRunner | None = None, allocator: NetAllocator | None = None,
                 broker_port: int = 3128) -> None:
        self._nft = runner or SubprocessNft()
        self._alloc = allocator or NetAllocator()
        self._port = broker_port
        self._cells: dict[uuid.UUID, CellNet] = {}
        self._revoked: dict[uuid.UUID, CellNet] = {}
        self._lock = asyncio.Lock()
        self._installed = False

    @property
    def cells(self) -> list[CellNet]:
        return list(self._cells.values())

    async def install(self) -> None:
        """Atomically (re)install the full ruleset for all registered cells."""
        async with self._lock:
            await self._nft.run(full_ruleset(self.cells))
            self._installed = True

    async def register(self, cell_id: uuid.UUID, broker_port: int | None = None) -> CellNet:
        async with self._lock:
            if cell_id in self._cells:
                return self._cells[cell_id]
            if not self._installed:
                await self._nft.run(full_ruleset(self.cells))
                self._installed = True
            sn = self._alloc.allocate(cell_id)
            hosts = list(sn.hosts())
            cell = CellNet(cell_id, ifname_for(cell_id), hosts[0], hosts[1], 30,
                           broker_port or self._port)
            try:
                await self._nft.run(_elements([cell]))
            except Exception:
                self._alloc.release(cell_id)
                raise
            self._cells[cell_id] = cell
            return cell

    async def revoke(self, cell_id: uuid.UUID) -> CellNet | None:
        """Remove the cell's access NOW but keep its /30 reserved. Two-phase teardown:
        the address must not be handed to a new cell while the old TAP still carries it."""
        async with self._lock:
            cell = self._cells.get(cell_id)
            if cell is None:
                return None
            await self._nft.run(_del_elements(cell))
            del self._cells[cell_id]
            self._revoked[cell_id] = cell
            return cell

    async def release(self, cell_id: uuid.UUID) -> None:
        """Free the /30 for reuse. Call only after the link is gone."""
        async with self._lock:
            self._revoked.pop(cell_id, None)
            self._alloc.release(cell_id)

    async def unregister(self, cell_id: uuid.UUID) -> None:
        await self.revoke(cell_id)
        await self.release(cell_id)

    async def verify(self) -> list[str]:
        """Return human-readable drift between registry and live kernel state."""
        try:
            doc = await self._nft.list_json()  # type: ignore[attr-defined]
        except NftError as exc:
            return [f"table missing or unreadable: {exc}"]
        live_broker, chains = set(), set()
        for item in doc.get("nftables", []):
            if "set" in item:
                s = item["set"]
                elems = s.get("elem", [])
                if s["name"] == "broker":
                    live_broker = {tuple(map(str, e["concat"])) for e in elems}
            if "chain" in item:
                chains.add(item["chain"]["name"])
        drift = []
        for need in ("input", "from_cell", "forward", "output"):
            if need not in chains:
                drift.append(f"chain {need} missing")
        want_broker = {(c.ifname, str(c.guest_ip), str(c.host_ip), str(c.broker_port))
                       for c in self.cells}
        if live_broker != want_broker:
            drift.append("broker set differs from registry")
        return drift

    async def enforce(self) -> list[str]:
        """verify(); on drift, atomically reinstall. Returns the drift that was repaired."""
        drift = await self.verify()
        if drift:
            await self.install()
        return drift


async def watchdog(manager: NetPolicyManager, interval: float = 5.0, on_drift=None,
                   stop: asyncio.Event | None = None) -> None:
    """Detect (and repair) a flushed/edited ruleset. Anything else on the host that runs
    ``nft flush ruleset`` (firewalld reload, container runtimes) silently removes cell
    filtering, so drift is an incident: ``on_drift(list[str])`` should audit it and may
    pause cells. Nothing here can close the window between the flush and the next tick;
    that is why the topology also gives the cell no route/forwarding of its own."""
    while stop is None or not stop.is_set():
        try:
            drift = await manager.enforce()
            if drift and on_drift:
                res = on_drift(drift)
                if asyncio.iscoroutine(res):
                    await res
        except Exception as exc:  # never let the watchdog die
            if on_drift:
                res = on_drift([f"watchdog error: {exc}"])
                if asyncio.iscoroutine(res):
                    await res
        try:
            if stop is None:
                await asyncio.sleep(interval)
            else:
                await asyncio.wait_for(stop.wait(), interval)
        except TimeoutError:
            pass
