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
    """Hands out one /30 per cell from a pool (default 10.200.0.0/16 -> 16384 cells/node).

    Index-based so that subnets recovered from a running host (``reserve``) can sit anywhere in
    the pool without ever being handed out a second time."""

    def __init__(self, pool: str = "10.200.0.0/16") -> None:
        net = ipaddress.ip_network(pool)
        if not isinstance(net, ipaddress.IPv4Network) or net.prefixlen > 30:
            raise ValueError("pool must be an IPv4 network containing at least one /30")
        self._net = net
        self._count = 1 << (30 - net.prefixlen)
        self._next = 0
        self._free: list[int] = []
        self._index: dict[uuid.UUID, int] = {}
        self._taken: set[int] = set()
        self._external: set[int] = set()   # in use on the host by resources we do not own (yet)

    def set_external(self, subnets) -> None:
        """Subnets that exist on the host but are not registered to a cell we manage (e.g. a
        cell mid-creation when we restarted). Never handed out while they exist."""
        out = set()
        for sn in subnets:
            if sn.prefixlen == 30 and sn.subnet_of(self._net):
                out.add((int(sn.network_address) - int(self._net.network_address)) // 4)
        # Slots that were skipped while occupied and are now vacant go back on the free list
        # (the bump pointer has already moved past them).
        for i in self._external - out:
            if i < self._next and i not in self._taken and i not in self._free:
                self._free.append(i)
        self._external = out

    def _subnet(self, i: int) -> ipaddress.IPv4Network:
        return ipaddress.ip_network((int(self._net.network_address) + 4 * i, 30))

    def _blocked(self, i: int) -> bool:
        return i in self._taken or i in self._external

    def allocate(self, cell_id: uuid.UUID) -> ipaddress.IPv4Network:
        if cell_id in self._index:
            return self._subnet(self._index[cell_id])
        i = None
        self._free = [f for f in self._free if f not in self._taken]  # drop reserved leftovers
        for k in range(len(self._free) - 1, -1, -1):  # prefer recently released
            if self._free[k] not in self._external:
                i = self._free.pop(k)
                break
        if i is None:
            while self._next < self._count and self._blocked(self._next):
                self._next += 1
            if self._next >= self._count:
                raise NftError("cell address pool exhausted")
            i = self._next
            self._next += 1
        self._index[cell_id] = i
        self._taken.add(i)
        return self._subnet(i)

    def reserve(self, cell_id: uuid.UUID, subnet: ipaddress.IPv4Network) -> None:
        """Claim a specific /30 (recovered from the running host)."""
        if subnet.prefixlen != 30 or not subnet.subnet_of(self._net):
            raise NftError(f"{subnet} is not a /30 inside pool {self._net}")
        i = (int(subnet.network_address) - int(self._net.network_address)) // 4
        if self._index.get(cell_id) == i:
            return
        if i in self._taken:
            raise NftError(f"{subnet} is already allocated to another cell")
        if cell_id in self._index:
            raise NftError(f"cell {cell_id} already holds a different subnet")
        self._index[cell_id] = i
        self._taken.add(i)

    def _slot(self, subnet: ipaddress.IPv4Network) -> int:
        if subnet.prefixlen != 30 or not subnet.subnet_of(self._net):
            raise NftError(f"{subnet} is not a /30 inside pool {self._net}")
        return (int(subnet.network_address) - int(self._net.network_address)) // 4

    def is_available(self, cell_id: uuid.UUID, subnet: ipaddress.IPv4Network) -> bool:
        """Could ``cell_id`` claim ``subnet`` right now (free, or already its own)?"""
        i = self._slot(subnet)
        return self._index.get(cell_id) == i or not self._blocked(i)

    def claim(self, cell_id: uuid.UUID, subnet: ipaddress.IPv4Network) -> None:
        """Take a specific /30 for a new cell (a restored guest keeps its address). Unlike
        ``reserve`` it also refuses subnets that exist on the host under someone else's name."""
        if not self.is_available(cell_id, subnet):
            raise NftError(f"{subnet} is already in use")
        self.reserve(cell_id, subnet)
        if self._slot(subnet) in self._free:
            self._free.remove(self._slot(subnet))

    def release(self, cell_id: uuid.UUID) -> None:
        i = self._index.pop(cell_id, None)
        if i is not None:
            self._taken.discard(i)
            self._free.append(i)


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

    def subnet_available(self, cell_id: uuid.UUID, subnet) -> bool:
        return self._alloc.is_available(cell_id, ipaddress.ip_network(subnet))

    async def register(self, cell_id: uuid.UUID, broker_port: int | None = None,
                       subnet=None) -> CellNet:
        """``subnet`` pins the cell to a specific /30 (restoring a snapshot); NftError if taken."""
        async with self._lock:
            if cell_id in self._cells:
                return self._cells[cell_id]
            if not self._installed:
                await self._nft.run(full_ruleset(self.cells))
                self._installed = True
            if subnet is not None:
                sn = ipaddress.ip_network(subnet)
                self._alloc.claim(cell_id, sn)
            else:
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

    async def adopt(self, cell: CellNet) -> None:
        """Take over a network that already exists on the host (e.g. after a service restart):
        reserve its /30 and re-grant its firewall tuple. Fails (leaving no state) if the
        address is outside the pool or already owned by another cell."""
        async with self._lock:
            if cell.cell_id in self._cells:
                return
            if not self._installed:
                await self._nft.run(full_ruleset(self.cells))
                self._installed = True
            self._alloc.reserve(cell.cell_id, ipaddress.ip_network(cell.network))
            try:
                await self._nft.run(_elements([cell]))
            except Exception:
                self._alloc.release(cell.cell_id)
                raise
            self._cells[cell.cell_id] = cell

    @property
    def broker_port(self) -> int:
        return self._port

    def set_external(self, subnets) -> None:
        self._alloc.set_external(subnets)

    def revoked_ids(self) -> list[uuid.UUID]:
        """Cells whose access was revoked but whose /30 is still reserved (failed teardown)."""
        return list(self._revoked)

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
