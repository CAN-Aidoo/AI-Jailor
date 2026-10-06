"""Per-cell link: a dedicated network namespace for the VMM, bridged to the host by a veth.

        root netns                         cell netns  (/run/netns/<ifname>; jailer --netns)
   +------------------+   veth pair   +----------------------------------+
   | aj<id>  host_ip  |<------------->| vc0 --[ br0 ]-- tap0 <--> Firecracker/guest
   +------------------+               +----------------------------------+

Why a namespace: the VMM process (Firecracker, started by the jailer inside this netns)
can then see exactly one network device and nothing of the host's: a compromised VMM has no
route to host services, other cells' links or the internet. The bridge makes the guest NIC
and the host's veth end one L2 segment, so everything the firewall (``nft.py``) and the
broker assume (iifname ``aj*``, guest/host /30, source-address match) holds unchanged.

TAP is created inside the namespace (persistent, owned by the jailer uid, so Firecracker
attaches unprivileged). pyroute2's sync API cannot run on a live event loop, so async
wrappers use worker threads; namespace entry happens only in throwaway threads, never in
a pooled thread that could later run unrelated work in the wrong namespace.
"""

import asyncio
import fcntl
import os
import struct
import threading
import time

from pyroute2 import IPRoute, netns

from aijailer.netpolicy.nft import CellNet, LinkInfo

TUNSETIFF = 0x400454CA
TUNSETPERSIST = 0x400454CB
TUNSETOWNER = 0x400454CC
TUNSETGROUP = 0x400454CE
IFF_TAP, IFF_NO_PI = 0x0002, 0x1000
CLONE_NEWNET = 0x40000000

TAP_NAME = "tap0"     # fixed inside every cell netns (names are per-namespace)
BRIDGE = "br0"
PEER = "vc0"
NETNS_DIR = "/run/netns"

# Anti-spoofing / no-routing hardening applied to the host-side veth.
_SYSCTLS = {
    "rp_filter": "1",          # drop packets whose source is not reachable via this iface
    "forwarding": "0",         # host never routes for the cell (nftables is the 2nd layer)
    "accept_local": "0",
    "accept_redirects": "0",
    "send_redirects": "0",
    "proxy_arp": "0",
    "arp_ignore": "1",         # answer ARP only for the address on this interface
}


def netns_name(cell: CellNet) -> str:
    return cell.ifname


def netns_path(cell: CellNet, netns_dir: str = NETNS_DIR) -> str:
    return f"{netns_dir}/{netns_name(cell)}"


def _in_netns(path: str, fn, *args):
    """Run fn in a throwaway thread that has entered the namespace at ``path``."""
    out: dict = {}

    def target():
        try:
            fd = os.open(path, os.O_RDONLY)
            try:
                os.setns(fd, CLONE_NEWNET)  # per-thread; the thread then simply exits
            finally:
                os.close(fd)
            out["v"] = fn(*args)
        except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
            out["e"] = exc

    t = threading.Thread(target=target)
    t.start()
    t.join()
    if "e" in out:
        raise out["e"]
    return out.get("v")


def _create_tap(ifname: str, uid: int, gid: int, dev: str = "/dev/net/tun") -> None:
    fd = os.open(dev, os.O_RDWR | os.O_CLOEXEC)
    try:
        req = struct.pack("16sH22x", ifname.encode(), IFF_TAP | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, req)
        fcntl.ioctl(fd, TUNSETOWNER, uid)
        fcntl.ioctl(fd, TUNSETGROUP, gid)
        fcntl.ioctl(fd, TUNSETPERSIST, 1)  # survives closing fd; dies with the namespace
    finally:
        os.close(fd)


def create_tap(ifname: str, uid: int, gid: int, path: str | None = None,
               dev: str = "/dev/net/tun") -> None:
    """Create a persistent TAP, inside the namespace at ``path`` when given."""
    if path is None:
        _create_tap(ifname, uid, gid, dev)
    else:
        _in_netns(path, _create_tap, ifname, uid, gid, dev)


def harden_iface(ifname: str, proc_root: str = "/proc/sys/net/ipv4/conf") -> None:
    for key, val in _SYSCTLS.items():
        with open(f"{proc_root}/{ifname}/{key}", "w") as f:
            f.write(val)


def setup_link(cell: CellNet, uid: int, gid: int, mtu: int = 1500,
               netns_dir: str = NETNS_DIR) -> LinkInfo:
    """Create namespace + TAP + veth + bridge, address/harden the host end, bring all up.
    Rolls everything back on any failure."""
    name, path = netns_name(cell), netns_path(cell, netns_dir)
    try:
        if name in netns.listnetns():  # leaked by a crash; names are per-cell UUIDs
            netns.remove(name)
        netns.create(name)
        create_tap(TAP_NAME, uid, gid, path)

        with IPRoute() as root:
            root.link("add", ifname=cell.ifname, kind="veth", peer={"ifname": PEER})
            peer_idx = root.link_lookup(ifname=PEER)[0]
            nsfd = os.open(path, os.O_RDONLY)
            try:
                root.link("set", index=peer_idx, net_ns_fd=nsfd)
            finally:
                os.close(nsfd)
            host_idx = root.link_lookup(ifname=cell.ifname)[0]
            root.addr("add", index=host_idx, address=str(cell.host_ip), prefixlen=cell.prefix)
            root.link("set", index=host_idx, mtu=mtu, state="up")
        harden_iface(cell.ifname)

        with IPRoute(netns=name) as inner:
            inner.link("add", ifname=BRIDGE, kind="bridge")
            br = inner.link_lookup(ifname=BRIDGE)[0]
            for port in (TAP_NAME, PEER):
                idx = inner.link_lookup(ifname=port)[0]
                inner.link("set", index=idx, master=br, mtu=mtu, state="up")
            inner.link("set", index=br, state="up")
            inner.link("set", index=1, state="up")  # lo
        _wait_oper_up(cell.ifname, name)
    except BaseException:
        teardown_link(cell.ifname, netns_dir)
        raise
    return LinkInfo(TAP_NAME, path)


def _oper_up(ipr: IPRoute, ifname: str) -> bool:
    idx = ipr.link_lookup(ifname=ifname)
    return bool(idx) and ipr.get_links(idx[0])[0].get_attr("IFLA_OPERSTATE") == "UP"


def _wait_oper_up(host_if: str, ns: str, timeout: float = 5.0) -> None:
    """Block until both veth ends are operationally UP.

    Carrier changes are applied asynchronously (linkwatch, up to ~1 s). Until then the
    bridge will not forward through the veth port, so early frames would be silently lost and
    a 'ready' cell would not be ready. Fail (and roll back) rather than report a dead link."""
    deadline = time.monotonic() + timeout
    while True:
        with IPRoute() as root, IPRoute(netns=ns) as inner:
            if _oper_up(root, host_if) and _oper_up(inner, PEER):
                return
        if time.monotonic() > deadline:
            raise TimeoutError(f"link for {host_if} did not come up within {timeout}s")
        time.sleep(0.05)


def teardown_link(ifname: str, netns_dir: str = NETNS_DIR) -> None:
    """Idempotent. Deleting the veth removes its peer; removing the namespace drops the TAP."""
    with IPRoute() as ipr:
        idx = ipr.link_lookup(ifname=ifname)
        if idx:
            ipr.link("del", index=idx[0])
    if ifname in netns.listnetns():
        netns.remove(ifname)


async def asetup_link(cell: CellNet, uid: int, gid: int) -> LinkInfo:
    return await asyncio.to_thread(setup_link, cell, uid, gid)


async def ateardown_link(ifname: str) -> None:
    await asyncio.to_thread(teardown_link, ifname)
