"""TAP device + address plumbing for a cell link (the part nftables rules are keyed on).

TAP is created through /dev/net/tun directly (persistent, owned by the jailer uid, so
Firecracker attaches without privileges); addressing uses pyroute2 netlink. pyroute2's
sync API cannot run on a live event loop, so async wrappers use a worker thread.
"""

import asyncio
import fcntl
import os
import struct

from pyroute2 import IPRoute

from aijailer.netpolicy.nft import CellNet

TUNSETIFF = 0x400454CA
TUNSETPERSIST = 0x400454CB
TUNSETOWNER = 0x400454CC
TUNSETGROUP = 0x400454CE
IFF_TAP, IFF_NO_PI = 0x0002, 0x1000

# Anti-spoofing / no-routing hardening applied to every cell interface.
_SYSCTLS = {
    "rp_filter": "1",          # drop packets whose source is not reachable via this iface
    "forwarding": "0",         # host never routes for the cell (nftables is the 2nd layer)
    "accept_local": "0",
    "accept_redirects": "0",
    "send_redirects": "0",
    "proxy_arp": "0",
    "arp_ignore": "1",         # answer ARP only for the address on this interface
}


def create_tap(ifname: str, uid: int, gid: int, dev: str = "/dev/net/tun") -> None:
    fd = os.open(dev, os.O_RDWR | os.O_CLOEXEC)
    try:
        req = struct.pack("16sH22x", ifname.encode(), IFF_TAP | IFF_NO_PI)
        fcntl.ioctl(fd, TUNSETIFF, req)
        fcntl.ioctl(fd, TUNSETOWNER, uid)
        fcntl.ioctl(fd, TUNSETGROUP, gid)
        fcntl.ioctl(fd, TUNSETPERSIST, 1)  # survives closing fd; removed by delete_link
    finally:
        os.close(fd)


def harden_iface(ifname: str, proc_root: str = "/proc/sys/net/ipv4/conf") -> None:
    for key, val in _SYSCTLS.items():
        with open(f"{proc_root}/{ifname}/{key}", "w") as f:
            f.write(val)


def setup_link(cell: CellNet, uid: int, gid: int, mtu: int = 1500) -> None:
    """Create the TAP, address the host end, harden, bring up. Rolls back on failure."""
    create_tap(cell.ifname, uid, gid)
    try:
        with IPRoute() as ipr:
            idx = ipr.link_lookup(ifname=cell.ifname)[0]
            ipr.addr("add", index=idx, address=str(cell.host_ip), prefixlen=cell.prefix)
            ipr.link("set", index=idx, mtu=mtu, state="up")
        harden_iface(cell.ifname)
    except Exception:
        teardown_link(cell.ifname)
        raise


def teardown_link(ifname: str) -> None:
    with IPRoute() as ipr:
        idx = ipr.link_lookup(ifname=ifname)
        if idx:
            ipr.link("del", index=idx[0])


async def asetup_link(cell: CellNet, uid: int, gid: int) -> None:
    await asyncio.to_thread(setup_link, cell, uid, gid)


async def ateardown_link(ifname: str) -> None:
    await asyncio.to_thread(teardown_link, ifname)
