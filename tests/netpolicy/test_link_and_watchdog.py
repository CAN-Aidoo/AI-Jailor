import asyncio
import os
import shutil
import subprocess
import sys
import textwrap
import uuid

import pytest

from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager, watchdog


def _netns_ok():
    if os.geteuid() != 0 or not shutil.which("unshare") or not os.path.exists("/dev/net/tun"):
        return False
    try:
        import pyroute2  # noqa: F401
    except ImportError:
        return False
    return subprocess.run(["unshare", "-n", "true"]).returncode == 0


@pytest.mark.skipif(not _netns_ok(), reason="needs root, netns, /dev/net/tun, pyroute2")
def test_tap_link_real_kernel():
    code = textwrap.dedent('''
        import ipaddress, uuid, os, json
        from pyroute2 import IPRoute
        from aijailer.netpolicy.nft import CellNet, ifname_for
        from aijailer.netpolicy.link import setup_link, teardown_link
        cid = uuid.uuid4()
        c = CellNet(cid, ifname_for(cid), ipaddress.IPv4Address("10.9.0.1"),
                    ipaddress.IPv4Address("10.9.0.2"), 30, 3128)
        setup_link(c, 10000, 10000)
        out = {}
        with IPRoute() as r:
            i = r.link_lookup(ifname=c.ifname)[0]
            link = r.get_links(i)[0]
            out["up"] = bool(link["flags"] & 1)
            out["addr"] = [a.get_attr("IFA_ADDRESS") for a in r.get_addr(index=i)]
        base = "/proc/sys/net/ipv4/conf/" + c.ifname + "/"
        out["rp"] = open(base + "rp_filter").read().strip()
        out["fwd"] = open(base + "forwarding").read().strip()
        with IPRoute() as r:
            d = r.get_links(r.link_lookup(ifname=c.ifname)[0])[0].get_nested(
                "IFLA_LINKINFO", "IFLA_INFO_DATA")
            out["owner"] = str(d.get_attr("IFLA_TUN_OWNER"))
            out["persist"] = d.get_attr("IFLA_TUN_PERSIST")
        teardown_link(c.ifname)
        with IPRoute() as r:
            out["gone"] = not r.link_lookup(ifname=c.ifname)
        print("OUT" + json.dumps(out))
    ''')
    env = {**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "..", "src")}
    r = subprocess.run(["unshare", "-n", sys.executable, "-c", code], capture_output=True,
                       text=True, env=env, timeout=60)
    import json
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("OUT")), None)
    assert line, r.stdout + r.stderr
    out = json.loads(line[3:])
    assert out["up"] and "10.9.0.1" in out["addr"]
    assert out["rp"] == "1" and out["fwd"] == "0" and out["owner"] == "10000" and out["persist"] == 1
    assert out["gone"] is True


class Flaky:
    """Runner whose live table 'disappears' once, then is reinstalled."""

    def __init__(self):
        self.installed = 0
        self.table_present = False

    async def run(self, script, check_only=False):
        if script.startswith("add table"):
            self.installed += 1
            self.table_present = True
        return ""

    async def list_json(self):
        from aijailer.netpolicy.nft import NftError
        if not self.table_present:
            raise NftError("No such file or directory")
        return {"nftables": [{"chain": {"name": n}} for n in
                             ("input", "from_cell", "forward", "output")]
                + [{"set": {"name": "broker", "elem": []}}]}


@pytest.mark.asyncio
async def test_watchdog_reports_and_repairs_drift():
    f = Flaky()
    m = NetPolicyManager(runner=f, allocator=NetAllocator("10.7.0.0/24"))
    seen, stop = [], asyncio.Event()

    def on_drift(d):
        seen.append(d)
        stop.set()

    await watchdog(m, interval=0.01, on_drift=on_drift, stop=stop)
    assert seen and "table missing" in seen[0][0]
    assert f.installed == 1 and f.table_present  # repaired
