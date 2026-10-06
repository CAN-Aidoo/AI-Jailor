"""Runs INSIDE `unshare -n`: drives the REAL CellNetwork (nft + proxy) with a veth link stand-in
for the TAP (a TAP's far end belongs to a VMM). Prints one JSON object of observations."""
import asyncio
import json
import os
import sys
import threading
import uuid

from pyroute2 import IPRoute

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
sys.path.insert(0, os.path.join(HERE, "..", ".."))
sys.path.insert(0, HERE)
from netns_harness import cell_run, in_new_netns, tcp_probe  # noqa: E402

from aijailer.agentsec.egress import SecretBinding  # noqa: E402
from aijailer.agentsec.proxy import CellProxy  # noqa: E402
from aijailer.netpolicy.cell_network import CellNetwork  # noqa: E402
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager, ifname_for  # noqa: E402
from tests.agentsec.test_proxy import SECRET, Upstream, client_ctx  # noqa: E402

PORT = 3128
loop = asyncio.new_event_loop()
threading.Thread(target=loop.run_forever, daemon=True).start()


def run(coro):
    return asyncio.run_coroutine_threadsafe(coro, loop).result(30)


class VethLinks:
    """LinkOps stand-in: veth pair, peer moved into the cell's netns (a 'guest')."""

    def __init__(self, ipr, guests):
        self.ipr, self.guests, self.fail_next = ipr, guests, False

    async def setup(self, cell):
        await asyncio.to_thread(self._setup, cell)

    def _setup(self, cell):
        if self.fail_next:
            self.fail_next = False
            raise OSError("injected link failure")
        child = self.guests[cell.ifname]
        peer = "p" + cell.ifname[2:10]
        self.ipr.link("add", ifname=cell.ifname, kind="veth", peer={"ifname": peer})
        h = self.ipr.link_lookup(ifname=cell.ifname)[0]
        p = self.ipr.link_lookup(ifname=peer)[0]
        self.ipr.link("set", index=p, net_ns_fd=os.open(f"/proc/{child.pid}/ns/net", os.O_RDONLY))
        self.ipr.addr("add", index=h, address=str(cell.host_ip), prefixlen=cell.prefix)
        self.ipr.link("set", index=h, state="up")
        cell_run(child.pid, f"""
from pyroute2 import IPRoute
r=IPRoute(); i=r.link_lookup(ifname="{peer}")[0]
r.addr("add",index=i,address="{cell.guest_ip}",prefixlen={cell.prefix})
r.link("set",index=i,state="up"); r.link("set",index=1,state="up")
""")

    async def set_bandwidth(self, cell, bw):
        pass  # shaping is verified separately (test_netns_shaping)

    async def get_bandwidth(self, cell):
        from aijailer.netpolicy.shaping import Bandwidth
        return Bandwidth()

    async def teardown(self, ifname):
        await asyncio.to_thread(self._teardown, ifname)

    def _teardown(self, ifname):
        idx = self.ipr.link_lookup(ifname=ifname)
        if idx:
            self.ipr.link("del", index=idx[0])


class Secrets:
    async def secrets_for(self, tenant_id, cell_id):
        return [SecretBinding("gh", SECRET, ("127.0.0.1",))]


def new_guest(cid):
    return in_new_netns("")


def main():
    ipr = IPRoute()
    ipr.link("set", index=1, state="up")
    up = Upstream(host="127.0.0.1")
    run(up.start())
    policy = {"default": "deny", "egress": [
        {"action": "allow", "destinations": [{"ip": "127.0.0.1"}], "ports": [up.port]}]}
    guests = {}
    links = VethLinks(ipr, guests)
    mgr = NetPolicyManager(allocator=NetAllocator("10.60.0.0/29"), broker_port=PORT)  # two /30s
    net = CellNetwork(mgr, links, secrets=Secrets(),
                      proxy_factory=lambda *a, **k: CellProxy(*a, ssl_context=client_ctx(up), **k))
    res = {}

    def prep(cid):
        g = new_guest(cid)
        guests[ifname_for(cid)] = g
        return g

    def via_proxy(g, p, raw):
        return cell_run(g.pid, f"""
import socket
s=socket.socket(); s.settimeout(5); s.bind(("{p.net.guest_ip}",0))
s.connect(("{p.net.host_ip}",{p.net.broker_port})); s.sendall({raw!r}.encode())
buf=b""
while True:
    d=s.recv(65536)
    if not d: break
    buf+=d
print(buf.split(b"\\\\r\\\\n")[0].decode()+"|"+buf.split(b"\\\\r\\\\n\\\\r\\\\n",1)[-1].decode())
""")

    # --- 1. provision + use ---
    cid = uuid.uuid4()
    g = prep(cid)
    p = run(net.provision(cid, uuid.uuid4(), policy))
    res["env_proxy"] = p.env["http_proxy"] == f"http://{p.net.host_ip}:{PORT}"
    res["allowed_call"] = via_proxy(g, p, f"GET http://127.0.0.1:{up.port}/v1 HTTP/1.1\r\n"
                                          "Authorization: Bearer {{secret:gh}}\r\n\r\n")
    res["upstream_saw_secret"] = bool(up.received) and SECRET.encode() in up.received[0]
    res["cell_never_saw_secret"] = SECRET not in res["allowed_call"]
    res["denied_call"] = via_proxy(g, p, "GET http://evil.example/ HTTP/1.1\r\n\r\n")
    res["direct_upstream_blocked"] = tcp_probe(g.pid, p.net.guest_ip, p.net.host_ip, up.port)
    res["drift_after_provision"] = run(mgr.verify())
    host_ip, ifname = str(p.net.host_ip), p.net.ifname

    # --- 2. deprovision: access revoked, link gone, port closed, address reusable ---
    errs = run(net.deprovision(cid))
    res["teardown_errors"] = errs
    res["link_gone"] = not ipr.link_lookup(ifname=ifname)
    res["registry_empty"] = mgr.cells == [] and net.provisioned == set()
    res["drift_after_teardown"] = run(mgr.verify())
    g.kill()

    # --- 3. address reuse (pool holds exactly two /30s) + failure injection ---
    cid2 = uuid.uuid4()
    g2 = prep(cid2)
    p2 = run(net.provision(cid2, uuid.uuid4(), policy))
    res["address_reused"] = str(p2.net.host_ip) == host_ip
    cid3 = uuid.uuid4()
    prep(cid3)
    links.fail_next = True
    try:
        run(net.provision(cid3, uuid.uuid4(), policy))
        res["failed_provision_raised"] = False
    except OSError:
        res["failed_provision_raised"] = True
    res["failed_provision_clean"] = (
        not ipr.link_lookup(ifname=ifname_for(cid3)) and cid3 not in net.provisioned
        and [c.cell_id for c in mgr.cells] == [cid2] and run(mgr.verify()) == [])

    # --- 4. reconcile removes a leaked network ---
    stale = run(net.reconcile(set()))
    res["reconciled"] = stale == [cid2] and mgr.cells == [] and not ipr.link_lookup(
        ifname=ifname_for(cid2))
    g2.kill()
    res["final_drift"] = run(mgr.verify())

    print("RESULT" + json.dumps(res, default=str))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
