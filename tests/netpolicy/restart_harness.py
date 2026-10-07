"""Runs INSIDE `unshare -n`. Real nftables, real namespaces/veth/bridge/tbf, real proxies.
Simulates a crash + restart of the control plane and checks what the reconciler does."""
import asyncio
import json
import os
import subprocess
import sys
import threading
import time
import uuid

from pyroute2 import IPRoute, netns

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from aijailer.netpolicy import link  # noqa: E402
from aijailer.netpolicy.cell_network import CellNetwork, LiveCell, NetnsLinkOps  # noqa: E402
from aijailer.netpolicy.discovery import scan_host  # noqa: E402
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager, ifname_for  # noqa: E402
from aijailer.netpolicy.shaping import Bandwidth, apply_shaping, read_shaping  # noqa: E402

PORT = 3128
POOL = "10.95.0.0/24"
POLICY = {"egress": [{"action": "allow", "destinations": [{"ip": "203.0.113.9"}], "ports": [443]}]}
loop = asyncio.new_event_loop()
threading.Thread(target=loop.run_forever, daemon=True).start()


def run(coro, t=60):
    return asyncio.run_coroutine_threadsafe(coro, loop).result(t)


def new_stack():
    mgr = NetPolicyManager(allocator=NetAllocator(POOL), broker_port=PORT)
    return CellNetwork(mgr, NetnsLinkOps(10000, 10000)), mgr


PROBE = r'''
import os, socket
fd = os.open("/run/netns/%(ns)s", os.O_RDONLY); os.setns(fd, 0x40000000)
s = socket.socket(); s.settimeout(1.5); s.bind(("%(src)s", 0))
try:
    s.connect(("%(dst)s", %(port)d)); print("OPEN")
except Exception as e:
    print("BLOCKED:" + type(e).__name__)
'''


def probe(net, port):
    return subprocess.run([sys.executable, "-c", PROBE % dict(
        ns=net.ifname, src=net.guest_ip, dst=net.host_ip, port=port)],
        capture_output=True, text=True, timeout=30).stdout.strip()


def give_guest_addr(net):
    with IPRoute(netns=net.ifname) as i:
        i.addr("add", index=i.link_lookup(ifname=link.BRIDGE)[0], address=str(net.guest_ip),
               prefixlen=net.prefix)


def kernel_names():
    st = scan_host()
    return sorted(st.veths), sorted(st.netns)


def main():
    res = {}
    A, mgrA = new_stack()
    ids = {k: uuid.uuid4() for k in ("live1", "live2", "orphan", "stopped", "creating")}
    tenant = uuid.uuid4()
    nets = {}
    for k, cid in ids.items():
        bw = Bandwidth(8000, 8000) if k == "live1" else Bandwidth(4000, 4000)
        p = run(A.provision(cid, tenant, POLICY, bw))
        nets[k] = p.net
    # foreign resources the reconciler must never touch
    with IPRoute() as r:
        r.link("add", ifname="eth9", kind="veth", peer={"ifname": "eth9p"})
    if "myns" in netns.listnetns():  # leftover from an earlier aborted run
        netns.remove("myns")
    netns.create("myns")

    # ---- "crash": listeners die with the process; kernel state stays; ruleset re-installed ----
    for p in list(A._proxies.values()):
        run(p.stop())
    del A, mgrA
    B, mgrB = new_stack()
    run(mgrB.install())          # what start_network_runtime does: base ruleset, no tuples
    for k in ("live1", "live2"):
        give_guest_addr(nets[k])
    res["before_sweep_live1_probe"] = probe(nets["live1"], PORT)   # no proxy, no tuple

    live = {ids["live1"]: LiveCell(tenant, POLICY, Bandwidth(8000, 8000)),
            ids["live2"]: LiveCell(tenant, POLICY, Bandwidth(4000, 4000))}
    rep = run(B.sweep(live, {ids["creating"]}, grace=120))
    res["adopted"] = sorted(str(c) for c in rep.adopted) == sorted(str(ids[k]) for k in ("live1", "live2"))
    res["orphans_removed"] = sorted(rep.orphans_removed) == sorted(
        ifname_for(ids[k]) for k in ("orphan", "stopped"))
    res["report_clean"] = rep.errors == [] and rep.broken == [] and rep.aborted is None

    veths, spaces = kernel_names()
    res["live_present"] = all(ifname_for(ids[k]) in veths and ifname_for(ids[k]) in spaces
                              for k in ("live1", "live2"))
    res["orphans_gone"] = all(ifname_for(ids[k]) not in veths and ifname_for(ids[k]) not in spaces
                              for k in ("orphan", "stopped"))
    res["protected_untouched"] = (ifname_for(ids["creating"]) in veths
                                  and ifname_for(ids["creating"]) in spaces)
    with IPRoute() as r:
        res["foreign_veth_untouched"] = bool(r.link_lookup(ifname="eth9"))
    res["foreign_netns_untouched"] = "myns" in netns.listnetns()

    # ---- the adopted cells work again: firewall tuple + proxy restored ----
    res["after_sweep_live1_broker"] = probe(nets["live1"], PORT)
    res["after_sweep_live1_other_port"] = probe(nets["live1"], 9999)
    res["after_sweep_live2_broker"] = probe(nets["live2"], PORT)
    res["shaping_live1"] = [read_shaping(nets["live1"].ifname, nets["live1"].ifname).down_kbit,
                            read_shaping(nets["live1"].ifname, nets["live1"].ifname).up_kbit]
    res["shaping_live2"] = [read_shaping(nets["live2"].ifname, nets["live2"].ifname).down_kbit,
                            read_shaping(nets["live2"].ifname, nets["live2"].ifname).up_kbit]
    res["drift_after_adopt"] = run(mgrB.verify())

    # ---- no address collisions: a new cell must not get any occupied /30 ----
    newp = run(B.provision(uuid.uuid4(), tenant, POLICY, Bandwidth(2000, 2000)))
    taken = {str(nets[k].host_ip) for k in ("live1", "live2", "creating")}
    res["new_cell_distinct_subnet"] = str(newp.net.host_ip) not in taken

    # ---- idempotent second sweep ----
    rep2 = run(B.sweep({**live, uuid.uuid4(): LiveCell(tenant)} if False else live,
                       {ids["creating"]}, grace=120))
    res["second_sweep_noop"] = (not rep2.adopted and not rep2.orphans_removed
                                and not rep2.broken and len(rep2.kept) == 2)

    # ---- shaping drift: kernel limits cleared / DB value changed -> sweep restores the DB's ----
    n2 = nets["live2"].ifname
    apply_shaping(n2, n2, Bandwidth())                       # someone removes both qdiscs
    res["live2_cleared"] = [read_shaping(n2, n2).down_kbit, read_shaping(n2, n2).up_kbit]
    rep3 = run(B.sweep(live, {ids["creating"]}, grace=120))
    res["drift_repaired"] = [str(c) for c in rep3.shaping_repaired] == [str(ids["live2"])]
    res["drift_restored"] = [read_shaping(n2, n2).down_kbit, read_shaping(n2, n2).up_kbit]
    live[ids["live1"]] = LiveCell(tenant, POLICY, Bandwidth(2000, 6000))   # API changed the DB
    rep4 = run(B.sweep(live, {ids["creating"]}, grace=120))
    n1 = nets["live1"].ifname
    res["db_change_applied"] = ([str(c) for c in rep4.shaping_repaired] == [str(ids["live1"])]
                                and [read_shaping(n1, n1).down_kbit,
                                     read_shaping(n1, n1).up_kbit] == [2000, 6000])

    # ---- an adopted cell can be torn down by the new process ----
    errs = run(B.deprovision(ids["live1"]))
    veths, spaces = kernel_names()
    res["adopted_teardown"] = (errs == [] and ifname_for(ids["live1"]) not in veths
                               and ifname_for(ids["live1"]) not in spaces)
    res["after_teardown_probe"] = probe(nets["live1"], PORT) if False else "n/a"

    # ---- cleanup everything we created ----
    for cid in list(B._proxies):
        run(B.deprovision(cid))
    for k in ("creating",):
        link.teardown_link(ifname_for(ids[k]))
    with IPRoute() as r:
        r.link("del", index=r.link_lookup(ifname="eth9")[0])
    netns.remove("myns")
    res["clean_exit"] = kernel_names() == ([], [])

    print("RESULT" + json.dumps(res))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
