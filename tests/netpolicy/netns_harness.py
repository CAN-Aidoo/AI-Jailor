"""Runs INSIDE `unshare -n` as the 'host' netns. Builds real kernel topology and
exercises the nftables enforcement with real TCP. Prints one JSON object of results.

Topology:  [cell A netns] --veth-- (host: ajA) ... host ... (host: ajB) --veth-- [cell B netns]
           plus a host-local 'internet' address 192.0.2.1 (dummy-less: added to lo).
"""
import asyncio
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid

from pyroute2 import IPRoute

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager, ifname_for  # noqa: E402

BROKER_PORT = 3128
CLONE_NEWNET = 0x40000000


def in_new_netns(argv_script: str):
    """Start a child in a new netns that waits on stdin; return Popen."""
    code = ("import os,sys;os.unshare(0x40000000);print('ready',flush=True);"
            "sys.stdin.readline()")
    p = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, text=True)
    assert p.stdout.readline().strip() == "ready"
    return p


def listen(host, port, banner):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(16)

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            c.sendall(banner)
            c.close()
    threading.Thread(target=loop, daemon=True).start()
    return s


def cell_run(pid, code, timeout=15):
    """Run python code inside a cell's netns (nsenter-free: setns via os)."""
    wrapper = ("import os,sys\nfd=os.open('/proc/%d/ns/net',os.O_RDONLY)\n"
               "os.setns(fd,0x40000000)\n%s" % (pid, code))
    r = subprocess.run([sys.executable, "-c", wrapper], capture_output=True, text=True,
                       timeout=timeout)
    return r.stdout.strip()


def tcp_probe(pid, src, dst, port, bind_src=True):
    code = f"""
import socket
s=socket.socket(); s.settimeout(1.5)
{'s.bind(("%s",0))' % src if bind_src else ''}
try:
    s.connect(("{dst}",{port})); print("OPEN:"+s.recv(64).decode())
except Exception as e:
    print("BLOCKED:"+type(e).__name__)
"""
    return cell_run(pid, code)


def main():
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()

    def run(coro):
        return asyncio.run_coroutine_threadsafe(coro, loop).result(30)
    ipr = IPRoute()
    res = {}
    ipr.link("set", index=1, state="up")  # lo up in host netns
    ipr.addr("add", index=1, address="192.0.2.1", prefixlen=32)  # fake 'internet'

    mgr = NetPolicyManager(allocator=NetAllocator("10.200.0.0/24"), broker_port=BROKER_PORT)
    cells = {}
    for name in ("A", "B"):
        cid = uuid.uuid4()
        net = run(mgr.register(cid))
        child = in_new_netns("")
        host_if = net.ifname
        tmp_peer = "pe" + name
        ipr.link("add", ifname=host_if, kind="veth", peer={"ifname": tmp_peer})
        idx_h = ipr.link_lookup(ifname=host_if)[0]
        idx_p = ipr.link_lookup(ifname=tmp_peer)[0]
        ipr.link("set", index=idx_p, net_ns_fd=os.open(f"/proc/{child.pid}/ns/net", os.O_RDONLY))
        ipr.addr("add", index=idx_h, address=str(net.host_ip), prefixlen=30)
        ipr.link("set", index=idx_h, state="up")
        cell_run(child.pid, f"""
from pyroute2 import IPRoute
r=IPRoute(); i=r.link_lookup(ifname="{tmp_peer}")[0]
r.link("set",index=i,ifname="eth0"); i=r.link_lookup(ifname="eth0")[0]
r.addr("add",index=i,address="{net.guest_ip}",prefixlen=30)
r.link("set",index=i,state="up"); r.link("set",index=1,state="up")
r.route("add",dst="default",gateway="{net.host_ip}")
""")
        cells[name] = (cid, net, child)

    # Host services: the broker (allowed), another host service (must be unreachable),
    # and a service on the fake internet (reachable only via forwarding: must be blocked).
    _, nA, cA = cells["A"]
    _, nB, cB = cells["B"]
    # Even with forwarding ON (worst-case misconfiguration) the firewall must hold.
    open("/proc/sys/net/ipv4/ip_forward", "w").write("1")
    listen("0.0.0.0", BROKER_PORT, b"broker")      # 0.0.0.0 => reachable on every iface
    listen("0.0.0.0", 9999, b"hostsvc")             # NOT the broker port
    listen("192.0.2.1", 80, b"internet")

    res["broker_open"] = tcp_probe(cA.pid, nA.guest_ip, nA.host_ip, BROKER_PORT)
    res["other_host_port_blocked"] = tcp_probe(cA.pid, nA.guest_ip, nA.host_ip, 9999)
    res["internet_blocked_forwarding_on"] = tcp_probe(cA.pid, nA.guest_ip, "192.0.2.1", 80)
    res["spoofed_source_blocked"] = tcp_probe(cA.pid, nB.guest_ip, nA.host_ip, BROKER_PORT) \
        if False else None
    # Spoof: cell A claims cell B's guest IP as source toward the broker.
    cell_run(cA.pid, f"""
from pyroute2 import IPRoute
r=IPRoute(); i=r.link_lookup(ifname="eth0")[0]
r.addr("add",index=i,address="{nB.guest_ip}",prefixlen=32)
""")
    res["spoofed_source_blocked"] = tcp_probe(cA.pid, nB.guest_ip, nA.host_ip, BROKER_PORT)
    # Cell A -> cell B's link address (cell-to-cell), forwarding on.
    res["cell_to_cell_blocked"] = tcp_probe(cA.pid, nA.guest_ip, nB.guest_ip, BROKER_PORT)
    # Broker IP of ANOTHER cell's link from cell A (host-side address of B).
    res["other_cells_gateway_blocked"] = tcp_probe(cA.pid, nA.guest_ip, nB.host_ip, BROKER_PORT)
    # Host cannot open NEW connections into the cell.
    listen_code = f"""
import socket,threading
s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("{nA.guest_ip}",7000));s.listen(1);open("/tmp/aj_ready","w").write("1")
c,_=s.accept();c.sendall(b"cellsvc")
"""
    srv = subprocess.Popen([sys.executable, "-c",
        f"import os\nos.setns(os.open('/proc/{cA.pid}/ns/net',os.O_RDONLY),0x40000000)\n{listen_code}"])
    for _ in range(50):
        if os.path.exists("/tmp/aj_ready"):
            break
        time.sleep(0.05)
    try:
        os.remove("/tmp/aj_ready")
    except OSError:
        pass
    s = socket.socket(); s.settimeout(1.5)
    try:
        s.connect((str(nA.guest_ip), 7000)); res["host_to_cell_blocked"] = "OPEN:" + s.recv(16).decode()
    except Exception as e:
        res["host_to_cell_blocked"] = "BLOCKED:" + type(e).__name__
    srv.kill()
    # IPv6: cell must not reach the host over v6 either.
    res["ipv6_blocked"] = cell_run(cA.pid, f"""
import socket
try:
    s=socket.socket(socket.AF_INET6); s.settimeout(1.5)
except OSError:
    print("UNAVAILABLE"); raise SystemExit
try:
    s.connect(("fe80::1%eth0",{BROKER_PORT}));print("OPEN")
except Exception as e: print("BLOCKED:"+type(e).__name__)
""")

    # Drift detection + repair.
    res["drift_clean"] = run(mgr.verify())
    subprocess.run(["nft", "delete", "table", "inet", "aijailer"], check=True)
    res["drift_after_delete"] = run(mgr.verify())
    res["blocked_while_table_missing_note"] = "see fail-open doc"
    repaired = run(mgr.enforce())
    res["repaired"] = bool(repaired)
    res["drift_after_repair"] = run(mgr.verify())
    res["broker_open_after_repair"] = tcp_probe(cA.pid, nA.guest_ip, nA.host_ip, BROKER_PORT)

    # Teardown: unregister removes access immediately.
    run(mgr.unregister(cells["A"][0]))
    res["broker_after_unregister"] = tcp_probe(cA.pid, nA.guest_ip, nA.host_ip, BROKER_PORT)
    res["address_reused_after_release"] = str((run(mgr.register(uuid.uuid4()))).host_ip) == str(nA.host_ip)

    # ---- Phase 2: real egress proxy behind the firewall, credential injection e2e ----
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
    from aijailer.agentsec.egress import EgressBroker, EgressRule, SecretBinding
    from aijailer.agentsec.proxy import CellProxy
    from tests.agentsec.test_proxy import SECRET, Upstream, client_ctx

    up = Upstream()
    run(up.start())
    cidC = uuid.uuid4()
    nC = run(mgr.register(cidC, broker_port=3129))
    childC = in_new_netns("")
    ipr.link("add", ifname=nC.ifname, kind="veth", peer={"ifname": "peC"})
    iH, iP = ipr.link_lookup(ifname=nC.ifname)[0], ipr.link_lookup(ifname="peC")[0]
    ipr.link("set", index=iP, net_ns_fd=os.open(f"/proc/{childC.pid}/ns/net", os.O_RDONLY))
    ipr.addr("add", index=iH, address=str(nC.host_ip), prefixlen=30)
    ipr.link("set", index=iH, state="up")
    cell_run(childC.pid, f"""
from pyroute2 import IPRoute
r=IPRoute(); i=r.link_lookup(ifname="peC")[0]
r.addr("add",index=i,address="{nC.guest_ip}",prefixlen=30)
r.link("set",index=i,state="up"); r.link("set",index=1,state="up")
""")
    events = []
    broker = EgressBroker([EgressRule("api.test", ports=(up.port,))],
                          [SecretBinding("gh", SECRET, ("api.test",))],
                          resolver=lambda h: ["127.0.0.1"], allow_private_cidrs=["127.0.0.0/8"])
    proxy = CellProxy(str(cidC), str(nC.host_ip), 3129, broker, audit=events.append,
                      ssl_context=client_ctx(up))
    run(proxy.start())

    def via_proxy(raw: str) -> str:
        return cell_run(childC.pid, f"""
import socket
s=socket.socket(); s.settimeout(5); s.bind(("{nC.guest_ip}",0))
s.connect(("{nC.host_ip}",3129)); s.sendall({raw!r}.encode())
buf=b""
while True:
    d=s.recv(65536)
    if not d: break
    buf+=d
print(buf.split(b"\\r\\n")[0].decode()+"|"+buf.split(b"\\r\\n\\r\\n",1)[-1].decode())
""")
    ok = via_proxy(f"GET http://api.test:{up.port}/v1 HTTP/1.1\r\nHost: api.test\r\n"
                   "Authorization: Bearer {{secret:gh}}\r\n\r\n")
    res["e2e_allowed"] = ok
    res["e2e_upstream_saw_secret"] = bool(up.received) and SECRET.encode() in up.received[0]
    res["e2e_cell_never_saw_secret"] = SECRET not in ok
    res["e2e_denied"] = via_proxy("GET http://evil.example/ HTTP/1.1\r\nHost: evil.example\r\n\r\n")
    # Bypass attempts from the cell: straight to the upstream's port on the host, and to
    # the proxy's address on a different port.
    res["e2e_direct_upstream_blocked"] = tcp_probe(childC.pid, nC.guest_ip, nC.host_ip, up.port)
    res["e2e_proxy_wrong_port_blocked"] = tcp_probe(childC.pid, nC.guest_ip, nC.host_ip, 3130)
    res["e2e_audit"] = [{k: e.get(k) for k in ("decision", "host", "status")} for e in events]
    res["e2e_audit_has_no_secret"] = SECRET not in json.dumps(events, default=str)
    childC.kill()

    print("RESULT" + json.dumps(res, default=str))
    for _, _, ch in cells.values():
        ch.kill()
    os._exit(0)


if __name__ == "__main__":
    main()
