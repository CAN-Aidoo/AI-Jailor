"""End-to-end scenario for the WHOLE system, run inside `unshare -n` (the 'host').

E2E_ENGINE=chroot       dry run: real guest userland + real agent in the cell namespace (no KVM)
E2E_ENGINE=firecracker  the real thing: jailed Firecracker microVM booted with KVM

Everything else is real in both modes: SQL database, CellService, security-policy compilation,
nftables, namespaces/veth/bridge, bandwidth shaping, egress proxy, secret store, reconciler.
Prints one JSON object (RESULT...)."""
import asyncio
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

HERE = os.path.dirname(__file__)
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path[:0] = [os.path.join(ROOT, "src"), ROOT]

MODE = os.environ.get("E2E_ENGINE", "chroot")
WORK = tempfile.mkdtemp(prefix="e2e")
SECRET = "E2E-SECRET-VALUE-9f3a"
os.environ.update(
    DATABASE_URL=f"sqlite+aiosqlite:///{WORK}/db.sqlite", AIJAILER_ENV="dev",
    JAILER_UID="10000", JAILER_GID="10000", CELL_NET_POOL="10.97.0.0/24",
    SECRETS_MASTER_KEYS="k1:" + __import__("base64").urlsafe_b64encode(os.urandom(32)).decode(),
    RECONCILE_INTERVAL_SECONDS="3600")
if MODE == "firecracker":
    FC = os.environ["REAL_FC_DIR"]
    GUEST = os.environ["AIJAILER_GUEST_DIR"]
    os.makedirs(f"{WORK}/rootfs")
    BASE_EXT4 = f"{GUEST}/base-e2e.ext4"
    os.symlink(BASE_EXT4, f"{WORK}/rootfs/base-e2e.ext4")
    cg = open("/sys/fs/cgroup/cgroup.controllers").read().split() if os.path.exists(
        "/sys/fs/cgroup/cgroup.controllers") else []
    os.environ.update(
        ENGINE_BACKEND="firecracker", FIRECRACKER_BINARY=f"{FC}/bin/firecracker",
        JAILER_BINARY=f"{FC}/bin/jailer", KERNEL_IMAGE_PATH=f"{FC}/vmlinux",
        ROOTFS_DIR=f"{WORK}/rootfs", JAILER_CHROOT_BASE=f"{WORK}/jail",
        JAILER_USE_CGROUPS="true" if {"cpu", "memory"} <= set(cg) else "false")

from sqlalchemy import select  # noqa: E402
from pyroute2 import IPRoute  # noqa: E402

from aijailer.agentsec.proxy import CellProxy  # noqa: E402
from aijailer.db.base import Base, async_session_factory, engine as db_engine  # noqa: E402
from aijailer.engine import microvm  # noqa: E402
from aijailer.models.tenant import Tenant  # noqa: E402
from aijailer.netpolicy import runtime  # noqa: E402
from aijailer.netpolicy.cell_network import CellNetwork, NetnsLinkOps  # noqa: E402
from aijailer.netpolicy.discovery import scan_host  # noqa: E402
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager  # noqa: E402
from aijailer.netpolicy.reconciler import NetworkReconciler  # noqa: E402
from aijailer.secretstore.runtime import DbSecretProvider, get_secret_store  # noqa: E402
from aijailer.services.cell_service import CellService  # noqa: E402
from aijailer.services.policy_service import PolicyService  # noqa: E402
from tests.agentsec.test_proxy import Upstream, client_ctx  # noqa: E402

res: dict = {"mode": MODE}


def gpy(code: str) -> str:
    return "python3 -c " + shlex.quote(code)


HTTP = '''
import json,urllib.request,urllib.error
req=urllib.request.Request({url!r}, headers={headers!r}, data={data})
try:
    r=urllib.request.urlopen(req, timeout=25); print(json.dumps({{"status":r.status,"body":r.read(300).decode()}}))
except urllib.error.HTTPError as e: print(json.dumps({{"status":e.code,"body":e.read(300).decode()}}))
except Exception as e: print(json.dumps({{"error":type(e).__name__+":"+str(e)}}))
'''
PROBE = '''
import socket,json
out={{}}
for name,(h,p) in {targets!r}.items():
    s=socket.socket(); s.settimeout(2)
    try: s.connect((h,p)); out[name]="OPEN"
    except Exception as e: out[name]="BLOCKED:"+type(e).__name__
print(json.dumps(out))
'''
DOWNLOAD = '''
import json,time,urllib.request
t=time.monotonic(); r=urllib.request.urlopen({url!r}, timeout=60); first=None; n=0
while True:
    d=r.read(65536)
    if not d: break
    first = first or time.monotonic(); n+=len(d)
print(json.dumps({{"bytes":n,"mbps":round(n*8/(time.monotonic()-first)/1e6,2)}}))
'''
UPLOAD = '''
import json,time,urllib.request
data=b"x"*{size}
t=time.monotonic(); r=urllib.request.urlopen(urllib.request.Request({url!r}, data=data), timeout=60); r.read()
print(json.dumps({{"mbps":round(len(data)*8/(time.monotonic()-t)/1e6,2)}}))
'''


async def bulk_server(up):
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(up.cp, up.kp)

    async def handle(r, w):
        head = await r.readuntil(b"\r\n\r\n")
        clen = 0
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                clen = int(line.split(b":")[1])
        if clen:
            await r.readexactly(clen)
            body = b"ok"
        else:
            body = b"x" * (2 * 1024 * 1024)
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body))
        w.write(body)
        await w.drain()
        w.close()
    srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    return srv, srv.sockets[0].getsockname()[1]


async def main():
    async with db_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    up = Upstream(host="127.0.0.1")
    await up.start()
    bulk, bulk_port = await bulk_server(up)
    host_svc = await asyncio.start_server(lambda r, w: w.close(), "0.0.0.0", 9999)   # a host service

    # ---- engine ----
    if MODE == "chroot":
        from tests.e2e.harness_support import ChrootAgentEngine
        engine = ChrootAgentEngine(os.environ["AIJAILER_GUEST_TREE"], WORK)
        microvm._engine = engine
    else:
        engine = microvm.get_microvm_engine()
        await engine.preflight()
        res["base_sha_before"] = hashlib.sha256(open(BASE_EXT4, "rb").read()).hexdigest()

    # ---- real network layer (broker trusts our test CA) ----
    ctx = client_ctx(up)
    mk_net = lambda: CellNetwork(  # noqa: E731
        NetPolicyManager(allocator=NetAllocator("10.97.0.0/24"), broker_port=3128),
        NetnsLinkOps(10000, 10000), secrets=DbSecretProvider(async_session_factory),
        proxy_factory=lambda *a, **k: CellProxy(*a, ssl_context=ctx, **k))
    net = mk_net()
    runtime._network = net
    rt = await runtime.start_network_runtime(engine, interval=1.0,
                                             session_factory=async_session_factory)

    # ---- tenant, policy, secret ----
    async with async_session_factory() as db:
        tenant = Tenant(name="e2e", slug="e2e", status="active", tier="pro", max_concurrent_cells=10)
        db.add(tenant)
        await db.flush()
        policy = await PolicyService(db).create_policy(tenant.id, "egress", network_policy={
            "default": "deny", "egress": [{"action": "allow", "destinations": [{"ip": "127.0.0.1"}],
                                           "ports": [up.port, bulk_port]}]})
        await get_secret_store(db).create(tenant.id, "gh", SECRET, ["127.0.0.1"])
        await db.commit()
        tid, pid = tenant.id, policy.id

    async def create(name):
        async with async_session_factory() as db:
            cell = await CellService(db).create_cell(
                tenant_id=tid, name=name, image="base-e2e", vcpus=1, memory_mb=256, disk_mb=1024,
                network_bandwidth_mbps=50, security_policy_id=pid, environment={"E2E": "1"}, tags={})
            await db.commit()
            return cell

    async def svc_call(fn, *a, **k):
        async with async_session_factory() as db:
            out = await getattr(CellService(db), fn)(*a, **k)
            await db.commit()
            return out

    cell = await create("a")
    res["cell_status"] = cell.status
    res["cell_error"] = cell.error_message
    if cell.status != "running":
        return finish(res)
    cid = cell.id
    n = net._nets[cid]
    proxy_url = f"http://{n.host_ip}:{n.broker_port}"

    async def sh(cmd, c=cid, timeout=60):
        r = await engine.exec_command(c, cmd, timeout)
        return r

    async def gjson(code, c=cid, timeout=90):
        r = await sh(gpy(code), c, timeout)
        try:
            return json.loads(r.stdout.strip().splitlines()[-1])
        except Exception:
            return {"raw": r.stdout[-300:], "stderr": r.stderr[-300:], "exit": r.exit_code}

    def url(path="/v1", port=None):
        return f"http://127.0.0.1:{port or up.port}{path}"

    # ---- guest basics ----
    r = await sh("id -un; id -u; echo $http_proxy; echo $E2E")
    res["guest_basics"] = r.stdout.split()
    res["expected_proxy"] = proxy_url
    if MODE == "firecracker":
        res["pid1"] = (await sh("tr '\\0' ' ' </proc/1/cmdline")).stdout.strip()
        res["kernel_cmdline"] = (await sh("cat /proc/cmdline")).stdout.strip()
        res["eth0_state"] = (await sh("cat /sys/class/net/eth0/operstate")).stdout.strip()
        res["default_route"] = (await sh("cat /proc/net/route")).stdout.strip().splitlines()[1:]
        res["guest_kernel"] = (await sh("uname -r")).stdout.strip()

    # ---- egress through the broker with credential injection ----
    up.received.clear()
    res["http_allowed"] = await gjson(HTTP.format(url=url(), headers={"Authorization": "Bearer {{secret:gh}}"}, data=None))
    res["upstream_saw_secret"] = bool(up.received) and f"Bearer {SECRET}".encode() in up.received[-1]
    res["denied_host"] = await gjson(HTTP.format(url="http://evil.example/", headers={}, data=None))
    res["unbound_secret_host"] = await gjson(HTTP.format(
        url=url(port=bulk_port), headers={"Authorization": "{{secret:nope}}"}, data=None))
    leak = await sh(f"(env; cat /proc/*/environ 2>/dev/null; grep -rl {SECRET} /home /tmp /etc 2>/dev/null) "
                    f"| grep -c {SECRET} || true")
    res["secret_in_guest"] = int(leak.stdout.strip() or 0)

    # ---- bypass attempts ----
    probe = await gjson(PROBE.format(targets={
        "broker": (str(n.host_ip), n.broker_port), "host_service": (str(n.host_ip), 9999),
        "guest_loopback_upstream": ("127.0.0.1", up.port), "internet": ("1.1.1.1", 443),
        "host_ssh": (str(n.host_ip), 22)}))
    res["probe"] = probe

    # ---- second cell: no cell-to-cell, and no access to the other cell's link ----
    cell_b = await create("b")
    nb = net._nets[cell_b.id]
    res["probe_cell_to_cell"] = await gjson(PROBE.format(targets={
        "b_guest": (str(nb.guest_ip), 22), "b_gateway_broker": (str(nb.host_ip), nb.broker_port)}))

    # ---- bandwidth via the service (live) ----
    view = await svc_call("set_bandwidth", cid, tid, 8000, 8000)
    res["bandwidth_view"] = [view.configured.down_kbit, view.configured.up_kbit,
                             view.enforced.down_kbit if view.enforced else None,
                             view.enforced.up_kbit if view.enforced else None]
    res["download"] = await gjson(DOWNLOAD.format(url=url("/bulk", bulk_port)))
    res["upload"] = await gjson(UPLOAD.format(url=url("/up", bulk_port), size=1024 * 1024))

    # ---- secrets rotate / revoke live ----
    async with async_session_factory() as db:
        await get_secret_store(db).update(tid, "gh", value="ROTATED-VALUE")
    up.received.clear()
    await gjson(HTTP.format(url=url(), headers={"Authorization": "Bearer {{secret:gh}}"}, data=None))
    res["rotated_seen"] = bool(up.received) and b"Bearer ROTATED-VALUE" in up.received[-1]
    async with async_session_factory() as db:
        await get_secret_store(db).delete(tid, "gh")
    res["after_revoke"] = await gjson(HTTP.format(url=url(), headers={"Authorization": "Bearer {{secret:gh}}"}, data=None))
    async with async_session_factory() as db:
        await get_secret_store(db).create(tid, "gh", SECRET, ["127.0.0.1"])

    # ---- pause / resume ----
    await svc_call("pause_cell", cid, tid)
    try:
        await sh("true", timeout=5)
        res["exec_while_paused"] = "ran"
    except Exception as exc:
        res["exec_while_paused"] = "refused"
    await svc_call("resume_cell", cid, tid)
    res["after_resume"] = (await sh("echo alive")).stdout.strip()

    # ---- control-plane restart: networks of RUNNING guests are adopted, egress works again ----
    for p in list(net._proxies.values()):
        await p.stop()
    await rt.stop()
    net2 = mk_net()
    runtime._network = net2
    await net2.manager.install()                       # fresh ruleset: cells are cut off until adopted
    probe_cut = await gjson(PROBE.format(targets={"broker": (str(n.host_ip), n.broker_port)}))
    res["cut_off_before_sweep"] = probe_cut
    rec = NetworkReconciler(net2, async_session_factory, interval=3600)
    rep = await rec.run_once()
    res["sweep"] = {"adopted": len(rep.adopted), "broken": len(rep.broken), "errors": rep.errors,
                    "orphans": rep.orphans_removed}
    up.received.clear()
    res["http_after_adopt"] = await gjson(HTTP.format(
        url=url(), headers={"Authorization": "Bearer {{secret:gh}}"}, data=None))
    res["secret_after_adopt"] = bool(up.received) and f"Bearer {SECRET}".encode() in up.received[-1]
    net = net2

    # ---- teardown: nothing may remain ----
    pids = []
    if MODE == "firecracker":
        pids = [engine._vms[c]["fc_pid"] for c in (cid, cell_b.id) if c in engine._vms]
    await svc_call("stop_cell", cid, tid)
    await svc_call("destroy_cell", cid, tid)
    await svc_call("destroy_cell", cell_b.id, tid)
    await asyncio.sleep(0.5)
    st = await asyncio.to_thread(scan_host)
    res["leftover_links"] = sorted(st.names)
    res["fw_drift"] = await net.manager.verify()
    res["leftover_vmm"] = [p for p in pids if os.path.exists(f"/proc/{p}")]
    if MODE == "firecracker":
        res["leftover_jails"] = os.listdir(f"{WORK}/jail/firecracker") if os.path.isdir(
            f"{WORK}/jail/firecracker") else []
        res["base_sha_after"] = hashlib.sha256(open(BASE_EXT4, "rb").read()).hexdigest()
    return finish(res)


def finish(r):
    print("RESULT" + json.dumps(r, default=str))
    sys.stdout.flush()
    shutil.rmtree(WORK, ignore_errors=True)
    os._exit(0)


try:
    with IPRoute() as _ipr:                                   # lo up: upstreams listen on 127.0.0.1
        _ipr.link("set", index=1, state="up")
    asyncio.run(main())
except BaseException as exc:                      # never hang a test: report and exit
    import traceback
    res["harness_error"] = traceback.format_exc()[-1500:]
    finish(res)
