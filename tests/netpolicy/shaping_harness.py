"""Runs INSIDE `unshare -n`. Real namespace link + real nftables + real tbf shapers; measures
actual TCP goodput in both directions between a 'guest' endpoint (an address on br0 inside the
cell namespace, standing in for the VM) and the host broker port."""
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

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from aijailer.netpolicy import link  # noqa: E402
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager  # noqa: E402
from aijailer.netpolicy.shaping import Bandwidth, apply_shaping, read_shaping  # noqa: E402

PORT = 3128
CHUNK = 65536


def server():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT))
    s.listen(8)

    def handle(c):
        mode = c.recv(1)
        n = int.from_bytes(c.recv(8), "big")
        if mode == b"U":  # guest uploads: host measures
            got, first, last = 0, None, None
            while got < n:
                d = c.recv(CHUNK)
                if not d:
                    break
                first = first or time.monotonic()
                got += len(d)
                last = time.monotonic()
            c.sendall(json.dumps({"bytes": got, "secs": (last - first) if first else 0}).encode())
        else:  # guest downloads: host sends, guest measures
            buf = b"x" * CHUNK
            sent = 0
            while sent < n:
                c.sendall(buf[: min(CHUNK, n - sent)])
                sent += min(CHUNK, n - sent)
        c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=handle, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return s


CLIENT = r'''
import os, socket, sys, time, json
fd = os.open("/run/netns/%(ns)s", os.O_RDONLY); os.setns(fd, 0x40000000)
mode, n = b"%(mode)s", %(n)d
s = socket.socket(); s.bind(("%(src)s", 0)); s.settimeout(60); s.connect(("%(dst)s", %(port)d))
s.sendall(mode + n.to_bytes(8, "big"))
if mode == b"U":
    buf = b"x" * 65536; sent = 0
    while sent < n:
        k = min(65536, n - sent); s.sendall(buf[:k]); sent += k
    s.shutdown(socket.SHUT_WR)
    print(s.recv(200).decode())
else:
    got, first, last = 0, None, None
    while got < n:
        d = s.recv(65536)
        if not d: break
        first = first or time.monotonic(); got += len(d); last = time.monotonic()
    print(json.dumps({"bytes": got, "secs": (last - first) if first else 0}))
'''


def measure(net, ns, mode, n):
    out = subprocess.run([sys.executable, "-c", CLIENT % dict(
        ns=ns, mode=mode.decode(), n=n, src=str(net.guest_ip), dst=str(net.host_ip), port=PORT)],
        capture_output=True, text=True, timeout=90).stdout.strip()
    r = json.loads(out)
    return round(r["bytes"] * 8 / r["secs"] / 1e6, 2) if r["secs"] else 0.0


def main():
    res = {}
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    mgr = NetPolicyManager(allocator=NetAllocator("10.90.0.0/24"), broker_port=PORT)
    net = asyncio.run_coroutine_threadsafe(mgr.register(uuid.uuid4()), loop).result(10)
    srv = server()
    link.setup_link(net, 10000, 10000)
    ns = link.netns_name(net)
    # The 'guest' endpoint: an address on br0 (frames leave via vc0 exactly like the VM's).
    with IPRoute(netns=ns) as inner:
        br = inner.link_lookup(ifname=link.BRIDGE)[0]
        inner.addr("add", index=br, address=str(net.guest_ip), prefixlen=net.prefix)
    time.sleep(1.2)  # neighbor/bridge settle

    def phase(name, bw, seconds=2.0):
        apply_shaping(net.ifname, ns, bw)
        res[f"{name}_readback"] = [read_shaping(net.ifname, ns).down_kbit,
                                   read_shaping(net.ifname, ns).up_kbit]
        def size(kbit):
            return int((kbit or 400_000) * 1000 / 8 * (seconds if kbit else 0.6))
        res[f"{name}_down_mbps"] = measure(net, ns, b"D", size(bw.down_kbit))
        res[f"{name}_up_mbps"] = measure(net, ns, b"U", size(bw.up_kbit))

    phase("unshaped", Bandwidth())
    phase("sym8", Bandwidth(8000, 8000))
    phase("asym", Bandwidth(4000, 16000))          # hot update to different limits
    phase("up_only", Bandwidth(None, 8000))        # clearing one direction
    phase("cleared", Bandwidth())                  # clearing both
    del srv
    link.teardown_link(net.ifname)
    print("RESULT" + json.dumps(res))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
