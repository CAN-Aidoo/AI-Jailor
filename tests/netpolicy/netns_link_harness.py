"""Runs INSIDE `unshare -n` (the 'host'). Exercises the REAL setup_link/teardown_link and
plays the VM: it attaches to the TAP inside the cell namespace (as Firecracker would) and
exchanges raw Ethernet/ARP/TCP frames with the host, with the real nftables rules active."""
import asyncio
import fcntl
import json
import os
import select
import socket
import struct
import sys
import threading
import time
import uuid

from pyroute2 import IPRoute, netns

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))
from aijailer.netpolicy import link  # noqa: E402
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager  # noqa: E402

BROKER = 3128
GMAC = bytes.fromhex("02aa0a000002")


def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def arp_request(spa, tpa):
    return (b"\xff" * 6 + GMAC + b"\x08\x06" + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
            + GMAC + socket.inet_aton(spa) + b"\0" * 6 + socket.inet_aton(tpa))


def syn(dmac, src, dst, dport, sport=40000):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 0, 5 << 4, 0x02, 8192, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    return dmac + GMAC + b"\x08\x00" + ip + tcp


def open_tap_in_netns(path):
    box = {}

    def go():
        fd = os.open(path, os.O_RDONLY)
        os.setns(fd, link.CLONE_NEWNET)
        os.close(fd)
        t = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
        fcntl.ioctl(t, link.TUNSETIFF, struct.pack("16sH22x", b"tap0", link.IFF_TAP | link.IFF_NO_PI))
        box["fd"] = t

    th = threading.Thread(target=go)
    th.start()
    th.join()
    return box["fd"]


def recv_until(fd, pred, timeout=1.5):
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            frame = os.read(fd, 2048)
            if pred(frame):
                return frame
    return None


def is_arp_reply(f):
    return f[12:14] == b"\x08\x06" and struct.unpack("!H", f[20:22])[0] == 2


def is_synack_from(host_ip, port):
    def p(f):
        return (f[12:14] == b"\x08\x00" and f[23] == 6 and f[26:30] == socket.inet_aton(host_ip)
                and struct.unpack("!H", f[34:36])[0] == port and f[47] & 0x12 == 0x12)
    return p


def tcp_ports(f):
    return struct.unpack("!HH", f[34:38]) if f[12:14] == b"\x08\x00" and f[23] == 6 else None


def listen(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    return s


def main():
    res = {}
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()

    def run(c):
        return asyncio.run_coroutine_threadsafe(c, loop).result(30)

    mgr = NetPolicyManager(allocator=NetAllocator("10.70.0.0/24"), broker_port=BROKER)
    cid = uuid.uuid4()
    net = run(mgr.register(cid))
    name = link.netns_name(net)
    servers = [listen(BROKER), listen(9999)]  # keep references: GC would close them (-> RST)

    # ---- real setup ----
    info = link.setup_link(net, 10000, 10000)
    res["info"] = [info.tap_name, info.netns_path == f"/run/netns/{name}"]
    res["netns_listed"] = name in netns.listnetns() and os.path.exists(info.netns_path)
    with IPRoute(netns=name) as inner:
        links = {l.get_attr("IFLA_IFNAME"): l for l in inner.get_links()}
        res["netns_devices"] = sorted(links)
        br_idx = links[link.BRIDGE]["index"]
        res["bridge_ports"] = sorted(n for n in (link.TAP_NAME, link.PEER)
                                     if links[n].get_attr("IFLA_MASTER") == br_idx)
        d = links[link.TAP_NAME].get_nested("IFLA_LINKINFO", "IFLA_INFO_DATA")
        res["tap_owner"], res["tap_persist"] = d.get_attr("IFLA_TUN_OWNER"), d.get_attr("IFLA_TUN_PERSIST")
        res["all_up"] = all(links[n]["flags"] & 1 for n in (link.TAP_NAME, link.PEER, link.BRIDGE))
    with IPRoute() as root:
        host = root.link_lookup(ifname=net.ifname)
        res["host_veth_present"] = bool(host)
        res["host_addr"] = [a.get_attr("IFA_ADDRESS") for a in root.get_addr(index=host[0])]
    base = f"/proc/sys/net/ipv4/conf/{net.ifname}/"
    res["sysctls"] = [open(base + k).read().strip() for k in ("rp_filter", "forwarding", "arp_ignore")]

    # ---- play the VM: raw frames through TAP -> bridge -> veth -> host ----
    tap = open_tap_in_netns(info.netns_path)
    time.sleep(0.2)
    os.write(tap, arp_request(str(net.guest_ip), str(net.host_ip)))
    reply = recv_until(tap, is_arp_reply)
    res["arp_reply"] = reply is not None
    if reply:
        hmac = reply[6:12]
        os.write(tap, syn(hmac, str(net.guest_ip), str(net.host_ip), BROKER))
        res["syn_to_broker_answered"] = recv_until(tap, is_synack_from(str(net.host_ip), BROKER)) is not None
        os.write(tap, syn(hmac, str(net.guest_ip), str(net.host_ip), 9999, 40001))
        # ANY TCP frame back (SYN-ACK or RST) would mean the firewall let the packet through.
        res["syn_to_other_port_answered"] = recv_until(tap, lambda f: (tcp_ports(f) or (0, 0))[0] == 9999, 1.5) is not None
        os.write(tap, syn(hmac, "10.70.0.99", str(net.host_ip), BROKER, 40002))
        # (retransmitted SYN-ACKs of the legitimate handshake are for sport 40000, not 40002)
        res["spoofed_syn_answered"] = recv_until(
            tap, lambda f: (tcp_ports(f) or (0, 0))[1] == 40002, 1.5) is not None
    os.close(tap)

    # ---- teardown ----
    link.teardown_link(net.ifname)
    link.teardown_link(net.ifname)  # idempotent
    with IPRoute() as root:
        res["host_veth_gone"] = not root.link_lookup(ifname=net.ifname)
    res["netns_gone"] = name not in netns.listnetns() and not os.path.exists(info.netns_path)

    # ---- stale namespace from a crash is recovered ----
    netns.create(name)
    link.setup_link(net, 10000, 10000)
    res["stale_recovered"] = True
    link.teardown_link(net.ifname)

    # ---- rollback at two different failure points leaves nothing behind ----
    def leftovers():
        with IPRoute() as root:
            return bool(root.link_lookup(ifname=net.ifname)) or name in netns.listnetns()

    real_tap, real_harden = link.create_tap, link.harden_iface
    link.create_tap = lambda *a, **k: (_ for _ in ()).throw(OSError("tap boom"))
    try:
        link.setup_link(net, 10000, 10000)
        res["rollback_tap"] = "no-raise"
    except OSError:
        res["rollback_tap"] = "clean" if not leftovers() else "LEAK"
    link.create_tap = real_tap
    link.harden_iface = lambda *a, **k: (_ for _ in ()).throw(OSError("sysctl boom"))
    try:
        link.setup_link(net, 10000, 10000)
        res["rollback_after_veth"] = "no-raise"
    except OSError:
        res["rollback_after_veth"] = "clean" if not leftovers() else "LEAK"
    link.harden_iface = real_harden

    print("RESULT" + json.dumps(res, default=str))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
