"""Test-only stand-in for the VMM: runs the real guest agent inside the real guest userland (a chroot
of the rootfs tree) inside the cell's network namespace. It reproduces everything about a cell that
does not need KVM: real userland (python3, sh, coreutils), real agent protocol, and the guest's view of
the network (an address on the cell bridge, default route via the host end), so the rest of the system
(CellService, firewall, broker, shaping, secrets, reconciler) runs for real against it."""

import asyncio
import json
import os
import signal
import struct
import subprocess
import uuid
from pathlib import Path

from pyroute2 import IPRoute

from aijailer.engine.microvm import ExecResult, MicroVMEngine, VMConfig, VMInfo, VMStatus

CLONE_NEWNET = 0x40000000


class ChrootAgentEngine(MicroVMEngine):
    isolation = "chroot-dryrun"      # NOT hardware isolation: this engine is a test double
    needs_network = True

    def __init__(self, tree: str, workdir: str) -> None:
        self.tree, self.workdir = Path(tree), Path(workdir)
        self._vms: dict[uuid.UUID, dict] = {}

    @staticmethod
    def _join_netns(path: str):
        def fn():
            fd = os.open(path, os.O_RDONLY)
            os.setns(fd, CLONE_NEWNET)
            os.close(fd)
        return fn

    @staticmethod
    def _address_guest(net) -> None:
        with IPRoute(netns=os.path.basename(net.netns_path)) as r:
            br = r.link_lookup(ifname="br0")[0]
            r.addr("add", index=br, address=net.guest_ip, prefixlen=net.prefix)
            r.link("set", index=br, state="up")
            r.route("add", dst="default", gateway=net.host_ip)

    async def create_vm(self, config: VMConfig) -> VMInfo:
        net = config.network
        assert net is not None and net.netns_path, "the dry-run guest needs the cell namespace"
        await asyncio.to_thread(self._address_guest, net)
        sock_dir = self.workdir / f"g-{str(config.cell_id)[:8]}"
        sock_dir.mkdir(parents=True, exist_ok=True)
        t = self.tree
        os.makedirs(t / "run" / "aj", exist_ok=True)
        script = (f"mount --bind {sock_dir} {t}/run/aj && mount -t proc proc {t}/proc && "
                  f"mount --rbind /dev {t}/dev && "
                  f"exec env -i PATH=/usr/bin:/bin $(command -v chroot) {t} /sbin/aijailer-agent "
                  f"-listen unix:/run/aj/a.sock -max-concurrent 8")
        log = open(sock_dir / "agent.log", "wb")
        proc = subprocess.Popen(
            ["unshare", "-m", "--propagation", "private", "sh", "-c", script],
            preexec_fn=self._join_netns(net.netns_path), start_new_session=True,
            stdout=log, stderr=log)
        sock = sock_dir / "a.sock"
        for _ in range(200):
            if sock.exists():
                break
            if proc.poll() is not None:
                raise RuntimeError("guest agent exited: " + (sock_dir / "agent.log").read_text()[-400:])
            await asyncio.sleep(0.05)
        else:
            proc.kill()
            raise RuntimeError("guest agent did not start")
        info = VMInfo(config.cell_id, VMStatus.RUNNING, pid=proc.pid, internal_ip=net.guest_ip,
                      vsock_path=str(sock))
        self._vms[config.cell_id] = {"info": info, "proc": proc, "dir": sock_dir,
                                     "env": dict(config.environment or {})}
        return info

    def _vm(self, cell_id):
        return self._vms[cell_id]

    async def start_vm(self, cell_id):
        return self._vm(cell_id)["info"]

    async def stop_vm(self, cell_id, grace_period=10):
        vm = self._vm(cell_id)
        self._killpg(vm["proc"])
        vm["info"].status = VMStatus.STOPPED

    @staticmethod
    def _killpg(proc):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()

    async def pause_vm(self, cell_id):
        vm = self._vm(cell_id)
        os.killpg(vm["proc"].pid, signal.SIGSTOP)
        vm["info"].status = VMStatus.PAUSED

    async def resume_vm(self, cell_id):
        vm = self._vm(cell_id)
        os.killpg(vm["proc"].pid, signal.SIGCONT)
        vm["info"].status = VMStatus.RUNNING

    async def destroy_vm(self, cell_id):
        vm = self._vms.pop(cell_id, None)
        if vm:
            self._killpg(vm["proc"])

    async def exec_command(self, cell_id, command, timeout=30, user="agent", env=None, cwd=None):
        vm = self._vm(cell_id)
        if vm["info"].status != VMStatus.RUNNING:
            raise RuntimeError(f"cell is {vm['info'].status.value}, cannot exec")
        r, w = await asyncio.open_unix_connection(vm["info"].vsock_path)
        body = json.dumps({"op": "exec", "cmd": command, "timeout": timeout, "user": user,
                           "env": {**vm["env"], **(env or {})},
                           **({"cwd": cwd} if cwd else {})}).encode()
        w.write(struct.pack(">I", len(body)) + body)
        await w.drain()
        (n,) = struct.unpack(">I", await asyncio.wait_for(r.readexactly(4), timeout + 10))
        resp = json.loads(await r.readexactly(n))
        w.close()
        if "error" in resp:
            raise RuntimeError(resp["error"])
        return ExecResult(resp["exit_code"], resp.get("stdout", ""), resp.get("stderr", ""),
                          resp.get("duration_ms", 0), timed_out=resp.get("timed_out", False))

    async def get_vm_info(self, cell_id):
        vm = self._vms.get(cell_id)
        return vm["info"] if vm else VMInfo(cell_id, VMStatus.DESTROYED)
