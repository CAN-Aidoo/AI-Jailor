"""Firecracker engine: drives the real Firecracker REST API and guest agent.

We do not reimplement a VMM. This module is a thin, fail-closed controller
for Firecracker (the VMM AWS runs Lambda/Fargate on), started under the
official ``jailer`` (chroot + namespaces + cgroups + seccomp).

Fail-closed rules:
* No ``/dev/kvm`` -> ``EngineUnavailable``. Never a fake success.
* Every cell gets its own writable copy of the base rootfs (reflink when the
  filesystem supports it) and a unique vsock CID. The shared base image is
  never opened read-write.
* Exec goes over vsock to the guest agent (length-prefixed JSON); there is no
  network path between host control and guest.

Everything that needs root/KVM (spawn, TAP, nftables) is behind ``spawner`` /
``kvm_path`` so the API client and protocol logic are unit-testable.
"""

import asyncio
import json
import os
import shutil
import struct
import subprocess
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

import httpx

from aijailer.core.config import get_settings
from aijailer.engine.microvm import (
    EngineUnavailable,
    ExecResult,
    MicroVMEngine,
    VMConfig,
    VMInfo,
    VMStatus,
)

_MAX_FRAME = 16 * 1024 * 1024


class FirecrackerAPI:
    """Minimal client for Firecracker's HTTP-over-UDS API."""

    def __init__(self, sock_path: str) -> None:
        self._client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=sock_path), base_url="http://localhost",
            timeout=10.0,
        )

    async def _call(self, method: str, path: str, body: dict | None = None) -> None:
        r = await self._client.request(method, path, json=body)
        if r.status_code >= 300:
            raise RuntimeError(f"firecracker {method} {path} -> {r.status_code}: {r.text}")

    async def configure(self, cfg: dict) -> None:
        await self._call("PUT", "/boot-source", cfg["boot-source"])
        for d in cfg["drives"]:
            await self._call("PUT", f"/drives/{d['drive_id']}", d)
        await self._call("PUT", "/machine-config", cfg["machine-config"])
        await self._call("PUT", "/vsock", cfg["vsock"])

    async def start(self) -> None:
        await self._call("PUT", "/actions", {"action_type": "InstanceStart"})

    async def ctrl_alt_del(self) -> None:
        await self._call("PUT", "/actions", {"action_type": "SendCtrlAltDel"})

    async def set_state(self, state: str) -> None:
        await self._call("PATCH", "/vm", {"state": state})  # "Paused" | "Resumed"

    async def create_snapshot(self, snap_path: str, mem_path: str) -> None:
        await self._call("PUT", "/snapshot/create", {
            "snapshot_type": "Full", "snapshot_path": snap_path, "mem_file_path": mem_path})

    async def load_snapshot(self, snap_path: str, mem_path: str, resume: bool = True) -> None:
        await self._call("PUT", "/snapshot/load", {
            "snapshot_path": snap_path,
            "mem_backend": {"backend_path": mem_path, "backend_type": "File"},
            "resume_vm": resume})

    async def close(self) -> None:
        await self._client.aclose()


async def agent_exec(vsock_uds: str, port: int, command: str, timeout: int,
                     user: str) -> ExecResult:
    """Run one command in the guest agent via Firecracker's vsock UDS proxy.

    Host side of the proxy protocol: connect to the UDS, send ``CONNECT <port>\\n``,
    expect ``OK <n>\\n``; then speak length-prefixed JSON with the agent.
    """
    reader, writer = await asyncio.open_unix_connection(vsock_uds)
    try:
        writer.write(f"CONNECT {port}\n".encode())
        await writer.drain()
        ack = await asyncio.wait_for(reader.readline(), 5)
        if not ack.startswith(b"OK"):
            raise RuntimeError(f"vsock connect refused: {ack!r}")
        req = json.dumps({"op": "exec", "cmd": command, "timeout": timeout, "user": user}).encode()
        writer.write(struct.pack(">I", len(req)) + req)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout + 5)
        (n,) = struct.unpack(">I", hdr)
        if n > _MAX_FRAME:
            raise RuntimeError("agent frame too large")
        resp = json.loads(await asyncio.wait_for(reader.readexactly(n), timeout + 5))
        return ExecResult(
            exit_code=int(resp["exit_code"]), stdout=resp.get("stdout", ""),
            stderr=resp.get("stderr", ""), duration_ms=int(resp.get("duration_ms", 0)),
            cpu_ms=int(resp.get("cpu_ms", 0)), memory_peak_mb=int(resp.get("memory_peak_mb", 0)),
        )
    finally:
        writer.close()


def jailer_argv(settings, vm_id: str, mem_mib: int, vcpus: int) -> list[str]:
    """Official jailer invocation (chroot, cgroups v2, non-root uid, own netns)."""
    return [
        settings.jailer_binary, "--id", vm_id, "--exec-file", settings.firecracker_binary,
        "--uid", str(settings.jailer_uid), "--gid", str(settings.jailer_gid),
        "--chroot-base-dir", settings.jailer_chroot_base, "--cgroup-version", "2",
        "--cgroup", f"cpu.max={vcpus * 100000} 100000",
        "--cgroup", f"memory.max={(mem_mib + 64) * 1024 * 1024}",
        "--new-pid-ns", "--", "--api-sock", "api.sock",
    ]


Spawner = Callable[[list[str]], Awaitable[int]]  # returns pid


async def _default_spawner(argv: list[str]) -> int:
    proc = await asyncio.create_subprocess_exec(*argv, stdout=subprocess.DEVNULL,
                                                stderr=subprocess.DEVNULL)
    return proc.pid


class FirecrackerEngine(MicroVMEngine):
    isolation = "hardware-kvm"

    def __init__(self, spawner: Spawner | None = None, kvm_path: str = "/dev/kvm",
                 api_factory: Callable[[str], FirecrackerAPI] = FirecrackerAPI,
                 agent_call=agent_exec) -> None:
        self.settings = get_settings()
        self._spawner = spawner or _default_spawner
        self._kvm = kvm_path
        self._api_factory = api_factory
        self._agent_call = agent_call
        self._vms: dict[uuid.UUID, dict] = {}
        self._next_cid = 3  # 0-2 reserved by the vsock spec

    def _require_kvm(self) -> None:
        if not os.path.exists(self._kvm):
            raise EngineUnavailable(f"{self._kvm} not present: refusing to run without hardware isolation")

    def _cell_dir(self, cell_id: uuid.UUID) -> Path:
        path = Path(self.settings.cell_data_dir) / str(cell_id)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        return path

    def _build_config(self, config: VMConfig, cell_dir: Path, cid: int) -> dict:
        return {
            "boot-source": {
                "kernel_image_path": self.settings.kernel_image_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro",
            },
            "drives": [{
                "drive_id": "rootfs",
                "path_on_host": str(cell_dir / "rootfs.ext4"),  # per-cell copy
                "is_root_device": True,
                "is_read_only": False,
            }],
            "machine-config": {"vcpu_count": config.vcpus, "mem_size_mib": config.memory_mb,
                               "smt": False},
            "vsock": {"guest_cid": cid, "uds_path": str(cell_dir / "vsock.sock")},
        }

    @staticmethod
    def _clone_rootfs(base: Path, dest: Path) -> None:
        if not base.exists():
            raise FileNotFoundError(f"base image missing: {base}")
        r = subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(base), str(dest)],
                           capture_output=True)
        if r.returncode != 0:
            shutil.copyfile(base, dest)
        os.chmod(dest, 0o600)

    async def create_vm(self, config: VMConfig) -> VMInfo:
        self._require_kvm()
        cell_dir = self._cell_dir(config.cell_id)
        self._clone_rootfs(Path(self.settings.rootfs_dir) / f"{config.image}.ext4",
                           cell_dir / "rootfs.ext4")
        cid = self._next_cid
        self._next_cid += 1
        fc_config = self._build_config(config, cell_dir, cid)
        argv = jailer_argv(self.settings, str(config.cell_id), config.memory_mb, config.vcpus)
        pid = await self._spawner(argv)
        sock = str(cell_dir / "api.sock")
        deadline = time.monotonic() + 5
        while not os.path.exists(sock):
            if time.monotonic() > deadline:
                raise RuntimeError("firecracker API socket did not appear")
            await asyncio.sleep(0.02)
        api = self._api_factory(sock)
        await api.configure(fc_config)
        await api.start()
        info = VMInfo(cell_id=config.cell_id, status=VMStatus.RUNNING, pid=pid,
                      vsock_path=fc_config["vsock"]["uds_path"])
        self._vms[config.cell_id] = {"info": info, "api": api, "cid": cid, "dir": cell_dir}
        return info

    def _vm(self, cell_id: uuid.UUID) -> dict:
        vm = self._vms.get(cell_id)
        if vm is None:
            raise KeyError(f"unknown cell {cell_id}")
        return vm

    async def start_vm(self, cell_id: uuid.UUID) -> VMInfo:
        vm = self._vm(cell_id)
        if vm["info"].status == VMStatus.PAUSED:
            await vm["api"].set_state("Resumed")
            vm["info"].status = VMStatus.RUNNING
        elif vm["info"].status == VMStatus.STOPPED:
            raise RuntimeError("stopped microVMs cannot be restarted in place; create a new cell "
                               "or restore a snapshot")
        return vm["info"]

    async def stop_vm(self, cell_id: uuid.UUID, grace_period: int = 10) -> None:
        vm = self._vm(cell_id)
        try:
            await vm["api"].ctrl_alt_del()
        except Exception:
            pass
        await asyncio.sleep(0)  # yield; guest shutdown is awaited by the caller's grace loop
        self._kill(vm["info"].pid)
        vm["info"].status = VMStatus.STOPPED

    @staticmethod
    def _kill(pid: int | None) -> None:
        if pid:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass

    async def pause_vm(self, cell_id: uuid.UUID) -> None:
        vm = self._vm(cell_id)
        await vm["api"].set_state("Paused")
        vm["info"].status = VMStatus.PAUSED

    async def resume_vm(self, cell_id: uuid.UUID) -> None:
        vm = self._vm(cell_id)
        await vm["api"].set_state("Resumed")
        vm["info"].status = VMStatus.RUNNING

    async def destroy_vm(self, cell_id: uuid.UUID) -> None:
        vm = self._vms.pop(cell_id, None)
        if vm:
            self._kill(vm["info"].pid)
            await vm["api"].close()
            shutil.rmtree(vm["dir"], ignore_errors=True)

    async def snapshot_vm(self, cell_id: uuid.UUID, snapshot_dir: str) -> dict:
        vm = self._vm(cell_id)
        out = Path(snapshot_dir)
        out.mkdir(parents=True, exist_ok=True, mode=0o700)
        was_running = vm["info"].status == VMStatus.RUNNING
        if was_running:
            await vm["api"].set_state("Paused")
        await vm["api"].create_snapshot(str(out / "vm.snap"), str(out / "vm.mem"))
        shutil.copyfile(vm["dir"] / "rootfs.ext4", out / "rootfs.ext4")
        if was_running:
            await vm["api"].set_state("Resumed")
        return {"state": str(out / "vm.snap"), "memory": str(out / "vm.mem"),
                "disk": str(out / "rootfs.ext4")}

    async def exec_command(self, cell_id: uuid.UUID, command: str, timeout: int = 30,
                           user: str = "agent") -> ExecResult:
        vm = self._vm(cell_id)
        if vm["info"].status != VMStatus.RUNNING:
            raise RuntimeError(f"cell is {vm['info'].status.value}, cannot exec")
        return await self._agent_call(vm["info"].vsock_path, self.settings.agent_vsock_port,
                                      command, timeout, user)

    async def get_vm_info(self, cell_id: uuid.UUID) -> VMInfo:
        vm = self._vms.get(cell_id)
        return vm["info"] if vm else VMInfo(cell_id=cell_id, status=VMStatus.DESTROYED)
