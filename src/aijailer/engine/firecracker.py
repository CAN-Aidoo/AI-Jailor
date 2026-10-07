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
import base64
import dataclasses
import hashlib
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
    EngineSweepReport,
    EngineUnavailable,
    ExecResult,
    MicroVMEngine,
    VMConfig,
    VMInfo,
    VMStatus,
)
from aijailer.netpolicy.cell_network import MASS_REMOVAL_FRACTION, MASS_REMOVAL_MIN

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

    async def state(self) -> str:
        """Instance state as reported by the VMM: "Not started" | "Running" | "Paused"."""
        r = await self._client.get("/")
        if r.status_code >= 300:
            raise RuntimeError(f"firecracker GET / -> {r.status_code}: {r.text}")
        return str(r.json().get("state", ""))

    async def configure(self, cfg: dict) -> None:
        await self._call("PUT", "/boot-source", cfg["boot-source"])
        for d in cfg["drives"]:
            await self._call("PUT", f"/drives/{d['drive_id']}", d)
        await self._call("PUT", "/machine-config", cfg["machine-config"])
        await self._call("PUT", "/vsock", cfg["vsock"])
        for nic in cfg.get("network-interfaces", []):
            await self._call("PUT", f"/network-interfaces/{nic['iface_id']}", nic)

    async def start(self) -> None:
        await self._call("PUT", "/actions", {"action_type": "InstanceStart"})

    async def ctrl_alt_del(self) -> None:
        await self._call("PUT", "/actions", {"action_type": "SendCtrlAltDel"})

    async def set_state(self, state: str) -> None:
        await self._call("PATCH", "/vm", {"state": state})  # "Paused" | "Resumed"

    async def create_snapshot(self, snap_path: str, mem_path: str) -> None:
        await self._call("PUT", "/snapshot/create", {
            "snapshot_type": "Full", "snapshot_path": snap_path, "mem_file_path": mem_path})

    async def load_snapshot(self, snap_path: str, mem_path: str, resume: bool = True,
                            network_overrides: list[dict] | None = None) -> None:
        body: dict = {
            "snapshot_path": snap_path,
            "mem_backend": {"backend_path": mem_path, "backend_type": "File"},
            "resume_vm": resume}
        if network_overrides:
            body["network_overrides"] = network_overrides    # [{"iface_id", "host_dev_name"}]
        await self._call("PUT", "/snapshot/load", body)

    async def close(self) -> None:
        await self._client.aclose()


class SnapshotError(RuntimeError):
    """A snapshot bundle is unusable or does not match the restore request."""


class AgentError(RuntimeError):
    """The guest agent refused or failed a request (it replied {"error": ...})."""


async def agent_request(vsock_uds: str, port: int, request: dict, timeout: float) -> dict:
    """One request/response with the guest agent via Firecracker's vsock UDS proxy.

    Host side of the proxy protocol: connect to the UDS, send ``CONNECT <port>\\n``,
    expect ``OK <n>\\n``; then speak length-prefixed JSON with the agent
    (see guest-agent/protocol.go). The reply is untrusted input from the guest.
    """
    reader, writer = await asyncio.open_unix_connection(vsock_uds)
    try:
        writer.write(f"CONNECT {port}\n".encode())
        await writer.drain()
        ack = await asyncio.wait_for(reader.readline(), 5)
        if not ack.startswith(b"OK"):
            raise RuntimeError(f"vsock connect refused: {ack!r}")
        body = json.dumps(request).encode()
        if len(body) > _MAX_FRAME:
            raise ValueError("request too large")
        writer.write(struct.pack(">I", len(body)) + body)
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout)
        (n,) = struct.unpack(">I", hdr)
        if n > _MAX_FRAME:
            raise RuntimeError("agent frame too large")
        resp = json.loads(await asyncio.wait_for(reader.readexactly(n), timeout))
        if not isinstance(resp, dict):
            raise RuntimeError("agent reply is not an object")
        if "error" in resp:
            raise AgentError(str(resp["error"]))
        return resp
    finally:
        writer.close()


async def agent_ping(vsock_uds: str, port: int, timeout: float = 2.0) -> dict:
    return await agent_request(vsock_uds, port, {"op": "ping"}, timeout)


async def agent_put_file(vsock_uds: str, port: int, path: str, data: bytes, mode: int = 0o644,
                         user: str = "agent") -> None:
    await agent_request(vsock_uds, port, {
        "op": "put_file", "path": path, "mode": mode, "user": user,
        "data": base64.b64encode(data).decode()}, 30)


async def agent_get_file(vsock_uds: str, port: int, path: str) -> bytes:
    resp = await agent_request(vsock_uds, port, {"op": "get_file", "path": path}, 30)
    return base64.b64decode(resp["data"], validate=True)


async def agent_exec(vsock_uds: str, port: int, command: str, timeout: int,
                     user: str, env: dict | None = None, cwd: str | None = None) -> ExecResult:
    req = {"op": "exec", "cmd": command, "timeout": timeout, "user": user}
    if env:
        req["env"] = env
    if cwd:
        req["cwd"] = cwd
    resp = await agent_request(vsock_uds, port, req, timeout + 5)
    return ExecResult(
        exit_code=int(resp["exit_code"]), stdout=resp.get("stdout", ""),
        stderr=resp.get("stderr", ""), duration_ms=int(resp.get("duration_ms", 0)),
        cpu_ms=int(resp.get("cpu_ms", 0)), memory_peak_mb=int(resp.get("memory_peak_mb", 0)),
        timed_out=bool(resp.get("timed_out", False)),
        output_truncated=bool(resp.get("output_truncated", False)),
    )


def jailer_argv(settings, vm_id: str, mem_mib: int, vcpus: int,
                netns_path: str | None = None) -> list[str]:
    """Official jailer invocation (chroot, cgroups v2, non-root uid, own PID ns, and, when the
    cell has a NIC, the cell's dedicated network namespace so the VMM sees no host network).

    Everything after ``--`` is interpreted INSIDE the jail: ``api.sock`` becomes
    ``<jail root>/api.sock`` on the host."""
    netns = ["--netns", netns_path] if netns_path else []
    cgroups: list[str] = []
    if settings.jailer_use_cgroups:
        cgroups = ["--cgroup-version", "2",
                   "--cgroup", f"cpu.max={vcpus * 100000} 100000",
                   "--cgroup", f"memory.max={(mem_mib + 64) * 1024 * 1024}"]
    return [
        settings.jailer_binary, "--id", vm_id, "--exec-file", settings.firecracker_binary,
        "--uid", str(settings.jailer_uid), "--gid", str(settings.jailer_gid),
        "--chroot-base-dir", settings.jailer_chroot_base, *cgroups,
        *netns, "--new-pid-ns", "--", "--api-sock", "api.sock",
    ]


# Names of the files inside the jail. The VMM sees only these (paths in API calls are jail-relative).
JAIL_KERNEL = "vmlinux"
JAIL_ROOTFS = "rootfs.ext4"
JAIL_VSOCK = "vsock.sock"
JAIL_API_SOCK = "api.sock"
SNAP_STATE, SNAP_MEM, SNAP_DISK, SNAP_META = "vm.snap", "vm.mem", "rootfs.ext4", "meta.json"
_UDS_MAX = 104  # sun_path is 108 bytes; keep margin


Spawner = Callable[[list[str], Path], Awaitable[int]]  # (argv, log file) -> pid


class _Spawned:
    def __init__(self, proc: asyncio.subprocess.Process) -> None:
        self.proc = proc


async def _default_spawner(argv: list[str], log_path: Path) -> int:
    """Start the jailer with its output in a log file we can read back on failure (a pipe would
    stay open for as long as the VMM lives, because the VMM inherits it)."""
    log = open(log_path, "ab")
    try:
        proc = await asyncio.create_subprocess_exec(*argv, stdout=log, stderr=log,
                                                    stdin=subprocess.DEVNULL)
    finally:
        log.close()
    _PROCS[proc.pid] = proc
    return proc.pid


_PROCS: dict[int, asyncio.subprocess.Process] = {}


def _log_tail(path: Path, n: int = 800) -> str:
    try:
        return path.read_text(errors="replace")[-n:].strip()
    except OSError:
        return ""


class FirecrackerEngine(MicroVMEngine):
    isolation = "hardware-kvm"
    needs_network = True

    def __init__(self, spawner: Spawner | None = None, kvm_path: str = "/dev/kvm",
                 api_factory: Callable[[str], FirecrackerAPI] = FirecrackerAPI,
                 agent_call=agent_exec, chown=os.chown, proc_root: str = "/proc",
                 cgroup_root: str = "/sys/fs/cgroup") -> None:
        self.settings = get_settings()
        self._spawner = spawner or _default_spawner
        self._kvm = kvm_path
        self._api_factory = api_factory
        self._agent_call = agent_call
        self._chown = chown
        self._vms: dict[uuid.UUID, dict] = {}
        self._next_cid = 3  # 0-2 reserved by the vsock spec
        self._proc, self._cgroup = Path(proc_root), Path(cgroup_root)
        self._launching: set[uuid.UUID] = set()      # create_vm in flight: reconcile must not touch
        self._reconcile_lock = asyncio.Lock()

    # ------------------------------------------------------------------ layout
    def _exec_name(self) -> str:
        return Path(self.settings.firecracker_binary).name

    def jail_dir(self, cell_id: uuid.UUID) -> Path:
        """``<chroot base>/<exec file name>/<id>``: the directory the jailer builds for this VM."""
        return Path(self.settings.jailer_chroot_base) / self._exec_name() / str(cell_id)

    def jail_root(self, cell_id: uuid.UUID) -> Path:
        return self.jail_dir(cell_id) / "root"

    def _require_kvm(self) -> None:
        if not os.path.exists(self._kvm):
            raise EngineUnavailable(f"{self._kvm} not present: refusing to run without hardware isolation")

    async def preflight(self) -> None:
        """Fail early, with the actual reason, if this host cannot run jailed VMs safely."""
        s = self.settings
        self._require_kvm()
        for label, path in (("firecracker", s.firecracker_binary), ("jailer", s.jailer_binary)):
            if not (os.path.isfile(path) and os.access(path, os.X_OK)):
                raise EngineUnavailable(f"{label} binary not executable at {path}")
        if not os.path.isfile(s.kernel_image_path):
            raise EngineUnavailable(f"guest kernel missing at {s.kernel_image_path}")
        if not os.path.isdir(s.rootfs_dir):
            raise EngineUnavailable(f"rootfs directory missing at {s.rootfs_dir}")
        if not os.path.exists("/dev/net/tun"):
            raise EngineUnavailable("/dev/net/tun missing (needed for cell TAP devices)")
        # Longest UDS path we will create must fit in sun_path.
        longest = self.jail_root(uuid.UUID(int=0)) / JAIL_VSOCK
        if len(str(longest)) >= _UDS_MAX:
            raise EngineUnavailable(
                f"JAILER_CHROOT_BASE too long: {len(str(longest))} byte socket paths exceed "
                f"{_UDS_MAX}; use a shorter base such as /srv/jailer")
        if s.jailer_use_cgroups:
            ctl = Path("/sys/fs/cgroup/cgroup.controllers")
            avail = ctl.read_text().split() if ctl.exists() else []
            missing = [c for c in ("cpu", "memory") if c not in avail]
            if missing:
                raise EngineUnavailable(
                    f"cgroup v2 controllers unavailable: {missing}. Resource limits would not be "
                    "enforced; enable them (or set JAILER_USE_CGROUPS=false in dev only)")
        elif s.environment != "dev":
            raise EngineUnavailable("JAILER_USE_CGROUPS=false is only allowed when AIJAILER_ENV=dev")

    @staticmethod
    def _mac(guest_ip: str) -> str:
        """Locally administered, derived from the (unique) guest IP."""
        o = [int(x) for x in guest_ip.split(".")]
        return "02:aa:%02x:%02x:%02x:%02x" % tuple(o)

    def _build_config(self, config: VMConfig, cid: int) -> dict:
        """Firecracker configuration. All paths are relative to the jail root."""
        boot_args = "console=ttyS0 reboot=k panic=1 pci=off init=/sbin/aijailer-agent"
        nics: list[dict] = []
        net = config.network
        if net is not None:
            import ipaddress
            mask = ipaddress.ip_network(f"{net.host_ip}/{net.prefix}", strict=False).netmask
            # Static address, default route = the host's link end (where the broker listens);
            # no DHCP, no DNS (names are resolved by the broker).
            boot_args += f" ip={net.guest_ip}::{net.host_ip}:{mask}::eth0:off"
            nics.append({"iface_id": "eth0", "host_dev_name": net.tap_name,
                         "guest_mac": self._mac(net.guest_ip)})
        return {
            "network-interfaces": nics,
            "boot-source": {"kernel_image_path": JAIL_KERNEL, "boot_args": boot_args},
            "drives": [{"drive_id": "rootfs", "path_on_host": JAIL_ROOTFS,
                        "is_root_device": True, "is_read_only": False}],
            "machine-config": {"vcpu_count": config.vcpus, "mem_size_mib": config.memory_mb,
                               "smt": False},
            "vsock": {"guest_cid": cid, "uds_path": JAIL_VSOCK},
        }

    @staticmethod
    def _clone_rootfs(base: Path, dest: Path) -> None:
        if not base.exists():
            raise FileNotFoundError(f"base image missing: {base}")
        r = subprocess.run(["cp", "--reflink=auto", "--sparse=always", str(base), str(dest)],
                           capture_output=True)
        if r.returncode != 0:
            shutil.copyfile(base, dest)

    def _prepare_jail(self, config: VMConfig, restore: Path | None = None) -> Path:
        """Create the jail root and put the VM's files in it BEFORE the jailer starts.

        The jailer chroots into this directory, so anything the VMM needs (kernel, disk) must
        already be inside it. The per-cell rootfs is a private copy owned by the jailer uid (the
        shared base image is never opened read-write); the kernel is hard-linked (read-only,
        world-readable, shared) or copied if the filesystems differ."""
        s = self.settings
        jail = self.jail_dir(config.cell_id)
        if jail.exists():  # leftover from a crash: ids are unique, so it is garbage
            shutil.rmtree(jail, ignore_errors=True)
        root = jail / "root"
        root.mkdir(parents=True, mode=0o755)
        disk = root / JAIL_ROOTFS
        if restore is None:
            self._clone_rootfs(Path(s.rootfs_dir) / f"{config.image}.ext4", disk)
        else:  # private copies: the snapshot stays pristine and can be restored again
            self._clone_rootfs(restore / SNAP_DISK, disk)
            self._clone_rootfs(restore / SNAP_MEM, root / SNAP_MEM)
            self._clone_rootfs(restore / SNAP_STATE, root / SNAP_STATE)
            for f in (SNAP_MEM, SNAP_STATE):
                os.chmod(root / f, 0o600)
                self._chown(root / f, s.jailer_uid, s.jailer_gid)
        os.chmod(disk, 0o600)
        self._chown(disk, s.jailer_uid, s.jailer_gid)
        if restore is None:     # a restored guest carries its kernel in its memory image
            kernel = root / JAIL_KERNEL
            try:
                os.link(s.kernel_image_path, kernel)
            except OSError:
                shutil.copyfile(s.kernel_image_path, kernel)
        if len(str(root / JAIL_VSOCK)) >= _UDS_MAX:
            raise EngineUnavailable("jail path too long for a unix socket; shorten JAILER_CHROOT_BASE")
        return root

    # ----------------------------------------------------------------- lifecycle
    async def _launch(self, config: VMConfig, restore: Path | None = None) -> dict:
        """Everything up to (not including) InstanceStart: jail, jailer, API socket, config.
        With ``restore`` the VMM is left unconfigured (the snapshot carries the configuration)."""
        self._require_kvm()
        if config.network is not None and not config.network.netns_path:
            raise EngineUnavailable(
                "refusing to attach a NIC outside a dedicated network namespace")
        root = self._prepare_jail(config, restore)
        jail = root.parent
        cid = self._next_cid
        self._next_cid += 1
        argv = jailer_argv(self.settings, str(config.cell_id), config.memory_mb, config.vcpus,
                           config.network.netns_path if config.network else None)
        log_path = jail / "jailer.log"
        vm: dict = {"root": root, "jail": jail, "cid": cid, "api": None,
                    "env": dict(config.environment or {}), "meta": self._meta(config)}
        try:
            spawner_pid = await self._spawner(argv, log_path)
            sock = root / JAIL_API_SOCK
            proc = _PROCS.get(spawner_pid)
            deadline = time.monotonic() + 10
            while not sock.exists():
                if proc is not None and proc.returncode not in (None, 0):
                    raise RuntimeError("jailer failed: " + (_log_tail(log_path) or "no output"))
                if time.monotonic() > deadline:
                    raise RuntimeError("firecracker API socket did not appear: "
                                       + (_log_tail(log_path) or "no output"))
                await asyncio.sleep(0.02)
            vm["fc_pid"] = self._read_pid(root) or spawner_pid
            vm["api"] = self._api_factory(str(sock))
            if restore is None:
                await vm["api"].configure(self._build_config(config, cid))
        except BaseException:
            await self._teardown(vm)
            raise
        return vm

    @staticmethod
    def _read_pid(root: Path) -> int | None:
        """The jailer writes the VMM's PID (it differs from the jailer's own) next to the socket."""
        try:
            return int((root / "firecracker.pid").read_text().strip())
        except (OSError, ValueError):
            return None

    async def create_vm(self, config: VMConfig) -> VMInfo:
        self._launching.add(config.cell_id)           # held until the VM is registered below
        try:
            vm = await self._launch(config)
            try:
                await vm["api"].start()
            except BaseException:
                await self._teardown(vm)
                raise
            return self._register(config, vm)
        finally:
            self._launching.discard(config.cell_id)

    def _register(self, config: VMConfig, vm: dict) -> VMInfo:
        info = VMInfo(cell_id=config.cell_id, status=VMStatus.RUNNING, pid=vm["fc_pid"],
                      internal_ip=config.network.guest_ip if config.network else None,
                      vsock_path=str(vm["root"] / JAIL_VSOCK))
        vm["info"] = info
        self._vms[config.cell_id] = vm
        return info

    def _vm(self, cell_id: uuid.UUID) -> dict:
        vm = self._vms.get(cell_id)
        if vm is None:
            raise KeyError(f"unknown cell {cell_id}")
        return vm

    @staticmethod
    def _kill_pid(pid: int | None) -> None:
        if pid:
            try:
                os.kill(pid, 9)
            except ProcessLookupError:
                pass

    async def _teardown(self, vm: dict) -> None:
        """Kill the VMM, close the API client, remove the jail and its cgroup. Idempotent."""
        pids = [p for p in (vm.get("fc_pid"), *vm.get("extra_pids", ())) if p]
        for pid in pids:
            self._kill_pid(pid)
        for pid in pids:  # wait until they are really gone before deleting their files
            for _ in range(100):
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    break
                await asyncio.sleep(0.02)
        if vm.get("api") is not None:
            try:
                await vm["api"].close()
            except Exception:
                pass
        jail = vm.get("jail")
        if jail is not None:
            shutil.rmtree(jail, ignore_errors=True)
            cg = self._cgroup / self._exec_name() / jail.name
            try:
                cg.rmdir()  # the jailer creates it; it is only removable once empty
            except OSError:
                pass

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
            await vm["api"].ctrl_alt_del()  # guest agent powers the guest off on SIGINT
        except Exception:
            pass
        pid = vm.get("fc_pid")
        deadline = time.monotonic() + max(0, grace_period)
        while pid and time.monotonic() < deadline:  # graceful shutdown, then force
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.05)
        self._kill_pid(pid)
        vm["info"].status = VMStatus.STOPPED

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
            await self._teardown(vm)

    @staticmethod
    def _meta(config: VMConfig) -> dict:
        """What a snapshot must remember about the VM: the guest's network identity is baked into
        its memory (IP, MAC, routes), so a restore has to be given the same one."""
        n = config.network
        return {"image": config.image, "vcpus": config.vcpus, "memory_mb": config.memory_mb,
                "network": {"guest_ip": n.guest_ip, "host_ip": n.host_ip, "prefix": n.prefix}
                if n else None}

    @staticmethod
    def _mkdir_private(path: Path) -> None:
        """mkdir -p where every directory we create is 0700 (``mkdir(mode=)`` only covers the leaf)."""
        missing = [p for p in (path, *path.parents) if not p.exists()]
        for p in reversed(missing):
            p.mkdir(mode=0o700, exist_ok=True)

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1 << 20):
                h.update(chunk)
        return h.hexdigest()

    async def snapshot_vm(self, cell_id: uuid.UUID, snapshot_dir: str) -> dict:
        """Snapshot files are written INSIDE the jail (jail-relative paths), then moved out,
        together with ``meta.json`` (guest identity + sha256 of every file)."""
        vm = self._vm(cell_id)
        if not vm.get("meta"):
            raise RuntimeError("cannot snapshot an adopted VM: its configuration is unknown")
        out = Path(snapshot_dir)
        self._mkdir_private(out)
        was_running = vm["info"].status == VMStatus.RUNNING
        if was_running:
            await vm["api"].set_state("Paused")
        try:
            await vm["api"].create_snapshot(SNAP_STATE, SNAP_MEM)
            shutil.move(str(vm["root"] / SNAP_STATE), out / SNAP_STATE)
            shutil.move(str(vm["root"] / SNAP_MEM), out / SNAP_MEM)
            shutil.copyfile(vm["root"] / JAIL_ROOTFS, out / SNAP_DISK)
        finally:
            if was_running:
                await vm["api"].set_state("Resumed")
        files = {n: await asyncio.to_thread(self._sha256, out / n)
                 for n in (SNAP_STATE, SNAP_MEM, SNAP_DISK)}
        (out / SNAP_META).write_text(json.dumps({"version": 1, **vm["meta"], "files": files}))
        return {"state": str(out / SNAP_STATE), "memory": str(out / SNAP_MEM),
                "disk": str(out / SNAP_DISK), "meta": str(out / SNAP_META)}

    async def _verify_bundle(self, snapshot_dir: str) -> tuple[Path, dict]:
        """Metadata present and well-formed, every file present and matching its sha256.
        Hashes catch corruption/truncation (not a malicious writer of the whole directory:
        keep snapshot storage write-protected)."""
        d = Path(snapshot_dir)
        try:
            meta = json.loads((d / SNAP_META).read_text())
        except (OSError, ValueError) as exc:
            raise SnapshotError(f"snapshot {d} has no readable {SNAP_META}: {exc}") from exc
        if meta.get("version") != 1 or set(meta.get("files", {})) != {SNAP_STATE, SNAP_MEM, SNAP_DISK}:
            raise SnapshotError(f"snapshot {d}: unsupported or incomplete metadata")
        for name, want in meta["files"].items():
            f = d / name
            if not f.is_file() or f.is_symlink():
                raise SnapshotError(f"snapshot {d}: {name} missing")
            if await asyncio.to_thread(self._sha256, f) != want:
                raise SnapshotError(f"snapshot {d}: {name} does not match its recorded sha256")
        return d, meta

    async def check_snapshot(self, snapshot_dir: str) -> None:
        await self._verify_bundle(snapshot_dir)

    async def _read_snapshot(self, snapshot_dir: str, config: VMConfig) -> tuple[Path, dict]:
        """Validate a snapshot bundle against the restore request BEFORE anything is spawned."""
        d, meta = await self._verify_bundle(snapshot_dir)
        want_net, have = meta.get("network"), config.network
        if (want_net is None) != (have is None) or (
                want_net and (want_net["guest_ip"], want_net["prefix"])
                != (have.guest_ip, have.prefix)):
            raise SnapshotError(
                "snapshot was taken with guest network "
                f"{want_net and (want_net['guest_ip'], want_net['prefix'])}; the restored cell must be "
                "given the same guest address (it is baked into guest memory)")
        return d, meta

    async def restore_vm(self, config: VMConfig, snapshot_dir: str) -> VMInfo:
        """Start a new jailed VMM and load a snapshot into it (resumed). The snapshot's disk and
        memory are copied into the new jail, so the bundle stays pristine and restorable again.

        The guest keeps its saved identity: same IP/MAC (checked), same machine shape (taken from
        the snapshot, overriding ``config``), and ALSO its saved RNG/entropy state, so restoring one
        snapshot into several cells yields clones that must not be trusted to be unique."""
        self._require_kvm()
        if config.cell_id in self._vms:
            raise RuntimeError(f"cell {config.cell_id} already has a VM")
        d, meta = await self._read_snapshot(snapshot_dir, config)
        config = dataclasses.replace(config, image=meta["image"], vcpus=meta["vcpus"],
                                     memory_mb=meta["memory_mb"])
        self._launching.add(config.cell_id)
        try:
            vm = await self._launch(config, restore=d)
            try:
                overrides = [{"iface_id": "eth0", "host_dev_name": config.network.tap_name}] \
                    if config.network else None
                await vm["api"].load_snapshot(SNAP_STATE, SNAP_MEM, True, overrides)
            except BaseException:
                await self._teardown(vm)
                raise
            return self._register(config, vm)
        finally:
            self._launching.discard(config.cell_id)

    async def exec_command(self, cell_id: uuid.UUID, command: str, timeout: int = 30,
                           user: str = "agent", env: dict[str, str] | None = None,
                           cwd: str | None = None) -> ExecResult:
        vm = self._vm(cell_id)
        if vm["info"].status != VMStatus.RUNNING:
            raise RuntimeError(f"cell is {vm['info'].status.value}, cannot exec")
        # The cell's own environment (creation-time settings plus the platform's proxy variables), with the
        # per-command one on top. The caller has already refused platform-managed names (core.exec_env).
        return await self._agent_call(vm["info"].vsock_path, self.settings.agent_vsock_port,
                                      command, timeout, user, env={**vm["env"], **(env or {})}, cwd=cwd)

    # ------------------------------------------------------------- reconciliation
    # A control-plane restart loses ``self._vms`` while jailed VMMs keep running (the jailer
    # daemonizes them). ``reconcile`` re-derives the truth from the host: jail directories
    # (``<base>/<exec>/<uuid>``) and VMM processes (argv ``<exec> --id <uuid>``), compared with the
    # cells the database says are live. Only things whose name proves they are ours are touched.
    def _scan_jails(self) -> dict[uuid.UUID, tuple[Path, float]]:
        base = Path(self.settings.jailer_chroot_base) / self._exec_name()
        out: dict[uuid.UUID, tuple[Path, float]] = {}
        try:
            entries = list(base.iterdir())
        except OSError:
            return out
        for e in entries:
            try:
                cid = uuid.UUID(e.name)
                if str(cid) == e.name and e.is_dir() and not e.is_symlink():
                    out[cid] = (e, e.stat().st_mtime)
            except (ValueError, OSError):
                continue  # not ours: never touch what we cannot identify
        return out

    def _scan_vmms(self) -> dict[uuid.UUID, list[int]]:
        """VMM processes by cell id, from /proc cmdlines (``firecracker ... --id <uuid>``)."""
        out: dict[uuid.UUID, list[int]] = {}
        try:
            names = os.listdir(self._proc)
        except OSError:
            return out
        for n in names:
            if n.isdigit():
                cid = self._vmm_cell_id(int(n))
                if cid is not None:
                    out.setdefault(cid, []).append(int(n))
        return out

    def _vmm_cell_id(self, pid: int) -> uuid.UUID | None:
        try:
            argv = (self._proc / str(pid) / "cmdline").read_bytes().split(b"\0")
        except OSError:
            return None
        if not argv or Path(argv[0].decode(errors="replace")).name != self._exec_name():
            return None
        try:
            i = argv.index(b"--id")
            return uuid.UUID(argv[i + 1].decode())
        except (ValueError, IndexError):
            return None

    def _vmm_alive(self, pid: int | None, cell_id: uuid.UUID) -> bool:
        """True only if ``pid`` is still THE VMM of this cell (guards against pid reuse)."""
        return bool(pid) and self._vmm_cell_id(pid) == cell_id

    async def _kill_orphan(self, cid: uuid.UUID, pids: list[int], jail: Path | None) -> None:
        await self._teardown({"fc_pid": None, "jail": jail,
                              "extra_pids": pids})

    async def _adopt(self, cid: uuid.UUID, pid: int, jail: Path | None, env: dict) -> bool:
        """Rebuild the in-memory handle for a VMM that survived a restart. False if it does not
        answer (the caller reports it; the cell is then marked error and cleaned next pass)."""
        if jail is None:
            return False
        root = jail / "root"
        api = self._api_factory(str(root / JAIL_API_SOCK))
        try:
            state = await asyncio.wait_for(api.state(), 5)
            if state not in ("Running", "Paused"):
                raise RuntimeError(f"unexpected VMM state {state!r}")
            status = VMStatus.PAUSED if state == "Paused" else VMStatus.RUNNING
            if status == VMStatus.RUNNING:
                await agent_ping(str(root / JAIL_VSOCK), self.settings.agent_vsock_port, 3.0)
        except Exception:
            try:
                await api.close()
            except Exception:
                pass
            return False
        info = VMInfo(cell_id=cid, status=status, pid=pid, vsock_path=str(root / JAIL_VSOCK))
        self._vms[cid] = {"root": root, "jail": jail, "cid": None, "api": api, "fc_pid": pid,
                          "env": dict(env or {}), "info": info}
        return True

    async def reconcile(self, live: dict[uuid.UUID, dict], protected: set[uuid.UUID],
                        grace: float = 120.0) -> EngineSweepReport:
        report = EngineSweepReport()
        async with self._reconcile_lock:
            try:
                jails = await asyncio.to_thread(self._scan_jails)
                vmms = await asyncio.to_thread(self._scan_vmms)
            except Exception as exc:
                report.errors.append(f"scan: {exc}")
                return report
            now = time.time()
            skip = protected | set(self._launching)
            doomed: list[uuid.UUID] = []          # not live, not ours to keep
            for cid in set(jails) | set(vmms) | set(self._vms):
                if cid in live or cid in skip:
                    continue
                vm = self._vms.get(cid)
                if vm is not None and vm["info"].status == VMStatus.STOPPED:
                    continue                       # stopped, kept until destroy_cell
                if cid not in self._vms and cid in jails and now - jails[cid][1] < grace:
                    report.skipped_young.append(cid)   # may be a launch from another process
                    continue
                doomed.append(cid)
            present = len(set(jails) | set(vmms) | set(self._vms))
            if len(doomed) > MASS_REMOVAL_MIN and len(doomed) > MASS_REMOVAL_FRACTION * present:
                report.aborted = True
                report.errors.append(f"refusing to remove {len(doomed)} of {present} VMs in one "
                                     "sweep (database read looks wrong?)")
                doomed = []
            for cid in doomed:
                try:
                    pids = vmms.get(cid, [])
                    vm = self._vms.pop(cid, None)
                    if vm is not None and self._vmm_alive(vm.get("fc_pid"), cid):
                        pids = list({*pids, vm["fc_pid"]})
                    jail = (vm or {}).get("jail") or (jails[cid][0] if cid in jails else None)
                    if vm is not None and vm.get("api") is not None:
                        try:
                            await vm["api"].close()
                        except Exception:
                            pass
                    await self._kill_orphan(cid, pids, jail)
                    (report.orphans_killed if pids else report.leftovers_removed).append(cid)
                except Exception as exc:
                    report.errors.append(f"{cid}: {exc}")
            for cid, env in live.items():
                if cid in skip:
                    continue
                try:
                    vm = self._vms.get(cid)
                    if vm is not None:
                        if vm["info"].status in (VMStatus.RUNNING, VMStatus.PAUSED) \
                                and not self._vmm_alive(vm.get("fc_pid"), cid):
                            self._vms.pop(cid, None)
                            await self._teardown({**vm, "fc_pid": None})
                            report.dead.append(cid)
                    elif cid in vmms:
                        if await self._adopt(cid, vmms[cid][0], jails.get(cid, (None,))[0], env):
                            report.adopted.append(cid)
                        else:
                            report.unresponsive.append(cid)
                    else:
                        report.dead.append(cid)    # DB says live, nothing is running
                except Exception as exc:
                    report.errors.append(f"{cid}: {exc}")
        return report

    async def get_vm_info(self, cell_id: uuid.UUID) -> VMInfo:
        vm = self._vms.get(cell_id)
        return vm["info"] if vm else VMInfo(cell_id=cell_id, status=VMStatus.DESTROYED)
