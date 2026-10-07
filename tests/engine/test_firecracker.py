"""Firecracker controller tests against a fake Firecracker API + guest agent (no KVM needed)."""

import asyncio
import json
import os
import struct
import uuid

import pytest

from aijailer.core.config import Settings
from aijailer.engine import firecracker as fc
from aijailer.engine.microvm import EngineUnavailable, VMConfig, VMStatus, build_engine


class FakeFirecracker:
    """Records API calls over a unix socket (HTTP/1.1, enough for httpx)."""

    def __init__(self, path):
        self.path, self.calls = path, []

    async def start(self):
        self.server = await asyncio.start_unix_server(self._handle, self.path)

    async def _handle(self, reader, writer):
        while True:
            line = await reader.readline()
            if not line:
                break
            method, path, _ = line.decode().split(" ", 2)
            length = 0
            while (h := await reader.readline()) not in (b"\r\n", b""):
                if h.lower().startswith(b"content-length"):
                    length = int(h.split(b":")[1])
            body = json.loads(await reader.readexactly(length)) if length else None
            self.calls.append((method, path, body))
            writer.write(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n")
            await writer.drain()
        writer.close()


@pytest.fixture
def env(monkeypatch):
    # AF_UNIX paths are limited to ~108 bytes, so avoid pytest's long tmp_path.
    import pathlib
    import shutil
    import tempfile

    tmp_path = pathlib.Path(tempfile.mkdtemp(prefix="fc"))
    s = Settings(ROOTFS_DIR=str(tmp_path / "rootfs"), JAILER_CHROOT_BASE=str(tmp_path / "jail"),
                 KERNEL_IMAGE_PATH=str(tmp_path / "vmlinux"))
    monkeypatch.setattr(fc, "get_settings", lambda: s)
    (tmp_path / "rootfs").mkdir()
    (tmp_path / "rootfs" / "base-python.ext4").write_bytes(b"BASE")
    (tmp_path / "vmlinux").write_bytes(b"KERNEL")
    (tmp_path / "kvm").write_text("")
    yield tmp_path, s
    shutil.rmtree(tmp_path, ignore_errors=True)


def jail_root(tmp, cell):
    # what the real jailer builds: <chroot base>/<exec file name>/<id>/root
    return os.path.join(str(tmp), "jail", "firecracker", cell, "root")


async def make_engine(tmp, fake_holder, pid=0):
    async def spawner(argv, log_path):
        cell = argv[argv.index("--id") + 1]
        root = jail_root(tmp, cell)
        assert os.path.isdir(root)                        # engine prepared the jail first
        fake = FakeFirecracker(os.path.join(root, "api.sock"))
        await fake.start()
        with open(os.path.join(root, "firecracker.pid"), "w") as f:   # jailer writes the VMM pid
            f.write(str(pid))
        fake_holder[cell] = fake
        return 0

    return fc.FirecrackerEngine(spawner=spawner, kvm_path=str(tmp / "kvm"),
                                chown=lambda *a: None)


@pytest.mark.asyncio
async def test_no_kvm_fails_closed(env):
    tmp, _ = env
    eng = fc.FirecrackerEngine(kvm_path=str(tmp / "missing"))
    with pytest.raises(EngineUnavailable):
        await eng.create_vm(VMConfig(cell_id=uuid.uuid4(), image="base-python"))


@pytest.mark.asyncio
async def test_create_configures_via_api_with_isolated_rootfs_and_unique_cid(env):
    tmp, s = env
    holder = {}
    eng = await make_engine(tmp, holder)
    a, b = uuid.uuid4(), uuid.uuid4()
    await eng.create_vm(VMConfig(cell_id=a, image="base-python", vcpus=2, memory_mb=256))
    await eng.create_vm(VMConfig(cell_id=b, image="base-python"))
    calls = holder[str(a)].calls
    paths = [c[1] for c in calls]
    assert paths == ["/boot-source", "/drives/rootfs", "/machine-config", "/vsock", "/actions"]
    drive = calls[1][2]
    assert drive["path_on_host"] == "rootfs.ext4"           # jail-relative, never a host path
    assert calls[0][2]["kernel_image_path"] == "vmlinux"
    assert calls[3][2]["uds_path"] == "vsock.sock"
    assert (tmp / "rootfs" / "base-python.ext4").read_bytes() == b"BASE"  # base untouched
    cids = {holder[str(x)].calls[3][2]["guest_cid"] for x in (a, b)}
    assert len(cids) == 2 and min(cids) >= 3
    assert calls[2][2]["vcpu_count"] == 2 and calls[2][2]["smt"] is False
    assert calls[-1][2] == {"action_type": "InstanceStart"}


@pytest.mark.asyncio
async def test_pause_resume_snapshot_calls(env):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    cid = uuid.uuid4()
    await eng.create_vm(VMConfig(cell_id=cid, image="base-python"))
    await eng.pause_vm(cid)
    assert (await eng.get_vm_info(cid)).status == VMStatus.PAUSED
    await eng.resume_vm(cid)
    root = jail_root(tmp, str(cid))
    # the real VMM writes snapshot files into its jail; emulate that, the engine must move them out
    for name in ("vm.snap", "vm.mem"):
        open(os.path.join(root, name), "wb").write(name.encode())
    out = await eng.snapshot_vm(cid, str(tmp / "snap"))
    calls = [c[:2] for c in holder[str(cid)].calls[5:]]
    assert calls == [("PATCH", "/vm"), ("PATCH", "/vm"), ("PATCH", "/vm"),
                     ("PUT", "/snapshot/create"), ("PATCH", "/vm")]
    assert holder[str(cid)].calls[8][2] == {
        "snapshot_type": "Full", "snapshot_path": "vm.snap", "mem_file_path": "vm.mem"}
    assert open(out["state"], "rb").read() == b"vm.snap" and os.path.exists(out["disk"])
    assert not os.path.exists(os.path.join(root, "vm.snap"))       # moved, not copied


@pytest.mark.asyncio
async def test_exec_over_vsock_protocol():
    import tempfile
    sock = tempfile.mktemp(prefix="v", suffix=".sock")
    seen = {}

    async def agent(reader, writer):
        seen["connect"] = (await reader.readline()).decode()
        writer.write(b"OK 1073741824\n")
        n = struct.unpack(">I", await reader.readexactly(4))[0]
        seen["req"] = json.loads(await reader.readexactly(n))
        resp = json.dumps({"exit_code": 3, "stdout": "hi", "stderr": "e", "duration_ms": 7}).encode()
        writer.write(struct.pack(">I", len(resp)) + resp)
        await writer.drain()
        writer.close()

    server = await asyncio.start_unix_server(agent, sock)
    res = await fc.agent_exec(sock, 5000, "echo hi", 5, "agent")
    server.close()
    assert seen["connect"] == "CONNECT 5000\n" and seen["req"]["cmd"] == "echo hi"
    assert (res.exit_code, res.stdout, res.stderr, res.duration_ms) == (3, "hi", "e", 7)


def test_jailer_argv_is_non_root_with_cgroup_limits():
    s = Settings()
    argv = fc.jailer_argv(s, "abc", 512, 2)
    assert argv[argv.index("--uid") + 1] != "0"
    assert "cpu.max=200000 100000" in argv and "--new-pid-ns" in argv


def test_simulated_refused_outside_dev():
    with pytest.raises(EngineUnavailable):
        build_engine("simulated", "prod")
    assert build_engine("simulated", "dev").isolation == "none"
    with pytest.raises(EngineUnavailable):
        build_engine("bogus", "dev")


@pytest.mark.asyncio
async def test_nic_and_static_ip_only_when_network_given(env):
    from aijailer.engine.microvm import VMNetwork
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    a, b = uuid.uuid4(), uuid.uuid4()
    net = VMNetwork("tap0", "10.200.0.2", "10.200.0.1", 30, "/run/netns/ajcell1")
    await eng.create_vm(VMConfig(cell_id=a, image="base-python", network=net))
    await eng.create_vm(VMConfig(cell_id=b, image="base-python"))  # no network -> no NIC at all
    with_net = {c[1]: c[2] for c in holder[str(a)].calls}
    assert with_net["/network-interfaces/eth0"]["host_dev_name"] == "tap0"
    assert with_net["/network-interfaces/eth0"]["guest_mac"].startswith("02:")
    assert "ip=10.200.0.2::10.200.0.1:255.255.255.252::eth0:off" in with_net["/boot-source"]["boot_args"]
    assert not any(p.startswith("/network-interfaces") for _, p, _ in holder[str(b)].calls)
    assert "ip=" not in {c[1]: c[2] for c in holder[str(b)].calls}["/boot-source"]["boot_args"]
    assert (await eng.get_vm_info(a)).internal_ip == "10.200.0.2"


@pytest.mark.asyncio
async def test_exec_passes_cell_environment_to_agent(env):
    tmp, _ = env
    holder, seen = {}, {}
    eng = await make_engine(tmp, holder)

    async def fake_agent(uds, port, cmd, timeout, user, env=None):
        seen["env"] = env
        from aijailer.engine.microvm import ExecResult
        return ExecResult(0, "", "", 1)

    eng._agent_call = fake_agent
    cid = uuid.uuid4()
    await eng.create_vm(VMConfig(cell_id=cid, image="base-python",
                                 environment={"http_proxy": "http://10.200.0.1:3128"}))
    await eng.exec_command(cid, "true")
    assert seen["env"] == {"http_proxy": "http://10.200.0.1:3128"}


@pytest.mark.asyncio
async def test_exec_env_is_applied_over_the_cells_own_environment_for_that_command_only(env):
    tmp, _ = env
    holder, seen = {}, []
    eng = await make_engine(tmp, holder)

    async def fake_agent(uds, port, cmd, timeout, user, env=None):
        seen.append(env)
        from aijailer.engine.microvm import ExecResult
        return ExecResult(0, "", "", 1)

    eng._agent_call = fake_agent
    cid = uuid.uuid4()
    await eng.create_vm(VMConfig(cell_id=cid, image="base-python",
                                 environment={"http_proxy": "http://10.200.0.1:3128", "FOO": "from-creation"}))
    await eng.exec_command(cid, "true", env={"FOO": "from-exec", "BAR": "1"})
    await eng.exec_command(cid, "true")
    await eng.exec_command(cid, "true", env={})
    base = {"http_proxy": "http://10.200.0.1:3128", "FOO": "from-creation"}
    assert seen[0] == {"http_proxy": "http://10.200.0.1:3128", "FOO": "from-exec", "BAR": "1"}   # exec wins, extras added
    assert seen[1] == base and seen[2] == base       # and it did not leak into the cell's stored environment


def test_jailer_argv_joins_cell_netns_only_when_given():
    s = Settings()
    with_ns = fc.jailer_argv(s, "abc", 512, 1, "/run/netns/ajcell1")
    i = with_ns.index("--netns")
    assert with_ns[i + 1] == "/run/netns/ajcell1" and i < with_ns.index("--")
    assert "--netns" not in fc.jailer_argv(s, "abc", 512, 1)


@pytest.mark.asyncio
async def test_nic_without_netns_is_refused(env):
    from aijailer.engine.microvm import VMNetwork
    tmp, _ = env
    eng = await make_engine(tmp, {})
    cfg = VMConfig(cell_id=uuid.uuid4(), image="base-python",
                   network=VMNetwork("tap0", "10.200.0.2", "10.200.0.1", 30, None))
    with pytest.raises(EngineUnavailable, match="dedicated network namespace"):
        await eng.create_vm(cfg)


@pytest.mark.asyncio
async def test_create_passes_netns_to_jailer(env):
    from aijailer.engine.microvm import VMNetwork
    tmp, _ = env
    argvs = []

    async def spawner(argv, log_path):
        argvs.append(argv)
        cell = argv[argv.index("--id") + 1]
        fake = FakeFirecracker(os.path.join(jail_root(tmp, cell), "api.sock"))
        await fake.start()
        return 0

    eng = fc.FirecrackerEngine(spawner=spawner, kvm_path=str(tmp / "kvm"), chown=lambda *a: None)
    await eng.create_vm(VMConfig(cell_id=uuid.uuid4(), image="base-python",
                                 network=VMNetwork("tap0", "10.200.0.2", "10.200.0.1", 30,
                                                   "/run/netns/ajcell1")))
    assert argvs[0][argvs[0].index("--netns") + 1] == "/run/netns/ajcell1"


# ------------------------------------------------------------- real-jailer layout contract
@pytest.mark.asyncio
async def test_files_are_placed_in_the_jail_before_the_jailer_starts(env):
    tmp, s = env
    seen = {}

    async def spawner(argv, log_path):
        cell = argv[argv.index("--id") + 1]
        root = jail_root(tmp, cell)
        seen["files"] = sorted(os.listdir(root))                    # state at jailer start
        seen["disk"] = open(os.path.join(root, "rootfs.ext4"), "rb").read()
        seen["kernel"] = open(os.path.join(root, "vmlinux"), "rb").read()
        seen["disk_mode"] = os.stat(os.path.join(root, "rootfs.ext4")).st_mode & 0o777
        fake = FakeFirecracker(os.path.join(root, "api.sock"))
        await fake.start()
        return 0

    chowned = []
    eng = fc.FirecrackerEngine(spawner=spawner, kvm_path=str(tmp / "kvm"),
                               chown=lambda *a: chowned.append(a))
    await eng.create_vm(VMConfig(cell_id=uuid.uuid4(), image="base-python"))
    assert seen["files"] == ["rootfs.ext4", "vmlinux"]
    assert seen["disk"] == b"BASE" and seen["kernel"] == b"KERNEL" and seen["disk_mode"] == 0o600
    assert chowned and chowned[0][1:] == (s.jailer_uid, s.jailer_gid)   # VMM user owns its disk
    assert (tmp / "rootfs" / "base-python.ext4").read_bytes() == b"BASE"


@pytest.mark.asyncio
async def test_destroy_kills_the_vmm_by_pidfile_and_removes_the_whole_jail(env):
    import subprocess
    tmp, _ = env
    victim = subprocess.Popen(["sleep", "60"])                      # stands in for the VMM
    holder = {}
    eng = await make_engine(tmp, holder, pid=victim.pid)
    cid = uuid.uuid4()
    info = await eng.create_vm(VMConfig(cell_id=cid, image="base-python"))
    assert info.pid == victim.pid                                   # pidfile, not the jailer's pid
    assert info.vsock_path == os.path.join(jail_root(tmp, str(cid)), "vsock.sock")
    await eng.destroy_vm(cid)
    assert victim.wait(timeout=5) == -9
    assert not os.path.exists(os.path.dirname(jail_root(tmp, str(cid))))     # jail dir gone
    await eng.destroy_vm(cid)                                       # idempotent


@pytest.mark.asyncio
async def test_failed_start_leaves_no_jail_or_process_behind(env):
    import subprocess
    tmp, _ = env
    victim = subprocess.Popen(["sleep", "60"])
    holder = {}
    eng = await make_engine(tmp, holder, pid=victim.pid)
    cid = uuid.uuid4()
    real = fc.FirecrackerAPI.start

    async def refuse(self):
        raise RuntimeError("firecracker PUT /actions -> 400: no /dev/kvm")
    fc.FirecrackerAPI.start = refuse
    try:
        with pytest.raises(RuntimeError, match="kvm"):
            await eng.create_vm(VMConfig(cell_id=cid, image="base-python"))
    finally:
        fc.FirecrackerAPI.start = real
    assert victim.wait(timeout=5) == -9
    assert not os.path.exists(os.path.dirname(jail_root(tmp, str(cid))))
    assert (await eng.get_vm_info(cid)).status == VMStatus.DESTROYED


@pytest.mark.asyncio
async def test_jailer_failure_surfaces_its_own_message(env):
    tmp, _ = env

    async def spawner(argv, log_path):
        log_path.write_text("Jailer error: Controller cpu is unavailable\n")
        import subprocess
        p = await asyncio.create_subprocess_exec("false")
        await p.wait()
        fc._PROCS[p.pid] = p
        return p.pid

    eng = fc.FirecrackerEngine(spawner=spawner, kvm_path=str(tmp / "kvm"), chown=lambda *a: None)
    cid = uuid.uuid4()
    with pytest.raises(RuntimeError, match="Controller cpu is unavailable"):
        await eng.create_vm(VMConfig(cell_id=cid, image="base-python"))
    assert not os.path.exists(os.path.dirname(jail_root(tmp, str(cid))))


@pytest.mark.asyncio
async def test_stale_jail_from_a_crash_is_replaced(env):
    tmp, _ = env
    cid = uuid.uuid4()
    stale = jail_root(tmp, str(cid))
    os.makedirs(stale)
    open(os.path.join(stale, "garbage"), "w").write("old")
    eng = await make_engine(tmp, {})
    await eng.create_vm(VMConfig(cell_id=cid, image="base-python"))
    assert not os.path.exists(os.path.join(stale, "garbage"))


def test_jailer_argv_cgroups_toggle_and_in_jail_socket():
    s = Settings()
    on = fc.jailer_argv(s, "abc", 512, 2)
    assert "--cgroup-version" in on and "memory.max=%d" % (576 * 1024 * 1024) in on
    assert on[on.index("--") + 1:] == ["--api-sock", "api.sock"]       # relative: resolved in the jail
    off = fc.jailer_argv(Settings(JAILER_USE_CGROUPS="false"), "abc", 512, 2)
    assert "--cgroup" not in off and "--cgroup-version" not in off


@pytest.mark.asyncio
async def test_preflight_names_the_actual_problem(env, monkeypatch):
    tmp, s = env
    s.firecracker_binary = s.jailer_binary = str(tmp / "kvm")        # exists but not executable
    eng = fc.FirecrackerEngine(kvm_path=str(tmp / "kvm"))
    with pytest.raises(EngineUnavailable, match="not executable"):
        await eng.preflight()
    os.chmod(tmp / "kvm", 0o755)
    s.kernel_image_path = str(tmp / "nokernel")
    with pytest.raises(EngineUnavailable, match="kernel missing"):
        await eng.preflight()
    s.kernel_image_path = str(tmp / "vmlinux")
    s.jailer_chroot_base = "/tmp/" + "x" * 80                         # socket path would not fit
    with pytest.raises(EngineUnavailable, match="too long"):
        await eng.preflight()
    s.jailer_chroot_base = str(tmp / "jail")
    s.jailer_use_cgroups = False
    s.environment = "prod"
    if os.path.exists("/dev/net/tun"):
        with pytest.raises(EngineUnavailable, match="only allowed when AIJAILER_ENV=dev"):
            await eng.preflight()
