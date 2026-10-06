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
    s = Settings(CELL_DATA_DIR=str(tmp_path / "cells"), ROOTFS_DIR=str(tmp_path / "rootfs"))
    monkeypatch.setattr(fc, "get_settings", lambda: s)
    (tmp_path / "rootfs").mkdir()
    (tmp_path / "rootfs" / "base-python.ext4").write_bytes(b"BASE")
    (tmp_path / "kvm").write_text("")
    yield tmp_path, s
    shutil.rmtree(tmp_path, ignore_errors=True)


async def make_engine(tmp, fake_holder):
    async def spawner(argv):
        cell = argv[argv.index("--id") + 1]
        sock = os.path.join(str(tmp), "cells", cell, "api.sock")
        fake = FakeFirecracker(sock)
        await fake.start()
        fake_holder[cell] = fake
        return 0

    return fc.FirecrackerEngine(spawner=spawner, kvm_path=str(tmp / "kvm"))


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
    assert drive["path_on_host"].endswith(f"{a}/rootfs.ext4") and "base-python" not in drive["path_on_host"]
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
    out = await eng.snapshot_vm(cid, str(tmp / "snap"))
    calls = [c[:2] for c in holder[str(cid)].calls[5:]]
    assert calls == [("PATCH", "/vm"), ("PATCH", "/vm"), ("PATCH", "/vm"),
                     ("PUT", "/snapshot/create"), ("PATCH", "/vm")]
    assert os.path.exists(out["disk"])


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
    net = VMNetwork("ajtap0000001", "10.200.0.2", "10.200.0.1", 30)
    await eng.create_vm(VMConfig(cell_id=a, image="base-python", network=net))
    await eng.create_vm(VMConfig(cell_id=b, image="base-python"))  # no network -> no NIC at all
    with_net = {c[1]: c[2] for c in holder[str(a)].calls}
    assert with_net["/network-interfaces/eth0"]["host_dev_name"] == "ajtap0000001"
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
