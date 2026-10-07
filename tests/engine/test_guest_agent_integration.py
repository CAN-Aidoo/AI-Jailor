"""End-to-end: real Go guest agent <-> Python host client through a Firecracker-style
vsock UDS proxy (CONNECT <port> / OK <n>). Skipped when no Go toolchain is available."""

import asyncio
import os
import pathlib
import shutil
import subprocess
import tempfile

import pytest

from aijailer.engine import firecracker as fc

AGENT_DIR = pathlib.Path(__file__).resolve().parents[2] / "guest-agent"
pytestmark = pytest.mark.skipif(shutil.which("go") is None, reason="go toolchain not installed")


@pytest.fixture(scope="module")
def agent_bin():
    out = pathlib.Path(tempfile.mkdtemp(prefix="ajbin")) / "aijailer-agent"
    env = {**os.environ, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local"}
    r = subprocess.run(["go", "build", "-trimpath", "-o", str(out), "."], cwd=AGENT_DIR,
                       env=env, capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip(f"agent build failed here: {r.stderr[-300:]}")
    yield out
    shutil.rmtree(out.parent, ignore_errors=True)


@pytest.fixture
async def vm(agent_bin):
    """Agent on a guest-side socket + a proxy on the 'host' UDS emulating Firecracker."""
    d = pathlib.Path(tempfile.mkdtemp(prefix="aj"))
    guest, host = str(d / "g.sock"), str(d / "v.sock")
    proc = subprocess.Popen([str(agent_bin), "-listen", f"unix:{guest}",
                             "-insecure-no-drop-privileges"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        if os.path.exists(guest):
            break
        await asyncio.sleep(0.02)

    async def proxy(r, w):
        line = await r.readline()
        assert line.startswith(b"CONNECT ")
        gr, gw = await asyncio.open_unix_connection(guest)
        w.write(b"OK 1073741824\n")
        await w.drain()

        async def pipe(src, dst):
            try:
                while data := await src.read(65536):
                    dst.write(data)
                    await dst.drain()
            finally:
                dst.close()

        await asyncio.gather(pipe(r, gw), pipe(gr, w))

    server = await asyncio.start_unix_server(proxy, host)
    yield host
    server.close()
    proc.kill()
    proc.wait()
    shutil.rmtree(d, ignore_errors=True)


@pytest.mark.asyncio
async def test_ping(vm):
    r = await fc.agent_ping(vm, 5000)
    assert r["ok"] is True and r["version"]


@pytest.mark.asyncio
async def test_exec_roundtrip_and_exit_code(vm):
    r = await fc.agent_exec(vm, 5000, "echo out; echo err >&2; exit 3", 10, "agent")
    assert (r.exit_code, r.stdout, r.stderr) == (3, "out\n", "err\n")
    assert not r.timed_out and r.duration_ms >= 0


@pytest.mark.asyncio
async def test_timeout_reported(vm):
    r = await fc.agent_exec(vm, 5000, "sleep 30", 1, "agent")
    assert r.exit_code == 124 and r.timed_out


@pytest.mark.asyncio
async def test_agent_error_surfaces_as_exception(vm):
    with pytest.raises(fc.AgentError):
        await fc.agent_request(vm, 5000, {"op": "bogus"}, 5)


@pytest.mark.asyncio
async def test_file_put_get_binary_safe(vm, tmp_path):
    payload = bytes(range(256)) * 100
    target = str(tmp_path / "blob.bin")
    await fc.agent_put_file(vm, 5000, target, payload, mode=0o600)
    assert await fc.agent_get_file(vm, 5000, target) == payload
    assert (os.stat(target).st_mode & 0o777) == 0o600


@pytest.mark.asyncio
async def test_get_missing_file_is_agent_error(vm):
    with pytest.raises(fc.AgentError):
        await fc.agent_get_file(vm, 5000, "/definitely/not/here")
