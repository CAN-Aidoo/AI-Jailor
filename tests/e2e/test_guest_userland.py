"""The guest agent running inside the REAL guest userland (Firecracker's Ubuntu 24.04 CI rootfs plus
our agent and `agent` user), in a chroot. No KVM needed.

Enable:  sudo scripts/e2e/build-rootfs.sh /opt/guest && AIJAILER_GUEST_TREE=/opt/guest/tree pytest tests/e2e/test_guest_userland.py

Proves what unit tests with a stand-in shell cannot: the static agent works against the real guest's
libc/shell/coreutils/python, switches to uid 1000 using the guest's own /etc/passwd, refuses root,
and applies no_new_privs, env isolation, process-group kill and orphan reaping there.
It does NOT prove PID-1 duties or vsock (those need the guest booted: tests/e2e/test_kvm_full_path.py)."""

import asyncio
import base64
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time

import pytest

TREE = os.environ.get("AIJAILER_GUEST_TREE", "")
pytestmark = pytest.mark.skipif(
    not TREE or not os.path.exists(f"{TREE}/sbin/aijailer-agent") or os.geteuid() != 0
    or not shutil.which("unshare"),
    reason="set AIJAILER_GUEST_TREE (see scripts/e2e/build-rootfs.sh); needs root")


async def call(sock, req, timeout=30):
    r, w = await asyncio.open_unix_connection(sock)
    body = json.dumps(req).encode()
    w.write(struct.pack(">I", len(body)) + body)
    await w.drain()
    (n,) = struct.unpack(">I", await asyncio.wait_for(r.readexactly(4), timeout))
    out = json.loads(await r.readexactly(n))
    w.close()
    return out


@pytest.fixture
async def agent():
    sock_dir = tempfile.mkdtemp(prefix="ag")
    host_sock = f"{sock_dir}/a.sock"
    os.makedirs(f"{TREE}/run/aj", exist_ok=True)
    # private mount namespace: bind-mount the socket dir, /proc and /dev into the tree, then chroot
    script = (f"mount --bind {sock_dir} {TREE}/run/aj && mount -t proc proc {TREE}/proc && "
              f"mount --rbind /dev {TREE}/dev && "
              f"exec env -i AGENT_SECRET=hunter2 PATH=/usr/bin:/bin $(command -v chroot) {TREE} "
              f"/sbin/aijailer-agent -listen unix:/run/aj/a.sock -max-concurrent 4")
    proc = subprocess.Popen(["unshare", "-m", "--propagation", "private", "sh", "-c", script],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(100):
        if os.path.exists(host_sock):
            break
        await asyncio.sleep(0.05)
    else:
        proc.kill()
        pytest.fail("agent did not start: " + proc.stderr.read().decode()[-500:])
    yield host_sock
    proc.kill()
    proc.wait()
    shutil.rmtree(sock_dir, ignore_errors=True)


async def sh(agent, cmd, **kw):
    return await call(agent, {"op": "exec", "cmd": cmd, **kw})


@pytest.mark.asyncio
async def test_ping_and_runs_as_the_guests_agent_user(agent):
    assert (await call(agent, {"op": "ping"}))["ok"] is True
    r = await sh(agent, "id -u; id -un; id -g; echo $HOME; pwd")
    uid = os.environ.get("AIJAILER_GUEST_AGENT_UID", "3000")
    assert r["exit_code"] == 0 and r["stdout"].split() == [uid, "agent", uid, "/home/agent",
                                                           "/home/agent"], r


@pytest.mark.asyncio
async def test_root_and_unknown_users_are_refused(agent):
    for user in ("root", "nobody-here"):
        r = await sh(agent, "id", user=user)
        assert "error" in r, r


@pytest.mark.asyncio
async def test_real_guest_tools_are_available_to_workloads(agent):
    r = await sh(agent, "python3 -c 'import sys; print(sys.version_info[0])'; which sh curl || true")
    assert r["stdout"].startswith("3"), r


@pytest.mark.asyncio
async def test_no_new_privs_and_clean_environment(agent):
    r = await sh(agent, "grep NoNewPrivs /proc/self/status; echo secret=${AGENT_SECRET:-unset}")
    assert "NoNewPrivs:\t1" in r["stdout"] and "secret=unset" in r["stdout"], r
    r = await sh(agent, "echo $FOO", env={"FOO": "bar"})
    assert r["stdout"].strip() == "bar"


@pytest.mark.asyncio
async def test_setuid_binaries_cannot_escalate(agent):
    r = await sh(agent, "su -c id root 2>&1; sudo -n id 2>&1; passwd -S root 2>&1; true")
    assert "uid=0" not in r["stdout"], r


@pytest.mark.asyncio
async def test_base_image_has_no_setuid_binaries_and_locked_logins(agent):
    r = await sh(agent, "find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | head -5; "
                        "awk -F: '$2 != \"*\" && $2 != \"!\" && $2 != \"!*\" {print $1}' /etc/shadow")
    assert r["stdout"].strip() == "", r["stdout"]       # nothing setuid, no usable password hashes


@pytest.mark.asyncio
async def test_files_roundtrip_owned_by_the_agent_user(agent):
    data = bytes(range(256)) * 50
    r = await call(agent, {"op": "put_file", "path": "/home/agent/blob.bin",
                           "data": base64.b64encode(data).decode(), "mode": 0o640})
    assert r.get("ok") is True, r
    g = await call(agent, {"op": "get_file", "path": "/home/agent/blob.bin"})
    assert base64.b64decode(g["data"]) == data
    st = await sh(agent, "stat -c '%u:%g %a' /home/agent/blob.bin")
    uid = os.environ.get("AIJAILER_GUEST_AGENT_UID", "3000")
    assert st["stdout"].strip() == f"{uid}:{uid} 640", st


@pytest.mark.asyncio
async def test_timeout_kills_the_group_and_orphans_are_reaped(agent):
    t = time.monotonic()
    r = await sh(agent, "sleep 300 & echo $!; wait", timeout=1)
    assert r["exit_code"] == 124 and r["timed_out"] and time.monotonic() - t < 6
    pid = r["stdout"].split()[0]
    for _ in range(40):
        s = await sh(agent, f"test -d /proc/{pid} && echo alive || echo gone")
        if "gone" in s["stdout"]:
            return
        await asyncio.sleep(0.1)
    pytest.fail("background process survived its request")


@pytest.mark.asyncio
async def test_background_jobs_do_not_pin_the_request(agent):
    t = time.monotonic()
    r = await sh(agent, "sleep 300 & echo started")
    assert r["stdout"].strip() == "started" and time.monotonic() - t < 3
