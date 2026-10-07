"""Engine-side reconciliation: orphan VMMs/jails after a control-plane restart.

The "VMMs" are real throwaway processes whose argv looks like the jailer's firecracker
(``<dir>/firecracker --id <uuid>``), so identification, SIGKILL and cleanup run for real."""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import pytest

from aijailer.core.config import Settings
from aijailer.engine import firecracker as fc
from aijailer.engine.microvm import VMStatus

OLD = time.time() - 3600


class FakeAPI:
    def __init__(self, sock, state="Running"):
        self.sock, self._state, self.closed = sock, state, False

    async def state(self):
        if self._state is None:
            raise RuntimeError("no answer")
        return self._state

    async def close(self):
        self.closed = True


@pytest.fixture
def host(monkeypatch):
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="fcr"))
    s = Settings(JAILER_CHROOT_BASE=str(tmp / "jail"), FIRECRACKER_BINARY=str(tmp / "firecracker"),
                 ROOTFS_DIR=str(tmp), KERNEL_IMAGE_PATH=str(tmp / "k"))
    monkeypatch.setattr(fc, "get_settings", lambda: s)
    procs: list[subprocess.Popen] = []
    pings = []

    async def ping(uds, port, timeout=2.0):
        pings.append(uds)
        return {}

    monkeypatch.setattr(fc, "agent_ping", ping)

    class H:
        pass
    h = H()
    h.tmp, h.s, h.pings = tmp, s, pings
    h.states = {}

    def jail(cid, age=3600):
        d = tmp / "jail" / "firecracker" / str(cid)
        (d / "root").mkdir(parents=True)
        (d / "root" / "rootfs.ext4").write_text("x")
        os.utime(d, (time.time() - age,) * 2)
        return d
    h.jail = jail

    def vmm(cid):
        p = subprocess.Popen([str(tmp / "firecracker"), "-c", "import time;time.sleep(120)",
                              "--id", str(cid)], executable=sys.executable)
        procs.append(p)
        time.sleep(0.15)                      # let exec set argv
        return p
    h.vmm = vmm

    def engine():
        return fc.FirecrackerEngine(
            api_factory=lambda sock: FakeAPI(sock, h.states.get(pathlib.Path(sock).parts[-3])),
            kvm_path=str(tmp / "kvm"), chown=lambda *a: None)
    h.engine = engine
    yield h
    for p in procs:
        p.kill()
        p.wait()
    shutil.rmtree(tmp, ignore_errors=True)


def alive(p):
    return p.poll() is None


@pytest.mark.asyncio
async def test_orphan_vmm_is_killed_and_its_jail_removed(host):
    cid = uuid.uuid4()
    d, p = host.jail(cid), host.vmm(cid)
    rep = await host.engine().reconcile({}, set(), grace=60)
    assert rep.orphans_killed == [cid] and not rep.errors
    assert not alive(p) and not d.exists()


@pytest.mark.asyncio
async def test_leftover_jail_without_vmm_is_removed(host):
    cid = uuid.uuid4()
    d = host.jail(cid)
    rep = await host.engine().reconcile({}, set(), grace=60)
    assert rep.leftovers_removed == [cid] and not d.exists()


@pytest.mark.asyncio
async def test_vmm_without_any_jail_is_still_killed(host):
    cid = uuid.uuid4()
    p = host.vmm(cid)
    rep = await host.engine().reconcile({}, set(), grace=60)
    assert rep.orphans_killed == [cid] and not alive(p)


@pytest.mark.asyncio
async def test_young_jail_protected_and_in_flight_cells_untouched(host):
    young, flight, launching = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    dy, df, dl = host.jail(young, age=5), host.jail(flight), host.jail(launching)
    py, pf, pl = host.vmm(young), host.vmm(flight), host.vmm(launching)
    eng = host.engine()
    eng._launching.add(launching)
    rep = await eng.reconcile({}, {flight}, grace=60)
    assert rep.skipped_young == [young] and not rep.orphans_killed
    assert all(alive(p) for p in (py, pf, pl)) and all(d.exists() for d in (dy, df, dl))


@pytest.mark.asyncio
async def test_things_we_cannot_identify_are_never_touched(host):
    base = host.tmp / "jail" / "firecracker"
    (base / "not-a-uuid").mkdir(parents=True)
    (base / "not-a-uuid" / "keep").write_text("x")
    other = uuid.uuid4()
    unrelated = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)",
                                  "--id", str(other)])           # same flag, different program
    try:
        time.sleep(0.1)
        rep = await host.engine().reconcile({}, set(), grace=60)
        assert not rep.orphans_killed and not rep.leftovers_removed
        assert (base / "not-a-uuid" / "keep").exists() and alive(unrelated)
    finally:
        unrelated.kill()
        unrelated.wait()


@pytest.mark.asyncio
async def test_surviving_vmm_of_live_cell_is_adopted_and_usable(host):
    cid = uuid.uuid4()
    host.jail(cid)
    p = host.vmm(cid)
    host.states[str(cid)] = "Running"
    eng = host.engine()
    rep = await eng.reconcile({cid: {"http_proxy": "http://h:1"}}, set(), grace=60)
    assert rep.adopted == [cid] and alive(p)
    info = await eng.get_vm_info(cid)
    assert info.status == VMStatus.RUNNING and info.pid == p.pid
    assert info.vsock_path.endswith(f"{cid}/root/vsock.sock")
    assert eng._vms[cid]["env"] == {"http_proxy": "http://h:1"}
    # now managed: a second pass changes nothing, and once the cell is no longer live it is reaped
    assert not (await eng.reconcile({cid: {}}, set(), 60)).changed
    rep = await eng.reconcile({}, set(), grace=60)
    assert rep.orphans_killed == [cid] and not alive(p) and cid not in eng._vms


@pytest.mark.asyncio
async def test_adopted_paused_vm_reports_paused(host):
    cid = uuid.uuid4()
    host.jail(cid), host.vmm(cid)
    host.states[str(cid)] = "Paused"
    eng = host.engine()
    await eng.reconcile({cid: {}}, set(), 60)
    assert (await eng.get_vm_info(cid)).status == VMStatus.PAUSED
    assert host.pings == []                    # a paused guest cannot answer; do not wait on it


@pytest.mark.asyncio
async def test_unresponsive_survivor_is_reported_not_adopted_then_reaped(host):
    cid = uuid.uuid4()
    host.jail(cid)
    p = host.vmm(cid)
    host.states[str(cid)] = None               # API does not answer
    eng = host.engine()
    rep = await eng.reconcile({cid: {}}, set(), 60)
    assert rep.unresponsive == [cid] and rep.broken == [cid] and cid not in eng._vms
    assert alive(p)                            # not killed while the DB still calls it live
    rep = await eng.reconcile({}, set(), 60)   # reconciler marked it error -> now an orphan
    assert rep.orphans_killed == [cid] and not alive(p)


@pytest.mark.asyncio
async def test_live_cell_with_no_vmm_is_dead(host):
    cid = uuid.uuid4()
    rep = await host.engine().reconcile({cid: {}}, set(), 60)
    assert rep.dead == [cid]


@pytest.mark.asyncio
async def test_managed_vm_whose_vmm_died_is_dead_and_cleaned(host):
    cid = uuid.uuid4()
    d = host.jail(cid)
    p = host.vmm(cid)
    host.states[str(cid)] = "Running"
    eng = host.engine()
    await eng.reconcile({cid: {}}, set(), 60)
    p.kill()
    p.wait()
    rep = await eng.reconcile({cid: {}}, set(), 60)
    assert rep.dead == [cid] and cid not in eng._vms and not d.exists()


@pytest.mark.asyncio
async def test_pid_reuse_is_not_mistaken_for_the_vmm(host):
    cid = uuid.uuid4()
    host.jail(cid)
    host.states[str(cid)] = "Running"
    eng = host.engine()
    await eng.reconcile({cid: {}}, set(), 60)          # nothing running -> dead, not adopted
    bystander = subprocess.Popen([sys.executable, "-c", "import time;time.sleep(30)"])
    try:
        eng._vms[cid] = {"jail": host.tmp, "fc_pid": bystander.pid, "api": None, "root": host.tmp,
                         "info": type("I", (), {"status": VMStatus.RUNNING})(), "env": {}}
        rep = await eng.reconcile({cid: {}}, set(), 60)
        assert rep.dead == [cid] and alive(bystander)   # pid exists but is not our VMM
    finally:
        bystander.kill()
        bystander.wait()


@pytest.mark.asyncio
async def test_stopped_vm_kept_until_destroy(host):
    cid = uuid.uuid4()
    d = host.jail(cid)
    eng = host.engine()
    eng._vms[cid] = {"jail": d, "fc_pid": None, "api": None, "root": d / "root", "env": {},
                     "info": type("I", (), {"status": VMStatus.STOPPED})()}
    rep = await eng.reconcile({}, set(), 60)
    assert not rep.changed and d.exists() and cid in eng._vms


@pytest.mark.asyncio
async def test_mass_removal_is_refused(host):
    ids = [uuid.uuid4() for _ in range(8)]
    ds = [host.jail(c) for c in ids]
    rep = await host.engine().reconcile({}, set(), 60)     # "DB returned nothing"
    assert rep.aborted and not rep.changed and all(d.exists() for d in ds)


@pytest.mark.asyncio
async def test_orphan_cgroup_is_removed(host, monkeypatch):
    cid = uuid.uuid4()
    host.jail(cid)
    cg = host.tmp / "cg" / "firecracker" / str(cid)
    cg.mkdir(parents=True)
    eng = host.engine()
    eng._cgroup = host.tmp / "cg"
    await eng.reconcile({}, set(), 60)
    assert not cg.exists()
