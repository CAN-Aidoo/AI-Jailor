"""restore_vm / snapshot bundle handling against the fake Firecracker API (no KVM needed)."""

import json
import os
import uuid

import pytest

from aijailer.engine import firecracker as fc
from aijailer.engine.microvm import VMConfig, VMNetwork, VMStatus
from tests.engine.test_firecracker import env, jail_root, make_engine  # noqa: F401

NET = VMNetwork("tapX", "10.97.0.2", "10.97.0.1", 30, "/proc/self/ns/net")


def cfg(cell=None, net=NET, **kw):
    return VMConfig(cell_id=cell or uuid.uuid4(), image="base-python", vcpus=2, memory_mb=256,
                    network=net, **kw)


async def snapshot_of(eng, tmp, holder, config):
    await eng.create_vm(config)
    root = jail_root(tmp, str(config.cell_id))
    for name in ("vm.snap", "vm.mem"):
        open(os.path.join(root, name), "wb").write(name.encode() * 100)
    open(os.path.join(root, "rootfs.ext4"), "wb").write(b"DISK-STATE")   # guest wrote to its disk
    return await eng.snapshot_vm(config.cell_id, str(tmp / "snap"))


@pytest.mark.asyncio
async def test_snapshot_writes_verifiable_metadata(env):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    out = await snapshot_of(eng, tmp, holder, cfg())
    meta = json.load(open(out["meta"]))
    assert meta["version"] == 1 and meta["network"]["guest_ip"] == "10.97.0.2"
    assert (meta["vcpus"], meta["memory_mb"], meta["image"]) == (2, 256, "base-python")
    assert set(meta["files"]) == {"vm.snap", "vm.mem", "rootfs.ext4"}


@pytest.mark.asyncio
async def test_restore_loads_snapshot_into_a_fresh_jail_without_reconfiguring(env):
    tmp, s = env
    holder = {}
    eng = await make_engine(tmp, holder)
    src = cfg()
    await snapshot_of(eng, tmp, holder, src)
    new = cfg(net=VMNetwork("tapNEW", "10.97.0.2", "10.97.0.1", 30, "/proc/self/ns/net"))
    chowned = []
    eng._chown = lambda path, *a: chowned.append(os.path.basename(path))
    info = await eng.restore_vm(new, str(tmp / "snap"))
    calls = holder[str(new.cell_id)].calls
    assert [c[:2] for c in calls] == [("PUT", "/snapshot/load")]       # no boot-source/drives/start
    assert calls[0][2] == {
        "snapshot_path": "vm.snap", "resume_vm": True,
        "mem_backend": {"backend_path": "vm.mem", "backend_type": "File"},
        "network_overrides": [{"iface_id": "eth0", "host_dev_name": "tapNEW"}]}
    root = jail_root(tmp, str(new.cell_id))
    assert open(f"{root}/rootfs.ext4", "rb").read() == b"DISK-STATE"    # the snapshot's disk
    assert os.path.exists(f"{root}/vm.mem") and not os.path.exists(f"{root}/vmlinux")
    assert {"rootfs.ext4", "vm.mem", "vm.snap"} <= set(chowned)         # owned by the jailer uid
    assert info.status == VMStatus.RUNNING and info.internal_ip == "10.97.0.2"
    assert (await eng.get_vm_info(new.cell_id)).status == VMStatus.RUNNING
    assert os.path.exists(tmp / "snap" / "vm.mem")                      # bundle left pristine


@pytest.mark.asyncio
async def test_restored_vm_is_a_normal_managed_vm_and_can_be_snapshotted_again(env):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    await snapshot_of(eng, tmp, holder, cfg())
    new = cfg()
    await eng.restore_vm(new, str(tmp / "snap"))
    await eng.pause_vm(new.cell_id)
    assert eng._vms[new.cell_id]["meta"]["network"]["guest_ip"] == "10.97.0.2"
    await eng.destroy_vm(new.cell_id)
    assert not os.path.exists(os.path.dirname(jail_root(tmp, str(new.cell_id))))


@pytest.mark.asyncio
async def test_machine_shape_comes_from_the_snapshot_not_the_request(env):
    tmp, _ = env
    holder, seen = {}, []
    eng = await make_engine(tmp, holder)
    await snapshot_of(eng, tmp, holder, cfg())
    orig = eng._spawner

    async def spy(argv, log):
        seen.append(argv)
        return await orig(argv, log)
    eng._spawner = spy
    wrong = VMConfig(cell_id=uuid.uuid4(), image="other", vcpus=8, memory_mb=4096, network=NET)
    await eng.restore_vm(wrong, str(tmp / "snap"))
    assert eng._vms[wrong.cell_id]["meta"]["vcpus"] == 2 and eng._vms[wrong.cell_id]["meta"]["memory_mb"] == 256


@pytest.mark.asyncio
async def test_two_restores_get_independent_disks(env):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    await snapshot_of(eng, tmp, holder, cfg())
    a, b = cfg(), cfg()
    await eng.restore_vm(a, str(tmp / "snap"))
    await eng.restore_vm(b, str(tmp / "snap"))
    open(f"{jail_root(tmp, str(a.cell_id))}/rootfs.ext4", "wb").write(b"A-WROTE")
    assert open(f"{jail_root(tmp, str(b.cell_id))}/rootfs.ext4", "rb").read() == b"DISK-STATE"
    assert open(tmp / "snap" / "rootfs.ext4", "rb").read() == b"DISK-STATE"


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["truncate_mem", "delete_disk", "no_meta", "bad_json"])
async def test_unusable_bundles_are_rejected_before_anything_is_spawned(env, damage):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    await snapshot_of(eng, tmp, holder, cfg())
    snap = tmp / "snap"
    if damage == "truncate_mem":
        open(snap / "vm.mem", "ab").write(b"x")
    elif damage == "delete_disk":
        os.unlink(snap / "rootfs.ext4")
    elif damage == "no_meta":
        os.unlink(snap / "meta.json")
    else:
        open(snap / "meta.json", "w").write("{")
    new = cfg()
    with pytest.raises(fc.SnapshotError):
        await eng.restore_vm(new, str(snap))
    assert str(new.cell_id) not in holder and new.cell_id not in eng._vms
    assert not os.path.exists(os.path.dirname(jail_root(tmp, str(new.cell_id))))


@pytest.mark.asyncio
@pytest.mark.parametrize("net", [
    VMNetwork("t", "10.97.0.6", "10.97.0.5", 30, "/proc/self/ns/net"),   # different guest address
    None])                                                                  # no NIC at all
async def test_restore_into_a_different_guest_network_is_refused(env, net):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    await snapshot_of(eng, tmp, holder, cfg())
    with pytest.raises(fc.SnapshotError, match="same guest address"):
        await eng.restore_vm(cfg(net=net), str(tmp / "snap"))


@pytest.mark.asyncio
async def test_failed_load_leaves_nothing_behind(env):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    await snapshot_of(eng, tmp, holder, cfg())

    async def boom(*a, **k):
        raise RuntimeError("firecracker PUT /snapshot/load -> 400: bad snapshot")
    new = cfg()
    orig = eng._api_factory

    def factory(sock):
        api = orig(sock)
        api.load_snapshot = boom
        return api
    eng._api_factory = factory
    with pytest.raises(RuntimeError, match="bad snapshot"):
        await eng.restore_vm(new, str(tmp / "snap"))
    assert new.cell_id not in eng._vms and new.cell_id not in eng._launching
    assert not os.path.exists(os.path.dirname(jail_root(tmp, str(new.cell_id))))


@pytest.mark.asyncio
async def test_restore_refuses_a_cell_that_already_has_a_vm_and_needs_kvm(env):
    tmp, _ = env
    holder = {}
    eng = await make_engine(tmp, holder)
    c = cfg()
    snap = await snapshot_of(eng, tmp, holder, c)
    with pytest.raises(RuntimeError, match="already has a VM"):
        await eng.restore_vm(c, str(tmp / "snap"))
    eng._kvm = str(tmp / "missing")
    with pytest.raises(Exception, match="refusing to run without hardware isolation"):
        await eng.restore_vm(cfg(), str(tmp / "snap"))
    assert snap["meta"]


@pytest.mark.asyncio
async def test_adopted_vm_cannot_be_snapshotted(env):
    tmp, _ = env
    eng = await make_engine(tmp, {})
    cid = uuid.uuid4()
    eng._vms[cid] = {"root": tmp, "api": None, "info": type("I", (), {"status": VMStatus.RUNNING})()}
    with pytest.raises(RuntimeError, match="adopted"):
        await eng.snapshot_vm(cid, str(tmp / "s"))
