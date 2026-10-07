"""SnapshotService: create / restore-in-place / clone, with a NIC engine and a real NetAllocator."""

import ipaddress
import uuid

import pytest
from sqlalchemy import select

from aijailer.core.config import get_settings
from aijailer.core.exceptions import AiJailerError, InvalidStateTransitionError
from aijailer.engine.microvm import MicroVMEngine, VMInfo, VMStatus
from aijailer.models.cell import Cell
from aijailer.models.snapshot import Snapshot
from aijailer.models.tenant import Tenant
from aijailer.netpolicy.cell_network import Provisioned
from aijailer.netpolicy.nft import CellNet, LinkInfo, NetAllocator, NftError
from aijailer.services import cell_service, snapshot_service
from aijailer.services.cell_service import CellService
from aijailer.services.snapshot_service import SnapshotService


class Engine(MicroVMEngine):
    isolation = "hardware-kvm"
    needs_network = True

    def __init__(self, log, root):
        self.log, self.root, self.vms = log, root, {}
        self.fail_restore = self.fail_check = self.fail_snapshot = False
        self.restored = []

    async def create_vm(self, config):
        self.log.append("vm:create")
        self.vms[config.cell_id] = config
        return VMInfo(config.cell_id, VMStatus.RUNNING, internal_ip=config.network.guest_ip)

    async def start_vm(self, cell_id): ...
    async def stop_vm(self, cell_id, grace_period=10): ...
    async def pause_vm(self, cell_id): ...
    async def resume_vm(self, cell_id): ...

    async def destroy_vm(self, cell_id):
        self.log.append("vm:destroy")
        self.vms.pop(cell_id, None)

    async def exec_command(self, *a, **k): raise NotImplementedError
    async def get_vm_info(self, cell_id): return VMInfo(cell_id, VMStatus.RUNNING)

    async def snapshot_vm(self, cell_id, snapshot_dir):
        self.log.append("vm:snapshot")
        if self.fail_snapshot:
            raise RuntimeError("disk full /secret/path")
        import os
        os.makedirs(snapshot_dir)
        for n, data in (("vm.mem", b"m" * 100), ("rootfs.ext4", b"d" * 50), ("vm.snap", b"s")):
            open(os.path.join(snapshot_dir, n), "wb").write(data)
        return {"state": f"{snapshot_dir}/vm.snap", "memory": f"{snapshot_dir}/vm.mem",
                "disk": f"{snapshot_dir}/rootfs.ext4"}

    async def check_snapshot(self, snapshot_dir):
        self.log.append("vm:check")
        if self.fail_check:
            raise RuntimeError("sha mismatch")

    async def restore_vm(self, config, snapshot_dir):
        self.log.append("vm:restore")
        if self.fail_restore:
            raise RuntimeError("firecracker said no")
        self.restored.append((config, snapshot_dir))
        self.vms[config.cell_id] = config
        return VMInfo(config.cell_id, VMStatus.RUNNING, internal_ip=config.network.guest_ip)


class AllocNet:
    """CellNetwork stand-in backed by the REAL allocator (so address rules are the real ones)."""

    def __init__(self, log):
        self.log, self.alloc, self.nets, self.policies = log, NetAllocator("10.97.0.0/24"), {}, {}
        self.bandwidths = {}

    async def provision(self, cell_id, tenant_id, policy, bandwidth=None, subnet=None):
        self.log.append("net:provision")
        if subnet:
            sn = ipaddress.ip_network(subnet)
            self.alloc.claim(cell_id, sn)
        else:
            sn = self.alloc.allocate(cell_id)
        h = list(sn.hosts())
        net = CellNet(cell_id, "aj" + cell_id.hex[:12], h[0], h[1], 30, 3128)
        self.nets[cell_id], self.policies[cell_id] = net, policy
        self.bandwidths[cell_id] = bandwidth
        return Provisioned(net, LinkInfo("tap0", "/run/netns/x"), "u", {"http_proxy": f"http://{h[0]}:3128"})

    def subnet_of(self, cell_id):
        n = self.nets.get(cell_id)
        return n.network if n else None

    def subnet_available(self, cell_id, subnet):
        return self.alloc.is_available(cell_id, ipaddress.ip_network(subnet))

    async def deprovision(self, cell_id):
        self.log.append("net:deprovision")
        self.alloc.release(cell_id)
        self.nets.pop(cell_id, None)
        return []


@pytest.fixture
async def world(db_session, monkeypatch, tmp_path):
    log = []
    eng = Engine(log, tmp_path)
    monkeypatch.setattr(cell_service, "get_microvm_engine", lambda: eng)
    monkeypatch.setenv("SNAPSHOT_DIR", str(tmp_path / "snaps"))     # get_settings() is uncached
    net = AllocNet(log)
    tenant = Tenant(name="t", slug=f"t-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                    max_concurrent_cells=3)
    db_session.add(tenant)
    await db_session.commit()
    cells = CellService(db_session, network=net)
    snaps = SnapshotService(db_session, cells)
    cell = await cells.create_cell(
        tenant_id=tenant.id, name="c", image="base-python", vcpus=2, memory_mb=256, disk_mb=512,
        network_bandwidth_mbps=10, security_policy_id=tenant.id, environment={"A": "1"}, tags={})
    log.clear()
    return snaps, cells, eng, net, tenant, cell, log


async def status(db, cid):
    await db.rollback()
    return (await db.get(Cell, cid, populate_existing=True)).status


@pytest.mark.asyncio
async def test_create_snapshot_records_config_files_and_address(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, "n", "d")
    assert snap.status == "available" and snap.completed_at
    assert snap.memory_size_bytes == 100 and snap.disk_size_bytes == 50 and snap.total_size_bytes == 150
    assert snap.cell_config["vcpus"] == 2 and snap.cell_config["environment"] == {"A": "1"}
    assert snap.cell_config["network"]["subnet"] == str(net.subnet_of(cell.id))
    assert snap.memory_snapshot_key == f"{tenant.id}/{snap.id}/vm.mem"


@pytest.mark.asyncio
async def test_snapshot_failure_leaks_nothing_and_hides_internals(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    eng.fail_snapshot = True
    with pytest.raises(AiJailerError) as e:
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    assert e.value.code == "snapshot_failed" and "/secret" not in e.value.message
    await db_session.rollback()
    assert (await db_session.execute(select(Snapshot))).scalars().all() == []


@pytest.mark.asyncio
async def test_snapshot_requires_a_live_cell_and_a_supporting_engine(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    cell.status = "stopped"
    with pytest.raises(InvalidStateTransitionError):
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    cell.status = "running"

    async def nope(*a):
        raise NotImplementedError
    eng.snapshot_vm = nope
    with pytest.raises(AiJailerError) as e:
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    assert e.value.code == "snapshot_unsupported"


@pytest.mark.asyncio
async def test_restore_replaces_vm_keeps_address_and_uses_current_policy_and_bandwidth(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, "n", None)
    old_subnet = net.subnet_of(cell.id)
    cell.effective_policy = {"network": {"egress": []}}            # tightened after the snapshot
    cell.bandwidth_override = {"down_kbit": 2000, "up_kbit": 1000}
    cell.environment = {"A": "2"}
    log.clear()
    out = await snaps.restore_cell(cell.id, tenant.id, snap.id)
    assert log == ["vm:check", "vm:destroy", "net:deprovision", "net:provision", "vm:restore"]
    assert out.status == "running" and out.error_message is None
    assert net.subnet_of(cell.id) == old_subnet
    cfg, path = eng.restored[0]
    assert path.endswith(f"{tenant.id}/{snap.id}") and cfg.network.guest_ip == str(
        list(ipaddress.ip_network(old_subnet).hosts())[1])
    assert cfg.environment["A"] == "2" and "http_proxy" in cfg.environment
    assert net.policies[cell.id] == {"egress": []}                  # current policy, not the old one
    assert (net.bandwidths[cell.id].down_kbit, net.bandwidths[cell.id].up_kbit) == (2000, 1000)


@pytest.mark.asyncio
async def test_restore_of_a_stopped_cell_after_its_address_moved_reclaims_the_old_one(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    old = net.subnet_of(cell.id)
    await net.deprovision(cell.id)
    cell.status = "stopped"
    tmp = uuid.uuid4()
    await net.provision(tmp, tenant.id, None)                        # takes the freed slot...
    await net.provision(cell.id, tenant.id, None)                    # ...so the restarted cell moves
    await net.deprovision(tmp)                                       # old slot is free again
    assert net.subnet_of(cell.id) != old
    out = await snaps.restore_cell(cell.id, tenant.id, snap.id)
    assert out.status == "running" and net.subnet_of(cell.id) == old


@pytest.mark.asyncio
async def test_restore_refused_before_anything_is_destroyed(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    # 1) address held by someone else
    await net.deprovision(cell.id)
    squatter = uuid.uuid4()
    net.alloc.claim(squatter, ipaddress.ip_network(snap.cell_config["network"]["subnet"]))
    log.clear()
    with pytest.raises(AiJailerError) as e:
        await snaps.restore_cell(cell.id, tenant.id, snap.id)
    assert e.value.code == "snapshot_address_in_use" and "vm:destroy" not in log
    net.alloc.release(squatter)
    # 2) corrupt bundle
    eng.fail_check = True
    with pytest.raises(AiJailerError) as e:
        await snaps.restore_cell(cell.id, tenant.id, snap.id)
    assert e.value.code == "snapshot_corrupt" and "vm:destroy" not in log
    eng.fail_check = False
    # 3) another cell's snapshot / wrong state / unknown / not available
    other = await cells.create_cell(
        tenant_id=tenant.id, name="o", image="i", vcpus=1, memory_mb=1, disk_mb=1,
        network_bandwidth_mbps=1, security_policy_id=tenant.id, environment={}, tags={})
    with pytest.raises(AiJailerError) as e:
        await snaps.restore_cell(other.id, tenant.id, snap.id)
    assert e.value.code == "snapshot_cell_mismatch"
    with pytest.raises(AiJailerError) as e:
        await snaps.restore_cell(cell.id, tenant.id, uuid.uuid4())
    assert e.value.code == "snapshot_not_found"
    snap.status = "creating"
    with pytest.raises(AiJailerError) as e:
        await snaps.restore_cell(cell.id, tenant.id, snap.id)
    assert e.value.code == "snapshot_not_available"
    snap.status = "available"
    cell.status = "destroyed"
    with pytest.raises(InvalidStateTransitionError):
        await snaps.restore_cell(cell.id, tenant.id, snap.id)


@pytest.mark.asyncio
async def test_failed_restore_marks_error_persistently_and_cleans_up(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    eng.fail_restore = True
    with pytest.raises(AiJailerError) as e:
        await snaps.restore_cell(cell.id, tenant.id, snap.id)
    assert e.value.code == "restore_failed" and "firecracker" not in e.value.message
    assert net.subnet_of(cell.id) is None and cell.id not in eng.vms
    assert await status(db_session, cell.id) == "error"


@pytest.mark.asyncio
async def test_restore_claims_the_cell_so_a_concurrent_restore_loses(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    assert await snaps._claim_in_flight(cell.id, {"running"}) is True
    assert await snaps._claim_in_flight(cell.id, {"running"}) is False      # now 'creating'
    assert await status(db_session, cell.id) == "creating"


@pytest.mark.asyncio
async def test_clone_after_source_is_gone_gets_same_address_and_snapshot_resources(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, "base", None)
    await cells.destroy_cell(cell.id, tenant.id)
    log.clear()
    clone = await snaps.clone_snapshot(snap.id, tenant.id, "c2")
    assert clone.status == "running" and clone.id != cell.id and clone.name == "c2"
    assert (clone.vcpus, clone.memory_mb, clone.environment) == (2, 256, {"A": "1"})
    assert clone.tags["cloned_from_snapshot"] == str(snap.id)
    assert net.subnet_of(clone.id) == snap.cell_config["network"]["subnet"]
    assert log == ["vm:check", "net:provision", "vm:restore"]


@pytest.mark.asyncio
async def test_clone_while_source_holds_the_address_is_refused_cleanly(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    log.clear()
    with pytest.raises(AiJailerError) as e:
        await snaps.clone_snapshot(snap.id, tenant.id, None)
    assert e.value.code == "snapshot_address_in_use" and log == []


@pytest.mark.asyncio
async def test_clone_rejects_resources_unknown_policy_and_cell_limit(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    await cells.destroy_cell(cell.id, tenant.id)
    with pytest.raises(AiJailerError) as e:
        await snaps.clone_snapshot(snap.id, tenant.id, None, resources_requested=True)
    assert e.value.code == "invalid_clone"
    with pytest.raises(AiJailerError) as e:
        await snaps.clone_snapshot(snap.id, tenant.id, None, security_policy_id=uuid.uuid4())
    assert e.value.code == "policy_not_found"
    tenant.max_concurrent_cells = 0
    with pytest.raises(AiJailerError) as e:
        await snaps.clone_snapshot(snap.id, tenant.id, None)
    assert e.value.code == "cell_limit_exceeded"


@pytest.mark.asyncio
async def test_failed_clone_returns_an_error_cell_and_frees_the_address(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    await cells.destroy_cell(cell.id, tenant.id)
    eng.fail_restore = True
    clone = await snaps.clone_snapshot(snap.id, tenant.id, None)
    assert clone.status == "error" and "firecracker" not in (clone.error_message or "")
    assert net.subnet_of(clone.id) is None
    eng.fail_restore = False
    assert (await snaps.clone_snapshot(snap.id, tenant.id, None)).status == "running"


@pytest.mark.asyncio
async def test_snapshots_are_tenant_scoped(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    other = Tenant(name="x", slug=f"x-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                   max_concurrent_cells=5)
    db_session.add(other)
    await db_session.commit()
    for call in (snaps.get_snapshot(snap.id, other.id),
                 snaps.clone_snapshot(snap.id, other.id, None)):
        with pytest.raises(AiJailerError) as e:
            await call
        assert e.value.code == "snapshot_not_found"


# ------------------------------------------------------------------ quota
@pytest.mark.asyncio
async def test_count_quota_blocks_the_next_snapshot_and_delete_frees_it(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshot_count = 2
    a = await snaps.create_snapshot(cell.id, tenant.id, "a", None)
    await snaps.create_snapshot(cell.id, tenant.id, "b", None)
    log.clear()
    with pytest.raises(AiJailerError) as e:
        await snaps.create_snapshot(cell.id, tenant.id, "c", None)
    assert e.value.code == "resource_limit_exceeded" and "snapshots" in e.value.message
    assert "vm:snapshot" not in log                               # refused before touching the VM
    q = await snaps.quota(tenant.id)
    assert (q.count, q.max_count) == (2, 2)
    await snaps.delete_snapshot(a.id, tenant.id)
    assert (await snaps.quota(tenant.id)).count == 1
    await snaps.create_snapshot(cell.id, tenant.id, "c", None)


@pytest.mark.asyncio
async def test_storage_quota_uses_a_reserved_estimate_then_the_real_size(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    # the cell is 256 MiB memory + 512 MiB disk => 768 MiB reserved per snapshot
    tenant.max_snapshot_storage_gb = 1
    first = await snaps.create_snapshot(cell.id, tenant.id, "a", None)
    assert first.total_size_bytes == 150                           # real size replaced the estimate
    q = await snaps.quota(tenant.id)
    assert q.bytes_used == 150 and q.max_bytes == 1 << 30
    # real usage is tiny, but a 768 MiB reservation on top of 150 B still fits in 1 GiB: allowed
    await snaps.create_snapshot(cell.id, tenant.id, "b", None)
    tenant.max_snapshot_storage_gb = 1
    cell.memory_mb = 900                                           # 900 + 512 MiB > 1 GiB
    with pytest.raises(AiJailerError) as e:
        await snaps.create_snapshot(cell.id, tenant.id, "c", None)
    assert e.value.code == "resource_limit_exceeded" and "snapshot_storage" in e.value.message


@pytest.mark.asyncio
async def test_failed_snapshot_gives_its_reservation_back(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshot_count = 1
    eng.fail_snapshot = True
    with pytest.raises(AiJailerError):
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    assert (await snaps.quota(tenant.id)).count == 0
    eng.fail_snapshot = False
    await snaps.create_snapshot(cell.id, tenant.id, None, None)    # the one slot is free again


@pytest.mark.asyncio
async def test_a_reservation_is_visible_to_other_requests_while_the_snapshot_runs(
        world, db_engine, db_session):
    import asyncio

    from sqlalchemy.ext.asyncio import async_sessionmaker
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshot_count = 1
    await db_session.commit()
    gate, entered = asyncio.Event(), asyncio.Event()
    orig = eng.snapshot_vm

    async def slow(cid, d):
        entered.set()
        await gate.wait()
        return await orig(cid, d)
    eng.snapshot_vm = slow
    first = asyncio.create_task(snaps.create_snapshot(cell.id, tenant.id, "slow", None))
    await entered.wait()
    async with async_sessionmaker(db_engine, expire_on_commit=False)() as s2:
        other = SnapshotService(s2, CellService(s2, network=net))
        with pytest.raises(AiJailerError) as e:
            await other.create_snapshot(cell.id, tenant.id, "second", None)
        assert e.value.code == "resource_limit_exceeded"
    gate.set()
    assert (await first).status == "available"


@pytest.mark.asyncio
async def test_snapshots_stuck_in_creating_expire_instead_of_wedging_the_quota(world, db_session):
    from datetime import datetime, timedelta, timezone
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshot_count = 1
    ghost = Snapshot(tenant_id=tenant.id, cell_id=cell.id, status="creating", cell_config={},
                     total_size_bytes=999)
    db_session.add(ghost)
    await db_session.commit()
    with pytest.raises(AiJailerError):                             # fresh in-flight row counts
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    ghost.created_at = datetime.now(timezone.utc) - timedelta(hours=3)
    await db_session.commit()
    ok = await snaps.create_snapshot(cell.id, tenant.id, None, None)  # owner died: row expires
    assert ok.status == "available"
    await db_session.refresh(ghost)
    assert ghost.status == "error"


@pytest.mark.asyncio
async def test_quota_is_per_tenant_and_delete_is_tenant_scoped(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshot_count = 1
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    other = Tenant(name="x", slug=f"x-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                   max_concurrent_cells=5, max_snapshot_count=1)
    db_session.add(other)
    await db_session.commit()
    assert (await snaps.quota(other.id)).count == 0
    with pytest.raises(AiJailerError) as e:
        await snaps.delete_snapshot(snap.id, other.id)
    assert e.value.code == "snapshot_not_found"
    assert (await snaps.quota(tenant.id)).count == 1


@pytest.mark.asyncio
async def test_delete_removes_files_refuses_in_flight_and_keeps_row_if_files_stay(
        world, db_session, monkeypatch):
    import os
    snaps, cells, eng, net, tenant, cell, log = world
    snap = await snaps.create_snapshot(cell.id, tenant.id, None, None)
    path = snaps._dir(snap)
    assert os.path.isdir(path)
    with monkeypatch.context() as m:
        m.setattr(SnapshotService, "_discard_dir", staticmethod(lambda p: None))
        with pytest.raises(AiJailerError) as e:                    # files could not be removed
            await snaps.delete_snapshot(snap.id, tenant.id)
    assert e.value.code == "snapshot_delete_failed" and (await snaps.quota(tenant.id)).count == 1
    snap.status = "creating"
    with pytest.raises(AiJailerError) as e:
        await snaps.delete_snapshot(snap.id, tenant.id)
    assert e.value.code == "snapshot_not_available"
    snap.status = "available"
    await snaps.delete_snapshot(snap.id, tenant.id)
    assert not os.path.exists(path) and (await snaps.quota(tenant.id)).count == 0


@pytest.mark.asyncio
async def test_reservation_is_committed_before_the_slow_engine_call(world, db_session):
    """The reservation (and the tenant row lock) must be released by a COMMIT before the
    snapshot runs; otherwise concurrent requests cannot see it (an in-memory SQLite shared
    connection hides that, so assert the transaction state directly)."""
    snaps, cells, eng, net, tenant, cell, log = world
    seen = {}
    orig = eng.snapshot_vm

    async def probe(cid, d):
        seen["in_tx"] = db_session.in_transaction()
        return await orig(cid, d)
    eng.snapshot_vm = probe
    await snaps.create_snapshot(cell.id, tenant.id, None, None)
    assert seen["in_tx"] is False


# ------------------------------------------------------------------ per-cell quota
@pytest.mark.asyncio
async def test_per_cell_limit_stops_one_cell_taking_the_whole_tenant_allowance(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshots_per_cell = 2
    tenant.max_snapshot_count = 10
    s1 = await snaps.create_snapshot(cell.id, tenant.id, "a", None)
    await snaps.create_snapshot(cell.id, tenant.id, "b", None)
    log.clear()
    with pytest.raises(AiJailerError) as e:
        await snaps.create_snapshot(cell.id, tenant.id, "c", None)
    assert e.value.code == "resource_limit_exceeded" and "snapshots_per_cell" in e.value.message
    assert "vm:snapshot" not in log
    q = await snaps.quota(tenant.id, cell.id)
    assert (q.cell_count, q.max_per_cell, q.count) == (2, 2, 2)
    # another cell of the same tenant is unaffected
    other = await cells.create_cell(
        tenant_id=tenant.id, name="o", image="i", vcpus=1, memory_mb=64, disk_mb=64,
        network_bandwidth_mbps=1, security_policy_id=tenant.id, environment={}, tags={})
    await snaps.create_snapshot(other.id, tenant.id, "x", None)
    assert (await snaps.quota(tenant.id, other.id)).cell_count == 1
    await snaps.delete_snapshot(s1.id, tenant.id)                  # deleting frees the slot
    await snaps.create_snapshot(cell.id, tenant.id, "c", None)


@pytest.mark.asyncio
async def test_per_cell_count_ignores_failed_rows_and_other_tenants(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshots_per_cell = 1
    eng.fail_snapshot = True
    with pytest.raises(AiJailerError):
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    eng.fail_snapshot = False
    db_session.add(Snapshot(tenant_id=tenant.id, cell_id=cell.id, status="error", cell_config={}))
    db_session.add(Snapshot(tenant_id=uuid.uuid4(), cell_id=cell.id, status="available",
                            cell_config={}))                       # same cell id, other tenant
    await db_session.commit()
    await snaps.create_snapshot(cell.id, tenant.id, None, None)    # still allowed: nothing counted
    with pytest.raises(AiJailerError):
        await snaps.create_snapshot(cell.id, tenant.id, None, None)


@pytest.mark.asyncio
async def test_cell_quota_query_is_tenant_scoped(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    other = Tenant(name="x", slug=f"x-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                   max_concurrent_cells=5)
    db_session.add(other)
    await db_session.commit()
    with pytest.raises(Exception) as e:
        await snaps.quota(other.id, cell.id)
    assert getattr(e.value, "code", "") == "cell_not_found"


# ------------------------------------------------------------------ per-cell size limit
@pytest.mark.asyncio
async def test_per_cell_size_limit_uses_real_sizes_and_the_reserved_estimate(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    # cell = 256 MiB memory + 512 MiB disk => 768 MiB reserved per snapshot; per-cell cap 1 GiB
    tenant.max_snapshot_storage_per_cell_gb = 1
    tenant.max_snapshots_per_cell = 10
    first = await snaps.create_snapshot(cell.id, tenant.id, "a", None)
    assert first.total_size_bytes == 150                      # real (tiny) size replaced the estimate
    await snaps.create_snapshot(cell.id, tenant.id, "b", None)   # 300 B + 768 MiB still fits
    cell.memory_mb = 900                                      # 900 + 512 MiB estimate > 1 GiB
    log.clear()
    with pytest.raises(AiJailerError) as e:
        await snaps.create_snapshot(cell.id, tenant.id, "c", None)
    assert e.value.code == "resource_limit_exceeded"
    assert "snapshot_storage_per_cell" in e.value.message and "vm:snapshot" not in log
    q = await snaps.quota(tenant.id, cell.id)
    assert (q.cell_bytes, q.max_bytes_per_cell) == (300, 1 << 30)


@pytest.mark.asyncio
async def test_per_cell_size_counts_real_bytes_of_existing_snapshots(world, db_session):
    snaps, cells, eng, net, tenant, cell, log = world
    tenant.max_snapshot_storage_per_cell_gb = 1
    db_session.add(Snapshot(tenant_id=tenant.id, cell_id=cell.id, status="available",
                            cell_config={}, total_size_bytes=(1 << 30) - 100 * (1 << 20)))
    await db_session.commit()                                 # 924 MiB used by this cell
    with pytest.raises(AiJailerError) as e:                   # +768 MiB estimate > 1 GiB
        await snaps.create_snapshot(cell.id, tenant.id, None, None)
    assert "snapshot_storage_per_cell" in e.value.message
    other = await cells.create_cell(                          # a different cell has its own budget
        tenant_id=tenant.id, name="o", image="i", vcpus=1, memory_mb=64, disk_mb=64,
        network_bandwidth_mbps=1, security_policy_id=tenant.id, environment={}, tags={})
    await snaps.create_snapshot(other.id, tenant.id, None, None)
    # error rows and other tenants' rows with the same cell id are not counted
    tenant.max_snapshot_storage_per_cell_gb = 2
    db_session.add(Snapshot(tenant_id=uuid.uuid4(), cell_id=cell.id, status="available",
                            cell_config={}, total_size_bytes=50 << 30))
    db_session.add(Snapshot(tenant_id=tenant.id, cell_id=cell.id, status="error",
                            cell_config={}, total_size_bytes=50 << 30))
    await db_session.commit()
    await snaps.create_snapshot(cell.id, tenant.id, None, None)
