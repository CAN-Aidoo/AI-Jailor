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
    s = get_settings()
    monkeypatch.setattr(s, "snapshot_dir", str(tmp_path / "snaps"))
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
