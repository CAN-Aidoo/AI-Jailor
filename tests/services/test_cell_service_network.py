"""CellService x network enforcement (fake engine that attaches a NIC)."""

import ipaddress
import uuid

import pytest

from aijailer.engine.microvm import MicroVMEngine, VMInfo, VMStatus
from aijailer.models.tenant import Tenant
from aijailer.netpolicy import runtime
from aijailer.netpolicy.cell_network import Provisioned
from aijailer.netpolicy.nft import CellNet, LinkInfo
from aijailer.netpolicy.shaping import Bandwidth
from aijailer.services import cell_service
from aijailer.services.cell_service import CellService


class NicEngine(MicroVMEngine):
    isolation = "hardware-kvm"
    needs_network = True

    def __init__(self, log):
        self.log, self.configs, self.fail_create = log, {}, False

    async def create_vm(self, config):
        self.log.append("vm:create")
        if self.fail_create:
            raise RuntimeError("boot failed")
        self.configs[config.cell_id] = config
        return VMInfo(config.cell_id, VMStatus.RUNNING, internal_ip=config.network.guest_ip)

    async def start_vm(self, cell_id):
        self.log.append("vm:start")
        return VMInfo(cell_id, VMStatus.RUNNING)

    async def stop_vm(self, cell_id, grace_period=10):
        self.log.append("vm:stop")

    async def pause_vm(self, cell_id):
        self.log.append("vm:pause")

    async def resume_vm(self, cell_id):
        self.log.append("vm:resume")

    async def destroy_vm(self, cell_id):
        self.log.append("vm:destroy")

    async def exec_command(self, *a, **k):
        raise NotImplementedError

    async def get_vm_info(self, cell_id):
        return VMInfo(cell_id, VMStatus.RUNNING)


class FakeCellNetwork:
    def __init__(self, log):
        self.log, self.live, self.fail = log, set(), False
        self.policies = {}

    async def provision(self, cell_id, tenant_id, policy, bandwidth=None):
        self.bandwidths = getattr(self, "bandwidths", {})
        self.bandwidths[cell_id] = bandwidth
        self.log.append("net:provision")
        if self.fail:
            raise OSError("nft unavailable")
        self.live.add(cell_id)
        self.policies[cell_id] = policy
        net = CellNet(cell_id, "aj" + cell_id.hex[:12], ipaddress.IPv4Address("10.200.0.1"),
                      ipaddress.IPv4Address("10.200.0.2"), 30, 3128)
        link = LinkInfo("tap0", f"/run/netns/{net.ifname}")
        return Provisioned(net, link, "http://10.200.0.1:3128",
                           {"http_proxy": "http://10.200.0.1:3128"})

    async def set_bandwidth(self, cell_id, bw):
        self.log.append("net:set_bandwidth")
        if cell_id not in self.live:
            raise LookupError("no network")
        if getattr(self, "fail_shape", False):
            raise OSError("tbf boom")
        self.actual = getattr(self, "actual", {})
        self.actual[cell_id] = bw

    async def get_bandwidth(self, cell_id):
        return getattr(self, "actual", {}).get(cell_id)

    async def deprovision(self, cell_id):
        self.log.append("net:deprovision")
        self.live.discard(cell_id)
        return []


@pytest.fixture
async def env(db_session, monkeypatch):
    log = []
    eng = NicEngine(log)
    monkeypatch.setattr(cell_service, "get_microvm_engine", lambda: eng)
    net = FakeCellNetwork(log)
    tenant = Tenant(name="t", slug=f"t-{uuid.uuid4().hex[:6]}", status="active", tier="pro",
                    max_concurrent_cells=10)
    db_session.add(tenant)
    await db_session.commit()
    svc = CellService(db_session, network=net)
    return svc, eng, net, tenant, log


async def make(svc, tenant, **kw):
    return await svc.create_cell(
        tenant_id=tenant.id, name="c", image="base-python", vcpus=1, memory_mb=256, disk_mb=512,
        network_bandwidth_mbps=10, security_policy_id=tenant.id, environment={"A": "1"},
        tags={}, **kw)


@pytest.mark.asyncio
async def test_create_builds_network_before_vm_and_passes_it_through(env):
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    assert log[:2] == ["net:provision", "vm:create"] and cell.status == "running"
    cfg = eng.configs[cell.id]
    assert cfg.network.guest_ip == "10.200.0.2" and cfg.network.host_ip == "10.200.0.1"
    assert cfg.network.tap_name == "tap0"  # TAP lives inside the cell's own namespace
    assert cfg.network.netns_path == f"/run/netns/aj{cell.id.hex[:12]}"
    assert cfg.environment["http_proxy"] == "http://10.200.0.1:3128" and cfg.environment["A"] == "1"
    assert cell.internal_ip == "10.200.0.2"
    # the cell's configured network_bandwidth_mbps (10 here) becomes symmetric shaping
    assert net.bandwidths[cell.id] == Bandwidth(10_000, 10_000)


@pytest.mark.asyncio
async def test_network_failure_means_no_vm_and_error_status(env):
    svc, eng, net, tenant, log = env
    net.fail = True
    cell = await make(svc, tenant)
    assert cell.status == "error" and "nft unavailable" in cell.error_message
    assert "vm:create" not in log  # fail closed: never boot without the firewall
    assert net.live == set()


@pytest.mark.asyncio
async def test_vm_boot_failure_tears_network_back_down(env):
    svc, eng, net, tenant, log = env
    eng.fail_create = True
    cell = await make(svc, tenant)
    assert cell.status == "error" and net.live == set()
    assert log == ["net:provision", "vm:create", "vm:destroy", "net:deprovision"]


@pytest.mark.asyncio
async def test_stop_and_destroy_revoke_network(env):
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    await svc.stop_cell(cell.id, tenant.id)
    assert net.live == set()
    await svc.start_cell(cell.id, tenant.id)  # rebuilds network, then starts VM
    assert net.live == {cell.id} and log[-2:] == ["net:provision", "vm:start"]
    await svc.destroy_cell(cell.id, tenant.id)
    assert net.live == set() and log[-2:] == ["vm:destroy", "net:deprovision"]


@pytest.mark.asyncio
async def test_destroy_revokes_network_even_if_vm_destroy_raises(env):
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)

    async def boom(cell_id):
        raise RuntimeError("vmm wedged")
    eng.destroy_vm = boom
    with pytest.raises(RuntimeError):
        await svc.destroy_cell(cell.id, tenant.id)
    assert net.live == set()


@pytest.mark.asyncio
async def test_pause_resume_keep_network(env):
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    await svc.pause_cell(cell.id, tenant.id)
    await svc.resume_cell(cell.id, tenant.id)
    assert net.live == {cell.id}


def test_enforcement_mode_is_fail_closed(monkeypatch):
    class NoNic(NicEngine):
        needs_network = False
    nic = NicEngine([])
    monkeypatch.setenv("NETWORK_ENFORCEMENT", "off")
    with pytest.raises(RuntimeError, match="not allowed"):
        runtime.network_required(nic)
    monkeypatch.setenv("NETWORK_ENFORCEMENT", "required")
    with pytest.raises(RuntimeError, match="cannot be firewalled"):
        runtime.network_required(NoNic([]))
    monkeypatch.setenv("NETWORK_ENFORCEMENT", "auto")
    assert runtime.network_required(nic) is True
    assert runtime.network_required(NoNic([])) is False
    monkeypatch.setenv("NETWORK_ENFORCEMENT", "bogus")
    with pytest.raises(ValueError):
        runtime.network_required(nic)
