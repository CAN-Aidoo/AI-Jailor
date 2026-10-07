"""CellService bandwidth change: ordering, persistence, states, validation, audit."""

import uuid

import pytest

from aijailer.core.exceptions import AiJailerError, CellNotFoundError, InvalidStateTransitionError
from aijailer.models.audit import EventType
from aijailer.netpolicy.shaping import Bandwidth, effective_bandwidth
from tests.services.test_cell_service_network import env, make  # noqa: F401  (fixtures)


@pytest.mark.asyncio
async def test_live_change_applies_to_kernel_then_persists(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)                        # created with 10 Mbit symmetric
    log.clear()
    v = await svc.set_bandwidth(cell.id, tenant.id, 4000, 16000)
    assert log == ["net:set_bandwidth"]
    assert v.source == "override" and v.configured == Bandwidth(4000, 16000)
    assert v.enforced == Bandwidth(4000, 16000)           # read back from the (fake) kernel
    assert cell.bandwidth_override == {"down_kbit": 4000, "up_kbit": 16000}
    assert (await svc.get_bandwidth(cell.id, tenant.id)).enforced == Bandwidth(4000, 16000)


@pytest.mark.asyncio
async def test_kernel_failure_persists_nothing(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    net.fail_shape = True
    with pytest.raises(AiJailerError) as e:
        await svc.set_bandwidth(cell.id, tenant.id, 1000, 1000)
    assert e.value.code == "bandwidth_apply_failed" and "tbf boom" not in e.value.message
    assert cell.bandwidth_override is None                # DB unchanged: no lie about the limit


@pytest.mark.asyncio
async def test_missing_network_is_reported_not_papered_over(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    net.live.clear()                                      # e.g. reconciler found it broken
    with pytest.raises(AiJailerError) as e:
        await svc.set_bandwidth(cell.id, tenant.id, 1000, 1000)
    assert e.value.code == "cell_network_unavailable" and cell.bandwidth_override is None


@pytest.mark.asyncio
async def test_stopped_cell_persists_and_override_applies_on_next_start(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    await svc.stop_cell(cell.id, tenant.id)
    log.clear()
    v = await svc.set_bandwidth(cell.id, tenant.id, 2000, 3000)
    assert "net:set_bandwidth" not in log and v.enforced is None   # nothing to apply it to yet
    await svc.start_cell(cell.id, tenant.id)
    assert net.bandwidths[cell.id] == Bandwidth(2000, 3000)         # provisioning uses the override


@pytest.mark.asyncio
@pytest.mark.parametrize("down,up", [(63, 1000), (1000, 63), (0, 0), (-5, 1000),
                                     (10_000_001, 1000), (1000, 10_000_001),
                                     (1.5, 1000), ("1000", 1000), (True, 1000), (None, 1000)])
async def test_invalid_limits_rejected(env, down, up):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    with pytest.raises(AiJailerError) as e:
        await svc.set_bandwidth(cell.id, tenant.id, down, up)
    assert e.value.code == "invalid_bandwidth" and cell.bandwidth_override is None


@pytest.mark.asyncio
async def test_platform_cap_applies_to_change_and_create(env, monkeypatch):  # noqa: F811
    svc, eng, net, tenant, log = env
    monkeypatch.setenv("MAX_CELL_BANDWIDTH_MBPS", "100")
    cell = await make(svc, tenant)
    await svc.set_bandwidth(cell.id, tenant.id, 100_000, 100_000)           # exactly the cap
    with pytest.raises(AiJailerError, match="between"):
        await svc.set_bandwidth(cell.id, tenant.id, 100_001, 1000)
    with pytest.raises(AiJailerError) as e:                                 # create-time too
        await svc.create_cell(
            tenant_id=tenant.id, name="big", image="i", vcpus=1, memory_mb=256, disk_mb=512,
            network_bandwidth_mbps=500, security_policy_id=tenant.id, environment={}, tags={})
    assert e.value.code == "invalid_bandwidth"
    assert (await svc.get_bandwidth(cell.id, tenant.id)).max_kbit == 100_000


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["creating", "stopping", "destroying", "destroyed", "error"])
async def test_changes_refused_in_non_applicable_states(env, status):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    cell.status = status
    with pytest.raises(InvalidStateTransitionError):
        await svc.set_bandwidth(cell.id, tenant.id, 1000, 1000)
    assert cell.bandwidth_override is None


@pytest.mark.asyncio
async def test_reset_returns_to_symmetric_default(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    await svc.set_bandwidth(cell.id, tenant.id, 2000, 3000)
    v = await svc.reset_bandwidth(cell.id, tenant.id)
    assert v.source == "default" and v.configured == Bandwidth(10_000, 10_000)
    assert v.enforced == Bandwidth(10_000, 10_000) and cell.bandwidth_override is None


@pytest.mark.asyncio
async def test_audit_records_before_after_and_actor(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    actor = uuid.uuid4()
    await svc.set_bandwidth(cell.id, tenant.id, 2000, 3000, actor=actor)
    ev = [e for e in svc.audit._events if e.details.get("action") == "bandwidth_changed"][-1]
    assert ev.event_type == EventType.LIFECYCLE and ev.details["actor"] == str(actor)
    assert ev.details["from"] == {"down_kbit": 10_000, "up_kbit": 10_000}
    assert ev.details["to"] == {"down_kbit": 2000, "up_kbit": 3000} and ev.details["live"] is True


@pytest.mark.asyncio
async def test_other_tenants_cell_is_invisible(env, db_session):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)
    with pytest.raises(CellNotFoundError):
        await svc.set_bandwidth(cell.id, uuid.uuid4(), 1000, 1000)
    with pytest.raises(CellNotFoundError):
        await svc.get_bandwidth(cell.id, uuid.uuid4())


def test_effective_bandwidth_rules():
    assert effective_bandwidth(25, None) == Bandwidth(25_000, 25_000)
    assert effective_bandwidth(25, {}) == Bandwidth(25_000, 25_000)           # empty => default
    assert effective_bandwidth(25, {"down_kbit": 100, "up_kbit": 200}) == Bandwidth(100, 200)
    assert effective_bandwidth(0, None) == Bandwidth() == effective_bandwidth(None, None)
