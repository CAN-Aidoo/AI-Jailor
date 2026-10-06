"""Cell creation resolves and compiles the security policy (previously effective_policy was never set,
so every cell silently had no egress at all)."""

import uuid

import pytest

from aijailer.core.exceptions import PolicyNotFoundError
from aijailer.models.policy import SecurityPolicy
from aijailer.models.tenant import Tenant
from aijailer.services.policy_service import PolicyService
from tests.services.test_cell_service_network import env, make  # noqa: F401

NET = {"default": "deny", "egress": [{"action": "allow", "destinations": [{"domain": "api.github.com"}],
                                      "ports": [443]}]}


async def new_policy(db, tenant_id, **kw):
    p = await PolicyService(db).create_policy(tenant_id, "p", network_policy=NET)
    for k, v in kw.items():
        setattr(p, k, v)
    await db.flush()
    return p


@pytest.mark.asyncio
async def test_chosen_policy_is_compiled_into_the_cell(env, db_session):  # noqa: F811
    svc, eng, net, tenant, log = env
    p = await new_policy(db_session, tenant.id)
    cell = await svc.create_cell(
        tenant_id=tenant.id, name="c", image="i", vcpus=1, memory_mb=256, disk_mb=512,
        network_bandwidth_mbps=10, security_policy_id=p.id, environment={}, tags={})
    assert cell.effective_policy["network"] == NET
    assert net.policies[cell.id] == NET            # and that is what the broker was built from


@pytest.mark.asyncio
async def test_no_policy_chosen_means_default_deny_not_an_error(env):  # noqa: F811
    svc, eng, net, tenant, log = env
    cell = await make(svc, tenant)                 # helper passes security_policy_id=tenant.id
    assert cell.effective_policy is None and net.policies[cell.id] is None


@pytest.mark.asyncio
async def test_requested_but_unusable_policies_fail_loudly(env, db_session):  # noqa: F811
    svc, eng, net, tenant, log = env
    other = Tenant(name="o", slug=f"o-{uuid.uuid4().hex[:6]}", status="active", tier="pro")
    db_session.add(other)
    await db_session.commit()
    theirs = await new_policy(db_session, other.id)
    deprecated = await new_policy(db_session, tenant.id, status="deprecated")
    for pid in (uuid.uuid4(), theirs.id, deprecated.id):
        with pytest.raises(PolicyNotFoundError):
            await svc.create_cell(
                tenant_id=tenant.id, name="c", image="i", vcpus=1, memory_mb=256, disk_mb=512,
                network_bandwidth_mbps=10, security_policy_id=pid, environment={}, tags={})


@pytest.mark.asyncio
async def test_platform_wide_policy_is_usable(env, db_session):  # noqa: F811
    svc, eng, net, tenant, log = env
    p = await new_policy(db_session, None)
    p.tenant_id = None
    await db_session.flush()
    cell = await svc.create_cell(
        tenant_id=tenant.id, name="c", image="i", vcpus=1, memory_mb=256, disk_mb=512,
        network_bandwidth_mbps=10, security_policy_id=p.id, environment={}, tags={})
    assert cell.effective_policy["network"] == NET
