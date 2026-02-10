"""Test Resource Governor service."""

import uuid

import pytest

from aijailer.services.resource_service import ResourceGovernor, TenantQuotas


@pytest.mark.asyncio
async def test_record_and_calculate_cost():
    governor = ResourceGovernor()
    tenant_id = uuid.uuid4()
    cell_id = uuid.uuid4()

    await governor.record_usage(
        cell_id=cell_id,
        tenant_id=tenant_id,
        cpu_seconds=1000.0,
        memory_gb_seconds=500.0,
        network_egress_bytes=1_073_741_824,  # 1 GB
    )

    cost = governor.calculate_cell_cost(cell_id)
    assert cost > 0.0


@pytest.mark.asyncio
async def test_tenant_usage_summary():
    governor = ResourceGovernor()
    tenant_id = uuid.uuid4()

    for i in range(3):
        cell_id = uuid.uuid4()
        await governor.record_usage(
            cell_id=cell_id,
            tenant_id=tenant_id,
            cpu_seconds=100.0,
            api_calls=10,
        )

    summary = governor.get_tenant_usage_summary(tenant_id)
    assert summary["cpu_core_seconds"] == 300.0
    assert summary["api_calls"] == 30
    assert summary["cell_count"] == 3


@pytest.mark.asyncio
async def test_spending_alerts():
    governor = ResourceGovernor()
    tenant_id = uuid.uuid4()

    governor.set_tenant_quotas(
        tenant_id,
        TenantQuotas(spending_cap_cents=100),  # $1.00 cap
    )

    cell_id = uuid.uuid4()
    # Record enough usage to trigger alerts
    await governor.record_usage(
        cell_id=cell_id,
        tenant_id=tenant_id,
        cpu_seconds=10_000_000.0,
        memory_gb_seconds=10_000_000.0,
        network_egress_bytes=100_000_000_000,
    )

    alerts = governor.get_alerts(tenant_id)
    assert len(alerts) > 0
