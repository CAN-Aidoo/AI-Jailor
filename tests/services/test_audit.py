"""Test audit service."""

import uuid

import pytest

from aijailer.models.audit import EventType, Severity
from aijailer.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_record_and_query_events():
    svc = AuditService()
    tenant_id = uuid.uuid4()
    cell_id = uuid.uuid4()

    await svc.record_event(
        tenant_id=tenant_id,
        cell_id=cell_id,
        event_type=EventType.EXECUTION,
        severity=Severity.INFO,
        details={"command": "echo hello", "exit_code": 0},
    )

    events = await svc.query_events(tenant_id=tenant_id, cell_id=cell_id)
    assert len(events) == 1
    assert events[0].event_type == EventType.EXECUTION
    assert events[0].details["command"] == "echo hello"


@pytest.mark.asyncio
async def test_hash_chain_integrity():
    svc = AuditService()
    tenant_id = uuid.uuid4()
    cell_id = uuid.uuid4()

    for i in range(5):
        await svc.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.EXECUTION,
            details={"command": f"cmd_{i}"},
        )

    assert await svc.verify_chain(tenant_id, cell_id) is True


@pytest.mark.asyncio
async def test_query_filter_by_event_type():
    svc = AuditService()
    tenant_id = uuid.uuid4()
    cell_id = uuid.uuid4()

    await svc.record_event(tenant_id=tenant_id, cell_id=cell_id, event_type=EventType.EXECUTION)
    await svc.record_event(tenant_id=tenant_id, cell_id=cell_id, event_type=EventType.NETWORK)
    await svc.record_event(tenant_id=tenant_id, cell_id=cell_id, event_type=EventType.EXECUTION)

    events = await svc.query_events(
        tenant_id=tenant_id, cell_id=cell_id, event_type="execution"
    )
    assert len(events) == 2
