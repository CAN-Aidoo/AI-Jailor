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


async def _filled(n=5):
    svc = AuditService()
    t, c = uuid.uuid4(), uuid.uuid4()
    for i in range(n):
        await svc.record_event(t, c, EventType.EXECUTION, details={"i": i})
    return svc, t, c


@pytest.mark.asyncio
async def test_detail_tamper_detected():
    svc, t, c = await _filled()
    svc._events[2].details["i"] = 999
    assert not await svc.verify_chain(t, c)


@pytest.mark.asyncio
async def test_tail_truncation_detected_via_signed_checkpoint():
    svc, t, c = await _filled()
    await svc.checkpoint(t, c)
    svc._events.pop()
    assert not await svc.verify_chain(t, c)


@pytest.mark.asyncio
async def test_full_rebuild_detected_via_checkpoint():
    svc, t, c = await _filled()
    await svc.checkpoint(t, c)
    svc._events[1].details["i"] = 42
    # attacker recomputes the whole chain consistently
    prev = ""
    for e in svc._events:
        e.previous_hash = prev
        e.event_hash = svc._compute_hash(e, prev)
        prev = e.event_hash
    assert not await svc.verify_chain(t, c)


@pytest.mark.asyncio
async def test_clean_chain_with_checkpoint_verifies():
    svc, t, c = await _filled()
    await svc.checkpoint(t, c)
    await svc.record_event(t, c, EventType.EXECUTION, details={"i": 99})
    assert await svc.verify_chain(t, c)
