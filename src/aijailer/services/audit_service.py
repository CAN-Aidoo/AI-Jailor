"""Audit event collection and query service.

In production, events flow through Kafka to ClickHouse. For the MVP,
events are stored in an in-memory list with optional PostgreSQL fallback.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from aijailer.models.audit import AuditEvent, EventType, Severity


class AuditService:
    """In-memory audit event store for MVP. Production uses ClickHouse."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []
        self._last_hash: dict[str, str] = {}  # per (tenant_id, cell_id) chain

    def _compute_hash(self, event: AuditEvent, previous_hash: str) -> str:
        """Compute tamper-evident hash for an event."""
        data = f"{event.id}{event.tenant_id}{event.cell_id}{event.event_type}{event.timestamp}{previous_hash}"
        return hashlib.sha256(data.encode()).hexdigest()

    async def record_event(
        self,
        tenant_id: uuid.UUID,
        cell_id: uuid.UUID,
        event_type: EventType,
        severity: Severity = Severity.INFO,
        details: dict | None = None,
        source_ip: str | None = None,
        api_key_id: uuid.UUID | None = None,
        request_id: str | None = None,
    ) -> AuditEvent:
        """Record a new audit event with hash chain integrity."""
        chain_key = f"{tenant_id}:{cell_id}"
        previous_hash = self._last_hash.get(chain_key, "")

        event = AuditEvent(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=event_type,
            severity=severity,
            details=details or {},
            source_ip=source_ip,
            api_key_id=api_key_id,
            request_id=request_id,
            previous_hash=previous_hash,
        )
        event.event_hash = self._compute_hash(event, previous_hash)
        self._last_hash[chain_key] = event.event_hash

        self._events.append(event)
        return event

    async def query_events(
        self,
        tenant_id: uuid.UUID,
        cell_id: uuid.UUID | None = None,
        event_type: str | None = None,
        severity: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Query audit events with filters."""
        results = []
        for event in reversed(self._events):
            if event.tenant_id != tenant_id:
                continue
            if cell_id and event.cell_id != cell_id:
                continue
            if event_type and event.event_type != event_type:
                continue
            if severity and event.severity != severity:
                continue
            if start_time and event.timestamp < start_time:
                continue
            if end_time and event.timestamp > end_time:
                continue
            results.append(event)
            if len(results) >= limit:
                break
        return results

    async def verify_chain(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> bool:
        """Verify hash chain integrity for a (tenant, cell) pair."""
        chain_events = [
            e
            for e in self._events
            if e.tenant_id == tenant_id and e.cell_id == cell_id
        ]
        prev_hash = ""
        for event in chain_events:
            expected = self._compute_hash(event, prev_hash)
            if event.event_hash != expected:
                return False
            prev_hash = event.event_hash
        return True


# Singleton for MVP
_audit_service: AuditService | None = None


def get_audit_service() -> AuditService:
    global _audit_service
    if _audit_service is None:
        _audit_service = AuditService()
    return _audit_service
