"""Audit event collection and query service.

In production, events flow through Kafka to ClickHouse. For the MVP,
events are stored in an in-memory list with optional PostgreSQL fallback.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from aijailer.models.audit import AuditEvent, EventType, Severity
from aijailer.services.attestation import (
    Ed25519Signer,
    Signer,
    canonical_json,
    make_statement,
    sign_statement,
    verify_envelope,
)


class AuditService:
    """In-memory audit event store for MVP. Production uses ClickHouse."""

    durable = False   # history is lost on restart; endpoints that serve it must say so

    def __init__(self, signer: Signer | None = None) -> None:
        self._events: list[AuditEvent] = []
        self._last_hash: dict[str, str] = {}  # per (tenant_id, cell_id) chain
        self._signer = signer or Ed25519Signer.generate()
        self._checkpoints: dict[str, list[dict]] = {}

    @property
    def public_key(self):
        return self._signer.public_key

    @staticmethod
    def _compute_hash(event: AuditEvent, previous_hash: str) -> str:
        """Hash EVERY field (details, severity, actor...) so any edit is detectable."""
        body = event.model_dump(mode="json", exclude={"event_hash"})
        body["previous_hash"] = previous_hash
        return hashlib.sha256(canonical_json(body)).hexdigest()

    def checkpoint(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> dict:
        """Sign (head hash, length) so deletion of recent events is detectable.

        A bare hash chain cannot detect truncation or a full rebuild by someone
        with write access; a signed checkpoint held elsewhere (like a
        transparency-log signed tree head) can.
        """
        key = f"{tenant_id}:{cell_id}"
        n = sum(1 for e in self._events if e.tenant_id == tenant_id and e.cell_id == cell_id)
        statement = make_statement(
            f"audit-chain/{key}", self._last_hash.get(key, "").ljust(64, "0"),
            "https://aijailer.dev/attestation/audit-checkpoint/v1",
            {"chain": key, "length": n, "head": self._last_hash.get(key, "")},
        )
        cp = sign_statement(statement, self._signer)
        self._checkpoints.setdefault(key, []).append(cp)
        return cp

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
        """Verify chain integrity AND consistency with every signed checkpoint."""
        key = f"{tenant_id}:{cell_id}"
        chain_events = [
            e for e in self._events if e.tenant_id == tenant_id and e.cell_id == cell_id
        ]
        prev_hash = ""
        hashes: list[str] = []
        for event in chain_events:
            if event.previous_hash != prev_hash:
                return False
            if event.event_hash != self._compute_hash(event, prev_hash):
                return False
            prev_hash = event.event_hash
            hashes.append(prev_hash)
        for cp in self._checkpoints.get(key, []):
            stmt = verify_envelope(cp, self.public_key)
            if stmt is None:
                return False
            pred = stmt["predicate"]
            n = pred["length"]
            if n > len(hashes):
                return False  # events were deleted after the checkpoint
            if n and hashes[n - 1] != pred["head"]:
                return False  # history was rewritten
        return True


# Singleton for MVP
_audit_service: AuditService | None = None


def get_audit_service() -> AuditService:
    global _audit_service
    if _audit_service is None:
        _audit_service = AuditService()
    return _audit_service
