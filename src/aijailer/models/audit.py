"""Audit event models (in-memory representation; stored in ClickHouse in production)."""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class EventType(str, Enum):
    EXECUTION = "execution"
    FILE_ACCESS = "file_access"
    NETWORK = "network"
    LIFECYCLE = "lifecycle"
    POLICY_VIOLATION = "policy_violation"
    API_CALL = "api_call"
    RESOURCE_ALERT = "resource_alert"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AuditEvent(BaseModel):
    """Audit event — stored in ClickHouse for analytics, represented here as Pydantic model."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID
    cell_id: uuid.UUID
    event_type: EventType
    severity: Severity = Severity.INFO
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    details: dict = Field(default_factory=dict)
    source_ip: str | None = None
    api_key_id: uuid.UUID | None = None
    request_id: str | None = None
    previous_hash: str = ""
    event_hash: str = ""
