"""Pydantic schemas for Audit API endpoints."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class AuditEventResponse(BaseModel):
    id: uuid.UUID
    cell_id: uuid.UUID
    event_type: str
    severity: str
    timestamp: datetime
    details: dict[str, Any] = Field(default_factory=dict)


class AuditEventListResponse(BaseModel):
    events: list[AuditEventResponse]
    next_cursor: str | None = None


class UsageTotals(BaseModel):
    cpu_core_seconds: float = 0.0
    memory_gb_seconds: float = 0.0
    storage_gb_hours: float = 0.0
    network_egress_gb: float = 0.0
    api_calls: int = 0
    cell_count: int = 0
    snapshot_count: int = 0
    estimated_cost_usd: float = 0.0


class UsagePeriod(BaseModel):
    start: datetime
    end: datetime


class UsageResponse(BaseModel):
    period: UsagePeriod
    totals: UsageTotals
