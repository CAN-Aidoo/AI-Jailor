"""Audit log query API routes."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.schemas.audit import AuditEventListResponse, AuditEventResponse
from aijailer.schemas.common import ApiResponse
from aijailer.services.audit_service import get_audit_service

router = APIRouter(prefix="/v1/audit", tags=["Audit"])


@router.get("/events", response_model=ApiResponse[AuditEventListResponse])
async def query_audit_events(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    cell_id: uuid.UUID | None = Query(None),
    event_type: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    cursor: str | None = Query(None),
    auth: AuthContext = Depends(authenticate),
):
    svc = get_audit_service()
    events = await svc.query_events(
        tenant_id=auth.tenant_id,
        cell_id=cell_id,
        event_type=event_type,
        severity=severity,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
    )
    return ApiResponse(
        data=AuditEventListResponse(
            events=[
                AuditEventResponse(
                    id=e.id,
                    cell_id=e.cell_id,
                    event_type=e.event_type,
                    severity=e.severity,
                    timestamp=e.timestamp,
                    details=e.details,
                )
                for e in events
            ]
        )
    )
