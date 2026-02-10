"""Execution API routes."""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.execution import (
    ExecuteRequest,
    ExecuteScriptRequest,
    ExecutionListItem,
    ExecutionResponse,
    ResourceUsageInfo,
)
from aijailer.services.execution_service import ExecutionService

router = APIRouter(prefix="/v1/cells/{cell_id}", tags=["Execution"])


@router.post("/exec", response_model=ApiResponse[ExecutionResponse])
async def execute_command(
    cell_id: uuid.UUID,
    body: ExecuteRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = ExecutionService(db)
    execution = await svc.execute_command(
        cell_id=cell_id,
        tenant_id=auth.tenant_id,
        command=body.command,
        timeout_seconds=body.timeout_seconds,
        user=body.user,
        working_directory=body.working_directory,
        environment=body.environment,
        api_key_id=auth.api_key_id,
    )
    return ApiResponse(
        data=ExecutionResponse(
            execution_id=execution.id,
            exit_code=execution.exit_code or 0,
            stdout=execution.stdout or "",
            stderr=execution.stderr or "",
            duration_ms=execution.duration_ms or 0,
            resource_usage=ResourceUsageInfo(
                cpu_ms=execution.cpu_ms,
                memory_peak_mb=execution.memory_peak_mb,
            ),
        )
    )


@router.post("/exec/script", response_model=ApiResponse[ExecutionResponse])
async def execute_script(
    cell_id: uuid.UUID,
    body: ExecuteScriptRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = ExecutionService(db)
    execution = await svc.execute_script(
        cell_id=cell_id,
        tenant_id=auth.tenant_id,
        script=body.script,
        interpreter=body.interpreter,
        timeout_seconds=body.timeout_seconds,
        api_key_id=auth.api_key_id,
    )
    return ApiResponse(
        data=ExecutionResponse(
            execution_id=execution.id,
            exit_code=execution.exit_code or 0,
            stdout=execution.stdout or "",
            stderr=execution.stderr or "",
            duration_ms=execution.duration_ms or 0,
            resource_usage=ResourceUsageInfo(
                cpu_ms=execution.cpu_ms,
                memory_peak_mb=execution.memory_peak_mb,
            ),
        )
    )


@router.post("/exec/cancel/{execution_id}", status_code=204)
async def cancel_execution(
    cell_id: uuid.UUID,
    execution_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = ExecutionService(db)
    await svc.cancel_execution(cell_id, execution_id, auth.tenant_id)


@router.get("/executions", response_model=ApiResponse[list[ExecutionListItem]])
async def list_executions(
    cell_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=200),
    cursor: Optional[str] = Query(None, description="Pagination cursor (ISO timestamp)"),
):
    """List execution history for a cell."""
    svc = ExecutionService(db)
    executions = await svc.list_executions(
        cell_id=cell_id,
        tenant_id=auth.tenant_id,
        status=status,
        limit=limit,
        cursor=cursor,
    )
    items = [
        ExecutionListItem(
            execution_id=e.id,
            cell_id=e.cell_id,
            status=e.status,
            command=e.command[:200] if e.command else "",
            exit_code=e.exit_code,
            duration_ms=e.duration_ms,
            started_at=e.started_at,
            completed_at=e.completed_at,
        )
        for e in executions
    ]
    return ApiResponse(data=items)
