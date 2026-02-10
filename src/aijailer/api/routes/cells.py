"""Cell lifecycle API routes."""

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.db.base import get_db
from aijailer.schemas.cells import (
    CellListResponse,
    CellResponse,
    CreateCellRequest,
    NetworkInfo,
    ResourcesRequest,
    StopCellRequest,
)
from aijailer.schemas.common import ApiResponse
from aijailer.services.cell_service import CellService

router = APIRouter(prefix="/v1/cells", tags=["Cells"])


def _cell_to_response(cell) -> CellResponse:
    return CellResponse(
        id=cell.id,
        name=cell.name,
        status=cell.status,
        image=cell.image,
        resources=ResourcesRequest(
            vcpus=cell.vcpus,
            memory_mb=cell.memory_mb,
            disk_mb=cell.disk_mb,
            network_bandwidth_mbps=cell.network_bandwidth_mbps,
        ),
        security_policy_id=cell.security_policy_id,
        network=NetworkInfo(internal_ip=str(cell.internal_ip) if cell.internal_ip else None),
        tags=cell.tags or {},
        created_at=cell.created_at,
        started_at=cell.started_at,
        paused_at=cell.paused_at,
        stopped_at=cell.stopped_at,
    )


@router.post("", status_code=201, response_model=ApiResponse[CellResponse])
async def create_cell(
    body: CreateCellRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    policy_id = uuid.UUID(body.security_policy_id) if body.security_policy_id else auth.tenant_id

    cell = await svc.create_cell(
        tenant_id=auth.tenant_id,
        name=body.name,
        image=body.image,
        vcpus=body.resources.vcpus,
        memory_mb=body.resources.memory_mb,
        disk_mb=body.resources.disk_mb,
        network_bandwidth_mbps=body.resources.network_bandwidth_mbps,
        security_policy_id=policy_id,
        environment=body.environment,
        tags=body.tags,
        auto_start=body.auto_start,
    )
    return ApiResponse(data=_cell_to_response(cell))


@router.get("", response_model=ApiResponse[CellListResponse])
async def list_cells(
    status: str | None = Query(None),
    tag: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    cursor: str | None = Query(None),
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    cells = await svc.list_cells(
        tenant_id=auth.tenant_id,
        status=status,
        limit=limit,
        cursor=cursor,
    )
    return ApiResponse(
        data=CellListResponse(cells=[_cell_to_response(c) for c in cells])
    )


@router.get("/{cell_id}", response_model=ApiResponse[CellResponse])
async def get_cell(
    cell_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    cell = await svc.get_cell(cell_id, auth.tenant_id)
    return ApiResponse(data=_cell_to_response(cell))


@router.post("/{cell_id}/start", response_model=ApiResponse[CellResponse])
async def start_cell(
    cell_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    cell = await svc.start_cell(cell_id, auth.tenant_id)
    return ApiResponse(data=_cell_to_response(cell))


@router.post("/{cell_id}/stop", response_model=ApiResponse[CellResponse])
async def stop_cell(
    cell_id: uuid.UUID,
    body: StopCellRequest | None = None,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    grace = body.grace_period_seconds if body else 10
    cell = await svc.stop_cell(cell_id, auth.tenant_id, grace)
    return ApiResponse(data=_cell_to_response(cell))


@router.post("/{cell_id}/pause", response_model=ApiResponse[CellResponse])
async def pause_cell(
    cell_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    cell = await svc.pause_cell(cell_id, auth.tenant_id)
    return ApiResponse(data=_cell_to_response(cell))


@router.post("/{cell_id}/resume", response_model=ApiResponse[CellResponse])
async def resume_cell(
    cell_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    cell = await svc.resume_cell(cell_id, auth.tenant_id)
    return ApiResponse(data=_cell_to_response(cell))


@router.delete("/{cell_id}", status_code=204)
async def destroy_cell(
    cell_id: uuid.UUID,
    destroy_persistent: bool = Query(False),
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = CellService(db)
    await svc.destroy_cell(cell_id, auth.tenant_id, destroy_persistent)
