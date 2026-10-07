"""Snapshot API routes."""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.core.exceptions import AiJailerError
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.snapshots import (
    CloneRequest,
    CreateSnapshotRequest,
    RestoreRequest,
    SnapshotResponse,
)
from aijailer.services.snapshot_service import SnapshotService

router = APIRouter(tags=["Snapshots"])


def _view(s) -> SnapshotResponse:
    return SnapshotResponse(
        id=s.id, cell_id=s.cell_id, name=s.name, description=s.description, status=s.status,
        total_size_bytes=s.total_size_bytes, created_at=s.created_at, completed_at=s.completed_at)


@router.post(
    "/v1/cells/{cell_id}/snapshots",
    status_code=202,
    response_model=ApiResponse[SnapshotResponse],
)
async def create_snapshot(
    cell_id: uuid.UUID,
    body: CreateSnapshotRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """Snapshot a running/paused cell (memory + VM state + disk). The guest is paused briefly
    and resumed. Backends without snapshot support answer 501."""
    snap = await SnapshotService(db).create_snapshot(
        cell_id, auth.tenant_id, body.name, body.description)
    return ApiResponse(data=_view(snap))


@router.get(
    "/v1/cells/{cell_id}/snapshots",
    response_model=ApiResponse[list[SnapshotResponse]],
)
async def list_snapshots(
    cell_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    from sqlalchemy import select

    from aijailer.models.snapshot import Snapshot

    result = await db.execute(
        select(Snapshot).where(Snapshot.cell_id == cell_id, Snapshot.tenant_id == auth.tenant_id)
        .order_by(Snapshot.created_at))
    return ApiResponse(data=[_view(s) for s in result.scalars().all()])


@router.post("/v1/cells/{cell_id}/restore", response_model=ApiResponse[dict])
async def restore_cell(
    cell_id: uuid.UUID,
    body: RestoreRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """Restore the cell from one of ITS snapshots. Destructive: the cell's current VM is
    replaced. Keeps the cell's current security policy and bandwidth. 409 if the snapshot's
    guest address is held by another cell."""
    try:
        snapshot_id = uuid.UUID(body.snapshot_id)
    except ValueError:
        raise AiJailerError("snapshot_id is not a valid id", code="snapshot_not_found") from None
    cell = await SnapshotService(db).restore_cell(cell_id, auth.tenant_id, snapshot_id)
    return ApiResponse(data={"cell_id": str(cell.id), "snapshot_id": str(snapshot_id),
                             "status": cell.status})


@router.post(
    "/v1/snapshots/{snapshot_id}/clone",
    status_code=201,
    response_model=ApiResponse[dict],
)
async def clone_from_snapshot(
    snapshot_id: uuid.UUID,
    body: CloneRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """New cell from a snapshot. Keeps the snapshot's resources (``resources`` is rejected) and
    its guest address, so it works only while no other cell holds that address."""
    policy = None
    if body.security_policy_id:
        try:
            policy = uuid.UUID(body.security_policy_id)
        except ValueError:
            raise AiJailerError("security_policy_id is not a valid id",
                                code="policy_not_found") from None
    cell = await SnapshotService(db).clone_snapshot(
        snapshot_id, auth.tenant_id, body.name, policy,
        resources_requested=body.resources is not None)
    return ApiResponse(data={"id": str(cell.id), "cell_id": str(cell.id),
                             "snapshot_id": str(snapshot_id), "name": cell.name,
                             "status": cell.status})
