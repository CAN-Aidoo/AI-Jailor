"""Snapshot API routes."""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.snapshots import (
    CloneRequest,
    CreateSnapshotRequest,
    RestoreRequest,
    SnapshotResponse,
)

router = APIRouter(tags=["Snapshots"])


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
    """Create a snapshot of a cell.

    In production:
    1. Pause VM via Firecracker API
    2. Dump memory state
    3. Snapshot overlay filesystem + persistent volume
    4. Upload to object storage
    5. Resume VM
    """
    from datetime import datetime, timezone

    from aijailer.models.snapshot import Snapshot

    snapshot = Snapshot(
        tenant_id=auth.tenant_id,
        cell_id=cell_id,
        name=body.name,
        description=body.description,
        status="creating",
        cell_config={},
    )
    db.add(snapshot)
    await db.flush()

    # MVP: Immediately mark as available
    snapshot.status = "available"
    snapshot.completed_at = datetime.now(timezone.utc)

    return ApiResponse(
        data=SnapshotResponse(
            id=snapshot.id,
            cell_id=snapshot.cell_id,
            name=snapshot.name,
            description=snapshot.description,
            status=snapshot.status,
            created_at=snapshot.created_at,
            completed_at=snapshot.completed_at,
        )
    )


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
        select(Snapshot).where(
            Snapshot.cell_id == cell_id, Snapshot.tenant_id == auth.tenant_id
        )
    )
    snapshots = result.scalars().all()
    return ApiResponse(
        data=[
            SnapshotResponse(
                id=s.id,
                cell_id=s.cell_id,
                name=s.name,
                status=s.status,
                created_at=s.created_at,
                completed_at=s.completed_at,
            )
            for s in snapshots
        ]
    )


@router.post("/v1/cells/{cell_id}/restore", response_model=ApiResponse[dict])
async def restore_cell(
    cell_id: uuid.UUID,
    body: RestoreRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    """Restore a cell from a snapshot."""
    return ApiResponse(
        data={
            "cell_id": str(cell_id),
            "snapshot_id": body.snapshot_id,
            "status": "restoring",
        }
    )


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
    """Create a new cell from a snapshot."""
    return ApiResponse(
        data={
            "snapshot_id": str(snapshot_id),
            "name": body.name,
            "status": "creating",
        }
    )
