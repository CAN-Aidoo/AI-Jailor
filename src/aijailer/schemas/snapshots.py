"""Pydantic schemas for Snapshot API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from aijailer.schemas.cells import ResourcesRequest


class CreateSnapshotRequest(BaseModel):
    name: str | None = None
    description: str | None = None


class RestoreRequest(BaseModel):
    snapshot_id: str


class CloneRequest(BaseModel):
    name: str | None = None
    resources: ResourcesRequest | None = None
    security_policy_id: str | None = None


class SnapshotResponse(BaseModel):
    id: uuid.UUID
    cell_id: uuid.UUID
    name: str | None
    description: str | None = None
    status: str
    total_size_bytes: int | None = None
    created_at: datetime
    completed_at: datetime | None = None

    model_config = {"from_attributes": True}
