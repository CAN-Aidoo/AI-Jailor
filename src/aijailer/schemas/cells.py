"""Pydantic schemas for Cell API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ResourcesRequest(BaseModel):
    vcpus: int = Field(default=1, ge=1, le=32)
    memory_mb: int = Field(default=512, ge=128, le=65536)
    disk_mb: int = Field(default=2048, ge=256, le=1048576)
    network_bandwidth_mbps: int = Field(default=100, ge=1, le=10000)


class PersistentVolumeRequest(BaseModel):
    size_mb: int = Field(ge=128, le=1048576)
    mount_path: str = "/data"


class CreateCellRequest(BaseModel):
    name: str | None = None
    image: str = "base-python"
    resources: ResourcesRequest = Field(default_factory=ResourcesRequest)
    security_policy_id: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    persistent_volume: PersistentVolumeRequest | None = None
    tags: dict[str, str] = Field(default_factory=dict)
    auto_start: bool = True
    warm_pool: bool = False


class StopCellRequest(BaseModel):
    grace_period_seconds: int = Field(default=10, ge=1, le=300)


class NetworkInfo(BaseModel):
    internal_ip: str | None = None


class PersistentVolumeInfo(BaseModel):
    id: str
    size_mb: int
    mount_path: str


class CellResponse(BaseModel):
    id: uuid.UUID
    name: str | None
    status: str
    image: str
    resources: ResourcesRequest
    security_policy_id: uuid.UUID
    persistent_volume: PersistentVolumeInfo | None = None
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    tags: dict[str, str] = Field(default_factory=dict)
    created_at: datetime
    started_at: datetime | None = None
    paused_at: datetime | None = None
    stopped_at: datetime | None = None

    model_config = {"from_attributes": True}


class CellListResponse(BaseModel):
    cells: list[CellResponse]
    next_cursor: str | None = None
