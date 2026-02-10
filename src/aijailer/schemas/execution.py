"""Pydantic schemas for Execution API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ExecuteRequest(BaseModel):
    command: str
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    user: str = "agent"
    working_directory: str | None = None
    environment: dict[str, str] = Field(default_factory=dict)
    stream: bool = False


class ExecuteScriptRequest(BaseModel):
    script: str
    interpreter: str = "/bin/bash"
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    stream: bool = False


class ResourceUsageInfo(BaseModel):
    cpu_ms: int | None = None
    memory_peak_mb: int | None = None


class ExecutionResponse(BaseModel):
    execution_id: uuid.UUID
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int
    resource_usage: ResourceUsageInfo = Field(default_factory=ResourceUsageInfo)


class ExecutionListItem(BaseModel):
    """Compact execution representation for list/history queries."""

    execution_id: uuid.UUID
    cell_id: uuid.UUID
    status: str
    command: str
    exit_code: int | None = None
    duration_ms: int | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class StreamEvent(BaseModel):
    type: str  # stdout, stderr, exit
    text: str | None = None
    exit_code: int | None = None
    duration_ms: int | None = None
