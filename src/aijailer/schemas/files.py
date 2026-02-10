"""Pydantic schemas for File Operations API endpoints."""

from datetime import datetime

from pydantic import BaseModel


class FileEntry(BaseModel):
    name: str
    type: str  # "file" or "directory"
    size: int | None = None
    modified_at: datetime | None = None
    permissions: str | None = None


class FileListResponse(BaseModel):
    path: str
    entries: list[FileEntry]
