"""Pydantic schemas for Policy API endpoints."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class EgressDestination(BaseModel):
    domain: str | None = None
    ip: str | None = None


class EgressRule(BaseModel):
    action: str = "allow"
    destinations: list[EgressDestination] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=lambda: ["tcp"])
    ports: list[int] = Field(default_factory=lambda: [443])


class NetworkPolicySchema(BaseModel):
    default: str = "deny"
    egress: list[EgressRule] = Field(default_factory=list)


class ResourcePolicySchema(BaseModel):
    max_vcpus: int | None = None
    max_memory_mb: int | None = None
    max_disk_mb: int | None = None
    max_pids: int | None = None
    max_open_files: int | None = None


class FilesystemPolicySchema(BaseModel):
    writable_paths: list[str] = Field(default_factory=list)
    denied_paths: list[str] = Field(default_factory=list)


class SyscallPolicySchema(BaseModel):
    blocked: list[str] = Field(default_factory=list)


class CreatePolicyRequest(BaseModel):
    name: str
    description: str | None = None
    network: NetworkPolicySchema = Field(default_factory=NetworkPolicySchema)
    resources: ResourcePolicySchema = Field(default_factory=ResourcePolicySchema)
    filesystem: FilesystemPolicySchema = Field(default_factory=FilesystemPolicySchema)
    syscalls: SyscallPolicySchema = Field(default_factory=SyscallPolicySchema)


class UpdatePolicyRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    network: NetworkPolicySchema | None = None
    resources: ResourcePolicySchema | None = None
    filesystem: FilesystemPolicySchema | None = None
    syscalls: SyscallPolicySchema | None = None


class PolicyResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID | None
    name: str
    description: str | None
    version: int
    status: str
    network: dict[str, Any]
    resources: dict[str, Any]
    filesystem: dict[str, Any]
    syscalls: dict[str, Any]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}
