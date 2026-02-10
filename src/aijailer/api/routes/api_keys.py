"""API Key management endpoints."""

import hashlib
import secrets
import uuid

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, require_role
from aijailer.db.base import get_db
from aijailer.models.tenant import ApiKey
from aijailer.schemas.common import ApiResponse

router = APIRouter(prefix="/v1/api-keys", tags=["API Keys"])


class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    role: str = Field(default="operator")
    rate_limit_per_minute: int | None = None


class ApiKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_prefix: str
    role: str
    status: str
    created_at: str
    last_used_at: str | None = None
    rate_limit_per_minute: int | None = None


class ApiKeyCreatedResponse(ApiKeyResponse):
    """Returned only on creation — includes the full key (shown once)."""
    key: str


@router.post("", status_code=201, response_model=ApiResponse[ApiKeyCreatedResponse])
async def create_api_key(
    body: CreateApiKeyRequest,
    auth: AuthContext = Depends(require_role("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key. The full key is returned only once."""
    raw_key = f"aj_live_{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_prefix = raw_key[:12]

    api_key = ApiKey(
        tenant_id=auth.tenant_id,
        created_by=auth.api_key_id,
        name=body.name,
        key_hash=key_hash,
        key_prefix=key_prefix,
        role=body.role,
        status="active",
        rate_limit_per_minute=body.rate_limit_per_minute,
    )
    db.add(api_key)
    await db.flush()

    return ApiResponse(
        data=ApiKeyCreatedResponse(
            id=api_key.id,
            name=api_key.name,
            key_prefix=key_prefix,
            role=api_key.role,
            status=api_key.status,
            created_at=api_key.created_at.isoformat() if api_key.created_at else "",
            rate_limit_per_minute=api_key.rate_limit_per_minute,
            key=raw_key,
        )
    )


@router.get("", response_model=ApiResponse[list[ApiKeyResponse]])
async def list_api_keys(
    auth: AuthContext = Depends(require_role("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """List all API keys for the tenant (key values are never shown)."""
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.tenant_id == auth.tenant_id)
        .order_by(ApiKey.created_at.desc())
    )
    keys = result.scalars().all()
    return ApiResponse(
        data=[
            ApiKeyResponse(
                id=k.id,
                name=k.name,
                key_prefix=k.key_prefix,
                role=k.role,
                status=k.status,
                created_at=k.created_at.isoformat() if k.created_at else "",
                last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
                rate_limit_per_minute=k.rate_limit_per_minute,
            )
            for k in keys
        ]
    )


@router.delete("/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: uuid.UUID,
    auth: AuthContext = Depends(require_role("owner", "admin")),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key (soft delete)."""
    result = await db.execute(
        select(ApiKey).where(
            ApiKey.id == key_id,
            ApiKey.tenant_id == auth.tenant_id,
        )
    )
    api_key = result.scalar_one_or_none()
    if api_key:
        api_key.status = "revoked"
