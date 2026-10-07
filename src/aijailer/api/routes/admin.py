"""Operator (platform) API. Authenticated by ADMIN_TOKEN, NOT by tenant API keys: a tenant's own
owner/admin must not be able to raise the limits that bound them. Disabled (404) when unset."""

import hmac
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, StrictInt
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.config import get_settings
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.services.tenant_quota import QuotaState, TenantQuotaService

router = APIRouter(prefix="/v1/admin", tags=["Admin"], include_in_schema=False)


async def require_operator(request: Request) -> str:
    token = get_settings().admin_token
    if not token:
        raise HTTPException(status_code=404, detail="Not Found")
    given = request.headers.get("authorization", "")
    if not hmac.compare_digest(given.encode(), f"Bearer {token}".encode()):
        raise HTTPException(status_code=401, detail="Unauthorized",
                            headers={"WWW-Authenticate": "Bearer"})
    return "operator"


class QuotaUpdate(BaseModel):
    """Any subset. Unknown fields are rejected (a typo must not silently change nothing)."""

    model_config = ConfigDict(extra="forbid")
    max_snapshot_count: StrictInt | None = None
    max_snapshots_per_cell: StrictInt | None = None
    max_snapshot_storage_gb: StrictInt | None = None
    max_snapshot_storage_per_cell_gb: StrictInt | None = None


def _view(s: QuotaState) -> dict:
    return {"limits": s.limits, "defaults": s.defaults, "usage": s.usage,
            "over_limit": s.over_limit, "warnings": s.warnings}


@router.get("/tenants/{tenant_id}/quotas", response_model=ApiResponse[dict])
async def get_quotas(tenant_id: uuid.UUID, _: str = Depends(require_operator),
                     db: AsyncSession = Depends(get_db)):
    return ApiResponse(data=_view(await TenantQuotaService(db).get(tenant_id)))


@router.patch("/tenants/{tenant_id}/quotas", response_model=ApiResponse[dict])
async def update_quotas(tenant_id: uuid.UUID, body: QuotaUpdate,
                        actor: str = Depends(require_operator),
                        db: AsyncSession = Depends(get_db)):
    """Partial update of the tenant's snapshot limits (effective for the next request; lowering
    below current usage keeps existing snapshots and refuses new ones)."""
    changes = body.model_dump(exclude_unset=True)
    if any(v is None for v in changes.values()):
        from aijailer.core.exceptions import AiJailerError
        raise AiJailerError("quota values must be integers, not null", code="invalid_quota")
    return ApiResponse(data=_view(await TenantQuotaService(db).update(tenant_id, changes, actor)))


@router.delete("/tenants/{tenant_id}/quotas", response_model=ApiResponse[dict])
async def reset_quotas(tenant_id: uuid.UUID, actor: str = Depends(require_operator),
                       db: AsyncSession = Depends(get_db)):
    """Reset all four snapshot limits to the platform defaults."""
    return ApiResponse(data=_view(await TenantQuotaService(db).reset(tenant_id, actor)))
