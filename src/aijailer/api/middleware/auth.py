"""Authentication middleware — API key and JWT validation."""

import hashlib
import uuid
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.models.tenant import ApiKey, Tenant

security_scheme = HTTPBearer(auto_error=False)


@dataclass
class AuthContext:
    """Resolved authentication context attached to every request."""

    tenant_id: uuid.UUID
    api_key_id: uuid.UUID
    role: str
    tenant_tier: str


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


async def authenticate(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    """Validate the Bearer token and resolve tenant context."""
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authentication credentials.")

    token = credentials.credentials

    # API key authentication (aj_live_*, aj_test_*)
    if token.startswith("aj_"):
        key_hash = _hash_key(token)
        result = await db.execute(
            select(ApiKey, Tenant)
            .join(Tenant, ApiKey.tenant_id == Tenant.id)
            .where(ApiKey.key_hash == key_hash, ApiKey.status == "active")
        )
        row = result.first()
        if row is None:
            raise HTTPException(status_code=401, detail="Invalid API key.")

        api_key, tenant = row
        if tenant.status != "active":
            raise HTTPException(status_code=403, detail="Tenant account is suspended.")

        return AuthContext(
            tenant_id=tenant.id,
            api_key_id=api_key.id,
            role=api_key.role,
            tenant_tier=tenant.tier,
        )

    # For MVP, reject anything that isn't an API key
    raise HTTPException(status_code=401, detail="Unsupported authentication method.")


def require_role(*allowed_roles: str):
    """Dependency that checks the caller has one of the allowed roles."""

    async def _check(auth: AuthContext = Depends(authenticate)) -> AuthContext:
        if auth.role not in allowed_roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{auth.role}' is not permitted for this action.",
            )
        return auth

    return _check
