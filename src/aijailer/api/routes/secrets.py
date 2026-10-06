"""Tenant secrets: write-only credentials injected by the egress broker.

Values can be created and rotated here and are never readable again, by anyone, through any
endpoint. Cells reference a secret by placeholder (``{{secret:NAME}}``) in request headers.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, require_role
from aijailer.core.exceptions import AiJailerError
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.secrets import CreateSecretRequest, SecretResponse, UpdateSecretRequest
from aijailer.secretstore.keys import (
    IntegrityError,
    KeyNotFoundError,
    KeyUnavailableError,
    SecretStoreError,
)
from aijailer.secretstore.runtime import get_secret_store
from aijailer.secretstore.store import (
    ConflictError,
    LimitError,
    NotFoundError,
    SecretMeta,
    SecretStore,
)
from aijailer.secretstore.validation import ValidationError

router = APIRouter(prefix="/v1/secrets", tags=["Secrets"])

WRITERS = ("owner", "admin")
READERS = ("owner", "admin", "auditor")


def _store(db: AsyncSession) -> SecretStore:
    store = get_secret_store(db)
    if store is None:
        raise AiJailerError("secret store is not configured on this deployment",
                            code="secret_store_unavailable")
    return store


def _api_error(exc: SecretStoreError) -> AiJailerError:
    """Translate store errors. Messages come from our own validators and never echo values."""
    if isinstance(exc, NotFoundError):
        return AiJailerError("secret not found", code="secret_not_found")
    if isinstance(exc, ConflictError):
        return AiJailerError(str(exc), code="secret_conflict")
    if isinstance(exc, LimitError):
        return AiJailerError(str(exc), code="secret_limit")
    if isinstance(exc, (KeyUnavailableError, KeyNotFoundError, IntegrityError)):
        return AiJailerError("secret store failure", code="secret_store_unavailable")
    if isinstance(exc, ValidationError) or type(exc) is SecretStoreError:
        return AiJailerError(str(exc), code="invalid_secret")
    return AiJailerError("secret store failure", code="secret_store_unavailable")


def _resp(m: SecretMeta) -> SecretResponse:
    return SecretResponse(name=m.name, version=m.version, hosts=m.hosts, expires_at=m.expires_at,
                          created_at=m.created_at, updated_at=m.updated_at,
                          rotated_at=m.rotated_at, placeholder="{{secret:%s}}" % m.name)


@router.post("", status_code=201, response_model=ApiResponse[SecretResponse])
async def create_secret(body: CreateSecretRequest,
                        auth: AuthContext = Depends(require_role(*WRITERS)),
                        db: AsyncSession = Depends(get_db)):
    try:
        meta = await _store(db).create(auth.tenant_id, body.name, body.value.get_secret_value(),
                                       body.hosts, body.expires_at, actor=auth.api_key_id)
    except SecretStoreError as exc:
        raise _api_error(exc) from None
    return ApiResponse(data=_resp(meta))


@router.get("", response_model=ApiResponse[list[SecretResponse]])
async def list_secrets(auth: AuthContext = Depends(require_role(*READERS)),
                       db: AsyncSession = Depends(get_db)):
    try:
        return ApiResponse(data=[_resp(m) for m in await _store(db).list_meta(auth.tenant_id)])
    except SecretStoreError as exc:
        raise _api_error(exc) from None


@router.get("/{name}", response_model=ApiResponse[SecretResponse])
async def get_secret(name: str, auth: AuthContext = Depends(require_role(*READERS)),
                     db: AsyncSession = Depends(get_db)):
    try:
        return ApiResponse(data=_resp(await _store(db).get_meta(auth.tenant_id, name)))
    except SecretStoreError as exc:
        raise _api_error(exc) from None


@router.put("/{name}", response_model=ApiResponse[SecretResponse])
async def update_secret(name: str, body: UpdateSecretRequest,
                        auth: AuthContext = Depends(require_role(*WRITERS)),
                        db: AsyncSession = Depends(get_db)):
    try:
        meta = await _store(db).update(
            auth.tenant_id, name,
            value=body.value.get_secret_value() if body.value else None,
            hosts=body.hosts, expires_at=body.expires_at, clear_expiry=body.clear_expiry,
            actor=auth.api_key_id)
    except SecretStoreError as exc:
        raise _api_error(exc) from None
    return ApiResponse(data=_resp(meta))


@router.delete("/{name}", status_code=204)
async def delete_secret(name: str, auth: AuthContext = Depends(require_role(*WRITERS)),
                        db: AsyncSession = Depends(get_db)):
    try:
        await _store(db).delete(auth.tenant_id, name, actor=auth.api_key_id)
    except SecretStoreError as exc:
        raise _api_error(exc) from None
