"""Security Policy API routes."""

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.policies import (
    CreatePolicyRequest,
    PolicyResponse,
    UpdatePolicyRequest,
)
from aijailer.services.policy_service import PolicyService

router = APIRouter(prefix="/v1/policies", tags=["Policies"])


def _policy_to_response(p) -> PolicyResponse:
    return PolicyResponse(
        id=p.id,
        tenant_id=p.tenant_id,
        name=p.name,
        description=p.description,
        version=p.version,
        status=p.status,
        network=p.network_policy,
        resources=p.resource_policy,
        filesystem=p.filesystem_policy,
        syscalls=p.syscall_policy,
        created_at=p.created_at,
        updated_at=p.updated_at,
    )


@router.post("", status_code=201, response_model=ApiResponse[PolicyResponse])
async def create_policy(
    body: CreatePolicyRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = PolicyService(db)
    policy = await svc.create_policy(
        tenant_id=auth.tenant_id,
        name=body.name,
        description=body.description,
        network_policy=body.network.model_dump(),
        filesystem_policy=body.filesystem.model_dump(),
        syscall_policy=body.syscalls.model_dump(),
        resource_policy=body.resources.model_dump(),
    )
    return ApiResponse(data=_policy_to_response(policy))


@router.get("", response_model=ApiResponse[list[PolicyResponse]])
async def list_policies(
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = PolicyService(db)
    policies = await svc.list_policies(auth.tenant_id)
    return ApiResponse(data=[_policy_to_response(p) for p in policies])


@router.get("/{policy_id}", response_model=ApiResponse[PolicyResponse])
async def get_policy(
    policy_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = PolicyService(db)
    policy = await svc.get_policy(policy_id, auth.tenant_id)
    return ApiResponse(data=_policy_to_response(policy))


@router.put("/{policy_id}", response_model=ApiResponse[PolicyResponse])
async def update_policy(
    policy_id: uuid.UUID,
    body: UpdatePolicyRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = PolicyService(db)
    policy = await svc.update_policy(
        policy_id=policy_id,
        tenant_id=auth.tenant_id,
        name=body.name,
        description=body.description,
        network_policy=body.network.model_dump() if body.network else None,
        filesystem_policy=body.filesystem.model_dump() if body.filesystem else None,
        syscall_policy=body.syscalls.model_dump() if body.syscalls else None,
        resource_policy=body.resources.model_dump() if body.resources else None,
    )
    return ApiResponse(data=_policy_to_response(policy))


@router.delete("/{policy_id}", status_code=204)
async def delete_policy(
    policy_id: uuid.UUID,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    svc = PolicyService(db)
    await svc.delete_policy(policy_id, auth.tenant_id)
