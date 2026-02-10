"""Security policy management service."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.exceptions import InvalidPolicyError, PolicyNotFoundError
from aijailer.models.policy import SecurityPolicy


class PolicyService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_policy(
        self,
        tenant_id: uuid.UUID,
        name: str,
        description: str | None = None,
        network_policy: dict | None = None,
        filesystem_policy: dict | None = None,
        syscall_policy: dict | None = None,
        resource_policy: dict | None = None,
        capability_policy: dict | None = None,
        created_by: uuid.UUID | None = None,
    ) -> SecurityPolicy:
        """Create a new security policy for a tenant."""
        policy = SecurityPolicy(
            tenant_id=tenant_id,
            name=name,
            description=description,
            network_policy=network_policy or {"default": "deny"},
            filesystem_policy=filesystem_policy or {},
            syscall_policy=syscall_policy or {},
            resource_policy=resource_policy or {},
            capability_policy=capability_policy or {},
            created_by=created_by,
        )
        self.db.add(policy)
        await self.db.flush()
        return policy

    async def get_policy(
        self, policy_id: uuid.UUID, tenant_id: uuid.UUID | None = None
    ) -> SecurityPolicy:
        """Get a policy by ID, optionally scoped to a tenant."""
        query = select(SecurityPolicy).where(SecurityPolicy.id == policy_id)
        if tenant_id is not None:
            # Allow both tenant-specific and platform-level policies
            query = query.where(
                (SecurityPolicy.tenant_id == tenant_id) | (SecurityPolicy.tenant_id.is_(None))
            )
        result = await self.db.execute(query)
        policy = result.scalar_one_or_none()
        if policy is None:
            raise PolicyNotFoundError(str(policy_id))
        return policy

    async def list_policies(
        self, tenant_id: uuid.UUID, status: str = "active"
    ) -> list[SecurityPolicy]:
        """List all policies available to a tenant (tenant-specific + platform)."""
        result = await self.db.execute(
            select(SecurityPolicy)
            .where(
                (SecurityPolicy.tenant_id == tenant_id) | (SecurityPolicy.tenant_id.is_(None)),
                SecurityPolicy.status == status,
            )
            .order_by(SecurityPolicy.created_at.desc())
        )
        return list(result.scalars().all())

    async def update_policy(
        self,
        policy_id: uuid.UUID,
        tenant_id: uuid.UUID,
        name: str | None = None,
        description: str | None = None,
        network_policy: dict | None = None,
        filesystem_policy: dict | None = None,
        syscall_policy: dict | None = None,
        resource_policy: dict | None = None,
    ) -> SecurityPolicy:
        """Update a policy by creating a new version."""
        existing = await self.get_policy(policy_id, tenant_id)

        # Policies are immutable — create a new version
        new_policy = SecurityPolicy(
            tenant_id=existing.tenant_id,
            name=name or existing.name,
            description=description or existing.description,
            version=existing.version + 1,
            network_policy=network_policy or existing.network_policy,
            filesystem_policy=filesystem_policy or existing.filesystem_policy,
            syscall_policy=syscall_policy or existing.syscall_policy,
            resource_policy=resource_policy or existing.resource_policy,
            capability_policy=existing.capability_policy,
            created_by=existing.created_by,
        )
        self.db.add(new_policy)

        # Deprecate old version
        existing.status = "deprecated"

        await self.db.flush()
        return new_policy

    async def delete_policy(self, policy_id: uuid.UUID, tenant_id: uuid.UUID) -> None:
        """Deactivate a policy (soft delete). Cells keep the last active version."""
        policy = await self.get_policy(policy_id, tenant_id)
        policy.status = "archived"

    def compile_policy(self, policy: SecurityPolicy) -> dict:
        """Compile a security policy into an effective enforcement configuration.

        In production, this would generate nftables rules, seccomp profiles,
        cgroup limits, etc. For the MVP, it returns a unified JSON config.
        """
        return {
            "network": policy.network_policy,
            "filesystem": policy.filesystem_policy,
            "syscalls": policy.syscall_policy,
            "resources": policy.resource_policy,
            "capabilities": policy.capability_policy,
        }
