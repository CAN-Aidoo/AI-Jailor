"""Tenant and User database models."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from aijailer.db.types import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from aijailer.db.base import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    tier: Mapped[str] = mapped_column(String(20), nullable=False, default="starter")

    # Limits
    max_concurrent_cells: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_persistent_storage_gb: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    max_snapshot_count: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    # Total bytes of snapshot bundles (memory dumps dominate): count alone does not bound disk use.
    # Keeps one runaway cell (or agent loop) from using the whole tenant allowance.
    max_snapshots_per_cell: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    max_snapshot_storage_gb: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    spending_cap_cents: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Settings
    default_security_policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )

    # CodeImmune: generation & compliance
    compliance_requirements: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=list
    )  # ["HIPAA", "SOC2", "PCI-DSS"]
    custom_constraints: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=list
    )  # Tenant-specific constraint overrides
    monthly_generation_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    users: Mapped[list["User"]] = relationship(back_populates="tenant")
    api_keys: Mapped[list["ApiKey"]] = relationship(back_populates="tenant")


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="operator")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    tenant: Mapped["Tenant"] = relationship(back_populates="users")


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(12), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="operator")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    rate_limit_per_minute: Mapped[int | None] = mapped_column(Integer)

    tenant: Mapped["Tenant"] = relationship(back_populates="api_keys")
