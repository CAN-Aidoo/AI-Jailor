"""Security Policy database model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

    # Policy definitions
    network_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=lambda: {"default": "deny"})
    filesystem_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    syscall_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    resource_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    capability_policy: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
