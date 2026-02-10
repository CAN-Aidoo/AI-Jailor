"""Cell database model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class Cell(Base):
    __tablename__ = "cells"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="creating")
    error_message: Mapped[str | None] = mapped_column(Text)

    # Configuration
    image: Mapped[str] = mapped_column(String(255), nullable=False)

    # Resources
    vcpus: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    memory_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=512)
    disk_mb: Mapped[int] = mapped_column(Integer, nullable=False, default=2048)
    network_bandwidth_mbps: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    # Security
    security_policy_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    effective_policy: Mapped[dict | None] = mapped_column(JSONB)

    # Networking
    node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    internal_ip: Mapped[str | None] = mapped_column(INET)

    # Environment
    environment: Mapped[dict] = mapped_column(JSONB, default=dict)
    working_directory: Mapped[str] = mapped_column(String(1024), default="/home/agent")

    # Persistent volume
    persistent_volume_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))

    # Tags
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    paused_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    destroyed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
