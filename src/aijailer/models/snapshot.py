"""Snapshot and PersistentVolume database models."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class Snapshot(Base):
    __tablename__ = "snapshots"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    cell_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str | None] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="creating")
    error_message: Mapped[str | None] = mapped_column(Text)

    # Storage references
    memory_snapshot_key: Mapped[str | None] = mapped_column(String(1024))
    disk_snapshot_key: Mapped[str | None] = mapped_column(String(1024))
    persistent_volume_snapshot_key: Mapped[str | None] = mapped_column(String(1024))

    # Size tracking
    memory_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    disk_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    total_size_bytes: Mapped[int | None] = mapped_column(BigInteger)

    # Cell configuration at time of snapshot
    cell_config: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Retention
    retention_policy: Mapped[str] = mapped_column(String(20), default="standard")
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class PersistentVolume(Base):
    __tablename__ = "persistent_volumes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    cell_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="creating")

    # Storage
    size_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    used_mb: Mapped[int] = mapped_column(Integer, default=0)
    node_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    host_path: Mapped[str | None] = mapped_column(String(1024))

    # Encryption
    encrypted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    encryption_key_id: Mapped[str | None] = mapped_column(String(255))

    # Metadata
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
