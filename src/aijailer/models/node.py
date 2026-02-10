"""Node database model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

    # Capacity
    total_vcpus: Mapped[int] = mapped_column(Integer, nullable=False)
    total_memory_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    total_disk_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    available_vcpus: Mapped[int] = mapped_column(Integer, nullable=False)
    available_memory_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    available_disk_mb: Mapped[int] = mapped_column(Integer, nullable=False)
    max_cells: Mapped[int] = mapped_column(Integer, nullable=False)
    running_cells: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Network
    internal_ip: Mapped[str] = mapped_column(INET, nullable=False)
    cell_subnet: Mapped[str] = mapped_column(CIDR, nullable=False)

    # Metadata
    region: Mapped[str | None] = mapped_column(String(50))
    zone: Mapped[str | None] = mapped_column(String(50))
    labels: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Health
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    agent_version: Mapped[str | None] = mapped_column(String(50))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
