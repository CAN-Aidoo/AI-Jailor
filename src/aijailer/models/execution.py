"""Execution database model."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from aijailer.db.types import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class Execution(Base):
    __tablename__ = "executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cell_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")

    # Execution details
    command: Mapped[str] = mapped_column(Text, nullable=False)
    interpreter: Mapped[str | None] = mapped_column(String(255))
    working_directory: Mapped[str | None] = mapped_column(String(1024))
    user_context: Mapped[str] = mapped_column(String(63), default="agent")
    environment: Mapped[dict] = mapped_column(JSONB, default=dict)

    # Results
    exit_code: Mapped[int | None] = mapped_column(Integer)
    stdout: Mapped[str | None] = mapped_column(Text)
    stderr: Mapped[str | None] = mapped_column(Text)

    # Resource usage
    cpu_ms: Mapped[int | None] = mapped_column(BigInteger)
    memory_peak_mb: Mapped[int | None] = mapped_column(Integer)

    # Timing
    timeout_seconds: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)

    # API context
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    request_id: Mapped[str | None] = mapped_column(String(64))
