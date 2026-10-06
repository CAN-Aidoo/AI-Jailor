"""Generation Log database model.

Audit trail for every code generation request — both successful
generations and blocked attempts. Used for analytics, compliance,
and immune memory learning.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from aijailer.db.types import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class GenerationLog(Base):
    __tablename__ = "generation_log"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    # Request context
    intent: Mapped[dict] = mapped_column(JSONB, nullable=False)
    constraints_applied: Mapped[list] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False
    )
    components_used: Mapped[list] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False
    )

    # Output
    output_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    security_certificate: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Block info
    blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    block_reason: Mapped[str | None] = mapped_column(Text)

    # Performance
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
