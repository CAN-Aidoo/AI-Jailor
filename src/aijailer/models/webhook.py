"""Webhook database model."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from aijailer.db.types import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    events: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")

    # Delivery tracking
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivery_status: Mapped[int | None] = mapped_column(Integer)
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
