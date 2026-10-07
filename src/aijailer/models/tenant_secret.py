"""Tenant secret (envelope-encrypted). The plaintext is never stored."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base
from aijailer.db.types import JSONB


class TenantSecret(Base):
    __tablename__ = "tenant_secrets"
    __table_args__ = (UniqueConstraint("tenant_id", "name", name="uq_tenant_secret_name"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(63), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    # Destinations the broker may send this secret to. Bound into the ciphertext's AAD.
    hosts: Mapped[list] = mapped_column(JSONB, nullable=False)
    # Expiry as epoch seconds (float) so it can be bound into the AAD exactly.
    expires_at_epoch: Mapped[float | None] = mapped_column(nullable=True)

    # Envelope: AES-256-GCM(DEK) over the value; DEK wrapped by KEK ``key_id``.
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
