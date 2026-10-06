"""Security Certificate database model.

Attestation documents that prove generated code satisfies specific
security properties, compliance frameworks, and constraint rules.
Certificates are signed, time-bounded, and revocable.
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.dialects.postgresql import UUID
from aijailer.db.types import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class SecurityCertificate(Base):
    __tablename__ = "security_certificates"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    generation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("generation_log.id"),
        nullable=False,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    # Certificate content
    constraints_satisfied: Mapped[dict] = mapped_column(JSONB, nullable=False)
    compliance_frameworks: Mapped[dict] = mapped_column(JSONB, nullable=False)
    components_versions: Mapped[dict] = mapped_column(JSONB, nullable=False)
    certificate_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Validity
    valid_until: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
