"""Certified Component database model.

Pre-verified, formally proven building blocks that handle
security-critical operations (auth, crypto, data access, etc.).
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class CertifiedComponent(Base):
    __tablename__ = "certified_components"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    version: Mapped[str] = mapped_column(String(50), nullable=False)
    language: Mapped[str] = mapped_column(String(50), nullable=False)  # python, typescript, java, go
    category: Mapped[str] = mapped_column(String(100), nullable=False)  # auth, crypto, data_access, etc.
    source_code: Mapped[str] = mapped_column(Text, nullable=False)
    formal_spec: Mapped[str | None] = mapped_column(Text)  # TLA+ or Dafny spec

    # Security metadata
    compliance_certs: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=list
    )  # ["HIPAA", "SOC2", "PCI-DSS"]
    cve_coverage: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=list
    )  # CVEs this component prevents
    fuzz_report_url: Mapped[str | None] = mapped_column(Text)

    # Status
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )  # active, deprecated, revoked

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
