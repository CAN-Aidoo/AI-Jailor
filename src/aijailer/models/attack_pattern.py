"""Attack Pattern database model.

Part of the Immune Memory system. Stores observed attack vectors,
maps them to vulnerability classes, and links to auto-generated
constraints that prevent similar attacks in the future.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class AttackPattern(Base):
    __tablename__ = "attack_patterns"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    pattern_signature: Mapped[str] = mapped_column(String(255), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # OWASP category / CWE
    attack_vector: Mapped[str] = mapped_column(Text, nullable=False)

    # Link to generated constraint
    generated_constraint_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("constraints.id"),
        nullable=True,
    )

    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )

    # Timestamps
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
