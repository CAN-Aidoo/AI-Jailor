"""Peer links: a consented, expiring permission for two specific cells to talk end-to-end encrypted."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, Index, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base


class PeerLink(Base):
    """pending (proposed by the initiator's tenant) -> active (accepted by the responder's tenant)
    -> revoked. Expiry is checked at every connection, so a link that lapses stops working without
    anyone having to flip a flag. The id doubles as the hostname label cells connect to
    (``<id hex>.peer.aijailer.invalid``)."""

    __tablename__ = "peer_links"
    __table_args__ = (
        Index("ix_peer_links_initiator", "initiator_tenant_id", "status"),
        Index("ix_peer_links_responder", "responder_tenant_id", "status"),
        Index("ix_peer_links_cells", "initiator_cell_id", "responder_cell_id"),
        CheckConstraint("status IN ('pending','active','revoked')", name="ck_peer_link_status"),
        CheckConstraint("initiator_cell_id <> responder_cell_id", name="ck_peer_link_distinct"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    initiator_tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    initiator_cell_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    responder_tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    responder_cell_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(10), nullable=False, default="pending")
    purpose: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_tenant_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
