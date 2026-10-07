"""Durable audit log: hash-chained events and signed chain checkpoints.

A chain is one (tenant_id, cell_id) pair; ``seq`` numbers events 1..n inside it and the UNIQUE
constraint on (tenant_id, cell_id, seq) means two writers can never both extend the same
predecessor (the loser retries). Rows are append-only: the migration installs a trigger that
rejects UPDATE and DELETE on PostgreSQL.

Ids use the generic ``Uuid`` type (native UUID on PostgreSQL). The PostgreSQL-only UUID type used
elsewhere is stored by SQLite under NUMERIC affinity, which turns the all-digit nil UUID (the
audit "cell" of non-cell events) into the integer 0 on read."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, String, UniqueConstraint, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column

from aijailer.db.base import Base
from aijailer.db.types import JSONB


class AuditEventRow(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "cell_id", "seq", name="uq_audit_chain_seq"),
        Index("ix_audit_events_tenant_time", "tenant_id", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    cell_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    # Naive UTC, exactly as hashed (AuditEvent.timestamp): the hash covers its isoformat().
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(64))
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    request_id: Mapped[str | None] = mapped_column(String(128))
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)


class AuditCheckpointRow(Base):
    """A signed (head hash, length) for a chain, so deleting recent events or rebuilding the
    whole chain consistently is detectable (a bare hash chain cannot see either)."""

    __tablename__ = "audit_checkpoints"
    __table_args__ = (Index("ix_audit_checkpoints_chain", "tenant_id", "cell_id", "length"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    cell_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    length: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head: Mapped[str] = mapped_column(String(64), nullable=False)
    key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    envelope: Mapped[dict] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
