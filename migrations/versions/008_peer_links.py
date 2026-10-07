"""Peer links.

Revision ID: 008_peer_links
Revises: 007_audit_log
Create Date: 2026-10-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "008_peer_links"
down_revision: Union[str, None] = "007_audit_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "peer_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("initiator_tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("initiator_cell_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("responder_tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("responder_cell_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(10), nullable=False, server_default="pending"),
        sa.Column("purpose", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("accepted_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_by_tenant_id", postgresql.UUID(as_uuid=True)),
        sa.CheckConstraint("status IN ('pending','active','revoked')", name="ck_peer_link_status"),
        sa.CheckConstraint("initiator_cell_id <> responder_cell_id", name="ck_peer_link_distinct"),
    )
    op.create_index("ix_peer_links_initiator", "peer_links", ["initiator_tenant_id", "status"])
    op.create_index("ix_peer_links_responder", "peer_links", ["responder_tenant_id", "status"])
    op.create_index("ix_peer_links_cells", "peer_links", ["initiator_cell_id", "responder_cell_id"])


def downgrade() -> None:
    op.drop_table("peer_links")
