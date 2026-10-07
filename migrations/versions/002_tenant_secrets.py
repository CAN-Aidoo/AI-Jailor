"""Tenant secret store.

Revision ID: 002_tenant_secrets
Revises: 001_initial
Create Date: 2026-10-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "002_tenant_secrets"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(63), nullable=False),
        sa.Column("version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("hosts", postgresql.JSONB, nullable=False),
        sa.Column("expires_at_epoch", sa.Float, nullable=True),
        sa.Column("ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("nonce", sa.LargeBinary(12), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary, nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.UniqueConstraint("tenant_id", "name", name="uq_tenant_secret_name"),
    )
    op.create_index("ix_tenant_secrets_tenant_id", "tenant_secrets", ["tenant_id"])
    op.create_index("ix_tenant_secrets_key_id", "tenant_secrets", ["key_id"])


def downgrade() -> None:
    op.drop_table("tenant_secrets")
