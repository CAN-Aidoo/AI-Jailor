"""Durable, append-only audit log (hash chain + signed checkpoints).

Revision ID: 007_audit_log
Revises: 006_snapshot_storage_per_cell
Create Date: 2026-10-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "007_audit_log"
down_revision: Union[str, None] = "006_snapshot_storage_per_cell"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cell_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("seq", sa.BigInteger, nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=False), nullable=False),
        sa.Column("details", postgresql.JSONB, nullable=False),
        sa.Column("source_ip", sa.String(64)),
        sa.Column("api_key_id", postgresql.UUID(as_uuid=True)),
        sa.Column("request_id", sa.String(128)),
        sa.Column("previous_hash", sa.String(64), nullable=False),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.UniqueConstraint("tenant_id", "cell_id", "seq", name="uq_audit_chain_seq"),
    )
    op.create_index("ix_audit_events_tenant_time", "audit_events", ["tenant_id", "timestamp"])
    op.create_table(
        "audit_checkpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("cell_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("length", sa.BigInteger, nullable=False),
        sa.Column("head", sa.String(64), nullable=False),
        sa.Column("key_id", sa.String(32), nullable=False),
        sa.Column("envelope", postgresql.JSONB, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_checkpoints_chain", "audit_checkpoints",
                    ["tenant_id", "cell_id", "length"])
    # Append-only at the database level: even the application role cannot rewrite history.
    # (Retention/erasure must go through a deliberate, privileged procedure that disables the
    # trigger; it should also re-anchor the chain and record that it did so.)
    op.execute("""
        CREATE FUNCTION audit_reject_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION '% on % is not allowed: the audit log is append-only', TG_OP, TG_TABLE_NAME;
        END;
        $$ LANGUAGE plpgsql
    """)
    for table in ("audit_events", "audit_checkpoints"):
        op.execute(f"""
            CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION audit_reject_mutation()
        """)


def downgrade() -> None:
    for table in ("audit_checkpoints", "audit_events"):
        op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}")
    op.execute("DROP FUNCTION IF EXISTS audit_reject_mutation()")
    op.drop_table("audit_checkpoints")
    op.drop_table("audit_events")
