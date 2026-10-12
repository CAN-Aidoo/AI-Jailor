"""CodeImmune tables and tenant columns that had models but no migration.

These existed only in the ORM models, so a database built with ``alembic upgrade head`` was missing
them (the test suite builds its schema from the models and did not notice):

  tables   certified_components, constraints, attack_patterns, generation_log, security_certificates
  columns  tenants.compliance_requirements, tenants.custom_constraints, tenants.monthly_generation_limit

The columns added to ``tenants`` get server defaults so existing rows are backfilled (an empty list)
and the NOT NULL columns can be added to a populated table.

``downgrade`` DROPS the five tables and the three columns and the data in them; there is nothing to
restore it from. Take a backup first if any of it matters.

Revision ID: 011_codeimmune_tables
Revises: 010_tenant_secret_key_id_length
Create Date: 2026-10-12
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "011_codeimmune_tables"
down_revision: Union[str, None] = "010_tenant_secret_key_id_length"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

EMPTY_LIST = sa.text("'[]'::jsonb")


def upgrade() -> None:
    # --- tenants: CodeImmune columns -------------------------------------------------------------
    op.add_column("tenants", sa.Column("compliance_requirements", postgresql.JSONB,
                                       nullable=False, server_default=EMPTY_LIST))
    op.add_column("tenants", sa.Column("custom_constraints", postgresql.JSONB,
                                       nullable=False, server_default=EMPTY_LIST))
    op.add_column("tenants", sa.Column("monthly_generation_limit", sa.Integer, nullable=True))

    # --- certified_components --------------------------------------------------------------------
    op.create_table(
        "certified_components",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("version", sa.String(50), nullable=False),
        sa.Column("language", sa.String(50), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("source_code", sa.Text, nullable=False),
        sa.Column("formal_spec", sa.Text, nullable=True),
        sa.Column("compliance_certs", postgresql.JSONB, nullable=False, server_default=EMPTY_LIST),
        sa.Column("cve_coverage", postgresql.JSONB, nullable=False, server_default=EMPTY_LIST),
        sa.Column("fuzz_report_url", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # --- constraints -----------------------------------------------------------------------------
    op.create_table(
        "constraints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("applies_when", postgresql.JSONB, nullable=False),
        sa.Column("rules", postgresql.JSONB, nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    # --- attack_patterns (links to constraints) --------------------------------------------------
    op.create_table(
        "attack_patterns",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pattern_signature", sa.String(255), nullable=False),
        sa.Column("vulnerability_class", sa.String(100), nullable=False),
        sa.Column("attack_vector", sa.Text, nullable=False),
        sa.Column("generated_constraint_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("occurrence_count", sa.Integer, nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["generated_constraint_id"], ["constraints.id"]),
    )

    # --- generation_log --------------------------------------------------------------------------
    op.create_table(
        "generation_log",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("intent", postgresql.JSONB, nullable=False),
        sa.Column("constraints_applied", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False),
        sa.Column("components_used", postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=False),
        sa.Column("output_hash", sa.String(64), nullable=False),
        sa.Column("security_certificate", postgresql.JSONB, nullable=False),
        sa.Column("blocked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("block_reason", sa.Text, nullable=True),
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_index("ix_generation_log_tenant_id", "generation_log", ["tenant_id"])

    # --- security_certificates (links to generation_log) -----------------------------------------
    op.create_table(
        "security_certificates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("generation_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("constraints_satisfied", postgresql.JSONB, nullable=False),
        sa.Column("compliance_frameworks", postgresql.JSONB, nullable=False),
        sa.Column("components_versions", postgresql.JSONB, nullable=False),
        sa.Column("certificate_hash", sa.String(64), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["generation_id"], ["generation_log.id"]),
    )
    op.create_index("ix_security_certificates_tenant_id", "security_certificates", ["tenant_id"])


def downgrade() -> None:
    # Children before parents. This destroys the data in these tables and columns.
    op.drop_index("ix_security_certificates_tenant_id", table_name="security_certificates")
    op.drop_table("security_certificates")
    op.drop_index("ix_generation_log_tenant_id", table_name="generation_log")
    op.drop_table("generation_log")
    op.drop_table("attack_patterns")
    op.drop_table("constraints")
    op.drop_table("certified_components")
    op.drop_column("tenants", "monthly_generation_limit")
    op.drop_column("tenants", "custom_constraints")
    op.drop_column("tenants", "compliance_requirements")
