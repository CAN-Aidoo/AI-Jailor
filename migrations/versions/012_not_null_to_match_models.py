"""Make the columns the models call NOT NULL actually NOT NULL.

Migration 001 and later created these columns nullable (with a server default), while the ORM models declare
them non-optional. Any row written through the application always has a value (the default fills it in), so
in practice nothing is NULL; this makes the database enforce it.

For each column: any existing NULL is first replaced with the column's own server default (so the backfill value is
exactly what an omitted value would have produced), then NOT NULL is set.

NOTE ON LOCKS: ``ALTER COLUMN ... SET NOT NULL`` takes an ACCESS EXCLUSIVE lock and scans the table to prove there
are no NULLs. That is quick on small tables and blocks reads and writes for the duration of the scan on large ones
(``executions`` is the one most likely to be large). Run it in a maintenance window, or pre-validate with a CHECK
constraint, if the table is big.

``downgrade`` drops the NOT NULL again; the backfilled values stay.

Revision ID: 012_not_null_to_match_models
Revises: 011_codeimmune_tables
Create Date: 2026-10-12
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "012_not_null_to_match_models"
down_revision: Union[str, None] = "011_codeimmune_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

NOW = "now()"
OBJ = "'{}'::jsonb"

# (table, column, the column's existing server default, used for the backfill)
COLUMNS = [
    ("api_keys", "created_at", NOW),
    ("audit_checkpoints", "created_at", NOW),
    ("cells", "created_at", NOW),
    ("cells", "updated_at", NOW),
    ("cells", "environment", OBJ),
    ("cells", "tags", OBJ),
    ("cells", "working_directory", "'/home/agent'"),
    ("executions", "started_at", NOW),
    ("executions", "environment", OBJ),
    ("executions", "user_context", "'agent'"),
    ("nodes", "created_at", NOW),
    ("nodes", "updated_at", NOW),
    ("nodes", "labels", OBJ),
    ("peer_links", "created_at", NOW),
    ("persistent_volumes", "created_at", NOW),
    ("persistent_volumes", "updated_at", NOW),
    ("persistent_volumes", "used_mb", "0"),
    ("security_policies", "created_at", NOW),
    ("security_policies", "updated_at", NOW),
    ("snapshots", "created_at", NOW),
    ("snapshots", "retention_policy", "'standard'"),
    ("tenant_secrets", "created_at", NOW),
    ("tenant_secrets", "updated_at", NOW),
    ("tenants", "created_at", NOW),
    ("tenants", "updated_at", NOW),
    ("users", "created_at", NOW),
    ("users", "updated_at", NOW),
    ("webhooks", "created_at", NOW),
    ("webhooks", "updated_at", NOW),
    ("webhooks", "consecutive_failures", "0"),
]


def upgrade() -> None:
    for table, column, default in COLUMNS:
        op.execute(sa.text(f'UPDATE "{table}" SET "{column}" = {default} WHERE "{column}" IS NULL'))
        op.alter_column(table, column, nullable=False)


def downgrade() -> None:
    for table, column, _default in reversed(COLUMNS):
        op.alter_column(table, column, nullable=True)
