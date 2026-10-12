"""Widen tenant_secrets.key_id so a full AWS KMS key ARN fits.

The column was VARCHAR(64), but the KMS provider stores the key's full ARN
(``arn:aws:kms:<region>:<account>:key/<uuid>``, about 76 characters and up to 2048 by
AWS's limits). PostgreSQL rejects that value ("value too long for type character varying(64)");
SQLite does not enforce the length, so the tests passed on it and the problem only showed
when the suite was run on PostgreSQL.

Widening is a metadata-only change on PostgreSQL (no table rewrite, no data change).
``downgrade`` narrows it again and will fail if any stored key_id is longer than 64 characters,
which is the honest outcome: those rows cannot fit.

Revision ID: 010_tenant_secret_key_id_length
Revises: 009_redact_execution_environment
Create Date: 2026-10-11
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "010_tenant_secret_key_id_length"
down_revision: Union[str, None] = "009_redact_execution_environment"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column("tenant_secrets", "key_id", existing_type=sa.String(64), type_=sa.String(2048),
                    existing_nullable=False)


def downgrade() -> None:
    op.alter_column("tenant_secrets", "key_id", existing_type=sa.String(2048), type_=sa.String(64),
                    existing_nullable=False)
