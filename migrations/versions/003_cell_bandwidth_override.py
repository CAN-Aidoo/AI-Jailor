"""Per-cell bandwidth override.

Revision ID: 003_cell_bandwidth_override
Revises: 002_tenant_secrets
Create Date: 2026-10-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "003_cell_bandwidth_override"
down_revision: Union[str, None] = "002_tenant_secrets"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("cells", sa.Column("bandwidth_override", postgresql.JSONB, nullable=True))


def downgrade() -> None:
    op.drop_column("cells", "bandwidth_override")
