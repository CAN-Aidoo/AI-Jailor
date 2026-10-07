"""Per-tenant snapshot storage quota.

Revision ID: 004_snapshot_storage_quota
Revises: 003_cell_bandwidth_override
Create Date: 2026-10-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "004_snapshot_storage_quota"
down_revision: Union[str, None] = "003_cell_bandwidth_override"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("max_snapshot_storage_gb", sa.Integer, nullable=False,
                                       server_default="50"))


def downgrade() -> None:
    op.drop_column("tenants", "max_snapshot_storage_gb")
