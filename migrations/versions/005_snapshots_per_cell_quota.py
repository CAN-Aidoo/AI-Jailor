"""Per-cell snapshot quota (limit lives on the tenant).

Revision ID: 005_snapshots_per_cell_quota
Revises: 004_snapshot_storage_quota
Create Date: 2026-10-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "005_snapshots_per_cell_quota"
down_revision: Union[str, None] = "004_snapshot_storage_quota"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("max_snapshots_per_cell", sa.Integer, nullable=False,
                                       server_default="10"))


def downgrade() -> None:
    op.drop_column("tenants", "max_snapshots_per_cell")
