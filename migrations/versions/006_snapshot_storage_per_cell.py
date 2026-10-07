"""Per-cell snapshot size limit (limit lives on the tenant).

Revision ID: 006_snapshot_storage_per_cell
Revises: 005_snapshots_per_cell_quota
Create Date: 2026-10-07
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "006_snapshot_storage_per_cell"
down_revision: Union[str, None] = "005_snapshots_per_cell_quota"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("max_snapshot_storage_per_cell_gb", sa.Integer,
                                       nullable=False, server_default="10"))


def downgrade() -> None:
    op.drop_column("tenants", "max_snapshot_storage_per_cell_gb")
