"""Redact the environment stored on existing executions rows.

Before this revision the exec ``environment`` was stored as given, values
included. The service now stores names with every value replaced by
``[redacted]``; this brings the rows written earlier in line.

IRREVERSIBLE: the original values are overwritten and cannot be restored, so
``downgrade`` does nothing. Take a backup first if the old values matter.
Rows that are already redacted, empty or NULL are left alone, so running it
twice is harmless. Backups, replicas and WAL taken before the upgrade still
hold the old values; they have to be dealt with separately.

Revision ID: 009_redact_execution_environment
Revises: 008_peer_links
Create Date: 2026-10-08
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "009_redact_execution_environment"
down_revision: Union[str, None] = "008_peer_links"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Same marker as aijailer.core.exec_env.REDACTED, repeated on purpose: a
# migration must not change meaning when application code does.
REDACTED = "[redacted]"
BATCH = 1000

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
executions = sa.table("executions", sa.column("id"), sa.column("environment", _JSON))


def _needs_redaction(env) -> bool:
    return isinstance(env, dict) and any(v != REDACTED for v in env.values())


def upgrade() -> None:
    bind = op.get_bind()
    last = None
    while True:
        query = sa.select(executions.c.id, executions.c.environment).order_by(executions.c.id).limit(BATCH)
        if last is not None:
            query = query.where(executions.c.id > last)
        rows = bind.execute(query).all()
        if not rows:
            return
        for row_id, env in rows:
            if _needs_redaction(env):
                bind.execute(
                    sa.update(executions)
                    .where(executions.c.id == row_id)
                    .values(environment={name: REDACTED for name in env})
                )
        last = rows[-1][0]


def downgrade() -> None:
    # The values are gone; there is nothing to restore.
    pass
