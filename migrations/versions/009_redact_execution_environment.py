"""Redact the environment stored on existing executions rows.

Before this revision the exec ``environment`` was stored as given, values
included. The service now stores names with every value replaced by
``[redacted]``; this brings the rows written earlier in line.

IRREVERSIBLE: the original values are overwritten and cannot be restored, so
``downgrade`` does nothing. Take a backup first if the old values matter.
Rows that are already redacted, empty or NULL are left alone, so running it
twice is harmless. Backups, replicas and WAL taken before the upgrade still
hold the old values; they have to be dealt with separately.

Batch size: rows are read and rewritten ``AIJAILER_REDACT_BATCH`` at a time
(default 1000; a positive integer, anything else aborts before any row is
touched). It bounds the memory used per read, not the transaction: Alembic runs
the whole migration in one transaction on PostgreSQL, so every batch commits or
rolls back together. Example:  AIJAILER_REDACT_BATCH=200 alembic upgrade head

Revision ID: 009_redact_execution_environment
Revises: 008_peer_links
Create Date: 2026-10-08
"""
import os
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
BATCH = 1000                                  # default; AIJAILER_REDACT_BATCH overrides it
BATCH_ENV = "AIJAILER_REDACT_BATCH"

_JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
executions = sa.table("executions", sa.column("id"), sa.column("environment", _JSON))


def _needs_redaction(env) -> bool:
    return isinstance(env, dict) and any(v != REDACTED for v in env.values())


def batch_size() -> int:
    raw = os.environ.get(BATCH_ENV)
    if raw is None:
        return BATCH
    try:
        size = int(raw)
    except ValueError:
        size = 0
    if size < 1:
        raise ValueError(f"{BATCH_ENV} must be a positive integer, got {raw!r}")
    return size


def upgrade() -> None:
    size = batch_size()                       # validated first, so a bad value touches nothing
    bind = op.get_bind()
    last = None
    while True:
        query = sa.select(executions.c.id, executions.c.environment).order_by(executions.c.id).limit(size)
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
        if len(rows) < size:
            return
        last = rows[-1][0]


def downgrade() -> None:
    # The values are gone; there is nothing to restore.
    pass
