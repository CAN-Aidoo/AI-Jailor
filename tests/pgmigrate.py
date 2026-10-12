"""Helpers for tests that run the real Alembic chain on a throwaway PostgreSQL database.

The server comes from tests/pgserver.py (AIJAILER_TEST_PG_URL, or a private throwaway cluster from the
installed server binaries); when neither is available the tests using these fixtures skip.
"""
import asyncio
import pathlib
import subprocess
import uuid

import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy.ext.asyncio import create_async_engine

from tests import pgserver

ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def admin_url():
    try:
        return pgserver.admin_url()
    except (RuntimeError, OSError, KeyError, subprocess.CalledProcessError) as e:
        pytest.skip(f"no PostgreSQL available: {getattr(e, 'stderr', None) or e!r}")


def run_sql(url, sql, params=None):
    async def go():
        engine = create_async_engine(url, isolation_level="AUTOCOMMIT")
        try:
            async with engine.connect() as c:
                r = await c.execute(sa.text(sql), params or {})
                return [tuple(x) for x in r.fetchall()] if r.returns_rows else None
        finally:
            await engine.dispose()
    return asyncio.run(go())


@pytest.fixture
def db(admin_url):
    """(url, alembic Config) for a fresh empty database, dropped afterwards."""
    name = "t_" + uuid.uuid4().hex[:12]
    run_sql(admin_url, f'CREATE DATABASE "{name}"')
    url = admin_url.rsplit("/", 1)[0] + "/" + name
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    yield url, cfg
    run_sql(admin_url, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
