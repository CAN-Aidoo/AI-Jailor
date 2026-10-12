"""AIJAILER_TEST_DB selects the database the whole suite runs on; make sure it is really honoured."""
import os

import pytest

from tests import pgserver


async def test_the_shared_engine_is_the_database_that_was_asked_for(db_engine):
    expected = "postgresql" if pgserver.use_postgres() else "sqlite"
    assert db_engine.dialect.name == expected


@pytest.mark.skipif(not pgserver.use_postgres(), reason="PostgreSQL run only")
async def test_a_postgres_run_is_on_a_real_server(db_engine):
    import sqlalchemy as sa
    async with db_engine.connect() as c:
        version = (await c.execute(sa.text("select version()"))).scalar()
    assert version.startswith("PostgreSQL")


def test_the_selector_values():
    old = os.environ.get("AIJAILER_TEST_DB")
    try:
        for value, want in (("postgres", True), ("PostgreSQL", True), ("pg", True), ("sqlite", False), ("", False)):
            os.environ["AIJAILER_TEST_DB"] = value
            assert pgserver.use_postgres() is want, value
        del os.environ["AIJAILER_TEST_DB"]
        assert pgserver.use_postgres() is False
    finally:
        if old is None:
            os.environ.pop("AIJAILER_TEST_DB", None)
        else:
            os.environ["AIJAILER_TEST_DB"] = old
