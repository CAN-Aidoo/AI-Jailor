"""Migration 009 rewrites existing executions.environment to names -> [redacted]."""
import importlib.util
import json
import pathlib
import uuid

import pytest
import sqlalchemy as sa
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

PATH = pathlib.Path(__file__).resolve().parents[2] / "migrations/versions/009_redact_execution_environment.py"
SECRET = "sentinel-value-that-must-never-be-stored"


def load():
    spec = importlib.util.spec_from_file_location("m009", PATH)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def conn():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as c:
        c.execute(sa.text(
            "CREATE TABLE executions (id TEXT PRIMARY KEY, command TEXT, environment JSON, stdout TEXT)"
        ))
        yield c


def put(conn, env, command="echo hi", raw=False):
    rid = str(uuid.uuid4())
    value = env if raw else (None if env is None else json.dumps(env))
    conn.execute(
        sa.text("INSERT INTO executions VALUES (:i, :c, :e, :o)"),
        {"i": rid, "c": command, "e": value, "o": "out"},
    )
    return rid


def env_of(conn, rid):
    v = conn.execute(sa.text("SELECT environment FROM executions WHERE id=:i"), {"i": rid}).scalar()
    return None if v is None else json.loads(v)


def run(conn, module):
    with Operations.context(MigrationContext.configure(conn)):
        module.upgrade()


def test_revision_chain():
    m = load()
    assert m.down_revision == "008_peer_links"
    assert m.revision == "009_redact_execution_environment"


def test_values_are_replaced_and_names_kept(conn):
    rid = put(conn, {"API_TOKEN": SECRET, "X": "1", "DB_URL": "postgres://u:p@h/d"})
    run(conn, load())
    assert env_of(conn, rid) == {"API_TOKEN": "[redacted]", "X": "[redacted]", "DB_URL": "[redacted]"}
    raw = conn.execute(sa.text("SELECT * FROM executions")).fetchall()
    assert SECRET not in repr(raw)


def test_other_columns_untouched(conn):
    rid = put(conn, {"A": SECRET}, command="run-me")
    run(conn, load())
    row = conn.execute(sa.text("SELECT command, stdout FROM executions WHERE id=:i"), {"i": rid}).one()
    assert tuple(row) == ("run-me", "out")


def test_empty_null_and_already_redacted_rows_are_left_alone(conn):
    empty, null, done = put(conn, {}), put(conn, None), put(conn, {"A": "[redacted]"})
    run(conn, load())
    assert env_of(conn, empty) == {} and env_of(conn, null) is None and env_of(conn, done) == {"A": "[redacted]"}


def test_unexpected_shapes_do_not_break_the_migration(conn):
    listy = put(conn, ["a", "b"])
    mixed = put(conn, {"A": SECRET, "B": "[redacted]"})
    run(conn, load())
    assert env_of(conn, listy) == ["a", "b"]
    assert env_of(conn, mixed) == {"A": "[redacted]", "B": "[redacted]"}


def test_runs_twice_harmlessly(conn):
    rid = put(conn, {"A": SECRET})
    m = load()
    run(conn, m)
    run(conn, m)
    assert env_of(conn, rid) == {"A": "[redacted]"}


def test_every_row_is_reached_across_batches(conn):
    m = load()
    m.BATCH = 3
    ids = [put(conn, {"K": f"{SECRET}-{n}"}) for n in range(10)]
    run(conn, m)
    assert [env_of(conn, i) for i in ids] == [{"K": "[redacted]"}] * 10


def test_downgrade_is_a_documented_noop(conn):
    rid = put(conn, {"A": "[redacted]"})
    with Operations.context(MigrationContext.configure(conn)):
        load().downgrade()
    assert env_of(conn, rid) == {"A": "[redacted]"}
    assert "IRREVERSIBLE" in PATH.read_text()


def test_short_and_empty_values_are_redacted_too(conn):
    rid = put(conn, {"X": "1", "Y": ""})
    run(conn, load())
    assert env_of(conn, rid) == {"X": "[redacted]", "Y": "[redacted]"}
