"""Migration 009 on a real PostgreSQL (JSONB, UUID keys), through the real Alembic chain.

Where the server comes from:
  * AIJAILER_TEST_PG_URL=postgresql+asyncpg://user:pw@host:port/postgres  -> uses that server and creates and
    drops one throwaway database on it;
  * otherwise, if PostgreSQL's server binaries are installed (initdb/pg_ctl under /usr/lib/postgresql/*/bin or
    on PATH), starts a private throwaway cluster on a free local port (as the `postgres` user when run as root);
  * otherwise the tests skip.
"""
import asyncio
import glob
import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import uuid

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.ext.asyncio import create_async_engine

ROOT = pathlib.Path(__file__).resolve().parents[2]
SECRET = "sentinel-value-that-must-never-be-stored"
ENV_URL = os.environ.get("AIJAILER_TEST_PG_URL", "")


def _bindir() -> str | None:
    found = sorted(glob.glob("/usr/lib/postgresql/*/bin/initdb"))
    if found:
        return str(pathlib.Path(found[-1]).parent)
    w = shutil.which("initdb")
    return str(pathlib.Path(w).parent) if w else None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def admin_url():
    if ENV_URL:
        yield ENV_URL
        return
    bindir = _bindir()
    if not bindir:
        pytest.skip("no PostgreSQL server: set AIJAILER_TEST_PG_URL or install postgresql")
    root = tempfile.mkdtemp(prefix="aijailer-pg-")
    os.chmod(root, 0o755)
    prefix = []
    if os.geteuid() == 0:                       # postgres refuses to run as root
        import pwd
        try:
            pwd.getpwnam("postgres")
        except KeyError:
            shutil.rmtree(root, ignore_errors=True)
            pytest.skip("running as root and there is no `postgres` user to run the server as")
        shutil.chown(root, "postgres")
        prefix = ["runuser", "-u", "postgres", "--"]
    data, port = f"{root}/data", _free_port()
    try:
        subprocess.run([*prefix, f"{bindir}/initdb", "-D", data, "-A", "trust", "-U", "postgres"],
                       check=True, capture_output=True)
        subprocess.run([*prefix, f"{bindir}/pg_ctl", "-D", data, "-w", "-l", f"{root}/log", "-o",
                        f"-p {port} -k {root} -c listen_addresses=127.0.0.1", "start"],
                       check=True, capture_output=True)
    except (subprocess.CalledProcessError, OSError) as e:
        shutil.rmtree(root, ignore_errors=True)
        pytest.skip(f"could not start a throwaway PostgreSQL: {getattr(e, 'stderr', e)!r}")
    try:
        yield f"postgresql+asyncpg://postgres@127.0.0.1:{port}/postgres"
    finally:
        subprocess.run([*prefix, f"{bindir}/pg_ctl", "-D", data, "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(root, ignore_errors=True)


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
    name = "t_" + uuid.uuid4().hex[:12]
    run_sql(admin_url, f'CREATE DATABASE "{name}"')
    url = admin_url.rsplit("/", 1)[0] + "/" + name
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    yield url, cfg
    run_sql(admin_url, f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


def seed_parents(url):
    """executions has a real foreign key to cells, which needs a tenant and a policy."""
    tenant, policy, cell = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    run_sql(url, "INSERT INTO tenants (id, name, slug) VALUES (:t, 'T', :s)", {"t": tenant, "s": "t-" + tenant.hex[:8]})
    run_sql(url, "INSERT INTO security_policies (id, name, network_policy, filesystem_policy, syscall_policy, "
                 "resource_policy, capability_policy) VALUES (:p, 'p', '{}', '{}', '{}', '{}', '{}')", {"p": policy})
    run_sql(url, "INSERT INTO cells (id, tenant_id, image, security_policy_id) VALUES (:c, :t, 'img', :p)",
            {"c": cell, "t": tenant, "p": policy})
    return tenant, cell


def insert(url, parents, env_sql, command_text="echo hi"):
    rid = uuid.uuid4()
    tenant, cell = parents
    run_sql(
        url,
        f"INSERT INTO executions (id, cell_id, tenant_id, command, stdout, environment) "
        f"VALUES (:i, :c, :t, :cmd, 'out', {env_sql})",
        {"i": rid, "c": cell, "t": tenant, "cmd": command_text},
    )
    return rid


def env_of(url, rid):
    ((v,),) = run_sql(url, "SELECT environment::text FROM executions WHERE id = :i", {"i": rid})
    return None if v is None else json.loads(v)


def test_full_chain_on_postgres_redacts_existing_rows(db):
    url, cfg = db
    command.upgrade(cfg, "008_peer_links")
    parents = seed_parents(url)

    plain = insert(url, parents, f"CAST('{json.dumps({'API_TOKEN': SECRET, 'X': '1', 'DB_URL': 'postgres://u:p@h/d'})}' AS jsonb)",
                   command_text="run-me")
    unicode_ = insert(url, parents, f"CAST('{json.dumps({'ÜBER': 'wert-ä'})}' AS jsonb)")
    mixed = insert(url, parents, f"CAST('{json.dumps({'A': SECRET, 'B': '[redacted]'})}' AS jsonb)")
    done = insert(url, parents, "CAST('{\"A\": \"[redacted]\"}' AS jsonb)")
    empty = insert(url, parents, "CAST('{}' AS jsonb)")
    null = insert(url, parents, "NULL")
    json_null = insert(url, parents, "CAST('null' AS jsonb)")
    listy = insert(url, parents, "CAST('[\"a\", \"b\"]' AS jsonb)")
    # more rows than one batch, random uuid keys, so the keyset paging is exercised on the real UUID type
    run_sql(url, "INSERT INTO executions (id, cell_id, tenant_id, command, environment) "
                 "SELECT gen_random_uuid(), :c, :t, 'bulk', "
                 f"jsonb_build_object('K', '{SECRET}-' || g) FROM generate_series(1, 2500) g",
            {"c": parents[1], "t": parents[0]})
    before_others = run_sql(url, "SELECT id::text, environment::text FROM executions WHERE id = ANY(:ids)",
                            {"ids": [done, empty, null, json_null, listy]})

    command.upgrade(cfg, "head")

    assert env_of(url, plain) == {"API_TOKEN": "[redacted]", "X": "[redacted]", "DB_URL": "[redacted]"}
    assert env_of(url, unicode_) == {"ÜBER": "[redacted]"}
    assert env_of(url, mixed) == {"A": "[redacted]", "B": "[redacted]"}
    assert env_of(url, done) == {"A": "[redacted]"} and env_of(url, empty) == {}
    assert env_of(url, null) is None and env_of(url, json_null) is None and env_of(url, listy) == ["a", "b"]
    assert run_sql(url, "SELECT environment::text FROM executions WHERE id = :i", {"i": json_null}) == [("null",)]

    assert run_sql(url, "SELECT count(*) FROM executions WHERE command = 'bulk' AND environment <> '{\"K\": \"[redacted]\"}'::jsonb") == [(0,)]
    assert run_sql(url, "SELECT count(*) FROM executions") == [(2508,)]
    assert run_sql(url, f"SELECT count(*) FROM executions WHERE executions::text LIKE '%{SECRET}%'") == [(0,)]
    assert run_sql(url, "SELECT command, stdout FROM executions WHERE id = :i", {"i": plain}) == [("run-me", "out")]
    assert run_sql(url, "SELECT id::text, environment::text FROM executions WHERE id = ANY(:ids)",
                   {"ids": [done, empty, null, json_null, listy]}) == before_others      # untouched rows are byte-identical


def test_downgrade_then_upgrade_again_is_harmless_on_postgres(db):
    url, cfg = db
    command.upgrade(cfg, "008_peer_links")
    parents = seed_parents(url)
    rid = insert(url, parents, f"CAST('{json.dumps({'A': SECRET})}' AS jsonb)")
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "008_peer_links")                       # data-only: nothing to undo, nothing restored
    assert env_of(url, rid) == {"A": "[redacted]"}
    command.upgrade(cfg, "head")
    assert env_of(url, rid) == {"A": "[redacted]"}
    assert run_sql(url, "SELECT version_num FROM alembic_version") == [("009_redact_execution_environment",)]
