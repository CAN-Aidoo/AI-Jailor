"""PostgreSQL for the test suite.

Default: the suite runs on SQLite, as before. Set AIJAILER_TEST_DB=postgres to run it on PostgreSQL:

    AIJAILER_TEST_DB=postgres pytest

Where the server comes from (first match wins):
  * AIJAILER_TEST_PG_URL=postgresql+asyncpg://user:pw@host:port/postgres  an existing server; the suite creates
    its own throwaway databases on it and drops them at the end;
  * the server binaries (initdb/pg_ctl under /usr/lib/postgresql/*/bin or on PATH): a private throwaway cluster
    on a free local port (run as the `postgres` user when started as root), removed at exit.
If neither exists the PostgreSQL run fails loudly instead of quietly falling back to SQLite.
"""
import asyncio
import atexit
import glob
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import uuid

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

_cluster: dict = {}
_databases: list[str] = []
_schema_ready: dict[str, bool] = {}


def use_postgres() -> bool:
    return os.environ.get("AIJAILER_TEST_DB", "sqlite").lower() in ("postgres", "postgresql", "pg")


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


def admin_url() -> str:
    """URL of the maintenance database; starts a private cluster the first time if none was given."""
    if _cluster.get("url"):
        return _cluster["url"]
    given = os.environ.get("AIJAILER_TEST_PG_URL", "")
    if given:
        _cluster["url"] = given
        return given
    bindir = _bindir()
    if not bindir:
        raise RuntimeError("AIJAILER_TEST_DB=postgres but no server: set AIJAILER_TEST_PG_URL or install postgresql")
    root = tempfile.mkdtemp(prefix="aijailer-pg-")
    os.chmod(root, 0o755)
    prefix: list[str] = []
    if os.geteuid() == 0:                                  # postgres refuses to run as root
        subprocess.run(["id", "-u", "postgres"], check=True, capture_output=True)   # no such user: fail loudly
        shutil.chown(root, "postgres")
        prefix = ["runuser", "-u", "postgres", "--"]
    data, port = f"{root}/data", _free_port()
    subprocess.run([*prefix, f"{bindir}/initdb", "-D", data, "-A", "trust", "-U", "postgres"],
                   check=True, capture_output=True)
    # Tests do not need durability: fsync off makes create/drop of tables and databases much faster.
    subprocess.run([*prefix, f"{bindir}/pg_ctl", "-D", data, "-w", "-l", f"{root}/log", "-o",
                    f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -c fsync=off "
                    f"-c synchronous_commit=off -c full_page_writes=off -c max_connections=200", "start"],
                   check=True, capture_output=True)

    def stop():
        subprocess.run([*prefix, f"{bindir}/pg_ctl", "-D", data, "-m", "immediate", "stop"], capture_output=True)
        shutil.rmtree(root, ignore_errors=True)
    atexit.register(stop)
    _cluster["url"] = f"postgresql+asyncpg://postgres@127.0.0.1:{port}/postgres"
    return _cluster["url"]


def _with_db(url: str, name: str) -> str:
    return url.rsplit("/", 1)[0] + "/" + name


async def _admin(sql: str):
    engine = create_async_engine(admin_url(), isolation_level="AUTOCOMMIT", poolclass=NullPool)
    try:
        async with engine.connect() as c:
            await c.execute(sa.text(sql))
    finally:
        await engine.dispose()


async def new_database(prefix: str = "t") -> str:
    """A fresh, empty database on the server; returns its URL. Dropped at exit by drop_all_databases()."""
    name = f"{prefix}_{uuid.uuid4().hex[:12]}"
    await _admin(f'CREATE DATABASE "{name}"')
    _databases.append(name)
    return _with_db(admin_url(), name)


async def drop_database(url: str) -> None:
    name = url.rsplit("/", 1)[1]
    await _admin(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
    if name in _databases:
        _databases.remove(name)


async def shared_database(metadata) -> str:
    """One database per process with the full model schema, reused by tests that empty it between runs."""
    if "shared" not in _schema_ready:
        url = await new_database("shared")
        engine = create_async_engine(url, poolclass=NullPool)
        try:
            async with engine.begin() as c:
                await c.run_sync(metadata.create_all)
        finally:
            await engine.dispose()
        _schema_ready["shared"] = url
    return _schema_ready["shared"]


async def empty_all_tables(engine, metadata) -> None:
    names = ", ".join(f'"{t.name}"' for t in metadata.sorted_tables)
    async with engine.begin() as c:
        await c.execute(sa.text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
