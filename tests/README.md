# Running the tests

```bash
pytest                                  # default: SQLite (in-memory / temp files), fast, nothing to install
AIJAILER_TEST_DB=postgres pytest        # the whole suite on PostgreSQL
```

`AIJAILER_TEST_DB=postgres` needs a PostgreSQL server, found in this order (see `tests/pgserver.py`):

1. `AIJAILER_TEST_PG_URL=postgresql+asyncpg://user:pw@host:port/postgres` — an existing server. The suite creates its own
   throwaway databases on it and drops them; it never touches your existing databases.
2. The server binaries (`initdb`/`pg_ctl` under `/usr/lib/postgresql/*/bin` or on `PATH`) — a private cluster on a
   free local port, with `fsync` off, removed at exit. When started as root it runs as the `postgres` user.

If neither is available a PostgreSQL run **fails** instead of quietly falling back to SQLite.

Why both: SQLite does not enforce `VARCHAR(n)` lengths, foreign keys by default, or most type rules, so some bugs only
show on PostgreSQL (for example `tenant_secrets.key_id` was `VARCHAR(64)` while a KMS key ARN is longer; migration 010).
The shared engine fixture (`db_engine`) uses one database with the model schema and truncates every table after each
test. Tests that build their own engine (audit store, quota concurrency) get a fresh database per test; the quota
concurrency tests run on plain PostgreSQL there, with no `BEGIN IMMEDIATE` emulation.

`tests/services/test_redact_migration_postgres.py` always uses PostgreSQL (it runs the real Alembic chain) and skips
when no server is available.

Not covered by either mode: anything that needs `/dev/kvm`, real jailer assets, or a booted Firecracker cell (those tests skip).
