"""Migration 009 on a real PostgreSQL (JSONB, UUID keys), through the real Alembic chain.

Where the server comes from:
  * AIJAILER_TEST_PG_URL=postgresql+asyncpg://user:pw@host:port/postgres  -> uses that server and creates and
    drops one throwaway database on it;
  * otherwise, if PostgreSQL's server binaries are installed (initdb/pg_ctl under /usr/lib/postgresql/*/bin or
    on PATH), starts a private throwaway cluster on a free local port (as the `postgres` user when run as root);
  * otherwise the tests skip.
"""
import json
import uuid

import pytest
from alembic import command
from alembic.script import ScriptDirectory

from tests.pgmigrate import admin_url, db, run_sql  # noqa: F401  (fixtures)

SECRET = "sentinel-value-that-must-never-be-stored"


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
    assert run_sql(url, "SELECT version_num FROM alembic_version") == [(ScriptDirectory.from_config(cfg).get_current_head(),)]


def test_batch_size_env_is_honoured_through_alembic_on_postgres(db, monkeypatch):
    url, cfg = db
    command.upgrade(cfg, "008_peer_links")
    parents = seed_parents(url)
    run_sql(url, "INSERT INTO executions (id, cell_id, tenant_id, command, environment) "
                 "SELECT gen_random_uuid(), :c, :t, 'bulk', "
                 f"jsonb_build_object('K', '{SECRET}-' || g) FROM generate_series(1, 25) g",
            {"c": parents[1], "t": parents[0]})
    monkeypatch.setenv("AIJAILER_REDACT_BATCH", "7")               # 7 + 7 + 7 + 4
    command.upgrade(cfg, "head")
    assert run_sql(url, "SELECT count(*) FROM executions WHERE environment = '{\"K\": \"[redacted]\"}'::jsonb") == [(25,)]


def test_a_bad_batch_size_fails_the_upgrade_and_leaves_the_data_alone_on_postgres(db, monkeypatch):
    url, cfg = db
    command.upgrade(cfg, "008_peer_links")
    rid = insert(url, seed_parents(url), f"CAST('{json.dumps({'A': SECRET})}' AS jsonb)")
    monkeypatch.setenv("AIJAILER_REDACT_BATCH", "0")
    with pytest.raises(ValueError, match="AIJAILER_REDACT_BATCH"):
        command.upgrade(cfg, "head")
    assert env_of(url, rid) == {"A": SECRET}
    assert run_sql(url, "SELECT version_num FROM alembic_version") == [("008_peer_links",)]   # not stamped


def test_a_full_kms_key_arn_fits_the_migrated_tenant_secrets_table(db):
    """tenant_secrets.key_id was VARCHAR(64); the KMS provider stores the full key ARN (about 76 characters).
    SQLite does not enforce VARCHAR lengths, so only PostgreSQL shows it."""
    url, cfg = db
    command.upgrade(cfg, "head")
    assert run_sql(url, "SELECT character_maximum_length FROM information_schema.columns "
                        "WHERE table_name = 'tenant_secrets' AND column_name = 'key_id'") == [(2048,)]
    tenant, _cell = seed_parents(url)
    arn = "arn:aws:kms:eu-central-1:123456789012:key/" + str(uuid.uuid4())
    assert len(arn) > 64
    run_sql(url, "INSERT INTO tenant_secrets (id, tenant_id, name, version, hosts, ciphertext, nonce, wrapped_dek, key_id) "
                 "VALUES (:i, :t, 's', 1, '[]', 'x', 'n', 'w', :k)", {"i": uuid.uuid4(), "t": tenant, "k": arn})
    assert run_sql(url, "SELECT key_id FROM tenant_secrets") == [(arn,)]


def test_the_key_id_migration_is_reversible_while_the_values_still_fit(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "009_redact_execution_environment")
    assert run_sql(url, "SELECT character_maximum_length FROM information_schema.columns "
                        "WHERE table_name = 'tenant_secrets' AND column_name = 'key_id'") == [(64,)]
