"""The migrated PostgreSQL schema vs the ORM models, and migration 011 (the tables that had no migration).

The rest of the suite builds its schema from the models (`create_all`), so a model with no migration is invisible
to it: a database made with `alembic upgrade head` would simply lack the table. These tests build the schema the
way production does, with the real Alembic chain, and compare.
"""
import asyncio
import uuid

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy.ext.asyncio import create_async_engine

import aijailer.api.app  # noqa: F401  (imports every model so Base.metadata is complete)
from aijailer.db.base import Base
from tests.pgmigrate import admin_url, db, run_sql  # noqa: F401  (fixtures)

NEW_TABLES = {"certified_components", "constraints", "attack_patterns", "generation_log", "security_certificates"}
NEW_TENANT_COLUMNS = {"compliance_requirements", "custom_constraints", "monthly_generation_limit"}

# There is no tolerated drift: the migrated schema must match the models in tables, columns, types, lengths,
# nullability, foreign keys and indexes. (It used to tolerate NOT NULL / foreign-key / index differences on older
# tables; migration 012 and the model fixes removed them.)
TOLERATED: set[str] = set()


def _flatten(diffs):
    for d in diffs:
        if isinstance(d, list):
            yield from _flatten(d)
        else:
            yield d


def _table_of(diff):
    kind = diff[0]
    if kind in ("add_table", "remove_table"):
        return diff[1].name
    if kind in ("add_column", "remove_column"):
        return diff[2]
    if kind.startswith("modify_"):
        return diff[2]
    if kind in ("add_index", "remove_index"):
        return diff[1].table.name
    if kind in ("add_fk", "remove_fk"):
        return diff[1].table.name
    return None


def model_diffs(url):
    async def go():
        engine = create_async_engine(url)
        try:
            async with engine.connect() as c:
                return await c.run_sync(lambda sc: list(_flatten(compare_metadata(
                    MigrationContext.configure(sc, opts={"compare_type": True}), Base.metadata))))
        finally:
            await engine.dispose()
    return asyncio.run(go())


def test_the_migrated_schema_has_every_table_and_column_the_models_declare(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    have = {(t, c) for t, c in run_sql(
        url, "SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = 'public'")}
    missing = sorted(f"{t.name}.{c.name}" for t in Base.metadata.sorted_tables for c in t.columns
                     if (t.name, c.name) not in have)
    assert missing == []


def test_the_migrated_schema_has_no_drift_from_the_models(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    bad = [d for d in model_diffs(url) if d[0] not in TOLERATED]
    assert bad == [], [(d[0], _table_of(d), d[3] if d[0].startswith("modify_") else None) for d in bad]


def test_the_tables_added_by_011_match_their_models_exactly(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    mine = [(d[0], _table_of(d)) for d in model_diffs(url) if _table_of(d) in NEW_TABLES]
    assert mine == []                                        # not even a nullability difference


def test_011_backfills_existing_tenants_and_enforces_not_null(db):
    url, cfg = db
    command.upgrade(cfg, "010_tenant_secret_key_id_length")
    tid = uuid.uuid4()
    run_sql(url, "INSERT INTO tenants (id, name, slug) VALUES (:t, 'Old', 'old')", {"t": tid})

    command.upgrade(cfg, "head")

    assert run_sql(url, "SELECT compliance_requirements::text, custom_constraints::text, monthly_generation_limit "
                        "FROM tenants WHERE id = :t", {"t": tid}) == [("[]", "[]", None)]
    with pytest.raises(Exception, match="null value in column"):
        run_sql(url, "INSERT INTO tenants (id, name, slug, compliance_requirements) VALUES (:t, 'X', 'x', NULL)",
                {"t": uuid.uuid4()})
    run_sql(url, "UPDATE tenants SET compliance_requirements = '[\"HIPAA\"]', monthly_generation_limit = 5 "
                 "WHERE id = :t", {"t": tid})
    assert run_sql(url, "SELECT compliance_requirements::text, monthly_generation_limit FROM tenants "
                        "WHERE id = :t", {"t": tid}) == [('["HIPAA"]', 5)]


def test_the_new_tables_accept_rows_with_their_foreign_keys_and_defaults(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    tenant, cid, gid, comp = uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()

    run_sql(url, "INSERT INTO certified_components (id, name, version, language, category, source_code) "
                 "VALUES (:i, 'argon2', '1.0', 'python', 'crypto', 'x')", {"i": comp})
    run_sql(url, "INSERT INTO constraints (id, name, category, severity, applies_when, rules, source) "
                 "VALUES (:i, 'no-eval', 'injection', 'HIGH', '{}', '{}', 'manual')", {"i": cid})
    run_sql(url, "INSERT INTO attack_patterns (id, pattern_signature, vulnerability_class, attack_vector, "
                 "generated_constraint_id, severity) VALUES (:i, 'sig', 'CWE-95', 'eval', :c, 'HIGH')",
            {"i": uuid.uuid4(), "c": cid})
    run_sql(url, "INSERT INTO generation_log (id, tenant_id, intent, constraints_applied, components_used, "
                 "output_hash, security_certificate, latency_ms) "
                 "VALUES (:g, :t, '{}', ARRAY[CAST(:c AS uuid)], ARRAY[CAST(:p AS uuid)], 'h', '{}', 12)",
            {"g": gid, "t": tenant, "c": cid, "p": comp})
    run_sql(url, "INSERT INTO security_certificates (id, generation_id, tenant_id, constraints_satisfied, "
                 "compliance_frameworks, components_versions, certificate_hash, valid_until) "
                 "VALUES (:i, :g, :t, '{}', '{}', '{}', 'h', now())", {"i": uuid.uuid4(), "g": gid, "t": tenant})

    # server-side defaults for rows inserted without the ORM
    assert run_sql(url, "SELECT status, compliance_certs::text, cve_coverage::text FROM certified_components") \
        == [("active", "[]", "[]")]
    assert run_sql(url, "SELECT is_active FROM constraints") == [(True,)]
    assert run_sql(url, "SELECT occurrence_count, status FROM attack_patterns") == [(1, "active")]
    assert run_sql(url, "SELECT blocked FROM generation_log") == [(False,)]
    assert run_sql(url, "SELECT revoked FROM security_certificates") == [(False,)]

    # the foreign keys are real: a certificate cannot point at a generation that does not exist
    with pytest.raises(Exception, match="foreign key"):
        run_sql(url, "INSERT INTO security_certificates (id, generation_id, tenant_id, constraints_satisfied, "
                     "compliance_frameworks, components_versions, certificate_hash, valid_until) "
                     "VALUES (:i, :g, :t, '{}', '{}', '{}', 'h', now())",
                {"i": uuid.uuid4(), "g": uuid.uuid4(), "t": tenant})


def test_011_downgrade_drops_exactly_what_it_added_and_upgrade_restores_it(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "010_tenant_secret_key_id_length")
    tables = {r[0] for r in run_sql(url, "SELECT table_name FROM information_schema.tables "
                                         "WHERE table_schema = 'public'")}
    assert not (NEW_TABLES & tables)
    cols = {r[0] for r in run_sql(url, "SELECT column_name FROM information_schema.columns "
                                       "WHERE table_name = 'tenants'")}
    assert not (NEW_TENANT_COLUMNS & cols)
    command.upgrade(cfg, "head")
    tables = {r[0] for r in run_sql(url, "SELECT table_name FROM information_schema.tables "
                                         "WHERE table_schema = 'public'")}
    assert NEW_TABLES <= tables


def test_012_backfills_nulls_with_the_column_defaults_and_enforces_not_null(db):
    url, cfg = db
    command.upgrade(cfg, "011_codeimmune_tables")
    tid, pid, cid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    # rows with explicit NULLs in columns that are about to become NOT NULL
    run_sql(url, "INSERT INTO tenants (id, name, slug, created_at, updated_at) VALUES (:t, 'T', 'tt', NULL, NULL)", {"t": tid})
    run_sql(url, "INSERT INTO security_policies (id, name, network_policy, filesystem_policy, syscall_policy, "
                 "resource_policy, capability_policy, created_at) VALUES (:p, 'p', '{}', '{}', '{}', '{}', '{}', NULL)",
            {"p": pid})
    run_sql(url, "INSERT INTO cells (id, tenant_id, image, security_policy_id, environment, tags, working_directory, "
                 "created_at) VALUES (:c, :t, 'img', :p, NULL, NULL, NULL, NULL)", {"c": cid, "t": tid, "p": pid})
    run_sql(url, "INSERT INTO executions (id, cell_id, tenant_id, command, environment, user_context, started_at) "
                 "VALUES (:i, :c, :t, 'x', NULL, NULL, NULL)", {"i": uuid.uuid4(), "c": cid, "t": tid})

    command.upgrade(cfg, "head")

    assert run_sql(url, "SELECT created_at IS NOT NULL, updated_at IS NOT NULL FROM tenants") == [(True, True)]
    assert run_sql(url, "SELECT environment::text, tags::text, working_directory, created_at IS NOT NULL FROM cells") \
        == [("{}", "{}", "/home/agent", True)]
    assert run_sql(url, "SELECT environment::text, user_context, started_at IS NOT NULL FROM executions") \
        == [("{}", "agent", True)]
    with pytest.raises(Exception, match="null value in column"):
        run_sql(url, "UPDATE tenants SET created_at = NULL")
    with pytest.raises(Exception, match="null value in column"):
        run_sql(url, "UPDATE cells SET tags = NULL")


def test_012_downgrade_relaxes_not_null_again_and_keeps_the_values(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    tid = uuid.uuid4()
    run_sql(url, "INSERT INTO tenants (id, name, slug) VALUES (:t, 'T', 'tt')", {"t": tid})
    command.downgrade(cfg, "011_codeimmune_tables")
    run_sql(url, "UPDATE tenants SET created_at = NULL")             # allowed again
    command.upgrade(cfg, "head")                                      # and re-tightened
    assert run_sql(url, "SELECT created_at IS NOT NULL FROM tenants") == [(True,)]


def test_the_foreign_keys_and_indexes_the_models_declare_exist_in_the_migrated_schema(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    fks = {r[0] for r in run_sql(url, "SELECT conname FROM pg_constraint WHERE contype = 'f'")}
    assert {"cells_tenant_id_fkey", "executions_cell_id_fkey", "snapshots_cell_id_fkey",
            "webhooks_tenant_id_fkey"} <= fks
    idx = {r[0] for r in run_sql(url, "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'")}
    assert {"ix_cells_tenant_status", "ix_executions_cell_started", "ix_snapshots_cell_created"} <= idx
