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

# Differences that are known and harmless, and that this check deliberately tolerates:
#  - modify_nullable: timestamp/JSON columns the models call NOT NULL but older migrations left nullable
#  - remove_fk / remove_index: foreign keys and indexes the migrations create that the models do not declare
# Anything else (a missing table or column, a changed type or length) is drift that matters and fails.
TOLERATED = {"modify_nullable", "remove_fk", "remove_index"}


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


def test_no_drift_beyond_the_known_harmless_kinds(db):
    url, cfg = db
    command.upgrade(cfg, "head")
    bad = [d for d in model_diffs(url) if d[0] not in TOLERATED]
    assert bad == [], [(d[0], _table_of(d)) for d in bad]


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
