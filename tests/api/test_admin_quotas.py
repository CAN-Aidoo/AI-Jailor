"""Operator API for per-tenant snapshot quota limits."""

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from aijailer.models.audit import EventType
from aijailer.models.tenant import Tenant
from aijailer.services import quota_metrics
from aijailer.services.audit_service import get_audit_service
from aijailer.services.tenant_quota import DEFAULTS, FIELDS

OP = {"Authorization": "Bearer op-secret"}


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("ADMIN_TOKEN", "op-secret")       # get_settings() is uncached
    monkeypatch.setenv("METRICS_TOKEN", "scrape")
    quota_metrics.reset_denials()


def url(tid):
    return f"/v1/admin/tenants/{tid}/quotas"


def test_defaults_match_the_tenant_column_defaults():
    for name, (default, _) in FIELDS.items():
        assert getattr(Tenant, name).default.arg == default, name


@pytest.mark.asyncio
async def test_operator_api_is_disabled_without_a_token_and_rejects_tenant_keys(
        client: AsyncClient, test_tenant, test_api_key, monkeypatch):
    u = url(test_tenant.id)
    assert (await client.get(u, headers=OP)).status_code == 200
    assert (await client.get(u)).status_code == 401
    assert (await client.get(u, headers={"Authorization": "Bearer wrong"})).status_code == 401
    # the tenant's OWN admin key must not be able to raise its limits
    own = {"Authorization": f"Bearer {test_api_key}"}
    for call in (client.get(u, headers=own), client.patch(u, headers=own, json={"max_snapshot_count": 10**6}),
                 client.delete(u, headers=own)):
        assert (await call).status_code == 401
    monkeypatch.setenv("ADMIN_TOKEN", "")
    assert (await client.get(u, headers=OP)).status_code == 404                # disabled, not open


@pytest.mark.asyncio
async def test_get_shows_limits_defaults_and_usage(client: AsyncClient, test_tenant):
    r = (await client.get(url(test_tenant.id), headers=OP)).json()["data"]
    assert r["limits"] == DEFAULTS and r["defaults"] == DEFAULTS
    assert r["usage"] == {"snapshots": 0, "snapshot_bytes": 0} and r["over_limit"] == []


@pytest.mark.asyncio
async def test_partial_update_changes_only_what_was_sent_and_takes_effect_immediately(
        client: AsyncClient, test_tenant):
    cell = (await client.post("/v1/cells", json={"name": "c", "image": "base-python"})).json()["data"]["id"]
    r = await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshots_per_cell": 1})
    assert r.status_code == 200
    lim = r.json()["data"]["limits"]
    assert lim["max_snapshots_per_cell"] == 1 and lim["max_snapshot_count"] == 100
    assert (await client.post(f"/v1/cells/{cell}/snapshots", json={})).status_code == 202
    denied = await client.post(f"/v1/cells/{cell}/snapshots", json={})
    assert denied.status_code == 429 and "snapshots_per_cell" in denied.text
    # raising it lets the tenant continue, no restart needed
    await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshots_per_cell": 5})
    assert (await client.post(f"/v1/cells/{cell}/snapshots", json={})).status_code == 202
    # the metrics reflect the new limit on the next scrape
    text = (await client.get("/metrics", headers={"Authorization": "Bearer scrape"})).text
    assert (f'aijailer_snapshot_quota_limit{{quota="snapshots_per_cell",tenant="{test_tenant.id}"}} 5'
            in text)


@pytest.mark.asyncio
async def test_lowering_below_usage_keeps_snapshots_refuses_new_and_reports_it(
        client: AsyncClient, test_tenant):
    cell = (await client.post("/v1/cells", json={"name": "c", "image": "base-python"})).json()["data"]["id"]
    for _ in range(3):
        await client.post(f"/v1/cells/{cell}/snapshots", json={})
    r = (await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshot_count": 1})).json()["data"]
    assert r["over_limit"] == ["max_snapshot_count"] and r["usage"]["snapshots"] == 3
    assert (await client.get(f"/v1/cells/{cell}/snapshots")).json()["data"].__len__() == 3
    assert (await client.post(f"/v1/cells/{cell}/snapshots", json={})).status_code == 429
    # zero forbids new snapshots outright
    await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshot_count": 0})
    assert (await client.post(f"/v1/cells/{cell}/snapshots", json={})).status_code == 429


@pytest.mark.asyncio
@pytest.mark.parametrize("body,status", [
    ({}, 400),                                                   # nothing to change
    ({"max_snapshot_count": -1}, 400),
    ({"max_snapshot_count": 10**9}, 400),                        # typo guard
    ({"max_snapshot_count": None}, 400),
    ({"max_snapshot_count": 1.5}, 422), ({"max_snapshot_count": "5"}, 422),
    ({"max_snapshot_count": True}, 422),
    ({"max_snapshot_cuont": 5}, 422),                            # unknown field must not no-op
])
async def test_invalid_updates_are_rejected_and_change_nothing(client: AsyncClient, test_tenant, body, status):
    r = await client.patch(url(test_tenant.id), headers=OP, json=body)
    assert r.status_code == status, r.text
    assert (await client.get(url(test_tenant.id), headers=OP)).json()["data"]["limits"] == DEFAULTS


@pytest.mark.asyncio
async def test_inconsistent_limits_are_allowed_but_warned_about(client: AsyncClient, test_tenant):
    r = (await client.patch(url(test_tenant.id), headers=OP, json={
        "max_snapshots_per_cell": 500, "max_snapshot_storage_per_cell_gb": 999})).json()["data"]
    assert len(r["warnings"]) == 2 and "tenant total" in r["warnings"][0]


@pytest.mark.asyncio
async def test_delete_resets_to_defaults_and_unknown_tenant_404s(client: AsyncClient, test_tenant):
    await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshot_count": 7, "max_snapshots_per_cell": 3})
    r = (await client.delete(url(test_tenant.id), headers=OP)).json()["data"]
    assert r["limits"] == DEFAULTS
    ghost = uuid.uuid4()
    for call in (client.get(url(ghost), headers=OP), client.patch(url(ghost), headers=OP, json={"max_snapshot_count": 1}),
                 client.delete(url(ghost), headers=OP)):
        res = await call
        assert res.status_code == 404 and "tenant_not_found" in res.text


@pytest.mark.asyncio
async def test_changes_are_audited_with_before_and_after_and_noops_are_not(client: AsyncClient, test_tenant):
    audit = get_audit_service()
    await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshot_count": 7})
    await client.patch(url(test_tenant.id), headers=OP, json={"max_snapshot_count": 7})     # no-op
    events = [e for e in await _events(audit, test_tenant.id) if e.details.get("action") == "quota_override_set"]
    assert len(events) == 1
    d = events[0].details
    assert d["from"] == {"max_snapshot_count": 100} and d["to"] == {"max_snapshot_count": 7}
    assert d["actor"] == "operator" and events[0].event_type == EventType.LIFECYCLE


async def _events(audit, tenant_id):
    return await audit.query_events(tenant_id)


def test_validate_rejects_bools_floats_and_out_of_range_directly():
    from aijailer.core.exceptions import AiJailerError
    from aijailer.services.tenant_quota import validate
    for bad in (True, False, 1.5, "3", -1, 10**9, None):
        with pytest.raises(AiJailerError):
            validate({"max_snapshot_count": bad})
    assert validate({"max_snapshot_count": 0}) == {"max_snapshot_count": 0}


@pytest.mark.asyncio
async def test_update_takes_the_tenant_row_lock(monkeypatch):
    """SQLite ignores FOR UPDATE, so assert the statement that would reach Postgres has it: the
    change must serialize with SnapshotService._reserve, which locks the same row."""
    from sqlalchemy.dialects import postgresql

    from aijailer.services.tenant_quota import TenantQuotaService
    seen = []

    class Db:
        async def execute(self, stmt):
            seen.append(str(stmt.compile(dialect=postgresql.dialect())))
            raise RuntimeError("stop")
    with pytest.raises(RuntimeError):
        await TenantQuotaService(Db()).update(uuid.uuid4(), {"max_snapshot_count": 1})
    with pytest.raises(RuntimeError):
        await TenantQuotaService(Db()).get(uuid.uuid4())
    assert "FOR UPDATE" in seen[0] and "FOR UPDATE" not in seen[1]
