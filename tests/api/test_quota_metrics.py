"""Prometheus quota metrics: exposition format, auth, counting rules, denials."""

import re

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from aijailer.core import promtext
from aijailer.models.tenant import Tenant
from aijailer.services import quota_metrics


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    quota_metrics.reset_denials()
    monkeypatch.setenv("METRICS_TOKEN", "scrape-secret")       # get_settings() is uncached
    yield
    quota_metrics.reset_denials()


H = {"Authorization": "Bearer scrape-secret"}


def sample(text: str, name: str, **labels) -> float | None:
    for line in text.splitlines():
        m = re.fullmatch(rf"{name}\{{(.*)\}} (\S+)", line)
        if m and all(f'{k}="{v}"' in m.group(1) for k, v in labels.items()):
            return float(m.group(2))
    return None


async def _cell(client, name="m"):
    return (await client.post("/v1/cells", json={"name": name, "image": "base-python"})).json()["data"]["id"]


@pytest.mark.asyncio
async def test_metrics_endpoint_is_off_without_a_token_and_needs_the_right_one(client: AsyncClient, monkeypatch):
    assert (await client.get("/metrics", headers=H)).status_code == 200
    assert (await client.get("/metrics")).status_code == 401
    assert (await client.get("/metrics", headers={"Authorization": "Bearer wrong"})).status_code == 401
    assert (await client.get("/metrics", headers={"Authorization": "scrape-secret"})).status_code == 401
    monkeypatch.setenv("METRICS_TOKEN", "")
    assert (await client.get("/metrics", headers=H)).status_code == 404    # disabled, not open


@pytest.mark.asyncio
async def test_used_and_limit_gauges_track_snapshots(client: AsyncClient, test_tenant):
    tid = str(test_tenant.id)
    cell = await _cell(client)
    r = await client.get("/metrics", headers=H)
    assert r.headers["content-type"].startswith("text/plain; version=0.0.4")
    t = r.text
    assert sample(t, "aijailer_snapshot_quota_used", tenant=tid, quota="snapshots") == 0
    assert sample(t, "aijailer_snapshot_quota_limit", tenant=tid, quota="snapshots") == 100
    assert sample(t, "aijailer_snapshot_quota_limit", tenant=tid, quota="snapshots_per_cell") == 10
    assert sample(t, "aijailer_snapshot_quota_limit", tenant=tid,
                  quota="snapshot_storage") == 50 * (1 << 30)
    assert sample(t, "aijailer_snapshot_quota_limit", tenant=tid,
                  quota="snapshot_storage_per_cell") == 10 * (1 << 30)
    for _ in range(3):
        await client.post(f"/v1/cells/{cell}/snapshots", json={})
    other = await _cell(client, "o")
    await client.post(f"/v1/cells/{other}/snapshots", json={})
    t = (await client.get("/metrics", headers=H)).text
    assert sample(t, "aijailer_snapshot_quota_used", tenant=tid, quota="snapshots") == 4
    assert sample(t, "aijailer_snapshot_quota_used", tenant=tid, quota="snapshots_per_cell") == 3  # fullest
    # the quota endpoint and the metric agree
    q = (await client.get("/v1/snapshots/quota")).json()["data"]
    assert q["count"] == 4 and q["bytes_used"] == sample(
        t, "aijailer_snapshot_quota_used", tenant=tid, quota="snapshot_storage")


@pytest.mark.asyncio
async def test_failed_deleted_and_stuck_snapshots_are_not_counted(client: AsyncClient, test_tenant, db_engine):
    from datetime import datetime, timedelta, timezone

    from aijailer.models.snapshot import Snapshot
    cell = await _cell(client)
    snap = (await client.post(f"/v1/cells/{cell}/snapshots", json={})).json()["data"]["id"]
    async with async_sessionmaker(db_engine, expire_on_commit=False)() as s:
        s.add(Snapshot(tenant_id=test_tenant.id, cell_id=test_tenant.id, status="error", cell_config={}))
        s.add(Snapshot(tenant_id=test_tenant.id, cell_id=test_tenant.id, status="creating", cell_config={},
                       created_at=datetime.now(timezone.utc) - timedelta(hours=5)))
        await s.commit()
    tid = str(test_tenant.id)
    t = (await client.get("/metrics", headers=H)).text
    assert sample(t, "aijailer_snapshot_quota_used", tenant=tid, quota="snapshots") == 1
    await client.delete(f"/v1/snapshots/{snap}")
    t = (await client.get("/metrics", headers=H)).text
    assert sample(t, "aijailer_snapshot_quota_used", tenant=tid, quota="snapshots") == 0


@pytest.mark.asyncio
async def test_denials_are_counted_per_quota(client: AsyncClient, test_tenant, db_engine):
    async with async_sessionmaker(db_engine, expire_on_commit=False)() as s:
        t = await s.get(Tenant, test_tenant.id)
        t.max_snapshots_per_cell = 1
        await s.commit()
    cell = await _cell(client)
    await client.post(f"/v1/cells/{cell}/snapshots", json={})
    for _ in range(2):
        assert (await client.post(f"/v1/cells/{cell}/snapshots", json={})).status_code == 429
    text = (await client.get("/metrics", headers=H)).text
    tid = str(test_tenant.id)
    assert sample(text, "aijailer_snapshot_quota_denied_total", tenant=tid,
                  quota="snapshots_per_cell") == 2
    assert sample(text, "aijailer_snapshot_quota_denied_total", tenant=tid, quota="snapshots") is None
    assert "# TYPE aijailer_snapshot_quota_denied_total counter" in text


@pytest.mark.asyncio
async def test_suspended_tenants_are_not_exported(client: AsyncClient, test_tenant, db_engine):
    async with async_sessionmaker(db_engine, expire_on_commit=False)() as s:
        t = await s.get(Tenant, test_tenant.id)
        t.status = "suspended"
        await s.commit()
    assert str(test_tenant.id) not in (await client.get("/metrics", headers=H)).text


def test_exposition_escapes_labels_and_omits_empty_families():
    out = promtext.render([
        ("m_a", "gauge", "help \\ with\nnewline", [({"k": 'a"b\\c\nd'}, 3)]),
        ("m_empty", "gauge", "nothing", []),
        ("m_f", "gauge", "float", [({}, 0.5)])])
    assert 'm_a{k="a\\"b\\\\c\\nd"} 3' in out and "m_empty" not in out
    assert "# HELP m_a help \\\\ with\\nnewline" in out and "m_f 0.5" in out
    assert out.endswith("\n")


@pytest.mark.asyncio
async def test_metrics_endpoint_includes_the_audit_batch_metrics(client: AsyncClient):
    text = (await client.get("/metrics", headers=H)).text
    for name in ("aijailer_audit_batch_pending", "aijailer_audit_batch_queue_capacity",
                 "aijailer_audit_events_dropped_total", "aijailer_audit_batch_flush_failures_total"):
        assert f"\n{name} " in "\n" + text, name
