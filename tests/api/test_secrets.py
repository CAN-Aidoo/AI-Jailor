"""Secrets API: write-only, role-gated, tenant-scoped, never echoes values."""

import hashlib
import json
import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from aijailer.api.app import create_app
from aijailer.db.base import get_db
from aijailer.models.audit import EventType
from aijailer.models.tenant import ApiKey, Tenant
from aijailer.secretstore import runtime as secret_runtime
from aijailer.secretstore.keys import LocalKeyProvider
from aijailer.services.audit_service import get_audit_service

VALUE = "ghp_API_LEVEL_SECRET_42"


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    monkeypatch.setenv("SECRETS_MASTER_KEYS", "k1:" + LocalKeyProvider.generate_key())
    secret_runtime.reset_for_tests()
    yield
    secret_runtime.reset_for_tests()


async def make_client(db_engine, tenant, role, raw):
    sessions = async_sessionmaker(db_engine, expire_on_commit=False)
    async with sessions() as s:
        s.add(ApiKey(tenant_id=tenant.id, created_by=tenant.id, name=role,
                     key_hash=hashlib.sha256(raw.encode()).hexdigest(), key_prefix=raw[:12],
                     role=role, status="active"))
        await s.commit()
    app = create_app()

    async def override():
        async with sessions() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
    app.dependency_overrides[get_db] = override
    c = AsyncClient(transport=ASGITransport(app=app), base_url="http://test")
    c.headers["Authorization"] = f"Bearer {raw}"
    return c


def body(name="gh", **kw):
    return {"name": name, "value": VALUE, "hosts": ["api.github.com"], **kw}


@pytest.mark.asyncio
async def test_create_returns_metadata_and_never_the_value(client):
    r = await client.post("/v1/secrets", json=body())
    assert r.status_code == 201
    d = r.json()["data"]
    assert d["name"] == "gh" and d["version"] == 1 and d["hosts"] == ["api.github.com"]
    assert d["placeholder"] == "{{secret:gh}}"
    for resp in (r, await client.get("/v1/secrets"), await client.get("/v1/secrets/gh")):
        assert VALUE not in resp.text and "value" not in json.dumps(resp.json()).lower().replace(
            "values", "")


@pytest.mark.asyncio
async def test_not_configured_means_503_not_a_weak_default(client, monkeypatch):
    monkeypatch.setenv("SECRETS_MASTER_KEYS", "")
    secret_runtime.reset_for_tests()
    r = await client.post("/v1/secrets", json=body())
    assert r.status_code == 503 and r.json()["error"]["code"] == "secret_store_unavailable"


@pytest.mark.asyncio
async def test_validation_errors_do_not_echo_the_value(client):
    bad_value = "line1\r\nX-Evil: " + VALUE
    r = await client.post("/v1/secrets", json=body(value=bad_value))
    assert r.status_code == 400 and VALUE not in r.text
    for b in (body(name="bad name"), body(hosts=[]), body(hosts=["*.com"])):
        r = await client.post("/v1/secrets", json=b)
        assert r.status_code == 400 and VALUE not in r.text


@pytest.mark.asyncio
async def test_conflict_not_found_update_delete_lifecycle(client):
    assert (await client.post("/v1/secrets", json=body())).status_code == 201
    assert (await client.post("/v1/secrets", json=body())).status_code == 409
    assert (await client.get("/v1/secrets/missing")).status_code == 404
    r = await client.put("/v1/secrets/gh", json={"value": "rotated-" + VALUE})
    assert r.status_code == 200 and r.json()["data"]["version"] == 2
    assert r.json()["data"]["rotated_at"] is not None and "rotated-" not in r.text
    r = await client.put("/v1/secrets/gh", json={"hosts": ["api.other.test"]})
    assert r.json()["data"]["hosts"] == ["api.other.test"] and r.json()["data"]["version"] == 3
    assert (await client.put("/v1/secrets/gh", json={})).status_code == 400
    assert (await client.delete("/v1/secrets/gh")).status_code == 204
    assert (await client.get("/v1/secrets/gh")).status_code == 404
    assert (await client.delete("/v1/secrets/gh")).status_code == 404


@pytest.mark.asyncio
async def test_roles(db_engine, test_tenant, client):
    await client.post("/v1/secrets", json=body())
    viewer = await make_client(db_engine, test_tenant, "viewer", "aj_test_viewer0001")
    operator = await make_client(db_engine, test_tenant, "operator", "aj_test_operator01")
    auditor = await make_client(db_engine, test_tenant, "auditor", "aj_test_auditor001")
    for c in (viewer, operator):                                   # no access at all
        assert (await c.get("/v1/secrets")).status_code == 403
        assert (await c.post("/v1/secrets", json=body("x"))).status_code == 403
    assert (await auditor.get("/v1/secrets")).status_code == 200   # metadata only
    assert (await auditor.post("/v1/secrets", json=body("x"))).status_code == 403
    assert (await auditor.put("/v1/secrets/gh", json={"value": "v"})).status_code == 403
    assert (await auditor.delete("/v1/secrets/gh")).status_code == 403
    assert (await client.get("/v1/secrets/gh")).status_code == 200  # still intact


@pytest.mark.asyncio
async def test_tenants_cannot_see_or_touch_each_others_secrets(db_engine, db_session, client):
    other = Tenant(name="o", slug=f"o-{uuid.uuid4().hex[:6]}", status="active", tier="pro")
    db_session.add(other)
    await db_session.commit()
    oc = await make_client(db_engine, other, "admin", "aj_test_other00001")
    await client.post("/v1/secrets", json=body())
    assert (await oc.get("/v1/secrets")).json()["data"] == []
    assert (await oc.get("/v1/secrets/gh")).status_code == 404
    assert (await oc.put("/v1/secrets/gh", json={"value": "hijack"})).status_code == 404
    assert (await oc.delete("/v1/secrets/gh")).status_code == 404
    assert (await oc.post("/v1/secrets", json=body(value="theirs"))).status_code == 201
    assert (await client.get("/v1/secrets/gh")).json()["data"]["version"] == 1


@pytest.mark.asyncio
async def test_audit_trail_has_actions_but_no_values(client):
    await client.post("/v1/secrets", json=body("audited"))
    await client.put("/v1/secrets/audited", json={"value": "v2-" + VALUE})
    await client.delete("/v1/secrets/audited")
    evs = [e for e in get_audit_service()._events
           if e.event_type == EventType.SECRET and e.details.get("name") == "audited"]
    assert [e.details["action"] for e in evs] == ["created", "rotated", "deleted"]
    assert VALUE not in str(evs) and "v2-" not in str(evs)


@pytest.mark.asyncio
async def test_schema_validation_errors_never_echo_the_request_body(client):
    # pydantic reports the WHOLE input object for a missing field, which includes the secret.
    for payload in ({"name": "x", "value": VALUE},                       # missing hosts
                    {"value": VALUE, "hosts": ["a.test"]},               # missing name
                    {"name": 5, "value": VALUE, "hosts": ["a.test"]},    # wrong type
                    {"name": "x", "value": VALUE, "hosts": "a.test"}):
        r = await client.post("/v1/secrets", json=payload)
        assert r.status_code in (400, 422) and VALUE not in r.text, r.text
    r = await client.put("/v1/secrets/gh", json={"value": VALUE, "hosts": 7})
    assert VALUE not in r.text
