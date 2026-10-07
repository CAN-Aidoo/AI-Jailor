"""PUT/GET/DELETE /v1/cells/{id}/bandwidth (simulated engine => no live network, persist only)."""

import uuid

import pytest

from aijailer.models.tenant import Tenant
from tests.api.test_secrets import make_client


async def new_cell(client, mbps=100):
    r = await client.post("/v1/cells", json={"name": "bw", "image": "base-python",
                                             "resources": {"network_bandwidth_mbps": mbps}})
    return r.json()["data"]["id"]


@pytest.mark.asyncio
async def test_default_then_override_then_reset(client):
    cid = await new_cell(client, 50)
    d = (await client.get(f"/v1/cells/{cid}/bandwidth")).json()["data"]
    assert d["source"] == "default" and d["configured"] == {"down_kbit": 50000, "up_kbit": 50000}
    assert d["enforced"] is None and d["min_kbit"] == 64 and d["max_kbit"] == 10_000_000
    r = await client.put(f"/v1/cells/{cid}/bandwidth", json={"down_kbit": 2000, "up_kbit": 8000})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["source"] == "override" and d["configured"] == {"down_kbit": 2000, "up_kbit": 8000}
    assert (await client.get(f"/v1/cells/{cid}/bandwidth")).json()["data"]["source"] == "override"
    d = (await client.delete(f"/v1/cells/{cid}/bandwidth")).json()["data"]
    assert d["source"] == "default" and d["configured"]["down_kbit"] == 50000


@pytest.mark.asyncio
@pytest.mark.parametrize("payload,status", [
    ({"down_kbit": 2000}, 422),                                  # up missing: never "leave unlimited"
    ({"up_kbit": 2000}, 422),
    ({"down_kbit": None, "up_kbit": 2000}, 422),                 # null/unlimited is not expressible
    ({"down_kbit": "fast", "up_kbit": 2000}, 422),
    ({"down_kbit": 10, "up_kbit": 2000}, 400),                   # below the shaper's minimum
    ({"down_kbit": 2000, "up_kbit": 10_000_001}, 400),           # above the ceiling
    ({"down_kbit": 0, "up_kbit": 0}, 400),
    ({}, 422)])
async def test_validation(client, payload, status):
    cid = await new_cell(client)
    r = await client.put(f"/v1/cells/{cid}/bandwidth", json=payload)
    assert r.status_code == status, r.text
    d = (await client.get(f"/v1/cells/{cid}/bandwidth")).json()["data"]
    assert d["source"] == "default"                              # nothing was changed


@pytest.mark.asyncio
async def test_cap_from_settings(client, monkeypatch):
    monkeypatch.setenv("MAX_CELL_BANDWIDTH_MBPS", "20")
    cid = await new_cell(client, 10)
    assert (await client.put(f"/v1/cells/{cid}/bandwidth",
                             json={"down_kbit": 20000, "up_kbit": 20000})).status_code == 200
    r = await client.put(f"/v1/cells/{cid}/bandwidth", json={"down_kbit": 20001, "up_kbit": 1000})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_bandwidth"
    r = await client.post("/v1/cells", json={"name": "x", "image": "i",
                                             "resources": {"network_bandwidth_mbps": 21}})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_bandwidth"


@pytest.mark.asyncio
async def test_only_owner_and_admin_may_change(db_engine, test_tenant, client):
    cid = await new_cell(client)
    operator = await make_client(db_engine, test_tenant, "operator", "aj_test_bwoper0001")
    viewer = await make_client(db_engine, test_tenant, "viewer", "aj_test_bwview0001")
    for c in (operator, viewer):
        r = await c.put(f"/v1/cells/{cid}/bandwidth", json={"down_kbit": 1000, "up_kbit": 1000})
        assert r.status_code == 403
        assert (await c.delete(f"/v1/cells/{cid}/bandwidth")).status_code == 403
        assert (await c.get(f"/v1/cells/{cid}/bandwidth")).status_code == 200   # reading is fine
    assert (await client.get(f"/v1/cells/{cid}/bandwidth")).json()["data"]["source"] == "default"


@pytest.mark.asyncio
async def test_other_tenants_cannot_see_or_change_a_cell(db_engine, db_session, client):
    cid = await new_cell(client)
    other = Tenant(name="o", slug=f"o-{uuid.uuid4().hex[:6]}", status="active", tier="pro")
    db_session.add(other)
    await db_session.commit()
    oc = await make_client(db_engine, other, "admin", "aj_test_bwother001")
    assert (await oc.get(f"/v1/cells/{cid}/bandwidth")).status_code == 404
    assert (await oc.put(f"/v1/cells/{cid}/bandwidth",
                         json={"down_kbit": 1000, "up_kbit": 1000})).status_code == 404
    assert (await oc.delete(f"/v1/cells/{cid}/bandwidth")).status_code == 404
    assert (await client.get(f"/v1/cells/{cid}/bandwidth")).json()["data"]["source"] == "default"


@pytest.mark.asyncio
async def test_unknown_cell_and_bad_state(client):
    assert (await client.get(f"/v1/cells/{uuid.uuid4()}/bandwidth")).status_code == 404
    cid = await new_cell(client)
    await client.delete(f"/v1/cells/{cid}")                      # destroyed
    r = await client.put(f"/v1/cells/{cid}/bandwidth", json={"down_kbit": 1000, "up_kbit": 1000})
    assert r.status_code == 409
