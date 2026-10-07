"""Test Snapshot API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_snapshot(client: AsyncClient):
    # Create a cell first
    create_resp = await client.post("/v1/cells", json={"name": "snap-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.post(
        f"/v1/cells/{cell_id}/snapshots",
        json={"name": "after-setup", "description": "Test snapshot"},
    )
    assert response.status_code == 202
    data = response.json()["data"]
    assert data["name"] == "after-setup"
    assert data["status"] == "available"


@pytest.mark.asyncio
async def test_list_snapshots(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "snap-list", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    # Create two snapshots
    await client.post(f"/v1/cells/{cell_id}/snapshots", json={"name": "snap-1"})
    await client.post(f"/v1/cells/{cell_id}/snapshots", json={"name": "snap-2"})

    response = await client.get(f"/v1/cells/{cell_id}/snapshots")
    assert response.status_code == 200
    data = response.json()["data"]
    assert len(data) >= 2


@pytest.mark.asyncio
async def test_restore_from_snapshot(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "restore-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    snap_resp = await client.post(
        f"/v1/cells/{cell_id}/snapshots", json={"name": "restore-snap"}
    )
    snap_id = snap_resp.json()["data"]["id"]

    response = await client.post(
        f"/v1/cells/{cell_id}/restore",
        json={"snapshot_id": str(snap_id)},
    )
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_clone_from_snapshot(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "clone-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    snap_resp = await client.post(
        f"/v1/cells/{cell_id}/snapshots", json={"name": "clone-snap"}
    )
    snap_id = snap_resp.json()["data"]["id"]

    response = await client.post(
        f"/v1/snapshots/{snap_id}/clone",
        json={"name": "cloned-cell"},
    )
    assert response.status_code == 201


async def _cell_and_snap(client, name="s"):
    cell = (await client.post("/v1/cells", json={"name": name, "image": "base-python"})).json()["data"]
    snap = (await client.post(f"/v1/cells/{cell['id']}/snapshots", json={"name": "x"})).json()["data"]
    return cell["id"], snap["id"]


@pytest.mark.asyncio
async def test_restore_replaces_the_vm_and_reports_running(client: AsyncClient):
    cell_id, snap_id = await _cell_and_snap(client)
    r = await client.post(f"/v1/cells/{cell_id}/restore", json={"snapshot_id": snap_id})
    assert r.status_code == 200
    assert r.json()["data"] == {"cell_id": cell_id, "snapshot_id": snap_id, "status": "running"}
    assert (await client.get(f"/v1/cells/{cell_id}")).json()["data"]["status"] == "running"


@pytest.mark.asyncio
async def test_restore_errors_map_to_http_codes(client: AsyncClient):
    import uuid
    cell_id, snap_id = await _cell_and_snap(client)
    other_cell, other_snap = await _cell_and_snap(client, "o")
    cases = [
        (cell_id, str(uuid.uuid4()), 404, "snapshot_not_found"),
        (cell_id, "not-a-uuid", 404, "snapshot_not_found"),
        (cell_id, other_snap, 400, "snapshot_cell_mismatch"),
    ]
    for cid, sid, code, err in cases:
        r = await client.post(f"/v1/cells/{cid}/restore", json={"snapshot_id": sid})
        assert r.status_code == code, r.text
        assert err in r.text
    assert (await client.post(f"/v1/cells/{uuid.uuid4()}/restore",
                              json={"snapshot_id": snap_id})).status_code == 404


@pytest.mark.asyncio
async def test_clone_returns_a_running_cell_and_rejects_resources(client: AsyncClient):
    cell_id, snap_id = await _cell_and_snap(client)
    r = await client.post(f"/v1/snapshots/{snap_id}/clone", json={"name": "c2"})
    assert r.status_code == 201
    data = r.json()["data"]
    assert data["status"] == "running" and data["name"] == "c2" and data["id"] != cell_id
    assert (await client.get(f"/v1/cells/{data['id']}")).status_code == 200
    bad = await client.post(f"/v1/snapshots/{snap_id}/clone",
                            json={"resources": {"vcpus": 8}})
    assert bad.status_code == 400 and "invalid_clone" in bad.text


@pytest.mark.asyncio
async def test_snapshot_of_a_stopped_cell_conflicts_and_unknown_cell_404s(client: AsyncClient):
    import uuid
    cell_id, _ = await _cell_and_snap(client)
    await client.post(f"/v1/cells/{cell_id}/stop", json={})
    assert (await client.post(f"/v1/cells/{cell_id}/snapshots", json={})).status_code == 409
    assert (await client.post(f"/v1/cells/{uuid.uuid4()}/snapshots", json={})).status_code == 404


@pytest.mark.asyncio
async def test_quota_endpoint_limit_429_and_delete_frees_a_slot(client: AsyncClient, db_engine, test_tenant):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from aijailer.models.tenant import Tenant
    async with async_sessionmaker(db_engine, expire_on_commit=False)() as s:
        t = await s.get(Tenant, test_tenant.id)
        t.max_snapshot_count = 1
        await s.commit()
    cell_id, snap_id = await _cell_and_snap(client)
    q = (await client.get("/v1/snapshots/quota")).json()["data"]
    assert q["count"] == 1 and q["max_count"] == 1 and q["max_bytes"] == 50 * (1 << 30)
    r = await client.post(f"/v1/cells/{cell_id}/snapshots", json={})
    assert r.status_code == 429 and "resource_limit_exceeded" in r.text
    assert (await client.delete(f"/v1/snapshots/{snap_id}")).status_code == 204
    assert (await client.get("/v1/snapshots/quota")).json()["data"]["count"] == 0
    assert (await client.post(f"/v1/cells/{cell_id}/snapshots", json={})).status_code == 202
    assert (await client.delete(f"/v1/snapshots/{snap_id}")).status_code == 404   # already gone
