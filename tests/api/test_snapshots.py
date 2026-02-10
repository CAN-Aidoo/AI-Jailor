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
