"""Test Cell API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_cell(client: AsyncClient):
    response = await client.post(
        "/v1/cells",
        json={
            "name": "test-cell",
            "image": "base-python",
            "resources": {"vcpus": 1, "memory_mb": 512},
        },
    )
    assert response.status_code == 201
    data = response.json()["data"]
    assert data["name"] == "test-cell"
    assert data["image"] == "base-python"
    assert data["status"] == "running"


@pytest.mark.asyncio
async def test_list_cells(client: AsyncClient):
    # Create a cell first
    await client.post("/v1/cells", json={"name": "list-test", "image": "base-python"})

    response = await client.get("/v1/cells")
    assert response.status_code == 200
    data = response.json()["data"]
    assert "cells" in data


@pytest.mark.asyncio
async def test_get_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "get-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.get(f"/v1/cells/{cell_id}")
    assert response.status_code == 200
    assert response.json()["data"]["id"] == cell_id


@pytest.mark.asyncio
async def test_stop_and_start_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "lifecycle-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    # Stop
    stop_resp = await client.post(f"/v1/cells/{cell_id}/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.json()["data"]["status"] == "stopped"

    # Start
    start_resp = await client.post(f"/v1/cells/{cell_id}/start")
    assert start_resp.status_code == 200
    assert start_resp.json()["data"]["status"] == "running"


@pytest.mark.asyncio
async def test_pause_resume_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "pause-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    # Pause
    pause_resp = await client.post(f"/v1/cells/{cell_id}/pause")
    assert pause_resp.status_code == 200
    assert pause_resp.json()["data"]["status"] == "paused"

    # Resume
    resume_resp = await client.post(f"/v1/cells/{cell_id}/resume")
    assert resume_resp.status_code == 200
    assert resume_resp.json()["data"]["status"] == "running"


@pytest.mark.asyncio
async def test_destroy_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "destroy-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.delete(f"/v1/cells/{cell_id}")
    assert response.status_code == 204
