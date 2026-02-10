"""Test error handling and edge cases."""

import uuid

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_get_nonexistent_cell(client: AsyncClient):
    fake_id = str(uuid.uuid4())
    response = await client.get(f"/v1/cells/{fake_id}")
    assert response.status_code == 404
    error = response.json()["error"]
    assert error["code"] == "cell_not_found"


@pytest.mark.asyncio
async def test_start_destroyed_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "error-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    await client.delete(f"/v1/cells/{cell_id}")

    response = await client.post(f"/v1/cells/{cell_id}/start")
    # Should return 404 (destroyed cells not found) or 409 (invalid transition)
    assert response.status_code in (404, 409)


@pytest.mark.asyncio
async def test_exec_on_stopped_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "stopped-exec", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    await client.post(f"/v1/cells/{cell_id}/stop")

    response = await client.post(
        f"/v1/cells/{cell_id}/exec",
        json={"command": "echo test"},
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "cell_not_running"


@pytest.mark.asyncio
async def test_invalid_state_pause_stopped_cell(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "invalid-pause", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    await client.post(f"/v1/cells/{cell_id}/stop")

    response = await client.post(f"/v1/cells/{cell_id}/pause")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "invalid_state_transition"


@pytest.mark.asyncio
async def test_unauthenticated_request(client: AsyncClient):
    # Make a request without auth header
    from httpx import AsyncClient as RawClient, ASGITransport
    from aijailer.api.app import create_app

    app = create_app()
    transport = ASGITransport(app=app)
    async with RawClient(transport=transport, base_url="http://test") as raw_client:
        response = await raw_client.get("/v1/cells")
        assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_get_nonexistent_policy(client: AsyncClient):
    fake_id = str(uuid.uuid4())
    response = await client.get(f"/v1/policies/{fake_id}")
    assert response.status_code == 404
