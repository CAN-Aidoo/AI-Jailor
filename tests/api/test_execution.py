"""Test Execution API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_execute_command(client: AsyncClient):
    # Create a cell first
    create_resp = await client.post("/v1/cells", json={"name": "exec-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.post(
        f"/v1/cells/{cell_id}/exec",
        json={"command": "echo hello"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["exit_code"] == 0
    assert "execution_id" in data


@pytest.mark.asyncio
async def test_execute_script(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "script-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.post(
        f"/v1/cells/{cell_id}/exec/script",
        json={"script": "print('hello')", "interpreter": "/usr/bin/python3"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["exit_code"] == 0
