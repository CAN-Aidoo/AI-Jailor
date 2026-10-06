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


@pytest.mark.asyncio
async def test_gate_enforce_blocks_dangerous_script(client: AsyncClient, monkeypatch):
    monkeypatch.setenv("EXECUTION_GATE_MODE", "enforce")
    cell_id = (await client.post("/v1/cells", json={"name": "gate", "image": "base-python"})
               ).json()["data"]["id"]
    bad = 'import os\nx = request.args["c"]\nos.system(x)\n'
    r = await client.post(f"/v1/cells/{cell_id}/exec/script",
                          json={"script": bad, "interpreter": "/usr/bin/python3"})
    assert r.status_code == 403
    ok = await client.post(f"/v1/cells/{cell_id}/exec/script",
                           json={"script": "print('hi')", "interpreter": "/usr/bin/python3"})
    assert ok.status_code == 200
