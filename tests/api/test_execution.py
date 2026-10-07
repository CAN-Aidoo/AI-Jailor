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


# ---------------------------------------------------------------- per-command environment
async def _running_cell(client):
    return (await client.post("/v1/cells", json={"name": "env-test", "image": "base-python"})).json()["data"]["id"]


@pytest.fixture
def captured_exec(monkeypatch):
    """Record what ExecutionService hands to the engine."""
    from aijailer.engine.microvm import ExecResult, get_microvm_engine
    seen = []

    async def fake(cell_id, command, timeout=30, user="agent", env=None, cwd=None):
        seen.append({"command": command, "user": user, "env": env, "cwd": cwd})
        return ExecResult(0, "ok\n", "", 1, 1, 1)
    monkeypatch.setattr(get_microvm_engine(), "exec_command", fake)
    return seen


@pytest.mark.asyncio
async def test_the_requests_environment_reaches_the_engine(client: AsyncClient, captured_exec):
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec",
                          json={"command": "env", "environment": {"DEBUG": "true", "PATH": "/opt/bin"}})
    assert r.status_code == 200
    assert captured_exec == [{"command": "env", "user": "agent", "env": {"DEBUG": "true", "PATH": "/opt/bin"},
                              "cwd": None}]


@pytest.mark.asyncio
async def test_no_environment_means_an_empty_one(client: AsyncClient, captured_exec):
    cell_id = await _running_cell(client)
    assert (await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "true"})).status_code == 200
    assert captured_exec[0]["env"] == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("env", [
    {"A=B": "x"}, {"1A": "x"}, {"": "x"}, {"A": "x\u0000y"},
    {"HTTP_PROXY": "http://evil:1"}, {"no_proxy": ""}, {"AIJAILER_PEER_ATTEST_PUBKEY": "x"}, {"HOME": "/"},
    {f"V{i}": "x" for i in range(101)},
], ids=["equals", "digit", "empty", "nul", "proxy", "no_proxy", "aijailer", "home", "too-many"])
async def test_a_bad_environment_is_a_400_and_nothing_runs_or_is_stored(client: AsyncClient, captured_exec, env):
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "true", "environment": env})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_environment"
    assert captured_exec == []                                                    # never reached the engine
    history = (await client.get(f"/v1/cells/{cell_id}/executions")).json()["data"]
    assert history == []                                                          # and no record was created


@pytest.mark.asyncio
async def test_the_script_endpoint_is_unchanged(client: AsyncClient, captured_exec):
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec/script", json={"script": "print(1)", "interpreter": "/usr/bin/python3"})
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_a_valid_request_is_recorded_so_the_empty_history_above_means_something(client: AsyncClient, captured_exec):
    cell_id = await _running_cell(client)
    assert (await client.post(f"/v1/cells/{cell_id}/exec",
                              json={"command": "true", "environment": {"OK": "1"}})).status_code == 200
    history = (await client.get(f"/v1/cells/{cell_id}/executions")).json()["data"]
    assert len(history) == 1 and history[0]["command"] == "true"


# ---------------------------------------------------------------- per-command working directory
@pytest.mark.asyncio
async def test_the_requests_working_directory_reaches_the_engine(client: AsyncClient, captured_exec):
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "pwd", "working_directory": "/data/project"})
    assert r.status_code == 200
    assert captured_exec[0]["cwd"] == "/data/project"


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"working_directory": None}, {"working_directory": ""}])
async def test_without_one_the_guest_default_applies_not_the_cell_default(client: AsyncClient, captured_exec, body):
    """The cell-level default is /home/agent; passing it would break commands run as another user."""
    cell_id = await _running_cell(client)
    assert (await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "pwd", **body})).status_code == 200
    assert captured_exec[0]["cwd"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["relative/dir", ".", "~", "/tmp/a\u0000b", "/" + "a" * 1025],
                         ids=["relative", "dot", "tilde", "nul", "too-long"])
async def test_a_bad_working_directory_is_a_400_and_nothing_runs_or_is_stored(client: AsyncClient, captured_exec, path):
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "true", "working_directory": path})
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "invalid_working_directory"
    assert captured_exec == []
    assert (await client.get(f"/v1/cells/{cell_id}/executions")).json()["data"] == []
