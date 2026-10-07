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


# ---------------------------------------------------------------- a command that did not run is not a success
ENDPOINTS = [("exec", {"command": "true"}),
             ("exec/script", {"script": "print(1)", "interpreter": "/usr/bin/python3"})]


def _engine_raises(monkeypatch, exc):
    from aijailer.engine.microvm import get_microvm_engine

    async def boom(*a, **k):
        raise exc
    monkeypatch.setattr(get_microvm_engine(), "exec_command", boom)


def _engine_returns(monkeypatch, **fields):
    from aijailer.engine.microvm import ExecResult, get_microvm_engine

    async def ok(*a, **k):
        return ExecResult(**{"exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 5, **fields})
    monkeypatch.setattr(get_microvm_engine(), "exec_command", ok)


async def _history(client, cell_id):
    return (await client.get(f"/v1/cells/{cell_id}/executions")).json()["data"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", ENDPOINTS, ids=["exec", "script"])
async def test_a_command_the_guest_could_not_start_is_an_error_not_exit_code_0(client: AsyncClient, monkeypatch, path, body):
    from aijailer.engine.microvm import AgentError
    reason = 'cannot start in working directory "/nope": no such file or directory'
    _engine_raises(monkeypatch, AgentError(reason))
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/{path}", json=body)
    assert r.status_code == 400
    err = r.json()["error"]
    assert err["code"] == "execution_not_started" and reason in err["message"]
    assert "data" not in r.json()                                    # no success payload with exit_code 0
    # The failed record must survive the error response (the session is rolled back on errors otherwise).
    history = await _history(client, cell_id)
    assert [h["status"] for h in history] == ["failed"]
    assert history[0]["execution_id"] == err["details"]["execution_id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", ENDPOINTS, ids=["exec", "script"])
async def test_a_busy_guest_is_a_retryable_429(client: AsyncClient, monkeypatch, path, body):
    from aijailer.engine.microvm import AgentError
    _engine_raises(monkeypatch, AgentError("too many concurrent executions"))
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/{path}", json=body)
    assert r.status_code == 429 and r.json()["error"]["code"] == "execution_busy"
    assert [h["status"] for h in await _history(client, cell_id)] == ["failed"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", ENDPOINTS, ids=["exec", "script"])
async def test_an_internal_failure_is_a_502_that_does_not_leak_its_details(client: AsyncClient, monkeypatch, path, body):
    _engine_raises(monkeypatch, RuntimeError("vsock connect refused: b'/var/lib/aijailer/jail/xyz/v.sock'"))
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/{path}", json=body)
    assert r.status_code == 502 and r.json()["error"]["code"] == "execution_failed"
    assert "vsock" not in r.text and "/var/lib" not in r.text
    assert "may or may not have run" in r.json()["error"]["message"]
    assert [h["status"] for h in await _history(client, cell_id)] == ["failed"]


@pytest.mark.asyncio
async def test_a_command_that_ran_and_failed_is_still_a_200_with_its_exit_code(client: AsyncClient, monkeypatch):
    _engine_returns(monkeypatch, exit_code=3, stderr="boom\n")
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "exit 3"})
    assert r.status_code == 200
    assert r.json()["data"]["exit_code"] == 3 and r.json()["data"]["stderr"] == "boom\n"
    assert [h["status"] for h in await _history(client, cell_id)] == ["completed"]


@pytest.mark.asyncio
async def test_a_timeout_the_guest_reports_is_still_a_200_with_exit_code_124(client: AsyncClient, monkeypatch):
    _engine_returns(monkeypatch, exit_code=124, timed_out=True)
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "sleep 99", "timeout_seconds": 1})
    assert r.status_code == 200 and r.json()["data"]["exit_code"] == 124


@pytest.mark.asyncio
async def test_a_failure_does_not_poison_the_next_request(client: AsyncClient, monkeypatch):
    from aijailer.engine.microvm import AgentError
    cell_id = await _running_cell(client)
    _engine_raises(monkeypatch, AgentError("unknown user \"x\""))
    assert (await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "true", "user": "x"})).status_code == 400
    _engine_returns(monkeypatch)
    ok = await client.post(f"/v1/cells/{cell_id}/exec", json={"command": "true"})
    assert ok.status_code == 200 and ok.json()["data"]["exit_code"] == 0
    assert sorted(h["status"] for h in await _history(client, cell_id)) == ["completed", "failed"]


@pytest.mark.asyncio
@pytest.mark.parametrize("path,body", ENDPOINTS, ids=["exec", "script"])
async def test_a_command_whose_result_never_arrives_is_a_408_not_a_silent_success(client: AsyncClient, monkeypatch, path, body):
    """The guest agent stopped answering within the timeout: no result exists, so it must not read as exit_code 0."""
    _engine_raises(monkeypatch, TimeoutError())
    cell_id = await _running_cell(client)
    r = await client.post(f"/v1/cells/{cell_id}/{path}", json=body)
    assert r.status_code == 408 and r.json()["error"]["code"] == "execution_timeout"
    assert "data" not in r.json()
    history = await _history(client, cell_id)
    assert [h["status"] for h in history] == ["timeout"]
    assert history[0]["execution_id"] == r.json()["error"]["details"]["execution_id"]
