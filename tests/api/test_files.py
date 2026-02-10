"""Test File Operations API endpoints."""

import io

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_upload_file(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "file-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.post(
        f"/v1/cells/{cell_id}/files/upload",
        data={"path": "/data/test.txt", "mode": "0644"},
        files={"file": ("test.txt", b"hello world", "text/plain")},
    )
    assert response.status_code == 201
    data = response.json()["data"]
    assert data["path"] == "/data/test.txt"
    assert data["size"] == 11


@pytest.mark.asyncio
async def test_download_file(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "download-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.get(
        f"/v1/cells/{cell_id}/files/download",
        params={"path": "/data/example.txt"},
    )
    assert response.status_code == 200
    assert response.headers.get("content-disposition") is not None


@pytest.mark.asyncio
async def test_list_files(client: AsyncClient):
    create_resp = await client.post("/v1/cells", json={"name": "list-files-test", "image": "base-python"})
    cell_id = create_resp.json()["data"]["id"]

    response = await client.get(
        f"/v1/cells/{cell_id}/files/list",
        params={"path": "/data"},
    )
    assert response.status_code == 200
    data = response.json()["data"]
    assert "entries" in data
