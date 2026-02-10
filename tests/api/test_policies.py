"""Test Policy API endpoints."""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_create_policy(client: AsyncClient):
    response = await client.post(
        "/v1/policies",
        json={
            "name": "test-policy",
            "description": "A test security policy",
            "network": {
                "default": "deny",
                "egress": [
                    {
                        "action": "allow",
                        "destinations": [{"domain": "api.openai.com"}],
                        "ports": [443],
                    }
                ],
            },
        },
    )
    assert response.status_code == 201
    data = response.json()["data"]
    assert data["name"] == "test-policy"
    assert data["version"] == 1


@pytest.mark.asyncio
async def test_list_policies(client: AsyncClient):
    await client.post("/v1/policies", json={"name": "list-test-policy"})

    response = await client.get("/v1/policies")
    assert response.status_code == 200
