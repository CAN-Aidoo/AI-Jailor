"""AI Jailer SDK client — synchronous and asynchronous implementations."""

from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from typing import Any, AsyncGenerator, Generator

import httpx

from aijailer.config import AiJailerConfig
from aijailer.exceptions import (
    AiJailerError,
    AuthenticationError,
    CellNotFoundError,
    CellNotRunningError,
    ExecutionTimeoutError,
    PolicyViolationError,
    RateLimitError,
    ResourceLimitError,
    SpendingCapError,
)
from aijailer.models import Cell, Execution, FileEntry, Snapshot


ERROR_MAP = {
    "cell_not_found": CellNotFoundError,
    "cell_not_running": CellNotRunningError,
    "policy_violation": PolicyViolationError,
    "rate_limited": RateLimitError,
    "unauthorized": AuthenticationError,
    "execution_timeout": ExecutionTimeoutError,
    "resource_limit_exceeded": ResourceLimitError,
    "spending_cap_reached": SpendingCapError,
}


# ---------------------------------------------------------------------------
# Synchronous sub-APIs
# ---------------------------------------------------------------------------


class _CellsAPI:
    """Cell management sub-API."""

    def __init__(self, client: AiJailer):
        self._client = client

    def create(self, **kwargs) -> Cell:
        data = self._client._post("/v1/cells", json=kwargs)
        cell = Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})
        cell._client = self._client
        return cell

    def get(self, cell_id: str) -> Cell:
        data = self._client._get(f"/v1/cells/{cell_id}")
        cell = Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})
        cell._client = self._client
        return cell

    def list(self, **kwargs) -> list[Cell]:
        data = self._client._get("/v1/cells", params=kwargs)
        cells_data = data.get("cells", [])
        cells = []
        for c in cells_data:
            cell = Cell(**{k: v for k, v in c.items() if k in Cell.__dataclass_fields__})
            cell._client = self._client
            cells.append(cell)
        return cells

    def start(self, cell_id: str) -> Cell:
        data = self._client._post(f"/v1/cells/{cell_id}/start")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    def stop(self, cell_id: str, grace_period_seconds: int = 10) -> Cell:
        data = self._client._post(
            f"/v1/cells/{cell_id}/stop",
            json={"grace_period_seconds": grace_period_seconds},
        )
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    def pause(self, cell_id: str) -> Cell:
        data = self._client._post(f"/v1/cells/{cell_id}/pause")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    def resume(self, cell_id: str) -> Cell:
        data = self._client._post(f"/v1/cells/{cell_id}/resume")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    def destroy(self, cell_id: str, destroy_persistent: bool = False) -> None:
        self._client._delete(
            f"/v1/cells/{cell_id}", params={"destroy_persistent": destroy_persistent}
        )


class _FilesAPI:
    """File operations sub-API."""

    def __init__(self, client: AiJailer):
        self._client = client

    def upload(self, cell_id: str, local_path: str, remote_path: str) -> dict:
        with open(local_path, "rb") as f:
            return self._client._post_multipart(
                f"/v1/cells/{cell_id}/files/upload",
                data={"path": remote_path},
                files={"file": f},
            )

    def write(self, cell_id: str, path: str, content: str) -> dict:
        return self._client._post_multipart(
            f"/v1/cells/{cell_id}/files/upload",
            data={"path": path},
            files={"file": ("content", content.encode())},
        )

    def download(self, cell_id: str, remote_path: str, local_path: str) -> None:
        content = self._client._get_raw(
            f"/v1/cells/{cell_id}/files/download", params={"path": remote_path}
        )
        with open(local_path, "wb") as f:
            f.write(content)

    def read(self, cell_id: str, path: str) -> str:
        content = self._client._get_raw(
            f"/v1/cells/{cell_id}/files/download", params={"path": path}
        )
        return content.decode()

    def list(self, cell_id: str, path: str = "/", recursive: bool = False) -> list[FileEntry]:
        data = self._client._get(
            f"/v1/cells/{cell_id}/files/list",
            params={"path": path, "recursive": recursive},
        )
        return [FileEntry(**e) for e in data.get("entries", [])]


class _SnapshotsAPI:
    """Snapshot management sub-API."""

    def __init__(self, client: AiJailer):
        self._client = client

    def create(
        self, cell_id: str, name: str | None = None, description: str | None = None
    ) -> Snapshot:
        data = self._client._post(
            f"/v1/cells/{cell_id}/snapshots",
            json={"name": name, "description": description},
        )
        return Snapshot(**{k: v for k, v in data.items() if k in Snapshot.__dataclass_fields__})

    def list(self, cell_id: str) -> list[Snapshot]:
        data = self._client._get(f"/v1/cells/{cell_id}/snapshots")
        if isinstance(data, list):
            return [
                Snapshot(**{k: v for k, v in s.items() if k in Snapshot.__dataclass_fields__})
                for s in data
            ]
        return []

    def restore(self, cell_id: str, snapshot_id: str) -> dict:
        return self._client._post(
            f"/v1/cells/{cell_id}/restore",
            json={"snapshot_id": snapshot_id},
        )

    def clone(
        self, snapshot_id: str, name: str | None = None, resources: dict | None = None
    ) -> dict:
        return self._client._post(
            f"/v1/snapshots/{snapshot_id}/clone",
            json={"name": name, "resources": resources},
        )


class _PoliciesAPI:
    """Policy management sub-API."""

    def __init__(self, client: AiJailer):
        self._client = client

    def create(self, **kwargs) -> Any:
        return self._client._post("/v1/policies", json=kwargs)

    def list(self) -> list[dict]:
        data = self._client._get("/v1/policies")
        return data if isinstance(data, list) else []

    def get(self, policy_id: str) -> dict:
        return self._client._get(f"/v1/policies/{policy_id}")

    def update(self, policy_id: str, **kwargs) -> dict:
        return self._client._put(f"/v1/policies/{policy_id}", json=kwargs)

    def delete(self, policy_id: str) -> None:
        self._client._delete(f"/v1/policies/{policy_id}")


class _AuditAPI:
    """Audit log sub-API."""

    def __init__(self, client: AiJailer):
        self._client = client

    def query(self, **kwargs) -> list[dict]:
        data = self._client._get("/v1/audit/events", params=kwargs)
        return data.get("events", []) if isinstance(data, dict) else []

    def export(
        self,
        start_time,
        end_time,
        format: str = "json",
        output_path: str | None = None,
    ):
        content = self._client._get_raw(
            "/v1/audit/export",
            params={
                "start_time": str(start_time),
                "end_time": str(end_time),
                "format": format,
            },
        )
        if output_path:
            with open(output_path, "wb") as f:
                f.write(content)
        return content


class _WebhooksAPI:
    """Webhook management sub-API."""

    def __init__(self, client: AiJailer):
        self._client = client

    def create(self, url: str, events: list[str], secret: str) -> dict:
        return self._client._post(
            "/v1/webhooks", json={"url": url, "events": events, "secret": secret}
        )

    def list(self) -> list[dict]:
        data = self._client._get("/v1/webhooks")
        return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# Synchronous client
# ---------------------------------------------------------------------------


class AiJailer:
    """Synchronous AI Jailer SDK client."""

    def __init__(
        self,
        api_key: str | None = None,
        config: AiJailerConfig | None = None,
    ):
        if config:
            self._config = config
        else:
            self._config = AiJailerConfig(api_key=api_key or "")

        self._http = httpx.Client(
            base_url=self._config.base_url,
            headers={"Authorization": f"Bearer {self._config.api_key}"},
            timeout=self._config.timeout,
        )

        self.cells = _CellsAPI(self)
        self.files = _FilesAPI(self)
        self.snapshots = _SnapshotsAPI(self)
        self.policies = _PoliciesAPI(self)
        self.audit = _AuditAPI(self)
        self.webhooks = _WebhooksAPI(self)

    def close(self) -> None:
        self._http.close()

    def _handle_error(self, response: httpx.Response) -> None:
        if response.status_code >= 400:
            try:
                body = response.json()
                error = body.get("error", {})
                code = error.get("code", "unknown")
                message = error.get("message", response.text)
                exc_class = ERROR_MAP.get(code, AiJailerError)
                raise exc_class(message)
            except (ValueError, KeyError):
                raise AiJailerError(f"HTTP {response.status_code}: {response.text}")

    def _get(self, path: str, params: dict | None = None) -> Any:
        response = self._http.get(path, params=params)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    def _post(self, path: str, json: dict | None = None) -> Any:
        response = self._http.post(path, json=json)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    def _put(self, path: str, json: dict | None = None) -> Any:
        response = self._http.put(path, json=json)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    def _delete(self, path: str, params: dict | None = None) -> None:
        response = self._http.delete(path, params=params)
        self._handle_error(response)

    def _post_multipart(self, path: str, data: dict, files: dict) -> Any:
        response = self._http.post(path, data=data, files=files)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    def _get_raw(self, path: str, params: dict | None = None) -> bytes:
        response = self._http.get(path, params=params)
        self._handle_error(response)
        return response.content

    # --- Convenience methods ---

    def run(self, image: str = "base-python", command: str = "", **kwargs) -> Execution:
        """Create a cell, run a command, and destroy the cell. One-liner execution."""
        cell = self.cells.create(image=image, auto_start=True, **kwargs)
        try:
            return self.exec(cell.id, command=command)
        finally:
            self.cells.destroy(cell.id)

    def exec(self, cell_id: str, command: str, **kwargs) -> Execution:
        """Execute a command in a cell."""
        data = self._post(f"/v1/cells/{cell_id}/exec", json={"command": command, **kwargs})
        return Execution(**{k: v for k, v in data.items() if k in Execution.__dataclass_fields__})

    def exec_script(self, cell_id: str, script: str, **kwargs) -> Execution:
        """Execute a script in a cell."""
        data = self._post(
            f"/v1/cells/{cell_id}/exec/script",
            json={"script": script, **kwargs},
        )
        return Execution(**{k: v for k, v in data.items() if k in Execution.__dataclass_fields__})

    @contextmanager
    def cell(self, image: str = "base-python", **kwargs) -> Generator[Cell, None, None]:
        """Context manager — creates a cell and destroys it on exit."""
        cell = self.cells.create(image=image, auto_start=True, **kwargs)
        try:
            yield cell
        finally:
            self.cells.destroy(cell.id)


# ---------------------------------------------------------------------------
# Async sub-APIs
# ---------------------------------------------------------------------------


class _AsyncCellsAPI:
    def __init__(self, client: AsyncAiJailer):
        self._client = client

    async def create(self, **kwargs) -> Cell:
        data = await self._client._post("/v1/cells", json=kwargs)
        cell = Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})
        cell._client = self._client
        return cell

    async def get(self, cell_id: str) -> Cell:
        data = await self._client._get(f"/v1/cells/{cell_id}")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    async def list(self, **kwargs) -> list[Cell]:
        data = await self._client._get("/v1/cells", params=kwargs)
        return [
            Cell(**{k: v for k, v in c.items() if k in Cell.__dataclass_fields__})
            for c in data.get("cells", [])
        ]

    async def start(self, cell_id: str) -> Cell:
        data = await self._client._post(f"/v1/cells/{cell_id}/start")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    async def stop(self, cell_id: str, grace_period_seconds: int = 10) -> Cell:
        data = await self._client._post(
            f"/v1/cells/{cell_id}/stop",
            json={"grace_period_seconds": grace_period_seconds},
        )
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    async def pause(self, cell_id: str) -> Cell:
        data = await self._client._post(f"/v1/cells/{cell_id}/pause")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    async def resume(self, cell_id: str) -> Cell:
        data = await self._client._post(f"/v1/cells/{cell_id}/resume")
        return Cell(**{k: v for k, v in data.items() if k in Cell.__dataclass_fields__})

    async def destroy(self, cell_id: str, destroy_persistent: bool = False) -> None:
        await self._client._delete(
            f"/v1/cells/{cell_id}", params={"destroy_persistent": destroy_persistent}
        )


class _AsyncFilesAPI:
    def __init__(self, client: AsyncAiJailer):
        self._client = client

    async def upload(self, cell_id: str, local_path: str, remote_path: str) -> dict:
        with open(local_path, "rb") as f:
            return await self._client._post_multipart(
                f"/v1/cells/{cell_id}/files/upload",
                data={"path": remote_path},
                files={"file": f},
            )

    async def read(self, cell_id: str, path: str) -> str:
        content = await self._client._get_raw(
            f"/v1/cells/{cell_id}/files/download", params={"path": path}
        )
        return content.decode()

    async def list(
        self, cell_id: str, path: str = "/", recursive: bool = False
    ) -> list[FileEntry]:
        data = await self._client._get(
            f"/v1/cells/{cell_id}/files/list",
            params={"path": path, "recursive": recursive},
        )
        return [FileEntry(**e) for e in data.get("entries", [])]


class _AsyncSnapshotsAPI:
    def __init__(self, client: AsyncAiJailer):
        self._client = client

    async def create(
        self, cell_id: str, name: str | None = None, description: str | None = None
    ) -> Snapshot:
        data = await self._client._post(
            f"/v1/cells/{cell_id}/snapshots",
            json={"name": name, "description": description},
        )
        return Snapshot(**{k: v for k, v in data.items() if k in Snapshot.__dataclass_fields__})

    async def list(self, cell_id: str) -> list[Snapshot]:
        data = await self._client._get(f"/v1/cells/{cell_id}/snapshots")
        if isinstance(data, list):
            return [
                Snapshot(**{k: v for k, v in s.items() if k in Snapshot.__dataclass_fields__})
                for s in data
            ]
        return []


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------


class AsyncAiJailer:
    """Async AI Jailer SDK client.

    Usage:
        async with AsyncAiJailer(api_key="aj_live_xxxx") as client:
            cell = await client.cells.create(image="base-python")
            result = await client.exec(cell.id, command="echo hello")
            await client.cells.destroy(cell.id)
    """

    def __init__(
        self,
        api_key: str | None = None,
        config: AiJailerConfig | None = None,
    ):
        if config:
            self._config = config
        else:
            self._config = AiJailerConfig(api_key=api_key or "")

        self._http = httpx.AsyncClient(
            base_url=self._config.base_url,
            headers={"Authorization": f"Bearer {self._config.api_key}"},
            timeout=self._config.timeout,
        )

        self.cells = _AsyncCellsAPI(self)
        self.files = _AsyncFilesAPI(self)
        self.snapshots = _AsyncSnapshotsAPI(self)

    async def __aenter__(self) -> AsyncAiJailer:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def close(self) -> None:
        await self._http.aclose()

    def _handle_error(self, response: httpx.Response) -> None:
        if response.status_code >= 400:
            try:
                body = response.json()
                error = body.get("error", {})
                code = error.get("code", "unknown")
                message = error.get("message", response.text)
                exc_class = ERROR_MAP.get(code, AiJailerError)
                raise exc_class(message)
            except (ValueError, KeyError):
                raise AiJailerError(f"HTTP {response.status_code}: {response.text}")

    async def _get(self, path: str, params: dict | None = None) -> Any:
        response = await self._http.get(path, params=params)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    async def _post(self, path: str, json: dict | None = None) -> Any:
        response = await self._http.post(path, json=json)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    async def _delete(self, path: str, params: dict | None = None) -> None:
        response = await self._http.delete(path, params=params)
        self._handle_error(response)

    async def _post_multipart(self, path: str, data: dict, files: dict) -> Any:
        response = await self._http.post(path, data=data, files=files)
        self._handle_error(response)
        body = response.json()
        return body.get("data", body)

    async def _get_raw(self, path: str, params: dict | None = None) -> bytes:
        response = await self._http.get(path, params=params)
        self._handle_error(response)
        return response.content

    # --- Convenience methods ---

    async def exec(self, cell_id: str, command: str, **kwargs) -> Execution:
        """Execute a command in a cell."""
        data = await self._post(
            f"/v1/cells/{cell_id}/exec", json={"command": command, **kwargs}
        )
        return Execution(**{k: v for k, v in data.items() if k in Execution.__dataclass_fields__})

    async def exec_script(self, cell_id: str, script: str, **kwargs) -> Execution:
        data = await self._post(
            f"/v1/cells/{cell_id}/exec/script", json={"script": script, **kwargs}
        )
        return Execution(**{k: v for k, v in data.items() if k in Execution.__dataclass_fields__})

    @asynccontextmanager
    async def cell(
        self, image: str = "base-python", **kwargs
    ) -> AsyncGenerator[Cell, None]:
        """Async context manager — creates and auto-destroys a cell."""
        cell = await self.cells.create(image=image, auto_start=True, **kwargs)
        try:
            yield cell
        finally:
            await self.cells.destroy(cell.id)
