"""SDK data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class Cell:
    """Represents an AI Jailer cell."""

    id: str
    name: str | None = None
    status: str = "creating"
    image: str = "base-python"
    resources: dict[str, Any] = field(default_factory=dict)
    security_policy_id: str | None = None
    network: dict[str, Any] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)
    created_at: str | None = None
    started_at: str | None = None

    # For context manager pattern — set by client
    _client: Any = field(default=None, repr=False)

    def exec(self, command: str, **kwargs) -> Execution:
        """Execute a command in this cell."""
        if self._client is None:
            raise RuntimeError("Cell not bound to a client. Use client.exec() instead.")
        return self._client.exec(self.id, command=command, **kwargs)

    def exec_script(self, script: str, **kwargs) -> Execution:
        """Execute a script in this cell."""
        if self._client is None:
            raise RuntimeError("Cell not bound to a client.")
        return self._client.exec_script(self.id, script=script, **kwargs)


@dataclass
class Execution:
    """Result of executing a command in a cell."""

    execution_id: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    resource_usage: dict[str, Any] = field(default_factory=dict)


@dataclass
class Snapshot:
    """Represents a cell snapshot."""

    id: str
    cell_id: str
    name: str | None = None
    description: str | None = None
    status: str = "creating"
    total_size_bytes: int | None = None
    created_at: str | None = None
    completed_at: str | None = None

    def wait_until_ready(self, timeout: int = 60) -> None:
        """Poll until snapshot is ready."""
        pass  # Implemented by client in production


@dataclass
class FileEntry:
    """Represents a file or directory inside a cell."""

    name: str
    type: str  # "file" or "directory"
    size: int | None = None
    modified_at: str | None = None
    permissions: str | None = None

    @property
    def is_dir(self) -> bool:
        return self.type == "directory"

    @property
    def path(self) -> str:
        return self.name


@dataclass
class NetworkPolicy:
    """Network policy configuration."""

    default: str = "deny"
    egress: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ResourcePolicy:
    """Resource limit policy configuration."""

    max_vcpus: int | None = None
    max_memory_mb: int | None = None
    max_disk_mb: int | None = None
    max_pids: int | None = None
    max_open_files: int | None = None


@dataclass
class PolicyResponse:
    """Represents a security policy."""

    id: str
    name: str
    description: str | None = None
    version: int = 1
    status: str = "active"
    network: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, Any] = field(default_factory=dict)
    filesystem: dict[str, Any] = field(default_factory=dict)
    syscalls: dict[str, Any] = field(default_factory=dict)
