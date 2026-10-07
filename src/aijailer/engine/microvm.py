"""MicroVM engine abstraction layer.

This module defines the interface for managing Firecracker microVMs.
In the MVP, operations are simulated. In production, this communicates
with the Firecracker process via its REST API and vsock for cell agent
communication.
"""

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum


class VMStatus(str, Enum):
    CREATING = "creating"
    READY = "ready"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    DESTROYED = "destroyed"
    ERROR = "error"


@dataclass(frozen=True)
class VMNetwork:
    """The cell's one controlled link (see netpolicy/). Absent => the VM gets NO NIC."""

    tap_name: str
    guest_ip: str
    host_ip: str
    prefix: int = 30
    netns_path: str | None = None  # the VMM must run inside this namespace (jailer --netns)


@dataclass
class VMConfig:
    """Configuration for a new microVM."""

    cell_id: uuid.UUID
    image: str
    vcpus: int = 1
    memory_mb: int = 512
    disk_mb: int = 2048
    network_bandwidth_mbps: int = 100
    environment: dict = field(default_factory=dict)
    network_policy: dict = field(default_factory=dict)
    network: VMNetwork | None = None


@dataclass
class VMInfo:
    """Runtime information about a microVM."""

    cell_id: uuid.UUID
    status: VMStatus
    pid: int | None = None
    internal_ip: str | None = None
    vsock_path: str | None = None


@dataclass
class ExecResult:
    """Result from executing a command inside a microVM."""

    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    cpu_ms: int = 0
    memory_peak_mb: int = 0
    timed_out: bool = False
    output_truncated: bool = False


@dataclass
class EngineSweepReport:
    """What one engine reconciliation pass found and did (see FirecrackerEngine.reconcile)."""

    adopted: list[uuid.UUID] = field(default_factory=list)    # live cell, VMM survived a restart
    orphans_killed: list[uuid.UUID] = field(default_factory=list)  # VMM with no live cell
    leftovers_removed: list[uuid.UUID] = field(default_factory=list)  # jail/cgroup, no VMM
    dead: list[uuid.UUID] = field(default_factory=list)       # live cell whose VMM is gone
    unresponsive: list[uuid.UUID] = field(default_factory=list)  # live cell, VMM not answering
    skipped_young: list[uuid.UUID] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    aborted: bool = False

    @property
    def broken(self) -> list[uuid.UUID]:
        return [*self.dead, *self.unresponsive]

    @property
    def changed(self) -> bool:
        return bool(self.adopted or self.orphans_killed or self.leftovers_removed or self.dead)


class MicroVMEngine(ABC):
    """Abstract interface for MicroVM management."""

    isolation = "unknown"
    needs_network = False  # True when the engine attaches a real NIC that must be firewalled

    @abstractmethod
    async def create_vm(self, config: VMConfig) -> VMInfo:
        """Create and boot a new microVM."""

    @abstractmethod
    async def start_vm(self, cell_id: uuid.UUID) -> VMInfo:
        """Start a stopped microVM."""

    @abstractmethod
    async def stop_vm(self, cell_id: uuid.UUID, grace_period: int = 10) -> None:
        """Stop a running microVM."""

    @abstractmethod
    async def pause_vm(self, cell_id: uuid.UUID) -> None:
        """Pause a running microVM (freeze VM state)."""

    @abstractmethod
    async def resume_vm(self, cell_id: uuid.UUID) -> None:
        """Resume a paused microVM."""

    @abstractmethod
    async def destroy_vm(self, cell_id: uuid.UUID) -> None:
        """Destroy a microVM and clean up all resources."""

    @abstractmethod
    async def exec_command(
        self, cell_id: uuid.UUID, command: str, timeout: int = 30, user: str = "agent"
    ) -> ExecResult:
        """Execute a command inside a microVM via the cell agent."""

    async def snapshot_vm(self, cell_id: uuid.UUID, snapshot_dir: str) -> dict:
        """Pause + dump memory/device state. Optional capability."""
        raise NotImplementedError(f"{type(self).__name__} does not support snapshots")

    async def restore_vm(self, config: "VMConfig", snapshot_dir: str) -> "VMInfo":
        raise NotImplementedError(f"{type(self).__name__} does not support restore")

    @abstractmethod
    async def get_vm_info(self, cell_id: uuid.UUID) -> VMInfo:
        """Get current status and info for a microVM."""

    async def reconcile(self, live: dict[uuid.UUID, dict], protected: set[uuid.UUID],
                        grace: float = 120.0) -> "EngineSweepReport | None":
        """Make the host's VMM processes/files match the set of cells the database says are live
        (``live`` maps cell id -> guest environment). Engines with no host state return None."""
        return None


class SimulatedMicroVMEngine(MicroVMEngine):
    isolation = "none"

    """Simulated MicroVM engine for development and testing.

    Tracks VM state in-memory without actually creating Firecracker processes.
    This allows the full API and service layer to be tested without
    requiring a Linux host with KVM support.
    """

    def __init__(self) -> None:
        self._vms: dict[uuid.UUID, VMInfo] = {}
        self._ip_counter = 10

    def _next_ip(self) -> str:
        self._ip_counter += 1
        return f"10.100.0.{self._ip_counter}"

    async def create_vm(self, config: VMConfig) -> VMInfo:
        info = VMInfo(
            cell_id=config.cell_id,
            status=VMStatus.RUNNING,
            pid=1000 + len(self._vms),
            internal_ip=self._next_ip(),
            vsock_path=f"/tmp/aijailer/{config.cell_id}.vsock",
        )
        self._vms[config.cell_id] = info
        return info

    async def start_vm(self, cell_id: uuid.UUID) -> VMInfo:
        info = self._vms.get(cell_id)
        if info:
            info.status = VMStatus.RUNNING
        else:
            info = VMInfo(cell_id=cell_id, status=VMStatus.RUNNING, internal_ip=self._next_ip())
            self._vms[cell_id] = info
        return info

    async def stop_vm(self, cell_id: uuid.UUID, grace_period: int = 10) -> None:
        info = self._vms.get(cell_id)
        if info:
            info.status = VMStatus.STOPPED

    async def pause_vm(self, cell_id: uuid.UUID) -> None:
        info = self._vms.get(cell_id)
        if info:
            info.status = VMStatus.PAUSED

    async def resume_vm(self, cell_id: uuid.UUID) -> None:
        info = self._vms.get(cell_id)
        if info:
            info.status = VMStatus.RUNNING

    async def destroy_vm(self, cell_id: uuid.UUID) -> None:
        self._vms.pop(cell_id, None)

    async def exec_command(
        self, cell_id: uuid.UUID, command: str, timeout: int = 30, user: str = "agent"
    ) -> ExecResult:
        """Simulate command execution."""
        return ExecResult(
            exit_code=0,
            stdout=f"[simulated] {command}\n",
            stderr="",
            duration_ms=1,
            cpu_ms=1,
            memory_peak_mb=10,
        )

    async def get_vm_info(self, cell_id: uuid.UUID) -> VMInfo:
        info = self._vms.get(cell_id)
        if info is None:
            return VMInfo(cell_id=cell_id, status=VMStatus.DESTROYED)
        return info


class EngineUnavailable(RuntimeError):
    """The configured isolation backend cannot provide real isolation here."""


_engine: MicroVMEngine | None = None


def build_engine(backend: str, environment: str) -> MicroVMEngine:
    """Select an engine. Fails CLOSED: never silently downgrades isolation."""
    if backend == "simulated":
        if environment != "dev":
            raise EngineUnavailable(
                "ENGINE_BACKEND=simulated provides no isolation and is only allowed "
                "when AIJAILER_ENV=dev"
            )
        return SimulatedMicroVMEngine()
    if backend == "firecracker":
        from aijailer.engine.firecracker import FirecrackerEngine

        return FirecrackerEngine()
    raise EngineUnavailable(f"unknown engine backend '{backend}'")


def get_microvm_engine() -> MicroVMEngine:
    global _engine
    if _engine is None:
        from aijailer.core.config import get_settings

        s = get_settings()
        _engine = build_engine(s.engine_backend, s.environment)
    return _engine
