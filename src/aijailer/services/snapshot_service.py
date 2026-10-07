"""Snapshots: create, restore-in-place, and clone.

A snapshot is the engine's bundle (memory, VM state, disk) in ``<SNAPSHOT_DIR>/<tenant>/<id>``
plus a database row holding the cell configuration at the time. Two properties of the guest shape
everything here:

* the guest's network identity (its /30) is baked into its memory, so a restore needs the SAME
  address: it is claimed explicitly and the request is refused (409) if another cell holds it;
* the machine shape is fixed by the snapshot, so a clone cannot be given different resources.

What is NOT taken from the snapshot, on purpose: the security policy and bandwidth. A restore
keeps the cell's *current* policy (restoring must never resurrect an older, looser one), and a
clone uses the snapshot's policy only if it still exists and is usable (else the caller must pass one).
"""

import uuid
from datetime import datetime, timezone
from pathlib import Path

import structlog
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.config import get_settings
from aijailer.core.exceptions import (
    AiJailerError,
    CellLimitExceededError,
    InvalidStateTransitionError,
)
from aijailer.engine.microvm import VMConfig, VMNetwork
from aijailer.models.audit import EventType
from aijailer.models.cell import Cell
from aijailer.models.snapshot import Snapshot
from aijailer.models.tenant import Tenant
from aijailer.services.cell_service import CellService

logger = structlog.get_logger(__name__)

SNAPSHOTTABLE = {"ready", "running", "paused"}
RESTORABLE = {"ready", "running", "paused", "stopped", "error"}


def _err(message: str, code: str) -> AiJailerError:
    return AiJailerError(message, code=code)


class SnapshotService:
    def __init__(self, db: AsyncSession, cells: CellService | None = None):
        self.db = db
        self.cells = cells or CellService(db)
        self.engine = self.cells.engine
        self.audit = self.cells.audit

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _key(tenant_id: uuid.UUID, snapshot_id: uuid.UUID) -> str:
        return f"{tenant_id}/{snapshot_id}"           # only UUIDs: no user input in a path

    def _dir(self, snap: Snapshot) -> str:
        return str(Path(get_settings().snapshot_dir) / self._key(snap.tenant_id, snap.id))

    async def get_snapshot(self, snapshot_id: uuid.UUID, tenant_id: uuid.UUID) -> Snapshot:
        snap = (await self.db.execute(select(Snapshot).where(
            Snapshot.id == snapshot_id, Snapshot.tenant_id == tenant_id))).scalar_one_or_none()
        if snap is None:
            raise _err(f"Snapshot '{snapshot_id}' does not exist or is not accessible.",
                       "snapshot_not_found")
        return snap

    @staticmethod
    def _usable(snap: Snapshot) -> None:
        if snap.status != "available":
            raise _err(f"Snapshot is {snap.status}, not available.", "snapshot_not_available")

    def _net_for(self, config: dict) -> str | None:
        subnet = (config.get("network") or {}).get("subnet")
        return subnet if self.cells._network is not None else None

    async def _vm_config(self, cell: Cell, provisioned) -> VMConfig:
        return VMConfig(
            cell_id=cell.id, image=cell.image, vcpus=cell.vcpus, memory_mb=cell.memory_mb,
            disk_mb=cell.disk_mb, network_bandwidth_mbps=cell.network_bandwidth_mbps,
            environment={**(cell.environment or {}), **(provisioned.env if provisioned else {})},
            network=VMNetwork(
                provisioned.link.tap_name if provisioned.link else provisioned.net.ifname,
                str(provisioned.net.guest_ip), str(provisioned.net.host_ip),
                provisioned.net.prefix,
                provisioned.link.netns_path if provisioned.link else None)
            if provisioned else None)

    async def _claim_in_flight(self, cell_id: uuid.UUID, allowed: set[str]) -> bool:
        """Atomically move the cell to 'creating' (a status the reconcilers never touch) so two
        restores cannot race and the sweeps leave the cell alone while its VM is replaced."""
        res = await self.db.execute(update(Cell).where(
            Cell.id == cell_id, Cell.status.in_(allowed)).values(status="creating"))
        await self.db.commit()                # visible to the reconcilers immediately
        return res.rowcount == 1

    # ------------------------------------------------------------------ create
    async def create_snapshot(self, cell_id: uuid.UUID, tenant_id: uuid.UUID, name: str | None,
                              description: str | None) -> Snapshot:
        cell = await self.cells.get_cell(cell_id, tenant_id)
        if cell.status not in SNAPSHOTTABLE:
            raise InvalidStateTransitionError(str(cell.id), cell.status, "snapshot")
        snap = Snapshot(tenant_id=tenant_id, cell_id=cell_id, name=name, description=description,
                        status="creating", cell_config={})
        self.db.add(snap)
        await self.db.flush()
        path = self._dir(snap)
        try:
            out = await self.engine.snapshot_vm(cell_id, path)
        except NotImplementedError:
            raise _err("this isolation backend does not support snapshots",
                       "snapshot_unsupported") from None
        except Exception as exc:
            logger.error("snapshot.failed", cell_id=str(cell_id), error=str(exc))
            self._discard_dir(path)
            raise _err("snapshot failed", "snapshot_failed") from None
        sizes = {k: self._size(out.get(k)) for k in ("memory", "disk")}
        snap.cell_config = {
            "image": cell.image, "vcpus": cell.vcpus, "memory_mb": cell.memory_mb,
            "disk_mb": cell.disk_mb, "network_bandwidth_mbps": cell.network_bandwidth_mbps,
            "bandwidth_override": cell.bandwidth_override,
            "security_policy_id": str(cell.security_policy_id), "environment": cell.environment,
            "network": {"subnet": self.cells._network.subnet_of(cell_id)
                        if self.cells._network is not None else None},
        }
        snap.memory_snapshot_key = self._key(tenant_id, snap.id) + "/vm.mem" if out.get("memory") else None
        snap.disk_snapshot_key = self._key(tenant_id, snap.id) + "/rootfs.ext4" if out.get("disk") else None
        snap.memory_size_bytes, snap.disk_size_bytes = sizes["memory"], sizes["disk"]
        snap.total_size_bytes = (sizes["memory"] or 0) + (sizes["disk"] or 0) or None
        snap.status = "available"
        snap.completed_at = datetime.now(timezone.utc)
        await self.db.flush()
        await self.audit.record_event(
            tenant_id=tenant_id, cell_id=cell_id, event_type=EventType.LIFECYCLE,
            details={"action": "snapshot_created", "snapshot_id": str(snap.id)})
        return snap

    @staticmethod
    def _size(path) -> int | None:
        try:
            return Path(path).stat().st_size if path else None
        except OSError:
            return None

    @staticmethod
    def _discard_dir(path: str) -> None:
        import shutil
        shutil.rmtree(path, ignore_errors=True)

    # ------------------------------------------------------------------ restore
    async def restore_cell(self, cell_id: uuid.UUID, tenant_id: uuid.UUID,
                           snapshot_id: uuid.UUID) -> Cell:
        """Replace the cell's VM with the snapshot's state. DESTRUCTIVE: the current VM (and
        everything in it since the snapshot) is gone. Everything that can be checked first is,
        so the usual refusals happen before anything is destroyed."""
        cell = await self.cells.get_cell(cell_id, tenant_id)
        snap = await self.get_snapshot(snapshot_id, tenant_id)
        self._usable(snap)
        if snap.cell_id != cell_id:
            raise _err("snapshot belongs to a different cell; use clone", "snapshot_cell_mismatch")
        if cell.status not in RESTORABLE:
            raise InvalidStateTransitionError(str(cell.id), cell.status, "restore")
        subnet = self._net_for(snap.cell_config)
        net = self.cells._network
        if net is not None and subnet and not net.subnet_available(cell_id, subnet):
            raise _err("the snapshot's guest address is held by another cell", "snapshot_address_in_use")
        await self._check(snap)
        if not await self._claim_in_flight(cell_id, RESTORABLE):
            raise InvalidStateTransitionError(str(cell.id), "changing", "restore")
        cell = await self.cells.get_cell(cell_id, tenant_id)
        try:
            try:
                await self.engine.destroy_vm(cell_id)
            except Exception:
                logger.exception("snapshot.restore.destroy_old_failed", cell_id=str(cell_id))
            await self.cells._deprovision_network(cell_id)
            provisioned = await self.cells._provision_network(cell, subnet)
            info = await self.engine.restore_vm(await self._vm_config(cell, provisioned),
                                                self._dir(snap))
        except Exception as exc:
            logger.error("snapshot.restore_failed", cell_id=str(cell_id), error=str(exc))
            try:
                await self.engine.destroy_vm(cell_id)
            except Exception:
                logger.exception("snapshot.restore.cleanup_vm_failed", cell_id=str(cell_id))
            await self.cells._deprovision_network(cell_id)
            cell.status, cell.error_message = "error", "restore failed; the cell has no VM"
            await self.db.commit()          # the error state must survive the raised exception
            raise _err("restore failed; the cell's previous VM was already replaced and is gone",
                       "restore_failed") from None
        cell.internal_ip = info.internal_ip
        cell.status, cell.error_message = "running", None
        cell.started_at, cell.paused_at, cell.stopped_at = datetime.now(timezone.utc), None, None
        await self.db.flush()
        await self.audit.record_event(
            tenant_id=tenant_id, cell_id=cell_id, event_type=EventType.LIFECYCLE,
            details={"action": "restored", "snapshot_id": str(snap.id)})
        return cell

    async def _check(self, snap: Snapshot) -> None:
        try:
            await self.engine.check_snapshot(self._dir(snap))
        except Exception as exc:
            logger.error("snapshot.bundle_invalid", snapshot_id=str(snap.id), error=str(exc))
            raise _err("snapshot data is missing or corrupt", "snapshot_corrupt") from None

    # ------------------------------------------------------------------ clone
    async def clone_snapshot(self, snapshot_id: uuid.UUID, tenant_id: uuid.UUID, name: str | None,
                             security_policy_id: uuid.UUID | None = None,
                             resources_requested: bool = False) -> Cell:
        """New cell from a snapshot. It gets the snapshot's guest address, so this works only
        while no other cell holds that address (typically: the source cell is gone). The clone
        shares the source's saved RNG state: do not treat it as independent for keys or nonces."""
        if resources_requested:
            raise _err("a clone keeps the snapshot's resources (they are part of the saved "
                       "machine); omit 'resources'", "invalid_clone")
        snap = await self.get_snapshot(snapshot_id, tenant_id)
        self._usable(snap)
        cfg = snap.cell_config
        tenant = await self.db.get(Tenant, tenant_id)
        active = (await self.db.execute(select(func.count()).select_from(Cell).where(
            Cell.tenant_id == tenant_id,
            Cell.status.in_(["creating", "ready", "running", "paused"])))).scalar_one()
        if active >= tenant.max_concurrent_cells:
            raise CellLimitExceededError(str(tenant_id), tenant.max_concurrent_cells)
        policy_id = security_policy_id or uuid.UUID(cfg["security_policy_id"])
        effective = await self.cells._effective_policy(tenant_id, policy_id)
        subnet = self._net_for(cfg)
        new_id = uuid.uuid4()
        net = self.cells._network
        if net is not None and subnet and not net.subnet_available(new_id, subnet):
            raise _err("the snapshot's guest address is held by another cell (is the source "
                       "cell still running?)", "snapshot_address_in_use")
        await self._check(snap)
        cell = Cell(
            id=new_id, tenant_id=tenant_id, name=name or (f"{snap.name}-clone" if snap.name else None),
            image=cfg["image"], vcpus=cfg["vcpus"], memory_mb=cfg["memory_mb"],
            disk_mb=cfg["disk_mb"], network_bandwidth_mbps=cfg["network_bandwidth_mbps"],
            bandwidth_override=cfg.get("bandwidth_override"), security_policy_id=policy_id,
            effective_policy=effective, environment=cfg.get("environment") or {},
            tags={"cloned_from_snapshot": str(snap.id)}, status="creating")
        self.db.add(cell)
        await self.db.flush()
        try:
            provisioned = await self.cells._provision_network(cell, subnet)
            info = await self.engine.restore_vm(await self._vm_config(cell, provisioned),
                                                self._dir(snap))
            cell.internal_ip = info.internal_ip
            cell.status, cell.started_at = "running", datetime.now(timezone.utc)
        except Exception as exc:
            logger.error("snapshot.clone_failed", cell_id=str(cell.id), error=str(exc))
            cell.status, cell.error_message = "error", "clone failed"
            try:
                await self.engine.destroy_vm(cell.id)
            except Exception:
                logger.exception("snapshot.clone.cleanup_vm_failed", cell_id=str(cell.id))
            await self.cells._deprovision_network(cell.id)
        await self.audit.record_event(
            tenant_id=tenant_id, cell_id=cell.id, event_type=EventType.LIFECYCLE,
            details={"action": "cloned", "snapshot_id": str(snap.id), "status": cell.status})
        return cell
