"""Cell lifecycle management service.

Manages the full cell lifecycle with validated state transitions,
MicroVM engine integration, and audit event recording.
"""

import uuid
from datetime import datetime, timezone

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.exceptions import (
    CellLimitExceededError,
    CellNotFoundError,
    CellNotRunningError,
    InvalidStateTransitionError,
)
from aijailer.engine.microvm import VMConfig, VMNetwork, get_microvm_engine
from aijailer.models.audit import EventType, Severity
from aijailer.models.cell import Cell
from aijailer.models.tenant import Tenant
from aijailer.netpolicy.shaping import Bandwidth
from aijailer.netpolicy.runtime import get_cell_network, network_required, remember_tenant
from aijailer.services.audit_service import get_audit_service

logger = structlog.get_logger(__name__)

# Valid state transitions (from -> set of valid targets)
VALID_TRANSITIONS: dict[str, set[str]] = {
    "creating": {"ready", "running", "error"},
    "ready": {"running", "destroying", "error"},
    "running": {"paused", "stopping", "destroying", "error"},
    "paused": {"running", "stopping", "destroying", "error"},
    "stopping": {"stopped", "error"},
    "stopped": {"running", "destroying", "error"},
    "destroying": {"destroyed", "error"},
}


class CellService:
    def __init__(self, db: AsyncSession, network=None):
        self.db = db
        self.engine = get_microvm_engine()
        self.audit = get_audit_service()
        # Network enforcement is mandatory for engines that attach a NIC (fail closed);
        # the simulator has no NIC, so it gets none.
        self._net_required = network_required(self.engine)
        self._network = (network or get_cell_network()) if self._net_required else None

    async def _provision_network(self, cell: Cell):
        """Build the cell's firewalled link + broker. Raises (and cleans up) on failure."""
        if self._network is None:
            return None
        remember_tenant(cell.id, cell.tenant_id)
        policy = (cell.effective_policy or {}).get("network")
        return await self._network.provision(
            cell.id, cell.tenant_id, policy,
            Bandwidth.symmetric_mbps(cell.network_bandwidth_mbps))

    async def _deprovision_network(self, cell_id: uuid.UUID) -> None:
        if self._network is None:
            return
        errors = await self._network.deprovision(cell_id)
        if errors:
            logger.error("cell.network.teardown_incomplete", cell_id=str(cell_id), errors=errors)

    async def create_cell(
        self,
        tenant_id: uuid.UUID,
        name: str | None,
        image: str,
        vcpus: int,
        memory_mb: int,
        disk_mb: int,
        network_bandwidth_mbps: int,
        security_policy_id: uuid.UUID,
        environment: dict,
        tags: dict,
        auto_start: bool = True,
    ) -> Cell:
        """Create a new cell, enforcing tenant limits.

        Steps:
        1. Validate tenant exists and check concurrent cell limit
        2. Persist cell record in DB (status: creating)
        3. Boot MicroVM via engine
        4. If auto_start, transition to running
        5. Record audit event
        """
        tenant = await self.db.get(Tenant, tenant_id)
        if tenant is None:
            raise CellNotFoundError(str(tenant_id))

        active_count_result = await self.db.execute(
            select(func.count())
            .select_from(Cell)
            .where(
                Cell.tenant_id == tenant_id,
                Cell.status.in_(["creating", "ready", "running", "paused"]),
            )
        )
        active_count = active_count_result.scalar_one()

        if active_count >= tenant.max_concurrent_cells:
            raise CellLimitExceededError(str(tenant_id), tenant.max_concurrent_cells)

        cell = Cell(
            tenant_id=tenant_id,
            name=name,
            image=image,
            vcpus=vcpus,
            memory_mb=memory_mb,
            disk_mb=disk_mb,
            network_bandwidth_mbps=network_bandwidth_mbps,
            security_policy_id=security_policy_id,
            environment=environment,
            tags=tags,
            status="creating",
        )
        self.db.add(cell)
        await self.db.flush()

        logger.info("cell.creating", cell_id=str(cell.id), image=image, tenant_id=str(tenant_id))

        # Network first, VM second: a cell is never booted without its enforced link, and a
        # failed network build never leaves a VM behind.
        provisioned = None
        try:
            provisioned = await self._provision_network(cell)
            vm_config = VMConfig(
                cell_id=cell.id,
                image=image,
                vcpus=vcpus,
                memory_mb=memory_mb,
                disk_mb=disk_mb,
                network_bandwidth_mbps=network_bandwidth_mbps,
                environment={**environment, **(provisioned.env if provisioned else {})},
                network=VMNetwork(
                    provisioned.link.tap_name if provisioned.link else provisioned.net.ifname,
                    str(provisioned.net.guest_ip), str(provisioned.net.host_ip),
                    provisioned.net.prefix,
                    provisioned.link.netns_path if provisioned.link else None)
                if provisioned else None,
            )
            vm_info = await self.engine.create_vm(vm_config)
            cell.internal_ip = vm_info.internal_ip

            if auto_start:
                cell.status = "running"
                cell.started_at = datetime.now(timezone.utc)
            else:
                cell.status = "ready"

            logger.info(
                "cell.created",
                cell_id=str(cell.id),
                status=cell.status,
                internal_ip=vm_info.internal_ip,
            )
        except Exception as e:
            cell.status = "error"
            cell.error_message = str(e)
            logger.error("cell.create_failed", cell_id=str(cell.id), error=str(e))
            try:  # a half-created VM must not survive, and the network must be torn down
                await self.engine.destroy_vm(cell.id)
            except Exception:
                logger.exception("cell.create_cleanup_vm_failed", cell_id=str(cell.id))
            await self._deprovision_network(cell.id)

        # Audit
        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell.id,
            event_type=EventType.LIFECYCLE,
            details={
                "action": "created",
                "image": image,
                "vcpus": vcpus,
                "memory_mb": memory_mb,
                "status": cell.status,
            },
        )

        return cell

    async def get_cell(self, cell_id: uuid.UUID, tenant_id: uuid.UUID) -> Cell:
        """Get a cell by ID, scoped to tenant."""
        result = await self.db.execute(
            select(Cell).where(Cell.id == cell_id, Cell.tenant_id == tenant_id)
        )
        cell = result.scalar_one_or_none()
        if cell is None:
            raise CellNotFoundError(str(cell_id))
        return cell

    async def list_cells(
        self,
        tenant_id: uuid.UUID,
        status: str | None = None,
        tag_key: str | None = None,
        tag_value: str | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> list[Cell]:
        """List cells for a tenant with optional filters."""
        query = (
            select(Cell)
            .where(Cell.tenant_id == tenant_id)
            .order_by(Cell.created_at.desc())
            .limit(limit)
        )

        if status:
            query = query.where(Cell.status == status)

        if cursor:
            query = query.where(Cell.created_at < cursor)

        result = await self.db.execute(query)
        return list(result.scalars().all())

    async def _transition(self, cell: Cell, action: str, target_status: str) -> Cell:
        """Perform a validated state transition."""
        valid = VALID_TRANSITIONS.get(cell.status, set())
        if target_status not in valid:
            raise InvalidStateTransitionError(str(cell.id), cell.status, action)
        old_status = cell.status
        cell.status = target_status
        logger.info(
            "cell.transition",
            cell_id=str(cell.id),
            from_status=old_status,
            to_status=target_status,
            action=action,
        )
        return cell

    async def start_cell(self, cell_id: uuid.UUID, tenant_id: uuid.UUID) -> Cell:
        cell = await self.get_cell(cell_id, tenant_id)
        was_stopped = cell.status == "stopped"
        await self._transition(cell, "start", "running")
        cell.started_at = datetime.now(timezone.utc)
        if was_stopped:  # network is torn down on stop; rebuild before the VM runs again
            await self._provision_network(cell)
        try:
            await self.engine.start_vm(cell_id)
        except Exception:
            if was_stopped:
                await self._deprovision_network(cell_id)
            raise

        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.LIFECYCLE,
            details={"action": "started"},
        )
        return cell

    async def stop_cell(
        self, cell_id: uuid.UUID, tenant_id: uuid.UUID, grace_period_seconds: int = 10
    ) -> Cell:
        cell = await self.get_cell(cell_id, tenant_id)
        await self._transition(cell, "stop", "stopping")
        try:
            await self.engine.stop_vm(cell_id, grace_period=grace_period_seconds)
        finally:
            # Stopped VMs hold no network. Even if the stop call failed, revoke access.
            await self._deprovision_network(cell_id)
        cell.status = "stopped"
        cell.stopped_at = datetime.now(timezone.utc)

        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.LIFECYCLE,
            details={"action": "stopped", "grace_period_seconds": grace_period_seconds},
        )
        return cell

    async def pause_cell(self, cell_id: uuid.UUID, tenant_id: uuid.UUID) -> Cell:
        cell = await self.get_cell(cell_id, tenant_id)
        await self._transition(cell, "pause", "paused")
        cell.paused_at = datetime.now(timezone.utc)
        await self.engine.pause_vm(cell_id)

        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.LIFECYCLE,
            details={"action": "paused"},
        )
        return cell

    async def resume_cell(self, cell_id: uuid.UUID, tenant_id: uuid.UUID) -> Cell:
        cell = await self.get_cell(cell_id, tenant_id)
        await self._transition(cell, "resume", "running")
        cell.started_at = datetime.now(timezone.utc)
        cell.paused_at = None
        await self.engine.resume_vm(cell_id)

        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.LIFECYCLE,
            details={"action": "resumed"},
        )
        return cell

    async def destroy_cell(
        self, cell_id: uuid.UUID, tenant_id: uuid.UUID, destroy_persistent: bool = False
    ) -> None:
        cell = await self.get_cell(cell_id, tenant_id)
        await self._transition(cell, "destroy", "destroying")
        try:
            await self.engine.destroy_vm(cell_id)
        finally:
            await self._deprovision_network(cell_id)
        cell.status = "destroyed"
        cell.destroyed_at = datetime.now(timezone.utc)

        logger.info(
            "cell.destroyed",
            cell_id=str(cell_id),
            destroy_persistent=destroy_persistent,
        )

        await self.audit.record_event(
            tenant_id=tenant_id,
            cell_id=cell_id,
            event_type=EventType.LIFECYCLE,
            details={"action": "destroyed", "destroy_persistent": destroy_persistent},
        )
