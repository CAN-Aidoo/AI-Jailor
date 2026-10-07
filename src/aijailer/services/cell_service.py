"""Cell lifecycle management service.

Manages the full cell lifecycle with validated state transitions,
MicroVM engine integration, and audit event recording.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.config import get_settings
from aijailer.core.exceptions import (
    AiJailerError,
    PolicyNotFoundError,
    CellLimitExceededError,
    CellNotFoundError,
    CellNotRunningError,
    InvalidStateTransitionError,
)
from aijailer.engine.microvm import VMConfig, VMNetwork, get_microvm_engine
from aijailer.models.audit import EventType, Severity
from aijailer.models.cell import Cell
from aijailer.models.policy import SecurityPolicy
from aijailer.models.tenant import Tenant
from aijailer.netpolicy.shaping import MIN_KBIT, Bandwidth, effective_bandwidth
from aijailer.netpolicy.runtime import get_cell_network, network_required, remember_tenant
from aijailer.services.audit_service import get_audit_service

logger = structlog.get_logger(__name__)


@dataclass(frozen=True)
class BandwidthView:
    configured: Bandwidth
    source: str                      # "default" | "override"
    enforced: Bandwidth | None       # None => the cell has no network right now
    min_kbit: int
    max_kbit: int


def _bandwidth_bounds() -> tuple[int, int]:
    return MIN_KBIT, get_settings().max_cell_bandwidth_mbps * 1000


def _check_limits(down_kbit, up_kbit) -> None:
    lo, hi = _bandwidth_bounds()
    for what, v in (("down_kbit", down_kbit), ("up_kbit", up_kbit)):
        if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
            raise AiJailerError(f"{what} must be an integer between {lo} and {hi} kbit/s",
                                code="invalid_bandwidth")

# Cell states in which a bandwidth change is meaningful (a network exists or will be rebuilt).
_BANDWIDTH_STATES = {"ready", "running", "paused", "stopped"}
_HAS_NETWORK = {"ready", "running", "paused"}

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

    async def _provision_network(self, cell: Cell, subnet: str | None = None):
        """Build the cell's firewalled link + broker. Raises (and cleans up) on failure."""
        if self._network is None:
            return None
        remember_tenant(cell.id, cell.tenant_id)
        policy = (cell.effective_policy or {}).get("network")
        extra = {"subnet": subnet} if subnet else {}      # only when pinning a restored guest
        return await self._network.provision(
            cell.id, cell.tenant_id, policy,
            effective_bandwidth(cell.network_bandwidth_mbps, cell.bandwidth_override), **extra)

    async def _deprovision_network(self, cell_id: uuid.UUID) -> None:
        if self._network is None:
            return
        errors = await self._network.deprovision(cell_id)
        if errors:
            logger.error("cell.network.teardown_incomplete", cell_id=str(cell_id), errors=errors)

    async def _effective_policy(self, tenant_id: uuid.UUID, policy_id: uuid.UUID) -> dict | None:
        """Compile the cell's security policy once, at creation (cells keep that version).

        No policy => None => the broker has no egress rules => default deny. A policy that was
        asked for but is missing, archived/deprecated, or belongs to another tenant is an error,
        never silently ignored. (The API passes the tenant id as the 'no policy chosen' marker.)"""
        policy = await self.db.get(SecurityPolicy, policy_id)
        usable = (policy is not None and policy.status == "active"
                  and policy.tenant_id in (tenant_id, None))      # None = platform-wide policy
        if usable:
            from aijailer.services.policy_service import PolicyService
            return PolicyService(self.db).compile_policy(policy)
        if policy_id == tenant_id:
            return None
        raise PolicyNotFoundError(str(policy_id))

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
        cap = get_settings().max_cell_bandwidth_mbps
        if network_bandwidth_mbps > cap:
            raise AiJailerError(f"network_bandwidth_mbps must be at most {cap}",
                                code="invalid_bandwidth")
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

        effective_policy = await self._effective_policy(tenant_id, security_policy_id)
        cell = Cell(
            tenant_id=tenant_id,
            effective_policy=effective_policy,
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


    # ------------------------------------------------------------------ bandwidth
    async def get_bandwidth(self, cell_id: uuid.UUID, tenant_id: uuid.UUID) -> BandwidthView:
        cell = await self.get_cell(cell_id, tenant_id)
        return await self._bandwidth_view(cell)

    async def _bandwidth_view(self, cell: Cell) -> BandwidthView:
        enforced = None
        if self._network is not None and cell.status in _HAS_NETWORK:
            enforced = await self._network.get_bandwidth(cell.id)
        lo, hi = _bandwidth_bounds()
        return BandwidthView(
            configured=effective_bandwidth(cell.network_bandwidth_mbps, cell.bandwidth_override),
            source="override" if cell.bandwidth_override else "default",
            enforced=enforced, min_kbit=lo, max_kbit=hi)

    async def set_bandwidth(self, cell_id: uuid.UUID, tenant_id: uuid.UUID, down_kbit: int,
                            up_kbit: int, actor: uuid.UUID | None = None) -> BandwidthView:
        """Change a cell's limits now (live if it has a network) and persist them.

        Kernel first, database second: if the kernel apply fails nothing is persisted; if the
        persist fails after a successful apply the reconciler restores the DB's value, so the DB
        stays the single source of truth."""
        _check_limits(down_kbit, up_kbit)
        cell = await self.get_cell(cell_id, tenant_id)
        return await self._apply_bandwidth(
            cell, Bandwidth(down_kbit, up_kbit), {"down_kbit": down_kbit, "up_kbit": up_kbit}, actor)

    async def reset_bandwidth(self, cell_id: uuid.UUID, tenant_id: uuid.UUID,
                              actor: uuid.UUID | None = None) -> BandwidthView:
        """Drop the override: back to the symmetric default from ``network_bandwidth_mbps``."""
        cell = await self.get_cell(cell_id, tenant_id)
        return await self._apply_bandwidth(
            cell, effective_bandwidth(cell.network_bandwidth_mbps, None), None, actor)

    async def _apply_bandwidth(self, cell: Cell, bw: Bandwidth, override: dict | None,
                               actor: uuid.UUID | None) -> BandwidthView:
        if cell.status not in _BANDWIDTH_STATES:
            raise InvalidStateTransitionError(str(cell.id), cell.status, "set_bandwidth")
        before = effective_bandwidth(cell.network_bandwidth_mbps, cell.bandwidth_override)
        if self._network is not None and cell.status in _HAS_NETWORK:
            try:
                await self._network.set_bandwidth(cell.id, bw)
            except LookupError:
                raise AiJailerError("cell has no active network (being recovered?)",
                                    code="cell_network_unavailable") from None
            except Exception as exc:
                logger.error("cell.bandwidth_apply_failed", cell_id=str(cell.id), error=str(exc))
                raise AiJailerError("could not apply bandwidth limits to the cell's network",
                                    code="bandwidth_apply_failed") from None
        cell.bandwidth_override = override
        await self.db.flush()
        await self.audit.record_event(
            tenant_id=cell.tenant_id, cell_id=cell.id, event_type=EventType.LIFECYCLE,
            details={"action": "bandwidth_changed", "actor": str(actor) if actor else None,
                     "from": {"down_kbit": before.down_kbit, "up_kbit": before.up_kbit},
                     "to": {"down_kbit": bw.down_kbit, "up_kbit": bw.up_kbit},
                     "live": self._network is not None and cell.status in _HAS_NETWORK})
        return await self._bandwidth_view(cell)
