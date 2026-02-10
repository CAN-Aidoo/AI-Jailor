"""Resource governor service — quota enforcement and usage metering.

In production, this collects metrics from cgroups v2 every 10 seconds,
stores in TimescaleDB, and enforces spending caps. For the MVP, it
provides an in-memory metering implementation.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class ResourceUsage:
    """Accumulated resource usage for a cell."""

    cell_id: uuid.UUID
    tenant_id: uuid.UUID
    cpu_core_seconds: float = 0.0
    memory_gb_seconds: float = 0.0
    disk_gb_hours: float = 0.0
    network_egress_bytes: int = 0
    api_calls: int = 0
    last_sample_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class TenantQuotas:
    """Tenant-level resource quotas."""

    max_concurrent_cells: int = 10
    max_total_vcpus: int = 32
    max_total_memory_mb: int = 65536
    max_persistent_storage_gb: int = 50
    max_snapshots: int = 100
    max_api_calls_per_minute: int = 300
    spending_cap_cents: int | None = None


@dataclass
class SpendingAlert:
    """Spending threshold alert."""

    tenant_id: uuid.UUID
    threshold_pct: int
    current_spend_cents: int
    cap_cents: int
    triggered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# Pricing (per unit, in cents)
PRICING = {
    "cpu_core_second": 0.000004,      # $0.04 / 10k core-seconds
    "memory_gb_second": 0.000002,     # $0.02 / 10k GB-seconds
    "disk_gb_hour": 0.01,             # $0.01 / GB-hour
    "network_egress_gb": 5.0,         # $0.05 / GB
    "api_call": 0.0001,              # $0.001 / 10 calls
    "snapshot_gb_hour": 0.005,        # $0.005 / GB-hour
}


class ResourceGovernor:
    """Resource metering, quota enforcement, and cost tracking."""

    def __init__(self) -> None:
        self._usage: dict[uuid.UUID, ResourceUsage] = {}  # per cell
        self._tenant_usage: dict[uuid.UUID, dict] = {}     # aggregated per tenant
        self._quotas: dict[uuid.UUID, TenantQuotas] = {}
        self._alerts: list[SpendingAlert] = []

    def set_tenant_quotas(self, tenant_id: uuid.UUID, quotas: TenantQuotas) -> None:
        """Set or update quotas for a tenant."""
        self._quotas[tenant_id] = quotas

    def get_tenant_quotas(self, tenant_id: uuid.UUID) -> TenantQuotas:
        return self._quotas.get(tenant_id, TenantQuotas())

    async def record_usage(
        self,
        cell_id: uuid.UUID,
        tenant_id: uuid.UUID,
        cpu_seconds: float = 0.0,
        memory_gb_seconds: float = 0.0,
        disk_gb_hours: float = 0.0,
        network_egress_bytes: int = 0,
        api_calls: int = 0,
    ) -> None:
        """Record resource usage for a cell."""
        if cell_id not in self._usage:
            self._usage[cell_id] = ResourceUsage(cell_id=cell_id, tenant_id=tenant_id)

        usage = self._usage[cell_id]
        usage.cpu_core_seconds += cpu_seconds
        usage.memory_gb_seconds += memory_gb_seconds
        usage.disk_gb_hours += disk_gb_hours
        usage.network_egress_bytes += network_egress_bytes
        usage.api_calls += api_calls
        usage.last_sample_at = datetime.now(timezone.utc)

        # Check spending alerts
        await self._check_spending(tenant_id)

    async def _check_spending(self, tenant_id: uuid.UUID) -> None:
        """Check if tenant spending exceeds thresholds and emit alerts."""
        quotas = self.get_tenant_quotas(tenant_id)
        if quotas.spending_cap_cents is None:
            return

        total_cost = self.calculate_tenant_cost(tenant_id)
        total_cents = int(total_cost * 100)

        for threshold in [50, 80, 95, 100]:
            if total_cents >= (quotas.spending_cap_cents * threshold // 100):
                alert = SpendingAlert(
                    tenant_id=tenant_id,
                    threshold_pct=threshold,
                    current_spend_cents=total_cents,
                    cap_cents=quotas.spending_cap_cents,
                )
                self._alerts.append(alert)
                logger.warning(
                    "spending.threshold_reached",
                    tenant_id=str(tenant_id),
                    threshold_pct=threshold,
                    current_cents=total_cents,
                    cap_cents=quotas.spending_cap_cents,
                )

    def calculate_cell_cost(self, cell_id: uuid.UUID) -> float:
        """Calculate current cost for a cell in dollars."""
        usage = self._usage.get(cell_id)
        if not usage:
            return 0.0

        return (
            usage.cpu_core_seconds * PRICING["cpu_core_second"]
            + usage.memory_gb_seconds * PRICING["memory_gb_second"]
            + usage.disk_gb_hours * PRICING["disk_gb_hour"]
            + (usage.network_egress_bytes / 1_073_741_824) * PRICING["network_egress_gb"]
            + usage.api_calls * PRICING["api_call"]
        )

    def calculate_tenant_cost(self, tenant_id: uuid.UUID) -> float:
        """Calculate total cost for all cells belonging to a tenant."""
        total = 0.0
        for cell_id, usage in self._usage.items():
            if usage.tenant_id == tenant_id:
                total += self.calculate_cell_cost(cell_id)
        return total

    def get_tenant_usage_summary(
        self,
        tenant_id: uuid.UUID,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict:
        """Get aggregated usage for a tenant."""
        totals = {
            "cpu_core_seconds": 0.0,
            "memory_gb_seconds": 0.0,
            "storage_gb_hours": 0.0,
            "network_egress_gb": 0.0,
            "api_calls": 0,
            "cell_count": 0,
            "estimated_cost_usd": 0.0,
        }

        for cell_id, usage in self._usage.items():
            if usage.tenant_id != tenant_id:
                continue
            totals["cpu_core_seconds"] += usage.cpu_core_seconds
            totals["memory_gb_seconds"] += usage.memory_gb_seconds
            totals["storage_gb_hours"] += usage.disk_gb_hours
            totals["network_egress_gb"] += usage.network_egress_bytes / 1_073_741_824
            totals["api_calls"] += usage.api_calls
            totals["cell_count"] += 1

        totals["estimated_cost_usd"] = self.calculate_tenant_cost(tenant_id)
        return totals

    def get_alerts(self, tenant_id: uuid.UUID) -> list[SpendingAlert]:
        return [a for a in self._alerts if a.tenant_id == tenant_id]


# Singleton
_governor: ResourceGovernor | None = None


def get_resource_governor() -> ResourceGovernor:
    global _governor
    if _governor is None:
        _governor = ResourceGovernor()
    return _governor
