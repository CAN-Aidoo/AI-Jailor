"""Usage and metering API routes."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.schemas.audit import UsagePeriod, UsageResponse, UsageTotals
from aijailer.schemas.common import ApiResponse
from aijailer.services.resource_service import get_resource_governor

router = APIRouter(prefix="/v1/usage", tags=["Usage"])


@router.get("", response_model=ApiResponse[UsageResponse])
async def get_usage(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    granularity: str = Query("daily"),
    group_by: str | None = Query(None),
    auth: AuthContext = Depends(authenticate),
):
    """Get usage summary for the authenticated tenant.

    In production, this queries TimescaleDB continuous aggregates
    for metering data and calculates costs. For the MVP, we pull
    from the in-memory ResourceGovernor.
    """
    governor = get_resource_governor()
    summary = governor.get_tenant_usage_summary(
        tenant_id=auth.tenant_id,
        start_time=start_time,
        end_time=end_time,
    )

    return ApiResponse(
        data=UsageResponse(
            period=UsagePeriod(start=start_time, end=end_time),
            totals=UsageTotals(
                cpu_core_seconds=summary["cpu_core_seconds"],
                memory_gb_seconds=summary["memory_gb_seconds"],
                storage_gb_hours=summary["storage_gb_hours"],
                network_egress_gb=summary["network_egress_gb"],
                api_calls=summary["api_calls"],
                cell_count=summary["cell_count"],
                estimated_cost_usd=summary["estimated_cost_usd"],
            ),
        )
    )


@router.get("/alerts", tags=["Usage"])
async def get_spending_alerts(
    auth: AuthContext = Depends(authenticate),
):
    """Get spending alerts for the authenticated tenant."""
    governor = get_resource_governor()
    alerts = governor.get_alerts(auth.tenant_id)
    return ApiResponse(
        data=[
            {
                "threshold_pct": a.threshold_pct,
                "current_spend_cents": a.current_spend_cents,
                "cap_cents": a.cap_cents,
                "triggered_at": a.triggered_at.isoformat(),
            }
            for a in alerts
        ]
    )
