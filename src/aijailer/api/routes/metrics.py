"""Metrics API route.

GET /v1/metrics/dashboard — Generation statistics and performance metrics.
"""

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.models.attack_pattern import AttackPattern
from aijailer.models.certified_component import CertifiedComponent
from aijailer.models.constraint import Constraint
from aijailer.models.generation_log import GenerationLog

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/metrics", tags=["Metrics"])


@router.get("/dashboard")
async def get_metrics_dashboard(db: AsyncSession = Depends(get_db)):
    """Get the generation metrics dashboard.

    Returns aggregate statistics about code generation,
    constraint enforcement, and immune memory activity.
    """
    # Total generations
    total_result = await db.execute(select(func.count(GenerationLog.id)))
    total = total_result.scalar() or 0

    # Blocked generations
    blocked_result = await db.execute(
        select(func.count(GenerationLog.id)).where(GenerationLog.blocked.is_(True))
    )
    blocked = blocked_result.scalar() or 0

    # Average latency
    avg_latency_result = await db.execute(
        select(func.avg(GenerationLog.latency_ms))
    )
    avg_latency = avg_latency_result.scalar() or 0

    # Active components
    comp_result = await db.execute(
        select(func.count(CertifiedComponent.id)).where(
            CertifiedComponent.status == "active"
        )
    )
    active_components = comp_result.scalar() or 0

    # Active constraints
    constraint_result = await db.execute(
        select(func.count(Constraint.id)).where(Constraint.is_active.is_(True))
    )
    active_constraints = constraint_result.scalar() or 0

    # Attack patterns
    pattern_result = await db.execute(
        select(func.count(AttackPattern.id)).where(AttackPattern.status == "active")
    )
    active_patterns = pattern_result.scalar() or 0

    return {
        "dashboard": {
            "generation": {
                "total": total,
                "successful": total - blocked,
                "blocked": blocked,
                "block_rate_percent": round(
                    (blocked / max(total, 1)) * 100, 2
                ),
                "avg_latency_ms": round(float(avg_latency), 1),
            },
            "components": {
                "active": active_components,
            },
            "constraints": {
                "active": active_constraints,
            },
            "immune_memory": {
                "active_attack_patterns": active_patterns,
            },
        },
    }
