"""Immune Memory API route.

POST /v1/immune/report — Report a vulnerability to the immune system
GET  /v1/immune/status — Get immune system threat level and status
"""

import uuid

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.models.attack_pattern import AttackPattern
from aijailer.models.constraint import Constraint
from aijailer.schemas.generate import ImmuneReportRequest, ImmuneStatusResponse
from aijailer.services.certificate_generator import IMMUNE_MEMORY_VERSION

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/immune", tags=["Immune Memory"])


@router.post("/report")
async def report_vulnerability(
    request: ImmuneReportRequest,
    db: AsyncSession = Depends(get_db),
):
    """Report a vulnerability to the immune memory system.

    The system stores the attack pattern and may auto-generate
    a new constraint to prevent similar attacks in the future.
    """
    # Store attack pattern
    pattern = AttackPattern(
        pattern_signature=f"manual_report_{uuid.uuid4().hex[:8]}",
        vulnerability_class=request.cwe_id or "UNKNOWN",
        attack_vector=request.vulnerability_description,
        severity=request.severity,
        occurrence_count=1,
    )
    db.add(pattern)
    await db.flush()

    logger.info(
        "immune.vulnerability_reported",
        pattern_id=str(pattern.id),
        severity=request.severity,
        cwe_id=request.cwe_id,
    )

    return {
        "pattern_id": str(pattern.id),
        "status": "recorded",
        "message": "Vulnerability reported to immune memory. "
                   "A constraint may be auto-generated in response.",
    }


@router.get("/status", response_model=ImmuneStatusResponse)
async def get_immune_status(db: AsyncSession = Depends(get_db)):
    """Get the current immune system status and threat level."""
    # Count active attack patterns
    pattern_count_result = await db.execute(
        select(func.count(AttackPattern.id)).where(
            AttackPattern.status == "active"
        )
    )
    active_patterns = pattern_count_result.scalar() or 0

    # Count total active constraints
    constraint_count_result = await db.execute(
        select(func.count(Constraint.id)).where(
            Constraint.is_active.is_(True)
        )
    )
    total_constraints = constraint_count_result.scalar() or 0

    # Determine threat level
    if active_patterns > 10:
        threat_level = "HIGH"
    elif active_patterns > 3:
        threat_level = "ELEVATED"
    else:
        threat_level = "NORMAL"

    # Get recent attack patterns
    recent_result = await db.execute(
        select(AttackPattern)
        .where(AttackPattern.status == "active")
        .order_by(AttackPattern.first_seen.desc())
        .limit(5)
    )
    recent_patterns = recent_result.scalars().all()

    return ImmuneStatusResponse(
        threat_level=threat_level,
        active_attack_patterns=active_patterns,
        total_constraints=total_constraints,
        recent_updates=[
            {
                "pattern_id": str(p.id),
                "vulnerability_class": p.vulnerability_class,
                "severity": p.severity,
                "first_seen": p.first_seen.isoformat() if p.first_seen else None,
            }
            for p in recent_patterns
        ],
        immune_memory_version=IMMUNE_MEMORY_VERSION,
    )
