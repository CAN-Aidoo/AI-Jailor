"""Constraints API route.

GET  /v1/constraints — List active constraints
POST /v1/constraints/custom — Add a custom tenant constraint
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.models.constraint import Constraint as ConstraintModel
from aijailer.schemas.generate import CustomConstraintRequest

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/constraints", tags=["Constraints"])


@router.get("")
async def list_constraints(
    category: str | None = None,
    severity: str | None = None,
    active_only: bool = True,
    db: AsyncSession = Depends(get_db),
):
    """List active security constraints."""
    query = select(ConstraintModel)
    if active_only:
        query = query.where(ConstraintModel.is_active.is_(True))
    if category:
        query = query.where(ConstraintModel.category == category)
    if severity:
        query = query.where(ConstraintModel.severity == severity)
    query = query.order_by(ConstraintModel.severity, ConstraintModel.category)

    result = await db.execute(query)
    constraints = result.scalars().all()
    return {
        "constraints": [
            {
                "id": str(c.id),
                "name": c.name,
                "category": c.category,
                "severity": c.severity,
                "source": c.source,
                "is_active": c.is_active,
            }
            for c in constraints
        ],
        "total": len(constraints),
    }


@router.post("/custom")
async def create_custom_constraint(
    request: CustomConstraintRequest,
    db: AsyncSession = Depends(get_db),
):
    """Create a custom tenant-specific constraint."""
    constraint = ConstraintModel(
        name=request.name,
        category=request.category,
        severity=request.severity,
        applies_when=request.applies_when,
        rules=request.rules,
        source="manual",
        is_active=True,
    )
    db.add(constraint)
    await db.flush()

    logger.info("constraint.custom_created", name=request.name, severity=request.severity)

    return {
        "id": str(constraint.id),
        "name": constraint.name,
        "category": constraint.category,
        "severity": constraint.severity,
        "source": constraint.source,
    }
