"""Certified Components API route.

GET /v1/components — List available certified components
GET /v1/components/{id} — Get a specific component
"""

import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.models.certified_component import CertifiedComponent

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/components", tags=["Certified Components"])


@router.get("")
async def list_components(
    category: str | None = None,
    language: str | None = None,
    status: str = "active",
    db: AsyncSession = Depends(get_db),
):
    """List available certified components with optional filters."""
    query = select(CertifiedComponent).where(CertifiedComponent.status == status)
    if category:
        query = query.where(CertifiedComponent.category == category)
    if language:
        query = query.where(CertifiedComponent.language == language)
    query = query.order_by(CertifiedComponent.category, CertifiedComponent.name)

    result = await db.execute(query)
    components = result.scalars().all()
    return {
        "components": [
            {
                "id": str(c.id),
                "name": c.name,
                "version": c.version,
                "language": c.language,
                "category": c.category,
                "compliance_certs": c.compliance_certs,
                "status": c.status,
            }
            for c in components
        ],
        "total": len(components),
    }


@router.get("/{component_id}")
async def get_component(
    component_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    """Get a specific certified component by ID."""
    result = await db.execute(
        select(CertifiedComponent).where(CertifiedComponent.id == component_id)
    )
    component = result.scalar_one_or_none()
    if component is None:
        raise HTTPException(status_code=404, detail="Component not found")

    return {
        "id": str(component.id),
        "name": component.name,
        "version": component.version,
        "language": component.language,
        "category": component.category,
        "source_code": component.source_code,
        "formal_spec": component.formal_spec,
        "compliance_certs": component.compliance_certs,
        "cve_coverage": component.cve_coverage,
        "fuzz_report_url": component.fuzz_report_url,
        "status": component.status,
        "created_at": component.created_at.isoformat() if component.created_at else None,
    }
