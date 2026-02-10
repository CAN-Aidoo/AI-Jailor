"""Compliance API route.

GET /v1/compliance/report — Generate a compliance report for a tenant.
"""

import structlog
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.db.base import get_db
from aijailer.models.generation_log import GenerationLog
from aijailer.models.security_certificate import SecurityCertificate

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1/compliance", tags=["Compliance"])


@router.get("/report")
async def get_compliance_report(
    tenant_id: str | None = None,
    framework: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Generate a compliance report for a tenant.

    Shows generation statistics, constraint satisfaction rates,
    and certificate validity summaries grouped by framework.
    """
    # Count total generations
    gen_query = select(func.count(GenerationLog.id))
    if tenant_id:
        import uuid as _uuid
        gen_query = gen_query.where(
            GenerationLog.tenant_id == _uuid.UUID(tenant_id)
        )
    total_result = await db.execute(gen_query)
    total_generations = total_result.scalar() or 0

    # Count blocked generations
    blocked_query = select(func.count(GenerationLog.id)).where(
        GenerationLog.blocked.is_(True)
    )
    if tenant_id:
        import uuid as _uuid
        blocked_query = blocked_query.where(
            GenerationLog.tenant_id == _uuid.UUID(tenant_id)
        )
    blocked_result = await db.execute(blocked_query)
    blocked_generations = blocked_result.scalar() or 0

    # Count valid certificates
    cert_query = select(func.count(SecurityCertificate.id)).where(
        SecurityCertificate.revoked.is_(False)
    )
    if tenant_id:
        import uuid as _uuid
        cert_query = cert_query.where(
            SecurityCertificate.tenant_id == _uuid.UUID(tenant_id)
        )
    cert_result = await db.execute(cert_query)
    valid_certificates = cert_result.scalar() or 0

    return {
        "report": {
            "tenant_id": tenant_id or "all",
            "total_generations": total_generations,
            "successful_generations": total_generations - blocked_generations,
            "blocked_generations": blocked_generations,
            "block_rate_percent": round(
                (blocked_generations / max(total_generations, 1)) * 100, 2
            ),
            "valid_certificates": valid_certificates,
            "compliance_frameworks": framework or "all",
        },
    }
