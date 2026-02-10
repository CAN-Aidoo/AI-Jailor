"""Code verification API route.

POST /v1/verify — Verify existing code against constraints.
"""

import structlog
from fastapi import APIRouter

from aijailer.schemas.generate import VerifyRequest, VerifyResponse
from aijailer.services.constraint_engine import get_constraint_engine
from aijailer.services.taint_tracker import get_taint_tracker

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Code Verification"])


@router.post("/verify", response_model=VerifyResponse)
async def verify_code(request: VerifyRequest):
    """Verify existing code against security constraints.

    Runs taint analysis and pattern-based vulnerability detection
    on the provided code without generating new code.
    """
    tracker = get_taint_tracker()
    violations = tracker.analyze_code(request.code, language=request.language)

    # Build violation details
    violation_details = [
        {
            "type": v.sink_type.value,
            "source": v.source_label.value,
            "location": v.location,
            "message": v.message,
            "severity": v.severity,
        }
        for v in violations
    ]

    # Build recommendations
    recommendations = []
    seen_types = set()
    for v in violations:
        if v.sink_type.value not in seen_types:
            seen_types.add(v.sink_type.value)
            if v.sink_type.value == "sql_query":
                recommendations.append("Use parameterized queries or an ORM instead of string formatting in SQL")
            elif v.sink_type.value == "html_output":
                recommendations.append("Use context-aware output encoding (e.g., html_escape) for user data in HTML")
            elif v.sink_type.value == "subprocess_arg":
                recommendations.append("Use a safe subprocess wrapper with an allowlist of permitted commands")
            elif v.sink_type.value == "file_path":
                recommendations.append("Use a safe_file_io component that validates paths against allowed directories")

    constraints_checked = [
        "sql_injection_prevention",
        "xss_prevention",
        "command_injection_prevention",
        "path_traversal_prevention",
        "taint_flow_analysis",
    ]

    is_safe = len(violations) == 0

    logger.info(
        "verify.complete",
        is_safe=is_safe,
        violation_count=len(violations),
    )

    return VerifyResponse(
        is_safe=is_safe,
        violations=violation_details,
        constraints_checked=constraints_checked,
        recommendations=recommendations,
    )
