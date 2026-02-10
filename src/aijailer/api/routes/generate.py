"""Code generation API route.

POST /v1/generate — Full pipeline:
  intent → constraints → components → assembly → cert → response
"""

import hashlib
import time
import uuid

import structlog
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.core.config import get_settings
from aijailer.db.base import get_db
from aijailer.schemas.generate import GenerateRequest, GenerateResponse
from aijailer.services.certificate_generator import get_certificate_generator
from aijailer.services.constraint_engine import get_constraint_engine
from aijailer.services.intent_parser import get_intent_parser
from aijailer.services.secure_assembler import get_secure_assembler
from aijailer.services.taint_tracker import get_taint_tracker

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/v1", tags=["Code Generation"])


@router.post("/generate", response_model=GenerateResponse)
async def generate_secure_code(
    request: GenerateRequest,
    db: AsyncSession = Depends(get_db),
):
    """Generate secure code through the constrained pipeline.

    Pipeline:
    1. Parse intent from prompt (Claude)
    2. Check constraints (Z3 / rule-based)
    3. Select certified components
    4. Assemble code (Claude + components)
    5. Taint-check output
    6. Generate security certificate
    7. Return response
    """
    start = time.monotonic()
    settings = get_settings()

    # Step 1: Parse intent
    parser = get_intent_parser(api_key=settings.anthropic_api_key)
    intent = await parser.parse_intent(request.prompt)
    if intent is None:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "unclassifiable_intent",
                "message": "Could not safely classify the intent. Generation blocked.",
            },
        )

    # Override language/framework from request
    intent.target_language = request.language
    intent.target_framework = request.framework

    # Merge compliance from request
    if request.compliance:
        for c in request.compliance:
            if c not in intent.compliance_domains:
                intent.compliance_domains.append(c)

    # Step 2: Check constraints
    engine = get_constraint_engine()
    constraint_result = engine.check_intent(intent)

    # In strict mode, all requirement violations = block
    # (the assembler will use certified components to satisfy them)
    constraints_applied = [
        v["constraint"] if isinstance(v, dict) else str(v)
        for v in constraint_result.violated_constraints
    ]

    # Step 3: Select components
    assembler = get_secure_assembler(api_key=settings.anthropic_api_key)
    components = assembler.select_components(intent, constraint_result)

    # Step 4: Assemble code
    code = await assembler.assemble(
        intent=intent,
        constraint_result=constraint_result,
        selected_components=components,
        language=request.language,
        framework=request.framework,
    )

    # Step 5: Taint check the output
    warnings = []
    tracker = get_taint_tracker()
    violations = tracker.analyze_code(code, language=request.language)
    if violations:
        if request.strict_mode:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "taint_violation",
                    "message": "Generated code contains taint violations",
                    "violations": [
                        {
                            "sink": v.sink_type.value,
                            "source": v.source_label.value,
                            "location": v.location,
                            "message": v.message,
                        }
                        for v in violations
                    ],
                },
            )
        else:
            warnings = [v.message for v in violations]

    # Step 6: Generate certificate
    gen_id = f"gen_{uuid.uuid4().hex[:12]}"
    cert_gen = get_certificate_generator()
    certificate = cert_gen.generate(
        code=code,
        intent=intent,
        constraints_applied=constraints_applied,
        components_used=components,
        tenant_id="default",  # In production, from auth context
        generation_id=gen_id,
    )

    elapsed_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "generate.complete",
        generation_id=gen_id,
        intent_action=intent.action.value,
        components=components,
        constraints=constraints_applied,
        latency_ms=elapsed_ms,
    )

    return GenerateResponse(
        code=code,
        certificate=certificate,
        components_used=certificate.components_used,
        constraints_applied=constraints_applied,
        warnings=warnings,
        latency_ms=elapsed_ms,
        immune_version=certificate.immune_memory_version,
    )
