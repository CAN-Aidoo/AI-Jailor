"""FastAPI application factory."""

import time
import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aijailer.core.config import get_settings
from aijailer.core.exceptions import AiJailerError
from aijailer.core.logging import configure_logging

from aijailer.api.routes import (
    cells,
    execution,
    policies,
    audit,
    files,
    snapshots,
    usage,
    webhooks,
    api_keys,
    terminal,
)

# CodeImmune routes
from aijailer.api.routes import (
    generate as generate_route,
    verify as verify_route,
    components as components_route,
    constraints as constraints_route,
    immune as immune_route,
    compliance as compliance_route,
    metrics as metrics_route,
)

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifecycle."""
    settings = get_settings()
    configure_logging(debug=settings.debug)

    logger.info("app.starting", host=settings.host, port=settings.port, debug=settings.debug)

    # In-memory stores for MVP
    app.state.rate_limit_store = {}

    # Host network enforcement: required for engines that attach a NIC. Failing to install
    # the firewall aborts startup (fail closed).
    from aijailer.engine.microvm import get_microvm_engine
    from aijailer.netpolicy.runtime import start_network_runtime

    from aijailer.db.base import async_session_factory

    net_runtime = await start_network_runtime(
        get_microvm_engine(), session_factory=async_session_factory)

    yield

    # Shutdown
    if net_runtime is not None:
        await net_runtime.stop()
    app.state.rate_limit_store.clear()
    logger.info("app.shutdown")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="AI Jailer API",
        description=(
            "Secure isolation-as-a-service for AI-generated code execution. "
            "AI Jailer provides hardware-isolated MicroVM environments (cells) "
            "for running untrusted code safely."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
        openapi_tags=[
            {"name": "System", "description": "Health checks and system info"},
            {"name": "Cells", "description": "Cell lifecycle management"},
            {"name": "Execution", "description": "Command and script execution"},
            {"name": "Files", "description": "File upload, download, and listing"},
            {"name": "Snapshots", "description": "Cell state snapshots and restore"},
            {"name": "Policies", "description": "Security policy management"},
            {"name": "Audit", "description": "Audit event querying"},
            {"name": "Usage", "description": "Resource metering and usage"},
            {"name": "Webhooks", "description": "Webhook registration and management"},
            {"name": "API Keys", "description": "API key management"},
            {"name": "Terminal", "description": "Interactive terminal sessions"},
            # CodeImmune
            {"name": "Code Generation", "description": "Secure code generation pipeline"},
            {"name": "Code Verification", "description": "Security verification of existing code"},
            {"name": "Certified Components", "description": "Browsing certified security components"},
            {"name": "Constraints", "description": "Security constraint management"},
            {"name": "Immune Memory", "description": "Vulnerability reporting and threat status"},
            {"name": "Compliance", "description": "Compliance reporting"},
            {"name": "Metrics", "description": "Generation statistics and dashboards"},
        ],
    )

    # --- CORS Middleware ---
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.debug else [],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # --- Exception handlers ---
    @app.exception_handler(AiJailerError)
    async def aijailer_error_handler(request: Request, exc: AiJailerError):
        status_map = {
            "cell_not_found": 404,
            "policy_not_found": 404,
            "snapshot_not_found": 404,
            "image_not_found": 404,
            "cell_not_running": 409,
            "invalid_state_transition": 409,
            "cell_limit_exceeded": 429,
            "resource_limit_exceeded": 429,
            "rate_limited": 429,
            "execution_timeout": 408,
            "policy_violation": 403,
            "spending_cap_reached": 402,
            "unauthorized": 401,
            "forbidden": 403,
            "invalid_policy": 400,
            "internal_error": 500,
        }
        status_code = status_map.get(exc.code, 500)
        return JSONResponse(
            status_code=status_code,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "details": exc.details,
                },
                "meta": {
                    "request_id": getattr(request.state, "request_id", "unknown"),
                    "timestamp": None,
                },
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_error_handler(request: Request, exc: Exception):
        logger.error(
            "unhandled_exception",
            error=str(exc),
            path=request.url.path,
            request_id=getattr(request.state, "request_id", "unknown"),
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": "An unexpected error occurred.",
                    "details": {},
                },
                "meta": {
                    "request_id": getattr(request.state, "request_id", "unknown"),
                },
            },
        )

    # --- Request lifecycle middleware ---
    @app.middleware("http")
    async def request_lifecycle(request: Request, call_next):
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        request.state.request_id = request_id

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=request.method,
            path=request.url.path,
        )

        start_time = time.perf_counter()

        response = await call_next(request)

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-Ms"] = str(duration_ms)

        if hasattr(request.state, "rate_limit_headers"):
            for key, value in request.state.rate_limit_headers.items():
                response.headers[key] = value

        logger.info(
            "http.request",
            status_code=response.status_code,
            duration_ms=duration_ms,
        )

        return response

    # --- Routes ---
    app.include_router(cells.router)
    app.include_router(execution.router)
    app.include_router(policies.router)
    app.include_router(audit.router)
    app.include_router(files.router)
    app.include_router(snapshots.router)
    app.include_router(usage.router)
    app.include_router(webhooks.router)
    app.include_router(api_keys.router)
    app.include_router(terminal.router)

    # CodeImmune routes
    app.include_router(generate_route.router)
    app.include_router(verify_route.router)
    app.include_router(components_route.router)
    app.include_router(constraints_route.router)
    app.include_router(immune_route.router)
    app.include_router(compliance_route.router)
    app.include_router(metrics_route.router)

    # --- Health check ---
    @app.get("/health", tags=["System"])
    async def health_check():
        return {
            "status": "healthy",
            "version": "0.1.0",
            "engine": "simulated",
        }

    @app.get("/", tags=["System"])
    async def root():
        return {
            "name": "AI Jailer API",
            "version": "0.1.0",
            "docs": "/docs",
            "description": "Secure isolation-as-a-service for AI-generated code execution",
        }

    return app
