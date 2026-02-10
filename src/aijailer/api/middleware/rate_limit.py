"""Sliding-window rate limiter backed by Redis."""

import time
import uuid

from fastapi import Depends, HTTPException, Request

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.core.config import get_settings


async def rate_limit(
    request: Request,
    auth: AuthContext = Depends(authenticate),
) -> AuthContext:
    """Enforce per-tenant, per-endpoint rate limits using a sliding window.

    In the MVP, this uses an in-memory counter. In production, this would use
    Redis sorted sets for distributed rate limiting.
    """
    settings = get_settings()

    # Simple in-memory rate limiting for MVP
    # Production: Redis sorted-set sliding window per (tenant_id, endpoint, minute)
    rate_limit_store = request.app.state.rate_limit_store

    window_key = f"{auth.tenant_id}:{request.url.path}:{int(time.time()) // 60}"
    count = rate_limit_store.get(window_key, 0)

    limit = settings.default_rate_limit_per_minute
    if count >= limit:
        raise HTTPException(
            status_code=429,
            detail="Too many requests.",
            headers={
                "X-RateLimit-Limit": str(limit),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(((int(time.time()) // 60) + 1) * 60),
                "Retry-After": str(60 - (int(time.time()) % 60)),
            },
        )

    rate_limit_store[window_key] = count + 1

    # Add rate limit headers to the response
    request.state.rate_limit_headers = {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(0, limit - count - 1)),
        "X-RateLimit-Reset": str(((int(time.time()) // 60) + 1) * 60),
    }

    return auth
