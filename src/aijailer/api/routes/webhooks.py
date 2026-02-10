"""Webhook registration API routes."""

import hashlib
import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.api.middleware.auth import AuthContext, authenticate
from aijailer.db.base import get_db
from aijailer.schemas.common import ApiResponse
from aijailer.schemas.webhooks import CreateWebhookRequest, WebhookResponse

router = APIRouter(prefix="/v1/webhooks", tags=["Webhooks"])


@router.post("", status_code=201, response_model=ApiResponse[WebhookResponse])
async def create_webhook(
    body: CreateWebhookRequest,
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    from aijailer.models.webhook import Webhook

    webhook = Webhook(
        tenant_id=auth.tenant_id,
        url=body.url,
        secret_hash=hashlib.sha256(body.secret.encode()).hexdigest(),
        events=body.events,
        status="active",
    )
    db.add(webhook)
    await db.flush()

    return ApiResponse(
        data=WebhookResponse(
            id=webhook.id,
            url=webhook.url,
            events=webhook.events,
            status=webhook.status,
            created_at=webhook.created_at,
        )
    )


@router.get("", response_model=ApiResponse[list[WebhookResponse]])
async def list_webhooks(
    auth: AuthContext = Depends(authenticate),
    db: AsyncSession = Depends(get_db),
):
    from aijailer.models.webhook import Webhook

    result = await db.execute(
        select(Webhook).where(Webhook.tenant_id == auth.tenant_id)
    )
    webhooks = result.scalars().all()
    return ApiResponse(
        data=[
            WebhookResponse(
                id=w.id,
                url=w.url,
                events=w.events,
                status=w.status,
                created_at=w.created_at,
            )
            for w in webhooks
        ]
    )
