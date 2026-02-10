"""Webhook dispatch service.

Delivers webhook events to registered endpoints with retry logic,
signature verification, and failure tracking.
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone

import httpx
import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.models.webhook import Webhook

logger = structlog.get_logger(__name__)


class WebhookService:
    """Dispatches events to registered webhook endpoints."""

    MAX_RETRIES = 3
    TIMEOUT_SECONDS = 10
    MAX_CONSECUTIVE_FAILURES = 10  # Disable after this many failures

    def __init__(self, db: AsyncSession):
        self.db = db

    def _sign_payload(self, payload: bytes, secret_hash: str) -> str:
        """Create HMAC-SHA256 signature for webhook payload."""
        return hmac.new(
            secret_hash.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()

    async def dispatch_event(
        self,
        tenant_id: uuid.UUID,
        event_name: str,
        event_data: dict,
    ) -> list[dict]:
        """Dispatch an event to all matching webhooks for a tenant.

        Returns a list of delivery results:
        [{"webhook_id": ..., "status": "delivered"|"failed", "status_code": ...}]
        """
        # Find all active webhooks for this tenant that are subscribed to this event
        result = await self.db.execute(
            select(Webhook).where(
                Webhook.tenant_id == tenant_id,
                Webhook.status == "active",
            )
        )
        webhooks = result.scalars().all()

        results = []
        for webhook in webhooks:
            if event_name not in webhook.events:
                continue

            delivery = await self._deliver(webhook, event_name, event_data)
            results.append(delivery)

        return results

    async def _deliver(
        self,
        webhook: Webhook,
        event_name: str,
        event_data: dict,
    ) -> dict:
        """Deliver a single webhook with retry logic."""
        payload = {
            "id": f"whk_{uuid.uuid4().hex[:12]}",
            "event": event_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": event_data,
        }
        payload_bytes = json.dumps(payload, default=str).encode()
        signature = self._sign_payload(payload_bytes, webhook.secret_hash)

        headers = {
            "Content-Type": "application/json",
            "X-AiJailer-Signature": f"sha256={signature}",
            "X-AiJailer-Event": event_name,
            "User-Agent": "AiJailer-Webhook/0.1.0",
        }

        for attempt in range(self.MAX_RETRIES):
            try:
                async with httpx.AsyncClient(timeout=self.TIMEOUT_SECONDS) as client:
                    response = await client.post(
                        webhook.url,
                        content=payload_bytes,
                        headers=headers,
                    )

                webhook.last_delivery_at = datetime.now(timezone.utc)
                webhook.last_delivery_status = response.status_code

                if 200 <= response.status_code < 300:
                    webhook.consecutive_failures = 0
                    logger.info(
                        "webhook.delivered",
                        webhook_id=str(webhook.id),
                        event=event_name,
                        status_code=response.status_code,
                    )
                    return {
                        "webhook_id": str(webhook.id),
                        "status": "delivered",
                        "status_code": response.status_code,
                    }
                else:
                    logger.warning(
                        "webhook.delivery_failed",
                        webhook_id=str(webhook.id),
                        event=event_name,
                        status_code=response.status_code,
                        attempt=attempt + 1,
                    )

            except Exception as e:
                logger.warning(
                    "webhook.delivery_error",
                    webhook_id=str(webhook.id),
                    event=event_name,
                    error=str(e),
                    attempt=attempt + 1,
                )

        # All retries failed
        webhook.consecutive_failures += 1
        if webhook.consecutive_failures >= self.MAX_CONSECUTIVE_FAILURES:
            webhook.status = "disabled"
            logger.error(
                "webhook.disabled",
                webhook_id=str(webhook.id),
                consecutive_failures=webhook.consecutive_failures,
            )

        return {
            "webhook_id": str(webhook.id),
            "status": "failed",
            "consecutive_failures": webhook.consecutive_failures,
        }

    async def test_webhook(self, webhook_id: uuid.UUID, tenant_id: uuid.UUID) -> dict:
        """Send a test event to a webhook to verify it's working."""
        result = await self.db.execute(
            select(Webhook).where(
                Webhook.id == webhook_id,
                Webhook.tenant_id == tenant_id,
            )
        )
        webhook = result.scalar_one_or_none()
        if webhook is None:
            raise ValueError(f"Webhook {webhook_id} not found")

        return await self._deliver(
            webhook,
            "webhook.test",
            {"message": "This is a test webhook delivery."},
        )
