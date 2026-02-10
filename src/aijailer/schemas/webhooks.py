"""Pydantic schemas for Webhook API endpoints."""

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CreateWebhookRequest(BaseModel):
    url: str
    events: list[str]
    secret: str


class WebhookResponse(BaseModel):
    id: uuid.UUID
    url: str
    events: list[str]
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}
