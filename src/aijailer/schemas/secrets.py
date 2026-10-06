"""Secret API schemas. Values appear ONLY in request bodies (as SecretStr) and never in any
response, log line or audit event."""

from datetime import datetime

from pydantic import BaseModel, Field, SecretStr


class CreateSecretRequest(BaseModel):
    name: str
    value: SecretStr
    hosts: list[str]
    expires_at: datetime | None = None


class UpdateSecretRequest(BaseModel):
    value: SecretStr | None = None
    hosts: list[str] | None = None
    expires_at: datetime | None = None
    clear_expiry: bool = False


class SecretResponse(BaseModel):
    name: str
    version: int
    hosts: list[str]
    expires_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    rotated_at: datetime | None = None
    # How a cell references it: set this header value to the placeholder, never the secret.
    placeholder: str = Field(default="")
