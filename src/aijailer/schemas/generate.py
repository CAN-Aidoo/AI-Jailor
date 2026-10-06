"""Generate endpoint request/response schemas.

Matches the API specification from spec Section 6.
"""

from pydantic import BaseModel, Field


class ComponentRef(BaseModel):
    """Reference to a certified component used in generation."""
    name: str
    version: str
    cert_id: str | None = None


class SecurityCertificateSchema(BaseModel):
    """Security attestation for generated code (spec Section 13)."""
    certificate_id: str
    generation_id: str
    timestamp: str
    tenant_id: str
    code_hash: str
    security_properties: dict = Field(default_factory=dict)
    compliance_frameworks: list[str] = Field(default_factory=list)
    constraints_applied: list[str] = Field(default_factory=list)
    components_used: list[ComponentRef] = Field(default_factory=list)
    immune_memory_version: str = ""
    valid_until: str = ""
    signature: str = ""
    attestation: dict | None = None  # DSSE envelope wrapping an in-toto Statement


class GenerateRequest(BaseModel):
    """POST /v1/generate request body."""
    prompt: str
    language: str = "python"
    framework: str | None = None          # e.g., "fastapi", "django", "express"
    compliance: list[str] = Field(default_factory=list)
    context: dict | None = None           # Existing codebase context
    strict_mode: bool = True              # Block on ANY constraint violation
    max_latency_ms: int = 5000


class GenerateResponse(BaseModel):
    """POST /v1/generate response body."""
    code: str
    certificate: SecurityCertificateSchema
    components_used: list[ComponentRef] = Field(default_factory=list)
    constraints_applied: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    latency_ms: int
    immune_version: str = ""


class VerifyRequest(BaseModel):
    """POST /v1/verify request body."""
    code: str
    language: str = "python"
    compliance: list[str] = Field(default_factory=list)
    strict_mode: bool = True


class VerifyResponse(BaseModel):
    """POST /v1/verify response body."""
    is_safe: bool
    violations: list[dict] = Field(default_factory=list)
    constraints_checked: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class ImmuneReportRequest(BaseModel):
    """POST /v1/immune/report request body."""
    vulnerability_description: str
    code_sample: str | None = None
    cwe_id: str | None = None
    severity: str = "MEDIUM"


class ImmuneStatusResponse(BaseModel):
    """GET /v1/immune/status response body."""
    threat_level: str
    active_attack_patterns: int
    total_constraints: int
    recent_updates: list[dict] = Field(default_factory=list)
    immune_memory_version: str


class CustomConstraintRequest(BaseModel):
    """POST /v1/constraints/custom request body."""
    name: str
    category: str
    severity: str = "MEDIUM"
    applies_when: dict
    rules: list[dict]
