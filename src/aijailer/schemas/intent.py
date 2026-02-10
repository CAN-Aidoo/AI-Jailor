"""CodeIntent schema and enum types.

Defines the typed, security-aware intent representation used
to classify developer prompts before code generation.
"""

from enum import Enum

from pydantic import BaseModel, Field


class ActionType(str, Enum):
    """High-level action the generated code performs."""
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    AUTH = "auth"
    PAYMENT = "payment"
    FILE_IO = "file_io"
    NETWORK = "network"
    CRYPTO = "crypto"


class DataClass(str, Enum):
    """Data classification level for handled data."""
    PII = "pii"           # Personally Identifiable Information
    PHI = "phi"           # Protected Health Information (HIPAA)
    PCI = "pci"           # Payment Card Industry data
    PUBLIC = "public"
    INTERNAL = "internal"


class AuthRequirement(str, Enum):
    """Authentication level required by the intent."""
    NONE = "none"
    SESSION = "session"
    TOKEN = "token"
    MTLS = "mtls"
    MFA = "mfa"


class InputSource(str, Enum):
    """Where the input data originates."""
    USER_INPUT = "user_input"
    API = "api"
    DATABASE = "database"
    FILE = "file"


class OutputTarget(str, Enum):
    """Where the output data is sent."""
    BROWSER = "browser"
    API_RESPONSE = "api_response"
    DATABASE = "database"
    LOG = "log"


class ConcurrencyType(str, Enum):
    """Concurrency model for the generated code."""
    SYNC = "sync"
    ASYNC = "async"
    PARALLEL = "parallel"


class ErrorClass(str, Enum):
    """Error handling philosophy."""
    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"
    FAIL_SAFE = "fail_safe"


class CodeIntent(BaseModel):
    """Typed, security-aware intent extracted from a developer prompt.

    Every field informs the constraint engine about what security
    properties must be enforced in the generated code.
    """
    action: ActionType
    data_classification: list[DataClass] = Field(default_factory=list)
    trust_boundary_crossing: bool = False
    auth_context: AuthRequirement = AuthRequirement.NONE
    compliance_domains: list[str] = Field(default_factory=list)
    input_sources: list[InputSource] = Field(default_factory=list)
    output_targets: list[OutputTarget] = Field(default_factory=list)
    concurrency_model: ConcurrencyType = ConcurrencyType.SYNC
    error_sensitivity: ErrorClass = ErrorClass.FAIL_CLOSED

    # Optional metadata extracted from the prompt
    description: str | None = None
    target_framework: str | None = None
    target_language: str = "python"
