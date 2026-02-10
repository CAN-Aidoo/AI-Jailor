"""SDK exception hierarchy."""

from typing import Any


class AiJailerError(Exception):
    """Base exception for AI Jailer SDK errors."""

    def __init__(self, message: str, code: str = "unknown", details: dict[str, Any] | None = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(message)


class CellNotFoundError(AiJailerError):
    pass


class CellNotRunningError(AiJailerError):
    pass


class PolicyViolationError(AiJailerError):
    def __init__(self, message: str, policy_id: str | None = None, violation_type: str = "", **kwargs):
        super().__init__(message, code="policy_violation", details=kwargs)
        self.policy_id = policy_id
        self.violation_type = violation_type


class ResourceLimitError(AiJailerError):
    pass


class SpendingCapError(AiJailerError):
    pass


class RateLimitError(AiJailerError):
    def __init__(self, retry_after: int = 60):
        super().__init__(f"Rate limited. Retry after {retry_after}s.", code="rate_limited")
        self.retry_after = retry_after


class AuthenticationError(AiJailerError):
    pass


class ExecutionTimeoutError(AiJailerError):
    pass
