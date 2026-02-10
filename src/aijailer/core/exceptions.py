"""Application-wide exception hierarchy."""

from typing import Any


class AiJailerError(Exception):
    """Base exception for all AI Jailer errors."""

    def __init__(self, message: str, code: str = "internal_error", details: Any = None):
        self.message = message
        self.code = code
        self.details = details or {}
        super().__init__(message)


class CellNotFoundError(AiJailerError):
    def __init__(self, cell_id: str):
        super().__init__(
            message=f"Cell with ID '{cell_id}' does not exist or is not accessible.",
            code="cell_not_found",
            details={"cell_id": cell_id},
        )


class CellNotRunningError(AiJailerError):
    def __init__(self, cell_id: str, current_status: str):
        super().__init__(
            message=f"Cell '{cell_id}' is not running (current status: {current_status}).",
            code="cell_not_running",
            details={"cell_id": cell_id, "current_status": current_status},
        )


class CellLimitExceededError(AiJailerError):
    def __init__(self, tenant_id: str, limit: int):
        super().__init__(
            message=f"Tenant has reached maximum concurrent cells ({limit}).",
            code="cell_limit_exceeded",
            details={"tenant_id": tenant_id, "limit": limit},
        )


class PolicyViolationError(AiJailerError):
    def __init__(self, message: str, policy_id: str | None = None, violation_type: str = ""):
        super().__init__(
            message=message,
            code="policy_violation",
            details={"policy_id": policy_id, "violation_type": violation_type},
        )


class PolicyNotFoundError(AiJailerError):
    def __init__(self, policy_id: str):
        super().__init__(
            message=f"Policy with ID '{policy_id}' does not exist.",
            code="policy_not_found",
            details={"policy_id": policy_id},
        )


class ExecutionTimeoutError(AiJailerError):
    def __init__(self, execution_id: str, timeout_seconds: int):
        super().__init__(
            message=f"Execution '{execution_id}' exceeded timeout of {timeout_seconds}s.",
            code="execution_timeout",
            details={"execution_id": execution_id, "timeout_seconds": timeout_seconds},
        )


class ResourceLimitExceededError(AiJailerError):
    def __init__(self, resource: str, limit: str):
        super().__init__(
            message=f"Resource limit exceeded: {resource} (limit: {limit}).",
            code="resource_limit_exceeded",
            details={"resource": resource, "limit": limit},
        )


class ImageNotFoundError(AiJailerError):
    def __init__(self, image: str):
        super().__init__(
            message=f"Base image '{image}' does not exist.",
            code="image_not_found",
            details={"image": image},
        )


class InvalidPolicyError(AiJailerError):
    def __init__(self, message: str):
        super().__init__(message=message, code="invalid_policy")


class SpendingCapReachedError(AiJailerError):
    def __init__(self, tenant_id: str):
        super().__init__(
            message="Tenant spending cap exceeded.",
            code="spending_cap_reached",
            details={"tenant_id": tenant_id},
        )


class RateLimitError(AiJailerError):
    def __init__(self, retry_after: int):
        super().__init__(
            message="Too many requests.",
            code="rate_limited",
            details={"retry_after": retry_after},
        )
        self.retry_after = retry_after


class AuthenticationError(AiJailerError):
    def __init__(self, message: str = "Invalid or missing authentication."):
        super().__init__(message=message, code="unauthorized")


class ForbiddenError(AiJailerError):
    def __init__(self, message: str = "Insufficient permissions for this action."):
        super().__init__(message=message, code="forbidden")


class SnapshotNotFoundError(AiJailerError):
    def __init__(self, snapshot_id: str):
        super().__init__(
            message=f"Snapshot with ID '{snapshot_id}' does not exist.",
            code="snapshot_not_found",
            details={"snapshot_id": snapshot_id},
        )


class InvalidStateTransitionError(AiJailerError):
    def __init__(self, cell_id: str, current_status: str, requested_action: str):
        super().__init__(
            message=(
                f"Cannot perform '{requested_action}' on cell '{cell_id}' "
                f"in status '{current_status}'."
            ),
            code="invalid_state_transition",
            details={
                "cell_id": cell_id,
                "current_status": current_status,
                "requested_action": requested_action,
            },
        )
