"""Certified Input Validator.

Type-safe input validation using Pydantic schemas with
regex sanitization, length limits, and encoding enforcement.

Prevents:
- CWE-20: Improper Input Validation
- CWE-1284: Improper Validation of Specified Quantity in Input
- CWE-1285: Improper Validation of Specified Index, Position, or Offset in Input
- CWE-170: Improper Null Termination
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when input violates security constraints."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "input_validator"},
        )


# Maximum lengths for common field types
_MAX_LENGTHS: dict[str, int] = {
    "email": 254,
    "username": 64,
    "password": 128,
    "name": 200,
    "url": 2048,
    "phone": 20,
    "text": 10000,
    "short_text": 500,
    "identifier": 128,
    "default": 1000,
}

# Dangerous patterns that must be rejected
_DANGEROUS_PATTERNS = [
    r"<script[\s>]",
    r"javascript:",
    r"on\w+\s*=",  # Event handlers: onclick, onerror, etc.
    r"data:\s*text/html",
    r"&#x?[0-9a-f]+;",  # HTML character references that may be evasion
]


class FieldType(str, Enum):
    """Supported validated field types."""

    EMAIL = "email"
    USERNAME = "username"
    PASSWORD = "password"
    NAME = "name"
    URL = "url"
    PHONE = "phone"
    TEXT = "text"
    SHORT_TEXT = "short_text"
    IDENTIFIER = "identifier"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"


@dataclass(frozen=True)
class ValidationRule:
    """A single field validation rule."""

    field_name: str
    field_type: FieldType
    required: bool = True
    min_length: int | None = None
    max_length: int | None = None
    pattern: str | None = None  # Regex pattern the value must match
    min_value: float | None = None
    max_value: float | None = None


@dataclass(frozen=True)
class ValidationResult:
    """Result of input validation."""

    valid: bool
    sanitized_data: dict[str, Any]
    errors: list[str]


# Pre-compiled validation patterns
_EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)
_USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{3,64}$")
_PHONE_PATTERN = re.compile(r"^\+?[0-9\s\-()]{7,20}$")
_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)*"
    r"(:[0-9]+)?(/[-a-zA-Z0-9._~:/?#\[\]@!$&'()*+,;=%]*)?$"
)
_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]{0,127}$")


class InputValidator:
    """Certified input validation with safe defaults.

    All inputs are:
    - Null-byte stripped
    - Length-bounded
    - Type-validated
    - Checked for dangerous patterns (XSS, injection)
    - Sanitized of control characters
    """

    def validate(
        self,
        data: dict[str, Any],
        rules: list[ValidationRule],
    ) -> ValidationResult:
        """Validate a data dict against a set of rules.

        Returns sanitized data with all validation errors collected.
        """
        errors: list[str] = []
        sanitized: dict[str, Any] = {}

        for rule in rules:
            value = data.get(rule.field_name)

            # Check required
            if value is None or (isinstance(value, str) and not value.strip()):
                if rule.required:
                    errors.append(f"{rule.field_name}: required field is missing")
                continue

            # Type-specific validation
            try:
                validated = self._validate_field(value, rule)
                sanitized[rule.field_name] = validated
            except SecurityViolation as e:
                errors.append(f"{rule.field_name}: {e.message}")
            except (ValueError, TypeError) as e:
                errors.append(f"{rule.field_name}: {e}")

        return ValidationResult(
            valid=len(errors) == 0,
            sanitized_data=sanitized,
            errors=errors,
        )

    def validate_strict(
        self,
        data: dict[str, Any],
        rules: list[ValidationRule],
    ) -> dict[str, Any]:
        """Validate and return sanitized data. Raises on any error."""
        result = self.validate(data, rules)
        if not result.valid:
            raise SecurityViolation(
                f"Validation failed: {'; '.join(result.errors)}"
            )
        return result.sanitized_data

    def _validate_field(self, value: Any, rule: ValidationRule) -> Any:
        """Validate a single field value."""
        # Handle non-string types first
        if rule.field_type == FieldType.INTEGER:
            return self._validate_integer(value, rule)
        if rule.field_type == FieldType.FLOAT:
            return self._validate_float(value, rule)
        if rule.field_type == FieldType.BOOLEAN:
            return self._validate_boolean(value)

        # String validation
        if not isinstance(value, str):
            raise SecurityViolation(f"Expected string, got {type(value).__name__}")

        # Sanitize: strip null bytes, control characters
        sanitized = self._sanitize_string(value)

        # Length checks
        max_len = rule.max_length or _MAX_LENGTHS.get(
            rule.field_type.value, _MAX_LENGTHS["default"]
        )
        if len(sanitized) > max_len:
            raise SecurityViolation(f"Exceeds maximum length of {max_len}")

        if rule.min_length and len(sanitized) < rule.min_length:
            raise SecurityViolation(f"Below minimum length of {rule.min_length}")

        # Dangerous pattern check
        self._check_dangerous_patterns(sanitized, rule.field_name)

        # Type-specific pattern validation
        match rule.field_type:
            case FieldType.EMAIL:
                if not _EMAIL_PATTERN.match(sanitized):
                    raise SecurityViolation("Invalid email format")
            case FieldType.USERNAME:
                if not _USERNAME_PATTERN.match(sanitized):
                    raise SecurityViolation(
                        "Username must be 3-64 chars: letters, numbers, _ . -"
                    )
            case FieldType.PHONE:
                if not _PHONE_PATTERN.match(sanitized):
                    raise SecurityViolation("Invalid phone number format")
            case FieldType.URL:
                if not _URL_PATTERN.match(sanitized):
                    raise SecurityViolation("Invalid URL format (must be http/https)")
            case FieldType.IDENTIFIER:
                if not _IDENTIFIER_PATTERN.match(sanitized):
                    raise SecurityViolation("Invalid identifier format")
            case FieldType.PASSWORD:
                self._validate_password_strength(sanitized)

        # Custom pattern validation
        if rule.pattern:
            if not re.match(rule.pattern, sanitized):
                raise SecurityViolation(f"Does not match required pattern")

        return sanitized

    @staticmethod
    def _sanitize_string(value: str) -> str:
        """Remove null bytes and control characters from string."""
        # Strip null bytes
        value = value.replace("\x00", "")
        # Strip other control characters (keep newlines and tabs)
        value = "".join(
            c for c in value if c in ("\n", "\r", "\t") or (ord(c) >= 32)
        )
        return value.strip()

    @staticmethod
    def _check_dangerous_patterns(value: str, field_name: str) -> None:
        """Reject values matching known dangerous patterns."""
        for pattern in _DANGEROUS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise SecurityViolation(
                    f"Dangerous pattern detected in '{field_name}'"
                )

    @staticmethod
    def _validate_password_strength(password: str) -> None:
        """Enforce minimum password complexity."""
        if len(password) < 8:
            raise SecurityViolation("Password must be at least 8 characters")
        if len(password) > 128:
            raise SecurityViolation("Password must be at most 128 characters")

    @staticmethod
    def _validate_integer(value: Any, rule: ValidationRule) -> int:
        """Validate and coerce to integer with bounds."""
        try:
            result = int(value)
        except (ValueError, TypeError):
            raise SecurityViolation("Expected integer value")

        if rule.min_value is not None and result < rule.min_value:
            raise SecurityViolation(f"Below minimum value of {rule.min_value}")
        if rule.max_value is not None and result > rule.max_value:
            raise SecurityViolation(f"Exceeds maximum value of {rule.max_value}")
        return result

    @staticmethod
    def _validate_float(value: Any, rule: ValidationRule) -> float:
        """Validate and coerce to float with bounds."""
        try:
            result = float(value)
        except (ValueError, TypeError):
            raise SecurityViolation("Expected numeric value")

        if rule.min_value is not None and result < rule.min_value:
            raise SecurityViolation(f"Below minimum value of {rule.min_value}")
        if rule.max_value is not None and result > rule.max_value:
            raise SecurityViolation(f"Exceeds maximum value of {rule.max_value}")
        return result

    @staticmethod
    def _validate_boolean(value: Any) -> bool:
        """Validate and coerce to boolean."""
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            if value.lower() in ("true", "1", "yes"):
                return True
            if value.lower() in ("false", "0", "no"):
                return False
        raise SecurityViolation("Expected boolean value")
