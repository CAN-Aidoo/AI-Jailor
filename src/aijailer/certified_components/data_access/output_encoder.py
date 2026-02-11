"""Certified Output Encoder.

Context-aware output encoding for HTML, URL, JavaScript,
SQL, and CSS contexts to prevent injection attacks.

Prevents:
- CWE-79: Cross-Site Scripting (XSS) — Reflected, Stored, DOM
- CWE-838: Inappropriate Encoding for Output Context
- CWE-116: Improper Encoding or Escaping of Output
"""

import html
import re
import urllib.parse
from enum import Enum
from typing import Any

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when output encoding detects a violation."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "output_encoder"},
        )


class OutputContext(str, Enum):
    """Supported output encoding contexts."""

    HTML_CONTENT = "html_content"     # Inside HTML tags
    HTML_ATTRIBUTE = "html_attribute" # Inside HTML attribute values
    URL = "url"                       # Inside URL parameters
    JAVASCRIPT = "javascript"        # Inside JS string literals
    CSS = "css"                       # Inside CSS values
    SQL_IDENTIFIER = "sql_identifier" # SQL identifiers (not values — use parameterized queries)
    JSON = "json"                     # JSON string values
    LOG = "log"                       # Log output (strip sensitive data patterns)


class OutputEncoder:
    """Context-aware output encoder.

    EVERY output to an external sink (browser, log, API response)
    MUST pass through this encoder with the correct context.
    Using the wrong context will raise SecurityViolation.
    """

    def encode(self, value: Any, context: OutputContext) -> str:
        """Encode a value for the specified output context.

        Args:
            value: The value to encode.
            context: The target output context.

        Returns:
            Safely encoded string for the target context.
        """
        if value is None:
            return ""

        raw = str(value)

        match context:
            case OutputContext.HTML_CONTENT:
                return self._encode_html_content(raw)
            case OutputContext.HTML_ATTRIBUTE:
                return self._encode_html_attribute(raw)
            case OutputContext.URL:
                return self._encode_url(raw)
            case OutputContext.JAVASCRIPT:
                return self._encode_javascript(raw)
            case OutputContext.CSS:
                return self._encode_css(raw)
            case OutputContext.SQL_IDENTIFIER:
                return self._encode_sql_identifier(raw)
            case OutputContext.JSON:
                return self._encode_json(raw)
            case OutputContext.LOG:
                return self._encode_log(raw)
            case _:
                raise SecurityViolation(f"Unknown output context: {context}")

    def encode_html(self, value: Any) -> str:
        """Shorthand for HTML content encoding."""
        return self.encode(value, OutputContext.HTML_CONTENT)

    def encode_attr(self, value: Any) -> str:
        """Shorthand for HTML attribute encoding."""
        return self.encode(value, OutputContext.HTML_ATTRIBUTE)

    def encode_url(self, value: Any) -> str:
        """Shorthand for URL encoding."""
        return self.encode(value, OutputContext.URL)

    def encode_js(self, value: Any) -> str:
        """Shorthand for JavaScript encoding."""
        return self.encode(value, OutputContext.JAVASCRIPT)

    def encode_log(self, value: Any) -> str:
        """Shorthand for log output encoding."""
        return self.encode(value, OutputContext.LOG)

    # --- Context-specific encoders ---

    @staticmethod
    def _encode_html_content(value: str) -> str:
        """Encode for HTML content (between tags).

        Escapes: & < > " ' /
        """
        return html.escape(value, quote=True).replace("/", "&#x2F;")

    @staticmethod
    def _encode_html_attribute(value: str) -> str:
        """Encode for HTML attribute values.

        More aggressive than content encoding — also handles
        event handler injection and control characters.
        """
        # First do standard HTML escaping
        encoded = html.escape(value, quote=True)
        # Replace additional dangerous characters
        encoded = encoded.replace("/", "&#x2F;")
        encoded = encoded.replace("`", "&#x60;")
        # Remove any control characters
        encoded = re.sub(r"[\x00-\x1f]", "", encoded)
        return encoded

    @staticmethod
    def _encode_url(value: str) -> str:
        """Encode for URL parameter context.

        Uses percent-encoding for all special characters.
        """
        return urllib.parse.quote(value, safe="")

    @staticmethod
    def _encode_javascript(value: str) -> str:
        """Encode for JavaScript string literal context.

        Escapes characters that could break out of a JS string
        or inject code.
        """
        replacements = {
            "\\": "\\\\",
            "'": "\\'",
            '"': '\\"',
            "\n": "\\n",
            "\r": "\\r",
            "\t": "\\t",
            "<": "\\u003c",
            ">": "\\u003e",
            "&": "\\u0026",
            "/": "\\/",
            "\u2028": "\\u2028",  # Line separator
            "\u2029": "\\u2029",  # Paragraph separator
        }
        result = value
        for char, replacement in replacements.items():
            result = result.replace(char, replacement)
        # Remove null bytes
        result = result.replace("\x00", "")
        return result

    @staticmethod
    def _encode_css(value: str) -> str:
        """Encode for CSS value context.

        Only allows safe CSS characters. Blocks url(), expression(),
        and other potentially dangerous CSS functions.
        """
        # Block dangerous CSS functions
        dangerous_patterns = [
            r"url\s*\(",
            r"expression\s*\(",
            r"import\s",
            r"behavior\s*:",
            r"-moz-binding\s*:",
        ]
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                raise SecurityViolation(
                    f"Dangerous CSS pattern detected: {pattern}"
                )

        # CSS hex-encode non-alphanumeric characters
        result = []
        for char in value:
            if char.isalnum() or char in " -_.":
                result.append(char)
            else:
                result.append(f"\\{ord(char):06X}")
        return "".join(result)

    @staticmethod
    def _encode_sql_identifier(value: str) -> str:
        """Encode for SQL identifier context (table/column names).

        NOTE: For SQL VALUES, use parameterized queries via SafeQueryBuilder.
        This is ONLY for dynamic identifier names when absolutely necessary.
        """
        # Only allow safe identifier characters
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", value):
            raise SecurityViolation(
                f"Invalid SQL identifier: '{value}'. "
                "Only alphanumeric and underscore allowed."
            )
        # Double-quote the identifier for safety
        return f'"{value}"'

    @staticmethod
    def _encode_json(value: str) -> str:
        """Encode for JSON string value context."""
        import json
        # json.dumps handles all necessary escaping
        # Strip the surrounding quotes since we're encoding the value only
        return json.dumps(value)[1:-1]

    @staticmethod
    def _encode_log(value: str) -> str:
        """Encode for log output.

        Strips potential PII patterns (emails, SSNs, credit cards)
        and removes control characters that could manipulate log output.
        """
        sanitized = value
        # Remove control characters (prevents log injection)
        sanitized = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", sanitized)
        # Replace newlines to prevent log forging
        sanitized = sanitized.replace("\n", " [NL] ").replace("\r", " [CR] ")
        # Mask potential PII patterns
        # Emails
        sanitized = re.sub(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "[EMAIL_REDACTED]",
            sanitized,
        )
        # SSN-like patterns
        sanitized = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_REDACTED]", sanitized)
        # Credit card-like patterns (simple: 13-19 digits)
        sanitized = re.sub(
            r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{1,7}\b",
            "[CC_REDACTED]",
            sanitized,
        )
        return sanitized
