"""Certified JWT Handler.

Provides secure JSON Web Token creation and validation with
safe algorithm defaults and mandatory expiration.

Prevents:
- CWE-347: Improper Verification of Cryptographic Signature
- CWE-613: Insufficient Session Expiration
- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CVE-2022-29217: PyJWT algorithm confusion
"""

import hashlib
import hmac
import json
import secrets
import time
from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from typing import Any

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when a certified component detects a security misuse."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "jwt_handler"},
        )


# Approved algorithms — NOTHING else is allowed
_APPROVED_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_DEFAULT_ALGORITHM = "HS256"

# Safe token lifetime bounds
_MIN_EXPIRY_SECONDS = 60        # 1 minute minimum
_MAX_EXPIRY_SECONDS = 3600      # 1 hour maximum for access tokens
_MAX_REFRESH_EXPIRY = 604800    # 7 days for refresh tokens


@dataclass(frozen=True)
class JWTConfig:
    """Immutable JWT configuration with safe defaults."""

    algorithm: str = _DEFAULT_ALGORITHM
    access_token_expiry: int = 900       # 15 minutes
    refresh_token_expiry: int = 86400    # 24 hours
    issuer: str = "aijailer"
    audience: str = "aijailer-api"

    def __post_init__(self) -> None:
        if self.algorithm not in _APPROVED_ALGORITHMS:
            raise SecurityViolation(
                f"Algorithm '{self.algorithm}' not approved. "
                f"Allowed: {sorted(_APPROVED_ALGORITHMS)}"
            )
        if not (_MIN_EXPIRY_SECONDS <= self.access_token_expiry <= _MAX_EXPIRY_SECONDS):
            raise SecurityViolation(
                f"Access token expiry must be {_MIN_EXPIRY_SECONDS}-{_MAX_EXPIRY_SECONDS}s"
            )
        if not (_MIN_EXPIRY_SECONDS <= self.refresh_token_expiry <= _MAX_REFRESH_EXPIRY):
            raise SecurityViolation(
                f"Refresh token expiry must be {_MIN_EXPIRY_SECONDS}-{_MAX_REFRESH_EXPIRY}s"
            )


@dataclass(frozen=True)
class TokenPair:
    """An access + refresh token pair."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 0


@dataclass(frozen=True)
class TokenClaims:
    """Validated JWT claims."""

    sub: str          # Subject (user ID)
    iss: str          # Issuer
    aud: str          # Audience
    exp: float        # Expiration timestamp
    iat: float        # Issued-at timestamp
    jti: str          # Unique token ID
    token_type: str   # "access" or "refresh"
    extra: dict[str, Any] | None = None


class JWTHandler:
    """Certified JWT handler with enforced safe defaults.

    - Only approved HMAC algorithms (no 'none', no algorithm confusion)
    - Mandatory expiration on all tokens
    - Refresh token rotation (one-time use)
    - Constant-time signature verification
    """

    def __init__(
        self,
        secret_key: str,
        config: JWTConfig | None = None,
    ) -> None:
        if not secret_key or len(secret_key) < 32:
            raise SecurityViolation("Secret key must be at least 32 characters")

        self._secret = secret_key.encode("utf-8")
        self._config = config or JWTConfig()
        # Track used refresh tokens to enforce rotation
        self._used_refresh_tokens: set[str] = set()

    def create_token_pair(
        self,
        user_id: str,
        extra_claims: dict[str, Any] | None = None,
    ) -> TokenPair:
        """Create an access + refresh token pair.

        Access token: short-lived, carries user claims.
        Refresh token: longer-lived, single-use (rotation enforced).
        """
        if not user_id:
            raise SecurityViolation("user_id is required for token creation")

        now = time.time()

        access_token = self._encode_token(
            sub=user_id,
            token_type="access",
            exp=now + self._config.access_token_expiry,
            iat=now,
            extra=extra_claims,
        )

        refresh_token = self._encode_token(
            sub=user_id,
            token_type="refresh",
            exp=now + self._config.refresh_token_expiry,
            iat=now,
        )

        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=self._config.access_token_expiry,
        )

    def verify_token(self, token: str, expected_type: str = "access") -> TokenClaims:
        """Verify and decode a JWT token.

        Checks: signature, expiration, issuer, audience, token type.
        Uses constant-time comparison for signature verification.

        Raises SecurityViolation on any validation failure.
        """
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise SecurityViolation("Malformed token structure")

            header_b64, payload_b64, signature_b64 = parts

            # Verify signature (constant-time)
            expected_sig = self._sign(f"{header_b64}.{payload_b64}")
            if not hmac.compare_digest(signature_b64, expected_sig):
                raise SecurityViolation("Invalid token signature")

            # Decode header — verify algorithm
            header = json.loads(self._b64decode(header_b64))
            if header.get("alg") != self._config.algorithm:
                raise SecurityViolation(
                    f"Algorithm mismatch: expected {self._config.algorithm}"
                )

            # Decode payload
            payload = json.loads(self._b64decode(payload_b64))

            # Validate claims
            now = time.time()
            if payload.get("exp", 0) < now:
                raise SecurityViolation("Token has expired")
            if payload.get("iss") != self._config.issuer:
                raise SecurityViolation("Invalid token issuer")
            if payload.get("aud") != self._config.audience:
                raise SecurityViolation("Invalid token audience")
            if payload.get("type") != expected_type:
                raise SecurityViolation(
                    f"Token type mismatch: expected '{expected_type}'"
                )

            return TokenClaims(
                sub=payload["sub"],
                iss=payload["iss"],
                aud=payload["aud"],
                exp=payload["exp"],
                iat=payload["iat"],
                jti=payload["jti"],
                token_type=payload["type"],
                extra=payload.get("extra"),
            )

        except SecurityViolation:
            raise
        except Exception as e:
            raise SecurityViolation(f"Token verification failed: {e}") from e

    def refresh(self, refresh_token: str) -> TokenPair:
        """Exchange a refresh token for a new token pair.

        Enforces one-time use: each refresh token can only be used once.
        This implements refresh token rotation per security best practices.
        """
        claims = self.verify_token(refresh_token, expected_type="refresh")

        # Enforce single-use
        if claims.jti in self._used_refresh_tokens:
            raise SecurityViolation(
                "Refresh token already used (possible token theft detected)"
            )
        self._used_refresh_tokens.add(claims.jti)

        return self.create_token_pair(user_id=claims.sub)

    def _encode_token(
        self,
        sub: str,
        token_type: str,
        exp: float,
        iat: float,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Encode a JWT token with HMAC signature."""
        header = {"alg": self._config.algorithm, "typ": "JWT"}
        payload: dict[str, Any] = {
            "sub": sub,
            "iss": self._config.issuer,
            "aud": self._config.audience,
            "exp": exp,
            "iat": iat,
            "jti": secrets.token_urlsafe(16),
            "type": token_type,
        }
        if extra:
            payload["extra"] = extra

        header_b64 = self._b64encode(json.dumps(header, separators=(",", ":")))
        payload_b64 = self._b64encode(json.dumps(payload, separators=(",", ":")))

        signature = self._sign(f"{header_b64}.{payload_b64}")
        return f"{header_b64}.{payload_b64}.{signature}"

    def _sign(self, message: str) -> str:
        """Create HMAC signature."""
        sig = hmac.new(self._secret, message.encode("utf-8"), hashlib.sha256).digest()
        return urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64encode(data: str) -> str:
        return urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("ascii")

    @staticmethod
    def _b64decode(data: str) -> bytes:
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding
        return urlsafe_b64decode(data)
