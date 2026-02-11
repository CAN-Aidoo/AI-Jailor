"""Certified Session Manager.

Provides secure session handling with HttpOnly cookies,
CSRF token generation, and safe session lifecycle management.

Prevents:
- CWE-384: Session Fixation
- CWE-614: Sensitive Cookie Without 'Secure' Flag
- CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
- CWE-613: Insufficient Session Expiration
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when a certified component detects a security misuse."""

    def __init__(self, message: str, component: str = "session_manager"):
        super().__init__(code="security_violation", message=message, details={"component": component})


# Safe defaults — cannot be weakened
_MIN_SESSION_TTL = 300          # 5 minutes minimum
_MAX_SESSION_TTL = 86400        # 24 hours maximum
_CSRF_TOKEN_BYTES = 32
_SESSION_ID_BYTES = 32


@dataclass(frozen=True)
class SessionConfig:
    """Immutable session configuration with safe defaults."""

    ttl_seconds: int = 3600         # 1 hour default
    cookie_name: str = "__session"
    csrf_cookie_name: str = "__csrf"
    httponly: bool = True            # CANNOT be set to False
    secure: bool = True             # CANNOT be set to False
    samesite: str = "Lax"           # Lax or Strict only
    domain: str | None = None
    path: str = "/"

    def __post_init__(self) -> None:
        if not self.httponly:
            raise SecurityViolation("HttpOnly flag cannot be disabled on session cookies")
        if not self.secure:
            raise SecurityViolation("Secure flag cannot be disabled on session cookies")
        if self.samesite not in ("Lax", "Strict"):
            raise SecurityViolation(
                f"SameSite must be 'Lax' or 'Strict', got '{self.samesite}'"
            )
        if not (_MIN_SESSION_TTL <= self.ttl_seconds <= _MAX_SESSION_TTL):
            raise SecurityViolation(
                f"Session TTL must be between {_MIN_SESSION_TTL}s and {_MAX_SESSION_TTL}s"
            )


@dataclass
class Session:
    """A validated user session."""

    session_id: str
    user_id: str
    csrf_token: str
    created_at: float
    expires_at: float
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    @property
    def token(self) -> str:
        """Public-facing session token."""
        return self.session_id


class SessionManager:
    """Certified session management with secure defaults.

    All sessions are HttpOnly, Secure, SameSite=Lax by default.
    Session IDs are cryptographically random (256-bit).
    CSRF tokens are generated per-session and verified on state-changing requests.
    """

    def __init__(self, config: SessionConfig | None = None) -> None:
        self._config = config or SessionConfig()
        self._sessions: dict[str, Session] = {}
        self._signing_key = secrets.token_bytes(32)

    async def create(
        self,
        user_id: str,
        data: dict[str, Any] | None = None,
    ) -> Session:
        """Create a new session with a cryptographically random ID.

        Automatically generates a CSRF token bound to this session.
        Previous sessions for the same user are invalidated (prevents session fixation).
        """
        if not user_id or not isinstance(user_id, str):
            raise SecurityViolation("user_id must be a non-empty string")

        # Invalidate any existing sessions for this user (prevent fixation)
        await self.invalidate_user_sessions(user_id)

        now = time.time()
        session = Session(
            session_id=secrets.token_urlsafe(_SESSION_ID_BYTES),
            user_id=user_id,
            csrf_token=secrets.token_urlsafe(_CSRF_TOKEN_BYTES),
            created_at=now,
            expires_at=now + self._config.ttl_seconds,
            data=data or {},
        )

        self._sessions[session.session_id] = session
        return session

    async def validate(self, session_id: str) -> Session | None:
        """Validate a session ID and return the session if valid.

        Returns None if the session is expired or doesn't exist.
        Expired sessions are automatically cleaned up.
        """
        if not session_id:
            return None

        session = self._sessions.get(session_id)
        if session is None:
            return None

        if session.is_expired:
            # Auto-cleanup expired session
            del self._sessions[session_id]
            return None

        return session

    async def validate_csrf(self, session_id: str, csrf_token: str) -> bool:
        """Validate a CSRF token against a session.

        Uses constant-time comparison to prevent timing attacks.
        """
        session = await self.validate(session_id)
        if session is None:
            return False

        return hmac.compare_digest(session.csrf_token, csrf_token)

    async def invalidate(self, session_id: str) -> None:
        """Explicitly invalidate (destroy) a session."""
        self._sessions.pop(session_id, None)

    async def invalidate_user_sessions(self, user_id: str) -> int:
        """Invalidate ALL sessions for a user (e.g., on password change)."""
        to_remove = [
            sid for sid, s in self._sessions.items() if s.user_id == user_id
        ]
        for sid in to_remove:
            del self._sessions[sid]
        return len(to_remove)

    def get_cookie_attributes(self) -> dict[str, Any]:
        """Get the safe cookie attributes for Set-Cookie header."""
        attrs: dict[str, Any] = {
            "httponly": True,  # Always True
            "secure": True,   # Always True
            "samesite": self._config.samesite,
            "path": self._config.path,
            "max_age": self._config.ttl_seconds,
        }
        if self._config.domain:
            attrs["domain"] = self._config.domain
        return attrs
