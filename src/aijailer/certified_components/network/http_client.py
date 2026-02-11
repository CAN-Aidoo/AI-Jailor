"""Certified HTTP Client.

TLS-enforced, timeout-safe, SSRF-preventing HTTP client
wrapper. All outbound HTTP requests MUST go through this client.

Prevents:
- CWE-918: Server-Side Request Forgery (SSRF)
- CWE-295: Improper Certificate Validation
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-400: Uncontrolled Resource Consumption (timeout enforcement)
"""

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when HTTP client detects a security violation."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "http_client"},
        )


# Private/internal IP ranges that SSRF attacks target
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 private
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),
]

# Blocked URL schemes
_BLOCKED_SCHEMES = {"file", "ftp", "gopher", "data", "dict", "ldap"}


@dataclass(frozen=True)
class HttpClientConfig:
    """Immutable HTTP client configuration with safe defaults."""

    timeout_seconds: float = 30.0          # Maximum request timeout
    max_redirects: int = 5                  # Maximum redirect follows
    verify_ssl: bool = True                 # CANNOT be disabled
    allow_private_ips: bool = False         # Block SSRF by default
    allowed_domains: list[str] = field(default_factory=list)  # Empty = allow all public
    blocked_domains: list[str] = field(default_factory=list)
    max_response_size_bytes: int = 10_485_760  # 10 MB
    user_agent: str = "AIJailer-CertifiedClient/1.0"

    def __post_init__(self) -> None:
        if not self.verify_ssl:
            raise SecurityViolation("SSL verification cannot be disabled")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise SecurityViolation("Timeout must be between 0 and 120 seconds")
        if self.max_redirects < 0 or self.max_redirects > 10:
            raise SecurityViolation("max_redirects must be between 0 and 10")


@dataclass
class HttpResponse:
    """Safe HTTP response wrapper."""

    status_code: int
    headers: dict[str, str]
    body: bytes
    url: str
    elapsed_ms: float

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    @property
    def json(self) -> Any:
        import json
        return json.loads(self.body)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400


class SecureHttpClient:
    """Certified HTTP client with SSRF prevention and TLS enforcement.

    - All requests MUST use HTTPS (HTTP is blocked)
    - Private/internal IPs are blocked by default (SSRF prevention)
    - DNS resolution is validated before connecting
    - Timeouts are enforced on all operations
    - SSL certificates are always verified
    """

    def __init__(self, config: HttpClientConfig | None = None) -> None:
        self._config = config or HttpClientConfig()

    def validate_url(self, url: str) -> str:
        """Validate a URL is safe to request.

        Checks: scheme, domain, IP resolution, blocklist/allowlist.
        Returns the validated URL.
        Raises SecurityViolation if the URL is not safe.
        """
        parsed = urlparse(url)

        # Check scheme — ONLY HTTPS allowed
        if parsed.scheme.lower() not in ("https",):
            raise SecurityViolation(
                f"Only HTTPS is allowed, got '{parsed.scheme}'"
            )

        # Check for blocked schemes in URL
        if parsed.scheme.lower() in _BLOCKED_SCHEMES:
            raise SecurityViolation(
                f"Blocked URL scheme: '{parsed.scheme}'"
            )

        # Check hostname exists
        hostname = parsed.hostname
        if not hostname:
            raise SecurityViolation("URL must have a hostname")

        # Check domain allowlist
        if self._config.allowed_domains:
            if not any(
                hostname == d or hostname.endswith(f".{d}")
                for d in self._config.allowed_domains
            ):
                raise SecurityViolation(
                    f"Domain '{hostname}' not in allowed list"
                )

        # Check domain blocklist
        if self._config.blocked_domains:
            if any(
                hostname == d or hostname.endswith(f".{d}")
                for d in self._config.blocked_domains
            ):
                raise SecurityViolation(
                    f"Domain '{hostname}' is blocked"
                )

        # Resolve hostname and check for private IPs (SSRF prevention)
        if not self._config.allow_private_ips:
            self._check_ssrf(hostname)

        return url

    async def get(self, url: str, headers: dict[str, str] | None = None) -> HttpResponse:
        """Perform a safe HTTP GET request."""
        return await self._request("GET", url, headers=headers)

    async def post(
        self,
        url: str,
        data: bytes | str | None = None,
        json_data: Any = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Perform a safe HTTP POST request."""
        return await self._request(
            "POST", url, data=data, json_data=json_data, headers=headers
        )

    async def put(
        self,
        url: str,
        data: bytes | str | None = None,
        json_data: Any = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Perform a safe HTTP PUT request."""
        return await self._request(
            "PUT", url, data=data, json_data=json_data, headers=headers
        )

    async def delete(
        self, url: str, headers: dict[str, str] | None = None
    ) -> HttpResponse:
        """Perform a safe HTTP DELETE request."""
        return await self._request("DELETE", url, headers=headers)

    async def _request(
        self,
        method: str,
        url: str,
        data: bytes | str | None = None,
        json_data: Any = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        """Execute a safe HTTP request."""
        import time

        # Validate URL before making request
        validated_url = self.validate_url(url)

        start = time.perf_counter()

        try:
            import httpx

            req_headers = {"User-Agent": self._config.user_agent}
            if headers:
                req_headers.update(headers)

            async with httpx.AsyncClient(
                timeout=self._config.timeout_seconds,
                follow_redirects=True,
                max_redirects=self._config.max_redirects,
                verify=True,  # Always True
            ) as client:
                if json_data is not None:
                    import json as json_mod
                    body = json_mod.dumps(json_data).encode("utf-8")
                    req_headers["Content-Type"] = "application/json"
                elif isinstance(data, str):
                    body = data.encode("utf-8")
                else:
                    body = data

                response = await client.request(
                    method,
                    validated_url,
                    content=body,
                    headers=req_headers,
                )

                elapsed = (time.perf_counter() - start) * 1000

                # Check response size
                if len(response.content) > self._config.max_response_size_bytes:
                    raise SecurityViolation(
                        f"Response exceeds maximum size of "
                        f"{self._config.max_response_size_bytes} bytes"
                    )

                return HttpResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=response.content,
                    url=str(response.url),
                    elapsed_ms=elapsed,
                )

        except ImportError:
            raise SecurityViolation(
                "httpx package is required. Install with: pip install httpx"
            )
        except SecurityViolation:
            raise
        except Exception as e:
            raise SecurityViolation(f"HTTP request failed: {e}") from e

    def _check_ssrf(self, hostname: str) -> None:
        """Check if a hostname resolves to a private IP (SSRF prevention)."""
        try:
            # Check if hostname is already an IP
            try:
                ip = ipaddress.ip_address(hostname)
                if any(ip in net for net in _PRIVATE_RANGES):
                    raise SecurityViolation(
                        f"SSRF blocked: '{hostname}' resolves to private IP"
                    )
                return
            except ValueError:
                pass  # Not an IP literal, resolve hostname

            # DNS resolution
            results = socket.getaddrinfo(hostname, None)
            for _, _, _, _, sockaddr in results:
                ip = ipaddress.ip_address(sockaddr[0])
                if any(ip in net for net in _PRIVATE_RANGES):
                    raise SecurityViolation(
                        f"SSRF blocked: '{hostname}' resolves to "
                        f"private IP {sockaddr[0]}"
                    )
        except SecurityViolation:
            raise
        except socket.gaierror:
            raise SecurityViolation(
                f"DNS resolution failed for '{hostname}'"
            )
