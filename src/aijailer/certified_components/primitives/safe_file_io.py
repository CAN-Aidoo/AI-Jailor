"""Certified Safe File I/O.

Path traversal prevention via strict allowlisting and
canonicalization. All file operations go through this module.

Prevents:
- CWE-22: Path Traversal
- CWE-23: Relative Path Traversal
- CWE-36: Absolute Path Traversal
- CWE-73: External Control of File Name or Path
"""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when file I/O detects a path traversal or other violation."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "safe_file_io"},
        )


# Patterns that indicate path traversal attempts
_TRAVERSAL_PATTERNS = [
    r"\.\.",              # Parent directory reference
    r"~",                 # Home directory expansion
    r"\$\{",              # Variable expansion
    r"\$\(",              # Command substitution
    r"%2e%2e",            # URL-encoded ..
    r"%252e%252e",        # Double-encoded ..
    r"\x00",              # Null byte injection
]

# Dangerous file extensions
_DANGEROUS_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".js", ".wsh", ".wsf", ".ps1", ".msi",
}


@dataclass(frozen=True)
class FileIOConfig:
    """Safe file I/O configuration."""

    allowed_directories: list[str] = field(default_factory=list)
    max_file_size_bytes: int = 10_485_760  # 10 MB default
    allowed_extensions: list[str] = field(default_factory=list)  # Empty = allow all safe
    deny_hidden_files: bool = True
    deny_symlinks: bool = True

    def __post_init__(self) -> None:
        if not self.allowed_directories:
            raise SecurityViolation(
                "At least one allowed directory must be configured"
            )
        if self.max_file_size_bytes <= 0:
            raise SecurityViolation("max_file_size_bytes must be positive")


class SafeFileIO:
    """Certified safe file operations with path traversal prevention.

    - ALL paths are canonicalized before use
    - Operations are restricted to configured allowed directories
    - Path traversal sequences are always rejected
    - Symlink following can be disabled
    - File size limits are enforced
    """

    def __init__(self, config: FileIOConfig) -> None:
        self._config = config
        # Resolve and normalize allowed directories at init time
        self._allowed_dirs: list[Path] = [
            Path(d).resolve() for d in config.allowed_directories
        ]

    def validate_path(self, path: str) -> Path:
        """Validate and canonicalize a file path.

        Returns the resolved Path if it's within allowed directories.
        Raises SecurityViolation if path traversal is detected.
        """
        if not path:
            raise SecurityViolation("File path must not be empty")

        # Check for traversal patterns in the raw input
        for pattern in _TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                raise SecurityViolation(
                    f"Path traversal pattern detected in: '{path}'"
                )

        # Resolve to absolute canonical path
        resolved = Path(path).resolve()

        # Check symlinks
        if self._config.deny_symlinks and Path(path).is_symlink():
            raise SecurityViolation(
                f"Symlinks are not allowed: '{path}'"
            )

        # Check hidden files
        if self._config.deny_hidden_files:
            for part in resolved.parts:
                if part.startswith(".") and part not in (".", ".."):
                    raise SecurityViolation(
                        f"Hidden files are not allowed: '{path}'"
                    )

        # Check if path is within an allowed directory
        if not any(self._is_within(resolved, d) for d in self._allowed_dirs):
            raise SecurityViolation(
                f"Path '{resolved}' is outside allowed directories"
            )

        # Check dangerous extensions
        ext = resolved.suffix.lower()
        if ext in _DANGEROUS_EXTENSIONS:
            raise SecurityViolation(
                f"Dangerous file extension: '{ext}'"
            )

        # Check allowed extensions
        if self._config.allowed_extensions and ext:
            if ext not in self._config.allowed_extensions:
                raise SecurityViolation(
                    f"File extension '{ext}' is not in allowed list"
                )

        return resolved

    async def read_file(self, path: str) -> bytes:
        """Safely read a file's contents."""
        validated = self.validate_path(path)

        if not validated.exists():
            raise SecurityViolation(f"File not found: '{path}'")

        if not validated.is_file():
            raise SecurityViolation(f"Not a regular file: '{path}'")

        # Check file size before reading
        size = validated.stat().st_size
        if size > self._config.max_file_size_bytes:
            raise SecurityViolation(
                f"File size {size} bytes exceeds limit of "
                f"{self._config.max_file_size_bytes} bytes"
            )

        return validated.read_bytes()

    async def read_text(self, path: str, encoding: str = "utf-8") -> str:
        """Safely read a text file."""
        data = await self.read_file(path)
        try:
            return data.decode(encoding)
        except UnicodeDecodeError as e:
            raise SecurityViolation(f"File is not valid {encoding}: {e}") from e

    async def write_file(self, path: str, data: bytes) -> Path:
        """Safely write data to a file."""
        validated = self.validate_path(path)

        if len(data) > self._config.max_file_size_bytes:
            raise SecurityViolation(
                f"Data size {len(data)} bytes exceeds limit of "
                f"{self._config.max_file_size_bytes} bytes"
            )

        # Create parent directories if needed (within allowed dir)
        validated.parent.mkdir(parents=True, exist_ok=True)
        validated.write_bytes(data)
        return validated

    async def write_text(
        self, path: str, text: str, encoding: str = "utf-8"
    ) -> Path:
        """Safely write text to a file."""
        return await self.write_file(path, text.encode(encoding))

    async def delete_file(self, path: str) -> None:
        """Safely delete a file."""
        validated = self.validate_path(path)

        if not validated.exists():
            raise SecurityViolation(f"File not found: '{path}'")

        if not validated.is_file():
            raise SecurityViolation(f"Not a regular file: '{path}'")

        validated.unlink()

    async def list_directory(self, path: str) -> list[dict[str, Any]]:
        """Safely list directory contents."""
        validated = self.validate_path(path)

        if not validated.is_dir():
            raise SecurityViolation(f"Not a directory: '{path}'")

        entries: list[dict[str, Any]] = []
        for entry in validated.iterdir():
            # Skip hidden files if configured
            if self._config.deny_hidden_files and entry.name.startswith("."):
                continue
            entries.append({
                "name": entry.name,
                "is_file": entry.is_file(),
                "is_dir": entry.is_dir(),
                "size": entry.stat().st_size if entry.is_file() else None,
            })
        return entries

    @staticmethod
    def _is_within(path: Path, directory: Path) -> bool:
        """Check if path is within directory (after both are resolved)."""
        try:
            path.relative_to(directory)
            return True
        except ValueError:
            return False
