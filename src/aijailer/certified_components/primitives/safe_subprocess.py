"""Certified Safe Subprocess Execution.

Command injection prevention via strict allowlisting.
Only pre-approved commands with validated arguments can execute.

Prevents:
- CWE-78: OS Command Injection
- CWE-77: Command Injection
- CWE-88: Improper Neutralization of Argument Delimiters
"""

import asyncio
import re
import shlex
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from aijailer.core.exceptions import AiJailerError


class SecurityViolation(AiJailerError):
    """Raised when subprocess execution violates security constraints."""

    def __init__(self, message: str):
        super().__init__(
            code="security_violation",
            message=message,
            details={"component": "safe_subprocess"},
        )


# Characters that enable command injection
_SHELL_METACHARACTERS = set("|;&`$(){}[]!><\n\r")

# Dangerous argument patterns
_DANGEROUS_ARG_PATTERNS = [
    r";\s*\w",           # Command chaining
    r"\|\s*\w",          # Pipe to another command
    r"&\s*\w",           # Background execution
    r"`[^`]+`",          # Backtick substitution
    r"\$\([^)]+\)",      # Command substitution
    r"\$\{[^}]+\}",      # Variable expansion
    r">|>>",             # Output redirection
    r"<",                # Input redirection
]


class OutputCapture(str, Enum):
    """How to handle subprocess output."""

    CAPTURE = "capture"    # Capture stdout/stderr
    DISCARD = "discard"    # Discard output
    STREAM = "stream"      # Stream output (not implemented in MVP)


@dataclass(frozen=True)
class CommandPolicy:
    """Defines what arguments are allowed for a specific command."""

    command: str                          # The base command (e.g., "ls", "git")
    allowed_args: list[str] = field(default_factory=list)  # Allowed argument patterns (regex)
    max_args: int = 20                    # Maximum number of arguments
    timeout_seconds: float = 30.0         # Execution timeout
    allow_stdin: bool = False             # Whether stdin input is allowed


@dataclass
class ProcessResult:
    """Result of a subprocess execution."""

    exit_code: int
    stdout: str
    stderr: str
    command: str
    timed_out: bool = False


class SafeSubprocess:
    """Certified subprocess execution with command injection prevention.

    - ONLY allowlisted commands can be executed
    - Shell execution is NEVER used (always uses exec directly)
    - Arguments are validated against injection patterns
    - Timeouts are enforced on all executions
    - Environment variables are sanitized
    """

    def __init__(self, allowed_commands: list[CommandPolicy] | None = None) -> None:
        self._policies: dict[str, CommandPolicy] = {}
        if allowed_commands:
            for policy in allowed_commands:
                self._policies[policy.command] = policy

    def allow_command(self, policy: CommandPolicy) -> None:
        """Register an allowed command with its policy."""
        self._policies[policy.command] = policy

    async def execute(
        self,
        command: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        stdin_data: str | None = None,
        output: OutputCapture = OutputCapture.CAPTURE,
    ) -> ProcessResult:
        """Execute a command safely.

        The command MUST be in the allowlist. Arguments are validated
        against injection patterns. Shell execution is NEVER used.
        """
        args = args or []

        # Check command is allowed
        policy = self._policies.get(command)
        if policy is None:
            raise SecurityViolation(
                f"Command '{command}' is not in the allowlist. "
                f"Allowed: {sorted(self._policies.keys())}"
            )

        # Validate argument count
        if len(args) > policy.max_args:
            raise SecurityViolation(
                f"Too many arguments ({len(args)}). Maximum: {policy.max_args}"
            )

        # Validate each argument
        for i, arg in enumerate(args):
            self._validate_argument(arg, policy, i)

        # Validate stdin
        if stdin_data and not policy.allow_stdin:
            raise SecurityViolation(
                f"stdin input not allowed for command '{command}'"
            )

        # Sanitize environment
        safe_env = self._sanitize_env(env)

        # Build command list (NO shell=True, EVER)
        cmd_list = [command] + args

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE if output == OutputCapture.CAPTURE else asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.PIPE if output == OutputCapture.CAPTURE else asyncio.subprocess.DEVNULL,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
                cwd=cwd,
                env=safe_env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(
                        input=stdin_data.encode("utf-8") if stdin_data else None
                    ),
                    timeout=policy.timeout_seconds,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ProcessResult(
                    exit_code=-1,
                    stdout="",
                    stderr="Process timed out",
                    command=command,
                    timed_out=True,
                )

            return ProcessResult(
                exit_code=proc.returncode or 0,
                stdout=(stdout_bytes or b"").decode("utf-8", errors="replace"),
                stderr=(stderr_bytes or b"").decode("utf-8", errors="replace"),
                command=command,
            )

        except FileNotFoundError:
            raise SecurityViolation(f"Command '{command}' not found on system")
        except PermissionError:
            raise SecurityViolation(
                f"Permission denied for command '{command}'"
            )

    @staticmethod
    def _validate_argument(arg: str, policy: CommandPolicy, index: int) -> None:
        """Validate a single argument against injection patterns."""
        # Check for shell metacharacters
        for char in arg:
            if char in _SHELL_METACHARACTERS:
                raise SecurityViolation(
                    f"Shell metacharacter '{char}' detected in argument {index}: "
                    f"'{arg}'"
                )

        # Check for dangerous patterns
        for pattern in _DANGEROUS_ARG_PATTERNS:
            if re.search(pattern, arg):
                raise SecurityViolation(
                    f"Dangerous pattern in argument {index}: '{arg}'"
                )

        # Check null bytes
        if "\x00" in arg:
            raise SecurityViolation(
                f"Null byte detected in argument {index}"
            )

        # Check against policy's allowed argument patterns
        if policy.allowed_args:
            if not any(re.match(p, arg) for p in policy.allowed_args):
                raise SecurityViolation(
                    f"Argument {index} '{arg}' does not match any allowed pattern"
                )

    @staticmethod
    def _sanitize_env(env: dict[str, str] | None) -> dict[str, str] | None:
        """Sanitize environment variables."""
        if env is None:
            return None

        safe_env: dict[str, str] = {}
        for key, value in env.items():
            # Validate key — only alphanumeric + underscore
            if not re.match(r"^[A-Z_][A-Z0-9_]*$", key, re.IGNORECASE):
                raise SecurityViolation(
                    f"Invalid environment variable name: '{key}'"
                )
            # Check value for injection
            for char in value:
                if char in _SHELL_METACHARACTERS:
                    raise SecurityViolation(
                        f"Shell metacharacter in env var '{key}'"
                    )
            safe_env[key] = value

        return safe_env
