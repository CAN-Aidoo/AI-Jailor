"""The per-command parameters of POST /v1/cells/{id}/exec that reach the guest: the environment and the
working directory.

The request's ``environment`` is applied on top of the cell's own environment (the creation-time settings
plus the variables the platform injects). Names the platform or the guest agent manage are refused instead of
silently ignored, so a request can never appear to set something it does not. That is a guard against
confusion, not a security boundary: a command can always export anything it likes itself, and what a cell can
reach is enforced by the host firewall.

``working_directory`` is where the command starts. It must be an absolute path; whether it exists and is
accessible to the user is only known inside the guest, which reports it when the command cannot start.
"""

import re

from aijailer.core.exceptions import AiJailerError

MAX_VARS = 100
MAX_NAME_LEN = 128
MAX_VALUE_BYTES = 8192
MAX_TOTAL_BYTES = 65536

_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
# Injected by the platform (netpolicy.cell_network, peerlink): proxy settings and AIJAILER_* values.
_PLATFORM_PROXY = frozenset({"http_proxy", "https_proxy", "no_proxy"})
_PLATFORM_PREFIX = "aijailer_"
# Set by the guest agent from the account the command runs as.
_AGENT_MANAGED = frozenset({"HOME", "USER"})


def managed_reason(name: str) -> str | None:
    """Why a name may not be set per command, or None if it may."""
    low = name.lower()
    if low in _PLATFORM_PROXY or low.startswith(_PLATFORM_PREFIX):
        return "managed by the platform"
    if name in _AGENT_MANAGED:
        return "set by the guest agent from the account the command runs as"
    return None


def _bad(message: str) -> AiJailerError:
    return AiJailerError(message, code="invalid_environment")


def validate_exec_environment(env: dict[str, str] | None) -> dict[str, str]:
    """Return a clean copy of ``env`` or raise ``invalid_environment`` (HTTP 400)."""
    env = dict(env or {})
    if len(env) > MAX_VARS:
        raise _bad(f"environment may have at most {MAX_VARS} variables")
    total = 0
    for name, value in env.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise _bad("environment names and values must be strings")
        if len(name) > MAX_NAME_LEN or not _NAME.match(name):
            raise _bad(f"invalid environment variable name {name[:40]!r}: use letters, digits and underscores, "
                       f"not starting with a digit, at most {MAX_NAME_LEN} characters")
        if "\x00" in value:
            raise _bad(f"the value of {name} contains a NUL byte")
        size = len(value.encode("utf-8"))
        if size > MAX_VALUE_BYTES:
            raise _bad(f"the value of {name} is larger than {MAX_VALUE_BYTES} bytes")
        total += len(name) + size
        reason = managed_reason(name)
        if reason:
            raise _bad(f"environment variable {name} cannot be set per command: {reason}")
    if total > MAX_TOTAL_BYTES:
        raise _bad(f"environment is larger than {MAX_TOTAL_BYTES} bytes in total")
    return env


MAX_CWD_LEN = 1024      # the length of the column the execution record keeps it in


def validate_working_directory(path: str | None) -> str | None:
    """Return the directory to start the command in, or None for the guest's default (the user's home).

    Only an explicit request value is passed on: the cell-level default (``/home/agent``) would be wrong for
    a command run as another user, and the guest already starts in the user's home when none is given.
    """
    if path is None or path == "":
        return None
    if not isinstance(path, str):
        raise AiJailerError("working_directory must be a string", code="invalid_working_directory")
    if "\x00" in path:
        raise AiJailerError("working_directory contains a NUL byte", code="invalid_working_directory")
    if len(path) > MAX_CWD_LEN:
        raise AiJailerError(f"working_directory is longer than {MAX_CWD_LEN} characters",
                            code="invalid_working_directory")
    if not path.startswith("/"):
        raise AiJailerError("working_directory must be an absolute path (start with /)",
                            code="invalid_working_directory")
    return path
