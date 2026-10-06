"""Input validation for secret names, values and destination hosts."""

import ipaddress
import re

from aijailer.secretstore.keys import SecretStoreError

MAX_VALUE_BYTES = 16 * 1024
MAX_HOSTS = 20
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")   # also the {{secret:NAME}} charset
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


class ValidationError(SecretStoreError):
    pass


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValidationError("name must be 1-63 chars of letters, digits, '_', '.', '-'")
    return name


def validate_value(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValidationError("value must be a non-empty string")
    raw = value.encode("utf-8")
    if len(raw) > MAX_VALUE_BYTES:
        raise ValidationError(f"value exceeds {MAX_VALUE_BYTES} bytes")
    # Secrets are substituted into HTTP headers: control characters would allow header injection.
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ValidationError("value must not contain control characters (CR, LF, NUL, ...)")
    return raw


def validate_host(h: str) -> str:
    if not isinstance(h, str):
        raise ValidationError("host must be a string")
    h = h.strip().lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(h)
        if ip.version != 4:
            raise ValidationError("only IPv4 literals are supported")
        return h
    except ValueError:
        pass
    wildcard = h.startswith("*.")
    labels = (h[2:] if wildcard else h).split(".")
    if len(labels) < 2 or any(not _LABEL.match(x) for x in labels):
        raise ValidationError(f"invalid host {h!r} (wildcards need at least two labels, e.g. *.example.com)")
    if len(h) > 253:
        raise ValidationError("host too long")
    return h


def validate_hosts(hosts: list[str]) -> list[str]:
    if not isinstance(hosts, list) or not hosts:
        raise ValidationError("hosts must be a non-empty list: a secret must be bound to destinations")
    if len(hosts) > MAX_HOSTS:
        raise ValidationError(f"at most {MAX_HOSTS} hosts")
    return sorted({validate_host(h) for h in hosts})
