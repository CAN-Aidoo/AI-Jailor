"""Minimal Prometheus text exposition (format 0.0.4), so metrics need no extra dependency."""

from collections.abc import Iterable

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def _escape_label(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _escape_help(v: str) -> str:
    return v.replace("\\", "\\\\").replace("\n", "\\n")


def render(families: Iterable[tuple[str, str, str, list[tuple[dict[str, str], float]]]]) -> str:
    """families: (name, type, help, [(labels, value), ...]). Families without samples are
    omitted (a HELP/TYPE with no series is noise)."""
    out: list[str] = []
    for name, typ, help_, samples in families:
        if not samples:
            continue
        out.append(f"# HELP {name} {_escape_help(help_)}")
        out.append(f"# TYPE {name} {typ}")
        for labels, value in samples:
            lab = ",".join(f'{k}="{_escape_label(v)}"' for k, v in sorted(labels.items()))
            val = repr(float(value)) if isinstance(value, float) else str(int(value))
            out.append(f"{name}{{{lab}}} {val}" if lab else f"{name} {val}")
    return "\n".join(out) + "\n"
