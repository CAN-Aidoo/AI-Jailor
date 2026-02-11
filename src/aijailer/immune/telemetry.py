"""Immune Telemetry — Generation Event Logging.

Logs code generation events: intent hash, constraints applied,
components used, blocked/allowed decisions, and latency.
In-memory store for MVP; ClickHouse interface-ready for production.
"""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class GenerationOutcome(str, Enum):
    SUCCESS = "success"
    BLOCKED = "blocked"
    PARTIAL = "partial"  # Generated with warnings
    ERROR = "error"


@dataclass
class GenerationEvent:
    """A single code generation event for analytics."""

    event_id: str
    tenant_id: str
    intent_hash: str
    action: str
    outcome: GenerationOutcome
    constraints_applied: list[str]
    constraints_violated: list[str]
    components_used: list[str]
    blocked_reason: str | None = None
    latency_ms: float = 0.0
    code_size_bytes: int = 0
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)


class Telemetry:
    """Generation event telemetry with analytics.

    Tracks all code generation attempts for:
    - Security posture monitoring
    - Constraint effectiveness analysis
    - Component usage patterns
    - Latency benchmarking
    """

    def __init__(self) -> None:
        self._events: list[GenerationEvent] = []
        self._counters: dict[str, int] = {
            "total": 0, "success": 0, "blocked": 0, "error": 0,
        }

    async def record(self, event: GenerationEvent) -> None:
        self._events.append(event)
        self._counters["total"] += 1
        self._counters[event.outcome.value] = (
            self._counters.get(event.outcome.value, 0) + 1
        )
        logger.info(
            "telemetry.event",
            event_id=event.event_id,
            outcome=event.outcome.value,
            latency_ms=event.latency_ms,
        )

    async def get_stats(
        self, tenant_id: str | None = None
    ) -> dict[str, Any]:
        events = self._events
        if tenant_id:
            events = [e for e in events if e.tenant_id == tenant_id]
        if not events:
            return {"total": 0, "block_rate": 0.0, "avg_latency_ms": 0.0}

        blocked = sum(1 for e in events if e.outcome == GenerationOutcome.BLOCKED)
        latencies = [e.latency_ms for e in events if e.latency_ms > 0]

        return {
            "total": len(events),
            "success": sum(1 for e in events if e.outcome == GenerationOutcome.SUCCESS),
            "blocked": blocked,
            "errors": sum(1 for e in events if e.outcome == GenerationOutcome.ERROR),
            "block_rate": blocked / len(events) if events else 0.0,
            "avg_latency_ms": sum(latencies) / len(latencies) if latencies else 0.0,
            "p95_latency_ms": sorted(latencies)[int(len(latencies) * 0.95)] if latencies else 0.0,
        }

    async def get_top_blocked_constraints(
        self, limit: int = 10
    ) -> list[dict[str, Any]]:
        counts: dict[str, int] = {}
        for e in self._events:
            for c in e.constraints_violated:
                counts[c] = counts.get(c, 0) + 1
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return [{"constraint": k, "count": v} for k, v in sorted_items[:limit]]

    async def get_component_usage(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in self._events:
            for c in e.components_used:
                counts[c] = counts.get(c, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))

    async def get_recent(
        self, limit: int = 100, outcome: str | None = None
    ) -> list[GenerationEvent]:
        events = self._events
        if outcome:
            events = [e for e in events if e.outcome.value == outcome]
        return events[-limit:]

    async def get_security_posture(self) -> dict[str, Any]:
        """Overall security health metrics."""
        if not self._events:
            return {"health": "no_data", "score": 0.0}

        recent = self._events[-1000:]
        blocked = sum(1 for e in recent if e.outcome == GenerationOutcome.BLOCKED)
        total = len(recent)
        block_rate = blocked / total

        unique_constraints = set()
        for e in recent:
            unique_constraints.update(e.constraints_applied)

        # Score: higher is better (more constraints enforced, moderate block rate)
        score = min(1.0, len(unique_constraints) / 10) * 0.5
        if 0.01 < block_rate < 0.3:
            score += 0.3  # Healthy block rate
        elif block_rate <= 0.01:
            score += 0.1  # Suspiciously low
        score += 0.2 if total > 100 else (total / 500)

        health = "good" if score > 0.7 else "moderate" if score > 0.4 else "poor"
        return {
            "health": health,
            "score": round(score, 2),
            "total_generations": total,
            "block_rate": round(block_rate, 4),
            "active_constraints": len(unique_constraints),
        }
