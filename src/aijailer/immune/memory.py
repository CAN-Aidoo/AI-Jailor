"""Immune Memory — Attack Pattern Storage.

In-memory attack pattern store with similarity matching,
occurrence tracking, and first/last seen timestamps.
Provides the "memory" for the immune system to recognize
previously observed vulnerability patterns.
"""

import hashlib
import time
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ThreatSeverity(str, Enum):
    """Severity classification for attack patterns."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PatternStatus(str, Enum):
    """Status of an attack pattern in memory."""

    ACTIVE = "active"          # Currently being enforced
    PENDING = "pending"        # Awaiting human review
    SUPERSEDED = "superseded"  # Replaced by a newer pattern
    ARCHIVED = "archived"      # No longer relevant


@dataclass
class AttackPattern:
    """A known vulnerability pattern stored in immune memory."""

    pattern_id: str
    cwe_id: str                          # e.g., "CWE-89"
    description: str
    attack_vector: str                   # Code pattern that triggers the vuln
    severity: ThreatSeverity
    detection_signature: str             # Regex or AST pattern for detection
    required_constraint: str | None      # Constraint that prevents this pattern
    required_component: str | None       # Certified component that prevents it
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    occurrence_count: int = 1
    status: PatternStatus = PatternStatus.ACTIVE
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = "manual"               # "manual", "cve_feed", "telemetry", "report"

    @property
    def pattern_hash(self) -> str:
        """Unique hash for deduplication."""
        return hashlib.sha256(
            f"{self.cwe_id}:{self.attack_vector}:{self.detection_signature}".encode()
        ).hexdigest()[:16]

    def is_similar_to(self, other: "AttackPattern", threshold: float = 0.7) -> bool:
        """Check if two patterns are similar using sequence matching."""
        vector_sim = SequenceMatcher(
            None, self.attack_vector, other.attack_vector
        ).ratio()
        sig_sim = SequenceMatcher(
            None, self.detection_signature, other.detection_signature
        ).ratio()
        # Weighted: attack vector matters more
        combined = (vector_sim * 0.6) + (sig_sim * 0.4)
        return combined >= threshold


class ImmuneMemory:
    """In-memory attack pattern store with similarity matching.

    Functions like biological immune memory:
    - Stores known attack patterns (antigens)
    - Matches new observations against known patterns
    - Tracks pattern frequency and recency
    - Supports similarity-based matching for variant detection
    """

    def __init__(self) -> None:
        self._patterns: dict[str, AttackPattern] = {}
        self._cwe_index: dict[str, list[str]] = {}  # CWE → pattern_ids
        self._stats = {
            "total_stored": 0,
            "total_matches": 0,
            "total_reports": 0,
        }

    async def store(self, pattern: AttackPattern) -> AttackPattern:
        """Store a new attack pattern or update existing.

        If a similar pattern exists, merge occurrence counts.
        """
        # Check for exact duplicate
        existing = self._patterns.get(pattern.pattern_id)
        if existing:
            existing.last_seen = time.time()
            existing.occurrence_count += 1
            logger.info(
                "immune.pattern_updated",
                pattern_id=existing.pattern_id,
                occurrences=existing.occurrence_count,
            )
            return existing

        # Check for similar patterns
        similar = await self.find_similar(pattern, threshold=0.85)
        if similar:
            # Merge into the most similar existing pattern
            best = similar[0]
            best.last_seen = time.time()
            best.occurrence_count += pattern.occurrence_count
            if pattern.severity.value < best.severity.value:
                best.severity = pattern.severity  # Escalate severity
            logger.info(
                "immune.pattern_merged",
                existing_id=best.pattern_id,
                new_id=pattern.pattern_id,
            )
            return best

        # Store as new pattern
        self._patterns[pattern.pattern_id] = pattern
        self._stats["total_stored"] += 1

        # Update CWE index
        if pattern.cwe_id not in self._cwe_index:
            self._cwe_index[pattern.cwe_id] = []
        self._cwe_index[pattern.cwe_id].append(pattern.pattern_id)

        logger.info(
            "immune.pattern_stored",
            pattern_id=pattern.pattern_id,
            cwe=pattern.cwe_id,
            severity=pattern.severity.value,
        )
        return pattern

    async def recall(self, pattern_id: str) -> AttackPattern | None:
        """Recall a specific attack pattern by ID."""
        return self._patterns.get(pattern_id)

    async def find_by_cwe(self, cwe_id: str) -> list[AttackPattern]:
        """Find all patterns for a specific CWE."""
        pattern_ids = self._cwe_index.get(cwe_id, [])
        return [
            self._patterns[pid]
            for pid in pattern_ids
            if pid in self._patterns
        ]

    async def find_similar(
        self,
        pattern: AttackPattern,
        threshold: float = 0.7,
    ) -> list[AttackPattern]:
        """Find attack patterns similar to the given one.

        Uses weighted sequence matching on attack vector and
        detection signature.
        """
        matches: list[tuple[float, AttackPattern]] = []

        for existing in self._patterns.values():
            if existing.status != PatternStatus.ACTIVE:
                continue

            vector_sim = SequenceMatcher(
                None, pattern.attack_vector, existing.attack_vector
            ).ratio()
            sig_sim = SequenceMatcher(
                None, pattern.detection_signature, existing.detection_signature
            ).ratio()

            # Boost similarity for same CWE
            cwe_boost = 0.1 if pattern.cwe_id == existing.cwe_id else 0.0
            combined = (vector_sim * 0.6) + (sig_sim * 0.4) + cwe_boost
            combined = min(combined, 1.0)

            if combined >= threshold:
                matches.append((combined, existing))

        # Sort by similarity (highest first)
        matches.sort(key=lambda x: x[0], reverse=True)
        self._stats["total_matches"] += len(matches)

        return [m[1] for m in matches]

    async def match_code(
        self,
        code: str,
        min_severity: ThreatSeverity = ThreatSeverity.LOW,
    ) -> list[AttackPattern]:
        """Match code against all stored attack patterns.

        Returns patterns whose detection signatures match the code.
        """
        import re

        matched: list[AttackPattern] = []

        severity_order = {
            ThreatSeverity.CRITICAL: 0,
            ThreatSeverity.HIGH: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 3,
            ThreatSeverity.INFO: 4,
        }
        min_level = severity_order.get(min_severity, 3)

        for pattern in self._patterns.values():
            if pattern.status != PatternStatus.ACTIVE:
                continue

            pattern_level = severity_order.get(pattern.severity, 4)
            if pattern_level > min_level:
                continue

            try:
                if re.search(pattern.detection_signature, code, re.MULTILINE):
                    matched.append(pattern)
                    pattern.last_seen = time.time()
            except re.error:
                # Invalid regex in signature — log but don't crash
                logger.warning(
                    "immune.invalid_signature",
                    pattern_id=pattern.pattern_id,
                    signature=pattern.detection_signature,
                )

        return matched

    async def get_active_constraints(self) -> list[str]:
        """Get all constraint IDs required by active patterns."""
        constraints: set[str] = set()
        for pattern in self._patterns.values():
            if (
                pattern.status == PatternStatus.ACTIVE
                and pattern.required_constraint
            ):
                constraints.add(pattern.required_constraint)
        return sorted(constraints)

    async def get_stats(self) -> dict[str, Any]:
        """Get memory statistics."""
        active = sum(
            1 for p in self._patterns.values()
            if p.status == PatternStatus.ACTIVE
        )
        return {
            **self._stats,
            "active_patterns": active,
            "cwe_coverage": len(self._cwe_index),
            "severity_distribution": self._severity_distribution(),
        }

    def _severity_distribution(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for p in self._patterns.values():
            if p.status == PatternStatus.ACTIVE:
                counts[p.severity.value] = counts.get(p.severity.value, 0) + 1
        return counts

    async def prune_old(self, max_age_days: int = 90) -> int:
        """Archive patterns not seen in the specified time period."""
        cutoff = time.time() - (max_age_days * 86400)
        pruned = 0
        for pattern in self._patterns.values():
            if (
                pattern.status == PatternStatus.ACTIVE
                and pattern.last_seen < cutoff
                and pattern.severity not in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)
            ):
                pattern.status = PatternStatus.ARCHIVED
                pruned += 1
        return pruned
