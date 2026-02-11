"""Immune Constraint Generator.

Auto-generates YAML constraint rules from analyzed vulnerabilities.
New constraints require human approval before being activated.
"""

import time
from dataclasses import dataclass, field
from typing import Any

import structlog
import yaml

from aijailer.immune.memory import AttackPattern, ThreatSeverity

logger = structlog.get_logger(__name__)


class ConstraintPriority(str):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class GeneratedConstraint:
    """A constraint rule auto-generated from a vulnerability pattern."""

    constraint_id: str
    name: str
    description: str
    yaml_content: str
    source_pattern_id: str
    source_cwe: str
    priority: str
    auto_approved: bool = False   # Only LOW severity can be auto-approved
    human_approved: bool = False
    created_at: float = field(default_factory=time.time)
    approved_at: float | None = None
    approved_by: str | None = None

    @property
    def is_active(self) -> bool:
        return self.auto_approved or self.human_approved


class ConstraintGenerator:
    """Generates YAML constraint rules from analyzed vulnerability patterns.

    When the analyzer detects a new vulnerability class, this generator
    creates a constraint rule that would prevent code with that
    vulnerability from passing the constraint engine.

    Safety: All generated constraints above LOW severity require
    human review before activation.
    """

    def __init__(self, auto_approve_low: bool = True) -> None:
        self._auto_approve_low = auto_approve_low
        self._generated: dict[str, GeneratedConstraint] = {}

    async def generate_from_pattern(
        self,
        pattern: AttackPattern,
    ) -> GeneratedConstraint:
        """Generate a constraint rule from an attack pattern.

        Builds a YAML constraint that the ConstraintEngine can load
        and enforce.
        """
        constraint_id = f"auto-{pattern.cwe_id.lower()}-{pattern.pattern_id[-8:]}"

        # Build the constraint YAML
        constraint_data = self._build_constraint_yaml(pattern, constraint_id)
        yaml_content = yaml.dump(constraint_data, default_flow_style=False, sort_keys=False)

        # Auto-approve only LOW severity patterns
        auto_approved = (
            self._auto_approve_low
            and pattern.severity == ThreatSeverity.LOW
        )

        constraint = GeneratedConstraint(
            constraint_id=constraint_id,
            name=f"Auto: Prevent {pattern.cwe_id}",
            description=(
                f"Automatically generated constraint to prevent "
                f"{pattern.description} ({pattern.cwe_id})"
            ),
            yaml_content=yaml_content,
            source_pattern_id=pattern.pattern_id,
            source_cwe=pattern.cwe_id,
            priority=pattern.severity.value,
            auto_approved=auto_approved,
        )

        self._generated[constraint_id] = constraint

        logger.info(
            "constraint_gen.created",
            constraint_id=constraint_id,
            cwe=pattern.cwe_id,
            auto_approved=auto_approved,
        )

        return constraint

    async def generate_batch(
        self, patterns: list[AttackPattern]
    ) -> list[GeneratedConstraint]:
        """Generate constraints for multiple patterns."""
        constraints: list[GeneratedConstraint] = []
        for pattern in patterns:
            # Skip if we already have a constraint from this pattern
            existing = self._find_by_pattern(pattern.pattern_id)
            if existing:
                constraints.append(existing)
                continue

            constraint = await self.generate_from_pattern(pattern)
            constraints.append(constraint)
        return constraints

    async def approve(
        self,
        constraint_id: str,
        approved_by: str,
    ) -> GeneratedConstraint | None:
        """Human approval of a generated constraint."""
        constraint = self._generated.get(constraint_id)
        if constraint is None:
            return None

        constraint.human_approved = True
        constraint.approved_at = time.time()
        constraint.approved_by = approved_by

        logger.info(
            "constraint_gen.approved",
            constraint_id=constraint_id,
            approved_by=approved_by,
        )
        return constraint

    async def reject(
        self,
        constraint_id: str,
        reason: str = "",
    ) -> bool:
        """Reject a generated constraint."""
        constraint = self._generated.get(constraint_id)
        if constraint is None:
            return False

        constraint.auto_approved = False
        constraint.human_approved = False
        constraint.approved_by = None

        logger.info(
            "constraint_gen.rejected",
            constraint_id=constraint_id,
            reason=reason,
        )
        return True

    async def get_pending(self) -> list[GeneratedConstraint]:
        """Get constraints awaiting human approval."""
        return [
            c for c in self._generated.values()
            if not c.is_active
        ]

    async def get_active(self) -> list[GeneratedConstraint]:
        """Get all active (approved) constraints."""
        return [
            c for c in self._generated.values()
            if c.is_active
        ]

    async def export_yaml(self, constraint_id: str) -> str | None:
        """Export a constraint's YAML for loading into the constraint engine."""
        constraint = self._generated.get(constraint_id)
        if constraint is None or not constraint.is_active:
            return None
        return constraint.yaml_content

    def _build_constraint_yaml(
        self,
        pattern: AttackPattern,
        constraint_id: str,
    ) -> dict[str, Any]:
        """Build a YAML-serializable constraint dict."""
        # Map severity to enforcement level
        enforcement = "block" if pattern.severity in (
            ThreatSeverity.CRITICAL, ThreatSeverity.HIGH
        ) else "warn"

        constraint: dict[str, Any] = {
            "id": constraint_id,
            "name": f"Prevent {pattern.cwe_id}: {pattern.description}",
            "version": "1.0.0",
            "source": "immune_system",
            "cwe": pattern.cwe_id,
            "severity": pattern.severity.value,
            "enforcement": enforcement,
            "description": (
                f"Auto-generated from attack pattern {pattern.pattern_id}. "
                f"{pattern.description}"
            ),
            "rules": [
                {
                    "type": "deny_pattern",
                    "pattern": pattern.detection_signature,
                    "message": f"Code matches known {pattern.cwe_id} vulnerability pattern",
                }
            ],
        }

        if pattern.required_component:
            constraint["required_components"] = [pattern.required_component]

        if pattern.required_constraint:
            constraint["depends_on"] = [pattern.required_constraint]

        return constraint

    def _find_by_pattern(self, pattern_id: str) -> GeneratedConstraint | None:
        """Find a constraint generated from a specific pattern."""
        for c in self._generated.values():
            if c.source_pattern_id == pattern_id:
                return c
        return None
