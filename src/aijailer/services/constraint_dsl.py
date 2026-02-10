"""Constraint DSL parser.

Parses YAML constraint files from the constraints/ directory into
internal ConstraintRule objects. Supports the FORBID_PATTERN,
REQUIRE_PATTERN, and REQUIRE_WRAPPER rule types from the spec.
"""

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


class RuleType(str, Enum):
    FORBID_PATTERN = "FORBID_PATTERN"
    REQUIRE_PATTERN = "REQUIRE_PATTERN"
    REQUIRE_WRAPPER = "REQUIRE_WRAPPER"


@dataclass
class ConstraintRule:
    """A single rule within a constraint definition."""
    rule_type: RuleType
    pattern: str = ""
    wrapper: str = ""
    on: str = ""
    message: str = ""


@dataclass
class ConstraintDefinition:
    """A parsed constraint definition from YAML."""
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    applies_when: dict = field(default_factory=dict)
    rules: list[ConstraintRule] = field(default_factory=list)
    source_file: str = ""


class ConstraintDSLParser:
    """Parses YAML constraint definitions into ConstraintDefinition objects."""

    def __init__(self, constraint_dir: str | None = None):
        if constraint_dir is None:
            # Default to project-root/constraints/
            project_root = Path(__file__).parent.parent.parent
            self.constraint_dir = project_root / "constraints"
        else:
            self.constraint_dir = Path(constraint_dir)

    def load_all(self) -> list[ConstraintDefinition]:
        """Load all constraint YAML files from the constraint directory."""
        constraints = []
        if not self.constraint_dir.exists():
            logger.warning("constraint_dir.not_found", path=str(self.constraint_dir))
            return constraints

        for yaml_file in self.constraint_dir.rglob("*.yaml"):
            try:
                constraint = self.parse_file(str(yaml_file))
                if constraint:
                    constraints.append(constraint)
            except Exception as e:
                logger.error(
                    "constraint.parse_error",
                    file=str(yaml_file),
                    error=str(e),
                )
        logger.info("constraints.loaded", count=len(constraints))
        return constraints

    def parse_file(self, filepath: str) -> ConstraintDefinition | None:
        """Parse a single YAML constraint file."""
        try:
            import yaml
        except ImportError:
            raise RuntimeError(
                "pyyaml package is required for constraint parsing. "
                "Install with: pip install pyyaml"
            )

        with open(filepath, "r") as f:
            data = yaml.safe_load(f)

        if not data or "constraint" not in data:
            return None

        c = data["constraint"]

        rules = []
        for rule_data in c.get("rules", []):
            rule = ConstraintRule(
                rule_type=RuleType(rule_data.get("type", "FORBID_PATTERN")),
                pattern=rule_data.get("pattern", ""),
                wrapper=rule_data.get("wrapper", ""),
                on=rule_data.get("on", ""),
                message=rule_data.get("message", ""),
            )
            rules.append(rule)

        return ConstraintDefinition(
            name=c.get("name", ""),
            severity=c.get("severity", "MEDIUM"),
            applies_when=c.get("applies_when", {}),
            rules=rules,
            source_file=filepath,
        )

    def matches_intent(
        self, constraint: ConstraintDefinition, intent_dict: dict
    ) -> bool:
        """Check if a constraint's applies_when conditions match an intent."""
        conditions = constraint.applies_when
        for key, expected_values in conditions.items():
            # Navigate dotted keys like "intent.action"
            parts = key.replace("intent.", "").split(".")
            actual = intent_dict
            for part in parts:
                if isinstance(actual, dict):
                    actual = actual.get(part)
                else:
                    actual = None
                    break

            if actual is None:
                return False

            # Check if actual value matches any expected value
            if isinstance(expected_values, list):
                if isinstance(actual, list):
                    if not any(v in actual for v in expected_values):
                        return False
                elif actual not in expected_values:
                    return False
            elif actual != expected_values:
                return False

        return True


# Singleton
_parser: ConstraintDSLParser | None = None


def get_constraint_dsl_parser(constraint_dir: str | None = None) -> ConstraintDSLParser:
    global _parser
    if _parser is None:
        _parser = ConstraintDSLParser(constraint_dir=constraint_dir)
    return _parser
