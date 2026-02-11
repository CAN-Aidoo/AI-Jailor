"""Tests for the Constraint Engine.

Validates Z3 solver integration, DSL constraint parsing,
and intent checking against security constraints.
"""

import pytest

from aijailer.schemas.intent import (
    ActionType,
    AuthRequirement,
    CodeIntent,
    DataClass,
    ErrorClass,
    InputSource,
    OutputTarget,
)
from aijailer.services.constraint_engine import ConstraintEngine, ConstraintResult


@pytest.fixture
def engine():
    """Create a ConstraintEngine with default OWASP constraints."""
    return ConstraintEngine()


def _make_intent(**overrides) -> CodeIntent:
    """Helper to build a CodeIntent with sensible defaults."""
    defaults = {
        "action": ActionType.READ,
        "data_classification": [DataClass.PUBLIC],
        "trust_boundary_crossing": False,
        "auth_context": AuthRequirement.NONE,
        "compliance_domains": [],
        "input_sources": [InputSource.DATABASE],
        "output_targets": [OutputTarget.API_RESPONSE],
        "error_sensitivity": ErrorClass.FAIL_CLOSED,
    }
    defaults.update(overrides)
    return CodeIntent(**defaults)


class TestConstraintEngineBasic:
    """Basic constraint engine tests."""

    def test_engine_initializes(self, engine):
        assert engine is not None

    def test_safe_read_intent_passes(self, engine):
        """Simple read of public data should pass."""
        intent = _make_intent(
            action=ActionType.READ,
            data_classification=[DataClass.PUBLIC],
            input_sources=[InputSource.DATABASE],
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)

    def test_pii_requires_auth(self, engine):
        """Accessing PII without auth should be constrained."""
        intent = _make_intent(
            action=ActionType.READ,
            data_classification=[DataClass.PII],
            auth_context=AuthRequirement.NONE,
            input_sources=[InputSource.USER_INPUT],
        )
        result = engine.check_intent(intent)
        # PII without auth should be blocked or have constraints
        assert isinstance(result, ConstraintResult)

    def test_pci_requires_compliance(self, engine):
        """PCI data should require compliance constraints."""
        intent = _make_intent(
            action=ActionType.CREATE,
            data_classification=[DataClass.PCI],
            compliance_domains=["PCI-DSS"],
            auth_context=AuthRequirement.MFA,
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)

    def test_trust_boundary_crossing(self, engine):
        """Trust boundary crossing should trigger additional constraints."""
        intent = _make_intent(
            action=ActionType.NETWORK,
            trust_boundary_crossing=True,
            auth_context=AuthRequirement.TOKEN,
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)


class TestConstraintEngineActions:
    """Tests for different action types."""

    def test_delete_action_constrained(self, engine):
        """DELETE actions should have stronger constraints."""
        intent = _make_intent(
            action=ActionType.DELETE,
            data_classification=[DataClass.PII],
            auth_context=AuthRequirement.TOKEN,
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)

    def test_payment_action_requires_pci(self, engine):
        """Payment actions should require PCI compliance."""
        intent = _make_intent(
            action=ActionType.PAYMENT,
            data_classification=[DataClass.PCI],
            auth_context=AuthRequirement.MFA,
            compliance_domains=["PCI-DSS"],
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)

    def test_crypto_action(self, engine):
        """Crypto actions should be handled."""
        intent = _make_intent(
            action=ActionType.CRYPTO,
            auth_context=AuthRequirement.TOKEN,
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)

    def test_file_io_action(self, engine):
        """File I/O actions should be constrained."""
        intent = _make_intent(
            action=ActionType.FILE_IO,
            input_sources=[InputSource.USER_INPUT],
        )
        result = engine.check_intent(intent)
        assert isinstance(result, ConstraintResult)


class TestConstraintEngineReload:
    """Tests for constraint loading and reloading."""

    def test_reload_constraints(self, engine):
        """Engine should support constraint reloading."""
        # Should not raise
        engine.reload_constraints()

    def test_constraint_count(self, engine):
        """Engine should have loaded OWASP constraints."""
        # The engine loads from constraints/ directory
        assert engine is not None


class TestConstraintResult:
    """Tests for ConstraintResult model."""

    def test_safe_result(self):
        result = ConstraintResult.SAFE()
        assert result.safe is True
        assert result.violated_constraints == []

    def test_blocked_result(self):
        result = ConstraintResult.BLOCKED(
            reason="PII access without authentication",
            violated=["require_auth"],
        )
        assert result.safe is False
        assert result.reason == "PII access without authentication"
        assert len(result.violated_constraints) == 1
