import pytest

from aijailer.schemas.intent import (
    ActionType, AuthRequirement, CodeIntent, DataClass, ErrorClass, InputSource, OutputTarget)
from aijailer.services.certificate_generator import CertificateGenerator
from aijailer.services.execution_gate import ExecutionGate, Tier

INTENT = CodeIntent(action=ActionType.READ, data_classification=[DataClass.PUBLIC],
                    auth_context=AuthRequirement.NONE, input_sources=[InputSource.DATABASE],
                    output_targets=[OutputTarget.API_RESPONSE], error_sensitivity=ErrorClass.FAIL_CLOSED)
GOOD = "def add(a, b):\n    return a + b\n"
BAD = 'import os\nx = request.args["c"]\nos.system(x)\n'


@pytest.fixture
def certs():
    return CertificateGenerator(signing_key="gate-test-key-material-1234567890")


def issue(certs, code):
    return certs.generate(code=code, intent=INTENT, constraints_applied=[], components_used=[],
                          tenant_id="t")


def test_valid_certificate_gets_standard_tier(certs):
    d = ExecutionGate(certs).decide(GOOD, certificate=issue(certs, GOOD))
    assert (d.tier, d.basis) == (Tier.STANDARD, "certified")


def test_certificate_for_different_code_is_not_honoured(certs):
    d = ExecutionGate(certs).decide(BAD, certificate=issue(certs, GOOD))
    assert d.tier == Tier.MAXIMUM and any("certificate" in r for r in d.reasons)


def test_clean_uncertified_code_is_restricted(certs):
    assert ExecutionGate(certs).decide(GOOD).tier == Tier.RESTRICTED


def test_dangerous_code_gets_maximum_and_blocks_in_enforce(certs):
    assert not ExecutionGate(certs).decide(BAD).blocked
    d = ExecutionGate(certs, enforce=True).decide(BAD)
    assert d.tier == Tier.MAXIMUM and d.blocked


def test_unanalysable_language_is_never_trusted(certs):
    assert ExecutionGate(certs).decide("echo hi", language="bash").tier == Tier.MAXIMUM
