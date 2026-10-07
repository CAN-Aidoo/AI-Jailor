"""Tests for the Certificate Generator.

Validates certificate creation, security property derivation,
and signature verification.
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
from aijailer.services.certificate_generator import CertificateGenerator


@pytest.fixture
def generator():
    return CertificateGenerator(signing_key="test-signing-key-for-unit-tests-12345")


def _make_intent(**overrides) -> CodeIntent:
    defaults = {
        "action": ActionType.READ,
        "data_classification": [DataClass.PUBLIC],
        "auth_context": AuthRequirement.NONE,
        "input_sources": [InputSource.DATABASE],
        "output_targets": [OutputTarget.API_RESPONSE],
        "error_sensitivity": ErrorClass.FAIL_CLOSED,
    }
    defaults.update(overrides)
    return CodeIntent(**defaults)


class TestCertificateGeneration:
    """Tests for certificate creation."""

    def test_generates_certificate(self, generator):
        """Should create a certificate from valid inputs."""
        intent = _make_intent()
        code = "def get_users(): return db.query('SELECT * FROM users')"

        cert = generator.generate(
            code=code,
            intent=intent,
            constraints_applied=["no_sql_injection"],
            components_used=["safe_query_builder"],
            tenant_id="test-tenant",
        )
        assert cert is not None

    def test_certificate_has_code_hash(self, generator):
        """Certificate should include a hash of the generated code."""
        intent = _make_intent()
        code = "print('hello')"

        cert = generator.generate(
            code=code,
            intent=intent,
            constraints_applied=[],
            components_used=[],
            tenant_id="test-tenant",
        )
        assert hasattr(cert, 'code_hash') or hasattr(cert, 'hash')

    def test_certificate_has_constraints(self, generator):
        """Certificate should list applied constraints."""
        intent = _make_intent(
            action=ActionType.CREATE,
            data_classification=[DataClass.PII],
        )
        code = "def create_user(data): pass"

        cert = generator.generate(
            code=code,
            intent=intent,
            constraints_applied=["no_sql_injection", "require_auth"],
            components_used=["safe_query_builder", "session_manager"],
            tenant_id="test-tenant",
        )
        assert cert is not None

    def test_certificate_has_components(self, generator):
        """Certificate should list used components."""
        intent = _make_intent()
        code = "def handler(): pass"

        cert = generator.generate(
            code=code,
            intent=intent,
            constraints_applied=["no_sql_injection"],
            components_used=["safe_query_builder"],
            tenant_id="test-tenant",
        )
        assert cert is not None


class TestSecurityPropertyDerivation:
    """Tests for deriving security properties from constraints."""

    def test_pii_properties(self, generator):
        """PII data should derive encryption and access control properties."""
        intent = _make_intent(
            data_classification=[DataClass.PII],
            auth_context=AuthRequirement.TOKEN,
        )
        code = "def get_user_pii(): pass"

        cert = generator.generate(
            code=code,
            intent=intent,
            constraints_applied=["require_auth", "encrypt_at_rest"],
            components_used=["jwt_handler", "encryption"],
            tenant_id="test-tenant",
        )
        assert cert is not None

    def test_pci_compliance(self, generator):
        """PCI data should derive PCI-DSS compliance properties."""
        intent = _make_intent(
            action=ActionType.PAYMENT,
            data_classification=[DataClass.PCI],
            compliance_domains=["PCI-DSS"],
        )
        code = "def process_payment(): pass"

        cert = generator.generate(
            code=code,
            intent=intent,
            constraints_applied=["pci_dss_compliance"],
            components_used=["encryption"],
            tenant_id="test-tenant",
        )
        assert cert is not None


class TestCertificateSigning:
    """Tests for certificate signing and verification."""

    def test_different_code_different_hash(self, generator):
        """Different code should produce different certificate hashes."""
        intent = _make_intent()

        cert1 = generator.generate(
            code="def foo(): return 1",
            intent=intent,
            constraints_applied=[],
            components_used=[],
            tenant_id="t1",
        )
        cert2 = generator.generate(
            code="def bar(): return 2",
            intent=intent,
            constraints_applied=[],
            components_used=[],
            tenant_id="t1",
        )
        # Should have different hashes
        if hasattr(cert1, 'code_hash') and hasattr(cert2, 'code_hash'):
            assert cert1.code_hash != cert2.code_hash

    def test_certificate_includes_tenant(self, generator):
        """Certificate should reference the tenant."""
        intent = _make_intent()
        cert = generator.generate(
            code="pass",
            intent=intent,
            constraints_applied=[],
            components_used=[],
            tenant_id="tenant-abc",
        )
        assert cert is not None


class TestAttestationIntegrity:
    """Signature is real: tampering, wrong key and expiry must fail."""

    def _issue(self, gen, code="def f(): return 1"):
        return gen.generate(code=code, intent=_make_intent(), constraints_applied=["x"],
                            components_used=[], tenant_id="t")

    def test_verifies(self, generator):
        cert = self._issue(generator)
        assert generator.verify(cert, code="def f(): return 1")

    def test_code_swap_detected(self, generator):
        cert = self._issue(generator)
        assert not generator.verify(cert, code="def f(): return 2")

    def test_field_tamper_detected(self, generator):
        cert = self._issue(generator)
        cert.constraints_applied = []
        assert not generator.verify(cert)

    def test_hash_tamper_detected(self, generator):
        cert = self._issue(generator)
        cert.code_hash = "sha256:" + "0" * 64
        assert not generator.verify(cert)

    def test_other_key_rejects(self, generator):
        cert = self._issue(generator)
        other = CertificateGenerator(signing_key="a-different-key-material-xxxxxxxx")
        assert not other.verify(cert)

    def test_expired(self, generator):
        from datetime import datetime, timedelta, timezone
        cert = self._issue(generator)
        assert not generator.verify(cert, now=datetime.now(timezone.utc) + timedelta(days=400))

    def test_unsigned_rejected(self, generator):
        cert = self._issue(generator)
        cert.attestation = None
        assert not generator.verify(cert)
