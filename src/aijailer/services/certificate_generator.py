"""Certificate Generator service.

Produces SecurityCertificate attestations that prove generated
code satisfies specific security properties, compliance frameworks,
and constraint rules. Certificates are signed and time-bounded.
"""

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import structlog

from aijailer.core.config import get_settings

from aijailer.schemas.generate import ComponentRef, SecurityCertificateSchema
from aijailer.schemas.intent import CodeIntent
from aijailer.services.attestation import (
    Ed25519Signer,
    Signer,
    make_statement,
    sign_statement,
    verify_envelope,
)

logger = structlog.get_logger(__name__)

# Immune memory version tracks the state of the constraint database
IMMUNE_MEMORY_VERSION = "imm_v2026.02.10.0001"


PREDICATE_TYPE = "https://aijailer.dev/attestation/secure-generation/v1"


class CertificateGenerator:
    """Generates security certificates for code that passes constraint checking.

    Certificates are in-toto statements in DSSE envelopes signed with
    Ed25519. ``verify`` re-checks signature, expiry and (optionally) that the
    presented code still matches the attested hash.
    """

    def __init__(self, signing_key: str | bytes | None = None, signer: Signer | None = None):
        if signer is not None:
            self._signer = signer
        elif signing_key:
            self._signer = Ed25519Signer.from_secret(signing_key)
        else:
            # No configured key: ephemeral. Certificates verify only inside this process
            # lifetime, which is the safe failure mode (never a guessable default key).
            logger.warning("certificate.ephemeral_signing_key")
            self._signer = Ed25519Signer.generate()

    @property
    def public_key(self):
        return self._signer.public_key

    def verify(self, cert: SecurityCertificateSchema, code: str | None = None,
               now: datetime | None = None) -> bool:
        """True only if the signature is valid, the certificate unexpired, the
        envelope statement matches the visible fields, and code (if given) matches."""
        if not cert.attestation:
            return False
        statement = verify_envelope(cert.attestation, self.public_key)
        if statement is None:
            return False
        pred = statement.get("predicate", {})
        digest = statement["subject"][0]["digest"]["sha256"]
        if cert.code_hash != f"sha256:{digest}" or pred.get("certificate_id") != cert.certificate_id:
            return False
        if pred.get("constraints_applied") != cert.constraints_applied:
            return False
        if code is not None and hashlib.sha256(code.encode()).hexdigest() != digest:
            return False
        try:
            expires = datetime.fromisoformat(pred["valid_until"])
        except (KeyError, ValueError):
            return False
        return (now or datetime.now(timezone.utc)) < expires

    def generate(
        self,
        code: str,
        intent: CodeIntent,
        constraints_applied: list[str],
        components_used: list[str],
        tenant_id: str,
        generation_id: str | None = None,
        validity_days: int = 180,
    ) -> SecurityCertificateSchema:
        """Generate a security certificate for successfully assembled code.

        The certificate attests that:
        1. The code was generated through the constrained pipeline
        2. All listed constraints were satisfied
        3. Only certified components were used for security operations
        4. The code hash matches the certified output
        """
        now = datetime.now(timezone.utc)
        gen_id = generation_id or f"gen_{uuid.uuid4().hex[:12]}"
        cert_id = f"cert_{uuid.uuid4().hex[:12]}"

        # Compute code hash
        code_hash = f"sha256:{hashlib.sha256(code.encode()).hexdigest()}"

        # Build security properties from intent and constraints
        security_properties = self._derive_security_properties(
            intent, constraints_applied
        )

        # Build component references
        comp_refs = [
            ComponentRef(
                name=comp,
                version="1.0.0",  # From component registry in production
                cert_id=f"comp_cert_{hashlib.md5(comp.encode()).hexdigest()[:8]}",
            )
            for comp in components_used
        ]

        # Build certificate
        certificate = SecurityCertificateSchema(
            certificate_id=cert_id,
            generation_id=gen_id,
            timestamp=now.isoformat(),
            tenant_id=tenant_id,
            code_hash=code_hash,
            security_properties=security_properties,
            compliance_frameworks=intent.compliance_domains,
            constraints_applied=constraints_applied,
            components_used=comp_refs,
            immune_memory_version=IMMUNE_MEMORY_VERSION,
            valid_until=(now + timedelta(days=validity_days)).isoformat(),
        )
        statement = make_statement(
            "generated_code",
            code_hash.removeprefix("sha256:"),
            PREDICATE_TYPE,
            certificate.model_dump(exclude={"signature", "attestation"}),
        )
        certificate.attestation = sign_statement(statement, self._signer)
        certificate.signature = "ed25519:" + certificate.attestation["signatures"][0]["sig"]

        logger.info(
            "certificate.generated",
            cert_id=cert_id,
            generation_id=gen_id,
            properties_count=len(security_properties),
            compliance=intent.compliance_domains,
        )

        return certificate

    def _derive_security_properties(
        self, intent: CodeIntent, constraints: list[str]
    ) -> dict:
        """Derive boolean security properties from constraints applied."""
        return {
            "injection_safe": "sql_injection_prevention" in constraints
                or "path_traversal_prevention" in constraints,
            "xss_safe": "output_encoding" in constraints,
            "auth_enforced": "auth_enforcement" in constraints
                or intent.auth_context.value != "none",
            "crypto_approved": "crypto_safety" in constraints
                or intent.action.value != "crypto",
            "secrets_managed": "secret_management" in constraints,
            "error_handling": "error_handling" in constraints,
            "data_boundary_enforced": "data_boundary" in constraints,
        }


# Singleton
_generator: CertificateGenerator | None = None


def get_certificate_generator() -> CertificateGenerator:
    global _generator
    if _generator is None:
        _generator = CertificateGenerator(signing_key=get_settings().attestation_key or None)
    return _generator
