"""Verify-then-jail: choose a containment tier for code before it runs.

Static analysis is undecidable in general (Rice's theorem), so verification
here NEVER substitutes for isolation: every cell is a microVM regardless.
The gate only decides *how tightly* to contain the code:

  certified   valid Ed25519/DSSE attestation whose hash matches this exact code
              -> standard tier (still jailed, egress still brokered)
  verified    no certificate, but verifier + dataflow taint find nothing
              -> restricted tier
  suspicious  verifier/taint findings, or code we cannot analyse (non-Python)
              -> maximum containment (no network, read-only FS), or blocked
              when the gate runs in ``enforce`` mode and findings are errors
"""

from dataclasses import dataclass, field
from enum import IntEnum

from aijailer.schemas.generate import SecurityCertificateSchema
from aijailer.services.certificate_generator import CertificateGenerator
from aijailer.services.formal_verifier import FormalVerifier, VerificationStatus
from aijailer.services.taint_tracker import TaintTracker


class Tier(IntEnum):
    """Matches the SECURITY_MODEL policy levels (higher = tighter)."""
    STANDARD = 2
    RESTRICTED = 3
    MAXIMUM = 4


@dataclass
class GateDecision:
    tier: Tier
    basis: str                      # certified | verified | suspicious | unanalysable
    blocked: bool = False
    reasons: list[str] = field(default_factory=list)


class ExecutionGate:
    def __init__(self, certs: CertificateGenerator, enforce: bool = False) -> None:
        self._certs = certs
        self._enforce = enforce
        self._verifier = FormalVerifier()
        self._taint = TaintTracker()

    def decide(self, code: str, language: str = "python",
               certificate: SecurityCertificateSchema | None = None) -> GateDecision:
        if certificate is not None and self._certs.verify(certificate, code=code):
            return GateDecision(Tier.STANDARD, "certified")
        reasons = []
        if certificate is not None:
            reasons.append("certificate invalid, expired, or does not match this code")

        if language != "python":
            return GateDecision(Tier.MAXIMUM, "unanalysable",
                                reasons=[*reasons, f"no analyzer for '{language}'"])

        result = self._verifier.verify(code, language=language)
        taint = self._taint.analyze(code)
        reasons += [f"{f.rule_id}: {f.message}" for f in result.errors]
        reasons += [v.message for v in taint.violations]
        has_errors = result.status == VerificationStatus.FAIL or not taint.safe
        if has_errors:
            return GateDecision(Tier.MAXIMUM, "suspicious", blocked=self._enforce, reasons=reasons)
        return GateDecision(Tier.RESTRICTED, "verified", reasons=reasons)
