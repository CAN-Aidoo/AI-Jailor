"""Peer attestations: the platform vouches 'this certificate belongs to cell X of tenant Y on link L'.

The hub learns each side's certificate over the connection of that cell's own proxy listener (the
cell's identity is the listener, never a claim in a message), then hands each side a DSSE-signed
statement about ITS PEER. A cell verifies it with the platform's public key (injected into its
environment by the platform) before trusting the peer's certificate as the sole trust anchor of the
end-to-end TLS session. in-toto + DSSE, like every other attestation in this codebase."""

import hashlib
import ssl
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aijailer.services.attestation import Signer, make_statement, sign_statement, verify_envelope

PREDICATE_TYPE = "https://aijailer.dev/attestation/peer-link/v1"
ROLES = ("initiator", "responder")
MAX_CERT_PEM = 8 * 1024
DEFAULT_TTL = 600.0
CLOCK_SKEW = 300.0


class PeerAttestationError(ValueError):
    """The attestation is not acceptable. Always fail closed."""


def cert_sha256(cert_pem: str) -> str:
    """sha256 of the DER encoding: the identity of a certificate."""
    if len(cert_pem) > MAX_CERT_PEM:
        raise PeerAttestationError("certificate too large")
    try:
        der = ssl.PEM_cert_to_DER_cert(cert_pem.strip() + "\n")
    except (ValueError, TypeError) as exc:
        raise PeerAttestationError("not a PEM certificate") from exc
    return hashlib.sha256(der).hexdigest()


@dataclass(frozen=True)
class Party:
    cell_id: str
    tenant_id: str
    cert_sha256: str


def make_attestation(signer: Signer, link_id: str, role: str, me: Party, peer: Party,
                     session_id: str, ttl: float = DEFAULT_TTL, now: float | None = None) -> dict:
    """Statement handed to ``me`` about ``peer`` (signed by the platform)."""
    if role not in ROLES:
        raise ValueError(role)
    now = time.time() if now is None else now
    pred = {
        "link_id": link_id, "role": role, "session_id": session_id,
        "self": {"cell_id": me.cell_id, "tenant_id": me.tenant_id, "cert_sha256": me.cert_sha256},
        "peer": {"cell_id": peer.cell_id, "tenant_id": peer.tenant_id,
                 "cert_sha256": peer.cert_sha256},
        "issued_at": now, "expires_at": now + ttl,
    }
    return sign_statement(
        make_statement(f"peer-link/{link_id}/{role}", me.cert_sha256, PREDICATE_TYPE, pred), signer)


def verify_attestation(envelope: dict, public_key: Ed25519PublicKey, *, link_id: str,
                       own_cert_pem: str, peer_cert_pem: str, now: float | None = None,
                       expect_role: str | None = None,
                       pin_peer_cert_sha256: str | None = None) -> dict:
    """What a cell must check before trusting ``peer_cert_pem``. Returns the predicate.

    Checks: platform signature; it is about THIS link; it names OUR certificate as 'self' (a hub
    cannot hand us someone else's attestation); the certificate we were given for the peer hashes
    to the attested peer hash (the PEM travels unsigned, the hash is what is signed); not expired
    (with clock-skew tolerance); optional role and out-of-band pin on the peer's certificate."""
    stmt = verify_envelope(envelope, public_key)
    if stmt is None or stmt.get("predicateType") != PREDICATE_TYPE:
        raise PeerAttestationError("attestation signature or type invalid")
    pred = stmt.get("predicate") or {}
    now = time.time() if now is None else now
    try:
        if pred["link_id"] != link_id:
            raise PeerAttestationError("attestation is for a different link")
        if pred["role"] not in ROLES or (expect_role and pred["role"] != expect_role):
            raise PeerAttestationError("unexpected role")
        if pred["self"]["cert_sha256"] != cert_sha256(own_cert_pem):
            raise PeerAttestationError("attestation does not name our certificate")
        peer_hash = cert_sha256(peer_cert_pem)
        if pred["peer"]["cert_sha256"] != peer_hash:
            raise PeerAttestationError("peer certificate does not match the attested hash")
        if pin_peer_cert_sha256 and pin_peer_cert_sha256.lower() != peer_hash:
            raise PeerAttestationError("peer certificate does not match the pinned hash")
        if not (pred["issued_at"] - CLOCK_SKEW <= now <= pred["expires_at"] + CLOCK_SKEW):
            raise PeerAttestationError("attestation expired or not yet valid")
    except (KeyError, TypeError) as exc:
        raise PeerAttestationError("malformed attestation") from exc
    return pred
