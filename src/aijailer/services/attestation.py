"""Standards-based attestations: in-toto Statement v1 inside a DSSE envelope.

We deliberately do NOT invent a certificate format. in-toto + DSSE is what
SLSA, Sigstore and GitHub Artifact Attestations use, so certificates issued
here can be verified by standard tooling (given the public key) and later
moved to keyless Sigstore signing by swapping the Signer.
"""

import base64
import json
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Signer(Protocol):
    keyid: str

    def sign(self, data: bytes) -> bytes: ...


@dataclass
class Ed25519Signer:
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def keyid(self) -> str:
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        digest = hashes.Hash(hashes.SHA256())
        digest.update(raw)
        return digest.finalize().hex()[:16]

    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)

    @classmethod
    def generate(cls) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_secret(cls, secret: str | bytes) -> "Ed25519Signer":
        """Derive a key from configured secret material with HKDF (never raw hashing)."""
        material = secret.encode() if isinstance(secret, str) else secret
        seed = HKDF(hashes.SHA256(), 32, salt=None, info=b"aijailer-attestation-v1").derive(
            material
        )
        return cls(Ed25519PrivateKey.from_private_bytes(seed))


def make_statement(subject_name: str, sha256_hex: str, predicate_type: str,
                   predicate: dict) -> dict:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": subject_name, "digest": {"sha256": sha256_hex}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


def sign_statement(statement: dict, signer: Signer) -> dict:
    """Wrap a statement in a signed DSSE envelope."""
    payload = canonical_json(statement)
    sig = signer.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": signer.keyid, "sig": base64.b64encode(sig).decode()}],
    }


def verify_envelope(envelope: dict, public_key: Ed25519PublicKey) -> dict | None:
    """Return the statement if any signature verifies, else None."""
    try:
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            return None
        payload = base64.b64decode(envelope["payload"], validate=True)
        msg = pae(PAYLOAD_TYPE, payload)
        for s in envelope.get("signatures", []):
            try:
                public_key.verify(base64.b64decode(s["sig"], validate=True), msg)
                return json.loads(payload)
            except InvalidSignature:
                continue
    except (KeyError, ValueError, TypeError):
        return None
    return None
