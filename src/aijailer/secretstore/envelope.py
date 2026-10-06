"""Envelope encryption with metadata-bound AAD.

The AAD binds a ciphertext to the exact row it belongs to: tenant, name, version, the hosts the
secret may be sent to, and its expiry. Moving a ciphertext to another tenant/name, or editing
``hosts``/``expires_at`` in the database (e.g. to redirect a credential to an attacker's host or to
resurrect an expired one), makes decryption fail closed instead of silently succeeding.
"""

import json
import os
import uuid
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from aijailer.secretstore.keys import (
    KEY_BYTES,
    NONCE_BYTES,
    IntegrityError,
    KeyProvider,
)

_VERSION_TAG = b"aijailer.secret.v1"


def build_aad(tenant_id: uuid.UUID, name: str, version: int, hosts: list[str],
              expires_at: float | None) -> bytes:
    return _VERSION_TAG + b"\x00" + json.dumps(
        {"t": str(tenant_id), "n": name, "v": version, "h": sorted(hosts), "e": expires_at},
        sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class Sealed:
    ciphertext: bytes
    nonce: bytes
    wrapped_dek: bytes
    key_id: str


def seal(plaintext: bytes, aad: bytes, provider: KeyProvider) -> Sealed:
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    key_id, wrapped = provider.wrap(dek, aad)
    return Sealed(ct, nonce, wrapped, key_id)


def open_sealed(s: Sealed, aad: bytes, provider: KeyProvider) -> bytes:
    dek = provider.unwrap(s.key_id, s.wrapped_dek, aad)
    if len(dek) != KEY_BYTES:
        raise IntegrityError("unwrapped key has wrong length")
    try:
        return AESGCM(dek).decrypt(s.nonce, s.ciphertext, aad)
    except InvalidTag:
        raise IntegrityError("secret failed authentication (tampered or mismatched metadata)") \
            from None


def rewrap(s: Sealed, aad: bytes, provider: KeyProvider) -> Sealed:
    """Re-wrap the data key under the provider's primary KEK. The value is never decrypted and
    the ciphertext/nonce are unchanged."""
    dek = provider.unwrap(s.key_id, s.wrapped_dek, aad)
    key_id, wrapped = provider.wrap(dek, aad)
    return Sealed(s.ciphertext, s.nonce, wrapped, key_id)
