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


def context_for(tenant_id: uuid.UUID, name: str) -> dict[str, str]:
    """The readable part of the binding, for KMS encryption context / audit / key policies."""
    return {"tenant_id": str(tenant_id), "secret_name": name}


async def seal(plaintext: bytes, aad: bytes, provider: KeyProvider,
               context: dict[str, str] | None = None) -> Sealed:
    dek = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    key_id, wrapped = await provider.wrap(dek, aad, context or {})
    return Sealed(ct, nonce, wrapped, key_id)


async def open_sealed(s: Sealed, aad: bytes, provider: KeyProvider,
                      context: dict[str, str] | None = None) -> bytes:
    dek = await provider.unwrap(s.key_id, s.wrapped_dek, aad, context or {})
    if len(dek) != KEY_BYTES:
        raise IntegrityError("unwrapped key has wrong length")
    try:
        return AESGCM(dek).decrypt(s.nonce, s.ciphertext, aad)
    except InvalidTag:
        raise IntegrityError("secret failed authentication (tampered or mismatched metadata)") \
            from None


async def rewrap(s: Sealed, aad: bytes, provider: KeyProvider,
                 context: dict[str, str] | None = None) -> Sealed:
    """Re-wrap the data key under the provider's primary KEK. The value is never decrypted and
    the ciphertext/nonce are unchanged."""
    dek = await provider.unwrap(s.key_id, s.wrapped_dek, aad, context or {})
    key_id, wrapped = await provider.wrap(dek, aad, context or {})
    return Sealed(s.ciphertext, s.nonce, wrapped, key_id)
