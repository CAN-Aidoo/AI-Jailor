"""Key-encryption-key providers.

A KeyProvider wraps/unwraps 32-byte data keys. Implementations for KMS/Vault only need these two
methods plus ``primary_id``; the store never sees KEK material. Wrapping binds ``aad`` so a wrapped
DEK cannot be replayed onto a different secret row.
"""

import base64
import binascii
import os
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12


class SecretStoreError(Exception):
    """Base class; messages never contain secret material."""


class KeyUnavailableError(SecretStoreError):
    """The key service could not be reached or refused (outage, throttling, IAM, disabled key).
    Treated as TRANSIENT: callers keep their previous state instead of concluding anything about
    the stored data."""


class KeyNotFoundError(SecretStoreError):
    """The row names a KEK this deployment does not know (retired before migration, or a
    tampered key id). PERMANENT for that row: it is skipped, other rows are unaffected."""


class IntegrityError(SecretStoreError):
    """Ciphertext, wrapped key or bound metadata failed authentication (tampering/corruption)."""


class KeyProvider(Protocol):
    """Async because real implementations call a network service (AWS KMS, Vault Transit).

    ``aad`` binds the wrapped key to its row; ``context`` is the human-readable part of that
    binding (tenant id, secret name) that a KMS can log and use in key-policy conditions.
    Both must be presented identically on unwrap."""

    async def primary_key_id(self) -> str: ...
    async def wrap(self, dek: bytes, aad: bytes, context: dict[str, str]) -> tuple[str, bytes]: ...
    async def unwrap(self, key_id: str, wrapped: bytes, aad: bytes,
                     context: dict[str, str]) -> bytes: ...
    def owns(self, key_id: str) -> bool: ...


class LocalKeyProvider:
    """KEKs held in process memory, loaded from configuration.

    Several keys can be configured at once so a new primary can be introduced while rows
    wrapped under the old one are still readable; ``SecretStore.rewrap_all`` then migrates them
    and the old key can be removed.
    """

    def __init__(self, keys: dict[str, bytes], primary_id: str) -> None:
        if not keys:
            raise SecretStoreError("no master keys configured")
        for kid, k in keys.items():
            if not kid or len(kid) > 64 or not kid.replace("-", "").replace("_", "").isalnum():
                raise SecretStoreError(f"invalid key id {kid!r}")
            if len(k) != KEY_BYTES:
                raise SecretStoreError(f"master key {kid!r} must be exactly {KEY_BYTES} bytes")
        if primary_id not in keys:
            raise SecretStoreError("primary key id is not among the configured keys")
        self._keys = {k: AESGCM(v) for k, v in keys.items()}
        self.primary_id = primary_id

    @classmethod
    def from_spec(cls, spec: str, primary_id: str = "") -> "LocalKeyProvider":
        """``id1:BASE64,id2:BASE64`` (32 raw bytes each, standard or urlsafe base64)."""
        keys: dict[str, bytes] = {}
        for item in filter(None, (p.strip() for p in spec.split(","))):
            kid, sep, b64 = item.partition(":")
            if not sep:
                raise SecretStoreError("master key spec must look like id:base64")
            try:
                raw = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
            except (binascii.Error, ValueError):
                raise SecretStoreError(f"master key {kid!r} is not valid base64") from None
            if kid in keys:
                raise SecretStoreError(f"duplicate key id {kid!r}")
            keys[kid] = raw
        if not primary_id:
            if len(keys) != 1:
                raise SecretStoreError("set SECRETS_PRIMARY_KEY_ID when several keys are configured")
            primary_id = next(iter(keys))
        return cls(keys, primary_id)

    @staticmethod
    def generate_key() -> str:
        """Helper for operators: a fresh base64 master key."""
        return base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode()

    async def primary_key_id(self) -> str:
        return self.primary_id

    def owns(self, key_id: str) -> bool:
        return key_id in self._keys

    async def wrap(self, dek: bytes, aad: bytes, context: dict[str, str] | None = None
                   ) -> tuple[str, bytes]:
        nonce = os.urandom(NONCE_BYTES)  # context is already part of the AAD
        return self.primary_id, nonce + self._keys[self.primary_id].encrypt(nonce, dek, aad)

    async def unwrap(self, key_id: str, wrapped: bytes, aad: bytes,
                     context: dict[str, str] | None = None) -> bytes:
        aead = self._keys.get(key_id)
        if aead is None:
            raise KeyNotFoundError(f"master key {key_id!r} is not configured")
        if len(wrapped) < NONCE_BYTES + 16:
            raise IntegrityError("wrapped key is truncated")
        try:
            return aead.decrypt(wrapped[:NONCE_BYTES], wrapped[NONCE_BYTES:], aad)
        except InvalidTag:
            raise IntegrityError("wrapped key failed authentication") from None


class ChainedKeyProvider:
    """New wraps go to ``primary``; unwraps are routed to whichever provider owns the row's key id.

    This is the migration path: keep the old (e.g. local) provider as a decrypt-only fallback,
    run ``SecretStore.rewrap_all`` to move every row to the primary, then drop the fallback."""

    def __init__(self, primary: KeyProvider, *fallbacks: KeyProvider) -> None:
        self._primary, self._all = primary, [primary, *fallbacks]

    async def primary_key_id(self) -> str:
        return await self._primary.primary_key_id()

    def owns(self, key_id: str) -> bool:
        return any(p.owns(key_id) for p in self._all)

    async def wrap(self, dek: bytes, aad: bytes, context: dict[str, str]) -> tuple[str, bytes]:
        return await self._primary.wrap(dek, aad, context)

    async def unwrap(self, key_id: str, wrapped: bytes, aad: bytes,
                     context: dict[str, str]) -> bytes:
        for p in self._all:
            if p.owns(key_id):
                return await p.unwrap(key_id, wrapped, aad, context)
        raise KeyNotFoundError(f"no configured key provider owns key {key_id!r}")

    async def check(self) -> None:
        for p in self._all:
            if hasattr(p, "check"):
                await p.check()
