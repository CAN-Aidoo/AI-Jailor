"""AWS KMS key provider: the KEK never leaves KMS.

We do not implement KMS. Each secret's data key (DEK) is wrapped with ``kms:Encrypt`` under a
customer-managed key and unwrapped with ``kms:Decrypt``; AWS holds the key material (HSM-backed),
rotates it, logs every use in CloudTrail and enforces IAM/key policy. The IAM principal needs only
``kms:Encrypt``, ``kms:Decrypt`` and ``kms:DescribeKey`` on the key.

Properties (each tested):
* The binding AAD is sent as KMS *encryption context* (a SHA-256 of it, plus readable tenant/name):
  KMS authenticates it, so a wrapped DEK cannot be replayed onto another row, and key policies can
  restrict by ``kms:EncryptionContext:tenant_id``.
* Decrypt always names the key (``KeyId``) and the response key is verified, and only key ARNs we
  were configured with are accepted, so a tampered ``key_id`` cannot point us at another key.
* boto3 is synchronous: every call runs in a worker thread, never on the event loop.
* Unwrapped DEKs are cached briefly (bounded, TTL) so steady-state refreshes do not hit KMS;
  the cache key includes the wrapped key and the AAD, so any change of either misses.
* Errors never contain key material or plaintext. Outages/throttling/access problems become
  ``KeyUnavailableError`` (transient, callers keep prior state); authentication failures become
  ``IntegrityError`` (permanent for that row).
"""

import asyncio
import hashlib
import os
import time
from collections import OrderedDict

from aijailer.secretstore.keys import (
    KEY_BYTES,
    IntegrityError,
    KeyNotFoundError,
    KeyUnavailableError,
)

_INTEGRITY_CODES = {"InvalidCiphertextException", "IncorrectKeyException"}
_ARN_PREFIX = "arn:"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class AwsKmsKeyProvider:
    def __init__(self, key_id: str, allowed_key_ids: tuple[str, ...] = (), region: str | None = None,
                 endpoint_url: str | None = None, cache_ttl: float = 300.0, cache_size: int = 1024,
                 client=None, clock=time.monotonic) -> None:
        if not key_id:
            raise ValueError("a KMS key id, ARN or alias is required")
        self._configured = key_id
        self._extra_allowed = {k for k in allowed_key_ids if k}
        self._ttl, self._size, self._clock = cache_ttl, cache_size, clock
        self._cache: OrderedDict[tuple, tuple[bytes, float]] = OrderedDict()
        self._primary_arn: str | None = None
        self._client = client or self._make_client(region, endpoint_url)

    @staticmethod
    def _make_client(region, endpoint_url):
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            raise KeyUnavailableError(
                "AWS KMS support needs boto3: pip install 'aijailer[kms]'") from None
        return boto3.client(
            "kms", region_name=region, endpoint_url=endpoint_url,
            config=Config(retries={"max_attempts": 3, "mode": "standard"},
                          connect_timeout=3, read_timeout=5))

    # ------------------------------------------------------------------ plumbing
    async def _call(self, op: str, **kwargs):
        """Run one KMS API call off the event loop; map failures without leaking payloads."""
        try:
            return await asyncio.to_thread(getattr(self._client, op), **kwargs)
        except Exception as exc:  # botocore ClientError / BotoCoreError / timeouts
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in _INTEGRITY_CODES:
                raise IntegrityError("KMS rejected the wrapped key (does not match its binding)"
                                     ) from None
            raise KeyUnavailableError(
                f"KMS {op} failed: {code or type(exc).__name__}") from None

    @staticmethod
    def _ctx(aad: bytes, context: dict[str, str]) -> dict[str, str]:
        return {**context, "aijailer:aad-sha256": _sha(aad)}

    def owns(self, key_id: str) -> bool:
        return key_id.startswith(_ARN_PREFIX) and ":kms:" in key_id

    async def primary_key_id(self) -> str:
        """The ARN of the key new wraps use (an alias is resolved once, then pinned)."""
        if self._primary_arn is None:
            meta = (await self._call("describe_key", KeyId=self._configured))["KeyMetadata"]
            self._primary_arn = meta["Arn"]
        return self._primary_arn

    async def _allowed(self) -> set[str]:
        return {await self.primary_key_id(), *self._extra_allowed}

    # --------------------------------------------------------------------- wrap
    async def wrap(self, dek: bytes, aad: bytes, context: dict[str, str]) -> tuple[str, bytes]:
        primary = await self.primary_key_id()
        r = await self._call("encrypt", KeyId=primary, Plaintext=dek,
                             EncryptionContext=self._ctx(aad, context),
                             EncryptionAlgorithm="SYMMETRIC_DEFAULT")
        if r.get("KeyId") != primary:
            raise IntegrityError("KMS wrapped the key under an unexpected key")
        return primary, bytes(r["CiphertextBlob"])

    # ------------------------------------------------------------------- unwrap
    def _cache_get(self, k: tuple) -> bytes | None:
        hit = self._cache.get(k)
        if hit is None:
            return None
        dek, expires = hit
        if self._clock() >= expires:
            del self._cache[k]
            return None
        self._cache.move_to_end(k)
        return dek

    def _cache_put(self, k: tuple, dek: bytes) -> None:
        if self._ttl <= 0 or self._size <= 0:
            return
        self._cache[k] = (dek, self._clock() + self._ttl)
        self._cache.move_to_end(k)
        while len(self._cache) > self._size:
            self._cache.popitem(last=False)

    async def unwrap(self, key_id: str, wrapped: bytes, aad: bytes,
                     context: dict[str, str]) -> bytes:
        if key_id not in await self._allowed():
            raise KeyNotFoundError("row names a KMS key this deployment does not trust")
        ck = (key_id, _sha(wrapped), _sha(aad), _sha(repr(sorted(context.items())).encode()))
        cached = self._cache_get(ck)
        if cached is not None:
            return cached
        r = await self._call("decrypt", CiphertextBlob=wrapped, KeyId=key_id,
                             EncryptionContext=self._ctx(aad, context),
                             EncryptionAlgorithm="SYMMETRIC_DEFAULT")
        if r.get("KeyId") != key_id:
            raise IntegrityError("KMS unwrapped the key under an unexpected key")
        dek = bytes(r["Plaintext"])
        if len(dek) != KEY_BYTES:
            raise IntegrityError("unwrapped key has wrong length")
        self._cache_put(ck, dek)
        return dek

    def clear_cache(self) -> None:
        self._cache.clear()

    # -------------------------------------------------------------- readiness
    async def check(self) -> None:
        """Startup/health check: the key exists, is enabled and symmetric, and this principal can
        really Encrypt and Decrypt with it (catches missing IAM permissions early)."""
        meta = (await self._call("describe_key", KeyId=self._configured))["KeyMetadata"]
        if meta.get("KeyState") != "Enabled":
            raise KeyUnavailableError(f"KMS key is {meta.get('KeyState')}, not Enabled")
        # (absent fields are tolerated: the Encrypt/Decrypt probe below is the real test)
        if meta.get("KeyUsage") not in (None, "ENCRYPT_DECRYPT") or meta.get("KeySpec") not in (
                None, "SYMMETRIC_DEFAULT"):
            raise KeyUnavailableError("KMS key must be a symmetric ENCRYPT_DECRYPT key")
        probe, ctx = os.urandom(KEY_BYTES), {"purpose": "aijailer-healthcheck"}
        key_id, wrapped = await self.wrap(probe, b"healthcheck", ctx)
        if await self.unwrap(key_id, wrapped, b"healthcheck", ctx) != probe:
            raise IntegrityError("KMS round trip returned different data")
