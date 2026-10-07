"""SecretStore: CRUD + rotation over envelope-encrypted tenant secrets.

Write-only by construction: nothing here returns a stored value to API callers. The only path that
decrypts is ``resolve`` (used by the egress broker's secret provider), and it returns values only as
``SecretBinding`` objects that live in the broker's memory.
"""

import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from aijailer.agentsec.egress import SecretBinding
from aijailer.models.audit import EventType, Severity
from aijailer.models.tenant_secret import TenantSecret
from aijailer.secretstore.envelope import (
    Sealed,
    build_aad,
    context_for,
    open_sealed,
    rewrap,
    seal,
)
from aijailer.secretstore.keys import (
    IntegrityError,
    KeyNotFoundError,
    KeyProvider,
    SecretStoreError,
)
from aijailer.secretstore.validation import (
    validate_hosts,
    validate_name,
    validate_value,
)

logger = structlog.get_logger(__name__)

MAX_SECRETS_PER_TENANT = 100
NIL = uuid.UUID(int=0)  # audit "cell" for events that are not about a cell


class NotFoundError(SecretStoreError):
    pass


class ConflictError(SecretStoreError):
    pass


class LimitError(SecretStoreError):
    pass


@dataclass(frozen=True)
class SecretMeta:
    """Everything about a secret EXCEPT its value."""

    name: str
    version: int
    hosts: list[str]
    expires_at: datetime | None
    key_id: str
    created_at: datetime | None
    updated_at: datetime | None
    rotated_at: datetime | None


def _epoch(dt: datetime | None) -> float | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return round(dt.timestamp(), 3)


def _meta(r: TenantSecret) -> SecretMeta:
    exp = datetime.fromtimestamp(r.expires_at_epoch, UTC) if r.expires_at_epoch else None
    return SecretMeta(r.name, r.version, list(r.hosts), exp, r.key_id, r.created_at,
                      r.updated_at, r.rotated_at)


def _aad(r: TenantSecret) -> bytes:
    return build_aad(r.tenant_id, r.name, r.version, list(r.hosts), r.expires_at_epoch)


def _sealed(r: TenantSecret) -> Sealed:
    return Sealed(r.ciphertext, r.nonce, r.wrapped_dek, r.key_id)


class SecretStore:
    def __init__(self, db: AsyncSession, provider: KeyProvider, audit=None,
                 on_change: Callable[[uuid.UUID], Awaitable[None]] | None = None) -> None:
        self._db, self._kp, self._audit, self._on_change = db, provider, audit, on_change

    async def _event(self, tenant_id, action: str, name: str, actor: uuid.UUID | None,
                     **extra) -> None:
        if self._audit is not None:  # NEVER include values; names and metadata only
            await self._audit.record_event(
                tenant_id=tenant_id, cell_id=NIL, event_type=EventType.SECRET,
                severity=Severity.INFO,
                details={"action": action, "name": name, "actor": str(actor) if actor else None,
                         **extra})

    async def _changed(self, tenant_id: uuid.UUID) -> None:
        if self._on_change is not None:
            try:  # propagation failure must not roll back the write, but must be loud
                await self._on_change(tenant_id)
            except Exception:
                logger.exception("secrets.change_propagation_failed", tenant_id=str(tenant_id))

    async def _get_row(self, tenant_id: uuid.UUID, name: str) -> TenantSecret:
        row = (await self._db.execute(select(TenantSecret).where(
            TenantSecret.tenant_id == tenant_id, TenantSecret.name == name))).scalar_one_or_none()
        if row is None:
            raise NotFoundError("secret not found")
        return row

    # ------------------------------------------------------------------ writes
    async def create(self, tenant_id: uuid.UUID, name: str, value: str, hosts: list[str],
                     expires_at: datetime | None = None, actor: uuid.UUID | None = None
                     ) -> SecretMeta:
        name = validate_name(name)
        raw = validate_value(value)
        hosts = validate_hosts(hosts)
        exp = self._check_expiry(expires_at)
        count = (await self._db.execute(select(func.count()).select_from(TenantSecret).where(
            TenantSecret.tenant_id == tenant_id))).scalar_one()
        if count >= MAX_SECRETS_PER_TENANT:
            raise LimitError(f"at most {MAX_SECRETS_PER_TENANT} secrets per tenant")
        exists = (await self._db.execute(select(TenantSecret.id).where(
            TenantSecret.tenant_id == tenant_id, TenantSecret.name == name))).first()
        if exists:
            raise ConflictError("a secret with this name already exists (rotate it instead)")
        s = await seal(raw, build_aad(tenant_id, name, 1, hosts, exp), self._kp,
                       context_for(tenant_id, name))
        row = TenantSecret(tenant_id=tenant_id, name=name, version=1, hosts=hosts,
                           expires_at_epoch=exp, ciphertext=s.ciphertext, nonce=s.nonce,
                           wrapped_dek=s.wrapped_dek, key_id=s.key_id, created_by=actor)
        self._db.add(row)
        await self._db.flush()
        await self._event(tenant_id, "created", name, actor, version=1, hosts=hosts)
        await self._db.commit()
        await self._changed(tenant_id)
        return _meta(row)

    async def update(self, tenant_id: uuid.UUID, name: str, value: str | None = None,
                     hosts: list[str] | None = None, expires_at: datetime | None = None,
                     clear_expiry: bool = False, actor: uuid.UUID | None = None) -> SecretMeta:
        """Rotate the value and/or change bindings. Any change re-seals under a new version,
        so ciphertext and metadata stay bound together."""
        row = await self._get_row(tenant_id, name)
        if value is None and hosts is None and expires_at is None and not clear_expiry:
            raise SecretStoreError("nothing to update")
        old_aad = _aad(row)
        raw = validate_value(value) if value is not None else await open_sealed(
            _sealed(row), old_aad, self._kp, context_for(tenant_id, name))
        new_hosts = validate_hosts(hosts) if hosts is not None else list(row.hosts)
        new_exp = row.expires_at_epoch
        if clear_expiry:
            new_exp = None
        if expires_at is not None:
            new_exp = self._check_expiry(expires_at)
        version = row.version + 1
        s = await seal(raw, build_aad(tenant_id, name, version, new_hosts, new_exp), self._kp,
                       context_for(tenant_id, name))
        row.version, row.hosts, row.expires_at_epoch = version, new_hosts, new_exp
        row.ciphertext, row.nonce, row.wrapped_dek, row.key_id = (
            s.ciphertext, s.nonce, s.wrapped_dek, s.key_id)
        if value is not None:
            row.rotated_at = datetime.now(UTC)
        await self._event(tenant_id, "rotated" if value is not None else "updated", name, actor,
                          version=version, hosts=new_hosts)
        await self._db.commit()
        await self._db.refresh(row)   # server-side onupdate columns (updated_at) must be loaded
        await self._changed(tenant_id)
        return _meta(row)

    async def delete(self, tenant_id: uuid.UUID, name: str, actor: uuid.UUID | None = None) -> None:
        row = await self._get_row(tenant_id, name)
        await self._db.delete(row)  # hard delete: the ciphertext must not outlive the secret
        await self._event(tenant_id, "deleted", name, actor)
        await self._db.commit()
        await self._changed(tenant_id)

    @staticmethod
    def _check_expiry(expires_at: datetime | None) -> float | None:
        ep = _epoch(expires_at)
        if ep is not None and ep <= time.time():
            raise SecretStoreError("expires_at must be in the future")
        return ep

    # ------------------------------------------------------------------- reads
    async def get_meta(self, tenant_id: uuid.UUID, name: str) -> SecretMeta:
        return _meta(await self._get_row(tenant_id, name))

    async def list_meta(self, tenant_id: uuid.UUID) -> list[SecretMeta]:
        rows = (await self._db.execute(select(TenantSecret).where(
            TenantSecret.tenant_id == tenant_id).order_by(TenantSecret.name))).scalars()
        return [_meta(r) for r in rows]

    async def resolve(self, tenant_id: uuid.UUID, now: float | None = None
                      ) -> list[SecretBinding]:
        """Decrypt this tenant's usable secrets for the egress broker. Expired secrets are
        omitted; a row that fails authentication (tampered metadata/ciphertext) is skipped and
        reported, never used. Values are returned only inside SecretBinding."""
        now = time.time() if now is None else now
        rows = (await self._db.execute(select(TenantSecret).where(
            TenantSecret.tenant_id == tenant_id))).scalars().all()
        out: list[SecretBinding] = []
        for r in rows:
            if r.expires_at_epoch is not None and r.expires_at_epoch <= now:
                continue
            try:
                value = (await open_sealed(_sealed(r), _aad(r), self._kp,
                                           context_for(r.tenant_id, r.name))).decode("utf-8")
            except (IntegrityError, KeyNotFoundError) as exc:
                # Permanent for THIS row (tampered, or wrapped under a key we no longer have):
                # never used, reported, and the other rows are unaffected.
                kind = "integrity_failure" if isinstance(exc, IntegrityError) else "key_missing"
                logger.error("secrets.unusable", tenant_id=str(tenant_id), name=r.name,
                             kind=kind, error=str(exc))
                await self._event(tenant_id, kind, r.name, None, error=str(exc))
                continue
            # KeyUnavailableError (key service outage) is deliberately NOT caught: it says nothing
            # about the data, so it must not look like "no secrets" to the caller, which keeps its
            # previous state (periodic refresh) or fails closed (change-triggered refresh).
            out.append(SecretBinding(r.name, value, tuple(r.hosts), not_after=r.expires_at_epoch))
        return out

    # ---------------------------------------------------------- KEK rotation
    async def rewrap_all(self, batch: int = 200) -> dict:
        """Migrate every row's data key to the primary KEK without decrypting any value.
        Run after introducing a new primary; retire the old key once ``remaining`` is 0."""
        done = failed = 0
        primary = await self._kp.primary_key_id()
        rows = (await self._db.execute(select(TenantSecret).where(
            TenantSecret.key_id != primary).limit(batch))).scalars().all()
        for r in rows:
            try:
                s = await rewrap(_sealed(r), _aad(r), self._kp, context_for(r.tenant_id, r.name))
            except SecretStoreError as exc:
                failed += 1
                logger.error("secrets.rewrap_failed", name=r.name, error=str(exc))
                continue
            r.wrapped_dek, r.key_id = s.wrapped_dek, s.key_id
            done += 1
        await self._db.commit()
        remaining = (await self._db.execute(select(func.count()).select_from(TenantSecret).where(
            TenantSecret.key_id != primary))).scalar_one()
        return {"rewrapped": done, "failed": failed, "remaining": remaining}
