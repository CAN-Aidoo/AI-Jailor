"""Wiring: configuration -> key provider, store factory, broker secret provider, change hook."""

import uuid
from collections.abc import Callable

import structlog

from aijailer.agentsec.egress import SecretBinding
from aijailer.core.config import get_settings
from aijailer.secretstore.keys import KeyProvider, LocalKeyProvider
from aijailer.secretstore.store import SecretStore

logger = structlog.get_logger(__name__)
_provider: KeyProvider | None = None
_loaded = False


def get_key_provider() -> KeyProvider | None:
    """None when no master keys are configured (store disabled). A *malformed* configuration
    raises at first use: a typo must not silently disable or weaken secret handling."""
    global _provider, _loaded
    if not _loaded:
        s = get_settings()
        if s.secrets_master_keys.strip():
            _provider = LocalKeyProvider.from_spec(s.secrets_master_keys, s.secrets_primary_key_id)
        _loaded = True
    return _provider


def reset_for_tests() -> None:
    global _provider, _loaded
    _provider, _loaded = None, False


async def _on_change(tenant_id: uuid.UUID) -> None:
    """Push a secret change to running cells now (fail closed if the store is unreadable)."""
    from aijailer.netpolicy.runtime import peek_cell_network
    net = peek_cell_network()
    if net is not None:
        await net.refresh_secrets(tenant_id, fail_closed=True)


def get_secret_store(db, audit=None) -> SecretStore | None:
    kp = get_key_provider()
    if kp is None:
        return None
    if audit is None:
        from aijailer.services.audit_service import get_audit_service
        audit = get_audit_service()
    return SecretStore(db, kp, audit=audit, on_change=_on_change)


class DbSecretProvider:
    """Broker-side secret source: decrypts a tenant's usable secrets for its cells."""

    def __init__(self, session_factory: Callable, provider: KeyProvider | None = None) -> None:
        self._sessions, self._kp = session_factory, provider

    async def secrets_for(self, tenant_id: uuid.UUID, cell_id: uuid.UUID) -> list[SecretBinding]:
        kp = self._kp or get_key_provider()
        if kp is None:
            return []
        async with self._sessions() as db:
            return await SecretStore(db, kp).resolve(tenant_id)
