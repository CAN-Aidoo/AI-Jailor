"""Wiring: configuration -> key provider, store factory, broker secret provider, change hook."""

import uuid
from collections.abc import Callable

import structlog

from aijailer.agentsec.egress import SecretBinding
from aijailer.core.config import get_settings
from aijailer.secretstore.keys import ChainedKeyProvider, KeyProvider, LocalKeyProvider
from aijailer.secretstore.store import SecretStore

logger = structlog.get_logger(__name__)
_provider: KeyProvider | None = None
_loaded = False


def get_key_provider() -> KeyProvider | None:
    """None when nothing is configured (store disabled). A *malformed* configuration raises at first
    use: a typo must not silently disable or weaken secret handling.

    * SECRETS_KMS_KEY_ID set          -> AWS KMS is the primary KEK provider
    * SECRETS_MASTER_KEYS also set    -> local keys become decrypt-only fallback (migration)
    * only SECRETS_MASTER_KEYS set    -> local provider (development / small deployments)
    """
    global _provider, _loaded
    if not _loaded:
        s = get_settings()
        local = (LocalKeyProvider.from_spec(s.secrets_master_keys, s.secrets_primary_key_id)
                 if s.secrets_master_keys.strip() else None)
        if s.secrets_kms_key_id.strip():
            from aijailer.secretstore.kms_aws import AwsKmsKeyProvider
            kms = AwsKmsKeyProvider(
                s.secrets_kms_key_id.strip(),
                tuple(x.strip() for x in s.secrets_kms_allowed_key_ids.split(",")),
                region=s.secrets_kms_region or None,
                endpoint_url=s.secrets_kms_endpoint_url or None,
                cache_ttl=s.secrets_kms_cache_ttl_seconds)
            _provider = ChainedKeyProvider(kms, local) if local else kms
            logger.info("secrets.key_provider", provider="aws-kms", local_fallback=bool(local))
        else:
            _provider = local
            if local:
                logger.info("secrets.key_provider", provider="local")
        _loaded = True
    return _provider


async def startup_check() -> None:
    """Verify the key service at boot. A failure is logged loudly but does not stop the control
    plane: secret operations return 503 (and brokers get no secrets) until the key service works,
    and every operation re-tries, so it heals without a restart."""
    try:
        kp = get_key_provider()
    except Exception as exc:  # malformed config: say so, do not crash unrelated features
        logger.critical("secrets.misconfigured", error=str(exc))
        return
    if kp is not None and hasattr(kp, "check"):
        try:
            await kp.check()
            logger.info("secrets.key_provider_ready")
        except Exception as exc:
            logger.critical("secrets.key_provider_unhealthy", error=str(exc))


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
