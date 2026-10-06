"""Configuration -> key provider selection, and the startup health check."""

import os

import boto3
import pytest
from moto import mock_aws

from aijailer.secretstore import runtime
from aijailer.secretstore.keys import ChainedKeyProvider, LocalKeyProvider, SecretStoreError
from aijailer.secretstore.kms_aws import AwsKmsKeyProvider


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for k in ("SECRETS_MASTER_KEYS", "SECRETS_PRIMARY_KEY_ID", "SECRETS_KMS_KEY_ID",
              "SECRETS_KMS_ALLOWED_KEY_IDS", "SECRETS_KMS_REGION", "SECRETS_KMS_ENDPOINT_URL",
              "SECRETS_KMS_CACHE_TTL_SECONDS"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "t")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "t")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    runtime.reset_for_tests()
    yield
    runtime.reset_for_tests()


def test_nothing_configured_disables_the_store():
    assert runtime.get_key_provider() is None


def test_local_only(monkeypatch):
    monkeypatch.setenv("SECRETS_MASTER_KEYS", "k1:" + LocalKeyProvider.generate_key())
    assert isinstance(runtime.get_key_provider(), LocalKeyProvider)


def test_kms_only_with_settings_applied(monkeypatch):
    monkeypatch.setenv("SECRETS_KMS_KEY_ID", "alias/aij")
    monkeypatch.setenv("SECRETS_KMS_REGION", "eu-west-1")
    monkeypatch.setenv("SECRETS_KMS_CACHE_TTL_SECONDS", "42")
    monkeypatch.setenv("SECRETS_KMS_ALLOWED_KEY_IDS", "arn:aws:kms:eu-west-1:1:key/old, ")
    p = runtime.get_key_provider()
    assert isinstance(p, AwsKmsKeyProvider) and p._ttl == 42
    assert p._client.meta.region_name == "eu-west-1"
    assert p._extra_allowed == {"arn:aws:kms:eu-west-1:1:key/old"}


def test_kms_plus_local_is_a_chained_migration_provider(monkeypatch):
    monkeypatch.setenv("SECRETS_KMS_KEY_ID", "alias/aij")
    monkeypatch.setenv("SECRETS_MASTER_KEYS", "k1:" + LocalKeyProvider.generate_key())
    p = runtime.get_key_provider()
    assert isinstance(p, ChainedKeyProvider)
    assert p.owns("k1") and p.owns("arn:aws:kms:us-east-1:1:key/x") and not p.owns("zzz")


def test_malformed_local_keys_raise_instead_of_silently_disabling(monkeypatch):
    monkeypatch.setenv("SECRETS_MASTER_KEYS", "k1:not-valid-base64!!")
    with pytest.raises(SecretStoreError):
        runtime.get_key_provider()


@pytest.mark.asyncio
async def test_startup_check_never_raises_and_reports(monkeypatch, caplog):
    await runtime.startup_check()                                       # nothing configured: quiet
    monkeypatch.setenv("SECRETS_MASTER_KEYS", "k1:not-valid-base64!!")
    runtime.reset_for_tests()
    await runtime.startup_check()                                       # misconfigured: logged only
    monkeypatch.delenv("SECRETS_MASTER_KEYS")
    monkeypatch.setenv("SECRETS_KMS_KEY_ID", "alias/aij")
    with mock_aws():
        k = boto3.client("kms")
        kid = k.create_key()["KeyMetadata"]["KeyId"]
        k.create_alias(AliasName="alias/aij", TargetKeyId=kid)
        runtime.reset_for_tests()
        await runtime.startup_check()                                   # healthy
        k.disable_key(KeyId=kid)
        runtime.reset_for_tests()
        await runtime.startup_check()                                   # unhealthy: no exception


@pytest.mark.asyncio
async def test_db_secret_provider_uses_the_configured_kms(monkeypatch, db_engine, test_tenant):
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from aijailer.secretstore.store import SecretStore
    monkeypatch.setenv("SECRETS_KMS_KEY_ID", "alias/aij")
    with mock_aws():
        k = boto3.client("kms")
        k.create_alias(AliasName="alias/aij", TargetKeyId=k.create_key()["KeyMetadata"]["KeyId"])
        sessions = async_sessionmaker(db_engine, expire_on_commit=False)
        async with sessions() as db:
            store = runtime.get_secret_store(db)
            await store.create(test_tenant.id, "gh", "TOKEN", ["api.github.com"])
        got = await runtime.DbSecretProvider(sessions).secrets_for(test_tenant.id, os.urandom(1))
        assert [(b.name, b.value) for b in got] == [("gh", "TOKEN")]
