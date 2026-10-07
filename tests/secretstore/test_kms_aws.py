"""AwsKmsKeyProvider against moto (a faithful KMS emulation, including encryption-context
enforcement) plus fake clients for failure modes moto cannot produce."""

import asyncio
import os
import time
import uuid

import boto3
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError
from moto import mock_aws
from sqlalchemy import select

from aijailer.models.tenant_secret import TenantSecret
from aijailer.secretstore.envelope import build_aad, context_for, open_sealed, seal
from aijailer.secretstore.keys import (
    ChainedKeyProvider, IntegrityError, KeyNotFoundError, KeyUnavailableError, LocalKeyProvider)
from aijailer.secretstore.kms_aws import AwsKmsKeyProvider
from aijailer.secretstore.store import SecretStore
from aijailer.services.audit_service import AuditService

T = uuid.uuid4()
AAD = build_aad(T, "gh", 1, ["api.github.com"], None)
CTX = context_for(T, "gh")
DEK = os.urandom(32)


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def kms():
    with mock_aws():
        yield boto3.client("kms")


def new_key(kms, alias=None):
    kid = kms.create_key()["KeyMetadata"]["KeyId"]
    if alias:
        kms.create_alias(AliasName=alias, TargetKeyId=kid)
    return kid


class Counting:
    """Wraps a real client and counts API calls."""

    def __init__(self, inner):
        self.inner, self.calls = inner, {}

    def __getattr__(self, name):
        fn = getattr(self.inner, name)

        def wrapped(**kw):
            self.calls[name] = self.calls.get(name, 0) + 1
            return fn(**kw)
        return wrapped


def err(code):
    return ClientError({"Error": {"Code": code, "Message": "secret-detail"}}, "Op")


class Failing:
    """Fake client where chosen operations raise."""

    def __init__(self, inner=None, **fail):
        self.inner, self.fail = inner, fail

    def __getattr__(self, name):
        def call(**kw):
            if name in self.fail:
                raise self.fail[name]
            return getattr(self.inner, name)(**kw)
        return call


@pytest.mark.asyncio
async def test_roundtrip_and_alias_is_pinned_to_the_key_arn(kms):
    kid = new_key(kms, "alias/aij")
    p = AwsKmsKeyProvider("alias/aij")
    arn = await p.primary_key_id()
    assert arn.startswith("arn:aws:kms:") and arn.endswith(kid) and p.owns(arn)
    key_id, wrapped = await p.wrap(DEK, AAD, CTX)
    assert key_id == arn and DEK not in wrapped
    assert await p.unwrap(key_id, wrapped, AAD, CTX) == DEK


@pytest.mark.asyncio
async def test_binding_is_enforced_by_kms_via_encryption_context(kms):
    new_key(kms, "alias/aij")
    p = AwsKmsKeyProvider("alias/aij", cache_ttl=0)
    key_id, wrapped = await p.wrap(DEK, AAD, CTX)
    other_aad = build_aad(T, "gh", 1, ["evil.example"], None)          # hosts edited in the DB
    with pytest.raises(IntegrityError):
        await p.unwrap(key_id, wrapped, other_aad, CTX)
    with pytest.raises(IntegrityError):                                # moved to another tenant
        await p.unwrap(key_id, wrapped, AAD, context_for(uuid.uuid4(), "gh"))
    with pytest.raises(IntegrityError):                                # renamed
        await p.unwrap(key_id, wrapped, AAD, context_for(T, "other"))
    bad = bytearray(wrapped)
    bad[-1] ^= 1
    with pytest.raises(IntegrityError):
        await p.unwrap(key_id, bytes(bad), AAD, CTX)


@pytest.mark.asyncio
async def test_only_configured_key_arns_are_trusted_for_decrypt(kms):
    k1, k2 = new_key(kms, "alias/old"), new_key(kms, "alias/new")
    old = AwsKmsKeyProvider("alias/old")
    key_id, wrapped = await old.wrap(DEK, AAD, CTX)
    new_only = AwsKmsKeyProvider("alias/new")
    with pytest.raises(KeyNotFoundError):                              # tampered/unknown key id
        await new_only.unwrap(key_id, wrapped, AAD, CTX)
    with pytest.raises(KeyNotFoundError):
        await new_only.unwrap("arn:aws:kms:us-east-1:1:key/attacker", wrapped, AAD, CTX)
    with_old = AwsKmsKeyProvider("alias/new", allowed_key_ids=(key_id,))   # after manual rotation
    assert await with_old.unwrap(key_id, wrapped, AAD, CTX) == DEK
    new_id, _ = await with_old.wrap(DEK, AAD, CTX)
    assert new_id != key_id and new_id.endswith(k2) and key_id.endswith(k1)


@pytest.mark.asyncio
async def test_response_key_mismatch_is_an_integrity_failure(kms):
    new_key(kms, "alias/aij")
    real = AwsKmsKeyProvider("alias/aij", cache_ttl=0)
    key_id, wrapped = await real.wrap(DEK, AAD, CTX)

    class Liar:
        def __init__(self, inner):
            self.inner = inner

        def __getattr__(self, n):
            def call(**kw):
                r = getattr(self.inner, n)(**kw)
                if n in ("encrypt", "decrypt"):
                    r["KeyId"] = "arn:aws:kms:us-east-1:1:key/some-other-key"
                return r
            return call
    p = AwsKmsKeyProvider("alias/aij", client=Liar(kms), cache_ttl=0)
    with pytest.raises(IntegrityError):
        await p.wrap(DEK, AAD, CTX)
    with pytest.raises(IntegrityError):
        await p.unwrap(key_id, wrapped, AAD, CTX)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", [
    err("AccessDeniedException"), err("ThrottlingException"), err("DisabledException"),
    err("KMSInvalidStateException"), err("KeyUnavailableException"), err("InternalException"),
    EndpointConnectionError(endpoint_url="https://kms.example")])
async def test_outages_and_access_problems_are_transient_and_leak_nothing(kms, fault):
    new_key(kms, "alias/aij")
    good = AwsKmsKeyProvider("alias/aij", cache_ttl=0)
    key_id, wrapped = await good.wrap(DEK, AAD, CTX)
    p = AwsKmsKeyProvider("alias/aij", client=Failing(kms, encrypt=fault, decrypt=fault),
                          cache_ttl=0)
    for call in (p.wrap(DEK, AAD, CTX), p.unwrap(key_id, wrapped, AAD, CTX)):
        with pytest.raises(KeyUnavailableError) as e:
            await call
        text = str(e.value)
        assert DEK.hex() not in text and "secret-detail" not in text and "wrapped" not in text


@pytest.mark.asyncio
async def test_unwrapped_keys_are_cached_per_exact_binding(kms):
    new_key(kms, "alias/aij")
    client = Counting(kms)
    clock = [1000.0]
    p = AwsKmsKeyProvider("alias/aij", client=client, cache_ttl=60, cache_size=2,
                          clock=lambda: clock[0])
    key_id, wrapped = await p.wrap(DEK, AAD, CTX)
    for _ in range(5):
        assert await p.unwrap(key_id, wrapped, AAD, CTX) == DEK
    assert client.calls["decrypt"] == 1                                # steady state: no KMS calls
    # a different binding must not be served from the cache (and is rejected by KMS)
    with pytest.raises(IntegrityError):
        await p.unwrap(key_id, wrapped, build_aad(T, "gh", 2, ["api.github.com"], None), CTX)
    clock[0] += 61                                                     # TTL expiry
    await p.unwrap(key_id, wrapped, AAD, CTX)
    assert client.calls["decrypt"] == 3
    p.clear_cache()
    await p.unwrap(key_id, wrapped, AAD, CTX)
    assert client.calls["decrypt"] == 4


@pytest.mark.asyncio
async def test_cache_can_be_disabled_and_is_bounded(kms):
    new_key(kms, "alias/aij")
    c1 = Counting(kms)
    p0 = AwsKmsKeyProvider("alias/aij", client=c1, cache_ttl=0)
    kid, w = await p0.wrap(DEK, AAD, CTX)
    for _ in range(3):
        await p0.unwrap(kid, w, AAD, CTX)
    assert c1.calls["decrypt"] == 3
    p = AwsKmsKeyProvider("alias/aij", client=Counting(kms), cache_ttl=60, cache_size=2)
    wraps = [await p.wrap(os.urandom(32), AAD, CTX) for _ in range(3)]
    for kid, w in wraps:
        await p.unwrap(kid, w, AAD, CTX)
    assert len(p._cache) == 2                                          # oldest evicted


@pytest.mark.asyncio
async def test_kms_calls_never_block_the_event_loop(kms):
    new_key(kms, "alias/aij")

    class Slow:
        def __getattr__(self, n):
            def call(**kw):
                time.sleep(0.3)                                        # a slow network round trip
                return getattr(kms, n)(**kw)
            return call
    p = AwsKmsKeyProvider("alias/aij", client=Slow(), cache_ttl=0)
    await p.primary_key_id()
    ticks, stop = 0, False

    async def ticker():
        nonlocal ticks
        while not stop:
            await asyncio.sleep(0.01)
            ticks += 1
    t = asyncio.create_task(ticker())
    start = time.monotonic()
    await asyncio.gather(*[p.wrap(os.urandom(32), AAD, CTX) for _ in range(4)])
    elapsed = time.monotonic() - start
    stop = True
    await t
    assert ticks >= 15                                                 # loop kept running
    assert elapsed < 0.3 * 4 * 0.8                                     # calls overlapped in threads


@pytest.mark.asyncio
async def test_check_validates_state_usage_and_real_permissions(kms):
    kid = new_key(kms, "alias/aij")
    await AwsKmsKeyProvider("alias/aij").check()                       # healthy
    kms.disable_key(KeyId=kid)
    with pytest.raises(KeyUnavailableError, match="Disabled"):
        await AwsKmsKeyProvider("alias/aij").check()
    sign = kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")["KeyMetadata"]["KeyId"]
    with pytest.raises(KeyUnavailableError, match="symmetric"):
        await AwsKmsKeyProvider(sign).check()
    kid2 = new_key(kms, "alias/ok")
    no_perm = Failing(kms, encrypt=err("AccessDeniedException"))        # IAM lacks kms:Encrypt
    with pytest.raises(KeyUnavailableError, match="AccessDenied"):
        await AwsKmsKeyProvider("alias/ok", client=no_perm).check()
    with pytest.raises(KeyUnavailableError):
        await AwsKmsKeyProvider("alias/does-not-exist").check()


def test_boto3_missing_gives_an_actionable_error(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(KeyUnavailableError, match="aijailer\\[kms\\]"):
        AwsKmsKeyProvider("alias/x")
    with pytest.raises(ValueError):
        AwsKmsKeyProvider("")


# --------------------------------------------------------------- through the secret store
@pytest.fixture
def store_factory(db_session):
    audit = AuditService()

    def make(provider):
        return SecretStore(db_session, provider, audit=audit)
    make.audit = audit
    return make


@pytest.mark.asyncio
async def test_store_works_end_to_end_on_kms_and_detects_tampering(kms, store_factory, db_session,
                                                                   test_tenant):
    new_key(kms, "alias/aij")
    s = store_factory(AwsKmsKeyProvider("alias/aij", cache_ttl=0))
    await s.create(test_tenant.id, "gh", "TOKEN-1", ["api.github.com"])
    await s.create(test_tenant.id, "ok", "TOKEN-2", ["ok.test"])
    assert {b.name: b.value for b in await s.resolve(test_tenant.id)} == {
        "gh": "TOKEN-1", "ok": "TOKEN-2"}
    await s.update(test_tenant.id, "gh", value="TOKEN-1b")
    row = (await db_session.execute(select(TenantSecret).where(TenantSecret.name == "gh"))
           ).scalar_one()
    assert row.key_id.startswith("arn:aws:kms:") and b"TOKEN" not in row.wrapped_dek
    row.hosts = ["attacker.example"]                                   # redirect attempt
    await db_session.commit()
    got = {b.name: b.value for b in await s.resolve(test_tenant.id)}
    assert got == {"ok": "TOKEN-2"}                                    # KMS refused the context
    assert any(e.details.get("action") == "integrity_failure" for e in store_factory.audit._events)


@pytest.mark.asyncio
async def test_outage_is_not_mistaken_for_tampering_or_for_no_secrets(kms, store_factory,
                                                                      test_tenant):
    new_key(kms, "alias/aij")
    good = AwsKmsKeyProvider("alias/aij", cache_ttl=0)
    await store_factory(good).create(test_tenant.id, "gh", "TOKEN", ["api.github.com"])
    down = AwsKmsKeyProvider("alias/aij", client=Failing(kms, decrypt=err("ThrottlingException")),
                             cache_ttl=0)
    with pytest.raises(KeyUnavailableError):                           # propagated, not swallowed
        await store_factory(down).resolve(test_tenant.id)
    assert not [e for e in store_factory.audit._events
                if e.details.get("action") in ("integrity_failure", "key_missing")]


@pytest.mark.asyncio
async def test_unknown_key_row_is_skipped_without_poisoning_the_tenant(kms, store_factory,
                                                                       db_session, test_tenant):
    new_key(kms, "alias/aij")
    s = store_factory(AwsKmsKeyProvider("alias/aij", cache_ttl=0))
    await s.create(test_tenant.id, "a", "AAA", ["a.test"])
    await s.create(test_tenant.id, "b", "BBB", ["b.test"])
    row = (await db_session.execute(select(TenantSecret).where(TenantSecret.name == "a"))
           ).scalar_one()
    row.key_id = "arn:aws:kms:us-east-1:999:key/retired"
    await db_session.commit()
    assert {b.name: b.value for b in await s.resolve(test_tenant.id)} == {"b": "BBB"}
    assert any(e.details.get("action") == "key_missing" for e in store_factory.audit._events)


@pytest.mark.asyncio
async def test_migration_from_local_keys_to_kms_without_decrypting_values(
        kms, store_factory, db_session, test_tenant):
    local = LocalKeyProvider({"k1": os.urandom(32)}, "k1")
    old = store_factory(local)
    await old.create(test_tenant.id, "a", "AAA", ["a.test"])
    await old.create(test_tenant.id, "b", "BBB", ["b.test"])
    before = {r.name: (r.ciphertext, r.nonce) for r in
              (await db_session.execute(select(TenantSecret))).scalars()}
    new_key(kms, "alias/aij")
    kp = AwsKmsKeyProvider("alias/aij", cache_ttl=0)
    chained = store_factory(ChainedKeyProvider(kp, local))             # KMS primary, local fallback
    assert {b.name: b.value for b in await chained.resolve(test_tenant.id)} == {
        "a": "AAA", "b": "BBB"}                                        # still readable mid-migration
    assert await chained.rewrap_all() == {"rewrapped": 2, "failed": 0, "remaining": 0}
    rows = (await db_session.execute(select(TenantSecret))).scalars().all()
    assert all(r.key_id.startswith("arn:aws:kms:") for r in rows)
    assert {r.name: (r.ciphertext, r.nonce) for r in rows} == before   # values never re-encrypted
    kms_only = store_factory(kp)                                       # local key can be retired
    assert {b.name: b.value for b in await kms_only.resolve(test_tenant.id)} == {
        "a": "AAA", "b": "BBB"}
    local_only = store_factory(local)
    assert await local_only.resolve(test_tenant.id) == []              # rows no longer local-wrapped
