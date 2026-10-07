import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from aijailer.models.audit import EventType
from aijailer.models.tenant import Tenant
from aijailer.models.tenant_secret import TenantSecret
from aijailer.secretstore import store as store_mod
from aijailer.secretstore.keys import LocalKeyProvider, SecretStoreError
from aijailer.secretstore.store import (
    ConflictError, LimitError, NotFoundError, SecretStore)
from aijailer.services.audit_service import AuditService

VALUE = "ghp_SUPERSECRET_value_123"


@pytest.fixture
def kp():
    return LocalKeyProvider({"k1": os.urandom(32)}, "k1")


@pytest.fixture
async def other_tenant(db_session):
    t = Tenant(name="other", slug=f"o-{uuid.uuid4().hex[:6]}", status="active", tier="pro")
    db_session.add(t)
    await db_session.commit()
    return t


@pytest.fixture
def mk(db_session, kp):
    audit = AuditService()
    changes = []

    async def on_change(tenant_id):
        changes.append(tenant_id)

    def make(**kw):
        return SecretStore(db_session, kw.pop("provider", kp), audit=audit,
                           on_change=kw.pop("on_change", on_change), **kw)
    make.audit, make.changes = audit, changes
    return make


async def create(s, tenant, name="gh", value=VALUE, hosts=("api.github.com",), **kw):
    return await s.create(tenant.id, name, value, list(hosts), **kw)


@pytest.mark.asyncio
async def test_create_stores_only_ciphertext_and_returns_no_value(mk, db_session, test_tenant):
    meta = await create(mk(), test_tenant)
    assert meta.name == "gh" and meta.version == 1 and meta.hosts == ["api.github.com"]
    assert VALUE not in repr(meta)
    row = (await db_session.execute(select(TenantSecret))).scalar_one()
    blob = row.ciphertext + row.nonce + row.wrapped_dek + str(row.hosts).encode()
    assert VALUE.encode() not in blob


@pytest.mark.asyncio
async def test_list_and_get_meta_never_include_values(mk, test_tenant):
    s = mk()
    await create(s, test_tenant, "a")
    await create(s, test_tenant, "b", hosts=["*.pypi.org"])
    metas = await s.list_meta(test_tenant.id)
    assert [m.name for m in metas] == ["a", "b"]
    assert VALUE not in repr(metas) and VALUE not in repr(await s.get_meta(test_tenant.id, "a"))


@pytest.mark.asyncio
async def test_duplicate_name_conflicts_and_validation_applies(mk, test_tenant):
    s = mk()
    await create(s, test_tenant)
    with pytest.raises(ConflictError):
        await create(s, test_tenant)
    for kw in (dict(name="bad name"), dict(value="a\r\nb"), dict(hosts=[]), dict(hosts=["*.com"])):
        with pytest.raises(SecretStoreError):
            await create(s, test_tenant, **{"name": "x", **kw})


@pytest.mark.asyncio
async def test_per_tenant_limit(mk, test_tenant, monkeypatch):
    monkeypatch.setattr(store_mod, "MAX_SECRETS_PER_TENANT", 2)
    s = mk()
    await create(s, test_tenant, "a")
    await create(s, test_tenant, "b")
    with pytest.raises(LimitError):
        await create(s, test_tenant, "c")


@pytest.mark.asyncio
async def test_tenant_isolation(mk, test_tenant, other_tenant):
    s = mk()
    await create(s, test_tenant)
    with pytest.raises(NotFoundError):
        await s.get_meta(other_tenant.id, "gh")
    with pytest.raises(NotFoundError):
        await s.update(other_tenant.id, "gh", value="x")
    with pytest.raises(NotFoundError):
        await s.delete(other_tenant.id, "gh")
    assert await s.list_meta(other_tenant.id) == [] and await s.resolve(other_tenant.id) == []
    await create(s, other_tenant, value="other-secret")           # same name, separate namespace
    mine = {b.name: b.value for b in await s.resolve(test_tenant.id)}
    theirs = {b.name: b.value for b in await s.resolve(other_tenant.id)}
    assert mine == {"gh": VALUE} and theirs == {"gh": "other-secret"}


@pytest.mark.asyncio
async def test_resolve_returns_bound_decrypted_bindings(mk, test_tenant):
    s = mk()
    await create(s, test_tenant, hosts=["B.test", "a.test"])
    (b,) = await s.resolve(test_tenant.id)
    assert (b.name, b.value, b.hosts, b.not_after) == ("gh", VALUE, ("a.test", "b.test"), None)


@pytest.mark.asyncio
async def test_rotation_bumps_version_and_changes_value(mk, test_tenant):
    s = mk()
    await create(s, test_tenant)
    m = await s.update(test_tenant.id, "gh", value="new-value")
    assert m.version == 2 and m.rotated_at is not None
    assert (await s.resolve(test_tenant.id))[0].value == "new-value"


@pytest.mark.asyncio
async def test_changing_hosts_keeps_value_and_rebinds(mk, test_tenant):
    s = mk()
    await create(s, test_tenant)
    m = await s.update(test_tenant.id, "gh", hosts=["api.other.test"])
    assert m.version == 2 and m.hosts == ["api.other.test"] and m.rotated_at is None
    (b,) = await s.resolve(test_tenant.id)
    assert b.value == VALUE and b.hosts == ("api.other.test",)
    with pytest.raises(SecretStoreError, match="nothing"):
        await s.update(test_tenant.id, "gh")


@pytest.mark.asyncio
async def test_expiry_is_enforced_and_must_be_future(mk, test_tenant):
    s = mk()
    with pytest.raises(SecretStoreError, match="future"):
        await create(s, test_tenant, expires_at=datetime.now(UTC) - timedelta(seconds=5))
    soon = datetime.now(UTC) + timedelta(hours=1)
    await create(s, test_tenant, expires_at=soon)
    assert (await s.resolve(test_tenant.id))[0].not_after == pytest.approx(soon.timestamp(), abs=1)
    assert await s.resolve(test_tenant.id, now=time.time() + 7200) == []     # expired -> omitted
    await s.update(test_tenant.id, "gh", clear_expiry=True)
    assert (await s.resolve(test_tenant.id, now=time.time() + 10**9))[0].not_after is None


@pytest.mark.asyncio
async def test_delete_removes_row_and_ciphertext(mk, db_session, test_tenant):
    s = mk()
    await create(s, test_tenant)
    await s.delete(test_tenant.id, "gh")
    assert (await db_session.execute(select(TenantSecret))).first() is None
    assert await s.resolve(test_tenant.id) == []
    with pytest.raises(NotFoundError):
        await s.delete(test_tenant.id, "gh")


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["hosts", "expiry", "name", "tenant", "ciphertext", "version"])
async def test_db_tampering_fails_closed(mk, db_session, test_tenant, other_tenant, attack):
    s = mk()
    await create(s, test_tenant)
    await create(s, test_tenant, "good", value="good-value", hosts=["ok.test"])
    row = (await db_session.execute(select(TenantSecret).where(
        TenantSecret.name == "gh"))).scalar_one()
    if attack == "hosts":
        row.hosts = ["attacker.example"]        # redirect the credential to an attacker host
    elif attack == "expiry":
        row.expires_at_epoch = time.time() + 10**7
    elif attack == "name":
        row.name = "renamed"
    elif attack == "tenant":
        row.tenant_id = other_tenant.id         # move a secret into another tenant
    elif attack == "ciphertext":
        row.ciphertext = row.ciphertext[:-1] + bytes([row.ciphertext[-1] ^ 1])
    elif attack == "version":
        row.version = 7
    await db_session.commit()
    names = {b.name: b.value for t in (test_tenant, other_tenant)
             for b in await s.resolve(t.id)}
    assert VALUE not in names.values()                                 # tampered row never usable
    assert names.get("good") == "good-value"                           # others unaffected
    events = [e.details for e in mk.audit._events if e.details.get("action") == "integrity_failure"]
    assert events and VALUE not in str(events)


@pytest.mark.asyncio
async def test_audit_events_exist_and_never_contain_values(mk, test_tenant):
    s = mk()
    await create(s, test_tenant)
    await s.update(test_tenant.id, "gh", value="rotated-VALUE-999")
    await s.delete(test_tenant.id, "gh")
    evs = [e for e in mk.audit._events if e.event_type == EventType.SECRET]
    assert [e.details["action"] for e in evs] == ["created", "rotated", "deleted"]
    assert VALUE not in str(evs) and "rotated-VALUE-999" not in str(evs)


@pytest.mark.asyncio
async def test_on_change_fires_for_every_write_and_failures_do_not_break_writes(mk, test_tenant):
    s = mk()
    await create(s, test_tenant)
    await s.update(test_tenant.id, "gh", value="v2")
    await s.delete(test_tenant.id, "gh")
    assert mk.changes == [test_tenant.id] * 3

    async def boom(tenant_id):
        raise RuntimeError("propagation down")
    s2 = mk(on_change=boom)
    await create(s2, test_tenant, "again")                              # write still succeeds
    assert [m.name for m in await s2.list_meta(test_tenant.id)] == ["again"]


@pytest.mark.asyncio
async def test_rewrap_all_migrates_to_new_primary_without_decrypting(mk, db_session, test_tenant):
    k1, k2 = os.urandom(32), os.urandom(32)
    s_old = mk(provider=LocalKeyProvider({"k1": k1}, "k1"))
    await create(s_old, test_tenant, "a")
    await create(s_old, test_tenant, "b", value="b-value")
    before = {r.name: (r.ciphertext, r.nonce) for r in
              (await db_session.execute(select(TenantSecret))).scalars()}
    s_new = mk(provider=LocalKeyProvider({"k1": k1, "k2": k2}, "k2"))
    assert (await s_new.rewrap_all()) == {"rewrapped": 2, "failed": 0, "remaining": 0}
    rows = (await db_session.execute(select(TenantSecret))).scalars().all()
    assert {r.key_id for r in rows} == {"k2"}
    assert {r.name: (r.ciphertext, r.nonce) for r in rows} == before   # value ciphertext untouched
    s_retired = mk(provider=LocalKeyProvider({"k2": k2}, "k2"))        # k1 can now be removed
    assert {b.name: b.value for b in await s_retired.resolve(test_tenant.id)} == {
        "a": VALUE, "b": "b-value"}
