"""Secret store -> DbSecretProvider -> CellNetwork -> real CellProxy -> real TLS upstream.

Shows the full path: a cell sends only a placeholder; the broker injects the decrypted value for the
bound host; rotation, revocation, expiry, tenant scoping and DB tampering all take effect on running
cells without a restart."""

import asyncio
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from aijailer.agentsec.proxy import CellProxy
from aijailer.models.tenant import Tenant
from aijailer.models.tenant_secret import TenantSecret
from aijailer.netpolicy.cell_network import CellNetwork
from aijailer.netpolicy.nft import NetAllocator, NetPolicyManager
from aijailer.secretstore.keys import LocalKeyProvider
from aijailer.secretstore.runtime import DbSecretProvider
from aijailer.secretstore.store import SecretStore
from tests.agentsec.test_proxy import Upstream, client_ctx, talk


class NoopNft:
    async def run(self, script, check_only=False):
        return ""


class NoopLinks:
    async def setup(self, cell): ...
    async def teardown(self, ifname): ...
    async def set_bandwidth(self, cell, bw): ...
    async def get_bandwidth(self, cell): ...


@pytest.fixture
async def world(db_engine, db_session, test_tenant):
    kp = LocalKeyProvider({"k1": os.urandom(32)}, "k1")
    sessions = async_sessionmaker(db_engine, expire_on_commit=False)
    up = Upstream(host="127.0.0.1")
    await up.start()
    ctx = client_ctx(up)

    def factory(cid, ip, port, broker, audit=None):
        return CellProxy(cid, "127.0.0.1", 0, broker, audit=audit, ssl_context=ctx)

    net = CellNetwork(NetPolicyManager(runner=NoopNft(), allocator=NetAllocator("10.77.0.0/24")),
                      NoopLinks(), secrets=DbSecretProvider(sessions, kp), proxy_factory=factory)
    policy = {"egress": [{"action": "allow", "destinations": [{"ip": "127.0.0.1"}],
                          "ports": [up.port]}]}

    async def on_change(tenant_id):
        await net.refresh_secrets(tenant_id, fail_closed=True)

    store = SecretStore(db_session, kp, on_change=on_change)

    async def cell(tenant):
        await net.provision(uuid.uuid4(), tenant.id, policy)
        return list(net._proxies.values())[-1]

    async def call(proxy, name="gh"):
        raw = (f"GET http://127.0.0.1:{up.port}/v1 HTTP/1.1\r\n"
               "Authorization: Bearer {{secret:%s}}\r\n\r\n" % name).encode()
        n = len(up.received)
        out = await talk(proxy.port, raw)
        return out.split(b"\r\n")[0].decode(), (up.received[-1] if len(up.received) > n else None)

    yield store, cell, call, up, net, db_session
    for p in list(net._proxies.values()):
        await p.stop()


@pytest.mark.asyncio
async def test_inject_rotate_revoke_on_a_running_cell(world, test_tenant):
    store, cell, call, up, net, _ = world
    proxy = await cell(test_tenant)
    status, seen = await call(proxy)
    assert " 403 " in status and seen is None                      # no secret yet -> denied
    await store.create(test_tenant.id, "gh", "TOKEN-ONE", ["127.0.0.1"])
    status, seen = await call(proxy)
    assert " 200 " in status and b"Bearer TOKEN-ONE" in seen       # live without restarting the cell
    await store.update(test_tenant.id, "gh", value="TOKEN-TWO")
    status, seen = await call(proxy)
    assert b"Bearer TOKEN-TWO" in seen and b"TOKEN-ONE" not in seen
    await store.delete(test_tenant.id, "gh")
    status, seen = await call(proxy)
    assert " 403 " in status and seen is None                      # revoked -> unusable at once


@pytest.mark.asyncio
async def test_rebinding_hosts_redirects_nothing_it_just_stops_working(world, test_tenant):
    store, cell, call, up, net, _ = world
    proxy = await cell(test_tenant)
    await store.create(test_tenant.id, "gh", "TOKEN", ["127.0.0.1"])
    assert " 200 " in (await call(proxy))[0]
    await store.update(test_tenant.id, "gh", hosts=["api.elsewhere.test"])
    status, seen = await call(proxy)
    assert " 403 " in status and seen is None                      # no longer bound to this host


@pytest.mark.asyncio
async def test_expiry_is_enforced_by_the_broker_itself(world, test_tenant):
    store, cell, call, up, net, _ = world
    proxy = await cell(test_tenant)
    await store.create(test_tenant.id, "gh", "SHORT-LIVED", ["127.0.0.1"],
                       expires_at=datetime.now(UTC) + timedelta(seconds=1.5))
    assert " 200 " in (await call(proxy))[0]
    await asyncio.sleep(1.7)                                       # no refresh happens here
    status, seen = await call(proxy)
    assert " 403 " in status and seen is None


@pytest.mark.asyncio
async def test_secrets_are_scoped_to_their_tenant(world, test_tenant, db_session):
    store, cell, call, up, net, _ = world
    other = Tenant(name="o", slug=f"o-{uuid.uuid4().hex[:6]}", status="active", tier="pro")
    db_session.add(other)
    await db_session.commit()
    mine, theirs = await cell(test_tenant), await cell(other)
    await store.create(test_tenant.id, "gh", "ONLY-MINE", ["127.0.0.1"])
    assert " 200 " in (await call(mine))[0]
    status, seen = await call(theirs)
    assert " 403 " in status and seen is None


@pytest.mark.asyncio
async def test_db_tampering_disables_the_secret_instead_of_redirecting_it(world, test_tenant):
    store, cell, call, up, net, db = world
    proxy = await cell(test_tenant)
    await store.create(test_tenant.id, "gh", "TOKEN", ["127.0.0.1"])
    assert " 200 " in (await call(proxy))[0]
    row = (await db.execute(select(TenantSecret))).scalar_one()
    row.hosts = ["127.0.0.1", "attacker.example"]                  # widen the destinations
    await db.commit()
    await net.refresh_secrets(test_tenant.id, fail_closed=True)
    status, seen = await call(proxy)
    assert " 403 " in status and seen is None                      # integrity failure -> not used


@pytest.mark.asyncio
async def test_store_outage_on_change_fails_closed(world, test_tenant, monkeypatch):
    store, cell, call, up, net, _ = world
    proxy = await cell(test_tenant)
    await store.create(test_tenant.id, "gh", "TOKEN", ["127.0.0.1"])
    assert " 200 " in (await call(proxy))[0]

    async def down(tenant_id, cell_id):
        raise ConnectionError("db down")
    monkeypatch.setattr(net._secrets, "secrets_for", down)
    await net.refresh_secrets(test_tenant.id, fail_closed=True)
    assert " 403 " in (await call(proxy))[0]                       # never keep a maybe-revoked secret
