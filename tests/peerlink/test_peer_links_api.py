"""Peer link lifecycle: consent, validation, authorisation of attaches, audit, cell lifecycle, and a
full API -> relay -> mutual-TLS round trip."""

import asyncio
import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from httpx import AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import async_sessionmaker

from aijailer.agentsec.egress import EgressBroker
from aijailer.agentsec.proxy import CellProxy
from aijailer.models.cell import Cell
from aijailer.models.peer_link import PeerLink
from aijailer.models.tenant import ApiKey, Tenant
from aijailer.netpolicy import runtime
from aijailer.peerlink.service import PeerLinkService, authorize_attach
from aijailer.services.audit_service import get_audit_service
from tests.peerlink.peer_client import PeerRefused, connect_peer, open_tunnel

KEY_B, KEY_C = "aj_test_peer_bbbbbb", "aj_test_peer_cccccc"


@pytest.fixture(autouse=True)
def peer_env(monkeypatch, db_engine):
    monkeypatch.setenv("PEER_ATTESTATION_SECRET", "peer-secret-for-tests")
    monkeypatch.setattr(runtime, "_peer_hub", None)
    sf = async_sessionmaker(db_engine, expire_on_commit=False)
    import aijailer.db.base as base
    monkeypatch.setattr(base, "async_session_factory", sf)      # authorize_attach uses its own session
    yield sf
    runtime._peer_hub = None


async def make_tenant(sf, name, key):
    async with sf() as s:
        t = Tenant(name=name, slug=f"{name}-{uuid.uuid4().hex[:5]}", status="active", tier="pro",
                   max_concurrent_cells=20)
        s.add(t)
        await s.flush()
        s.add(ApiKey(tenant_id=t.id, created_by=t.id, name="k", key_hash=hashlib.sha256(key.encode()).hexdigest(),
                     key_prefix=key[:12], role="admin", status="active"))
        await s.commit()
        return t


async def make_cell(sf, tenant, status="running"):
    async with sf() as s:
        c = Cell(tenant_id=tenant.id, name="c", image="i", status=status, security_policy_id=tenant.id)
        s.add(c)
        await s.commit()
        return c.id


def auth(key):
    return {"Authorization": f"Bearer {key}"}


@pytest.fixture
async def two(client: AsyncClient, test_tenant, test_api_key, peer_env):
    """tenant A (the conftest tenant) with a cell, tenant B with a cell."""
    sf = peer_env
    tb = await make_tenant(sf, "b", KEY_B)
    ca, cb = await make_cell(sf, test_tenant), await make_cell(sf, tb)
    return dict(sf=sf, ta=test_tenant, tb=tb, ca=ca, cb=cb, ka=test_api_key, kb=KEY_B, client=client)


async def propose(w, **kw):
    return await w["client"].post("/v1/peer-links", headers=auth(w["ka"]), json={
        "cell_id": str(w["ca"]), "peer_cell_id": str(w["cb"]), **kw})


# ------------------------------------------------------------------ consent
@pytest.mark.asyncio
async def test_disabled_without_a_signing_secret(client, test_api_key, monkeypatch):
    monkeypatch.delenv("PEER_ATTESTATION_SECRET")
    for call in (client.get("/v1/peer-links", headers=auth(test_api_key)),
                 client.get("/v1/peer-links/attestation-key", headers=auth(test_api_key)),
                 client.post("/v1/peer-links", headers=auth(test_api_key),
                             json={"cell_id": str(uuid.uuid4()), "peer_cell_id": str(uuid.uuid4())})):
        r = await call
        assert r.status_code == 503 and "peer_links_disabled" in r.text
    assert runtime.get_peer_hub() is None


@pytest.mark.asyncio
async def test_two_sided_consent_flow(two):
    c = two["client"]
    r = await propose(two, purpose="psi-demo", ttl_seconds=600)
    assert r.status_code == 201
    link = r.json()["data"]
    assert link["status"] == "pending" and link["my_role"] == "initiator" and link["purpose"] == "psi-demo"
    assert link["connect_host"] == f"{uuid.UUID(link['id']).hex}.peer.aijailer.invalid"
    # the other tenant sees the incoming proposal, as responder
    inc = (await c.get("/v1/peer-links", headers=auth(two["kb"]))).json()["data"]
    assert [x["id"] for x in inc] == [link["id"]] and inc[0]["my_role"] == "responder"
    assert inc[0]["peer_cell_id"] == str(two["ca"]) and inc[0]["my_cell_id"] == str(two["cb"])
    # neither pending nor the proposer can make it work; only the responder's tenant can accept
    assert await authorize_attach(uuid.UUID(link["id"]).hex, str(two["ca"])) is None
    r = await c.post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["ka"]))
    assert r.status_code == 400 and "peer_link_invalid" in r.text
    r = await c.post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    assert r.status_code == 200 and r.json()["data"]["status"] == "active"
    # now both sides may attach, with the right roles
    ha = await authorize_attach(uuid.UUID(link["id"]).hex, str(two["ca"]))
    hb = await authorize_attach(uuid.UUID(link["id"]).hex, str(two["cb"]))
    assert (ha.role, hb.role) == ("initiator", "responder")
    assert ha.peer_cell_id == str(two["cb"]) and hb.peer_tenant_id == str(two["ta"].id)


@pytest.mark.asyncio
async def test_a_link_between_two_cells_of_one_tenant_needs_no_second_consent(two):
    cell2 = await make_cell(two["sf"], two["ta"])
    r = await two["client"].post("/v1/peer-links", headers=auth(two["ka"]),
                                 json={"cell_id": str(two["ca"]), "peer_cell_id": str(cell2)})
    assert r.status_code == 201 and r.json()["data"]["status"] == "active"
    assert await authorize_attach(uuid.UUID(r.json()["data"]["id"]).hex, str(cell2)) is not None


@pytest.mark.asyncio
async def test_only_parties_can_see_or_touch_a_link(two):
    link = (await propose(two)).json()["data"]
    tc = await make_tenant(two["sf"], "c", KEY_C)
    for call in (two["client"].get(f"/v1/peer-links/{link['id']}", headers=auth(KEY_C)),
                 two["client"].post(f"/v1/peer-links/{link['id']}/accept", headers=auth(KEY_C)),
                 two["client"].delete(f"/v1/peer-links/{link['id']}", headers=auth(KEY_C))):
        r = await call
        assert r.status_code == 404 and "peer_link_not_found" in r.text
    assert (await two["client"].get("/v1/peer-links", headers=auth(KEY_C))).json()["data"] == []
    assert tc.id and (await two["client"].get(f"/v1/peer-links/{uuid.uuid4()}", headers=auth(two["ka"]))).status_code == 404


@pytest.mark.asyncio
@pytest.mark.parametrize("body,code", [
    ({"ttl_seconds": 10}, "peer_link_invalid"), ({"ttl_seconds": 10**7}, "peer_link_invalid"),
    ({"purpose": "x" * 65}, 422), ({"purpose": "bad\x00"}, "peer_link_invalid"),
    ({"ttl_seconds": 600.5}, 422), ({"surprise": 1}, 422)])
async def test_proposal_validation(two, body, code):
    r = await propose(two, **body)
    assert r.status_code in (400, 422), r.text
    assert (str(code) in r.text) if isinstance(code, str) else r.status_code == code


@pytest.mark.asyncio
async def test_proposals_cannot_probe_for_cells_and_dups_are_refused(two):
    c, sf = two["client"], two["sf"]
    stopped = await make_cell(sf, two["tb"], status="stopped")
    bodies = set()
    for peer in (uuid.uuid4(), stopped):                   # no such cell / not running: same answer
        r = await c.post("/v1/peer-links", headers=auth(two["ka"]),
                         json={"cell_id": str(two["ca"]), "peer_cell_id": str(peer)})
        assert r.status_code == 400
        bodies.add(r.json()["error"]["message"] if "error" in r.json() else r.text)
    assert len(bodies) == 1
    r = await c.post("/v1/peer-links", headers=auth(two["ka"]),
                     json={"cell_id": str(two["ca"]), "peer_cell_id": str(two["ca"])})
    assert r.status_code == 400
    r = await c.post("/v1/peer-links", headers=auth(two["ka"]),       # not YOUR cell
                     json={"cell_id": str(two["cb"]), "peer_cell_id": str(two["ca"])})
    assert r.status_code == 404
    assert (await propose(two)).status_code == 201
    assert (await propose(two)).status_code == 409                    # duplicate, either direction
    r = await c.post("/v1/peer-links", headers=auth(two["kb"]),
                     json={"cell_id": str(two["cb"]), "peer_cell_id": str(two["ca"])})
    assert r.status_code == 409


@pytest.mark.asyncio
async def test_open_link_limit_per_tenant(two, monkeypatch):
    monkeypatch.setenv("PEER_LINK_MAX_OPEN_PER_TENANT", "2")
    for _ in range(2):
        peer = await make_cell(two["sf"], two["tb"])
        r = await two["client"].post("/v1/peer-links", headers=auth(two["ka"]),
                                     json={"cell_id": str(two["ca"]), "peer_cell_id": str(peer)})
        assert r.status_code == 201
    peer = await make_cell(two["sf"], two["tb"])
    r = await two["client"].post("/v1/peer-links", headers=auth(two["ka"]),
                                 json={"cell_id": str(two["ca"]), "peer_cell_id": str(peer)})
    assert r.status_code == 429 and "peer_link_limit" in r.text


# ------------------------------------------------------------------ attach authorisation
@pytest.mark.asyncio
async def test_authorize_attach_says_no_for_every_kind_of_no(two):
    c, sf = two["client"], two["sf"]
    link = (await propose(two)).json()["data"]
    await c.post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    lid = uuid.UUID(link["id"]).hex
    assert await authorize_attach(lid, str(two["ca"])) is not None
    assert await authorize_attach(lid, str(uuid.uuid4())) is None               # not a party
    assert await authorize_attach("zz", str(two["ca"])) is None                 # malformed
    assert await authorize_attach(lid, "not-a-uuid") is None
    assert await authorize_attach(uuid.uuid4().hex, str(two["ca"])) is None     # unknown link

    async def set_cell(cid, **v):
        async with sf() as s:
            await s.execute(update(Cell).where(Cell.id == cid).values(**v))
            await s.commit()
    await set_cell(two["cb"], status="stopped")                                  # peer not running
    assert await authorize_attach(lid, str(two["ca"])) is None
    assert await authorize_attach(lid, str(two["cb"])) is None
    await set_cell(two["cb"], status="running")
    await set_cell(two["ca"], tenant_id=uuid.uuid4())                           # no longer owned as agreed
    assert await authorize_attach(lid, str(two["cb"])) is None
    await set_cell(two["ca"], tenant_id=two["ta"].id)
    assert await authorize_attach(lid, str(two["ca"])) is not None
    async with sf() as s:                                                       # expiry needs no cleanup job
        await s.execute(update(PeerLink).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        await s.commit()
    assert await authorize_attach(lid, str(two["ca"])) is None
    assert (await c.get("/v1/peer-links", headers=auth(two["ka"]))).json()["data"] == []       # hidden...
    assert len((await c.get("/v1/peer-links?include_inactive=true", headers=auth(two["ka"]))).json()["data"]) == 1


# ------------------------------------------------------------------ revoke, cell lifecycle, audit
@pytest.mark.asyncio
async def test_either_party_can_revoke_and_it_cuts_the_relay(two, monkeypatch):
    c = two["client"]
    cut = []
    hub = runtime.get_peer_hub()
    monkeypatch.setattr(hub, "revoke_link", lambda lid: cut.append(lid) or 0)
    link = (await propose(two)).json()["data"]
    await c.post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    r = await c.delete(f"/v1/peer-links/{link['id']}", headers=auth(two["kb"]))      # the responder revokes
    assert r.status_code == 200 and r.json()["data"]["status"] == "revoked"
    assert cut == [uuid.UUID(link["id"]).hex]
    assert await authorize_attach(uuid.UUID(link["id"]).hex, str(two["ca"])) is None
    r = await c.post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    assert r.status_code == 400                                                       # cannot be revived
    assert (await c.delete(f"/v1/peer-links/{link['id']}", headers=auth(two["ka"]))).status_code == 200  # idempotent


@pytest.mark.asyncio
async def test_a_cell_losing_its_network_loses_its_peer_links(two, monkeypatch):
    from aijailer.services import cell_service

    class Net:
        async def deprovision(self, cell_id):
            return []
    monkeypatch.setattr(cell_service, "network_required", lambda engine: True)
    link = (await propose(two)).json()["data"]
    await two["client"].post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    async with two["sf"]() as s:
        svc = cell_service.CellService(s, network=Net())
        await svc.stop_cell(two["cb"], two["tb"].id)           # stop -> _deprovision_network -> revoke links
        await s.commit()
    assert await authorize_attach(uuid.UUID(link["id"]).hex, str(two["ca"])) is None
    got = (await two["client"].get(f"/v1/peer-links/{link['id']}", headers=auth(two["ka"]))).json()["data"]
    assert got["status"] == "revoked"


@pytest.mark.asyncio
async def test_every_step_is_audited_on_both_tenants_chains(two):
    audit = get_audit_service()
    link = (await propose(two, purpose="p")).json()["data"]
    await two["client"].post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    await two["client"].delete(f"/v1/peer-links/{link['id']}", headers=auth(two["ka"]))

    async def actions(tid):
        return sorted(e.details["action"] for e in await audit.query_events(tid)
                      if str(e.details.get("action", "")).startswith("peer_link_"))
    a, b = await actions(two["ta"].id), await actions(two["tb"].id)
    assert a == ["peer_link_accepted", "peer_link_proposed", "peer_link_revoked"]
    assert b == ["peer_link_accepted", "peer_link_requested", "peer_link_revoked"]


@pytest.mark.asyncio
async def test_attestation_key_endpoint_matches_what_the_hub_signs_with(two):
    d = (await two["client"].get("/v1/peer-links/attestation-key", headers=auth(two["ka"]))).json()["data"]
    hub = runtime.get_peer_hub()
    raw = hub._signer.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.b64decode(d["public_key"]) == raw and d["keyid"] == hub._signer.keyid
    assert runtime.peer_public_key_b64() == d["public_key"]          # what cells get as AIJAILER_PEER_ATTEST_PUBKEY
    assert "private" not in str(d).lower()


@pytest.mark.asyncio
async def test_cells_get_the_public_key_in_their_environment(monkeypatch):
    """CellNetwork merges the platform-owned env LAST so a tenant cannot override it."""
    from aijailer.netpolicy.cell_network import CellNetwork
    net = CellNetwork(manager=None, link_ops=None, extra_env={"AIJAILER_PEER_ATTEST_PUBKEY": "PUB"})
    env = net._proxy_env("http://10.0.0.1:3128")
    assert env["AIJAILER_PEER_ATTEST_PUBKEY"] == "PUB" and env["http_proxy"] == "http://10.0.0.1:3128"


# ------------------------------------------------------------------ the whole thing, for real
@pytest.mark.asyncio
async def test_api_to_relay_to_mutual_tls_and_revocation_through_the_api_cuts_it(two):
    c = two["client"]
    link = (await propose(two)).json()["data"]
    await c.post(f"/v1/peer-links/{link['id']}/accept", headers=auth(two["kb"]))
    hub = runtime.get_peer_hub()
    pub = hub._signer.public_key
    proxies = {}
    for name, cid in (("a", two["ca"]), ("b", two["cb"])):
        broker = EgressBroker([], [], resolver=lambda h: [], allow_private_cidrs=[])
        p = CellProxy(str(cid), "127.0.0.1", 0, broker, peer_hub=hub)
        await p.start()
        proxies[name] = p
    lid = uuid.UUID(link["id"]).hex
    try:
        (a, pa), (b, pb) = await asyncio.gather(
            asyncio.to_thread(connect_peer, "127.0.0.1", proxies["a"].port, lid, pub),
            asyncio.to_thread(connect_peer, "127.0.0.1", proxies["b"].port, lid, pub))
        assert (pa["role"], pb["role"]) == ("initiator", "responder")
        assert pa["peer"]["tenant_id"] == str(two["tb"].id) and pb["peer"]["cell_id"] == str(two["ca"])
        a.sendall(b"hello from a")
        assert await asyncio.to_thread(b.recv, 100) == b"hello from a"
        r = await c.delete(f"/v1/peer-links/{link['id']}", headers=auth(two["ka"]))     # revoke via the API
        assert r.status_code == 200
        a.settimeout(5)
        with pytest.raises(Exception):
            for _ in range(50):
                a.sendall(b"x" * 100)
                await asyncio.sleep(0.05)
                if not await asyncio.to_thread(a.recv, 10):
                    raise ConnectionError("closed")
        with pytest.raises(PeerRefused):                                                # and cannot come back
            await asyncio.to_thread(open_tunnel, "127.0.0.1", proxies["a"].port, lid)
        a.close()
        b.close()
    finally:
        for p in proxies.values():
            await p.stop()
