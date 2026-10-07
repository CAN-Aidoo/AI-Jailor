"""Peer relay: real sockets, real TLS between the peers, the real CellProxy in front of the hub."""

import asyncio
import json
import ssl
import time

import pytest

from aijailer.agentsec.egress import EgressBroker
from aijailer.agentsec.proxy import CellProxy
from aijailer.peerlink.attest import (
    Party,
    PeerAttestationError,
    cert_sha256,
    make_attestation,
    verify_attestation,
)
from aijailer.peerlink.hub import PeerAuth, PeerHub
from aijailer.services.attestation import Ed25519Signer
from tests.peerlink.peer_client import (
    PeerError,
    PeerRefused,
    connect_peer,
    make_identity,
    open_tunnel,
    read_exact_line,
)

LINK = "a" * 32
SIGNER = Ed25519Signer.from_secret("platform-test")
PUB = SIGNER.public_key


class World:
    """Two cells (A = initiator, B = responder) with their own proxies, one hub."""

    def __init__(self):
        self.links = {(LINK, "cell-a"): PeerAuth(LINK, "initiator", "cell-a", "tenant-a", "cell-b", "tenant-b"),
                      (LINK, "cell-b"): PeerAuth(LINK, "responder", "cell-b", "tenant-b", "cell-a", "tenant-a")}
        self.events: dict[str, list] = {"cell-a": [], "cell-b": []}
        self.proxies: dict[str, CellProxy] = {}

    async def authorize(self, link_id, cell_id):
        return self.links.get((link_id, cell_id))


@pytest.fixture
async def world():
    w = World()
    w.hub = PeerHub(w.authorize, SIGNER, wait_seconds=3, session_seconds=30, idle_seconds=30)
    for cell in ("cell-a", "cell-b"):
        broker = EgressBroker([], [], resolver=lambda h: [], allow_private_cidrs=[])
        p = CellProxy(cell, "127.0.0.1", 0, broker, audit=w.events[cell].append, peer_hub=w.hub,
                      total_timeout=1.0)           # short on purpose: peer sessions must outlive it
        await p.start()
        w.proxies[cell] = p
    yield w
    for p in w.proxies.values():
        await p.stop()


def connect(w, cell, **kw):
    return asyncio.to_thread(connect_peer, "127.0.0.1", w.proxies[cell].port, kw.pop("link", LINK),
                             kw.pop("pub", PUB), **kw)


async def pair(w, **kw):
    (a, pa), (b, pb) = await asyncio.gather(connect(w, "cell-a", **kw), connect(w, "cell-b", **kw))
    return a, pa, b, pb


def exchange(a, b, a_to_b: bytes, b_to_a: bytes):
    """Blocking helper: A sends, B echoes a reply, both directions."""
    a.sendall(a_to_b)
    got = b""
    while len(got) < len(a_to_b):
        got += b.recv(65536)
    b.sendall(b_to_a)
    back = b""
    while len(back) < len(b_to_a):
        back += a.recv(65536)
    return got, back


# ---------------------------------------------------------------- the happy path
@pytest.mark.asyncio
async def test_mutual_tls_between_the_peers_through_the_relay_and_each_learns_who_the_other_is(world):
    a, pa, b, pb = await pair(world)
    try:
        assert (pa["role"], pb["role"]) == ("initiator", "responder")
        assert pa["peer"]["cell_id"] == "cell-b" and pa["peer"]["tenant_id"] == "tenant-b"
        assert pb["peer"]["cell_id"] == "cell-a" and pb["peer"]["tenant_id"] == "tenant-a"
        assert pa["session_id"] == pb["session_id"]
        assert a.version() == "TLSv1.3" and b.version() == "TLSv1.3"
        big = bytes(range(256)) * 4096                                  # 1 MiB
        got, back = await asyncio.to_thread(exchange, a, b, big, b"pong" * 1000)
        assert got == big and back == b"pong" * 1000
    finally:
        a.close()
        b.close()


@pytest.mark.asyncio
async def test_the_relay_carries_only_ciphertext(world):
    """Everything the proxy-side of each cell's connection sees after the hello must be TLS records."""
    captured: list[bytes] = []

    class Tap:
        async def start(self, upstream_port):
            self.server = await asyncio.start_server(
                lambda r, w: self.handle(r, w, upstream_port), "127.0.0.1", 0)
            return self.server.sockets[0].getsockname()[1]

        async def handle(self, r, w, upstream_port):
            ur, uw = await asyncio.open_connection("127.0.0.1", upstream_port)

            async def pipe(src, dst, direction):
                while data := await src.read(65536):
                    captured.append((direction, data))
                    dst.write(data)
                    await dst.drain()
                dst.close()
            await asyncio.gather(pipe(r, uw, "up"), pipe(ur, w, "down"), return_exceptions=True)
    tap = Tap()
    port = await tap.start(world.proxies["cell-a"].port)
    secret = b"TOP-SECRET-MARKER-" * 50
    (a, _), (b, _) = await asyncio.gather(
        asyncio.to_thread(connect_peer, "127.0.0.1", port, LINK, PUB), connect(world, "cell-b"))
    try:
        await asyncio.to_thread(exchange, a, b, secret, secret)
    finally:
        a.close()
        b.close()
    blob = b"".join(d for _, d in captured)
    assert b"TOP-SECRET-MARKER" not in blob                              # E2E: relay saw ciphertext
    assert b"cert_pem" in blob                                           # (the hello is plaintext, by design)
    assert b"\x17\x03\x03" in blob                                       # and TLS application records exist
    tap.server.close()


@pytest.mark.asyncio
async def test_a_session_outlives_the_proxys_short_total_timeout_and_is_audited(world):
    a, _, b, _ = await pair(world)                                       # proxy total_timeout = 1s
    try:
        await asyncio.sleep(1.5)
        got, _ = await asyncio.to_thread(exchange, a, b, b"still alive", b"yes")
        assert got == b"still alive"
    finally:
        a.close()
        b.close()
    await asyncio.sleep(0.3)
    ev = world.events["cell-a"][-1]
    assert ev["peer_link"] == LINK and ev["decision"] == "allow" and ev["role"] == "initiator"
    assert ev["bytes_initiator_to_responder"] > 0 and ev["bytes_responder_to_initiator"] > 0
    assert "TOP" not in json.dumps(ev)


# ---------------------------------------------------------------- authorisation
@pytest.mark.asyncio
async def test_refusals_look_identical_whatever_the_reason(world):
    world.links[("b" * 32, "cell-a")] = PeerAuth("b" * 32, "initiator", "cell-a", "t", "cell-z", "t")
    outsiders = [("a" * 32, "cell-c"), ("c" * 32, "cell-a"), ("not-hex", "cell-a"),
                 ("A" * 32, "cell-a"), ("a" * 31, "cell-a")]
    bodies = set()
    for link, cell in outsiders:
        world.proxies.setdefault(cell, world.proxies["cell-a"])          # cell-c shares a listener...
    # a listener whose cell is not on the link
    broker = EgressBroker([], [], resolver=lambda h: [], allow_private_cidrs=[])
    stranger = CellProxy("cell-c", "127.0.0.1", 0, broker, peer_hub=world.hub)
    await stranger.start()
    try:
        for link in ("a" * 32, "f" * 32, "not-a-link", ""):
            with pytest.raises(PeerRefused) as e:
                await asyncio.to_thread(open_tunnel, "127.0.0.1", stranger.port, link)
            assert e.value.status == 403
            bodies.add(e.value.body)
        with pytest.raises(PeerRefused) as e:                            # real cell, unknown link
            await asyncio.to_thread(open_tunnel, "127.0.0.1", world.proxies["cell-a"].port, "f" * 32)
        bodies.add(e.value.body)
    finally:
        await stranger.stop()
    assert len(bodies) == 1 and "peer link not available" in bodies.pop()   # no oracle


@pytest.mark.asyncio
async def test_peer_links_off_means_off(world):
    broker = EgressBroker([], [], resolver=lambda h: [], allow_private_cidrs=[])
    p = CellProxy("cell-a", "127.0.0.1", 0, broker)                      # no hub configured
    await p.start()
    try:
        with pytest.raises(PeerRefused) as e:
            await asyncio.to_thread(open_tunnel, "127.0.0.1", p.port, LINK)
        assert e.value.status == 403 and "not enabled" in e.value.body
    finally:
        await p.stop()


@pytest.mark.asyncio
async def test_a_side_cannot_be_connected_twice_and_is_free_again_afterwards(world):
    first = await asyncio.to_thread(open_tunnel, "127.0.0.1", world.proxies["cell-a"].port, LINK)
    first.sendall(json.dumps({"v": 1, "cert_pem": make_identity()[0]}).encode() + b"\n")
    await asyncio.sleep(0.2)                                             # first is now waiting for B
    with pytest.raises(PeerRefused) as e:
        await asyncio.to_thread(open_tunnel, "127.0.0.1", world.proxies["cell-a"].port, LINK)
    assert e.value.status == 403
    first.close()                                                        # waits out / ends
    await asyncio.sleep(0.2)
    world.hub.revoke_link(LINK)                                          # frees the pending slot
    await asyncio.sleep(0.2)
    a, _, b, _ = await pair(world)                                       # usable again
    a.close()
    b.close()


# ---------------------------------------------------------------- failure modes
@pytest.mark.asyncio
async def test_if_the_peer_never_shows_up_the_waiting_side_gets_an_error_and_the_slot_frees(world):
    world.hub.wait_seconds = 0.5
    t0 = time.monotonic()
    with pytest.raises(PeerError, match="did not connect"):
        await connect(world, "cell-a")
    assert time.monotonic() - t0 < 5
    await asyncio.sleep(0.1)
    assert (LINK, "initiator") not in world.hub._busy and not world.hub._pending


@pytest.mark.asyncio
@pytest.mark.parametrize("hello", [b"not json\n", b'{"v":2,"cert_pem":"x"}\n', b'{"v":1}\n',
                                   b'{"v":1,"cert_pem":"not a cert"}\n',
                                   b'{"v":1,"cert_pem":"' + b"A" * 20000 + b'"}\n'])
async def test_bad_hellos_are_rejected_without_pairing(world, hello):
    s = await asyncio.to_thread(open_tunnel, "127.0.0.1", world.proxies["cell-a"].port, LINK)
    s.sendall(hello)
    s.settimeout(5)
    reply = json.loads(await asyncio.to_thread(read_exact_line, s))
    assert "error" in reply and "attestation" not in reply
    s.close()
    await asyncio.sleep(0.1)
    assert not world.hub._pending and (LINK, "initiator") not in world.hub._busy


@pytest.mark.asyncio
async def test_revoking_the_link_cuts_a_live_session(world):
    a, _, b, _ = await pair(world)
    try:
        await asyncio.to_thread(exchange, a, b, b"hi", b"ho")
        assert world.hub.revoke_link(LINK) >= 2
        a.settimeout(5)
        with pytest.raises((ssl.SSLError, ConnectionError, OSError, TimeoutError)):
            for _ in range(50):                                          # writes eventually fail / reads end
                a.sendall(b"x" * 1000)
                await asyncio.sleep(0.05)
                data = await asyncio.to_thread(a.recv, 10)
                if not data:
                    raise ConnectionError("closed")
    finally:
        a.close()
        b.close()


@pytest.mark.asyncio
async def test_byte_cap_and_idle_limits_end_the_session(world):
    world.hub.max_bytes = 5000
    a, _, b, _ = await pair(world)
    try:
        a.sendall(b"z" * 2000)
        got = b""
        while len(got) < 2000:
            got += await asyncio.to_thread(b.recv, 65536)
        with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
            for _ in range(20):                                          # exceed the cap
                a.sendall(b"z" * 4000)
                await asyncio.sleep(0.05)
    finally:
        a.close()
        b.close()
    await asyncio.sleep(0.3)
    assert "byte cap" in world.events["cell-a"][-1]["reason"]


# ---------------------------------------------------------------- attestation checks (the client's duties)
def _fixture_material():
    a_pem, _ = make_identity("a")
    b_pem, _ = make_identity("b")
    me = Party("cell-a", "tenant-a", cert_sha256(a_pem))
    peer = Party("cell-b", "tenant-b", cert_sha256(b_pem))
    env = make_attestation(SIGNER, LINK, "initiator", me, peer, "s" * 32)
    return a_pem, b_pem, env


def test_attestation_accepts_the_genuine_article():
    a, b, env = _fixture_material()
    pred = verify_attestation(env, PUB, link_id=LINK, own_cert_pem=a, peer_cert_pem=b,
                              expect_role="initiator", pin_peer_cert_sha256=cert_sha256(b))
    assert pred["peer"]["cell_id"] == "cell-b"


@pytest.mark.parametrize("what", ["wrong_key", "other_link", "not_my_cert", "swapped_peer_cert",
                                  "wrong_pin", "wrong_role", "expired", "future", "tampered"])
def test_attestation_rejects(what):
    a, b, env = _fixture_material()
    other_pem, _ = make_identity("evil")
    kw = dict(link_id=LINK, own_cert_pem=a, peer_cert_pem=b)
    pub = PUB
    if what == "wrong_key":
        pub = Ed25519Signer.from_secret("not-the-platform").public_key
    elif what == "other_link":
        kw["link_id"] = "b" * 32
    elif what == "not_my_cert":
        kw["own_cert_pem"] = other_pem                 # hub handed us an attestation about someone else
    elif what == "swapped_peer_cert":
        kw["peer_cert_pem"] = other_pem                # hub substitutes a certificate it controls
    elif what == "wrong_pin":
        kw["pin_peer_cert_sha256"] = cert_sha256(other_pem)
    elif what == "wrong_role":
        kw["expect_role"] = "responder"
    elif what == "expired":
        kw["now"] = time.time() + 3600
    elif what == "future":
        kw["now"] = time.time() - 3600
    elif what == "tampered":
        env = dict(env)
        env["payload"] = env["payload"][:-4] + ("AAAA" if env["payload"][-4:] != "AAAA" else "BBBB")
    with pytest.raises(PeerAttestationError):
        verify_attestation(env, pub, **kw)


@pytest.mark.asyncio
async def test_a_hub_that_substitutes_a_certificate_is_caught_by_the_client(world, monkeypatch):
    """Malicious/compromised hub: pairs the cells but gives A a certificate of its own choosing."""
    evil_pem, _ = make_identity("mitm")
    orig = PeerHub._pair_and_relay

    async def evil_pair(self, a, b):
        victim = a if a.auth.role == "responder" else b                  # arrival order decides a/b
        victim.cert_pem, victim.cert_hash = evil_pem, cert_sha256(evil_pem)   # attest the wrong cert
        return await orig(self, a, b)
    monkeypatch.setattr(PeerHub, "_pair_and_relay", evil_pair)
    a_pem = make_identity("a")
    b_ident = make_identity("b")
    # B (honest) sees an attestation naming the MITM cert as ITS OWN: refuses
    res = await asyncio.gather(
        connect(world, "cell-a", identity=a_pem), connect(world, "cell-b", identity=b_ident),
        return_exceptions=True)
    assert isinstance(res[1], PeerAttestationError)                      # B notices: "does not name our certificate"
    # A was handed the MITM cert as its peer and the matching attestation: only a PIN protects it
    pin = cert_sha256(b_ident[0])
    world.hub.revoke_link(LINK)
    await asyncio.sleep(0.2)
    res = await asyncio.gather(
        connect(world, "cell-a", identity=a_pem, pin=pin), connect(world, "cell-b", identity=b_ident),
        return_exceptions=True)
    assert isinstance(res[0], PeerAttestationError) and "pinned" in str(res[0])
    for r in res:
        if not isinstance(r, Exception):
            r[0].close()
