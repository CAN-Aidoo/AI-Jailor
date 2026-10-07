"""CellProxy tests with a real TLS upstream (local CA) and real sockets."""

import asyncio
import datetime
import ssl
import tempfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aijailer.agentsec.egress import EgressBroker, EgressRule, SecretBinding
from aijailer.agentsec.proxy import CellProxy

SECRET = "ghp_SUPERSECRET123"


def _san(host: str):
    import ipaddress
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def make_cert(host: str):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([_san(host)]), critical=False)
            .sign(key, hashes.SHA256()))
    d = tempfile.mkdtemp()
    cp, kp = f"{d}/c.pem", f"{d}/k.pem"
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                         serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cp, kp


class Upstream:
    """TLS server that records what it received and answers with a canned body."""

    def __init__(self, host="api.test", echo_secret=False):
        self.cp, self.kp = make_cert(host)
        self.received: list[bytes] = []
        self.echo_secret = echo_secret

    async def start(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cp, self.kp)
        self.server = await asyncio.start_server(self._h, "127.0.0.1", 0, ssl=ctx)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _h(self, r, w):
        data = await r.readuntil(b"\r\n\r\n")
        self.received.append(data)
        body = (b"echo:" + (SECRET.encode() if self.echo_secret else b"ok"))
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                % (len(body), body))
        await w.drain()
        w.close()


def client_ctx(up: Upstream):
    ctx = ssl.create_default_context()
    ctx.load_verify_locations(up.cp)
    return ctx


async def mk(up, rules=None, secrets=None, **kw):
    events = []
    broker = EgressBroker(
        rules or [EgressRule("api.test", ports=(up.port,))],
        secrets if secrets is not None else [SecretBinding("gh", SECRET, ("api.test",))],
        resolver=lambda h: ["127.0.0.1"], allow_private_cidrs=["127.0.0.0/8"])
    p = CellProxy("cell-1", "127.0.0.1", 0, broker, audit=events.append,
                  ssl_context=client_ctx(up), **kw)
    await p.start()
    return p, events


async def talk(port, raw: bytes, read=True) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(raw)
    await w.drain()
    out = await asyncio.wait_for(r.read(), 10) if read else b""
    w.close()
    return out


def get(up, path="/x", extra="", host="api.test", scheme="http"):
    return (f"GET {scheme}://{host}:{up.port}{path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n"
            ).encode()


@pytest.mark.asyncio
async def test_secret_injected_upstream_and_never_visible_to_cell_or_audit():
    up = Upstream(); await up.start()
    p, events = await mk(up)
    out = await talk(p.port, get(up, extra="Authorization: Bearer {{secret:gh}}\r\n"))
    assert b"200 OK" in out and b"echo:ok" in out
    assert f"Bearer {SECRET}".encode() in up.received[0]
    assert SECRET.encode() not in out and SECRET not in str(events)
    assert events[-1]["decision"] == "allow" and events[-1]["secrets_used"] == ["gh"]
    assert events[-1]["status"] == 200 and events[-1]["cell_id"] == "cell-1"
    await p.stop()


@pytest.mark.asyncio
async def test_secret_echoed_by_origin_is_redacted_same_length():
    up = Upstream(echo_secret=True); await up.start()
    p, _ = await mk(up)
    out = await talk(p.port, get(up, extra="Authorization: {{secret:gh}}\r\n"))
    assert SECRET.encode() not in out and b"*" * len(SECRET) in out
    head, _, body = out.partition(b"\r\n\r\n")
    assert f"Content-Length: {len(body)}".encode() in head  # framing intact
    await p.stop()


@pytest.mark.asyncio
async def test_denied_destination_never_touches_network():
    up = Upstream(); await up.start()
    p, events = await mk(up)
    out = await talk(p.port, get(up, host="evil.example"))
    assert b" 403 " in out.split(b"\r\n")[0] and up.received == []
    assert events[-1]["decision"] == "deny"
    await p.stop()


@pytest.mark.asyncio
async def test_secret_for_other_host_refused():
    up = Upstream(); await up.start()
    p, _ = await mk(up, rules=[EgressRule("api.test", ports=(up.port,))],
                    secrets=[SecretBinding("gh", SECRET, ("other.test",))])
    out = await talk(p.port, get(up, extra="Authorization: {{secret:gh}}\r\n"))
    assert b" 403 " in out.split(b"\r\n")[0] and up.received == []
    await p.stop()


@pytest.mark.asyncio
async def test_wrong_cert_name_is_bad_gateway():
    up = Upstream(host="other.name"); await up.start()
    p, _ = await mk(up)
    out = await talk(p.port, get(up))
    assert b" 502 " in out.split(b"\r\n")[0]
    await p.stop()


@pytest.mark.asyncio
async def test_protocol_abuse_rejected():
    up = Upstream(); await up.start()
    p, _ = await mk(up)
    st = lambda b: b.split(b"\r\n")[0]  # noqa: E731
    assert b" 400 " in st(await talk(p.port, b"GET /origin-form HTTP/1.1\r\nHost: api.test\r\n\r\n"))
    assert b" 501 " in st(await talk(p.port, get(up, extra="Transfer-Encoding: chunked\r\n").replace(
        b"GET", b"POST")))
    assert b" 400 " in st(await talk(p.port, get(up, extra="Bad Header: x\r\n")))  # space in name
    assert b" 400 " in st(await talk(p.port, b"GARBAGE\r\n\r\n"))
    assert b" 400 " in st(await talk(p.port, b"GET http://u:p@api.test/ HTTP/1.1\r\n\r\n"))
    big = b"POST http://api.test:%d/ HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n" % up.port
    assert b" 413 " in st(await talk(p.port, big))
    huge = get(up, extra="X: " + "a" * 70000 + "\r\n")
    assert b" 431 " in st(await talk(p.port, huge)) or b" 400 " in st(await talk(p.port, huge))
    assert up.received == []
    await p.stop()


@pytest.mark.asyncio
async def test_crlf_in_secret_value_cannot_smuggle_headers():
    up = Upstream(); await up.start()
    evil = SecretBinding("gh", "tok\r\nX-Evil: 1", ("api.test",))
    p, _ = await mk(up, secrets=[evil])
    out = await talk(p.port, get(up, extra="Authorization: {{secret:gh}}\r\n"))
    assert b" 400 " in out.split(b"\r\n")[0] and up.received == []
    await p.stop()


@pytest.mark.asyncio
async def test_connect_tunnel_allowed_and_denied():
    async def echo(r, w):
        w.write(b"hello:" + await r.read(5)); await w.drain(); w.close()
    srv = await asyncio.start_server(echo, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    up = Upstream(); await up.start()
    p, events = await mk(up, rules=[EgressRule("tcp.test", ports=(port,))])
    r, w = await asyncio.open_connection("127.0.0.1", p.port)
    w.write(f"CONNECT tcp.test:{port} HTTP/1.1\r\nHost: tcp.test\r\n\r\n".encode())
    assert b"200" in await r.readuntil(b"\r\n\r\n")
    w.write(b"world"); await w.drain()
    assert await asyncio.wait_for(r.read(), 5) == b"hello:world"
    w.close()
    deny = await talk(p.port, f"CONNECT evil.example:{port} HTTP/1.1\r\n\r\n".encode())
    assert b" 403 " in deny.split(b"\r\n")[0]
    meta = await talk(p.port, b"CONNECT metadata.google.internal:80 HTTP/1.1\r\n\r\n")
    assert b" 403 " in meta.split(b"\r\n")[0]
    await asyncio.sleep(0.1)
    assert any(e.get("bytes_up") == 5 and e.get("bytes_down") == 11 for e in events)
    await p.stop(); srv.close()


@pytest.mark.asyncio
async def test_ssrf_resolution_blocked_through_proxy():
    up = Upstream(); await up.start()
    broker = EgressBroker([EgressRule("api.test", ports=(up.port,))],
                          resolver=lambda h: ["169.254.169.254"])
    p = CellProxy("c", "127.0.0.1", 0, broker, ssl_context=client_ctx(up))
    await p.start()
    out = await talk(p.port, get(up))
    assert b" 403 " in out.split(b"\r\n")[0] and b"SSRF" in out
    await p.stop()


@pytest.mark.asyncio
async def test_concurrency_cap_returns_503():
    gate = asyncio.Event()

    async def slow(r, w):
        await gate.wait(); w.close()
    srv = await asyncio.start_server(slow, "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    up = Upstream(); await up.start()
    p, _ = await mk(up, rules=[EgressRule("tcp.test", ports=(port,))], max_concurrent=1)
    r1, w1 = await asyncio.open_connection("127.0.0.1", p.port)
    w1.write(f"CONNECT tcp.test:{port} HTTP/1.1\r\n\r\n".encode())
    await r1.readuntil(b"\r\n\r\n")
    out = await talk(p.port, f"CONNECT tcp.test:{port} HTTP/1.1\r\n\r\n".encode())
    assert b" 503 " in out.split(b"\r\n")[0]
    gate.set(); w1.close()
    await p.stop(); srv.close()
