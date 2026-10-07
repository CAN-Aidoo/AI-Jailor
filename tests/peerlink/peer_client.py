"""Reference peer for the tests (the shipped cell-side client is the Go helper, aijailer-peer).

Blocking sockets, run in threads. It reads the hello/attestation line BYTE-EXACTLY: any byte read
past the newline would be the start of the peer's TLS records and would be lost to the TLS layer
(the Go helper handles the same hazard with a buffered reader feeding the TLS connection)."""

import datetime
import json
import os
import socket
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

from aijailer.peerlink.attest import verify_attestation


class PeerRefused(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"{status} {body}")
        self.status, self.body = status, body


class PeerError(Exception):
    """The hub answered with an error line."""


def make_identity(cn: str = "cell", minutes: int = 10) -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(minutes=minutes))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()).decode())


def read_exact_line(sock: socket.socket, limit: int = 1 << 20) -> bytes:
    out = bytearray()
    while not out.endswith(b"\n"):
        b = sock.recv(1)
        if not b:
            raise ConnectionError("closed")
        out += b
        if len(out) > limit:
            raise ValueError("line too long")
    return bytes(out)


def open_tunnel(host: str, port: int, link_id: str, timeout: float = 15.0) -> socket.socket:
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(f"CONNECT {link_id}.peer.aijailer.invalid:443 HTTP/1.1\r\n"
              f"Host: {link_id}.peer.aijailer.invalid:443\r\n\r\n".encode())
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        b = s.recv(1)
        if not b:
            break
        head += b
    status = int(head.split(b" ", 2)[1]) if head.startswith(b"HTTP/") else 0
    if status != 200:
        body = b""
        try:
            while chunk := s.recv(4096):
                body += chunk
        except OSError:
            pass
        s.close()
        raise PeerRefused(status, body.decode(errors="replace"))
    return s


def tls_context(role: str, own_pem: str, own_key: str, peer_pem: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if role == "initiator" else ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False                       # identity = the attested certificate itself
    ctx.verify_mode = ssl.CERT_REQUIRED               # both directions: mutual authentication
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=peer_pem)        # the ONLY trust anchor: the attested peer cert
    with tempfile.TemporaryDirectory() as d:
        c, k = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        open(c, "w").write(own_pem)
        open(k, "w").write(own_key)
        ctx.load_cert_chain(c, k)
    return ctx


def connect_peer(host: str, port: int, link_id: str, platform_pubkey: Ed25519PublicKey, *,
                 identity: tuple[str, str] | None = None, pin: str | None = None,
                 expect_role: str | None = None, timeout: float = 15.0):
    """Full client flow. Returns (tls_socket, attested_predicate)."""
    own_pem, own_key = identity or make_identity()
    s = open_tunnel(host, port, link_id, timeout)
    s.sendall(json.dumps({"v": 1, "cert_pem": own_pem}).encode() + b"\n")
    msg = json.loads(read_exact_line(s))
    if "error" in msg:
        s.close()
        raise PeerError(msg["error"])
    pred = verify_attestation(msg["attestation"], platform_pubkey, link_id=link_id,
                              own_cert_pem=own_pem, peer_cert_pem=msg["peer_cert_pem"],
                              expect_role=expect_role, pin_peer_cert_sha256=pin)
    ctx = tls_context(pred["role"], own_pem, own_key, msg["peer_cert_pem"])
    tls = ctx.wrap_socket(s, server_side=pred["role"] == "responder")
    return tls, pred
