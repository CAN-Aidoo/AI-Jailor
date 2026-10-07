"""The relay: pairs the two cells of a link, vouches for their certificates, then pipes bytes.

Per connection (already authorised by the cell's own proxy, so the cell's identity is known):

  1. the cell sends one line ``{"v":1,"cert_pem":"..."}`` (its ephemeral self-signed certificate);
  2. when BOTH sides of the link are present the hub sends each a line
     ``{"v":1,"attestation":<DSSE about the peer>,"peer_cert_pem":"..."}``;
  3. from here on the hub is an opaque pipe. The cells run mutual TLS 1.3 through it, trusting only
     the attested peer certificate, so the hub (and anyone on the path) sees ciphertext.

What the hub can and cannot do is spelled out in PEER_LINKS.md: it cannot read or alter the TLS
stream, but it is the party that vouches for who owns which certificate, so a malicious hub could
attest a certificate it controls. Cells that pin the peer's certificate hash out-of-band are immune.

Bounds: one connection per side of a link; the second side must arrive within ``wait_seconds``;
sessions have a lifetime, idle timeout and byte cap; revoking a link tears its sessions down.
"""

import asyncio
import json
import secrets
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from aijailer.peerlink.attest import (
    MAX_CERT_PEM,
    Party,
    PeerAttestationError,
    cert_sha256,
    make_attestation,
)
from aijailer.services.attestation import Signer

MAX_HELLO = 16 * 1024


@dataclass(frozen=True)
class PeerAuth:
    """What the platform knows about one side of an active link (from the database)."""

    link_id: str
    role: str                    # "initiator" (TLS client) | "responder" (TLS server)
    cell_id: str
    tenant_id: str
    peer_cell_id: str
    peer_tenant_id: str


Authorize = Callable[[str, str], Awaitable[PeerAuth | None]]   # (link_id, cell_id) -> PeerAuth


class _Side:
    def __init__(self, auth: PeerAuth, r, w, cert_pem: str, cert_hash: str) -> None:
        self.auth, self.r, self.w = auth, r, w
        self.cert_pem, self.cert_hash = cert_pem, cert_hash
        self.done: asyncio.Future = asyncio.get_running_loop().create_future()
        self.bytes_in = 0                       # bytes this side sent into the relay


class PeerHub:
    def __init__(self, authorize: Authorize, signer: Signer, wait_seconds: float = 60.0,
                 session_seconds: float = 3600.0, idle_seconds: float = 300.0,
                 max_bytes: int = 1 << 30, attestation_ttl: float = 600.0) -> None:
        self._authorize, self._signer = authorize, signer
        self.wait_seconds, self.session_seconds = wait_seconds, session_seconds
        self.idle_seconds, self.max_bytes, self.ttl = idle_seconds, max_bytes, attestation_ttl
        self._pending: dict[tuple[str, str], _Side] = {}        # (link, role) waiting for the peer
        self._busy: set[tuple[str, str]] = set()                # (link, role) pending OR in a session
        self._sessions: dict[str, set[asyncio.Task]] = {}       # link -> running relay tasks
        self._sides: dict[str, set[_Side]] = {}                 # link -> sides holding a connection

    async def authorize(self, link_id: str, cell_id: str) -> PeerAuth | None:
        """Called by the proxy BEFORE it answers 200, so refusals are ordinary HTTP errors."""
        if len(link_id) != 32 or any(c not in "0123456789abcdef" for c in link_id):
            return None
        auth = await self._authorize(link_id, cell_id)
        if auth is None or (auth.link_id, auth.role) in self._busy:
            return None                                          # no oracle: same answer
        return auth

    # ------------------------------------------------------------------ attach
    async def attach(self, auth: PeerAuth, r: asyncio.StreamReader, w: asyncio.StreamWriter,
                     event: dict) -> None:
        key = (auth.link_id, auth.role)
        if key in self._busy:                                    # lost a race with ourselves
            await self._error(w, "this side of the link is already connected")
            return
        self._busy.add(key)
        side: _Side | None = None
        try:
            try:
                cert_pem = await self._read_hello(r)
                side = _Side(auth, r, w, cert_pem, cert_sha256(cert_pem))
            except (PeerAttestationError, ValueError, KeyError, TypeError, TimeoutError,
                    asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                await self._error(w, "bad hello")
                event.update(decision="deny", reason="bad peer hello")
                return
            self._sides.setdefault(auth.link_id, set()).add(side)
            other = self._pending.get((auth.link_id, "responder" if auth.role == "initiator"
                                       else "initiator"))
            if other is None:
                self._pending[key] = side
                try:
                    await asyncio.wait_for(asyncio.shield(side.done), self.wait_seconds)
                except TimeoutError:
                    self._pending.pop(key, None)
                    event.update(decision="deny", reason="peer did not connect in time")
                    await self._error(w, "peer did not connect in time")
                except asyncio.CancelledError:
                    self._pending.pop(key, None)
                    raise
                else:
                    event.update(**side.done.result())
                return
            # The second arrival pairs the sides and runs the relay for both.
            self._pending.pop((other.auth.link_id, other.auth.role), None)
            event.update(await self._pair_and_relay(side, other))
        finally:
            self._busy.discard(key)
            if side is not None:
                self._sides.get(auth.link_id, set()).discard(side)

    @staticmethod
    async def _read_hello(r: asyncio.StreamReader) -> str:
        line = await asyncio.wait_for(r.readuntil(b"\n"), 10)
        if len(line) > MAX_HELLO:
            raise ValueError("hello too large")
        msg = json.loads(line)
        pem = msg["cert_pem"]
        if msg.get("v") != 1 or not isinstance(pem, str) or len(pem) > MAX_CERT_PEM:
            raise ValueError("bad hello")
        return pem

    @staticmethod
    async def _error(w, message: str) -> None:
        try:
            w.write(json.dumps({"v": 1, "error": message}).encode() + b"\n")
            await w.drain()
        except (ConnectionError, OSError):
            pass

    # ------------------------------------------------------------------ pair + relay
    async def _pair_and_relay(self, a: _Side, b: _Side) -> dict:
        sid = secrets.token_hex(16)
        link = a.auth.link_id
        for me, peer in ((a, b), (b, a)):
            att = make_attestation(
                self._signer, link, me.auth.role,
                Party(me.auth.cell_id, me.auth.tenant_id, me.cert_hash),
                Party(peer.auth.cell_id, peer.auth.tenant_id, peer.cert_hash), sid, self.ttl)
            me.w.write(json.dumps({"v": 1, "attestation": att, "peer_cert_pem": peer.cert_pem,
                                   "session_id": sid}).encode() + b"\n")
        try:
            await asyncio.gather(a.w.drain(), b.w.drain())
        except (ConnectionError, OSError):
            for s in (a, b):
                s.w.close()
            result = {"decision": "error", "reason": "peer went away during pairing"}
            for s in (a, b):
                if not s.done.done():
                    s.done.set_result(result)
            return result

        started = time.monotonic()
        moved = {"a": 0, "b": 0}
        total = [0]

        async def pipe(src, dst, who):
            try:
                while True:
                    data = await asyncio.wait_for(src.r.read(65536), self.idle_seconds)
                    if not data:
                        break
                    total[0] += len(data)
                    if total[0] > self.max_bytes:
                        break
                    moved[who] += len(data)
                    dst.w.write(data)
                    await dst.w.drain()
            except (TimeoutError, ConnectionError, OSError):
                pass
            finally:
                dst.w.close()

        t1 = asyncio.ensure_future(pipe(a, b, "a"))
        t2 = asyncio.ensure_future(pipe(b, a, "b"))
        tasks = self._sessions.setdefault(link, set())
        tasks.update((t1, t2))
        try:
            done, pending = await asyncio.wait({t1, t2}, timeout=self.session_seconds,
                                               return_when=asyncio.FIRST_COMPLETED)
            for t in pending:                                    # one side hung up, or time is up
                t.cancel()
            for s in (a, b):
                s.w.close()
            await asyncio.gather(t1, t2, return_exceptions=True)
        finally:
            tasks.difference_update((t1, t2))
            if not tasks:
                self._sessions.pop(link, None)
        reason = "closed"
        if time.monotonic() - started >= self.session_seconds:
            reason = "session lifetime reached"
        elif total[0] > self.max_bytes:
            reason = "byte cap reached"
        result = {"decision": "allow", "reason": f"peer session {reason}", "peer_link": link,
                  "session_id": sid, "bytes_initiator_to_responder": moved["a"] if a.auth.role == "initiator" else moved["b"],
                  "bytes_responder_to_initiator": moved["b"] if a.auth.role == "initiator" else moved["a"]}
        for s in (a, b):
            if not s.done.done():
                s.done.set_result(result)
        return result

    # ------------------------------------------------------------------ revocation
    def revoke_link(self, link_id: str) -> int:
        """Tear down everything on a link NOW (pending sides and live sessions). Returns how many
        connections were cut."""
        cut = 0
        for side in list(self._sides.get(link_id, ())):
            side.w.close()
            if not side.done.done():          # a side still waiting for its peer: release it now
                side.done.set_result({"decision": "deny", "reason": "link revoked"})
            cut += 1
        for t in list(self._sessions.get(link_id, ())):
            t.cancel()
        for key in [k for k in self._pending if k[0] == link_id]:
            self._pending.pop(key, None)
        return cut

    @property
    def active_links(self) -> set[str]:
        return set(self._sessions) | {k[0] for k in self._pending}


def new_link_id() -> str:
    return uuid.uuid4().hex
