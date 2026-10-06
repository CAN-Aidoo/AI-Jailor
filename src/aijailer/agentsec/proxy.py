"""Per-cell egress proxy: the single endpoint nftables lets a cell reach.

One listener per cell, bound to that cell's link address (``host_ip``). The
cell's identity is *which listener accepted the connection*; we never trust a
source address or a header for identity.

Two request styles, both evaluated by ``EgressBroker`` before any upstream
socket is opened:

* ``CONNECT host:port``  allowlisted TLS pass-through (no inspection, so no
  credential injection; use for clients that must verify the origin themselves).
* absolute-form ``GET http://host/path``  the cell speaks *plaintext to the
  broker over its private point-to-point link*; the broker originates TLS to
  the origin (certificate verified for ``host``), injects credentials for
  ``{{secret:NAME}}`` header placeholders, and redacts any secret value that
  the origin echoes back. This is how a cell uses an API without ever holding
  the key and without a MITM CA inside the guest. Plaintext upstream is never
  permitted.

Hardening: pinned-IP upstream connects (from the broker's own resolution),
header/body size caps, no request smuggling surface (Transfer-Encoding is
rejected, ``Connection: close`` upstream, one request per connection), idle and
total timeouts, per-cell concurrency cap, redacted audit for every decision.
"""

import asyncio
import ssl
import time
from collections.abc import Callable
from urllib.parse import urlsplit

from aijailer.agentsec.egress import EgressBroker, EgressDecision, EgressRequest

MAX_REQUEST_LINE = 8 * 1024
MAX_HEADER_BYTES = 64 * 1024
MAX_HEADERS = 100
MAX_BODY = 8 * 1024 * 1024
MAX_RESPONSE = 32 * 1024 * 1024
HOP_BY_HOP = {"connection", "proxy-connection", "proxy-authorization", "proxy-authenticate",
              "keep-alive", "te", "trailer", "upgrade", "host", "content-length",
              "transfer-encoding"}

AuditSink = Callable[[dict], None]


class _BadRequest(Exception):
    def __init__(self, status: int, msg: str):
        super().__init__(msg)
        self.status, self.msg = status, msg


def _reason(status: int) -> str:
    return {200: "OK", 400: "Bad Request", 403: "Forbidden", 413: "Payload Too Large",
            431: "Request Header Fields Too Large", 501: "Not Implemented",
            502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout"}.get(
                status, "Error")


async def _respond(w: asyncio.StreamWriter, status: int, msg: str) -> None:
    body = ('{"error": ' + _json_str(msg) + "}").encode()
    w.write(f"HTTP/1.1 {status} {_reason(status)}\r\nContent-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n"
            f"X-AIJailer-Egress: denied\r\n\r\n".encode() + body)
    try:
        await w.drain()
    except ConnectionError:
        pass


def _json_str(s: str) -> str:
    import json
    return json.dumps(s)


async def _read_head(r: asyncio.StreamReader) -> tuple[str, list[tuple[str, str]]]:
    try:
        line = await r.readuntil(b"\r\n")
    except asyncio.LimitOverrunError:
        raise _BadRequest(431, "request line too long") from None
    except asyncio.IncompleteReadError:
        raise _BadRequest(400, "incomplete request") from None
    if len(line) > MAX_REQUEST_LINE:
        raise _BadRequest(431, "request line too long")
    headers: list[tuple[str, str]] = []
    total = 0
    while True:
        try:
            h = await r.readuntil(b"\r\n")
        except (asyncio.LimitOverrunError, asyncio.IncompleteReadError):
            raise _BadRequest(400, "malformed headers") from None
        total += len(h)
        if total > MAX_HEADER_BYTES or len(headers) > MAX_HEADERS:
            raise _BadRequest(431, "headers too large")
        if h == b"\r\n":
            break
        try:
            name, sep, value = h.decode("latin-1").partition(":")
        except UnicodeError:
            raise _BadRequest(400, "bad header encoding") from None
        if not sep or not name or name != name.strip() or any(c in name for c in " \t"):
            raise _BadRequest(400, "malformed header name")  # incl. obs-fold / smuggling tricks
        headers.append((name, value.strip()))
    return line.decode("latin-1").rstrip("\r\n"), headers


class CellProxy:
    def __init__(self, cell_id: str, bind_ip: str, port: int, broker: EgressBroker,
                 audit: AuditSink | None = None, ssl_context: ssl.SSLContext | None = None,
                 max_concurrent: int = 64, connect_timeout: float = 10.0,
                 idle_timeout: float = 300.0, total_timeout: float = 120.0) -> None:
        self.cell_id, self._ip, self._port = cell_id, bind_ip, port
        self._broker, self._audit = broker, audit or (lambda e: None)
        self._ssl = ssl_context or ssl.create_default_context()
        self._sem = asyncio.Semaphore(max_concurrent)
        self._ct, self._idle, self._total = connect_timeout, idle_timeout, total_timeout
        self._server: asyncio.base_events.Server | None = None

    def replace_broker(self, broker: EgressBroker) -> None:
        """Atomically swap policy/secrets. Requests already past evaluation keep the old broker;
        every later request sees the new one (this is how a revoked secret stops working)."""
        self._broker = broker

    @property
    def port(self) -> int:
        return self._server.sockets[0].getsockname()[1] if self._server else self._port

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self._ip, self._port,
                                                  limit=MAX_REQUEST_LINE)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    # -- connection handling --
    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        if self._sem.locked():
            await _respond(w, 503, "too many concurrent requests")
            # Swallow the unread request so close() sends FIN, not RST (RST can discard the 503).
            try:
                await asyncio.wait_for(r.read(65536), 0.3)
            except (TimeoutError, ConnectionError):
                pass
            w.close()
            return
        async with self._sem:
            start = time.monotonic()
            event: dict = {"cell_id": self.cell_id}
            try:
                await asyncio.wait_for(self._serve(r, w, event), self._total)
            except _BadRequest as e:
                event.update(decision="deny", reason=e.msg, status=e.status)
                await _respond(w, e.status, e.msg)
            except TimeoutError:
                event.setdefault("decision", "error")
                event["reason"] = "timeout"
                await _respond(w, 504, "timeout")
            except (ConnectionError, OSError) as e:
                event.setdefault("decision", "error")
                event["reason"] = f"{type(e).__name__}"
            finally:
                event["duration_ms"] = int((time.monotonic() - start) * 1000)
                self._audit(event)
                w.close()

    async def _serve(self, r, w, event: dict) -> None:
        try:
            line, headers = await asyncio.wait_for(_read_head(r), 10)
        except TimeoutError:
            raise _BadRequest(400, "request header timeout") from None
        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
            raise _BadRequest(400, "malformed request line")
        method, target, _ = parts
        method = method.upper()
        names = {n.lower() for n, _ in headers}
        if "transfer-encoding" in names:
            raise _BadRequest(501, "Transfer-Encoding is not supported")
        if method == "CONNECT":
            await self._connect(r, w, target, event)
        else:
            await self._forward(r, w, method, target, headers, event)

    # -- CONNECT: allowlisted TLS tunnel --
    async def _connect(self, r, w, target: str, event: dict) -> None:
        host, _, port_s = target.rpartition(":")
        if not host or not port_s.isdigit() or not (1 <= int(port_s) <= 65535):
            raise _BadRequest(400, "CONNECT target must be host:port")
        host = host.strip("[]")
        d = self._broker.evaluate(EgressRequest("CONNECT", host, int(port_s)))
        event.update(d.audit)
        if not d.allowed:
            raise _BadRequest(403, d.reason)
        up_r, up_w = await self._open(d, int(port_s), None)
        w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await w.drain()
        up = down = 0

        async def pipe(src, dst, counter):
            nonlocal up, down
            try:
                while True:
                    data = await asyncio.wait_for(src.read(65536), self._idle)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
                    if counter == "up":
                        up += len(data)
                    else:
                        down += len(data)
            except (TimeoutError, ConnectionError, OSError):
                pass
            finally:
                dst.close()

        await asyncio.gather(pipe(r, up_w, "up"), pipe(up_r, w, "down"))
        event.update(status=200, bytes_up=up, bytes_down=down)

    async def _open(self, d: EgressDecision, port: int, ctx, host: str | None = None):
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(d.pinned_ip, port, ssl=ctx, server_hostname=host if ctx else None),
                self._ct)
        except (TimeoutError, OSError, ssl.SSLError) as e:
            raise _BadRequest(502, f"upstream connect failed: {type(e).__name__}") from None

    # -- forward: broker originates TLS, injects credentials --
    async def _forward(self, r, w, method: str, target: str, headers, event: dict) -> None:
        u = urlsplit(target)
        if u.scheme not in ("http", "https") or not u.hostname:
            raise _BadRequest(400, "proxy requests must use absolute-form URLs")
        if u.username or u.password:
            raise _BadRequest(400, "credentials in URL are not allowed")
        host, port = u.hostname, u.port or 443
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        clen = 0
        for n, v in headers:
            if n.lower() == "content-length":
                if not v.isdigit():
                    raise _BadRequest(400, "bad Content-Length")
                clen = int(v)
        if clen > MAX_BODY:
            raise _BadRequest(413, "request body too large")
        try:
            body = await asyncio.wait_for(r.readexactly(clen), 30) if clen else b""
        except (asyncio.IncompleteReadError, TimeoutError):
            raise _BadRequest(400, "incomplete body") from None

        fwd = {n: v for n, v in headers if n.lower() not in HOP_BY_HOP}
        d = self._broker.evaluate(EgressRequest(
            method, host, port, path, fwd, body.decode("latin-1")))
        event.update(d.audit)
        if not d.allowed:
            raise _BadRequest(403, d.reason)

        up_r, up_w = await self._open(d, port, self._ssl, host)
        head = [f"{method} {path} HTTP/1.1", f"Host: {u.netloc.rsplit('@', 1)[-1]}",
                "Connection: close", f"Content-Length: {len(body)}"]
        head += [f"{n}: {v}" for n, v in d.headers.items()]
        # CRLF in an injected value would let a secret smuggle headers; refuse outright.
        if any(("\r" in x or "\n" in x) for x in head):
            up_w.close()
            raise _BadRequest(400, "illegal control characters in headers")
        up_w.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)
        await up_w.drain()

        chunks, total = [], 0
        while True:
            chunk = await asyncio.wait_for(up_r.read(65536), self._idle)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_RESPONSE:
                up_w.close()
                raise _BadRequest(502, "upstream response too large")
            chunks.append(chunk)
        up_w.close()
        resp = b"".join(chunks)
        # Redact echoed secrets with same-length filler so Content-Length stays valid.
        for name in d.audit.get("secrets_used", []):
            val = self._broker.secret_value(name)
            if val:
                resp = resp.replace(val.encode(), b"*" * len(val))
        w.write(resp)
        await w.drain()
        status = int(resp[9:12]) if resp[:5] == b"HTTP/" and resp[9:12].isdigit() else 0
        event.update(status=status, bytes_down=len(resp), bytes_up=len(body))
