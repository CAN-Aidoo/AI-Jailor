#!/usr/bin/env python3
"""Two-party private set intersection (PSI): a REFERENCE DEMO of a workload that runs on a peer link.

One party (the receiver) learns which of ITS items are also in the other party's set; the other
(the sender) learns nothing about the receiver's items beyond how many there are. Neither learns the
other's non-matching items. See examples/psi/README.md for how to run it across two cells.

Protocol (DDH-based, semi-honest; Meadows 1986 / Huberman-Franklin-Hogg 1999), in the 2048-bit
RFC 3526 group, order-q subgroup of quadratic residues, p = 2q + 1:
    receiver -> sender : { H(x)^a        for x in X }                     (in X's order)
    sender   -> receiver: { (H(x)^a)^b   for each of those }              (same order)
                          sorted { H(s)^b for s in S }                    (order hides nothing)
    receiver computes (H(s)^b)^a for every s and intersects it with its own (H(x)^a)^b values.
H hashes into the subgroup (SHA-512 expanded, then squared), keyed by an agreed context string.

What this is NOT: it is secure only against honest-but-curious parties. A malicious sender can lie
about its set or about the results. It leaks both set sizes. It is not constant-time. And, inherently
to PSI, the receiver may put ANY items in its own set: if the identifiers have little entropy (phone
numbers, e-mail addresses, small ID ranges) a receiver can enumerate every candidate and so learn the
sender's whole set. Use it on high-entropy identifiers, or limit what each side may submit. This is a
demonstration, not a vetted library; for production use a reviewed implementation (for example
OpenMined PSI, or Private Join and Compute).

Pure standard library, so it runs in the stock guest image (no cryptography package there).
"""

import argparse
import hashlib
import json
import secrets
import socket
import struct
import sys
import time

# RFC 3526 group 14 (2048-bit MODP). p = 2^2048 - 2^1984 - 1 + 2^64 * (floor(2^1918 * pi) + 124476).
# tests/peerlink/test_psi.py recomputes it from that formula and checks that p and (p-1)/2 are prime.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74"
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437"
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB"
    "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
    "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
Q = (P - 1) // 2
ELEM_BYTES = 256
VERSION = 1
KIND_BLINDED, KIND_DOUBLE, KIND_SET = 1, 2, 3
HEADER = struct.Struct("!BBI")          # version, kind, element count
DEFAULT_MAX_ITEMS = 50_000


class PsiError(Exception):
    """The peer sent something that is not a valid protocol message, or the stream failed."""


def hash_to_group(context: bytes, item: bytes) -> int:
    """Map an item to a quadratic residue (an element of the order-q subgroup), unpredictably."""
    seed = hashlib.sha512(b"aijailer-psi-v1\x00" + len(context).to_bytes(4, "big") + context + item).digest()
    stream = b"".join(hashlib.sha512(seed + bytes([i])).digest() for i in range(5))   # 320 bytes
    v = int.from_bytes(stream, "big") % P
    g = v * v % P
    if g in (0, 1):                      # probability about 2^-2048
        raise PsiError("degenerate hash value")
    return g


def _jacobi(a: int, n: int) -> int:
    """Jacobi symbol (a/n) for odd n > 0: for the prime P it is the Legendre symbol, +1 exactly for
    quadratic residues. Much cheaper than the equivalent a^Q mod P."""
    a %= n
    result = 1
    while a:
        while a % 2 == 0:
            a //= 2
            if n & 7 in (3, 5):
                result = -result
        a, n = n, a
        if a & 3 == 3 and n & 3 == 3:
            result = -result
        a %= n
    return result if n == 1 else 0


def valid_element(v: int) -> bool:
    """In the order-q subgroup and not the identity: rejects 0, 1, p-1 and every non-residue, which
    is what stops a peer from sending small-order elements to learn bits of our key."""
    return 1 < v < P - 1 and _jacobi(v, P) == 1


def random_key() -> int:
    return secrets.randbelow(Q - 2) + 2


# ---------------------------------------------------------------- framing
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()
    while len(out) < n:
        try:
            chunk = sock.recv(min(1 << 20, n - len(out)))
        except OSError as e:
            raise PsiError(f"connection failed: {e}") from e
        if not chunk:
            raise PsiError("peer closed the connection mid-protocol")
        out += chunk
    return bytes(out)


def send_elements(sock: socket.socket, kind: int, elements: list[int]) -> None:
    sock.sendall(HEADER.pack(VERSION, kind, len(elements))
                 + b"".join(e.to_bytes(ELEM_BYTES, "big") for e in elements))


def recv_elements(sock: socket.socket, kind: int, *, max_count: int, expect: int | None = None) -> list[int]:
    version, got_kind, count = HEADER.unpack(_recv_exact(sock, HEADER.size))
    if version != VERSION or got_kind != kind:
        raise PsiError(f"unexpected message (version {version}, kind {got_kind}, wanted kind {kind})")
    if count > max_count or (expect is not None and count != expect):
        raise PsiError(f"unacceptable element count {count}")
    raw = _recv_exact(sock, count * ELEM_BYTES)
    out = [int.from_bytes(raw[i * ELEM_BYTES:(i + 1) * ELEM_BYTES], "big") for i in range(count)]
    if not all(valid_element(v) for v in out):
        raise PsiError("peer sent an element outside the protocol group")
    return out


def normalise(items) -> list[bytes]:
    """Unique, in first-seen order. Comparison is byte-exact: normalise case/format before calling."""
    seen, out = set(), []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# ---------------------------------------------------------------- the two roles
def run_sender(sock: socket.socket, items, context: bytes, max_items: int = DEFAULT_MAX_ITEMS) -> dict:
    """Holds a set; learns only the receiver's set size."""
    items = normalise(items)
    if len(items) > max_items:
        raise PsiError("own set exceeds the item limit")
    blinded = recv_elements(sock, KIND_BLINDED, max_count=max_items)
    b = random_key()
    send_elements(sock, KIND_DOUBLE, [pow(v, b, P) for v in blinded])
    send_elements(sock, KIND_SET, sorted(pow(hash_to_group(context, s), b, P) for s in items))
    return {"role": "sender", "own_items": len(items), "peer_items": len(blinded)}


def run_receiver(sock: socket.socket, items, context: bytes, max_items: int = DEFAULT_MAX_ITEMS):
    """Learns which of its items the sender also has. Returns (intersection, stats)."""
    items = normalise(items)
    if len(items) > max_items:
        raise PsiError("own set exceeds the item limit")
    a = random_key()
    send_elements(sock, KIND_BLINDED, [pow(hash_to_group(context, x), a, P) for x in items])
    doubled = recv_elements(sock, KIND_DOUBLE, max_count=max_items, expect=len(items))
    theirs = recv_elements(sock, KIND_SET, max_count=max_items)
    mine = {d: x for d, x in zip(doubled, items)}
    matched = {mine[d] for d in (pow(z, a, P) for z in theirs) if d in mine}
    result = [x for x in items if x in matched]
    return result, {"role": "receiver", "own_items": len(items), "peer_items": len(theirs),
                    "intersection": len(result)}


# ---------------------------------------------------------------- command line
def _addr(text: str) -> tuple[str, int]:
    host, _, port = text.rpartition(":")
    return host or "127.0.0.1", int(port)


def _connect(addr, wait: float) -> socket.socket:
    """Retry until the local aijailer-peer listener is up (it listens first, then handshakes)."""
    deadline = time.monotonic() + wait
    while True:
        try:
            return socket.create_connection(addr, timeout=10)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Two-party PSI demo over a local socket (see README).")
    ap.add_argument("--role", required=True, choices=["receiver", "sender"])
    ap.add_argument("--items", required=True, help="file with one item per line")
    ap.add_argument("--context", required=True, help="string both sides agree on, e.g. the peer link id")
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument("--connect", help="HOST:PORT of the local aijailer-peer --listen address")
    where.add_argument("--listen", help="HOST:PORT: accept one connection (to run two copies directly)")
    ap.add_argument("--max-items", type=int, default=DEFAULT_MAX_ITEMS)
    ap.add_argument("--timeout", type=float, default=300.0, help="seconds for the whole exchange")
    ap.add_argument("--connect-wait", type=float, default=30.0)
    args = ap.parse_args(argv)

    with open(args.items, "rb") as f:
        items = [line.strip() for line in f.read().splitlines() if line.strip()]
    ctx = args.context.encode()
    try:
        if args.listen:
            srv = socket.create_server(_addr(args.listen))
            srv.settimeout(args.connect_wait)
            sock, _ = srv.accept()
            srv.close()
        else:
            sock = _connect(_addr(args.connect), args.connect_wait)
        sock.settimeout(args.timeout)
        with sock:
            if args.role == "receiver":
                result, stats = run_receiver(sock, items, ctx, args.max_items)
                for x in result:
                    sys.stdout.buffer.write(x + b"\n")
                sys.stdout.buffer.flush()
            else:
                stats = run_sender(sock, items, ctx, args.max_items)
    except (PsiError, OSError) as e:
        print(json.dumps({"event": "psi_error", "detail": str(e)}), file=sys.stderr)
        return 1
    print(json.dumps({"event": "psi_done", **stats}), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
