"""The reference PSI demo (examples/psi/psi.py): correctness, what each side can and cannot see, how it
treats a hostile peer, and the whole stack: PSI -> aijailer-peer -> real CellProxy + PeerHub -> mutual TLS."""

import asyncio
import importlib.util
import os
import random
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tests.peerlink.test_go_helper import PUBKEY_B64, helper  # noqa: F401  (fixture)
from tests.peerlink.test_hub import LINK, world  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[2]
PSI_PATH = ROOT / "examples" / "psi" / "psi.py"
_spec = importlib.util.spec_from_file_location("psi_demo", PSI_PATH)
psi = importlib.util.module_from_spec(_spec)
sys.modules["psi_demo"] = psi
_spec.loader.exec_module(psi)


# ---------------------------------------------------------------- helpers
class Recorder:
    """Wraps a socket and remembers every byte sent and received (the 'view' of that party)."""

    def __init__(self, sock):
        self.sock, self.sent, self.received = sock, bytearray(), bytearray()

    def sendall(self, data):
        self.sent += data
        self.sock.sendall(data)

    def recv(self, n):
        data = self.sock.recv(n)
        self.received += data
        return data

    def close(self):
        self.sock.close()


def run_pair(receiver_items, sender_items, *, context=b"ctx", sender_context=None, max_items=10_000):
    """Run both roles over a socket pair in threads. Returns (intersection, rstats, sstats, rview, sview)."""
    a, b = socket.socketpair()
    a.settimeout(60)
    b.settimeout(60)
    ra, sb = Recorder(a), Recorder(b)
    out, err = {}, {}

    def sender():
        try:
            out["s"] = psi.run_sender(sb, sender_items, sender_context or context, max_items)
        except Exception as e:  # noqa: BLE001
            err["s"] = e
            b.close()

    t = threading.Thread(target=sender)
    t.start()
    try:
        result, rstats = psi.run_receiver(ra, receiver_items, context, max_items)
    finally:
        t.join(60)
        a.close()
        b.close()
    assert "s" not in err, err
    return result, rstats, out["s"], ra, sb


def frames(buf: bytes):
    """Split a recorded byte stream into (kind, [elements])."""
    out, i = [], 0
    while i < len(buf):
        _, kind, count = psi.HEADER.unpack_from(buf, i)
        i += psi.HEADER.size
        out.append((kind, [int.from_bytes(buf[i + j * 256:i + (j + 1) * 256], "big") for j in range(count)]))
        i += count * 256
    return out


# ---------------------------------------------------------------- the group
def _pi_scaled(bits):
    def arctan_inv(x):
        one = 1 << (bits + 64)
        term, total, n, sign = one // x, one // x, 1, -1
        while term:
            term //= x * x
            n += 2
            total += sign * (term // n)
            sign = -sign
        return total
    return (4 * (4 * arctan_inv(5) - arctan_inv(239))) >> 64


def _probably_prime(n, rounds=12):
    rng = random.Random(1)
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def test_the_group_is_the_rfc3526_2048_bit_safe_prime():
    formula = 2**2048 - 2**1984 - 1 + 2**64 * (_pi_scaled(1918) + 124476)
    assert psi.P == formula                                  # not a typo'd constant
    assert psi.P.bit_length() == 2048
    assert _probably_prime(psi.P) and _probably_prime(psi.Q)  # safe prime: q = (p-1)/2 is prime too


def test_hash_to_group_stays_in_the_subgroup_and_is_domain_separated():
    h = psi.hash_to_group(b"c1", b"item")
    assert psi.valid_element(h) and h == psi.hash_to_group(b"c1", b"item")
    assert h != psi.hash_to_group(b"c2", b"item")            # the context separates sessions
    assert h != psi.hash_to_group(b"c1", b"item2")
    # no ambiguity between (context, item) splits
    assert psi.hash_to_group(b"ab", b"c") != psi.hash_to_group(b"a", b"bc")


def test_valid_element_rejects_the_small_subgroup_and_non_residues():
    nonresidue = next(v for v in range(2, 100) if pow(v, psi.Q, psi.P) != 1)
    for bad in (0, 1, psi.P - 1, psi.P, psi.P + 5, -4, nonresidue):
        assert not psi.valid_element(bad)
    assert psi.valid_element(4)                              # 2^2: a quadratic residue


def test_the_fast_membership_check_agrees_with_the_definition():
    """valid_element uses a Jacobi symbol; the definition is v^q == 1 (mod p). They must never differ."""
    rng = random.Random(3)
    samples = [0, 1, 2, 3, 4, 5, psi.P - 2, psi.P - 1, psi.P, psi.P + 1] + \
              [rng.randrange(psi.P) for _ in range(60)] + [pow(rng.randrange(2, psi.P), 2, psi.P) for _ in range(60)]
    for v in samples:
        by_definition = 1 < v < psi.P - 1 and pow(v, psi.Q, psi.P) == 1
        assert psi.valid_element(v) == by_definition, v
    assert sum(psi.valid_element(v) for v in samples[10:70]) in range(15, 45)   # about half are residues


# ---------------------------------------------------------------- correctness
CASES = {
    "overlap": ([b"alice", b"bob", b"carol", b"dave"], [b"carol", b"erin", b"bob", b"frank"], [b"bob", b"carol"]),
    "disjoint": ([b"a", b"b"], [b"c", b"d"], []),
    "identical": ([b"x", b"y", b"z"], [b"z", b"y", b"x"], [b"x", b"y", b"z"]),
    "receiver empty": ([], [b"a"], []),
    "sender empty": ([b"a"], [], []),
    "both empty": ([], [], []),
    "duplicates collapse": ([b"a", b"a", b"b"], [b"a", b"a", b"c"], [b"a"]),
    "binary and unicode": ([b"\x00\xff", "naïve ☃".encode(), b"q"], ["naïve ☃".encode(), b"\x00\xff"],
                           [b"\x00\xff", "naïve ☃".encode()]),
}


@pytest.mark.parametrize("name", CASES)
def test_the_receiver_learns_exactly_the_intersection(name):
    mine, theirs, expected = CASES[name]
    result, rstats, sstats, *_ = run_pair(mine, theirs)
    assert result == expected                                  # also: in the receiver's own item order
    assert rstats["intersection"] == len(expected)
    assert rstats["peer_items"] == len(set(theirs)) and sstats["peer_items"] == len(set(mine))


def test_a_larger_random_instance():
    rng = random.Random(7)
    universe = [f"id-{i}".encode() for i in range(120)]
    mine, theirs = rng.sample(universe, 50), rng.sample(universe, 50)
    result, *_ = run_pair(mine, theirs)
    assert set(result) == set(mine) & set(theirs) and len(result) == len(set(result))


def test_different_contexts_find_nothing():
    """Both sides must agree on the context (the link id): otherwise nothing matches, nothing breaks."""
    result, *_ = run_pair([b"a", b"b"], [b"a", b"b"], context=b"one", sender_context=b"two")
    assert result == []


# ---------------------------------------------------------------- what each side sees
def test_the_wire_never_carries_items_or_their_plain_hashes():
    mine, theirs = [b"SECRET-RECEIVER-ONLY", b"shared"], [b"SECRET-SENDER-ONLY", b"shared"]
    _, _, _, rview, sview = run_pair(mine, theirs, context=b"ctx")
    wire = bytes(rview.sent + rview.received)
    assert b"SECRET-RECEIVER-ONLY" not in wire and b"SECRET-SENDER-ONLY" not in wire
    elements = {e for _, es in frames(wire) for e in es}
    for item in mine + theirs:                              # nobody ever sends an unblinded H(item)
        assert psi.hash_to_group(b"ctx", item) not in elements


def test_every_run_uses_fresh_keys_so_transcripts_are_unlinkable():
    one = run_pair([b"a", b"b"], [b"a", b"b"])
    two = run_pair([b"a", b"b"], [b"a", b"b"])
    first, second = frames(bytes(one[3].sent)), frames(bytes(two[3].sent))
    assert set(first[0][1]).isdisjoint(second[0][1])         # same items, different blinding


def test_the_senders_set_is_sent_sorted_so_its_order_leaks_nothing():
    theirs = [f"s{i}".encode() for i in range(40)]
    _, _, _, rview, _ = run_pair([b"s3"], theirs)
    kinds = frames(bytes(rview.received))
    assert [k for k, _ in kinds] == [psi.KIND_DOUBLE, psi.KIND_SET]
    members = kinds[1][1]
    assert members == sorted(members) and len(members) == 40


def test_only_the_receiver_learns_the_result_the_sender_sees_sizes_only():
    _, rstats, sstats, *_ = run_pair([b"a", b"b", b"c"], [b"c", b"d"])
    assert "intersection" not in sstats and sstats == {"role": "sender", "own_items": 2, "peer_items": 3}


# ---------------------------------------------------------------- hostile peers
def feed(role, payload: bytes, *, max_items=100, items=(b"a", b"b")):
    """Run one role against a 'peer' that sends exactly `payload` and then closes."""
    a, b = socket.socketpair()
    a.settimeout(10)

    def peer():
        try:
            b.sendall(payload)
            b.shutdown(socket.SHUT_WR)
            while b.recv(65536):
                pass
        except OSError:
            pass
        finally:
            b.close()
    t = threading.Thread(target=peer)
    t.start()
    try:
        fn = psi.run_sender if role == "sender" else psi.run_receiver
        return fn(a, list(items), b"ctx", max_items)
    finally:
        a.close()
        t.join(10)


def frame(kind, elements, version=1, count=None):
    return psi.HEADER.pack(version, kind, len(elements) if count is None else count) + b"".join(
        e.to_bytes(256, "big") for e in elements)


GOOD = psi.hash_to_group(b"x", b"y")
NONRESIDUE = next(v for v in range(2, 100) if pow(v, psi.Q, psi.P) != 1)


@pytest.mark.parametrize("bad", [0, 1, psi.P - 1, NONRESIDUE], ids=["zero", "identity", "minus-one", "non-residue"])
def test_the_sender_refuses_elements_outside_the_group(bad):
    with pytest.raises(psi.PsiError, match="outside the protocol group"):
        feed("sender", frame(psi.KIND_BLINDED, [GOOD, bad]))


def test_the_receiver_refuses_bad_elements_in_either_reply():
    with pytest.raises(psi.PsiError, match="outside the protocol group"):
        feed("receiver", frame(psi.KIND_DOUBLE, [GOOD, 1]))
    with pytest.raises(psi.PsiError, match="outside the protocol group"):
        feed("receiver", frame(psi.KIND_DOUBLE, [GOOD, GOOD]) + frame(psi.KIND_SET, [GOOD, psi.P - 1]))


def test_counts_are_bounded_before_any_allocation():
    with pytest.raises(psi.PsiError, match="element count"):
        feed("sender", psi.HEADER.pack(1, psi.KIND_BLINDED, 10**9))           # claims a billion elements
    with pytest.raises(psi.PsiError, match="element count"):
        feed("sender", frame(psi.KIND_BLINDED, [GOOD] * 5), max_items=4)


def test_the_receiver_insists_on_one_reply_per_item_it_sent():
    with pytest.raises(psi.PsiError, match="element count"):
        feed("receiver", frame(psi.KIND_DOUBLE, [GOOD]) + frame(psi.KIND_SET, []))     # sent 2 items, got 1 back


def test_wrong_version_wrong_kind_and_truncation_are_errors_not_crashes():
    with pytest.raises(psi.PsiError, match="unexpected message"):
        feed("sender", frame(psi.KIND_BLINDED, [GOOD], version=9))
    with pytest.raises(psi.PsiError, match="unexpected message"):
        feed("sender", frame(psi.KIND_SET, [GOOD]))
    with pytest.raises(psi.PsiError, match="closed"):
        feed("sender", frame(psi.KIND_BLINDED, [GOOD], count=3))                  # promises 3, sends 1
    with pytest.raises(psi.PsiError, match="closed"):
        feed("receiver", b"")


def test_a_set_bigger_than_the_limit_is_refused_locally():
    with pytest.raises(psi.PsiError, match="item limit"):
        psi.run_sender(object(), [b"a", b"b", b"c"], b"c", max_items=2)


# ---------------------------------------------------------------- the whole stack
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_psi_between_two_cells_over_a_real_peer_link(helper, world, tmp_path):  # noqa: F811
    """Each side: aijailer-peer --listen (attested mutual TLS via the platform relay) + psi.py on localhost."""
    files = {"cell-a": tmp_path / "a.txt", "cell-b": tmp_path / "b.txt"}
    files["cell-a"].write_text("\n".join(["alice", "bob", "carol", "dave", "naïve ☃"]) + "\n")
    files["cell-b"].write_text("\n".join(["carol", "erin", "bob", "frank", "naïve ☃"]) + "\n")
    roles = {"cell-a": "receiver", "cell-b": "sender"}

    def side(cell):
        port = _free_port()
        env = {"PATH": os.environ["PATH"], "HTTPS_PROXY": f"http://127.0.0.1:{world.proxies[cell].port}",
               "AIJAILER_PEER_ATTEST_PUBKEY": PUBKEY_B64}
        peer = subprocess.Popen([helper, "--link", LINK, "--listen", f"127.0.0.1:{port}", "--wait", "20s"],
                                env=env, stderr=subprocess.PIPE)
        try:
            app = subprocess.run(
                [sys.executable, "-I", str(PSI_PATH), "--role", roles[cell], "--items", str(files[cell]),
                 "--context", LINK, "--connect", f"127.0.0.1:{port}", "--timeout", "60"],
                capture_output=True, timeout=90)
            peer_rc = peer.wait(timeout=30)
            return app.returncode, app.stdout, app.stderr.decode(), peer_rc, peer.stderr.read().decode()
        finally:
            if peer.poll() is None:
                peer.kill()

    ra, rb = await asyncio.gather(asyncio.to_thread(side, "cell-a"), asyncio.to_thread(side, "cell-b"))
    assert (ra[0], ra[3], rb[0], rb[3]) == (0, 0, 0, 0), (ra, rb)
    assert ra[1].decode().splitlines() == ["bob", "carol", "naïve ☃"]     # the receiver learns the overlap...
    assert rb[1] == b""                                                    # ...the sender prints nothing
    assert '"intersection": 3' in ra[2] and '"intersection"' not in rb[2]
    assert '"peer_items": 5' in rb[2]
