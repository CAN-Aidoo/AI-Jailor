"""The shipped cell-side client (Go, aijailer-peer) against the real CellProxy + PeerHub, with the Python
reference peer and with itself. Skipped when no Go toolchain is available."""

import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from tests.peerlink.peer_client import connect_peer
from tests.peerlink.test_hub import LINK, PUB, SIGNER, connect, world  # noqa: F401  (fixture)

ROOT = Path(__file__).resolve().parents[2]
PUBKEY_B64 = base64.b64encode(PUB.public_bytes(serialization.Encoding.Raw,
                                                serialization.PublicFormat.Raw)).decode()


@pytest.fixture(scope="session")
def helper(tmp_path_factory):
    if shutil.which("go") is None:
        pytest.skip("no Go toolchain")
    out = tmp_path_factory.mktemp("peerbin") / "aijailer-peer"
    r = subprocess.run(["go", "build", "-o", str(out), "./cmd/aijailer-peer"], cwd=ROOT / "guest-agent",
                       env={**os.environ, "CGO_ENABLED": "0"}, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        pytest.fail(f"go build failed: {r.stderr}")
    return str(out)


def events(stderr: str) -> list[dict]:
    return [json.loads(line) for line in stderr.splitlines() if line.startswith("{")]


def run_helper(helper, world, cell, *args, stdin=b"", link=LINK, pubkey=PUBKEY_B64, timeout=30):
    """Blocking: run aijailer-peer --stdio the way a cell would (proxy + pubkey from its environment)."""
    env = {"PATH": os.environ["PATH"], "HTTPS_PROXY": f"http://127.0.0.1:{world.proxies[cell].port}",
           "AIJAILER_PEER_ATTEST_PUBKEY": pubkey}
    p = subprocess.run([helper, "--link", link, "--stdio", "--wait", "10s", *args], input=stdin, env=env,
                       capture_output=True, timeout=timeout)
    return p.returncode, p.stdout, events(p.stderr.decode())




@pytest.mark.asyncio
@pytest.mark.parametrize("go_cell", ["cell-a", "cell-b"])
async def test_go_helper_and_python_reference_peer_talk_in_both_roles(helper, world, go_cell):
    py_cell = "cell-b" if go_cell == "cell-a" else "cell-a"

    def python_side():
        tls, pred = connect_peer("127.0.0.1", world.proxies[py_cell].port, LINK, PUB)
        tls.sendall(b"from-python-" * 5000)
        got = b""
        while c := tls.recv(65536):          # Go half-closes after its stdin ends; read to EOF, then leave
            got += c
        tls.close()
        return got, pred

    go = asyncio.to_thread(run_helper, helper, world, go_cell, stdin=b"from-go-" * 3)
    (code, out, ev), (got, pred) = await asyncio.gather(go, asyncio.to_thread(python_side))
    assert code == 0, ev
    assert out == b"from-python-" * 5000                  # Go -> its stdout, byte for byte (60 KB)
    assert got == b"from-go-" * 3
    est = next(e for e in ev if e["event"] == "established")
    assert est["role"] == ("initiator" if go_cell == "cell-a" else "responder")
    assert est["peer_cell_id"] == py_cell and est["tls"] == "1.3"
    assert pred["peer"]["cell_id"] == go_cell


@pytest.mark.asyncio
async def test_two_go_helpers_through_the_relay_with_a_local_socket_each(helper, world):
    """The realistic shape: the workload speaks plain TCP to localhost; plaintext never leaves the guest."""
    def free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def side(cell, payload):
        port = free_port()
        env = {"PATH": os.environ["PATH"], "HTTPS_PROXY": f"http://127.0.0.1:{world.proxies[cell].port}",
               "AIJAILER_PEER_ATTEST_PUBKEY": PUBKEY_B64}
        p = subprocess.Popen([helper, "--link", LINK, "--listen", f"127.0.0.1:{port}", "--wait", "10s"],
                             env=env, stderr=subprocess.PIPE)
        first = json.loads(p.stderr.readline())
        assert first["event"] == "listening"
        deadline = time.time() + 15
        while True:
            try:
                c = socket.create_connection(("127.0.0.1", port), timeout=5)
                break
            except OSError:
                assert time.time() < deadline
                time.sleep(0.05)
        c.sendall(payload)
        c.shutdown(socket.SHUT_WR)
        got = b""
        c.settimeout(15)
        while chunk := c.recv(65536):
            got += chunk
        c.close()
        rc = p.wait(timeout=15)
        return rc, got

    (rc1, got1), (rc2, got2) = await asyncio.gather(
        asyncio.to_thread(side, "cell-a", b"A->B " * 20000), asyncio.to_thread(side, "cell-b", b"B->A " * 7))
    assert (rc1, rc2) == (0, 0)
    assert got1 == b"B->A " * 7 and got2 == b"A->B " * 20000


@pytest.mark.asyncio
async def test_pinning_a_persistent_identity_works_and_a_wrong_pin_is_refused_with_exit_4(helper, world, tmp_path):
    ida, idb = str(tmp_path / "a.pem"), str(tmp_path / "b.pem")
    ha, hb = str(tmp_path / "a.hash"), str(tmp_path / "b.hash")

    def hashes():                                   # each side creates its stable identity out of band
        for ident, hf in ((ida, ha), (idb, hb)):
            subprocess.run([helper, "--link", LINK, "--stdio", "--identity-file", ident, "--cert-hash-file", hf,
                            "--wait", "1s"],
                           env={"PATH": os.environ["PATH"], "HTTPS_PROXY": "http://127.0.0.1:1",
                                "AIJAILER_PEER_ATTEST_PUBKEY": PUBKEY_B64},
                           capture_output=True, timeout=10)
        return Path(ha).read_text().strip(), Path(hb).read_text().strip()
    pa, pb = await asyncio.to_thread(hashes)         # (these runs fail to reach any proxy, but only AFTER writing the hash)
    assert len(pa) == 64 and pa != pb

    ok = await asyncio.gather(
        asyncio.to_thread(run_helper, helper, world, "cell-a", "--identity-file", ida, "--pin", pb,
                          stdin=b"x"),
        asyncio.to_thread(run_helper, helper, world, "cell-b", "--identity-file", idb, "--pin", pa,
                          stdin=b"y"))
    assert [r[0] for r in ok] == [0, 0]
    assert next(e for e in ok[0][2] if e["event"] == "established")["peer_cert_sha256"] == pb

    bad = await asyncio.gather(
        asyncio.to_thread(run_helper, helper, world, "cell-a", "--identity-file", ida, "--pin", "0" * 64),
        asyncio.to_thread(run_helper, helper, world, "cell-b", "--identity-file", idb, "--pin", pa))
    assert bad[0][0] == 4                            # attestation rejected: the pin did not match


@pytest.mark.asyncio
async def test_refusals_map_to_distinct_exit_codes(helper, world):
    code, _, ev = await asyncio.to_thread(run_helper, helper, world, "cell-a", link="b" * 32)
    assert code == 3 and ev[-1]["event"] == "error"                      # platform refused (unknown link)

    other = base64.b64encode(os.urandom(32)).decode()                    # a key that did not sign it

    def python_peer():                       # its counterpart: must NOT end up with an open channel
        with pytest.raises(OSError):
            connect_peer("127.0.0.1", world.proxies["cell-b"].port, LINK, PUB, timeout=15)
    bad, _ = await asyncio.gather(
        asyncio.to_thread(run_helper, helper, world, "cell-a", pubkey=other),
        asyncio.to_thread(python_peer))
    assert bad[0] == 4

    code, _, _ = await asyncio.to_thread(run_helper, helper, world, "cell-a", pubkey="not-base64!")
    assert code == 2
