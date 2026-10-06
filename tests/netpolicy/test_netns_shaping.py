"""Real-kernel bandwidth shaping: measured TCP goodput through the actual tbf shapers."""

import json
import os
import pathlib
import subprocess

import pytest

from tests.netpolicy.test_netns_enforcement import _can_run

HARNESS = pathlib.Path(__file__).with_name("shaping_harness.py")
pytestmark = pytest.mark.skipif(
    _can_run() is not None or not os.path.exists("/dev/net/tun"),
    reason=_can_run() or "needs /dev/net/tun")


@pytest.fixture(scope="module")
def r():
    p = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True,
                       text=True, timeout=240)
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={p.stdout}\nSTDERR={p.stderr}"
    return json.loads(line[len("RESULT"):])


def within(measured, limit_mbps, lo=0.7, hi=1.2):
    return limit_mbps * lo <= measured <= limit_mbps * hi


def test_unshaped_link_is_much_faster_than_any_limit(r):
    assert r["unshaped_down_mbps"] > 100 and r["unshaped_up_mbps"] > 100
    assert r["unshaped_readback"] == [None, None]


def test_symmetric_limit_enforced_in_both_directions(r):
    assert r["sym8_readback"] == [8000, 8000]
    assert within(r["sym8_down_mbps"], 8), r["sym8_down_mbps"]
    assert within(r["sym8_up_mbps"], 8), r["sym8_up_mbps"]


def test_asymmetric_limits_and_hot_update(r):
    assert r["asym_readback"] == [4000, 16000]
    assert within(r["asym_down_mbps"], 4), r["asym_down_mbps"]
    assert within(r["asym_up_mbps"], 16), r["asym_up_mbps"]


def test_clearing_one_direction_leaves_the_other_limited(r):
    assert r["up_only_readback"] == [None, 8000]
    assert r["up_only_down_mbps"] > 100          # download unlimited again
    assert within(r["up_only_up_mbps"], 8)       # upload still capped


def test_clearing_both_removes_shaping(r):
    assert r["cleared_readback"] == [None, None]
    assert r["cleared_down_mbps"] > 100 and r["cleared_up_mbps"] > 100
