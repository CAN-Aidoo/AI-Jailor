"""Real-kernel test of the per-cell namespace link (jailer --netns target).

The test process plays the VM: it attaches to the TAP *inside the cell namespace* and sends
raw Ethernet/ARP/TCP frames; the host side runs the real nftables ruleset."""

import json
import os
import pathlib
import subprocess

import pytest

from tests.netpolicy.test_netns_enforcement import _can_run

HARNESS = pathlib.Path(__file__).with_name("netns_link_harness.py")
pytestmark = pytest.mark.skipif(
    _can_run() is not None or not os.path.exists("/dev/net/tun"),
    reason=_can_run() or "needs /dev/net/tun")


@pytest.fixture(scope="module")
def r():
    p = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True,
                       text=True, timeout=180)
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={p.stdout}\nSTDERR={p.stderr}"
    return json.loads(line[len("RESULT"):])


def test_namespace_contains_only_the_cells_devices(r):
    assert r["info"] == ["tap0", True] and r["netns_listed"] is True
    # The VMM sees its TAP, the bridge and the veth peer: no host device, no other cell.
    assert r["netns_devices"] == ["br0", "lo", "tap0", "vc0"]
    assert r["bridge_ports"] == ["tap0", "vc0"] and r["all_up"] is True


def test_tap_is_persistent_and_owned_by_the_jailer_uid(r):
    assert r["tap_owner"] == 10000 and r["tap_persist"] == 1


def test_host_end_addressed_and_hardened(r):
    assert r["host_veth_present"] is True and len(r["host_addr"]) >= 1
    assert r["sysctls"] == ["1", "0", "1"]


def test_guest_frames_reach_host_through_tap_bridge_veth(r):
    assert r["arp_reply"] is True, "L2 path guest->tap->bridge->veth->host is broken"
    assert r["syn_to_broker_answered"] is True


def test_firewall_still_applies_to_traffic_arriving_via_the_namespace(r):
    assert r["syn_to_other_port_answered"] is False
    assert r["spoofed_syn_answered"] is False


def test_teardown_removes_veth_and_namespace_idempotently(r):
    assert r["host_veth_gone"] is True and r["netns_gone"] is True


def test_stale_namespace_recovered_and_failures_roll_back(r):
    assert r["stale_recovered"] is True
    assert r["rollback_tap"] == "clean" and r["rollback_after_veth"] == "clean"
