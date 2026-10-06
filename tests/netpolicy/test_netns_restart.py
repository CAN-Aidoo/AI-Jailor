"""Real-kernel crash/restart recovery: what the reconciler does with resources that survive a
control-plane restart (adopt live cells, delete orphans, spare in-flight and foreign ones)."""

import json
import os
import pathlib
import subprocess

import pytest

from tests.netpolicy.test_netns_enforcement import _can_run

HARNESS = pathlib.Path(__file__).with_name("restart_harness.py")
pytestmark = pytest.mark.skipif(
    _can_run() is not None or not os.path.exists("/dev/net/tun"),
    reason=_can_run() or "needs /dev/net/tun")


@pytest.fixture(scope="module")
def r():
    p = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True,
                       text=True, timeout=300)
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={p.stdout[-3000:]}\nSTDERR={p.stderr[-3000:]}"
    return json.loads(line[len("RESULT"):])


def test_after_restart_but_before_sweep_cells_are_cut_off(r):
    assert r["before_sweep_live1_probe"].startswith("BLOCKED")   # fail closed until adopted


def test_live_cells_adopted_orphans_removed(r):
    assert r["adopted"] and r["orphans_removed"] and r["report_clean"]
    assert r["live_present"] and r["orphans_gone"]


def test_in_flight_and_foreign_resources_untouched(r):
    assert r["protected_untouched"]
    assert r["foreign_veth_untouched"] and r["foreign_netns_untouched"]


def test_adopted_cells_work_again_through_the_firewall(r):
    assert r["after_sweep_live1_broker"] == "OPEN"
    assert r["after_sweep_live2_broker"] == "OPEN"
    assert r["after_sweep_live1_other_port"].startswith("BLOCKED")
    assert r["drift_after_adopt"] == []


def test_bandwidth_limits_reasserted_on_adoption(r):
    assert r["shaping_live1"] == [8000, 8000] and r["shaping_live2"] == [4000, 4000]


def test_no_subnet_collisions_and_idempotent_sweeps(r):
    assert r["new_cell_distinct_subnet"] is True
    assert r["second_sweep_noop"] is True


def test_adopted_cell_is_fully_manageable_and_nothing_leaks(r):
    assert r["adopted_teardown"] is True
    assert r["clean_exit"] is True
