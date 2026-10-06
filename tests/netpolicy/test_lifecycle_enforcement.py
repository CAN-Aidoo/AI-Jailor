"""Real-kernel lifecycle test: CellNetwork provisioning/teardown against real nftables,
real links (veth stand-in for TAP) and the real proxy, observed from inside a cell netns."""

import json
import pathlib
import subprocess

import pytest

from tests.netpolicy.test_netns_enforcement import _can_run

HARNESS = pathlib.Path(__file__).with_name("lifecycle_harness.py")
pytestmark = pytest.mark.skipif(_can_run() is not None, reason=_can_run() or "")


@pytest.fixture(scope="module")
def r():
    p = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True,
                       text=True, timeout=180)
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={p.stdout}\nSTDERR={p.stderr}"
    return json.loads(line[len("RESULT"):])


def test_provisioned_cell_can_use_broker_with_injected_credentials(r):
    assert r["env_proxy"] is True
    assert "HTTP/1.1 200 OK" in r["allowed_call"] and "echo:ok" in r["allowed_call"], r["allowed_call"]
    assert r["upstream_saw_secret"] and r["cell_never_saw_secret"]
    assert " 403 " in r["denied_call"] and "echo:ok" not in r["denied_call"]


def test_provisioned_cell_cannot_bypass_broker(r):
    assert r["direct_upstream_blocked"].startswith("BLOCKED")
    assert r["drift_after_provision"] == []


def test_deprovision_revokes_everything(r):
    assert r["teardown_errors"] == []
    assert r["link_gone"] and r["registry_empty"] and r["drift_after_teardown"] == []


def test_address_reuse_after_clean_teardown(r):
    assert r["address_reused"] is True


def test_failed_provisioning_leaves_nothing_behind(r):
    assert r["failed_provision_raised"] is True
    assert r["failed_provision_clean"] is True


def test_reconcile_removes_leaked_network(r):
    assert r["reconciled"] is True and r["final_drift"] == []
