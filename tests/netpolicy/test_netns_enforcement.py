"""Real-kernel enforcement tests (network namespaces + veth + nftables).

Needs root/CAP_NET_ADMIN, `unshare`, `nft` and pyroute2; skipped otherwise.
Every assertion is about real packets, not about the generated ruleset text.
"""

import json
import os
import pathlib
import shutil
import subprocess

import pytest

HARNESS = pathlib.Path(__file__).with_name("netns_harness.py")


def _can_run() -> str | None:
    if os.geteuid() != 0:
        return "needs root"
    if not (shutil.which("unshare") and shutil.which("nft")):
        return "needs unshare and nft"
    try:
        import pyroute2  # noqa: F401
    except ImportError:
        return "needs pyroute2"
    r = subprocess.run(["unshare", "-n", "nft", "list", "ruleset"], capture_output=True)
    return None if r.returncode == 0 else "netns+nftables not permitted here"


pytestmark = pytest.mark.skipif(_can_run() is not None, reason=_can_run() or "")


@pytest.fixture(scope="module")
def result():
    r = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True,
                       text=True, timeout=180)
    line = next((ln for ln in r.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={r.stdout}\nSTDERR={r.stderr}"
    return json.loads(line[len("RESULT"):])


def test_cell_reaches_its_broker(result):
    assert result["broker_open"] == "OPEN:broker"


def test_other_host_service_unreachable(result):
    assert result["other_host_port_blocked"].startswith("BLOCKED")


def test_internet_unreachable_even_with_ip_forward_on(result):
    assert result["internet_blocked_forwarding_on"].startswith("BLOCKED")


def test_spoofed_source_ip_dropped(result):
    assert result["spoofed_source_blocked"].startswith("BLOCKED")


def test_cell_to_cell_dropped(result):
    assert result["cell_to_cell_blocked"].startswith("BLOCKED")
    assert result["other_cells_gateway_blocked"].startswith("BLOCKED")


def test_host_cannot_open_new_connections_into_cell(result):
    assert result["host_to_cell_blocked"].startswith("BLOCKED")


def test_ipv6_dropped(result):
    if result["ipv6_blocked"] == "UNAVAILABLE":
        pytest.skip("kernel has no IPv6; covered structurally by test_ruleset_default_deny_shape")
    assert result["ipv6_blocked"].startswith("BLOCKED")


def test_drift_detected_and_repaired(result):
    assert result["drift_clean"] == []
    assert result["drift_after_delete"], "deleting the table must be reported as drift"
    assert result["repaired"] and result["drift_after_repair"] == []
    assert result["broker_open_after_repair"] == "OPEN:broker"


def test_unregister_revokes_access_and_frees_address(result):
    assert result["broker_after_unregister"].startswith("BLOCKED")
    assert result["address_reused_after_release"] is True


def test_e2e_proxy_behind_firewall_injects_credentials(result):
    assert result["e2e_allowed"].startswith("HTTP/1.1 200 OK|echo:ok"), result["e2e_allowed"]
    assert result["e2e_upstream_saw_secret"] is True
    assert result["e2e_cell_never_saw_secret"] is True
    assert " 403 " in result["e2e_denied"].split("|")[0]
    assert result["e2e_audit_has_no_secret"] is True
    assert [e["decision"] for e in result["e2e_audit"]] == ["allow", "deny"]


def test_e2e_cell_cannot_bypass_proxy(result):
    assert result["e2e_direct_upstream_blocked"].startswith("BLOCKED")
    assert result["e2e_proxy_wrong_port_blocked"].startswith("BLOCKED")
