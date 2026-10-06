"""Whole-system end-to-end scenario.

Dry run (no KVM):  AIJAILER_GUEST_TREE=/opt/guest/tree pytest tests/e2e/test_full_path.py -k dryrun
Real (needs KVM):  AIJAILER_REAL_FC_DIR=/opt/assets AIJAILER_GUEST_DIR=/opt/guest pytest tests/e2e/test_full_path.py -k kvm
See scripts/e2e/README.md. The dry run replaces ONLY the VMM with the real guest agent in the real
guest userland inside the cell namespace; everything else is the production code path."""

import json
import os
import pathlib
import shutil
import subprocess

import pytest

from tests.netpolicy.test_netns_enforcement import _can_run

HARNESS = pathlib.Path(__file__).with_name("full_path_harness.py")
TREE = os.environ.get("AIJAILER_GUEST_TREE", "")
FC = os.environ.get("AIJAILER_REAL_FC_DIR", "")
GUEST = os.environ.get("AIJAILER_GUEST_DIR", "")


def _base_skip() -> str | None:
    if not (shutil.which("nft") and shutil.which("unshare")) or not os.path.exists("/dev/net/tun"):
        return "needs nft, unshare, /dev/net/tun"
    return _can_run()


def run(env_extra: dict) -> dict:
    p = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True, text=True,
                       timeout=600, env={**os.environ, **env_extra})
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={p.stdout[-3000:]}\nSTDERR={p.stderr[-3000:]}"
    return json.loads(line[len("RESULT"):])


def common_checks(r: dict, expect_vm: bool) -> None:
    assert "harness_error" not in r, r.get("harness_error")
    assert r["cell_status"] == "running", r.get("cell_error")
    # guest identity, platform-injected proxy env, tenant env
    user, uid, proxy, e2e = r["guest_basics"]
    assert (user, uid, e2e) == ("agent", "3000", "1") and proxy == r["expected_proxy"]
    # credential injection: upstream saw the secret, guest never did
    assert r["http_allowed"] == {"status": 200, "body": "echo:ok"}, r["http_allowed"]
    assert r["upstream_saw_secret"] is True and r["secret_in_guest"] == 0
    assert r["denied_host"]["status"] == 403
    assert r["unbound_secret_host"]["status"] == 403
    # firewall: only the broker is reachable
    p = r["probe"]
    assert p["broker"] == "OPEN"
    for k in ("host_service", "internet", "host_ssh"):
        assert p[k].startswith("BLOCKED"), (k, p)
    assert p["guest_loopback_upstream"].startswith("BLOCKED")      # guest lo != host lo
    assert all(v.startswith("BLOCKED") for v in r["probe_cell_to_cell"].values()), r["probe_cell_to_cell"]
    # bandwidth set live through the service, enforced and measured (8 Mbit/s)
    assert r["bandwidth_view"] == [8000, 8000, 8000, 8000]
    assert 5.0 <= r["download"]["mbps"] <= 9.8, r["download"]
    assert 4.0 <= r["upload"]["mbps"] <= 9.8, r["upload"]
    # secrets: rotation and revocation apply to the running cell
    assert r["rotated_seen"] is True and r["after_revoke"]["status"] == 403
    # pause/resume
    assert r["exec_while_paused"] == "refused" and r["after_resume"] == "alive"
    # control-plane restart: cut off until adopted, then adopted and working again
    assert r["cut_off_before_sweep"]["broker"].startswith("BLOCKED")
    assert r["sweep"]["adopted"] == 2 and r["sweep"]["broken"] == 0 and not r["sweep"]["errors"]
    assert r["http_after_adopt"] == {"status": 200, "body": "echo:ok"} and r["secret_after_adopt"]
    # teardown leaves nothing
    assert r["leftover_links"] == [] and r["fw_drift"] == [] and r["leftover_vmm"] == []


@pytest.mark.skipif(not TREE or _base_skip() is not None or not shutil.which("unshare"),
                    reason=_base_skip() or "set AIJAILER_GUEST_TREE (scripts/e2e/build-rootfs.sh)")
def test_full_path_dryrun_without_kvm():
    common_checks(run({"E2E_ENGINE": "chroot", "AIJAILER_GUEST_TREE": TREE}), expect_vm=False)


@pytest.mark.skipif(
    not (FC and GUEST and os.path.exists("/dev/kvm") and os.access("/dev/kvm", os.R_OK | os.W_OK))
    or _base_skip() is not None,
    reason="needs /dev/kvm plus AIJAILER_REAL_FC_DIR and AIJAILER_GUEST_DIR")
def test_full_path_on_kvm():
    r = run({"E2E_ENGINE": "firecracker", "REAL_FC_DIR": FC, "AIJAILER_GUEST_DIR": GUEST})
    common_checks(r, expect_vm=True)
    # things only a booted microVM can show
    assert "aijailer-agent" in r["pid1"]                       # our agent really is PID 1
    assert "init=/sbin/aijailer-agent" in r["kernel_cmdline"] and "ip=" in r["kernel_cmdline"]
    assert r["eth0_state"] == "up"
    assert any(row.split()[0] == "eth0" and row.split()[1] == "00000000" for row in r["default_route"])
    assert r["base_sha_before"] == r["base_sha_after"]          # shared base image never written
    assert r["leftover_jails"] == []
