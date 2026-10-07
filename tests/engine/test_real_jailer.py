"""REAL jailer + REAL Firecracker, as far as possible without /dev/kvm.

Enable with:  scripts/e2e/fetch-assets.sh /opt/assets && AIJAILER_REAL_FC_DIR=/opt/assets pytest tests/engine/test_real_jailer.py
(needs root, unshare, mkfs.ext4, /dev/net/tun). Without the assets the tests skip.

What this proves (no KVM needed): our jail layout is what the real jailer expects; the VMM runs as the
unprivileged jailer uid with zero capabilities in its own PID/mount/network namespaces and sees only the
cell's devices; real Firecracker accepts our complete configuration, including attaching to our
persistent TAP inside the cell namespace; teardown leaves nothing. What it cannot prove: booting a
guest (the only failure is KVM: "Error creating KVM object")."""

import json
import os
import pathlib
import shutil
import subprocess

import pytest

from tests.netpolicy.test_netns_enforcement import _can_run

HARNESS = pathlib.Path(__file__).with_name("real_jailer_harness.py")
ASSETS = os.environ.get("AIJAILER_REAL_FC_DIR", "")


def _skip_reason() -> str | None:
    if not ASSETS or not all(os.path.exists(f"{ASSETS}/{p}")
                             for p in ("bin/firecracker", "bin/jailer", "vmlinux")):
        return "set AIJAILER_REAL_FC_DIR (see scripts/e2e/fetch-assets.sh)"
    if not shutil.which("mkfs.ext4") or not os.path.exists("/dev/net/tun"):
        return "needs mkfs.ext4 and /dev/net/tun"
    return _can_run()


pytestmark = pytest.mark.skipif(_skip_reason() is not None, reason=_skip_reason() or "")


@pytest.fixture(scope="module")
def r():
    p = subprocess.run(["unshare", "-n", "python3", str(HARNESS)], capture_output=True, text=True,
                       timeout=180, env={**os.environ, "REAL_FC_DIR": ASSETS})
    line = next((ln for ln in p.stdout.splitlines() if ln.startswith("RESULT")), None)
    assert line, f"harness failed:\nSTDOUT={p.stdout[-3000:]}\nSTDERR={p.stderr[-3000:]}"
    return json.loads(line[len("RESULT"):])


def test_real_jailer_launches_our_jail(r):
    assert r["launch_ok"] is True, r.get("launch_error")
    assert r["jail_files"] == ["api.sock", "dev", "firecracker", "firecracker.pid", "rootfs.ext4",
                               "run", "vmlinux", "vsock.sock"]
    assert r["api_socket_in_jail"] and r["pid_from_pidfile"] > 1


def test_vmm_is_unprivileged_and_namespaced(r):
    p = r["proc"]
    assert (p["uid"], p["gid"]) == ("10000", "10000")
    assert int(p["cap_eff"], 16) == 0                          # no capabilities at all
    assert len(p["nspid"]) == 2 and p["nspid"][-1] == "1"      # PID 1 in its own PID namespace
    assert not p["pidns_same_as_host"] and not p["mntns_same_as_host"]
    assert not p["netns_same_as_host"]


def test_vmm_sees_only_the_cells_network_devices(r):
    assert r["vmm_devices"] == ["br0", "lo", "tap0", "vc0"]    # no host NIC, no other cell


def test_seccomp_filter_is_active_on_the_api_thread(r):
    assert "2" in r["thread_seccomp"].values()


def test_real_firecracker_accepted_our_full_configuration(r):
    assert r["instance_state"] == "Not started"
    assert r["cfg_boot_source"]["kernel_image_path"] == "vmlinux"
    assert "init=/sbin/aijailer-agent" in r["cfg_boot_source"]["boot_args"]
    assert "ip=10.99.0.2::10.99.0.1:255.255.255.252::eth0:off" in r["cfg_boot_source"]["boot_args"]
    assert r["cfg_drives"] == ["rootfs.ext4"]
    assert r["cfg_machine"]["vcpu_count"] == 1 and r["cfg_machine"]["mem_size_mib"] == 128
    assert r["cfg_vsock"] == {"guest_cid": 3, "uds_path": "vsock.sock"}


def test_firecracker_attached_to_our_tap_inside_the_cell_namespace(r):
    # The NIC is created (TAP opened) when configured: acceptance proves the jailer-created
    # /dev/net/tun + persistent, jailer-uid-owned TAP + the --netns join all work together.
    assert r["cfg_nics"] == [["eth0", "tap0"]]


def test_the_only_thing_missing_is_kvm(r):
    assert r["start"] == "failed" and "Error creating KVM object" in r["start_error"]


def test_teardown_leaves_nothing(r):
    assert r["vmm_gone"] is True and r["jail_removed"] is True


def test_reconcile_after_restart_finds_and_reaps_the_real_vmm(r):
    """A fresh engine (no memory) identifies the real jailer-spawned VMM by its argv, refuses to
    adopt one that never started, and kills + cleans it once the cell is no longer live."""
    assert r["restart_scan_finds_vmm"] is True
    assert r["restart_live_not_started"] == {"unresponsive": True, "adopted": False}
    assert r["restart_orphan_killed"] is True
    assert r["restart_orphan_vmm_gone"] is True and r["restart_orphan_jail_removed"] is True
