"""Runs INSIDE `unshare -n`. Drives the REAL jailer + REAL Firecracker binaries with our engine as
far as is possible WITHOUT /dev/kvm: jail layout, privilege drop, namespaces, seccomp, NIC attach
inside the cell namespace, and acceptance of our full configuration by Firecracker's real API.
InstanceStart is expected to fail (no KVM); everything before it is verified.

Env: REAL_FC_DIR with bin/firecracker, bin/jailer, vmlinux."""
import asyncio
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "src"))

FC = os.environ["REAL_FC_DIR"]
WORK = tempfile.mkdtemp(prefix="fcj")
os.makedirs(f"{WORK}/rootfs")
subprocess.run(["truncate", "-s", "16M", f"{WORK}/rootfs/base.ext4"], check=True)
subprocess.run(["mkfs.ext4", "-q", "-F", f"{WORK}/rootfs/base.ext4"], check=True)
os.environ.update(
    FIRECRACKER_BINARY=f"{FC}/bin/firecracker", JAILER_BINARY=f"{FC}/bin/jailer",
    KERNEL_IMAGE_PATH=f"{FC}/vmlinux", ROOTFS_DIR=f"{WORK}/rootfs",
    JAILER_CHROOT_BASE=f"{WORK}/jail", JAILER_USE_CGROUPS="false", AIJAILER_ENV="dev",
    JAILER_UID="10000", JAILER_GID="10000")
os.chmod(f"{FC}/vmlinux", 0o644)

from aijailer.engine.firecracker import FirecrackerEngine, JAIL_API_SOCK  # noqa: E402
from aijailer.engine.microvm import VMConfig, VMNetwork  # noqa: E402
from aijailer.netpolicy import link  # noqa: E402
from aijailer.netpolicy.nft import CellNet, ifname_for  # noqa: E402


def proc_info(pid):
    st = {}
    for line in open(f"/proc/{pid}/status"):
        k, _, v = line.partition(":")
        st[k] = v.strip()
    return {
        "uid": st["Uid"].split()[0], "gid": st["Gid"].split()[0],
        "cap_eff": st["CapEff"], "seccomp": st["Seccomp"], "nonewprivs": st.get("NoNewPrivs"),
        "nspid": st["NSpid"].split(),
        "netns_same_as_host": os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/self/ns/net"),
        "pidns_same_as_host": os.readlink(f"/proc/{pid}/ns/pid") == os.readlink("/proc/self/ns/pid"),
        "mntns_same_as_host": os.readlink(f"/proc/{pid}/ns/mnt") == os.readlink("/proc/self/ns/mnt"),
    }


def thread_seccomp(pid):
    """Seccomp mode per thread: Firecracker filters each thread, not the process leader."""
    out = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        comm = open(f"/proc/{pid}/task/{tid}/comm").read().strip()
        for line in open(f"/proc/{pid}/task/{tid}/status"):
            if line.startswith("Seccomp:"):
                out[f"{comm}:{tid}"] = line.split()[1]
    return out


def devices_in_netns(pid):
    """Network devices visible to the VMM process (read in ITS namespace via /proc/<pid>/net)."""
    out = []
    for line in open(f"/proc/{pid}/net/dev").read().splitlines()[2:]:
        out.append(line.split(":")[0].strip())
    return sorted(out)


async def main():
    res = {}
    cid = uuid.uuid4()
    net = CellNet(cid, ifname_for(cid), ipaddress.IPv4Address("10.99.0.1"),
                  ipaddress.IPv4Address("10.99.0.2"), 30, 3128)
    info = await asyncio.to_thread(link.setup_link, net, 10000, 10000)
    eng = FirecrackerEngine(kvm_path="/dev/null")        # test-only: skip the /dev/kvm gate
    cfg = VMConfig(cell_id=cid, image="base", vcpus=1, memory_mb=128,
                   network=VMNetwork(info.tap_name, "10.99.0.2", "10.99.0.1", 30, info.netns_path))
    vm = None
    try:
        vm = await eng._launch(cfg)
        res["launch_ok"] = True
    except Exception as exc:
        res["launch_ok"] = False
        res["launch_error"] = str(exc)[:600]
    if vm:
        root = vm["root"]
        res["jail_files"] = sorted(os.listdir(root))
        res["pid_from_pidfile"] = vm["fc_pid"]
        res["proc"] = proc_info(vm["fc_pid"])
        res["vmm_devices"] = devices_in_netns(vm["fc_pid"])
        res["thread_seccomp"] = thread_seccomp(vm["fc_pid"])
        res["api_socket_in_jail"] = os.path.exists(root / JAIL_API_SOCK)
        # Real Firecracker's view of what we configured:
        import httpx
        async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(root / JAIL_API_SOCK)),
                                     base_url="http://localhost") as c:
            inst = (await c.get("/")).json()
            res["instance_state"] = inst.get("state")
            vmcfg = (await c.get("/vm/config")).json()
            res["cfg_boot_source"] = vmcfg.get("boot-source", {})
            res["cfg_drives"] = [d.get("path_on_host") for d in vmcfg.get("drives", [])]
            res["cfg_machine"] = vmcfg.get("machine-config")
            res["cfg_vsock"] = vmcfg.get("vsock")
            res["cfg_nics"] = [(n.get("iface_id"), n.get("host_dev_name")) for n in
                               vmcfg.get("network-interfaces", [])]
        try:
            await vm["api"].start()
            res["start"] = "started"
        except Exception as exc:
            res["start"] = "failed"
            res["start_error"] = str(exc)[:400]
        pid = vm["fc_pid"]
        # --- control-plane restart: a NEW engine has no memory of this VM ---
        eng2 = FirecrackerEngine(kvm_path="/dev/null")
        found = await asyncio.to_thread(eng2._scan_vmms)
        res["restart_scan_finds_vmm"] = found.get(cid) == [pid]
        rep = await eng2.reconcile({cid: {}}, set(), grace=0)     # DB says live, VMM never started
        res["restart_live_not_started"] = {"unresponsive": rep.unresponsive == [cid],
                                           "adopted": bool(rep.adopted)}
        rep = await eng2.reconcile({}, set(), grace=0)            # DB says not live -> orphan
        await asyncio.sleep(0.3)
        res["restart_orphan_killed"] = rep.orphans_killed == [cid] and not rep.errors
        res["restart_orphan_vmm_gone"] = not os.path.exists(f"/proc/{pid}")
        res["restart_orphan_jail_removed"] = not os.path.exists(vm["jail"])
        await eng._teardown(vm)
        await asyncio.sleep(0.3)
        res["vmm_gone"] = not os.path.exists(f"/proc/{pid}")
        res["jail_removed"] = not os.path.exists(vm["jail"])
    await asyncio.to_thread(link.teardown_link, net.ifname)
    shutil.rmtree(WORK, ignore_errors=True)
    print("RESULT" + json.dumps(res, default=str))
    sys.stdout.flush()
    os._exit(0)


asyncio.run(main())
