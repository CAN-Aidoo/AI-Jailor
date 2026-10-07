# Whole-path end-to-end (KVM host runbook)

Needs a Linux host with `/dev/kvm` (rw), root, `nft`, `unshare`, `mkfs.ext4`, `squashfs-tools`, python deps (`pip install -e .[dev]`).

```bash
scripts/e2e/fetch-assets.sh  /opt/aij/assets      # sha256-pinned Firecracker, jailer, kernel
scripts/e2e/build-rootfs.sh  /opt/aij/guest       # needs the guest agent: make -C guest-agent build
export AIJAILER_REAL_FC_DIR=/opt/aij/assets AIJAILER_GUEST_DIR=/opt/aij/guest
export AIJAILER_GUEST_TREE=/opt/aij/guest/tree

pytest tests/e2e/test_full_path.py -k dryrun -v   # no KVM: real guest userland + agent, real everything else
pytest tests/e2e/test_full_path.py -k kvm -v      # real jailed microVM boot
pytest tests/engine/test_real_jailer.py tests/e2e/test_guest_userland.py -v
```

The KVM test additionally asserts: agent is PID 1, `ip=` boot arg applied, `eth0` up with default route,
base image hash unchanged, no leftover VMM process or jail directory.

## Verified without KVM (this repo's CI sandbox)
Real jailer + Firecracker up to guest start (privilege drop, namespaces, seccomp, config accepted, teardown);
real guest userland + agent hardening; the whole control plane (DB, policy, nft, netns, shaping, broker, secrets,
reconciler restart/adopt) via the dry run.

## Only a KVM host can confirm
Kernel boot of the agent as PID 1, vsock agent channel, TAP traffic from a real VMM, snapshot/restore
(`restore_vm` is not implemented), KVM-mode timings. Treat these as unverified until the `-k kvm` test passes.
