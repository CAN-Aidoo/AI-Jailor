#!/usr/bin/env bash
# Build the guest root filesystem used by the KVM end-to-end test.
#   sudo scripts/e2e/build-rootfs.sh OUT_DIR [AGENT_BINARY]
# Produces OUT_DIR/tree (unpacked rootfs, useful for chroot checks) and OUT_DIR/base-e2e.ext4.
# Base: Firecracker's own CI rootfs (Ubuntu 24.04, checksum pinned). Added: the AI Jailer guest agent
# as /sbin/aijailer-agent (the kernel cmdline sets init=/sbin/aijailer-agent) and an unprivileged
# `agent` user (uid 1000). Needs root (preserves ownership), unsquashfs, mkfs.ext4.
set -euo pipefail
OUT="${1:?usage: build-rootfs.sh OUT_DIR [AGENT_BINARY]}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AGENT="${2:-$HERE/../../guest-agent/dist/aijailer-agent}"
URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/ubuntu-24.04.squashfs"
SHA256="88821a26b5a38c92b84a064d452167d7f80f9e17cf4441d1ebbae7569e340aee"
SIZE_MB="${ROOTFS_SIZE_MB:-1024}"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ -x "$AGENT" ] || { echo "agent not built: make -C guest-agent build" >&2; exit 1; }
mkdir -p "$OUT"; cd "$OUT"
[ -f ubuntu.squashfs ] || curl -fsSL --retry 3 -o ubuntu.squashfs "$URL"
echo "$SHA256  ubuntu.squashfs" | sha256sum -c - >/dev/null || { echo "CHECKSUM MISMATCH" >&2; exit 1; }
rm -rf tree && unsquashfs -q -d tree ubuntu.squashfs
install -D -m 0755 "$AGENT" tree/sbin/aijailer-agent
# Peer-link client (PEER_LINKS.md): optional, installed when built next to the agent.
PEER="$(dirname "$AGENT")/aijailer-peer"
[ -x "$PEER" ] && install -D -m 0755 "$PEER" tree/usr/sbin/aijailer-peer
# Unprivileged workload user. The agent refuses to run workloads as uid 0. The uid must be FREE in the
# base image: the CI rootfs already has `ubuntu` at 1000, and sharing a uid would hand the workload
# that user's files.
AGENT_UID="${AGENT_UID:-3000}"
if awk -F: -v u="$AGENT_UID" '$3==u || $4==u {f=1} END{exit !f}' tree/etc/passwd tree/etc/group; then
  echo "uid/gid $AGENT_UID is already used in the base image; set AGENT_UID" >&2; exit 1
fi
echo "agent:x:${AGENT_UID}:${AGENT_UID}:agent:/home/agent:/bin/sh" >> tree/etc/passwd
echo "agent:x:${AGENT_UID}:" >> tree/etc/group
echo 'agent:*:19000:0:99999:7:::' >> tree/etc/shadow
install -d -o "$AGENT_UID" -g "$AGENT_UID" -m 0750 tree/home/agent
# Lock every account's password: the CI image ships passwordless/default logins, which would let a
# workload `su` its way to root wherever setuid still works. Nothing in a cell logs in.
sed -i -E 's/^([^:]+):[^:]*:/\1:*:/' tree/etc/shadow
# SECURITY_MODEL: no setuid/setgid binaries in base images (defence in depth next to no_new_privs).
find tree -xdev -type f \( -perm -4000 -o -perm -2000 \) -print -exec chmod a-s {} + > setuid-stripped.txt
echo "stripped setuid/setgid from $(wc -l < setuid-stripped.txt) files (list: $OUT/setuid-stripped.txt)"
install -d -m 0755 tree/proc tree/sys tree/dev tree/tmp tree/run
: > tree/etc/resolv.conf        # no DNS in the cell: names are resolved by the broker
rm -f base-e2e.ext4
truncate -s "${SIZE_MB}M" base-e2e.ext4
mkfs.ext4 -q -F -L aijailer -d tree base-e2e.ext4
echo "ok: $OUT/base-e2e.ext4 ($(du -h base-e2e.ext4 | cut -f1) used), tree in $OUT/tree"
