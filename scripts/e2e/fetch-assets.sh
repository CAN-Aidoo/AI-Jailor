#!/usr/bin/env bash
# Fetch pinned, checksum-verified Firecracker + jailer + a guest kernel into DIR.
#   scripts/e2e/fetch-assets.sh /opt/aijailer-assets
# Layout produced: DIR/bin/firecracker  DIR/bin/jailer  DIR/vmlinux
# Everything is verified against SHA-256 before use; nothing is executed from a download here.
set -euo pipefail
DIR="${1:?usage: fetch-assets.sh DIR}"
FC_VERSION="v1.12.1"
FC_TGZ_SHA256="0a75e67ef6e4c540a2cf248b06822b0be9820cbba9fe19f9e0321200fe76ff6b"   # x86_64
KERNEL_URL="https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/vmlinux-6.1.128"
KERNEL_SHA256="27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8"
[ "$(uname -m)" = "x86_64" ] || { echo "this script pins x86_64 artifacts" >&2; exit 1; }
mkdir -p "$DIR/bin" "$DIR/.dl"
tmp="$DIR/.dl"
fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
check() { echo "$2  $1" | sha256sum -c - >/dev/null || { echo "CHECKSUM MISMATCH: $1" >&2; exit 1; }; }

fetch "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VERSION}/firecracker-${FC_VERSION}-x86_64.tgz" "$tmp/fc.tgz"
check "$tmp/fc.tgz" "$FC_TGZ_SHA256"
tar -xzf "$tmp/fc.tgz" -C "$tmp" --strip-components=1 \
  "release-${FC_VERSION}-x86_64/firecracker-${FC_VERSION}-x86_64" "release-${FC_VERSION}-x86_64/jailer-${FC_VERSION}-x86_64"
install -m 0755 "$tmp/firecracker-${FC_VERSION}-x86_64" "$DIR/bin/firecracker"
install -m 0755 "$tmp/jailer-${FC_VERSION}-x86_64" "$DIR/bin/jailer"

fetch "$KERNEL_URL" "$tmp/vmlinux"
check "$tmp/vmlinux" "$KERNEL_SHA256"
install -m 0644 "$tmp/vmlinux" "$DIR/vmlinux"      # must be world-readable: the jailed VMM user reads it
rm -rf "$tmp"
echo "ok: $("$DIR/bin/firecracker" --version | head -1), $("$DIR/bin/jailer" --version | head -1), kernel $(basename "$KERNEL_URL")"
