#!/bin/sh
# Environment record for an experiment (plan.md §7), one "key: value" per line.
#
# Usage: experiments/env.sh [IMAGE...]
# Reads only; prints the SHA-256 of every IMAGE given. Run from any directory.
set -eu

REPO=$(cd "$(dirname "$0")/.." && pwd)
VM=$REPO/images/vm

echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "host_cpu: $(sed -n 's/^model name[[:space:]]*: //p' /proc/cpuinfo | head -n 1)"
echo "host_logical_cpus: $(nproc)"
echo "host_ram: $(awk '/^MemTotal/ {printf "%.1f GiB", $2 / 1048576}' /proc/meminfo)"

source=$(df --output=source "$REPO/images" | tail -n 1)
fstype=$(df --output=fstype "$REPO/images" | tail -n 1)
disk=$(lsblk -no PKNAME "$source" 2>/dev/null | head -n 1)
if [ -n "$disk" ]; then
    model=$(lsblk -dno MODEL "/dev/$disk" | sed 's/[[:space:]]*$//')
    rotational=$(lsblk -dno ROTA "/dev/$disk" | tr -d ' ')
    echo "images_storage: $source ($fstype) on /dev/$disk, model $model, rotational $rotational"
else
    echo "images_storage: $source ($fstype)"
fi
echo "host_kernel: $(uname -r)"

qemu=${QEMU:-qemu-system-x86_64}
if command -v "$qemu" >/dev/null; then
    echo "qemu: $("$qemu" --version | head -n 1) (host)"
else
    echo "qemu: not installed"
fi
echo "guest_kernel: $(ls "$VM/kernel/boot" 2>/dev/null | sed -n 's/^vmlinuz-//p' | head -n 1)"
# Images are formatted by the pinned mkfs (corpus/vm/pinned.sh), not by the host's btrfs-progs.
pinned=$REPO/corpus/vm/pinned.sh
if "$pinned" mkfs.btrfs --version >/dev/null 2>&1; then
    echo "mkfs_btrfs_progs: $("$pinned" mkfs.btrfs --version | head -n 1) (pinned)"
    echo "guest_btrfs_progs: $("$pinned" btrfs --version | head -n 1) (pinned)"
else
    echo "mkfs_btrfs_progs: pinned bundle not fetched (corpus/vm/fetch_vm.sh)"
    echo "guest_btrfs_progs: pinned bundle not fetched (corpus/vm/fetch_vm.sh)"
fi
echo "host_btrfs_progs: $(btrfs --version 2>/dev/null | head -n 1 || true) (dump-tree oracle only)"
echo "guest_lock_sha256: $(sha256sum "$REPO/corpus/vm/guest.lock" | cut -d ' ' -f 1)"

echo "python: $(cd "$REPO" && uv run python -c 'import sys; print(sys.version.split()[0])')"
echo "uv: $(uv --version)"
echo "uv_lock_sha256: $(sha256sum "$REPO/uv.lock" | cut -d ' ' -f 1)"
echo "git_commit: $(git -C "$REPO" rev-parse HEAD)"
dirty=$(git -C "$REPO" status --porcelain --untracked-files=no | wc -l | tr -d ' ')
echo "git_dirty_tracked_files: $dirty"
for image in "$@"; do
    echo "image_sha256: $(sha256sum "$image" | cut -d ' ' -f 1)  $image"
done
