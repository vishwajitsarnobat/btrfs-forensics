#!/bin/sh
# Boot the stock Ubuntu 7.0 kernel in a rootless QEMU/KVM guest against IMAGE.
# The guest /init mounts /dev/vda, runs the scenario, unmounts, powers off.
#
# Usage: corpus/vm/run_scenario.sh IMAGE
# Environment:
#   SCENARIO    guest scenario name (default s01)
#   MOUNT_OPTS  btrfs mount options (default compress=zstd,commit=5)
#   DISCARD     if non-empty, the virtio disk gets discard=unmap, so guest
#               TRIMs punch holes in the raw file (and btrfs auto-enables
#               discard=async unless MOUNT_OPTS says otherwise)
#   TIMEOUT     seconds before the VM is killed (default 600)
#   QEMU        the emulator (default: qemu-system-x86_64 from PATH; install the
#               distro's QEMU package, any recent version)
#   VM_DIR      tooling directory (default <repo>/images/vm)
#   KVER        guest kernel version (default 7.0.0-31-generic)
# The serial console (ground-truth hashes, "=== SCENARIO-DONE") goes to stdout.
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
VM=${VM_DIR:-$REPO/images/vm}
KVER=${KVER:-7.0.0-31-generic}
IMG=$1
# the guest writes to IMG: refuse the golden evidence image
case $(basename "$IMG") in sandbox.img) echo "refusing to mutate sandbox.img" >&2; exit 1;; esac
SCENARIO=${SCENARIO:-s01}
MOUNT_OPTS=${MOUNT_OPTS-compress=zstd,commit=5}

QEMU=${QEMU:-qemu-system-x86_64}
command -v "$QEMU" >/dev/null || {
    echo "run_scenario.sh: $QEMU not found; install QEMU (x86-64 system emulator)" >&2; exit 1; }
[ -r /dev/kvm ] && [ -w /dev/kvm ] || {
    echo "run_scenario.sh: no read/write access to /dev/kvm" >&2; exit 1; }

# -nic none: no network; -no-reboot + panic=-1: a guest panic ends the run
exec timeout "${TIMEOUT:-600}" "$QEMU" \
    -nic none -enable-kvm -cpu host -m 1024 -nographic -no-reboot \
    -kernel "$VM/kernel/boot/vmlinuz-$KVER" -initrd "$VM/initramfs.cpio.gz" \
    -append "console=ttyS0 quiet panic=-1 scenario=$SCENARIO mountopts=$MOUNT_OPTS" \
    -drive "file=$IMG,format=raw,if=virtio${DISCARD:+,discard=unmap}"
