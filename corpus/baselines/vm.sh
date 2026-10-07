#!/bin/sh
# Boot one baseline job in a rootless QEMU/KVM guest and unpack what it wrote.
#
# Usage: corpus/baselines/vm.sh JOB_DIR OUT_DIR [EVIDENCE]
#   JOB_DIR   the job's input (job.sh, job.env, recipe/, ...); packed into a tar, symlinks
#             followed, and attached read-only as /dev/vdc
#   OUT_DIR   where the job's /work/out is unpacked (must not exist; under images/)
#   EVIDENCE  the image copy the job reads, attached with readonly=on as /dev/vdb
# The disks and the guest side are described in corpus/baselines/guest/init. The serial log goes
# to OUT_DIR/console.log and, while the job runs, to stdout.
#
# Environment:
#   MEM       guest memory in MiB (default 2048)
#   SMP       guest CPUs (default 2)
#   TIMEOUT   seconds before the VM is killed (default 3600)
#   WORK_SIZE size of the sparse work disk (default 8G); the output disk has the same size
#   QEMU      the emulator (default qemu-system-x86_64 from PATH)
#   VM_DIR, KVER as in corpus/vm/run_scenario.sh; BASELINES_DIR (default <repo>/images/baselines)
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
VM=${VM_DIR:-$REPO/images/vm}
WORK=${BASELINES_DIR:-$REPO/images/baselines}
KVER=${KVER:-7.0.0-31-generic}
QEMU=${QEMU:-qemu-system-x86_64}
[ $# -ge 2 ] || { echo "usage: vm.sh JOB_DIR OUT_DIR [EVIDENCE]" >&2; exit 2; }
JOB=$1 OUT=$2 EVIDENCE=${3:-}

case $(cd "$(dirname "$OUT")" 2>/dev/null && pwd)/ in
    "$REPO"/images/*) ;;
    *) echo "vm.sh: OUT_DIR must lie under $REPO/images/" >&2; exit 1 ;;
esac
[ ! -e "$OUT" ] || { echo "vm.sh: $OUT exists" >&2; exit 1; }
[ -r "$WORK/toolchain.img" ] || { echo "vm.sh: no toolchain disk; run build.sh" >&2; exit 1; }
[ -r "$VM/initramfs.cpio.gz" ] || { echo "vm.sh: run corpus/vm/build_initramfs.sh" >&2; exit 1; }
command -v "$QEMU" >/dev/null || { echo "vm.sh: $QEMU not found; install QEMU" >&2; exit 1; }
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "vm.sh: no read/write access to /dev/kvm" >&2; exit 1; }

# the corpus initramfs plus a second archive with /baseline_init: the kernel unpacks both
D=$(mktemp -d "$WORK/job.XXXXXX")
trap 'rm -rf "$D"' EXIT
mkdir "$D/init"
cp "$HERE/guest/init" "$D/init/baseline_init"
chmod 755 "$D/init/baseline_init"
(cd "$D/init" && echo baseline_init | cpio -o -H newc --quiet) | gzip -1 > "$D/init.cpio.gz"
cat "$VM/initramfs.cpio.gz" "$D/init.cpio.gz" > "$D/initramfs.cpio.gz"

tar -chf "$D/in.tar" -C "$JOB" .
truncate -s "${WORK_SIZE:-8G}" "$D/work.img" "$D/out.raw"
"$REPO/corpus/vm/pinned.sh" mkfs.btrfs -q -f "$D/work.img"
if [ -z "$EVIDENCE" ]; then
    EVIDENCE=$D/empty.img
    truncate -s 4096 "$EVIDENCE"
fi
# the guest refuses to run a tool unless /dev/vdb is read-only (guest/job.sh)
ro=format=raw,if=virtio,readonly=on
mkdir -p "$OUT"
timeout "${TIMEOUT:-3600}" "$QEMU" \
    -nic none -enable-kvm -cpu host -m "${MEM:-2048}" -smp "${SMP:-2}" -nographic -no-reboot \
    -kernel "$VM/kernel/boot/vmlinuz-$KVER" -initrd "$D/initramfs.cpio.gz" \
    -append "console=ttyS0 quiet panic=-1 rdinit=/baseline_init" \
    -drive "file=$WORK/toolchain.img,$ro" \
    -drive "file=$EVIDENCE,$ro" \
    -drive "file=$D/in.tar,$ro" \
    -drive "file=$D/work.img,format=raw,if=virtio" \
    -drive "file=$D/out.raw,format=raw,if=virtio" | tee "$D/console.log"

grep -q '^=== OUTPUT-WRITTEN' "$D/console.log" || {
    cp "$D/console.log" "$OUT/vm-console.log"
    echo "vm.sh: the job wrote no output, see $OUT/vm-console.log" >&2; exit 1; }
tar -xf "$D/out.raw" -C "$OUT"
chmod -R u+rwX "$OUT"
cp "$D/console.log" "$OUT/vm-console.log"
exit "$(cat "$OUT/job-status")"
