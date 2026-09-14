#!/bin/sh
# Build images/vm/initramfs.cpio.gz for the scenario guest (no root needed).
#
# Contents: busybox-static (all applets as symlinks), the `btrfs` binary from
# btrfs-progs plus the shared libraries ldd reports for it, the btrfs kernel
# module and its dependencies (zstd-decompressed), corpus/vm/init as /init,
# and every guest scenario body corpus/vm/scenarios/*.guest.sh as
# /scenarios/<name>.sh.
#
# Run fetch_vm.sh first. Re-run this after editing init or a guest scenario.
# Environment: VM_DIR (default <repo>/images/vm), KVER (default 7.0.0-31-generic).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
VM=${VM_DIR:-$REPO/images/vm}
KVER=${KVER:-7.0.0-31-generic}
ROOT=$VM/initramfs

BUSYBOX=$VM/tools/usr/bin/busybox
BTRFS=$(find "$VM/tools" -name btrfs -type f -path '*bin/*' | head -n 1)
[ -x "$BUSYBOX" ] && [ -n "$BTRFS" ] || { echo "run fetch_vm.sh first" >&2; exit 1; }

# Modules: prefer the host's copy, fall back to the unpacked linux-modules deb.
MODDIR=/lib/modules/$KVER
[ -e "$MODDIR/kernel/fs/btrfs/btrfs.ko.zst" ] ||
    MODDIR=$(find "$VM/kernel" -type d -path "*/modules/$KVER" | head -n 1)

rm -rf "$ROOT"
mkdir -p "$ROOT/bin" "$ROOT/lib/modules" "$ROOT/lib/x86_64-linux-gnu" "$ROOT/lib64" \
         "$ROOT/dev" "$ROOT/proc" "$ROOT/sys" "$ROOT/mnt" "$ROOT/tmp" "$ROOT/scenarios"

# busybox + one symlink per applet
cp "$BUSYBOX" "$ROOT/bin/busybox"
for applet in $("$BUSYBOX" --list); do
    [ "$applet" = busybox ] || ln -sf busybox "$ROOT/bin/$applet"
done

# btrfs-progs CLI and its shared libraries (resolved against the host, same distro)
cp "$BTRFS" "$ROOT/bin/btrfs"
for lib in $(ldd "$BTRFS" | awk '$2 == "=>" && $3 ~ /^\// {print $3}'); do
    cp -L "$lib" "$ROOT/lib/x86_64-linux-gnu/"
done
cp -L /lib64/ld-linux-x86-64.so.2 "$ROOT/lib64/"

# btrfs.ko and its dependencies (modinfo -F depends btrfs), load order in init
for mod in xor raid6_pq libblake2b btrfs; do
    src=$(find "$MODDIR" -name "$mod.ko.zst" | head -n 1)
    [ -n "$src" ] || { echo "module $mod not found under $MODDIR" >&2; exit 1; }
    zstd -q -d -f -o "$ROOT/lib/modules/$mod.ko" "$src"
done

cp "$HERE/init" "$ROOT/init"
chmod 755 "$ROOT/init"
for s in "$HERE"/scenarios/*.guest.sh; do
    cp "$s" "$ROOT/scenarios/$(basename "$s" .guest.sh).sh"
done

(cd "$ROOT" && find . | cpio -o -H newc --quiet) | gzip -1 > "$VM/initramfs.cpio.gz"
echo "wrote $VM/initramfs.cpio.gz"
