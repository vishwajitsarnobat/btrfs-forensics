#!/bin/sh
# Fetch the rootless VM tooling into images/vm/ (gitignored). No root needed:
# packages are fetched with `apt-get download` and unpacked with `dpkg -x`.
#
#   images/vm/debs/    QEMU 8.2.2 + firmware + libs  -> unpacked into images/vm/qemu/
#   images/vm/kdeb/    guest kernel image (and modules if the host lacks them)
#                                                    -> unpacked into images/vm/kernel/
#   images/vm/tooldebs busybox-static + btrfs-progs  -> unpacked into images/vm/tools/
#
# Idempotent: a package whose .deb is already present is not downloaded again,
# and a tree that is already unpacked is not unpacked again.
#
# Environment: VM_DIR (default <repo>/images/vm), KVER (default 7.0.0-31-generic).
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
VM=${VM_DIR:-$REPO/images/vm}
KVER=${KVER:-7.0.0-31-generic}

QEMU_PKGS="qemu-system-x86 qemu-system-common qemu-system-data seabios \
libfdt1 libpmem1 librdmacm1t64 libslirp0 libndctl6 libdaxctl1"
TOOL_PKGS="busybox-static btrfs-progs"
KERNEL_PKGS="linux-image-unsigned-$KVER"
# The btrfs module and its deps come from the host's world-readable
# /lib/modules/$KVER when it exists; otherwise fetch the modules package too.
[ -e "/lib/modules/$KVER/kernel/fs/btrfs/btrfs.ko.zst" ] ||
    KERNEL_PKGS="$KERNEL_PKGS linux-modules-$KVER"

# download DIR PKG... : apt-get download each PKG into DIR unless a .deb exists
download() {
    dir=$1; shift
    mkdir -p "$dir"
    for pkg in "$@"; do
        if ls "$dir/${pkg}_"*.deb >/dev/null 2>&1; then
            echo "have  $pkg"
        else
            echo "fetch $pkg"
            (cd "$dir" && apt-get download "$pkg")
        fi
    done
}

# unpack DIR DEST STAMP : dpkg -x every .deb in DIR into DEST unless STAMP exists
unpack() {
    if [ -e "$3" ]; then
        echo "unpacked already: $2"
    else
        mkdir -p "$2"
        for deb in "$1"/*.deb; do dpkg -x "$deb" "$2"; done
    fi
}

download "$VM/debs" $QEMU_PKGS
download "$VM/kdeb" $KERNEL_PKGS
download "$VM/tooldebs" $TOOL_PKGS

unpack "$VM/debs"     "$VM/qemu"   "$VM/qemu/usr/bin/qemu-system-x86_64"
unpack "$VM/kdeb"     "$VM/kernel" "$VM/kernel/boot/vmlinuz-$KVER"
unpack "$VM/tooldebs" "$VM/tools"  "$VM/tools/usr/bin/busybox"

echo "VM tooling ready in $VM"
