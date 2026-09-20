#!/bin/sh
# Fetch the pinned guest bundle into images/vm/ (gitignored). No root and no package manager:
# every package in corpus/vm/guest.lock is downloaded with curl, checked against its SHA-256 and
# unpacked with ar + tar, so the host distribution does not matter.
#
#   images/vm/debs/    the downloaded .deb files
#   images/vm/kernel/  guest kernel image and modules        (lock group `kernel`)
#   images/vm/tools/   busybox, btrfs-progs and their libs    (lock group `tools`)
#
# QEMU is not fetched: run_scenario.sh uses the host's qemu-system-x86_64.
#
# Idempotent: a .deb that is present with the right hash is not downloaded again, and a group is
# unpacked again only when the lock file is newer than its stamp.
#
# Host requirements: curl, sha256sum, ar (binutils), tar with zstd and xz support.
# Environment: VM_DIR (default <repo>/images/vm), UBUNTU_MIRROR (default: the fixed snapshot below;
# any Ubuntu archive root that still carries the pinned versions works).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
VM=${VM_DIR:-$REPO/images/vm}
LOCK=$HERE/guest.lock
MIRROR=${UBUNTU_MIRROR:-https://snapshot.ubuntu.com/ubuntu/20260919T000000Z}

for tool in curl sha256sum ar tar; do
    command -v "$tool" >/dev/null || { echo "fetch_vm.sh needs $tool on the host" >&2; exit 1; }
done

mkdir -p "$VM/debs"
TAB=$(printf '\t')

# hash_ok FILE SHA256
hash_ok() {
    [ -f "$1" ] && [ "$(sha256sum "$1" | cut -d' ' -f1)" = "$2" ]
}

grep -v '^#' "$LOCK" | while IFS=$TAB read -r group sha path; do
    [ -n "$group" ] || continue
    deb=$VM/debs/$(basename "$path")
    if hash_ok "$deb" "$sha"; then
        echo "have  $(basename "$path")"
    else
        echo "fetch $(basename "$path")"
        curl -fsSL --retry 3 -o "$deb.part" "$MIRROR/$path"
        hash_ok "$deb.part" "$sha" || {
            echo "SHA-256 mismatch for $path" >&2; rm -f "$deb.part"; exit 1; }
        mv "$deb.part" "$deb"
    fi
done

# unpack GROUP: extract every .deb of the group into images/vm/GROUP
unpack() {
    dest=$VM/$1
    stamp=$dest/.unpacked
    if [ -e "$stamp" ] && [ "$stamp" -nt "$LOCK" ]; then
        echo "unpacked already: $dest"
        return
    fi
    rm -rf "$dest"
    mkdir -p "$dest"
    grep -v '^#' "$LOCK" | while IFS=$TAB read -r group sha path; do
        [ "$group" = "$1" ] || continue
        deb=$VM/debs/$(basename "$path")
        member=$(ar t "$deb" | grep '^data\.tar')
        case $member in
            *.zst) ar p "$deb" "$member" | tar --zstd -x -C "$dest" ;;
            *.xz)  ar p "$deb" "$member" | tar -J -x -C "$dest" ;;
            *.gz)  ar p "$deb" "$member" | tar -z -x -C "$dest" ;;
            *)     ar p "$deb" "$member" | tar -x -C "$dest" ;;
        esac
    done
    touch "$stamp"
    echo "unpacked: $dest"
}

unpack kernel
unpack tools

echo "VM tooling ready in $VM"
