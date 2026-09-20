#!/bin/sh
# Run a tool of the pinned bundle (corpus/vm/guest.lock) on the host, whatever the host distro:
# the binary is started through the bundle's own dynamic loader with the bundle's own libraries,
# so no host library and no host btrfs-progs is involved. No root needed.
#
# Usage: corpus/vm/pinned.sh TOOL [ARGS...]      TOOL: mkfs.btrfs, btrfs, btrfs-find-root, ...
#   corpus/vm/pinned.sh mkfs.btrfs --version     -> mkfs.btrfs, part of btrfs-progs v6.6.3
#
# Images are formatted with this mkfs so that a regenerated corpus does not depend on the
# btrfs-progs version of the machine it is built on (mkfs defaults changed in 6.19).
# Environment: VM_DIR (default <repo>/images/vm).
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
TOOLS=${VM_DIR:-$REPO/images/vm}/tools
[ $# -ge 1 ] || { echo "usage: pinned.sh TOOL [ARGS...]" >&2; exit 2; }
TOOL=$1; shift

LOADER=$(find "$TOOLS" -name 'ld-linux-x86-64.so.2' 2>/dev/null | head -n 1)
BIN=$(find "$TOOLS" \( -type f -o -type l \) -name "$TOOL" -path '*bin/*' 2>/dev/null | head -n 1)
[ -n "$LOADER" ] && [ -n "$BIN" ] || {
    echo "pinned.sh: $TOOL not found under $TOOLS; run corpus/vm/fetch_vm.sh first" >&2; exit 1; }

# both library directories: some packages still ship under /lib (not usr-merged)
exec "$LOADER" --library-path "$TOOLS/usr/lib/x86_64-linux-gnu:$TOOLS/lib/x86_64-linux-gnu" \
    "$BIN" "$@"
