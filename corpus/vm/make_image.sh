#!/bin/sh
# Create one scenario image: fresh host mkfs, guest mutation, serial log.
#
# Usage: corpus/vm/make_image.sh NAME
#   -> images/scenarios/NAME.img and images/scenarios/NAME.log
# Environment: SIZE (default 512M), CSUM (default xxhash), MKFS_ARGS (extra
# mkfs.btrfs options, e.g. "-O block-group-tree"), DEVICES (1 or 2, default 1:
# with 2, a second image NAME.dev2.img of the same size is formatted together
# with the first and attached to the guest as /dev/vdb), plus everything
# run_scenario.sh reads (SCENARIO, MOUNT_OPTS, DISCARD, SCENARIO_ARGS, TIMEOUT, ...),
# MKFS (default: the pinned mkfs.btrfs 6.6.3 of corpus/vm/guest.lock through
# pinned.sh; set MKFS=mkfs.btrfs to format with the host's btrfs-progs), and
# DONE_MARKER (default "=== SCENARIO-DONE"): the serial-log line that proves
# the scenario finished, for scenarios that power off without unmounting.
# OUT_DIR (default <repo>/images/scenarios, and always under <repo>/images/)
# puts the image and its log elsewhere, for experiments that build their own.
#
# The log starts with what the host did: `=== HOST-MKFS` (the mkfs version),
# `=== HOST-MKFS-ARGS`, `=== HOST-SIZE`, `=== HOST-DEVICES` and `=== HOST-DISCARD`
# (unmap when the virtio disk passes the guest's discards through to the image
# file, else none). The guest's serial console follows.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${OUT_DIR:-$REPO/images/scenarios}
case $OUT in
    *..*|"$REPO"/images/) echo "OUT_DIR must lie under $REPO/images/" >&2; exit 1;;
    "$REPO"/images/*) ;;
    *) echo "OUT_DIR must lie under $REPO/images/" >&2; exit 1;;
esac
NAME=$1
# NAME is a plain file stem: never let it escape images/scenarios/
case $NAME in ''|*/*|.*) echo "invalid scenario name: $NAME" >&2; exit 1;; esac
DEVICES=${DEVICES:-1}
case $DEVICES in 1|2) ;; *) echo "DEVICES must be 1 or 2, not $DEVICES" >&2; exit 1;; esac
mkdir -p "$OUT"

rm -f "$OUT/$NAME.img" "$OUT/$NAME.dev2.img"
truncate -s "${SIZE:-512M}" "$OUT/$NAME.img"
IMAGE2=
if [ "$DEVICES" = 2 ]; then
    IMAGE2=$OUT/$NAME.dev2.img
    truncate -s "${SIZE:-512M}" "$IMAGE2"
fi
# pinned mkfs unless MKFS says otherwise; MKFS, MKFS_ARGS and IMAGE2 unquoted on purpose
MKFS=${MKFS:-"$HERE/pinned.sh mkfs.btrfs"}
$MKFS -q -f --csum "${CSUM:-xxhash}" ${MKFS_ARGS:-} "$OUT/$NAME.img" $IMAGE2

DISCARD_MODE=none
[ -z "${DISCARD:-}" ] || DISCARD_MODE=unmap
{
    echo "=== HOST-MKFS $($MKFS --version 2>&1 | head -n 1)"
    echo "=== HOST-MKFS-ARGS -q -f --csum ${CSUM:-xxhash} ${MKFS_ARGS:-}"
    echo "=== HOST-SIZE ${SIZE:-512M}"
    echo "=== HOST-DEVICES $DEVICES"
    echo "=== HOST-DISCARD $DISCARD_MODE"
} > "$OUT/$NAME.log"
IMAGE2=$IMAGE2 "$HERE/run_scenario.sh" "$OUT/$NAME.img" >> "$OUT/$NAME.log" 2>&1
grep -q -- "${DONE_MARKER:-=== SCENARIO-DONE}" "$OUT/$NAME.log" || {
    echo "$NAME: scenario did not finish, see $OUT/$NAME.log" >&2; exit 1; }
echo "$OUT/$NAME.img"
