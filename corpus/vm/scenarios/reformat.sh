#!/bin/sh
# A reformat (plan.md M6f): a filesystem lives (guest scenario `foreign`), then the pinned
# mkfs.btrfs formats the same image again and, unless NEW_LIFE=0, the new filesystem lives too
# (`foreign` again).
# On a regular file mkfs trims nothing (BLKDISCARD fails) and zeroes only the first 2 MiB and the
# superblock copies that lie inside the new filesystem's size (btrfs-progs v6.6.3
# common/device-utils.c:121, 270-293), so the old filesystem's tree blocks survive wherever the
# new one has not written. With a new size below 64 MiB (`-b`), the old mirror-1 superblock at
# 64 MiB survives too.
#
# Environment: NAME (required), OLD_CSUM and NEW_CSUM (default xxhash), OLD_MKFS_ARGS and
# NEW_MKFS_ARGS (extra mkfs.btrfs options), NEW_LIFE (default 1; 0 leaves the new filesystem as
# mkfs wrote it), SIZE (default 512M), OUT_DIR (as make_image.sh).
# Writes OUT_DIR/NAME.img and one log of both lives, OUT_DIR/NAME.log.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${OUT_DIR:-$REPO/images/scenarios}
NAME=${NAME:?NAME is required}

CSUM=${OLD_CSUM:-xxhash} MKFS_ARGS=${OLD_MKFS_ARGS:-} SCENARIO=foreign MOUNT_OPTS=commit=5 \
    "$HERE/make_image.sh" "$NAME" > /dev/null
echo "=== REFORMAT --csum ${NEW_CSUM:-xxhash} ${NEW_MKFS_ARGS:-}" >> "$OUT/$NAME.log"
# NEW_MKFS_ARGS unquoted on purpose
"$HERE/pinned.sh" mkfs.btrfs -q -f --csum "${NEW_CSUM:-xxhash}" ${NEW_MKFS_ARGS:-} \
    "$OUT/$NAME.img" >> "$OUT/$NAME.log" 2>&1
LIVES=1
if [ "${NEW_LIFE:-1}" != 0 ]; then
    SCENARIO=foreign MOUNT_OPTS=commit=5 "$HERE/run_scenario.sh" "$OUT/$NAME.img" \
        >> "$OUT/$NAME.log" 2>&1
    LIVES=2
fi
[ "$(grep -c -- '=== SCENARIO-DONE' "$OUT/$NAME.log")" -eq $LIVES ] || {
    echo "$NAME: the second life did not finish, see $OUT/$NAME.log" >&2; exit 1; }
echo "$OUT/$NAME.img"
