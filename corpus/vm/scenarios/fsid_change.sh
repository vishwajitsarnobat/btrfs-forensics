#!/bin/sh
# An fsid change (plan.md M6f): a filesystem lives (guest scenario `foreign`), the pinned btrfstune
# changes its fsid, and the filesystem lives on under the new one (`foreign` again).
# - TUNE=-u rewrites the fsid and the chunk tree uuid in place in every tree block the extent
#   tree lists and in every DEV_ITEM, then in the superblocks (btrfs-progs v6.6.3
#   tune/change-uuid.c:84-143, 145-197, 235-307). Blocks the extent tree no longer lists
#   (superseded ones, those only backup roots reach) keep the old fsid. The device uuid is kept.
# - TUNE=-m rewrites no tree block's header: the old fsid becomes metadata_uuid, which tree blocks
#   go on carrying, and fsid gets a new random value, in one committed transaction
#   (tune/change-metadata-uuid.c:51-142).
#
# Environment: NAME and TUNE (both required), CSUM (default xxhash), MKFS_ARGS, SIZE, OUT_DIR
# (as make_image.sh). Writes OUT_DIR/NAME.img and one log of both lives, OUT_DIR/NAME.log.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${OUT_DIR:-$REPO/images/scenarios}
NAME=${NAME:?NAME is required}
TUNE=${TUNE:?TUNE is required: -u or -m}
case $TUNE in -u|-m) ;; *) echo "TUNE must be -u or -m, not $TUNE" >&2; exit 1;; esac

SCENARIO=foreign MOUNT_OPTS=commit=5 "$HERE/make_image.sh" "$NAME" > /dev/null
echo "=== BTRFSTUNE $TUNE" >> "$OUT/$NAME.log"
"$HERE/pinned.sh" btrfstune -f "$TUNE" "$OUT/$NAME.img" >> "$OUT/$NAME.log" 2>&1
SCENARIO=foreign MOUNT_OPTS=commit=5 "$HERE/run_scenario.sh" "$OUT/$NAME.img" \
    >> "$OUT/$NAME.log" 2>&1
[ "$(grep -c -- '=== SCENARIO-DONE' "$OUT/$NAME.log")" -eq 2 ] || {
    echo "$NAME: the second life did not finish, see $OUT/$NAME.log" >&2; exit 1; }
echo "$OUT/$NAME.img"
