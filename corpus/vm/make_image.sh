#!/bin/sh
# Create one scenario image: fresh host mkfs, guest mutation, serial log.
#
# Usage: corpus/vm/make_image.sh NAME
#   -> images/scenarios/NAME.img and images/scenarios/NAME.log
# Environment: SIZE (default 512M), CSUM (default xxhash), MKFS_ARGS (extra
# mkfs.btrfs options, e.g. "-O block-group-tree"), plus everything
# run_scenario.sh reads (SCENARIO, MOUNT_OPTS, DISCARD, TIMEOUT, ...).
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=$REPO/images/scenarios
NAME=$1
mkdir -p "$OUT"

rm -f "$OUT/$NAME.img"
truncate -s "${SIZE:-512M}" "$OUT/$NAME.img"
# host btrfs-progs mkfs (6.6.3 on the development host); MKFS_ARGS unquoted on purpose
mkfs.btrfs -q -f --csum "${CSUM:-xxhash}" ${MKFS_ARGS:-} "$OUT/$NAME.img"

"$HERE/run_scenario.sh" "$OUT/$NAME.img" > "$OUT/$NAME.log" 2>&1
grep -q '=== SCENARIO-DONE' "$OUT/$NAME.log" || {
    echo "$NAME: scenario did not finish, see $OUT/$NAME.log" >&2; exit 1; }
echo "$OUT/$NAME.img"
