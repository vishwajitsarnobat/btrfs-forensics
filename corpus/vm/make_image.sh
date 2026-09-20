#!/bin/sh
# Create one scenario image: fresh host mkfs, guest mutation, serial log.
#
# Usage: corpus/vm/make_image.sh NAME
#   -> images/scenarios/NAME.img and images/scenarios/NAME.log
# Environment: SIZE (default 512M), CSUM (default xxhash), MKFS_ARGS (extra
# mkfs.btrfs options, e.g. "-O block-group-tree"), plus everything
# run_scenario.sh reads (SCENARIO, MOUNT_OPTS, DISCARD, TIMEOUT, ...),
# MKFS (default: the pinned mkfs.btrfs 6.6.3 of corpus/vm/guest.lock through
# pinned.sh; set MKFS=mkfs.btrfs to format with the host's btrfs-progs), and
# DONE_MARKER (default "=== SCENARIO-DONE"): the serial-log line that proves
# the scenario finished, for scenarios that power off without unmounting.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=$REPO/images/scenarios
NAME=$1
# NAME is a plain file stem: never let it escape images/scenarios/
case $NAME in ''|*/*|.*) echo "invalid scenario name: $NAME" >&2; exit 1;; esac
mkdir -p "$OUT"

rm -f "$OUT/$NAME.img"
truncate -s "${SIZE:-512M}" "$OUT/$NAME.img"
# pinned mkfs unless MKFS says otherwise; MKFS and MKFS_ARGS unquoted on purpose
${MKFS:-"$HERE/pinned.sh" mkfs.btrfs} -q -f --csum "${CSUM:-xxhash}" ${MKFS_ARGS:-} "$OUT/$NAME.img"

"$HERE/run_scenario.sh" "$OUT/$NAME.img" > "$OUT/$NAME.log" 2>&1
grep -q -- "${DONE_MARKER:-=== SCENARIO-DONE}" "$OUT/$NAME.log" || {
    echo "$NAME: scenario did not finish, see $OUT/$NAME.log" >&2; exit 1; }
echo "$OUT/$NAME.img"
