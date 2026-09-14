#!/bin/sh
# Rebuild the three discard images and print the research.md §10.4 table rows:
#   row  fsid_blocks  stale_blocks  needle_copies  nonzero_blocks
# (column meanings: see probe_stale_metadata.py).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
for row in none async sync; do
    "$HERE/scenarios/discard_$row.sh" > /dev/null
    echo "$row $(python3 "$HERE/probe_stale_metadata.py" "$REPO/images/scenarios/s01_discard_$row.img")"
done
