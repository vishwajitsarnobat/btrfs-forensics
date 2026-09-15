#!/bin/sh
# Rebuild the three discard images and print the research.md §10.4 table rows:
#   row  fsid_blocks  stale_blocks  needle_copies  nonzero_blocks
# (column meanings: see probe_stale_metadata.py).
# RUN (optional, a number): name the images s01_discard_<row>_r<RUN>.img, so repeated runs
# (experiments/exp000.py) keep distinct files. Without RUN they are s01_discard_<row>.img.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
if [ -n "${RUN:-}" ]; then
    case $RUN in *[!0-9]*) echo "RUN must be a number, not $RUN" >&2; exit 1;; esac
fi
for row in none async sync; do
    name=s01_discard_$row${RUN:+_r$RUN}
    NAME=$name "$HERE/scenarios/discard_$row.sh" > /dev/null
    echo "$row $(python3 "$HERE/probe_stale_metadata.py" "$REPO/images/scenarios/$name.img")"
done
