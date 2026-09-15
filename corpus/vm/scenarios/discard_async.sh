#!/bin/sh
# research.md §10.4 discard table, row "discard=async": virtio disk with
# discard=unmap (DISCARD=1) and the SAME mount options as the no-discard row.
# No discard option is passed: the kernel (>= 6.2) enables discard=async by
# itself because the device advertises discard. The guest log line
# "=== MOUNTED" shows the effective options.
# NAME (optional): the image name, default s01_discard_async.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
DISCARD=1 SCENARIO=s01 MOUNT_OPTS=compress=zstd,commit=5 "$HERE/make_image.sh" "${NAME:-s01_discard_async}"
