#!/bin/sh
# research.md §10.4 discard table, row "discard=sync": virtio disk with
# discard=unmap (DISCARD=1) and discard=sync added to the mount options.
# NAME (optional): the image name, default s01_discard_sync.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
DISCARD=1 SCENARIO=s01 MOUNT_OPTS=compress=zstd,commit=5,discard=sync "$HERE/make_image.sh" "${NAME:-s01_discard_sync}"
