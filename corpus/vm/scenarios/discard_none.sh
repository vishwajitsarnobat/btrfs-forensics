#!/bin/sh
# research.md §10.4 discard table, row "no discard": virtio disk without
# discard=unmap, mount options compress=zstd,commit=5.
# NAME (optional): the image name, default s01_discard_none.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
unset DISCARD
SCENARIO=s01 MOUNT_OPTS=compress=zstd,commit=5 "$HERE/make_image.sh" "${NAME:-s01_discard_none}"
