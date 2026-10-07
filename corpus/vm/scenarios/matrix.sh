#!/bin/sh
# One image of the M7 corpus matrix (docs/plan.md M7a): translates the matrix axes into
# make_image.sh settings and runs the guest scenario `matrix` (matrix.guest.sh).
#
# Usage: [AXIS=VALUE ...] corpus/vm/scenarios/matrix.sh NAME
# Axes (the default is the base configuration):
#   OP         delete | overwrite | stress | snapshot | balance | defrag      (delete)
#   SIZE       a truncate size: 512M, 8G, 100G                                (512M)
#   COMPRESS   none | zstd | lzo | zlib (mounted compress-force=)            (none)
#   CSUM       crc32c | xxhash | sha256 | blake2b                            (crc32c)
#   BGT        off | on: mkfs -O ^block-group-tree | -O block-group-tree     (off)
#   DISCARD_MODE  none: no unmap on the virtio disk, nodiscard
#              async: unmap, discard=async, unmount right after the workload
#              idle: unmap, discard=async, 130 s idle before the unmount
#              sync: unmap, discard=sync
#              nodiscard: unmap, nodiscard (the control row)                (none)
#   RECLAIM    off | on: bg_reclaim_threshold 50 on allocation/data         (off)
#   LAYOUT     single | mixed (mkfs -M, MIXED_GROUPS) | raid1 (two devices, data and
#              metadata RAID1)                                               (single)
#
# The discard mount option is always explicit: kernels since 6.2 turn discard=async on by
# themselves on any device that advertises discard (fs/btrfs/super.c v7.0), and the virtio disk
# advertises it even without discard=unmap, when QEMU drops the guest's discards instead.
set -eu
HERE=$(cd "$(dirname "$0")/.." && pwd)
NAME=${1:?usage: matrix.sh NAME}

OP=${OP:-delete}
COMPRESS=${COMPRESS:-none}
CSUM_AXIS=${CSUM:-crc32c}
BGT=${BGT:-off}
DISCARD_MODE=${DISCARD_MODE:-none}
RECLAIM=${RECLAIM:-off}
LAYOUT=${LAYOUT:-single}

case $OP in delete|overwrite|stress|snapshot|balance|defrag) ;;
    *) echo "matrix.sh: unknown OP $OP" >&2; exit 2;; esac
case $CSUM_AXIS in
    crc32c|xxhash|sha256) CSUM=$CSUM_AXIS ;;
    blake2b) CSUM=blake2 ;;  # the name mkfs.btrfs 6.6.3 takes
    *) echo "matrix.sh: unknown CSUM $CSUM_AXIS" >&2; exit 2;;
esac
case $BGT in
    off) MKFS_ARGS="-O ^block-group-tree" ;;
    on) MKFS_ARGS="-O block-group-tree" ;;
    *) echo "matrix.sh: unknown BGT $BGT" >&2; exit 2;;
esac
MOUNT_OPTS=commit=300
case $COMPRESS in
    none) ;;
    zstd|lzo|zlib) MOUNT_OPTS=$MOUNT_OPTS,compress-force=$COMPRESS ;;
    *) echo "matrix.sh: unknown COMPRESS $COMPRESS" >&2; exit 2;;
esac
DISCARD=
IDLE=0
case $DISCARD_MODE in
    none) MOUNT_OPTS=$MOUNT_OPTS,nodiscard ;;
    async) DISCARD=1; MOUNT_OPTS=$MOUNT_OPTS,discard=async ;;
    idle) DISCARD=1; MOUNT_OPTS=$MOUNT_OPTS,discard=async; IDLE=130 ;;
    sync) DISCARD=1; MOUNT_OPTS=$MOUNT_OPTS,discard=sync ;;
    nodiscard) DISCARD=1; MOUNT_OPTS=$MOUNT_OPTS,nodiscard ;;
    *) echo "matrix.sh: unknown DISCARD_MODE $DISCARD_MODE" >&2; exit 2;;
esac
case $RECLAIM in
    off) RECLAIM_PCT=0 ;;
    on) RECLAIM_PCT=50 ;;
    *) echo "matrix.sh: unknown RECLAIM $RECLAIM" >&2; exit 2;;
esac
DEVICES=1
case $LAYOUT in
    single) ;;
    mixed) MKFS_ARGS="$MKFS_ARGS -M" ;;
    raid1) DEVICES=2; MKFS_ARGS="$MKFS_ARGS -d raid1 -m raid1"
           MOUNT_OPTS=$MOUNT_OPTS,device=/dev/vdb ;;
    *) echo "matrix.sh: unknown LAYOUT $LAYOUT" >&2; exit 2;;
esac

export SIZE=${SIZE:-512M} CSUM MKFS_ARGS DEVICES MOUNT_OPTS DISCARD
export SCENARIO=matrix TIMEOUT=900
# the guest needs op, reclaim and idle; the other axes are passed so that its log records them
export SCENARIO_ARGS="op=$OP reclaim=$RECLAIM_PCT idle=$IDLE size=$SIZE compress=$COMPRESS \
csum=$CSUM_AXIS bgt=$BGT discard=$DISCARD_MODE layout=$LAYOUT"
[ -n "$DISCARD" ] || unset DISCARD
"$HERE/make_image.sh" "$NAME"
