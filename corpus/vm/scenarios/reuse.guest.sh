# Guest scenario reuse (sourced by /init with the filesystem mounted at $MNT).
# One logical chunk range that two chunks hold at different times, on different physical bytes
# (EXP-010; the answer on issue #48). Two kernel rules decide where a new data chunk goes, both
# at v7.0:
# - logical: it starts at the end of the highest chunk mapped (find_next_chunk,
#   fs/btrfs/volumes.c:2000-2016), so a range is reused only after the topmost chunk is removed;
# - physical: it asks for a 1 GiB device extent (gather_device_info, volumes.c:5529, with
#   max_stripe_size at most 1 GiB, volumes.c:5449, and a data chunk_size of 10 GiB,
#   space-info.c:216-217) and, when no hole is that large, takes the largest hole
#   (find_free_dev_extent, volumes.c:1883-1946). On a 512 MiB device that is always the case.
# The topmost chunk is also the last one on the device, so its hole joins the free space behind
# it; for the new chunk to land elsewhere, a lower hole must be larger than that.
#
# So six 64 MiB data chunks D1 to D6 are filled, which leaves 27 MiB free at the end of the
# device. a.bin fills D1, z.bin D2 and D3, w.bin D4 and D5 (kept), b.bin part of D6 (= B).
# z.bin and b.bin are deleted and `balance -dusage=0` removes the three empty chunks (top first:
# D6, D3, D2). The next data chunk R starts where B started (D5 is now the topmost chunk), and
# lands on the 128 MiB hole of D2 and D3, which is larger than the 91 MiB of B and the free
# tail. B's device bytes are not handed out again: the version of b.bin that older states hold
# is still there, at a logical address the current map gives to R.
#
# Every file is written as 4 MiB pieces, each fsynced on its own, so that every data extent is
# 4 MiB and the chunks fill in order: a 64 MiB chunk takes exactly 16 pieces. After the removal
# the free space of the surviving data chunks is read from `btrfs filesystem df`, and c.bin is
# that much plus four pieces, so that exactly one new data chunk is needed.
#
# Mount without compression and without discard (MOUNT_OPTS=commit=5,nodiscard): compression
# would change how much a piece takes, async discard (which the kernel turns on by itself, since
# the virtio disk offers discard) would trim the emptied chunks before removing them, and sync
# discard would delay the removal past the commit (block-group.c:1325-1340, 1603-1611).
# Contents come from /dev/urandom, so no two pieces share bytes. The log prints every file's
# SHA-256 and the chunk, block-group and device-extent items before the deletion, after the
# removal and at the end.
piece() {  # piece FILE INDEX: one 4 MiB piece of random bytes at INDEX, fsynced
    dd if=/dev/urandom of=$1 bs=4M count=1 seek=$2 iflag=fullblock conv=notrunc,fsync 2>/dev/null
}
fill() {  # fill FILE COUNT
    i=0; while [ $i -lt $2 ]; do piece $1 $i; i=$((i + 1)); done
}
layout() {  # layout LABEL: what the committed trees say now
    echo "=== LAYOUT $1 generation $(btrfs inspect-internal dump-super /dev/vda | awk '$1 == "generation" {print $2}')"
    btrfs inspect-internal dump-tree -t chunk /dev/vda | grep -A 9 'CHUNK_ITEM' | grep -E 'CHUNK_ITEM|type|stripe [0-9]'
    btrfs inspect-internal dump-tree -t extent /dev/vda | grep -A 1 'BLOCK_GROUP_ITEM' | grep -v '^--'
    btrfs inspect-internal dump-tree -t dev /dev/vda | grep -A 1 'DEV_EXTENT' | grep -v '^--'
}
seq 1 20000 > $MNT/keep.txt
sync
fill $MNT/a.bin 16
sync
fill $MNT/z.bin 32
sync
fill $MNT/w.bin 32
sync
fill $MNT/b.bin 10
sync; btrfs filesystem sync $MNT
sha256sum $MNT/keep.txt $MNT/a.bin $MNT/z.bin $MNT/w.bin $MNT/b.bin
sleep 6; sync  # one more commit, so a state after b.bin's is backed up as well
layout before-delete
rm $MNT/z.bin $MNT/b.bin
sync
echo "=== BALANCE $(btrfs balance start -dusage=0 $MNT 2>&1 | tail -n 1)"
sync; sleep 6; sync  # the removal reaches the commit root, so its device extents count as free
layout after-removal
free=$(btrfs filesystem df -b $MNT | awk -F'[=, ]+' '/^Data/ {print int(($4 - $6) / 4194304)}')
echo "=== FREE-PIECES $free"
fill $MNT/c.bin $((free + 4))
sync; btrfs filesystem sync $MNT
sha256sum $MNT/c.bin
sleep 6; sync
layout end
