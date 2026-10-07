# Guest scenario reuse_same (sourced by /init with the filesystem mounted at $MNT).
# The control of scenario reuse (EXP-010): a logical chunk range reused on the same physical
# bytes. It is the layout the answer on issue #48 proposed for a different placement, and it
# shows why that did not work: three data chunks Z, W and B are filled in that order, Z and B
# are emptied and removed (`balance -dusage=0`, top first), and the next data chunk R starts
# where B started (find_next_chunk, fs/btrfs/volumes.c:2000-2016 at v7.0). Z's old device
# extent is the lowest hole that fits, but a data chunk asks for a 1 GiB device extent
# (gather_device_info, volumes.c:5529) and, finding none, takes the largest hole
# (find_free_dev_extent, volumes.c:1883-1946): B's own bytes together with the free space behind
# them. So R lands where B was, both maps translate the range alike, and c.bin overwrites the
# start of what b.bin left in B.
#
# Every file is written as 4 MiB pieces, each fsynced on its own, so that every data extent is
# 4 MiB and the chunks fill in order: a 64 MiB chunk takes exactly 16 pieces. z.bin (20 pieces)
# fills Z and the start of W; w.bin (5) stays in W; b.bin (14) fills W and puts its last pieces
# into B. After the removal the free space of the surviving data chunks is read from `btrfs
# filesystem df`, and c.bin is that much plus four pieces, so that exactly one new data chunk is
# needed.
#
# Mount options and logging as in scenario reuse (MOUNT_OPTS=commit=5,nodiscard).
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
fill $MNT/z.bin 20
sync
fill $MNT/w.bin 5
sync
fill $MNT/b.bin 14
sync; btrfs filesystem sync $MNT
sha256sum $MNT/keep.txt $MNT/z.bin $MNT/w.bin $MNT/b.bin
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
