# Guest scenario datacsum (sourced by /init with the filesystem mounted at $MNT).
# Files whose data checksums matter (plan.md M6a): a regular file, an inline file, a file of
# prealloc extents, two regular files that `corpus/mutate.py flip-data` damages later (one on
# one mirror, one on both), and a file written with compress-force=zstd. Then `mount -o remount,nodatasum`: a file created after it gets the
# NODATASUM inode flag and no checksums. Prints the SHA-256 of every file as ground truth.
#
# Format with data DUP (MKFS_ARGS="-d dup"), so that every data sector has two copies.
seq 100000 140000 > $MNT/plain.txt
echo "a small file whose data stays inline in its leaf" > $MNT/inline.txt
fallocate -l 1048576 $MNT/prealloc.bin
seq 200000 230000 > $MNT/repairable.txt
seq 300000 320000 > $MNT/damaged.txt
sync
mount -o remount,compress-force=zstd $MNT
seq 500000 540000 > $MNT/compressed.txt
sync
mount -o remount,compress=no,nodatasum $MNT && echo "=== REMOUNTED $(grep ' /mnt ' /proc/mounts)"
seq 400000 425000 > $MNT/nosum.txt
sync
for f in plain.txt inline.txt prealloc.bin repairable.txt damaged.txt compressed.txt nosum.txt; do
    echo "=== FILE $f $(sha256sum < $MNT/$f)"
done
