# Guest scenario s01 (sourced by /init with the filesystem mounted at $MNT).
# Subvolume with 3 files -> sync -> read-only snapshot -> delete 2 files
# (one 250 KiB-ish regular file, one inline) -> 6 committed churn writes ->
# full balance (relocates every chunk). Prints ground-truth SHA-256s.
btrfs subvolume create $MNT/sv1
seq 1 20000 > $MNT/sv1/keep.txt
seq 1 50000 > $MNT/sv1/deleted_big.txt
echo "small secret" > $MNT/sv1/deleted_inline.txt
sync; btrfs filesystem sync $MNT
sha256sum $MNT/sv1/*.txt
btrfs subvolume snapshot -r $MNT/sv1 $MNT/snap_before_delete
rm $MNT/sv1/deleted_big.txt $MNT/sv1/deleted_inline.txt
sync
for i in 1 2 3 4 5 6; do echo gen$i > $MNT/sv1/churn_$i; sync; done
btrfs balance start --full-balance $MNT 2>&1 | tail -n 1
sync
btrfs filesystem df $MNT
