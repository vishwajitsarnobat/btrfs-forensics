# Guest scenario foreign (sourced by /init with the filesystem mounted at $MNT).
# One life of a filesystem that is later reformatted or given a new fsid (plan.md M6f, driven by
# scenarios/reformat.sh and scenarios/fsid_change.sh): 200 small files and a large one in a
# subvolume, a read-only snapshot, four rounds of churn with deletions, each committed, then the
# large file deleted. The device then holds superseded tree blocks of this filesystem as well as
# its live ones. The same body runs on both filesystems of a reformat and before and after an
# fsid change: every file names the fsid it was written under, so two lives never share content.
# Prints the identity and geometry of the filesystem as dump-super reads it, and the SHA-256 of
# every file that stays.
super() {  # super FIELD: one field of the primary superblock
    btrfs inspect-internal dump-super /dev/vda | awk -v f="$1" '$1 == f {print $2; exit}'
}
FSID=$(super fsid)
echo "=== FS fsid $FSID metadata_uuid $(super metadata_uuid) dev_uuid $(super dev_item.uuid)" \
     "nodesize $(super nodesize) csum_type $(super csum_type) generation $(super generation)"
btrfs subvolume create $MNT/sv > /dev/null
i=1; while [ $i -le 200 ]; do echo "file $i of filesystem $FSID" > $MNT/sv/f$i; i=$((i + 1)); done
seq 1 30000 | sed "s/^/$FSID /" > $MNT/sv/big.txt
sync; btrfs filesystem sync $MNT
btrfs subvolume snapshot -r $MNT/sv $MNT/snap > /dev/null
for round in 1 2 3 4; do
    echo "round $round of filesystem $FSID" > $MNT/sv/churn_$round
    rm $MNT/sv/f${round}0 $MNT/sv/f${round}1 $MNT/sv/f${round}2
    sync
done
rm $MNT/sv/big.txt
sync
sha256sum $MNT/sv/f1 $MNT/sv/f100 $MNT/sv/churn_4 $MNT/snap/big.txt
echo "=== FS-DONE fsid $FSID generation $(super generation)"
