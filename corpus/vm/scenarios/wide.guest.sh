# Guest scenario wide (sourced by /init with the filesystem mounted at $MNT).
# Trees with internal nodes, which the small scenarios never grow: 48 subvolumes push the root
# tree past one leaf, 1500 files push the top-level fs tree and the extent tree past one. Files
# are deleted between commits and a read-only snapshot is taken. There is no balance, so every
# older state stays inside the current chunk map. Prints ground-truth SHA-256s.
i=1; while [ $i -le 48 ]; do btrfs subvolume create $MNT/sv$i > /dev/null; i=$((i + 1)); done
mkdir $MNT/d
i=1; while [ $i -le 1500 ]; do echo "file $i" > $MNT/d/f$i; i=$((i + 1)); done
sync; btrfs filesystem sync $MNT
sha256sum $MNT/d/f1 $MNT/d/f750 $MNT/d/f1500
rm $MNT/d/f7??
sync
i=1; while [ $i -le 5 ]; do seq 1 $((i * 3000)) > $MNT/big_$i; sync; i=$((i + 1)); done
sha256sum $MNT/big_*
btrfs subvolume snapshot -r $MNT $MNT/snap_top > /dev/null
rm $MNT/d/f1???
sync
btrfs filesystem df $MNT
