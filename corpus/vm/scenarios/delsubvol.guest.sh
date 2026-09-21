# Guest scenario delsubvol (sourced by /init with the filesystem mounted at $MNT).
# A subvolume is filled, committed and deleted. `btrfs subvolume sync` waits until the cleaner
# has dropped its tree and removed its ROOT_ITEM, so the last states do not name it any more;
# older root trees still do, as long as their leaves survive. 300 small files give the doomed
# tree a second level (a root node above its leaves). Three more commits of small writes in the
# other subvolume follow, then a normal unmount. Prints the SHA-256 of the two files that
# matter as ground truth, and the doomed subvolume's id.
btrfs subvolume create $MNT/keep > /dev/null
btrfs subvolume create $MNT/doomed > /dev/null
mkdir $MNT/doomed/docs $MNT/doomed/many
seq 1 30000 > $MNT/doomed/docs/big.txt
echo "inline secret of the doomed subvolume" > $MNT/doomed/small.txt
i=1; while [ $i -le 300 ]; do echo "file $i" > $MNT/doomed/many/f$i; i=$((i + 1)); done
seq 1 100 > $MNT/keep/stays.txt
sync; btrfs filesystem sync $MNT
echo "=== DOOMED-ID $(btrfs inspect-internal rootid $MNT/doomed)"
echo "=== DOOMED docs/big.txt $(sha256sum < $MNT/doomed/docs/big.txt)"
echo "=== DOOMED small.txt $(sha256sum < $MNT/doomed/small.txt)"
btrfs subvolume delete $MNT/doomed > /dev/null
btrfs subvolume sync $MNT
sync
for i in 1 2 3; do echo "after the deletion $i" > $MNT/keep/churn_$i; sync; done
