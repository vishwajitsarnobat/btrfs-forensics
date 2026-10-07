# Guest scenario hidden (sourced by /init with the filesystem mounted at $MNT).
# A snapshot hidden as Schwietert & Hilgert 2025 hide one (hide-and-seek scenario 7): taken of the
# top-level subvolume under the name U+FEFF (ZERO WIDTH NO-BREAK SPACE, which a listing shows as
# nothing), then moved into the hidden directory .lib32, and the live file it preserves changed.
# A second snapshot with an ordinary name is the control (plan.md M6d: only the first is a
# finding). Prints both subvolume ids and the SHA-256 of the file in each place.
mkdir -p $MNT/home $MNT/.lib32
echo "HIDDEN DATA kept only by the snapshot" > $MNT/home/File.txt
seq 1 2000 > $MNT/home/Test.txt
sync
NAME=$(printf '\357\273\277')
btrfs subvolume snapshot $MNT "$MNT/$NAME" > /dev/null
btrfs subvolume snapshot $MNT $MNT/snapshot-weekly > /dev/null
echo "an ordinary file" > $MNT/home/File.txt
mv "$MNT/$NAME" $MNT/.lib32/
sync; btrfs filesystem sync $MNT
echo "=== HIDDEN-ID $(btrfs inspect-internal rootid "$MNT/.lib32/$NAME")"
echo "=== NORMAL-ID $(btrfs inspect-internal rootid $MNT/snapshot-weekly)"
echo "=== HIDDEN home/File.txt $(sha256sum < "$MNT/.lib32/$NAME/home/File.txt")"
echo "=== LIVE home/File.txt $(sha256sum < $MNT/home/File.txt)"
