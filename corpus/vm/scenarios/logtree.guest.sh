# Guest scenario logtree (sourced by /init with the filesystem mounted at $MNT).
# Leaves a non-empty log tree on disk: files are committed, then new data is
# fsynced in two subvolumes (fs tree 5 and sv1) and the guest powers off
# without a transaction commit. Mount with a long commit interval
# (MOUNT_OPTS=commit=300) so the transaction kthread cannot commit first.
#
# The power-off is sysrq 'o' (kernel_power_off: no sync, no unmount), so the
# superblock written by btrfs_sync_log, with log_root set, is the last one on
# disk. /init never reaches its umount; make_image.sh is run with
# DONE_MARKER='=== LOGTREE-POWEROFF'.
btrfs subvolume create $MNT/sv1
seq 1 20000 > $MNT/committed.txt
seq 1 20000 > $MNT/sv1/committed.txt
sync; btrfs filesystem sync $MNT
echo "=== COMMITTED"
# fsync only: dd conv=fsync calls fsync(2) on the output file
seq 1 30000 | dd of=$MNT/fsynced.txt conv=fsync 2>/dev/null
seq 1 40000 | dd of=$MNT/sv1/fsynced.txt conv=fsync 2>/dev/null
echo "appended after commit" >> $MNT/sv1/committed.txt
dd if=/dev/null of=$MNT/sv1/committed.txt conv=notrunc,fsync 2>/dev/null
sha256sum $MNT/*.txt $MNT/sv1/*.txt
echo "=== LOGTREE-POWEROFF"
echo o > /proc/sysrq-trigger
sleep 60
