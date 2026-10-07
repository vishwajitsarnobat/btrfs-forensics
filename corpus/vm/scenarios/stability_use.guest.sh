# Guest scenario stability_use (sourced by /init with the filesystem mounted at $MNT).
# What Toolan & Humphries 2026 did to each image they hid data in, to see whether the data
# survives and whether anything notices (EXP-021): a read-only scrub, read every file, create,
# modify and delete files over more than four commits (so every backup root slot is refilled),
# unmount. Under the name stability_balance (stability_balance.guest.sh) a full balance follows.
# Prints the scrub summary, every file that cannot be read, and every BTRFS kernel message.
btrfs scrub start -B -r $MNT 2>&1 | while read -r line; do echo "=== SCRUB $line"; done
find $MNT -type f | while read -r f; do
    cat "$f" > /dev/null 2>&1 || echo "=== READ-ERROR $f"
done
mkdir -p $MNT/stability
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do seq 1 $((i * 700)) > $MNT/stability/new_$i.txt; done
sync
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do echo modified >> $MNT/stability/new_$i.txt; done
sync
rm $MNT/stability/new_1*.txt
sync
for i in 1 2 3 4 5 6; do echo round $i > $MNT/stability/round_$i; sync; done
if [ "$SCENARIO" = stability_balance ]; then
    echo "=== BALANCE $(btrfs balance start --full-balance $MNT 2>&1 | tail -n 1)"
    sync
fi
btrfs filesystem sync $MNT
dmesg | grep -i btrfs | while read -r line; do echo "=== DMESG $line"; done
