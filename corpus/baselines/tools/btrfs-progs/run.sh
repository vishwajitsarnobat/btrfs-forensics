# btrfs restore from the current roots, then from every older root tree `btrfs-find-root -a` reports
# (docs/research/baselines.md §3.1). Both open the device O_RDONLY unless OPEN_CTREE_WRITES is
# set (kernel-shared/disk-io.c:1741-1742). Each root restores into its own directory, so a path
# restored from several roots appears once per root: files/live/ for the current roots and
# files/root-BYTENR/ for each older one. Options (cmds/restore.c): -i ignore errors, -m owner,
# mode and times, -S symlinks, -s snapshots, -x xattrs, -t root tree location.
B=$PREFIX/bin
mkdir -p "$OUT/live"
"$B/btrfs" restore -i -m -S -s -x "$EVIDENCE" "$OUT/live" > "$LOGS/restore-live.txt" 2>&1
status=$?
"$B/btrfs-find-root" -a "$EVIDENCE" > "$LOGS/find-root.txt" 2>&1
# the candidate roots are the `Well block N(gen: ...` lines, the parse undelete-btrfs uses
sed -n 's/^Well block \([0-9]*\)(gen.*/\1/p' "$LOGS/find-root.txt" | sort -un > "$LOGS/roots.txt"
while read -r bytenr; do
    mkdir -p "$OUT/root-$bytenr"
    "$B/btrfs" restore -t "$bytenr" -i -m -S -s -x "$EVIDENCE" "$OUT/root-$bytenr" \
        >> "$LOGS/restore-roots.txt" 2>&1
done < "$LOGS/roots.txt"
echo "older roots tried: $(wc -l < "$LOGS/roots.txt")"
exit $status
