# mbkn-btrfs-rescue: `analyze` (sweep the device for tree blocks of every generation, index them
# in SQLite, classify every data extent against the checksum tree), then `restore` every
# subvolume it found with every category and old names included (docs/research/baselines.md
# §3.9). The device "is only ever opened read-only" (device.py:26, O_RDONLY). The index, its
# caches and its scratch space stay out of files/; the exclude list is emptied so no name is
# hidden. Each subvolume restores into files/NAME@ID/ (restore creates DEST/NAME@ID itself).
cat > "$SCRATCH/mbkn.toml" <<EOF
tmp_dir = "$SCRATCH/tmp"
cache_dir = "$SCRATCH/cache"
db_name = "index.sqlite"
exclude = []
EOF
M() { "$PREFIX/python/bin/python3" -m mbkn_btrfs_rescue -c "$SCRATCH/mbkn.toml" -d "$EVIDENCE" "$@"; }
M analyze > "$LOGS/analyze.txt" 2>&1 || exit $?
M subvols > "$LOGS/subvols.txt" 2>&1 || exit $?
status=0
for sv in $(awk '$1 ~ /^\/.*@[0-9]+$/ {print $1}' "$LOGS/subvols.txt"); do
    M restore --include all --include-stale --no-exclude "$sv" "$OUT" \
        >> "$LOGS/restore.txt" 2>&1 || status=$?
done
# restore writes its report into the destination; keep it with the logs, not as a file produced
find "$OUT" -name '.mbkn-restore-*.tsv' | while read -r report; do
    mv "$report" "$LOGS/$(basename "$(dirname "$report")")$(basename "$report")"
done
exit $status
