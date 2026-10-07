# FKIE-TSK through its pool tools (docs/research/baselines.md §3.7): the pool is a directory of
# member devices (tsk/pool/TSK_POOL_INFO.cpp:18-69), here one link to /dev/vdb. `fls -P` lists
# the live FS tree recursively (BTRFS_POOL::fls, which ignores -r, -p and -T); every regular file
# it lists is read with `icat -P POOL INODE`, which writes the content to stdout, into
# files/PATH. FKIE's btrfs code has no decompression, so a compressed file comes out as stored.
B=$PREFIX/bin
mkdir -p "$SCRATCH/pool"
ln -s "$EVIDENCE" "$SCRATCH/pool/dev1"
"$B/fls" -P "$SCRATCH/pool" > "$LOGS/fls.txt" 2> "$LOGS/fls.err" || exit $?
awk -f "$IN/fls-tree.awk" "$LOGS/fls.txt" > "$LOGS/listing.tsv"
while IFS=$'\t' read -r type inode path; do
    [ "$type" = r ] || continue
    mkdir -p "$OUT/$(dirname "$path")"
    "$B/icat" -P "$SCRATCH/pool" "$inode" > "$OUT/$path" 2>> "$LOGS/icat.err" ||
        echo "icat $inode failed: $path" >> "$LOGS/icat.err"
done < "$LOGS/listing.tsv"
