# btrForensics lists the live FS tree with `fls -r` (it cannot list deleted files,
# Tools/FLS_README.md) and writes each regular file under its original name into the current
# directory with `icat IMAGE INODE` (Tools/ICAT_README.md); each runs in files/DIR so the paths
# are kept. It opens the image through TSK (tsk_img_open), read-only. No decompression code.
B=$PREFIX/bin
"$B/fls" -r "$EVIDENCE" > "$LOGS/fls.txt" 2> "$LOGS/fls.err" || exit $?
awk -f "$IN/fls-tree.awk" "$LOGS/fls.txt" > "$LOGS/listing.tsv"
while IFS=$'\t' read -r type inode path; do
    [ "$type" = r ] || continue
    mkdir -p "$OUT/$(dirname "$path")"
    (cd "$OUT/$(dirname "$path")" && "$B/icat" "$EVIDENCE" "$inode") >> "$LOGS/icat.txt" 2>&1 ||
        echo "icat $inode failed: $path" >> "$LOGS/icat.txt"
done < "$LOGS/listing.tsv"
