# btrfscue: identify the filesystem id, gather every tree block of it into a metadata database
# (recon), then restore files from that database (recover); docs/research/baselines.md §3.4.
# recon and recover open the image with os.Open, read-only (cmd/recon.go:54, cmd/recover.go:53).
# identify samples blocks at random; its most frequent fsid comes first. The block size is the
# nodesize from the superblock (offset 0x10094), since btrfscue's default is 16 KiB.
B=$PREFIX/bin/btrfscue
nodesize=$(od -An -tu4 -j $((0x10094)) -N 4 "$EVIDENCE" | tr -d ' ')
"$B" -p=false -m --block-size "$nodesize" identify "$EVIDENCE" > "$LOGS/identify.txt" 2>&1
fsid=$(awk -F '\t' 'NF >= 2 {print $1; exit}' "$LOGS/identify.txt" | tr -d ' ')
echo "fsid $fsid nodesize $nodesize"
"$B" -p=false --block-size "$nodesize" --metadata "$SCRATCH/meta.db" recon --id "$fsid" \
    "$EVIDENCE" > "$LOGS/recon.txt" 2>&1 || exit $?
"$B" -p=false -v --block-size "$nodesize" --metadata "$SCRATCH/meta.db" recover "$EVIDENCE" \
    "$OUT/btrfscue" > "$LOGS/recover.txt" 2>&1
