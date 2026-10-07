# recover_deleted reads the whole device into memory (guest memory must exceed the image size),
# diffs the FS tree 5 roots of the four backup roots against the current one, and carves every
# inode found only in an older root (docs/research/baselines.md §3.5). The harness writes each
# file as inode_INODE_gen_GENERATION and its recovered name into names.tsv.
"$PREFIX/bin/recover_deleted" "$EVIDENCE" "$OUT" /work/out/names.tsv > "$LOGS/recovered.tsv"
