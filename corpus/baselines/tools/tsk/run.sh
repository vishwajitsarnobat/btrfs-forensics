# TSK develop: tsk_recover -e writes allocated and unallocated files with their paths, and fls
# lists every name, deleted ones marked (docs/research/baselines.md §3.6). TSK opens images
# read-only. Its btrfs code opens only crc32c filesystems and sees a deleted file only while
# its inode is in the live tree with nlink 0 (tsk/fs/btrfs.cpp:886-891, 2699).
B=$PREFIX/bin
"$B/fls" -r -p -f btrfs "$EVIDENCE" > "$LOGS/fls.txt" 2> "$LOGS/fls.err"
"$B/tsk_recover" -e -f btrfs "$EVIDENCE" "$OUT/tsk" > "$LOGS/tsk_recover.txt" 2>&1
