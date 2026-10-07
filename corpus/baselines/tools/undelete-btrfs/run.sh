# undelete-btrfs is interactive; it is driven through stdin to its deepest mode
# (undelete.sh:95-364). Answers: path `.*` (everything), Enter after the dry-run notice, `1`
# recover at depth 0 (plain btrfs restore), `2` one level deeper (every root btrfs-find-root
# reports), `2` deeper again (btrfs-find-root -a), any key at the depth-2 notice, then `1` until
# it exits: `1` is "recover" in a dry-run menu and "exit" in a results menu, so a run whose
# depths go differently still ends. All depths restore into the same directory; btrfs restore
# skips files that exist, so a later depth only adds files. The script runs `btrfs restore -ivv`
# without -m (no metadata) and deletes empty files. It reads the device through btrfs restore and
# btrfs-find-root, which open it O_RDONLY.
export PATH=$DEPS/btrfs-progs/bin:$PATH
cd "$SCRATCH"
{ printf '%s\n' '.*' '' 1 2 2 x; yes 1; } |
    timeout 3000 bash "$PREFIX/bin/undelete.sh" "$EVIDENCE" "$OUT/"
