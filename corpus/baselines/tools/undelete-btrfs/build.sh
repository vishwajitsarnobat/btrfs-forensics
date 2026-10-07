# undelete-btrfs v1.0: a bash script, nothing to compile. It calls `btrfs restore` and
# `btrfs-find-root` from PATH; the run puts the btrfs-progs 7.1 build first (needs: btrfs-progs).
# Run in the guest by guest/job.sh with bash -e.
tar -xzf "$DL/undelete-btrfs/undelete-btrfs-1.0.tar.gz" -C "$SRC"
install -D -m 755 "$SRC/undelete-btrfs-1.0/undelete.sh" "$PREFIX/bin/undelete.sh"
echo "undelete-btrfs v1.0 (tag commit f045a80) with $("$DEPS/btrfs-progs/bin/btrfs" --version)" \
    > "$PREFIX/VERSION"
