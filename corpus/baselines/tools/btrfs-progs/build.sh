# btrfs-progs v7.1: `btrfs` (for `btrfs restore`) and `btrfs-find-root`, from the release
# tarball, which ships `configure` (INSTALL, "To build from the released tarballs"). Only the two
# programs are built; documentation, convert, the Python bindings and libudev are left out.
# Run in the guest by guest/job.sh with bash -e.
tar -xJf "$DL/btrfs-progs/btrfs-progs-v7.1.tar.xz" -C "$SRC"
cd "$SRC/btrfs-progs-v7.1"
./configure --prefix="$PREFIX" --disable-documentation --disable-convert --disable-python \
    --disable-libudev --disable-backtrace
make btrfs btrfs-find-root
install -D -m 755 btrfs "$PREFIX/bin/btrfs"
install -D -m 755 btrfs-find-root "$PREFIX/bin/btrfs-find-root"
"$PREFIX/bin/btrfs" --version > "$PREFIX/VERSION"
