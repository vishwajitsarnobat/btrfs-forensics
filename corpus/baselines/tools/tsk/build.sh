# The Sleuth Kit `develop` at 424ee3c, the last commit with the experimental btrfs code (the
# default branch develop-4.1x has none; docs/research/baselines.md §3.6). A git archive has no
# configure, so ./bootstrap (autoreconf -fi) runs first. Static libtsk, no Java, none of the
# optional image-format libraries; zlib is found, the only decompressor its btrfs code uses.
# The install tree (headers and libtsk.a) is also what btrForensics builds against.
# Run in the guest by guest/job.sh with bash -e.
tar -xzf "$DL/tsk/sleuthkit-424ee3c.tar.gz" -C "$SRC"
cd "$SRC"/sleuthkit-424ee3ce50fff43c8e29de6c5becc3e88ed5e39d
./bootstrap
./configure --prefix="$PREFIX" --disable-java --disable-shared --without-afflib \
    --without-libewf --without-libvhdi --without-libvmdk --without-libbfio --without-libqcow \
    --without-libvslvm --without-libaff4 --without-libcrypto
make
make install
echo "$("$PREFIX/bin/fls" -V) (develop, commit 424ee3c)" > "$PREFIX/VERSION"
