# FKIE-TSK (fkie-cad/sleuthkit `develop` at 4237621, TSK 4.4.2 with btrfs as a pool), autotools
# via ./bootstrap. Its btrfs is reachable only through the pool tools (fls, icat with -P); its
# tsk_recover cannot open btrfs (docs/research/baselines.md §3.7). Code of 2017 on GCC 13: the
# C++ is compiled as C++14, the default of the GCC of its time (GCC 13 defaults to C++17, which
# removed `register` and dynamic exception specifications). That is a compiler flag, not a patch.
# Run in the guest by guest/job.sh with bash -e.
tar -xzf "$DL/fkie-tsk/fkie-sleuthkit-4237621.tar.gz" -C "$SRC"
cd "$SRC"/sleuthkit-423762115e7b1dc7c0ad27c634db4d48328f2a0c
./bootstrap
./configure --prefix="$PREFIX" --disable-java --disable-shared --without-afflib \
    --without-libewf CXXFLAGS="-O2 -std=gnu++14"
make
make install
echo "$("$PREFIX/bin/fls" -V) (fkie-cad develop, commit 4237621)" > "$PREFIX/VERSION"
