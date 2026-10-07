# btrForensics (master at 5206e32, 2018) with CMake, against the TSK develop build of this
# harness (needs: tsk; its headers and static libtsk). Two changes of ours, both build settings:
# its CMakeLists.txt sets C++11, but the TSK headers it includes need C++17 (TSK's configure.ac
# makes C++17 mandatory), so the standard is raised to 17 with one sed; and the static libtsk
# needs zlib and pthreads at the end of the link line. Run in the guest by guest/job.sh with
# bash -e.
tar -xzf "$DL/btrforensics/btrForensics-5206e32.tar.gz" -C "$SRC"
cd "$SRC"/btrForensics-5206e3253778169b954986c38b020f0783bdfc58
sed -i 's/set(CMAKE_CXX_STANDARD 11)/set(CMAKE_CXX_STANDARD 17)/' CMakeLists.txt
export CPATH=$DEPS/tsk/include LIBRARY_PATH=$DEPS/tsk/lib
mkdir build
cd build
cmake -DCMAKE_CXX_STANDARD_LIBRARIES="-lz -lpthread" ..
make
cd ..
for tool in fsstat fls icat istat subls devls; do
    install -D -m 755 "Tools/$tool" "$PREFIX/bin/$tool"
done
echo "btrForensics master (commit 5206e32) against $(head -n 1 "$DEPS/tsk/VERSION")" \
    > "$PREFIX/VERSION"
