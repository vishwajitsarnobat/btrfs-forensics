# btrForensics (master at 5206e32, 2018) with CMake, against the TSK develop build of this
# harness (needs: tsk; its headers and static libtsk). Its CMakeLists.txt sets the compiler flags
# itself, so our build settings go in with one sed on that file and no source change: C++17
# instead of 11, because the TSK headers it includes need it (TSK's configure.ac makes C++17
# mandatory); `-include cstdint`, because Basics/Enums.h uses uint8_t without including it and
# GCC 13's headers no longer include it on the way (the same failure as FKIE-TSK, whose btrfs code
# is this code); and zlib and pthreads at the end of the link line for the static libtsk.
# Run in the guest by guest/job.sh with bash -e.
tar -xzf "$DL/btrforensics/btrForensics-5206e32.tar.gz" -C "$SRC"
cd "$SRC"/btrForensics-5206e3253778169b954986c38b020f0783bdfc58
sed -i -e 's/set(CMAKE_CXX_STANDARD 11)/set(CMAKE_CXX_STANDARD 17)/' \
    -e 's/set(CMAKE_CXX_FLAGS "-g -Wall -ltsk")/set(CMAKE_CXX_FLAGS "-g -Wall -include cstdint")/' \
    CMakeLists.txt
grep -q 'CMAKE_CXX_STANDARD 17' CMakeLists.txt && grep -q 'include cstdint' CMakeLists.txt
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
