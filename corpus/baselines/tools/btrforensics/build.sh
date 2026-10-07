# btrForensics (master at 5206e32, 2018) with CMake. It links libtsk for image access, and it is
# built against the libtsk of its time: TSK 4.4.2, as the FKIE-TSK build of this harness provides
# it (needs: fkie-tsk; headers and static libtsk). Against TSK develop it does not compile:
# Utility/Uuid.cpp does pointer arithmetic on gpt_entry.type_guid, a uint8_t[16] in TSK 4.4.2
# (tsk/vs/tsk_gpt.h:52) and a struct gpt_guid in develop (tsk/vs/tsk_gpt.h:42, 66), the build
# failing with "no match for 'operator+' (operand types are 'gpt_guid' and 'int')".
# Its CMakeLists.txt sets the compiler flags itself, so one sed on that file adds
# `-include cstdint` (Basics/Enums.h uses uint8_t without including it and GCC 13's headers no
# longer include it on the way, the failure FKIE-TSK has too, whose btrfs code is this code) and
# drops `-ltsk` from the compile flags; no source file changes. The static libtsk needs zlib,
# pthreads and libdl at the end of the link line. Run in the guest by guest/job.sh with bash -e.
tar -xzf "$DL/btrforensics/btrForensics-5206e32.tar.gz" -C "$SRC"
cd "$SRC"/btrForensics-5206e3253778169b954986c38b020f0783bdfc58
sed -i 's/set(CMAKE_CXX_FLAGS "-g -Wall -ltsk")/set(CMAKE_CXX_FLAGS "-g -Wall -include cstdint")/' \
    CMakeLists.txt
grep -q 'include cstdint' CMakeLists.txt
export CPATH=$DEPS/fkie-tsk/include LIBRARY_PATH=$DEPS/fkie-tsk/lib
mkdir build
cd build
cmake -DCMAKE_CXX_STANDARD_LIBRARIES="-lz -lpthread -ldl" ..
make
cd ..
for tool in fsstat fls icat istat subls devls; do
    install -D -m 755 "Tools/$tool" "$PREFIX/bin/$tool"
done
echo "btrForensics master (commit 5206e32) against libtsk of $(head -n 1 "$DEPS/fkie-tsk/VERSION")" \
    > "$PREFIX/VERSION"
