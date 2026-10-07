# PhotoRec 7.2: the publisher's static x86-64 binary, pinned by SHA-256 (maintainer decision
# 2026-10-07); nothing is compiled. Run in the guest by guest/job.sh with bash -e.
tar -xjf "$DL/photorec/testdisk-7.2.linux26-x86_64.tar.bz2" -C "$SRC"
install -D -m 755 "$SRC/testdisk-7.2/photorec_static" "$PREFIX/bin/photorec_static"
"$PREFIX/bin/photorec_static" /version | grep -m 1 'PhotoRec' > "$PREFIX/VERSION"
