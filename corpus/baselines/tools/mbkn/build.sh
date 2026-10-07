# mbkn-btrfs-rescue v0.4.0 needs CPython 3.14 (noble has 3.12): the python-build-standalone
# CPython 3.14.7 build of the lock, with the wheels its uv.lock pins for its runtime dependencies
# (lock group mbkn-deps, uv.lock's SHA-256) installed offline. Its build backend (uv_build) is not
# available offline, so its package directory is copied into site-packages as it is; nothing in
# it is compiled. Run in the guest by guest/job.sh with bash -e.
tar -xzf "$DL/mbkn/cpython-3.14.7+20260901-x86_64-unknown-linux-gnu-install_only.tar.gz" \
    -C "$PREFIX"
P=$PREFIX/python/bin/python3
"$P" -m pip install --no-index --no-deps --disable-pip-version-check --root-user-action=ignore \
    "$DL"/mbkn-deps/wheels/*.whl
tar -xzf "$DL/mbkn/mbkn-btrfs-rescue-0.4.0.tar.gz" -C "$SRC"
site=$("$P" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')
cp -R "$SRC/mbkn-btrfs-rescue-0.4.0/src/mbkn_btrfs_rescue" "$site/"
echo "$("$P" -m mbkn_btrfs_rescue --version) (tag v0.4.0, commit c2eddfb), $("$P" --version)" \
    > "$PREFIX/VERSION"
