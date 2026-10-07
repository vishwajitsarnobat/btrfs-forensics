# SecurityRonin btrfs-forensic 0.1.3 (with btrfs-core 0.1.5) through our harness crate
# (harness/), built offline with noble's rustc and cargo 1.89. Every crate comes from the lock
# (groups securityronin and securityronin-deps, crates.io's own checksums) and is vendored as a
# directory source; harness/Cargo.lock pins the resolution. Run in the guest by guest/job.sh with
# bash -e.
V=$SRC/vendor
mkdir -p "$V"
for crate in "$DL"/securityronin/crates/*.crate "$DL"/securityronin-deps/crates/*.crate; do
    tar -xzf "$crate" -C "$V"
    dir=$V/$(basename "$crate" .crate)
    printf '{"files":{},"package":"%s"}' "$(sha256sum < "$crate" | cut -d' ' -f1)" \
        > "$dir/.cargo-checksum.json"
done
cp -R "$RECIPE/harness" "$SRC/harness"
cd "$SRC/harness"
mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[source.crates-io]
replace-with = "vendored"
[source.vendored]
directory = "$V"
EOF
export CARGO_HOME=/work/cargo
locked=
[ -r Cargo.lock ] && locked=--locked
cargo build --release --offline $locked
install -D -m 755 target/release/recover_deleted "$PREFIX/bin/recover_deleted"
cp Cargo.lock "$PREFIX/Cargo.lock"
echo "btrfs-forensic 0.1.3 + btrfs-core 0.1.5 (tag commit e6cd73f), harness 0.1.0, $(rustc --version)" \
    > "$PREFIX/VERSION"
