# Baseline tools for M7: sources, pins, builds and read-only runs

Answer to GitHub issue #47. For each baseline named in `docs/plan.md` §5 M7 ("Baseline
harness"), plus `michal2229/mbkn-btrfs-rescue`, this note gives the canonical source, the
version to pin with its tarball URL and SHA-256, the licence, the toolchain and build
dependencies, whether it can be built in the Ubuntu 24.04 guest from pinned packages, how to
run it read-only against an image, and what it writes out for scoring.

**How this was checked (2026-10-07).** Repository metadata, tags and releases were read from
the GitHub REST API; crate metadata from the crates.io API; package versions and hashes from the
`noble`, `noble-updates` Packages indices of the snapshot that `corpus/vm/fetch_vm.sh` uses
(`https://snapshot.ubuntu.com/ubuntu/20260919T000000Z/`). Every tarball below was downloaded into
`images/scratch/baselines/` and hashed with `sha256sum`; the source was read there, never
executed. **No tool was built or run.** Every statement about build success, run-time behaviour
or exact command lines that has not been exercised is marked UNVERIFIED; statements about what
the source code does cite the file and line in the pinned tarball.

## 1. The constraints this must satisfy

From `CONTRIBUTING.md` §4 and `corpus/vm/README.md`:

- Every input is fetched by URL and pinned by SHA-256 (as in `corpus/vm/guest.lock`). Nothing is
  installed on the host, nothing needs root, everything lands under the gitignored `images/`.
- Baselines are built and run inside the QEMU guest, not on the host.
- The guest today is a **busybox initramfs**: busybox-static, `btrfs` 6.6.3 and its shared
  libraries, four kernel modules and `/init` (`corpus/vm/build_initramfs.sh`). It has no compiler,
  no bash, no network, and the scenario image is `/dev/vda`. So "build in the guest" means adding
  a build environment; §4 proposes one.
- Evidence is read-only. The image copy can be attached with QEMU's `readonly=on`, which makes the
  guest block device itself refuse writes, independent of what each tool does.

## 2. Summary

| Tool | Pin | SHA-256 of the pinned source | Licence | Toolchain | Builds in the noble guest? | Reads image how |
|---|---|---|---|---|---|---|
| btrfs-progs (`btrfs restore`, `btrfs-find-root`) | v7.1 (tag commit `4ab0e80`, 2026-07-14) | `d1f55cc29713…` | GPL-2.0 | C, autotools (configure shipped) | Yes, from noble `-dev` packages (UNVERIFIED) | block device or file, `O_RDONLY` |
| undelete-btrfs | v1.0 (tag commit `f045a80`) | `65d0aef4fc74…` | GPL-3.0 | Bash script, no build | Needs bash + `tput` added to the guest | via `btrfs restore` |
| PhotoRec (TestDisk) | 7.2 | static binary `19669b6d3631…`; source `f8343be20cb4…` | GPL-2.0-or-later | C, autotools (configure shipped) | Not needed: upstream ships a static x86-64 binary | file or device, read-only flag |
| btrfscue `recover` | v0.7 (tag commit `5d87ef3`, 2026-07-04) | tag archive `8aee2ebee460…` (see §3.4) | BSD-2-Clause | Go ≥ 1.18, 13 modules not vendored | Yes with noble `golang-1.24` or the go.dev tarball + a local module proxy (UNVERIFIED) | `os.Open` (read-only) |
| SecurityRonin `btrfs-forensic` `recover_deleted` | crate 0.1.3 + `btrfs-core` 0.1.5 (both tag commit `e6cd73f`) | `49f242bd84a9…` / `ee286263ad67…` | Apache-2.0 | Rust, MSRV 1.87; library only | Yes with noble `rustc-1.89` + vendored crates; needs a small harness binary of ours (UNVERIFIED) | whole image as a byte slice |
| The Sleuth Kit `develop` | commit `424ee3c` (2026-04-26) | `cf36664af42e…` | CPL-1.0 (btrfs code) plus IBM-PL and others | C/C++17, autotools via `autoreconf` | Yes from noble packages (UNVERIFIED) | file or device |
| FKIE-TSK (`fkie-cad/sleuthkit`) | `develop` at `4237621` (2022-10-19) | `8aea1f88931b…` | CPL-1.0 and others | C/C++, autotools via `autoreconf` | Uncertain: 2017-era code on GCC 13 (UNVERIFIED) | pool directory of member images |
| btrForensics | `master` at `5206e32` (2018-08-06) | `05129f94ccde…` | MIT | C++11, CMake, links libtsk | Probably, against TSK from this list or noble `libtsk-dev` (UNVERIFIED) | file via `tsk_img_open` |
| mbkn-btrfs-rescue | v0.4.0 (tag commit `c2eddfb`, 2026-09-27) | `550e15e9b3ef…` | GPL-3.0 | Python ≥ 3.14, uv; wheels locked | Needs CPython 3.14 and wheels brought in by URL (UNVERIFIED) | file or device, `O_RDONLY` |

The table shows the first 12 hex digits; full hashes are in each section.

**Hard cases, in short.**

1. **FKIE-TSK has no `tsk_recover -e` for btrfs.** In the fork, btrfs is reachable only through
   its pool layer (`fls`, `istat`, `icat`, `fsstat` with `-P`); `tsk_recover` has no pool
   option and `tsk/fs/fs_open.c` has no btrfs entry (§3.7). The plan's line "FKIE-TSK
   `tsk_recover -e`" cannot be run as written. Its btrfs `fls` lists the live tree only.
2. **TSK `develop` btrfs is narrow.** It opens only crc32c filesystems (other checksum types are
   skipped as "unknown", `tsk/fs/btrfs.cpp:886-891`), decodes only zlib extents, and sees a
   "deleted" file only while its inode is still in the live tree with `nlink == 0`
   (`btrfs.cpp:2699`). Upstream's default branch is now `develop-4.1x`, which has no btrfs code at
   all (checked 2026-10-07), so the pin must name the `develop` commit.
3. **SecurityRonin `recover_deleted` is a library call, not a program.** It needs a harness
   binary of ours, takes the whole image as `&[u8]` (RAM at least the image size unless the
   harness maps the file), looks only at FS tree 5, and reads each tree root as a single node:
   if a root is an interior node it yields nothing, so on any FS tree taller than one leaf it
   recovers nothing or misclassifies (§3.5).
4. **btrfscue does not decompress and does not restore metadata.** Compressed extents are copied
   raw (`cmd/recover.go:164-215`), files are created `0644` with no times; its README still says
   restoring files larger than the block size does not work, while the v0.7 release notes say
   multi-extent recovery was added. Measure, do not assume.
5. **undelete-btrfs is interactive and needs bash, `tput` and `EUID == 0`.** It must be driven
   through stdin; it stops at the first depth that finds anything unless told to go deeper.
6. **btrForensics cannot list deleted files** (its own `Tools/FLS_README.md`); it is a live-tree
   baseline only, and it is dead since 2018.
7. **mbkn-btrfs-rescue is 10 days old** (repository created 2026-09-27, three tags that day) and is
   the closest in design to `btrfska` (sweeps every tree block, all generations). It is not in the
   plan's list; adding it is the maintainer's decision.
8. **Commercial tools** (UFS Explorer, R-Studio) need a paid licence; per `CONTRIBUTING.md` §7 they
   stay out unless the maintainer decides otherwise.

None of the nine is dead in the sense of "unavailable": every source above downloaded on
2026-10-07. FKIE-TSK (last push 2022-10-19) and btrForensics (2018-08-06) are unmaintained.

## 3. Per tool

### 3.1 btrfs-progs ≥ 7.1: `btrfs restore` and `btrfs-find-root`

- **Canonical source:** <https://github.com/kdave/btrfs-progs> (release tarballs on kernel.org).
- **Pin:** v7.1, released 2026-07-14, tag commit `4ab0e80be9e3bb1db2e6038e6d4316d35fb7ba8b`.
  It is the newest tag (v7.0 was 2026-05-09).
- **Tarball:** <https://mirrors.edge.kernel.org/pub/linux/kernel/people/kdave/btrfs-progs/btrfs-progs-v7.1.tar.xz>
  SHA-256 `d1f55cc2971398c9142eaa79d203e63d586a3b4b867f956664a1d68322cd4e34`. This matches the
  maintainer's signed `sha256sums.asc` in the same directory (the signature itself was not
  checked). A detached `btrfs-progs-v7.1.tar.sign` covers the uncompressed tar.
- **Licence:** GPL-2.0 (GitHub metadata; `COPYING`).
- **Toolchain:** C, autotools; the release tarball ships a generated `configure`, so autoconf is
  not needed (`INSTALL`, "To build from the released tarballs").
- **Build dependencies** (`INSTALL`, `configure.ac:452-501`): libuuid, libblkid, zlib, liblzo2,
  libzstd; libudev optional. Documentation, `btrfs-convert` and the Python bindings can be
  disabled.
- **Builds in the guest?** Probably yes (UNVERIFIED). Everything needed is in noble:
  `gcc-13`, `make`, `pkgconf`, `libc6-dev`, `uuid-dev`, `libblkid-dev`, `zlib1g-dev`,
  `liblzo2-dev`, `libzstd-dev` (versions and hashes in the noble-updates index). The Makefile has
  static targets (`Makefile:631` `static:`, `Makefile:697` pattern rule `btrfs-%.static`,
  `Makefile:715` `btrfs.static`), so
  `./configure --disable-documentation --disable-convert --disable-python --disable-libudev &&
  make btrfs.static btrfs-find-root.static` should give two self-contained binaries that drop
  straight into the busybox initramfs, using the `.a` archives the noble `-dev` packages ship
  (UNVERIFIED).
- **Prebuilt alternative:** Debian ships `7.1-1` in sid/forky and `7.1-1~bpo13+1` in
  trixie-backports (sources.debian.org API). Those binaries are linked against Debian's newer
  glibc; whether they run with noble's glibc 2.39 is UNVERIFIED. Building from source is cleaner.
- **Read-only run.** Both open the device read-only: `open_ctree` uses `O_RDONLY` unless
  `OPEN_CTREE_WRITES` is set (`kernel-shared/disk-io.c:1741-1742`); restore passes
  `OPEN_CTREE_PARTIAL | OPEN_CTREE_NO_BLOCK_GROUPS | OPEN_CTREE_ALLOW_TRANSID_MISMATCH`
  (`cmds/restore.c:1237-1238`), find-root passes `OPEN_CTREE_CHUNK_ROOT_ONLY |
  OPEN_CTREE_IGNORE_CHUNK_TREE_ERROR` (`btrfs-find-root.c:388`). They take a block device or a
  plain file; no loop device and no mount. With the image attached read-only as `/dev/vdb`:

  ```sh
  btrfs restore -i -m -S -s -x -v /dev/vdb /out/restore-live          # current roots
  btrfs-find-root /dev/vdb > /out/roots.txt 2>&1                       # candidate old roots
  btrfs-find-root -a /dev/vdb > /out/roots-all.txt 2>&1                # every candidate
  btrfs restore -t BYTENR -i -m -S -s -x -v /dev/vdb /out/restore-$BYTENR   # per root
  ```

  Options from `cmds/restore.c:1346-1385`: `-i` ignore errors, `-m` owner/mode/times, `-S`
  symlinks, `-s` snapshots, `-x` xattrs, `-t` tree location, `-D` dry run. Root bytenrs are the
  `Well block N` lines of find-root output (the parse undelete-btrfs uses, `undelete.sh:251`).
- **Output for scoring:** a directory tree with original paths and, with `-m`, original mode and
  times. One tree per `-t` root; the harness merges them and records which root produced a file.
- **Plan note:** M7's "beyond-4-generations" variant (a) expects find-root + restore to reach a
  state outside the backup roots; this pair is the baseline for it.

### 3.2 undelete-btrfs v1.0

- **Canonical source:** <https://github.com/danthem/undelete-btrfs>.
- **Pin:** tag v1.0, commit `f045a80cc3db8a906c1dbd4787ddff8bc98d7601` (committed 2025-09-13;
  the GitHub release was published 2025-12-27). The only later commit, `e9cf44b` (2026-08-18), is
  a README typo fix.
- **Tarball:** <https://github.com/danthem/undelete-btrfs/archive/refs/tags/v1.0.tar.gz>
  SHA-256 `65d0aef4fc746e7d31ed1ad5eac06dbb36495c87a8787ac84c2e15e47f5f34a0` (a GitHub-generated
  archive; see §4.5).
- **Licence:** GPL-3.0. **Language:** Bash (`undelete.sh`, 15 KB). No build.
- **Runtime needs** (read from `undelete.sh`): `bash` (it uses `[[ ]]`, `readarray -d`,
  `read -e`), `tput` (lines 19-24), `clear`, awk, `sed -r`, `grep -E/-a/-cw`, `sort`, `find
  -empty -delete`, `/etc/mtab` (line 85), `EUID == 0` (line 60), and `btrfs` and
  `btrfs-find-root` on `PATH`. The README says it was tested with btrfs-progs 6.16.1. In the guest
  this means adding noble's `bash`, `ncurses-bin`, `libtinfo6` (and a terminfo entry) to the
  run-time image, linking `/etc/mtab` to `/proc/mounts`, and putting the 7.1 binaries from §3.1 on
  `PATH`. The guest already runs as root.
- **What it does:** builds a `--path-regex` from a path the user types, then dry-runs and
  restores at three depths: 0 = plain `btrfs restore`; 1 = every root from `btrfs-find-root`;
  2 = every root from `btrfs-find-root -a` (`undelete.sh:160-300`, README "Depth?").
- **Read-only run:** inherits `btrfs restore`'s read-only open (§3.1). `syntaxcheck` only tests
  that the source exists (`-a`), so `/dev/vdb` or an image file both work. It is interactive and
  must be driven through stdin, for example (UNVERIFIED):

  ```sh
  printf '%s\n' '.*' '' 1 1 | TERM=linux bash undelete.sh /dev/vdb /out/undelete/
  ```

  Answers: path `.*` (everything), Enter after the dry-run notice, `1` recover, `1` exit. If depth 0
  finds anything it stops there (`checkresult`, lines 176-240); a second run that answers `2` until
  depth 2 measures the deepest mode. The script's dry-run filter greps `Restoring.*$recname`, which
  with `.*` matches every line.
- **Output for scoring:** files under the destination with original paths (it calls `btrfs
  restore -ivv` without `-m`, so no metadata), empty files deleted.

### 3.3 PhotoRec (TestDisk) 7.2

- **Canonical source:** <https://www.cgsecurity.org/wiki/TestDisk_Download>, code at
  <https://github.com/cgsecurity/testdisk>.
- **Pin:** 7.2 (tag v7.2, commit `281be432dd79121e08e0898887a9ee1f30fb3e96`), the newest release.
- **Prebuilt static binary (recommended):**
  <https://www.cgsecurity.org/testdisk-7.2.linux26-x86_64.tar.bz2>
  SHA-256 `19669b6d36314d6e531efdf836c768574e8a556d1e9db3c8f3c4e93a5092cb1c`, which matches the
  publisher's list <https://www.cgsecurity.org/testdisk_sha256.txt>. It contains `photorec_static`,
  which `file` reports as "ELF 64-bit LSB executable, x86-64, statically linked". It runs in the
  busybox initramfs with no libraries (UNVERIFIED by a run). It is a vendor binary, not built by
  us; if the maintainer wants every baseline built from source, use the source tarball.
- **Source tarball:** <https://www.cgsecurity.org/testdisk-7.2.tar.bz2>
  SHA-256 `f8343be20cb4001c5d91a2e3bcd918398f00ae6d8310894a5a9f2feb813c283f` (also in the
  publisher's list). `configure` is shipped; `photorec` is always in `bin_PROGRAMS`
  (`src/Makefile.am:35`); ncurses, libjpeg, ext2fs, ntfs, ntfs-3g, ewf, iconv, uuid, zlib are all
  optional `--with/--without` switches (`configure.ac:36-193`). A guest build needs only `gcc-13`,
  `make`, `libc6-dev` (UNVERIFIED). Noble also has a prebuilt `testdisk 7.1-5+nmu1build2`
  (`dfef5dcd9d0d74238d85247662df518a362040cd03e5b347ab37c9e28764bfa1`), with eight library
  dependencies.
- **Licence:** GPL-2.0-or-later (GitHub reports GPL-2.0).
- **Read-only run:** PhotoRec opens the source with `TESTDISK_O_RDONLY` (`src/phmain.c:170`). It
  reads a file or a block device; no loop device or mount. Non-interactive use is the `/cmd`
  mode (`src/phmain.c:303`, parser in `src/phcli.c`); btrfs has no free-space support in
  PhotoRec, so carve the whole space (UNVERIFIED exact string):

  ```sh
  photorec_static /log /d /out/photorec/recup_dir /cmd /dev/vdb \
      partition_none,options,keep_corrupted_file,fileopt,everything,enable,wholespace,search
  ```

- **Output for scoring:** `recup_dir.N/fNNNNNNN.ext` files with no names, paths or times, plus a
  DFXML `report.xml` per directory with the byte runs of every carved file (`src/dfxml.c:83`;
  DFXML is on unless configured off, `configure.ac:216-223`). Score by hash only; report "files
  produced" separately because a carver produces more files than were deleted (plan §5 M7
  metrics).

### 3.4 btrfscue v0.7 `recover`

- **Canonical source:** <https://github.com/cblichmann/btrfscue>.
- **Pin:** v0.7, released 2026-07-04, tag commit `5d87ef39543cdf294c7b5d59d5676bf209eb5354`.
- **Tarballs:** the release asset
  <https://github.com/cblichmann/btrfscue/releases/download/v0.7/btrfscue_0.7.orig.tar.xz>
  with SHA-256 `5e38f966928cc7c23e95f34aacbb7688b88127dbd1b22b93f2ecdd9dcf6d91c7` (the digest
  GitHub publishes for the asset; the download failed here because
  `release-assets.githubusercontent.com` did not resolve, so this hash was **not recomputed**), or
  the tag archive <https://github.com/cblichmann/btrfscue/archive/refs/tags/v0.7.tar.gz>
  SHA-256 `8aee2ebee4602218b9e4797170e2ae728e3d2c7c543f5dd74cb7b63b10917c31` (computed). The
  release's only binaries are arm64 `.deb` files, so amd64 must be built.
- **Licence:** BSD-2-Clause (`LICENSE`, `Makefile` SPDX line; GitHub shows NOASSERTION).
- **Toolchain:** Go ≥ 1.18 (`go.mod`: `go 1.18`). **Dependencies:** 13 modules in `go.sum`
  (cobra, pflag, bbolt, go-fuse/v2, cheggaaa/pb/v3 and their indirect dependencies); there is no
  `vendor/` directory.
- **Builds in the guest?** Yes in principle (UNVERIFIED). Toolchain options, both pinnable:
  noble-updates `golang-1.24-go 1.24.4-1ubuntu1~24.04.2`
  (`79f3c3d8daa5fbc0767c4d8caec2f1d42d8f3e9bb85e5be9c6bd9397ed836d6b`, needs `golang-1.24-src`
  `643cd7b4bb3b928812d31f34395709c4dbc391ee44c6e19e112eab469c293c4a`), or the official
  <https://go.dev/dl/go1.24.13.linux-amd64.tar.gz>
  `1fc94b57134d51669c72173ad5d49fd62afb0f1db9bf3f798fd98ee423f8d730` (from go.dev's JSON
  index). The guest has no network, so the host fetches each module zip from
  `https://proxy.golang.org/<module>/@v/<version>.zip` (plus `.mod` and `.info`) into a file
  proxy under `images/`, and the guest builds with
  `GOPROXY=file:///… GOFLAGS=-mod=mod GOTOOLCHAIN=local CGO_ENABLED=0 go build ./cmd/btrfscue`.
  `go.sum` gives the integrity check, so the module set is pinned by the tarball. FUSE is only used
  by the `mount` subcommand; the build does not need the FUSE kernel module.
- **Read-only run:** `recon` and `recover` open the image with `os.Open` (read-only;
  `cmd/recon.go:54`, `cmd/recover.go:53`) and open the metadata database read-only for
  `recover` (`cmd/recover.go:49`). No loop device, no mount (the README's `mount` step is optional).

  ```sh
  btrfscue identify /dev/vdb                      # optional: the FSID is in the image manifest
  btrfscue recon --id FSID --metadata /out/meta.db /dev/vdb
  btrfscue recover --metadata /out/meta.db /dev/vdb /out/btrfscue/
  ```

- **Output for scoring:** a directory tree from the FS tree root, plus every unreferenced
  subvolume as `subvol_<ID>/` (`cmd/recover.go:77`). Limits read from source: no
  decompression, the extent bytes are copied as stored (`cmd/recover.go:164-215`); files are
  created with mode `0644` and no times or owner (`cmd/recover.go:148`); single-device mapping
  (`ix.Physical`); README "This definitely does not work" lists files bigger than the block size
  and multi-device, while the v0.7 release notes claim multi-extent support. Expect zero hash
  matches for compressed files.

### 3.5 SecurityRonin `btrfs-forensic` `recover_deleted`

- **Canonical source:** <https://github.com/SecurityRonin/btrfs-forensic>; crates
  <https://crates.io/crates/btrfs-forensic> and <https://crates.io/crates/btrfs-core>.
- **Pin:** `btrfs-forensic` 0.1.3 and `btrfs-core` 0.1.5, both published 2026-08-26 and both
  tagged at commit `e6cd73f3fb15155e7c7b254f66c0b2086a39c834` (tags `btrfs-forensic-v0.1.3`,
  `btrfs-core-v0.1.5`). The same commit `docs/research.md` §10.12 read. `main` has moved on
  (`d58e436`, 2026-09-21: hard links, forensic-vfs 0.9) without a release; pin the release.
- **Tarballs and hashes:**
  - <https://static.crates.io/crates/btrfs-forensic/btrfs-forensic-0.1.3.crate>
    `49f242bd84a9d2dc6b9a94bdfe399e3bdbc54d0c026aafeab1251ff9c237dd07`
  - <https://static.crates.io/crates/btrfs-core/btrfs-core-0.1.5.crate>
    `ee286263ad672971c2dc1e4d9c7e6bf0e9aab594e94cc152aa44bd613ce93d4b`
  - both equal crates.io's own checksums; the workspace at the tag,
    <https://github.com/SecurityRonin/btrfs-forensic/archive/e6cd73f3fb15155e7c7b254f66c0b2086a39c834.tar.gz>,
    is `97002fba24a98ce2053a769d59fde65c047f32f979f3656f044df1c6188da3ed`.
- **Licence:** Apache-2.0. **Language:** Rust 2021, `#![forbid(unsafe_code)]`.
- **Toolchain:** MSRV 1.87, set by `ruzstd 0.8` (workspace `Cargo.toml`); `rust-toolchain.toml`
  names 1.96.0, which only matters under rustup. The workspace `Cargo.lock` at the tag holds 22
  registry crates; all their checksums match crates.io, and the highest `rust-version` among them
  is 1.87 (`ruzstd 0.8.3`); licences are MIT/Apache-2.0/0BSD/Zlib/Unicode-3.0 combinations. No C
  dependencies (flate2 uses `miniz_oxide`).
- **Builds in the guest?** Yes in principle (UNVERIFIED). noble-updates has `rustc-1.89` +
  `cargo-1.89` (`6d3ef7d9…e3334` / `66d62d33…dec93`) and `rustc-1.91` + `cargo-1.91`; the
  official <https://static.rust-lang.org/dist/rust-1.89.0-x86_64-unknown-linux-gnu.tar.xz> is
  `c4f2796b10ee886001f0799bc40caea38746403a33c379d77878c4f4683f9b51`. Vendoring without network:
  the host fetches each `.crate` named in `Cargo.lock` from
  `https://static.crates.io/crates/<name>/<name>-<version>.crate`, checks it against the lock's
  checksum, unpacks it into `vendor/<name>-<version>/` with a `.cargo-checksum.json` of
  `{"files":{},"package":"<sha256>"}`, and the guest builds with a source-replacement
  `.cargo/config.toml` and `cargo build --offline --locked`.
- **No CLI exists.** The crate is a library (`[lib]` only, `autobins = false`). The baseline needs
  a harness crate of ours, about 30 lines: read the image, call
  `btrfs_forensic::recover_deleted(&image)`, write each `RecoveredFile.content` to
  `/out/securityronin/<inode>_<name>` and a TSV of `path, inode, generation, size,
  content_sha256` (the struct's fields, `forensic/src/lib.rs:541-556`). Reading the whole image
  into memory needs guest RAM above the image size; mapping it with `memmap2` in the harness avoids
  that (the `unsafe` would be in our harness, not in their crate).
- **What `recover_deleted` does** (`forensic/src/lib.rs:639-690`, `570-630`): parse the primary
  superblock, read the current FS tree 5 root **as one node**, then for each of the four backup
  roots read its `fs_root` as one node and report inodes ≥ 257 that are in the old node and not in
  the current one and still have an `EXTENT_DATA` item. `Node::leaf_items` yields nothing for an
  interior node (`core/src/node.rs:284-290`). Consequences read from that code (not run):
  - if the old root is interior (any FS tree taller than one leaf), nothing is recovered;
  - if the current root is interior but an old one is a leaf, every inode of the old leaf looks
    deleted, so live files are reported too; scoring must count against the ground-truth deleted
    set;
  - only FS tree 5, never a subvolume; the name is the bare directory-entry name, not a path;
  - the README mentions crc32c only (UNVERIFIED for other checksum types).
- **Output for scoring:** what the harness writes: content plus name and the generation it came
  from.

### 3.6 The Sleuth Kit, `develop` (experimental btrfs)

- **Canonical source:** <https://github.com/sleuthkit/sleuthkit>.
- **Pin:** `develop` at `424ee3ce50fff43c8e29de6c5becc3e88ed5e39d` (2026-04-26, "Merge pull
  request #3489 from sleuthkit/release-4.13.0"; `configure.ac` says `4.15.0-develop`). No release
  has btrfs: `NEWS.txt` says 4.14.0 "does NOT have the experimental btrfs", and the
  `sleuthkit-4.15.0` tag has no btrfs files (`docs/research.md` §10.2). The repository's default
  branch is now `develop-4.1x` (last commit 2026-10-06); its `tsk/fs/` has no btrfs files and it
  has diverged from `develop` (GitHub compare API, 2026-10-07). PR #3466 (memory fixes to the
  btrfs code) is still open, so the pinned code does not have them.
- **Tarball:** <https://github.com/sleuthkit/sleuthkit/archive/424ee3ce50fff43c8e29de6c5becc3e88ed5e39d.tar.gz>
  SHA-256 `cf36664af42e5388847dc6572605157b61f4b9ad5aa2eab0ed4586bc12684fee` (GitHub-generated, §4.5).
- **Licence:** mixed; `tsk/fs/btrfs.cpp` is under the Common Public License 1.0 (file header);
  the tree also carries IBM Public License, GPL, MIT and Apache texts (`licenses/`).
- **Toolchain:** C and C++17 (`configure.ac:18` `AX_CXX_COMPILE_STDCXX([17], …, [mandatory])`).
  A git archive has no `configure`, so `./bootstrap` (`autoreconf -fi`) needs autoconf,
  automake and libtool. Btrfs is compiled unconditionally (`Makefile.am:237-238`). zlib is
  optional and is the only decompressor btrfs uses (`#ifdef HAVE_LIBZ`, `btrfs.cpp:3353` on);
  sqlite falls back to a bundled copy (`configure.ac:120-131`); Java off with `--disable-java`.
- **Builds in the guest?** Probably (UNVERIFIED): noble `g++-13`, `make`, `autoconf 2.71`,
  `automake 1.16.5`, `libtool 2.4.7`, `zlib1g-dev`, `pkgconf`.
  `./bootstrap && ./configure --disable-java --without-afflib --without-libewf --without-libvhdi
  --without-libvmdk && make`.
- **What the btrfs code supports** (source, not run):
  - checksum: crc32c only; a superblock with another `csum_type` is skipped as unknown
    (`btrfs.cpp:741-750`, `886-891`), so the xxhash, sha256 and blake2b rows of the M7 matrix
    will not open;
  - incompat flags accepted: mixed backref, default subvol, mixed groups, LZO, ZSTD, big
    metadata, extended iref, RAID56, skinny metadata, no-holes (`tsk/fs/tsk_btrfs.h:76-86`); any
    other bit is refused (`btrfs.cpp:4976-4983`). LZO and ZSTD are accepted at the superblock but
    "not (yet) supported" for extents (`tsk_btrfs.h:68-69`);
  - "deleted": an inode is unallocated when its `nlink` is 0 (`btrfs.cpp:2699`); there is no
    walk of older roots, so a file whose items left the live tree is invisible.
- **Read-only run:** TSK opens images read-only; file or block device, no loop device or mount.
  Btrfs is in the autodetect table (`tsk/fs/fs_open.c:149`) and named `btrfs` for `-f`
  (`tsk/fs/fs_types.c:70`).

  ```sh
  tsk_recover -e -f btrfs /dev/vdb /out/tsk/          # -e: allocated and unallocated
  fls -r -p -f btrfs /dev/vdb > /out/tsk-fls.txt       # names, with deleted entries marked
  ```

  (Options from `tools/autotools/tsk_recover.cpp:20-46`.)
- **Output for scoring:** files under the output directory with their paths, plus `fls` output
  for names. No timestamps are restored on the written files; `fls -l` or `-m` prints them.

### 3.7 FKIE-TSK: `fkie-cad/sleuthkit`

- **Canonical source:** <https://github.com/fkie-cad/sleuthkit> (Hilgert et al., DFRWS 2017/2018).
- **Pin:** `develop` at `423762115e7b1dc7c0ad27c634db4d48328f2a0c` (2022-10-19, the last push;
  103 commits ahead of the fork's `master`, which is upstream 4.4.2). No tags of its own.
- **Tarball:** <https://github.com/fkie-cad/sleuthkit/archive/423762115e7b1dc7c0ad27c634db4d48328f2a0c.tar.gz>
  SHA-256 `8aea1f88931bc353eeb98bf3ab5f214bc730028978dd4b28864319b0f508d73f` (GitHub-generated, §4.5).
- **Licence:** CPL-1.0 (e.g. `tools/pooltools/pls.cpp` header) plus upstream TSK's mix; GitHub
  reports none.
- **Toolchain:** C/C++ on TSK 4.4.2 (`configure.ac:7`), autotools via `./bootstrap`; a
  `CMakeLists.txt` also exists. Btrfs lives in `tsk/fs/btrfs/` (C++ classes) and
  `tsk/pool/BTRFS_POOL.cpp`.
- **The hard case.** Btrfs is reachable only through the pool layer:
  `TSK_POOL_INFO` builds a `BTRFS_POOL` from a **directory of member images**
  (`tsk/pool/TSK_POOL_INFO.cpp:18-69`), and only `fls`, `istat`, `icat` and `fsstat` accept `-P`
  (`tools/fstools/fls.cpp:36-62`, `icat.cpp:38-59`). `tsk/fs/fs_open.c` has no btrfs entry and
  `tools/autotools/tsk_recover.cpp` has no pool option, so **`tsk_recover -e` cannot open a btrfs
  filesystem in this fork**. `BTRFS_POOL::fls` lists the live FS tree (or a named subvolume); the
  `-T` generation argument is accepted but unused for btrfs (`tsk/pool/BTRFS_POOL.cpp:334-358`,
  `388-410`). No decompression code was found in `tsk/fs/btrfs/` (the compression byte is only
  parsed and printed, `Basics/ExtentData.cpp:28`, `56`).
- **Builds in the guest?** Uncertain (UNVERIFIED): 2017-era autotools and C++ on GCC 13 and
  autoconf 2.71 may need patches; any patch would be ours and must be recorded.
- **Read-only run** (UNVERIFIED):

  ```sh
  mkdir /work/pool && ln -s /dev/vdb /work/pool/dev1    # the pool reader skips only directories
  fls -P -r -p /work/pool > /out/fkie-fls.txt
  icat -P /work/pool INODE > /out/fkie/INODE           # per inode listed by fls
  ```

- **Output for scoring:** live-tree names from `fls` and file contents per inode from `icat`.
  Expected deleted-file recovery is near zero; it is the "established forensic suite" baseline
  the plan and Hilgert et al. motivate, not a recovery tool.

### 3.8 btrForensics

- **Canonical source:** <https://github.com/shujianyang/btrForensics>.
- **Pin:** `master` at `5206e3253778169b954986c38b020f0783bdfc58` (2018-08-06, last commit).
  No tags.
- **Tarball:** <https://github.com/shujianyang/btrForensics/archive/5206e3253778169b954986c38b020f0783bdfc58.tar.gz>
  SHA-256 `05129f94ccde8fccaee398174310460b37d55d447998e35f0d57ac63ac933a1b` (GitHub-generated, §4.5).
- **Licence:** MIT. **Toolchain:** C++11 with CMake ≥ 3.1 (`CMakeLists.txt`), links libtsk
  (`#include <tsk/libtsk.h>`, `tsk_img_open` in `Tools/fls.cpp:82`).
- **Builds in the guest?** Probably (UNVERIFIED): noble `cmake 3.28.3` and `g++-13`, against either
  the TSK `develop` build of §3.6 or noble's `libtsk-dev 4.12.1+dfsg-1.1ubuntu2`
  (`136038bb154964016e3aca76187c7c7e75ca2af373ff55186e8647b9bd54797a`, which pulls in `libewf2`,
  `libafflib0t64`, `libvhdi1`, `libvmdk1`, `libsqlite3-0`). Newer TSK headers may need a newer C++
  standard than the `CMAKE_CXX_STANDARD 11` it sets; that would be a one-line change of ours.
- **Read-only run:** tools `fsstat`, `fls`, `istat`, `icat`, `subls`, `devls` and the interactive
  `btrfrsc` (`Tools/*_README.md`). File or device via TSK; no loop or mount.

  ```sh
  fls -r /dev/vdb > /out/btrforensics-fls.txt
  (cd /out/btrforensics && icat /dev/vdb INODE)     # writes the file under its original name
  ```

- **Output for scoring:** names from `fls`, contents from `icat`. "Unable to list deleted files
  yet" (`Tools/FLS_README.md`); the compression byte is parsed but no decompressor exists. A
  live-tree baseline only.

### 3.9 michal2229/mbkn-btrfs-rescue

- **Canonical source:** <https://github.com/michal2229/mbkn-btrfs-rescue>.
- **Pin:** v0.4.0, commit `c2eddfbc610b23a85e5f04d960d6994f998299e8` (2026-09-27; v0.2.0 and
  v0.3.0 were tagged the same day; repository created 2026-09-27, last push 2026-09-27).
- **Tarball:** <https://github.com/michal2229/mbkn-btrfs-rescue/archive/refs/tags/v0.4.0.tar.gz>
  SHA-256 `550e15e9b3ef3c80876d1015f2f6d859c4ed6fb50851f4183e389935995f004c` (GitHub-generated, §4.5).
- **Licence:** GPL-3.0. Its dependency `dissect.btrfs` is AGPL-3.0-or-later (we use the same
  package as a test oracle, `docs/plan.md` §3.1).
- **Toolchain:** Python ≥ 3.14 with uv (`pyproject.toml`). Runtime dependencies `crc32c`,
  `dissect-btrfs`, `numpy`, `xxhash`; optional `mfusepy` for the FUSE mount. `uv.lock` pins every
  wheel by URL and SHA-256; cp314 manylinux x86-64 wheels exist for all compiled ones, e.g.
  `numpy-2.5.3-cp314-cp314-manylinux_2_27_x86_64…whl`
  `b0521d0f4aebb6e06189451025fa17a913287b13c03d5fe05c017333b654ea5b`.
- **Runs in the guest?** Needs CPython 3.14 (noble has 3.12). Options (UNVERIFIED): a
  python-build-standalone CPython 3.14 tarball pinned by SHA-256 (the distribution uv itself
  installs) plus the locked wheels fetched by URL on the host and installed offline in the guest
  (`pip install --no-index --require-hashes`, or uv in offline mode). No compilation is needed.
- **What it does** (README, `docs/how-it-works.md`): sweeps the raw device for every btrfs tree
  block of all generations, indexes them in SQLite, rebuilds the tree bottom-up, verifies data
  sectors against checksums, and restores the best version of each file. README compatibility
  table: single device, all four checksum types, none/zlib/lzo/zstd. This is the same approach as
  `btrfska`'s full-sweep recovery, so it is likely the strongest baseline in the list.
- **Read-only run:** the device "is only ever opened read-only" (`device.py:26`: `os.open(path,
  os.O_RDONLY | os.O_CLOEXEC)`); the config says "Device (or image file)". The loop-mount in
  `scripts/make-test-image.sh` only builds its test images. Without FUSE (UNVERIFIED commands):

  ```sh
  mbkn-btrfs-rescue -d /dev/vdb --db /out/mbkn.sqlite analyze
  mbkn-btrfs-rescue -d /dev/vdb --db /out/mbkn.sqlite restore --include all --include-stale / /out/mbkn/
  ```

- **Output for scoring:** files at `DEST/<subvolume>@<id>/path` with mtimes, plus
  `DEST/.mbkn-restore-<timestamp>.tsv` listing each file's category, action and the generation used
  (`docs/usage.md`, restore section).

### 3.10 Commercial (UFS Explorer, R-Studio)

Both need a paid licence. `CONTRIBUTING.md` §7 says the project spends nothing, so they stay out
unless the maintainer decides otherwise (the plan already says "if licensed").

## 4. What building and running in the guest needs

These are design consequences of the findings, for the M7 harness. None is implemented.

### 4.1 A build environment from pinned noble packages

The current initramfs cannot compile anything. A build guest needs, from the same Ubuntu snapshot
as `guest.lock`: `gcc-13`, `g++-13`, `binutils`, `make`, `pkgconf`, `libc6-dev` and their
dependency closure; `autoconf`, `automake`, `libtool`, `cmake`; the `-dev` packages of §3.1 and
§3.6; `golang-1.24-go` + `golang-1.24-src`; `rustc-1.89` + `cargo-1.89` (or 1.91); `bash`,
`ncurses-bin`. Unpacking `.deb` files with `ar` + `tar` (as `fetch_vm.sh` does) skips maintainer
scripts, so the "alternatives" links (`cc`, `gcc`, `g++`, `go`, `rustc`, `cargo`) must be created
by our script. The dependency closure should be computed once from the Packages index by a
committed script and written into a lock group (for example `build` in `guest.lock`, or a separate
`corpus/vm/build.lock`), so the list is reproducible.

### 4.2 Getting the build tree into the guest without root

A compiler toolchain (several hundred MB with Rust and Go) is too big for an initramfs. Two
rootless options:

- format a disk image from the unpacked directory with the bundle's own
  `corpus/vm/pinned.sh mkfs.btrfs --rootdir DIR IMG` and attach it as a second virtio disk
  (`--rootdir` exists in mkfs 6.6.3; UNVERIFIED for this use);
- QEMU's `-virtfs local,…,security_model=none` (9p), which depends on the host QEMU build having
  virtfs, so it is less host-independent.

The first fits `CONTRIBUTING.md` §4 better.

### 4.3 Sources without network

The guest has no network. The host fetches, by URL with SHA-256 checks, the source tarballs of §3,
the Go module zips (file `GOPROXY`, §3.4), the Rust crates (vendored directory, §3.5) and the Python
wheels (§3.9), all under `images/tools/`.

### 4.4 Running the baselines read-only and getting results out

- Attach the scenario image copy as
  `-drive file=COPY,format=raw,if=virtio,readonly=on`; inside the guest it is `/dev/vdb`. Every
  tool above takes a block device, so no loop device and no mount are needed, and the read-only
  drive enforces it for tools whose own open mode was not checked.
- Write outputs to a scratch disk mounted in the guest, then stream them out as
  `tar -cf /dev/vdc -C /out .` onto a raw virtio disk; the host reads it with `tar -xf`. That
  avoids mounting anything on the host.
- Prefer static binaries for the run guest: `btrfs.static`, `btrfs-find-root.static`,
  `photorec_static`, a `CGO_ENABLED=0` btrfscue. The Rust harness, TSK, FKIE-TSK and btrForensics
  are dynamically linked and need their libraries (all from noble) in the run image. A two-phase
  layout, a build VM that produces binaries and a small run VM that executes them, keeps each run
  close to today's initramfs.
- Record in each run's manifest: tool, pin, source SHA-256, toolchain package versions, exact
  command, exit status, wall time and peak memory (plan §5 M7, §7).

### 4.5 GitHub-generated archives

Six pins (undelete-btrfs, TSK, FKIE-TSK, btrForensics, mbkn, and the btrfscue tag archive) are
GitHub's on-the-fly `archive/` tarballs. GitHub does not promise their bytes stay identical over
time (it changed its compression once in 2023 and reverted after complaints). The hashes above are
right for 2026-10-07. If one ever changes, the fallback is to check out the pinned commit and
compare the tree, then re-pin; publisher-provided tarballs (btrfs-progs, TestDisk, crates.io,
btrfscue's `orig.tar.xz`) do not have this problem.

## 5. Open questions for the maintainer

1. Accept vendor static binaries (PhotoRec) as "pinned by SHA-256 and fetched by URL", like the
   Ubuntu `.deb` files, or require a from-source build for every baseline?
2. FKIE-TSK: replace "`tsk_recover -e`" in plan §5 M7 with "`fls -P` / `icat -P`", or drop it?
3. Add mbkn-btrfs-rescue to plan §5 M7?
4. SecurityRonin needs a harness binary of ours; is a small Rust crate under `corpus/` acceptable
   (it adds Rust to the corpus tooling, not to `btrfska`)?

## 6. To verify before relying on this

- Build each tool in the guest as described; record any patch.
- Run each command once on `m1_xxhash` (or a crc32c image for TSK) and confirm output form.
- Confirm the PhotoRec `/cmd` string, the undelete-btrfs stdin sequence and the mbkn `restore /`
  path on a real run.
- Confirm SecurityRonin's behaviour on a multi-level FS tree (the source reading in §3.5).
- Recompute the btrfscue `orig.tar.xz` hash once the asset host resolves.
