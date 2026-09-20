# corpus/vm — rootless Btrfs scenario images

Builds Btrfs test images with real kernel history (commits, snapshots,
deletions, balance, discard) **without root, on any Linux distribution**: a pinned
`mkfs.btrfs` formats an image file, a QEMU/KVM guest running the stock Ubuntu
`7.0.0-31-generic` kernel mutates it, and the host analyses the result. Background and measurements:
`research.md` §10.4.

The scripts here are tracked. Everything they produce (packages, unpacked
QEMU and kernel, initramfs, images, logs) goes to the gitignored `images/`
folder. Nothing is written to `/tmp` or outside the repo.

Requirements (host, any distro): read/write access to `/dev/kvm`,
`qemu-system-x86_64` from the distro's QEMU package (any recent version),
`curl`, `sha256sum`, `ar` (binutils), `tar` with zstd support, `zstd`, `cpio`,
`python3`. No package manager is used and nothing is installed.

**What is pinned, and why.** The host can be any Linux distribution; nothing
is installed on it and no package manager runs. The *guest*, however, is the
experimental variable: the kernel that writes the filesystem and the
`mkfs.btrfs` that creates it decide what ends up on disk, so both must be the
same for everyone who rebuilds the corpus. kernel.org publishes kernel source
only, and building a kernel would need a compiler toolchain and far more than
a few minutes, so the guest is assembled from prebuilt packages. They are
Ubuntu 24.04 packages because EXP-000 to EXP-003 were measured with exactly
this kernel and this btrfs-progs build. Ubuntu is only where these twelve
files are downloaded from:

| Package (version in [`guest.lock`](guest.lock)) | What is used from it |
|---|---|
| `linux-image-unsigned-7.0.0-31-generic` | the guest kernel, `vmlinuz` |
| `linux-modules-7.0.0-31-generic` | `btrfs.ko` and the modules it needs: `xor`, `raid6_pq`, `libblake2b` |
| `busybox-static` | the guest's shell and core utilities, one static binary |
| `btrfs-progs` 6.6.3 | `btrfs` inside the guest (subvolumes, snapshots, balance) and `mkfs.btrfs` on the host |
| `libc6`, `libuuid1`, `libblkid1`, `libudev1`, `libcap2`, `zlib1g`, `liblzo2-2`, `libzstd1` | the shared libraries `btrfs` and `mkfs.btrfs` load, and the dynamic loader |

Each file is pinned by SHA-256. The hashes are the ones in Ubuntu's signed
package indices, and the default mirror is a fixed `snapshot.ubuntu.com`
timestamp, so the URLs stay valid after Ubuntu supersedes a version. To move
the guest to another kernel or distribution, edit `guest.lock`; no script
names a package.

Images are formatted with the bundle's `mkfs.btrfs` through
[`pinned.sh`](pinned.sh), which starts it with the bundle's own loader and
libraries. The host's btrfs-progs is not used, because mkfs defaults differ
between versions (6.19 turned the block-group tree on). QEMU is the host's:
on 2026-09-20 host QEMU 10.2.2 (Fedora 44) reproduced the EXP-000 medians
measured with QEMU 8.2.2 (Ubuntu 24.04 base) exactly, for all three discard
rows.

## Pipeline

```sh
corpus/vm/fetch_vm.sh           # curl + sha256 + ar/tar of guest.lock into images/vm/ (idempotent)
corpus/vm/build_initramfs.sh    # images/vm/initramfs.cpio.gz (busybox, btrfs, modules, init, scenarios)
corpus/vm/discard_table.sh      # rebuild the 3 discard images and print the §10.4 table rows
```

One image by hand:

```sh
truncate -s 512M images/scenarios/x.img
corpus/vm/pinned.sh mkfs.btrfs -q -f --csum xxhash images/scenarios/x.img
time corpus/vm/run_scenario.sh images/scenarios/x.img     # serial log on stdout
python3 corpus/vm/probe_stale_metadata.py images/scenarios/x.img
```

## Files

| File | Role |
|---|---|
| `guest.lock` | The pinned bundle: group, SHA-256 and archive path of every `.deb` |
| `fetch_vm.sh` | Downloads every `guest.lock` entry, verifies its SHA-256 and unpacks it into `images/vm/kernel` and `images/vm/tools`. Env: `UBUNTU_MIRROR` |
| `pinned.sh TOOL ARGS…` | Runs a bundle tool (`mkfs.btrfs`, `btrfs`, `btrfs-find-root`, …) on the host through the bundle's loader and libraries |
| `build_initramfs.sh` | Packs busybox, `btrfs` + its libraries, `xor raid6_pq libblake2b btrfs` modules (all from the bundle), `init`, `scenarios/*.guest.sh` |
| `init` | Guest `/init` template. Reads `scenario=` and `mountopts=` from the kernel command line |
| `run_scenario.sh` | Boots the guest on one image. Env: `SCENARIO` (s01), `MOUNT_OPTS` (compress=zstd,commit=5), `DISCARD` (non-empty → virtio `discard=unmap`), `TIMEOUT` (600), `QEMU` (qemu-system-x86_64) |
| `make_image.sh NAME` | truncate + pinned mkfs (`SIZE`, `CSUM`, `MKFS_ARGS`; `MKFS=mkfs.btrfs` for the host's) + guest run → `images/scenarios/NAME.{img,log}` |
| `scenarios/s01.guest.sh` | Subvolume, 3 files, snapshot, delete 2 (one inline), 6 commits, full balance |
| `scenarios/discard_{none,async,sync}.sh` | The three §10.4 discard rows |
| `probe_stale_metadata.py` | Prints `fsid_blocks stale_blocks needle_copies nonzero_blocks` (definitions in its docstring) |

Derived images and the manifest (one level up, in `corpus/`):
- `corpus/manifest.tsv` has one row per generated image: name, generator
  command, mkfs version (column `host_mkfs`), guest kernel, sha256. The sha256 is that of
  one generated instance: a regenerated image has a new filesystem UUID and so a new hash. Tests reference images by
  name and skip when absent.
- `corpus/mutate.py SRC DST OP` writes a damaged copy of a generated image
  (`set-incompat-bit BIT`, `zero-primary-sb`, `transplant-sb DONOR MIRROR
  GENERATION`, `flip-byte OFFSET...`). It only reads `SRC` (and `DONOR`) and
  refuses an existing `DST`, a `DST` outside `images/`, or any file named
  `sandbox.img`. All patches are computed and validated before `DST` is
  created, so a refused run leaves no file.
- `flip-byte` takes physical offsets. `m1_badnode` inverts the last byte of
  mirror 1 of `m1_xxhash`'s `sv1` leaf (logical 65159168, copies at physical
  107102208 and 174211072, from `btrfska walk images/scenarios/m1_xxhash.img
  --tree 256`); `m1_badnode_both` inverts it in both copies.

Notes:
- `DISCARD=1` alone makes the async row: kernels ≥ 6.2 enable
  `discard=async` automatically on a discard-capable device. The log line
  `=== MOUNTED` shows the effective mount options.
- The pinned `mkfs.btrfs` 6.6.3 does **not** enable the block-group tree by
  default (compat_ro 0x3). Use `MKFS_ARGS="-O block-group-tree"` when tree
  11 must be present.
- The stock kernel has `CONFIG_BTRFS_EXPERIMENTAL` unset, so RST,
  extent-tree-v2 and remap-tree images cannot be mounted in this guest.
