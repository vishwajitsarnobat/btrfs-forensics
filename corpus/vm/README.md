# corpus/vm — rootless Btrfs scenario images

Builds Btrfs test images with real kernel history (commits, snapshots,
deletions, balance, discard) **without root**: the host formats an image
file, a QEMU/KVM guest running the stock Ubuntu `7.0.0-31-generic` kernel
mutates it, and the host analyses the result. Background and measurements:
`research.md` §10.4.

The scripts here are tracked. Everything they produce (packages, unpacked
QEMU and kernel, initramfs, images, logs) goes to the gitignored `images/`
folder. Nothing is written to `/tmp` or outside the repo.

Requirements: `apt-get`/`dpkg` (Ubuntu 24.04 base), read/write access to
`/dev/kvm`, host `mkfs.btrfs`, `zstd`, `cpio`, `python3`.

## Pipeline

```sh
corpus/vm/fetch_vm.sh           # apt-get download + dpkg -x into images/vm/ (idempotent)
corpus/vm/build_initramfs.sh    # images/vm/initramfs.cpio.gz (busybox, btrfs, modules, init, scenarios)
corpus/vm/discard_table.sh      # rebuild the 3 discard images and print the §10.4 table rows
```

One image by hand:

```sh
truncate -s 512M images/scenarios/x.img
mkfs.btrfs -q -f --csum xxhash images/scenarios/x.img
time corpus/vm/run_scenario.sh images/scenarios/x.img     # serial log on stdout
python3 corpus/vm/probe_stale_metadata.py images/scenarios/x.img
```

## Files

| File | Role |
|---|---|
| `fetch_vm.sh` | Downloads QEMU 8.2.2 (+seabios, libs), the guest kernel, `busybox-static`, `btrfs-progs` (and `linux-modules-$KVER` if the host has no btrfs module) |
| `build_initramfs.sh` | Packs busybox, `btrfs` + ldd libs, `xor raid6_pq libblake2b btrfs` modules, `init`, `scenarios/*.guest.sh` |
| `init` | Guest `/init` template. Reads `scenario=` and `mountopts=` from the kernel command line |
| `run_scenario.sh` | Boots the guest on one image. Env: `SCENARIO` (s01), `MOUNT_OPTS` (compress=zstd,commit=5), `DISCARD` (non-empty → virtio `discard=unmap`), `TIMEOUT` (600) |
| `make_image.sh NAME` | truncate + host mkfs (`SIZE`, `CSUM`, `MKFS_ARGS`) + guest run → `images/scenarios/NAME.{img,log}` |
| `scenarios/s01.guest.sh` | Subvolume, 3 files, snapshot, delete 2 (one inline), 6 commits, full balance |
| `scenarios/discard_{none,async,sync}.sh` | The three §10.4 discard rows |
| `probe_stale_metadata.py` | Prints `fsid_blocks stale_blocks needle_copies nonzero_blocks` (definitions in its docstring) |

Derived images and the manifest (one level up, in `corpus/`):
- `corpus/manifest.tsv` has one row per generated image: name, generator
  command, host mkfs version, guest kernel, sha256. Tests reference images by
  name and skip when absent.
- `corpus/mutate.py SRC DST OP` writes a damaged copy of a generated image
  (`set-incompat-bit BIT`, `zero-primary-sb`, `transplant-sb DONOR MIRROR
  GENERATION`). It only reads `SRC` (and `DONOR`) and refuses an existing
  `DST`, a `DST` outside `images/`, or any file named `sandbox.img`. All
  patches are computed and validated before `DST` is created, so a refused
  run leaves no file.

Notes:
- `DISCARD=1` alone makes the async row: kernels ≥ 6.2 enable
  `discard=async` automatically on a discard-capable device. The log line
  `=== MOUNTED` shows the effective mount options.
- Host `mkfs.btrfs` 6.6.3 does **not** enable the block-group tree by
  default (compat_ro 0x3). Use `MKFS_ARGS="-O block-group-tree"` when tree
  11 must be present.
- The stock kernel has `CONFIG_BTRFS_EXPERIMENTAL` unset, so RST,
  extent-tree-v2 and remap-tree images cannot be mounted in this guest.
