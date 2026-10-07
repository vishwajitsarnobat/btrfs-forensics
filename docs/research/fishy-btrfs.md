# fishy's btrfs module, and what to validate the hiding detector against

Research for issue #46 (plan.md M6: "Validate against images generated with **fishy**'s btrfs
module"). Read on 2026-10-07 from the repositories' code and the papers in `docs/papers/`. Every
claim names its source; anything not checked is marked UNVERIFIED.

## Answer in short

- **There is no public fishy btrfs module.** The only public fishy repository, `dasec/fishy`, has
  modules for FAT, NTFS, ext4 and APFS and nothing for btrfs, on any branch. Its last commit is
  from 2019. The btrfs module that Göbel, Baier & Türr (2025) describe was never published in
  that repository, nor in the public ForTrace repository, nor in either fork.
- What that unpublished module plants on btrfs, by the paper's own table: **file slack** and
  **nanosecond timestamp fields**, two techniques. Pre-superblock space and node slack are only
  discussed in the paper, not marked as implemented.
- **Best fallback: plant ourselves with `corpus/mutate.py`**, one subcommand per technique of
  Toolan & Humphries 2026 plus Göbel's two, and check the planted images with
  `btrfs check --check-data-csum` in the guest. For an independent, third-party check, use the
  **btrfs images of `fkie-cad/hide-and-seek-dataset`** (Schwietert & Hilgert 2025), fetched by URL
  and pinned by SHA-256. One of those images does not match its own ground truth (below).
- The M6 definition of done ("finds ≥ the fishy-plantable techniques") and claim C5 ("evaluated
  against fishy-generated images") cannot be met as written. Rewording them is the maintainer's
  decision (CONTRIBUTING §1: a change of a claim).

## 1. Does a fishy btrfs module exist?

**Public repository: no.** `https://github.com/dasec/fishy`, cloned 2026-10-07:

- `master` is at `f34cac648dac6bc993384246789908e1f7dcf10c` (2019-09-13, "Update README.md"),
  390 commits; the GitHub API reports the last push on 2019-09-13. `setup.py` says version 0.2.
- `fishy/` holds `APFS/`, `ext4/`, `fat/`, `ntfs/` and `wrapper/`. The filesystem detector
  (`fishy/filesystem_detector.py`, `get_filesystem_type`) returns `FAT`, `NTFS`, `EXT4` or `APFS`
  and raises `UnsupportedFilesystemError` for anything else.
- `git grep -i btrfs` over all four remote branches (`master`, `ext4_hidingTec_i_obso_faddr`,
  `ntfs-cluster-allocator`, `ntfs-meta`) finds one line, a sentence in
  `doc/source/02_filesystem_datastructures.rst:252` comparing APFS with "ZFS, BTRFS and newer
  iterations of XFS". `git log --all --grep=btrfs` finds nothing. The wiki
  (`dasec/fishy.wiki.git`) has the same sentence and nothing else.
- Forks: `ekojs/fishy` (last push 2019-09-13, identical) and `ltsyk/fishy` (push 2026-07-30, 0
  commits ahead of `dasec:master` per the compare API). No other repository on GitHub matches
  "fishy btrfs", "btrfs anti-forensic" or "btrfs slack hide" (GitHub search, 2026-10-07).

**The ForTrace side: also no.** Göbel et al. say the btrfs work reached users through a new
"DataHiding utility class" in ForTrace and a `--area` partition-offset parameter in fishy
(`goebel_generating_traces_filesystem_2024.pdf`, §4.3 and §5.3). The public
`https://github.com/dasec/ForTrace` (head `eba0700a47e20ff99b0e277cdf0e4fa9b6e58150`,
2022-08-28; last push 2024-11-05) contains neither the word "fishy" nor "DataHiding" nor
"btrfs" anywhere. The `--area` parameter is not in public fishy either (`fishy/cli.py`).

**Independent confirmation.** Schwietert & Hilgert 2025 (§2.4,
`schwietert_hilgert_datahiding_corpus_2025.pdf`) describe fishy as supporting "FAT, NTFS, ext4,
and more recently, APFS", without btrfs. Their corpus's btrfs images were made by hand: the
metadata of `btrfs_superblock` says "direct byte-level modification via dd" (§4.2 below).

So the module exists only as described in the paper. Whether the authors would share it is
UNVERIFIED; asking them (Thomas Göbel, Jan Türr, da/sec, Hochschule Darmstadt) is an option, and
whether to ask is the maintainer's call.

## 2. What the described module plants, and where

From Göbel, Baier & Türr, "Generating Usable and Assessable Datasets Containing Anti-Forensic
Traces at the Filesystem Level", IFIP AICT, 2025, DOI 10.1007/978-3-031-71025-4_12:

| Technique | Implemented? | Layout | Checksums it updates |
|---|---|---|---|
| Nanosecond timestamps | yes (Table 2, §3.2, Fig. 3) | the four 4-byte nsec fields of every INODE_ITEM (`0x78`, `0x84`, `0x90`, `0x9c` in Table 1): 16 bytes per inode | the tree-block checksum of the leaf |
| File slack | yes (Table 2, §3.2, Fig. 4) | from the inode size to the end of the last allocated block of a regular extent; inline files have none | the EXTENT_CSUM entry in the csum tree, then that csum-tree leaf's block checksum |
| Pre-superblock 64 KiB | discussed only (§3.2, "Additional") | 0x0–0x10000 | none |
| Internal and leaf node slack | discussed only (§3.2, Figs. 5, 6) | after the key pointers; between item headers and item data | block checksum |

Table 2 (page 12, read from the rendered page because the check marks do not survive text
extraction) marks btrfs only for `file slack` and `nanoseconds`. Limits the paper states (§6):
single device, single subvolume. Which checksum types the module handles is not stated
(UNVERIFIED; the paper only mentions CRC32C implicitly through its examples).

None of the superblock reserved range, superblock slack, chunk-array slack, INODE_ITEM reserved
bytes or STRING_ITEM techniques is in the fishy module; those come from Toolan & Humphries 2026
(research.md §8.3).

## 3. What public fishy needs to run

Answered for the code that exists (FAT/NTFS/ext4/APFS), since there is no btrfs code to run.

- **Python and dependencies** (`README.md`, `requirements.txt`, `setup.py`): Python 3.5 or
  later; `construct < 2.9` (2.8.22 recommended, released 2018-01-18 on PyPI); `pytsk3` (a C
  extension around The Sleuth Kit); `simple-crypt`, whose only release line ends at 4.1.7 and
  whose `setup.py` requires `pycrypto`, last released as 2.6.1 (PyPI). Whether pycrypto 2.6.1 and
  construct 2.8 build and run on a current Python (our `uv` uses 3.14) is UNVERIFIED; pycrypto is
  unmaintained.
- **Root, loop devices, mounting.** The hiding itself does not need them: the CLI opens the
  target as a plain file, `open(args.dev, 'rb+')` (`fishy/cli.py:1189`, `-d/--device` at
  `cli.py:992`), so it works on an image file without root. Only the test-image generator needs
  root: `utils/create_testfs.sh:133` runs `sudo mount` to copy files in, and the README installs
  and tests with `sudo python setup.py ...` (`README.md:54-56`).
- **Inside our guest.** The guest is busybox, btrfs-progs 6.6.3 and their libraries
  (`corpus/vm/guest.lock`); it has no Python interpreter. Running fishy there would mean pinning a
  Python, construct, pytsk3 with libtsk and pycrypto into `guest.lock`. Since fishy writes to an
  image file, nothing about it needs the guest kernel; if it were worth running, it would run on
  the host through `uv` against a copy of an image. Adding it as a dependency is a maintainer
  decision (CONTRIBUTING §3).
- **Licence.** MIT (`LICENSE`: "Copyright (c) 2018 da/sec", plus Jonas Plum for a checksum file
  taken from afro). The README asks publications using the code to cite Kailus et al. 2018 and
  Göbel & Baier 2018. ForTrace is MIT too (GitHub API).

## 4. Other sources of btrfs hiding

### 4.1 Toolan & Humphries, FSI:DI 58:302198 (2026): six techniques, no code

`toolan_humphries_hiding_data_btrfs_2026.pdf`, §3–4. Techniques: pre-superblock, superblock
reserved and slack (0x325 bytes per copy), chunk-array slack (0x77F bytes when the array is
0x81 bytes), INODE_ITEM reserved (0x20 bytes at +0x50), internal-node slack, and a forged
STRING_ITEM (type 0xFD) appended to a leaf: `nritems` + 1, a 25-byte item header at
`0x65 + N*25`, the payload just below the lowest existing item data offset, block checksum
updated (§3.6, steps 1–8). They tested on images made with btrfs-progs 6.6.3 and 6.19.1 (§4),
checked each with mount, user actions, TSK 4.14 `fsstat/fls/istat/icat`, `btrfs check`,
`btrfs check --check-data-csum` and `dmesg` (Table 1). All passed except message recovery from
internal-node slack, which CoW zeroes. **No code or images are released**: the data
availability statement reads "Any Btrfs file system can be used to validate the techniques",
and the CRediT "Software" role is Toolan's. The method is described precisely enough to
reimplement.

### 4.2 `fkie-cad/hide-and-seek-dataset`: third-party btrfs images

`https://github.com/fkie-cad/hide-and-seek-dataset`, head
`decd14bd9cb39a978a3a2ce0d2a0d472ac88b703` (2025-11-12). This is the corpus of Schwietert &
Hilgert 2025 that research.md §10 recorded as a 404; it is online now. **No licence file**, and the
README states none, so it may be downloaded and read but not redistributed or committed
(UNVERIFIED whether the authors intend a licence; ask them). Gzip images plus a `metadata.json`
ground truth per technique. Btrfs entries, with the SHA-256 of each `.gz` as fetched:

| Directory | What is hidden | `.gz` SHA-256 |
|---|---|---|
| `scenario_6_reserved_space/btrfs_superblock` | "HIDDEN DATA" in superblock reserved (0x23B) and slack (0xDCB) areas, crc32c recomputed, says the metadata | `a0aa6234912063feff0c5dc9435b2148483ee134b0a45f41a40245511474ee79` |
| `scenario_6_reserved_space/btrfs_inode_reserved` | 32 bytes in the reserved area of five INODE_ITEMs in one leaf, leaf checksum recomputed | `f3c62ae38842d51ac02f3aad4935e7370a2d44226b334bc00bff286450cc19e1` |
| `scenario_7_snapshots/btrfs_hidden_snapshot` | a snapshot named U+FEFF moved into `.lib32` (kernel-made, mounted) | `21f46693d87867c26903d4e68d6cdc0ee329f5faf37f3c0bdbb495cf5dd8742b` |
| `scenario_9_pooled_storage_slack/btrfs_raid1_slack` | 50 MiB written with `dd` past the used part of the larger of two RAID1 devices | `8892ca84…e8a4` (dev1), `b174cac4…9778` (dev2) |

There is no btrfs file-slack, timestamp, chunk-array, node-slack or STRING_ITEM image.

**I checked the two scenario-6 images with `btrfska info` and `btrfska scan`** (read-only,
from `/tmp`, 2026-10-07):

- `btrfs_superblock` **does not match its metadata.** The primary superblock at 64 KiB is valid
  (generation 15) and holds no hidden bytes at 0x1023B or 0x10DCB; the metadata's "0xDCB"
  segment is given as an absolute offset 3531, inside the zero pre-superblock area, which is also
  empty. The string occurs only from 64 MiB to 64 MiB + 4093: **mirror 1 is overwritten from its
  first byte**, so its magic is gone and `btrfska info` reports
  `mirror 1 @ 67108864: INVALID (magic mismatch, unknown csum_type 16724)`. The image is a
  useful "destroyed mirror full of ASCII" case, not ground truth for superblock reserved-area
  hiding.
- `btrfs_inode_reserved` matches: the ten occurrences of "HIDDEN DATA" lie in five 32-byte runs
  at the metadata's offsets (first at 39580858), all in one leaf at physical 39567360, in stripe 0
  of a METADATA|DUP chunk. `btrfska scan` finds all 51 candidates in that stripe valid, so the
  checksum was recomputed. The stripe-1 copy of that leaf does not contain the string: the two DUP
  copies diverge, which is itself a detection signal.
- Both images have the same primary superblock (generation 15, csum `72dc9830`), so they were
  made from one base filesystem. The mkfs and kernel versions are not recorded (UNVERIFIED).

### 4.3 `fkie-cad/mind-the-slack`: a slack-measurement harness, not a hider

`https://github.com/fkie-cad/mind-the-slack`, head `5e4f0c15cd7039fc4b1d9c536a41334685c46229`
(2026-07-29), MIT (Hilgert and Schwietert). It measures whether residual data survives in file
slack (experiments d01–d03, p01–p05). Its one planting step is `d00_synthetic.py`: it writes
"SSSS" into the RAM and drive slack of a test file through `open(image_path, 'r+b')`, then for
btrfs recomputes the EXTENT_CSUM and the csum-tree block checksum
(`common/fs_backends/dissect_backend.py:590`, `update_btrfs_checksums`). That code assumes CRC32C
(`csum_size = 4  # CRC32C is 4 bytes`, line 518) and needs `dissect.btrfs` and `crc32c`. The
harness as a whole needs root to create, loop-attach and mount images (`README.md:75`,
`platforms/linux/disk_ops.sh:3`, `losetup` at line 34) and system btrfs-progs. It is a reference
for how to plant file slack correctly, not something to run in our pipeline.

## 5. Recommendation for M6e

1. **Plant with `corpus/mutate.py`.** It already does the hard part for one technique:
   `plant-slack` writes into the slack of an fs-tree root node and its first leaf in every
   physical copy and recomputes the block checksums with the image's own checksum type
   (`m4_planted_slack`). Add one subcommand per remaining technique, each a new
   `corpus/manifest.tsv` row derived from an existing pinned image:
   - superblock reserved and slack, chunk-array slack (every superblock copy, csum recomputed),
     with the reserved range taken from the v7.0 layout (0x264–0x32A) and a separate variant
     writing into the feature-gated 0x23B–0x263 fields without their flags;
   - pre-superblock 0x0–0x10000;
   - INODE_ITEM reserved bytes and nanosecond fields (leaf rewritten in every copy, block csum);
   - a forged STRING_ITEM, following Toolan & Humphries §3.6;
   - file slack in a regular extent, with the csum-tree entry and the csum leaf both updated
     (Göbel §3.2; mind-the-slack's `update_btrfs_checksums` as the worked example);
   - device slack past `total_bytes` (Wani et al. 2020, W5; hide-and-seek scenario 9).
   This keeps CONTRIBUTING §4 (no root, nothing installed, deterministic, any distribution) and
   works for all four checksum types, which none of the external planters do.
2. **Prove each planted image is still a healthy filesystem** the way Toolan & Humphries did: a
   guest scenario that runs `btrfs check --readonly --check-data-csum` and mounts it, using the
   pinned btrfs-progs 6.6.3 already in `guest.lock`. A planted image that fails this check
   tests the corruption path, not hiding.
3. **Kernel-made techniques as guest scenarios:** the hidden U+FEFF snapshot (busybox and
   `btrfs subvolume snapshot` suffice) and, if multi-device is in scope, RAID1 member slack.
4. **Use hide-and-seek as the independent check** against circularity (the same people writing
   the planter and the detector). Fetch the btrfs `.gz` files at commit `decd14b` by URL into
   `images/`, pinned by the SHA-256 values above, never committed (no licence). Expect the
   `btrfs_superblock` image to show a destroyed mirror 1, not reserved-area hiding, and say so in
   the EXP record.
5. **Reword the plan and claim** (maintainer): "validate against fishy's btrfs module" becomes
   "validate against the Toolan & Humphries and Göbel et al. techniques, planted by a committed
   script, and against the hide-and-seek btrfs images". Optionally write to Göbel and Türr for the
   module; if it arrives, it becomes one more generator, not the basis of the DoD.

## Sources

- `https://github.com/dasec/fishy` at `f34cac6`, its wiki, and forks `ekojs/fishy`, `ltsyk/fishy`.
- `https://github.com/dasec/ForTrace` at `eba0700`.
- `https://github.com/fkie-cad/mind-the-slack` at `5e4f0c1`.
- `https://github.com/fkie-cad/hide-and-seek-dataset` at `decd14b`.
- PyPI JSON for `simple-crypt` 4.1.7, `pycrypto`, `construct` 2.8.22.
- `docs/papers/goebel_generating_traces_filesystem_2024.pdf` (Table 2 on p. 12, §3.2, §4, §6),
  `toolan_humphries_hiding_data_btrfs_2026.pdf`, `schwietert_hilgert_datahiding_corpus_2025.pdf`.
