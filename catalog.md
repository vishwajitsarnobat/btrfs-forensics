# Development Catalog

The chronological record of everything done in this project — every milestone,
commit, decision, empirical finding, and verification result. **Update this
file immediately after doing something**; it is the project's memory and the
source for the paper's "implementation history" narrative.

Companion docs: [`research.md`](research.md) (full prior-art and gap analysis),
[`plan.md`](plan.md) (forward-looking build plan).

Maintenance rules:

1. Add a `## YYYY-MM-DD — <title>` entry at the **top** of the Timeline for
   each unit of work (feature, experiment, decision, doc rewrite).
2. Record: branch, commit hashes, what was done and why, empirical numbers,
   and how it was verified (tests, measurements).
3. One branch per feature (`feature/<short-name>`), merged to `main` via PR.

---

# Timeline (newest first)

## 2026-09-15 — M1a: on-disk tables, checksums, superblock trust gate

- **Branch:** `feature/m1a-trust-foundations` (from `main` at `85cbc07`).
  This is the first of three M1 PRs. It covers plan.md §5 M1 tasks 1–4, the
  task-9 images these need (plus `m1_lzo` and `m1_zlib`), and the `info`
  half of task 10.
- **Commits:**
  - `d393c1e` Record defect #8 and the sandbox.img ground truth
  - `5efc964` Add on-disk struct tables checked against kernel v7.0 headers
  - `4a1317a` Add checksum dispatch for crc32c, xxhash64, sha256 and blake2b-256
  - `e34ae6e` Add superblock mirrors, best-copy selection and the incompat gate
  - `fda8316` Show superblock copies, gate verdict and backup roots in btrfska info
  - `00c93ea` Add the M1a corpus images, corpus/mutate.py and the image manifest
  - `d8140fa` Add an import-boundary test keeping test oracles out of src/
  - `5d61695` Record M1a format notes and update the README status
  - this catalog entry (the commit after `5d61695`)

**What was done.** Each module's tests were written and seen failing
(ImportError or assertion) before the implementation.
1. **Ground truth (task 1).**
   - research.md §8.1 gains **defect #8**: legacy uses the EXTENT_ITEM key
     offset as the address, but the offset is the length. Evidence is below.
   - `tests/ground_truth/sandbox.json` holds the superblock copies, the four
     backup roots by slot, and the gen 11–14 fs-tree contents.
   - `tests/test_ground_truth.py` asserts the superblock facts (green) and
     has four strict xfails for the per-generation fs trees
     (`reason="tree walker lands in M1b"`).
2. **`substrate/ondisk.py` (task 2).**
   - A small `Layout` (named little-endian `struct` fields, `.size`,
     `.offset()`, `.unpack_from()`).
   - Layouts: superblock, backup root, header, key, item, key pointer, dev
     item, chunk and stripe, inode item/ref/extref, dir item, root item/ref,
     file extent item, dev extent, extent item and inline refs (incl. owner
     ref 172), block group item v1/v2, free-space info, remap item.
   - Constants: objectids 1–13 and the negative ones, all item keys incl.
     172, 230 and 234–236, incompat/compat_ro/block-group bits, csum table,
     mirror offsets, FT and extent constants.
   - `flag_names()` names unknown bits `UNKNOWN_BIT_<n>`.
3. **`substrate/csum.py` (task 3).**
   - `compute()` and `block_csum_ok()` follow kernel `btrfs_csum()`
     (`fs.c:44-62`): crc32c stored as LE u32, XXH64 seed 0 stored as LE u64,
     SHA-256, and BLAKE2b with `digest_size=32`.
   - The test proves the BLAKE2b result is not a truncated BLAKE2b-512; the
     test value was checked with `printf abc | b2sum -l 256`.
   - Runtime deps: `crc32c>=2.9` (locked 2.9.post0) and `xxhash>=4.0`
     (locked 4.0.1).
4. **`substrate/superblock.py` (task 4).**
   - `read_copies()` covers all three mirror slots; slots that do not fit
     the image are marked not present.
   - `parse_copy()` checks magic, then bytenr (only when the magic matches),
     then csum (unknown csum types reported).
   - `select()` takes the valid copy with the highest generation, lowest
     mirror on a tie. Each disagreement is reported: invalid copy, older
     generation, or same generation with differing fields (named).
   - `backup_roots()` returns the slots sorted by generation, each keeping
     its slot.
   - `gate()` refuses EXTENT_TREE_V2, RAID_STRIPE_TREE, REMAP_TREE and
     unknown bits, with `UNSUPPORTED_INCOMPAT <name>` lines;
     `allow_unsupported` gives status `OVERRIDDEN`.
   - The compat_ro BLOCK_GROUP_TREE bit is noted ("block groups are read
     from tree 11"). Unknown compat_ro bits are listed but do not refuse.
   - A property-style test feeds 300 random and 300 mutated blocks; none
     raises, and no mutated block validates.
5. **CLI (task 10, `info` half).** `btrfska info IMAGE [--allow-unsupported]`
   prints:
   - path, size and sha256;
   - each superblock copy (valid with generation and csum, `INVALID
     (reasons)`, or not present);
   - the selected copy and the disagreements;
   - the fields: fsid, generation, roots, csum type, compat/compat_ro/incompat
     flags;
   - the backup roots by generation;
   - `gate:` and any `UNSUPPORTED_INCOMPAT` lines.

   Exit 0 when OK or overridden, 2 when refused (gate or
   `NO_VALID_SUPERBLOCK`), 1 on I/O errors.
6. **Corpus (task 9).**
   - Five images generated with `corpus/vm/make_image.sh`; two derived with
     the new `corpus/mutate.py`.
   - `mutate.py` only reads its source and creates the output with `open(...,
     "xb")`. It refuses an existing path or symlink, a path outside `images/`
     (after resolving `..`), any file named `sandbox.img`, and output equal to
     the source. All-zero 1 MiB chunks stay sparse.
   - `corpus/manifest.tsv` has seven rows; `corpus/vm/README.md` documents
     both.
   - `tests/test_vm_images.py` (18 tests, `@pytest.mark.vm`) skips when an
     image is absent.
7. **Import boundary.** `tests/test_import_boundary.py` scans `src/` for
   `dissect`/`lzallright` imports: static imports plus `import_module` and
   `__import__` with a string. It includes 8 scanner self-tests. Plan task 8
   lists this test, but it is part of the M1a DoD, so it lands here.
8. **Shared helpers.** `tests/helpers.py` provides the synthetic superblock
   builder, sparse scratch images and a scratch-dir context under
   `images/scratch/`. No test uses `/tmp` or `tmp_path`.

**Ground-truth capture** (btrfs-progs v6.6.3, host; outputs in
`images/scratch/m1a/`). To rule out any write by btrfs-progs, dump-tree ran on
a byte-identical read-only copy, not on `sandbox.img` itself:

```sh
cp sandbox.img images/scratch/m1a/sandbox-ro.img && chmod 0444 images/scratch/m1a/sandbox-ro.img
sha256sum images/scratch/m1a/sandbox-ro.img     # 07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418
btrfs inspect-internal dump-super -fa images/scratch/m1a/sandbox-ro.img
btrfs inspect-internal dump-tree -t root images/scratch/m1a/sandbox-ro.img
btrfs inspect-internal dump-tree -t 5 -b 30785536 images/scratch/m1a/sandbox-ro.img   # gen 11
btrfs inspect-internal dump-tree -t 5 -b 30867456 images/scratch/m1a/sandbox-ro.img   # gen 12
btrfs inspect-internal dump-tree -t 5 -b 30539776 images/scratch/m1a/sandbox-ro.img   # gen 13
btrfs inspect-internal dump-tree -t 5 -b 30703616 images/scratch/m1a/sandbox-ro.img   # gen 14
btrfs inspect-internal dump-tree -b 30474240 images/scratch/m1a/sandbox-ro.img        # gen-13 extent tree (defect #8)
```

- **Superblock** (`dump-super -fa`): two copies, both `[match]`.
  - bytenr 65536, csum `0xeadc2eaa`, generation 14;
  - bytenr 67108864, csum `0x4abd0664`, generation 14;
  - the 256 GiB mirror does not fit.
  - Shared fields: root 30720000, chunk_root 22036480,
    chunk_root_generation 8, total_bytes 268435456, bytes_used 163840,
    csum_type 0, compat_ro 0xb (FST, FST_VALID, BGT), incompat 0x361.
- **Backup roots** (slot: tree_root gen / fs_root):
  - 0: 30572544 **13** / 30539776;
  - 1: 30720000 **14** / 30703616;
  - 2: 30801920 **11** / 30785536;
  - 3: 30883840 **12** / 30867456.

  All four share chunk_root 22036480 gen 8 and backup_total_bytes
  268435456.
- **Gen 11** (leaf 30785536, 8 items):
  - inode 256 is a dir (size 30) with DIR_ITEM/DIR_INDEX 2
    `target_file.txt` → 257;
  - inode 257 has size 31, nbytes 31, and INODE_REF index 2
    `target_file.txt`;
  - XATTR `security.selinux`;
  - `EXTENT_DATA 0` `type 0 (inline)`, `inline extent data size 31 ram_bytes
    31 compression 0`.
- **Gen 12** (not asserted on the old branch; captured now), full leaf:
  ```
  leaf 30867456 items 2 free space 16061 generation 12 owner FS_TREE
      item 0 key (256 INODE_ITEM 0) itemoff 16123 itemsize 160
          generation 3 transid 12 size 0 nbytes 16384
          block group 0 mode 40755 links 1 uid 1000 gid 1000 rdev 0
          sequence 3 flags 0x0(none)
      item 1 key (256 INODE_REF 256) itemoff 16111 itemsize 12
          index 0 namelen 2 name: ..
  ```
  So the gen-12 state is the root directory only, now empty (size 0).
  `target_file.txt` was deleted in transaction 12, not "by gen 14".
- **Gen 13** (leaf 30539776, 8 items):
  - inode 256 dir (size 32) → `large_target.txt` 257;
  - inode 257 has size 5242880 and INODE_REF `large_target.txt`;
  - `EXTENT_DATA 0` `type 1 (regular)`, disk byte 13631488, nr 5242880,
    ram 5242880, no compression.
- **Gen 14** (leaf 30703616): 2 items, the root dir only (size 0).
- **Defect #8 evidence** (gen-13 extent tree): `item 0 key (13631488
  EXTENT_ITEM 5242880) ... extent data backref root FS_TREE objectid 257`.
  The objectid is the address that EXTENT_DATA points to; the offset is the
  length.
- **Plan values checked.** Slot order 13, 14, 11, 12; chunk-root gen 8;
  total_bytes 268435456; newest backup tree_root == SB root 30720000; gen 11
  inode 257 31 B inline; gen 13 5 242 880 B; gen 14 root only. All are
  correct, and none is wrong. research.md §10.5's "both deleted by gen 14"
  is loose for `target_file.txt`, which is already gone at gen 12.

**Constant sources.** Linux tag `v7.0` (tag object `3131ff5a1174`), fetched as
`https://raw.githubusercontent.com/torvalds/linux/v7.0/<path>` into
`images/scratch/m1a/kernel/`:
- `include/uapi/linux/btrfs_tree.h`: structs l.473–1354, objectids l.38–130,
  keys l.143–377, csum enum l.386–391;
- `include/uapi/linux/btrfs.h`: feature bits l.298–339, sizes l.33 and
  l.62–63;
- `fs/btrfs/fs.h`: SB offset/size and static_assert l.80–82, masks l.286–330;
- `fs/btrfs/fs.c`: csum sizes and names l.12–17, `btrfs_csum()` l.44–62;
- `fs/btrfs/disk-io.h`: mirrors l.26–43;
- `fs/btrfs/disk-io.c`: `btrfs_check_super_csum` l.153–169, backup ring
  l.1596–1607, SB write l.3795–3810;
- `fs/btrfs/volumes.c`: `btrfs_read_disk_super` edge rule l.1356 and
  magic/bytenr check l.1378–1379.

Every size, offset and value is asserted in `tests/test_ondisk.py` with its
file:line.

**Checksum library choice: `crc32c` (ICRAR) 2.9.post0, as planned.** Checked
2026-09-15:

| | `crc32c` 2.9.post0 | `google-crc32c` 1.8.0 |
|---|---|---|
| Licence | LGPL-2.1-or-later (plan §3.3: fine as a separate, unmodified dep) | Apache-2.0 |
| cp314 wheels | 24: manylinux/musllinux x86_64, aarch64, riscv64; macOS; Windows; free-threaded `cp314t` too | 5; no musllinux or `cp314t` |
| Last release | 2026-09-11 | 2025-12-16 |
| `memoryview` input | accepted (zero-copy over the image mmap) | `TypeError: argument 1 must be read-only bytes-like object, not memoryview` |
| Speed (16 KiB blocks, this host) | ~20.8 GB/s, `hardware_based=True` | ~24.7 GB/s |
| `crc32c(b"123456789")` | `0xe3069283` | `0xe3069283` |

`crc32c` is simpler for us: it hashes mmap slices without copying, and it has
wheels for every platform and free-threaded build we might meet. The
`google-crc32c` swap stays documented in plan §3.3 for a frozen binary.
`xxhash` 4.0.1 (BSD-2-Clause) has cp314 and cp314t wheels.

**Generated images** (under `images/scenarios/`; host mkfs btrfs-progs
v6.6.3; guest kernel `7.0.0-31-generic`; QEMU 8.2.2; scenario s01; all
512 MiB):

| Name | Generator | Superblock | sha256 |
|---|---|---|---|
| `m1_xxhash` | `CSUM=xxhash corpus/vm/make_image.sh m1_xxhash` | xxhash64, gen 38, compat_ro 0x3, incompat 0x371 | `8f4190c9dc500bbdaa15f65fc7994ec8d5476a19b35aa07456f5bab336e98bf7` |
| `m1_sha256_bgt` | `CSUM=sha256 MKFS_ARGS="-O block-group-tree" corpus/vm/make_image.sh m1_sha256_bgt` | sha256, gen 38, compat_ro 0xb (BGT), incompat 0x371 | `f29c1e819d00f77816c3d7181eb38a3ea01c8ceffa7e9e16b6d0161cb93800b6` |
| `m1_blake2b` | `CSUM=blake2 corpus/vm/make_image.sh m1_blake2b` | blake2b, gen 38, compat_ro 0x3 | `909d7573e9725b2fec2dc07c7caaa6f9c3895de30feca759ea65ba89abc470db` |
| `m1_lzo` | `CSUM=xxhash MOUNT_OPTS=compress-force=lzo,commit=5 corpus/vm/make_image.sh m1_lzo` | xxhash64, incompat 0x369 (COMPRESS_LZO) | `fb6f3a0ad7a96244897a4b3e78d084899f8638b4ea0eeda7f584d2965efe7190` |
| `m1_zlib` | `CSUM=xxhash MOUNT_OPTS=compress-force=zlib,commit=5 corpus/vm/make_image.sh m1_zlib` | xxhash64, incompat 0x361 | `91a0140dd93310323281d99a3b79f130e0b02093fdea2282d570a49b924fbfc4` |
| `m1_unknown_incompat` | `uv run python corpus/mutate.py images/scenarios/m1_xxhash.img images/scenarios/m1_unknown_incompat.img set-incompat-bit 40` | both copies valid, incompat 0x10000000371 | `aa6d133f6600803eecf50506b86fd15ac74030c98b19c270b6e88427fd9f63c7` |
| `m1_mirror_damage` | `uv run python corpus/mutate.py images/scenarios/m1_xxhash.img images/scenarios/m1_mirror_damage.img zero-primary-sb` | mirror 0 zeroed, mirror 1 valid | `22472b300e20aca37c333e6e2030448ffbaedda237c46f63ebdb124325b546a7` |

- All five guest logs end in `=== SCENARIO-DONE`, and the balance line reads
  "had to relocate 3 out of 3 chunks".
- Guest-printed SHA-256s are identical across the five runs:
  - `keep.txt` `f6351f5e…9587a`;
  - `deleted_big.txt` `44969d02…3e5fd4`;
  - `deleted_inline.txt` `df6ff35a…5db2`.
- The five s01 generations are bit-unstable across reruns (§7). The manifest
  pins this run, and `test_local_image_matches_manifest_sha256` fails if an
  image is regenerated without updating the manifest.

**`btrfska info` per image** (full outputs in `images/scratch/m1a/info/`):

| Image | Copies | Selected / disagreements | csum type | compat_ro | Gate | Exit |
|---|---|---|---|---|---|---|
| `sandbox.img` | m0 valid `eadc2eaa`, m1 valid `4abd0664`, m2 not present | mirror 0 (gen 14) / none | 0 crc32c | 0xb, BGT note | OK | 0 |
| `m1_xxhash` | m0 `076c0ab4c57738b5`, m1 `103e07ea76928450` valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | OK | 0 |
| `m1_sha256_bgt` | m0 `215d22af…abebd9c`, m1 `4ab60866…17497132` valid | mirror 0 (gen 38) / none | 2 sha256 | 0xb, BGT note | OK | 0 |
| `m1_blake2b` | m0 `a6b01c3d…441ec5dd`, m1 `c34dd59f…7299a54e` valid | mirror 0 (gen 38) / none | 3 blake2b | 0x3 | OK | 0 |
| `m1_lzo` | both valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | OK | 0 |
| `m1_zlib` | both valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | OK | 0 |
| `m1_unknown_incompat` | both valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | `REFUSED` + `UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40` | 2 |
| same, `--allow-unsupported` | | | | | `OVERRIDDEN (--allow-unsupported: derived rows are unsupported_format=1)` + the same line | 0 |
| `m1_mirror_damage` | m0 `INVALID (magic mismatch, csum mismatch)`, m1 valid | **mirror 1** (gen 38) / `mirror 0 invalid: magic mismatch, csum mismatch` | 1 xxhash64 | 0x3 | OK | 0 |

The vm test `test_superblock_csums_agree_with_dump_super` also checks that
`btrfs inspect-internal dump-super -a` prints the same csum bytes with
`[match]` for every copy on the three non-crc32c csum images.

**Deviations** (none changes a plan decision; `plan.md` is not edited):
- **dump-tree ran on a read-only copy.** It ran on a hash-identical 0444
  copy of `sandbox.img` under `images/scratch/`, not on the file itself,
  so btrfs-progs could not write the evidence.
- **`m1_unknown_incompat` sets bit 40 in every copy.** The plan says "bit
  1<<40 set and superblock csum recomputed". Both copies get the bit, each
  with a recomputed csum. Patching only the primary would make best-copy
  selection report a disagreement, which mixes two effects into a test aimed
  at the gate. Both mutated images derive from `m1_xxhash` (the plan names no
  source), so the csum recompute is exercised on a non-crc32c type.
- **`m1_badnode` is deferred to M1b.** Metadata in the s01 images is DUP.
  Whether one or both copies of the leaf must be flipped depends on whether
  M1b's node reader falls back to the second stripe, and M1b owns that
  decision. `m1_lzo` and `m1_zlib` were trivial and are added now.
- **mkfs csum name.** `m1_blake2b` uses `CSUM=blake2`, the btrfs-progs 6.6.3
  mkfs spelling.
- **Device-end rule.** A superblock copy that ends exactly at the image end is
  treated as not present, as the kernel does (`volumes.c:1356`).
- **Unknown compat_ro bits are reported but not refused.** compat_ro only
  forbids writing, and the plan's gate specifies incompat bits only.
- **`NO_VALID_SUPERBLOCK`.** An image without any valid superblock exits 2
  with this line; the plan does not specify this case.
- **Bytenr check needs the magic.** The bytenr problem is reported only when
  the magic matches, so a zeroed copy reads "magic mismatch, csum mismatch"
  rather than three reasons.
- **Import-boundary test moved forward.** It lands here (plan task 8) because
  it is in the M1a DoD. The dissect.btrfs and lzallright oracles are not yet
  in the `dev` group.
- **Placeholder walker API.** The strict-xfail fs-tree tests import
  `btrfska.substrate.tree.fs_tree_inventory`, a placeholder name. M1b may
  rename it, but must make the four tests pass and remove the marker.
- **Sparse copies are coarser.** `mutate.py` keeps only all-zero 1 MiB
  chunks sparse, so derived images use 17–18 MiB on disk against ~10 MiB for
  their source (apparent size identical, 536 870 912 B).
- **Header citation.** research.md §10.3 cites `btrfs_tree.h` for
  incompat-bit values; they are defined in `btrfs.h`. This is recorded in
  §10.7, and §10.3 is not rewritten.

**Research notes.** Added as research.md §10.7:
- superblock copies agree on all healthy images, so a disagreement is
  evidence;
- the kernel's device-end rule;
- the feature bits live in `btrfs.h`;
- dump-super prints csum bytes in disk order;
- in every s01 image all four `backup_fs_root` slots are the same gen-19
  subvolume-5 tree. Deletions inside other subvolumes are invisible to
  `backup_fs_root` diffing, and the scenario's deletions already predate all
  four backups.

**Verification** (local, branch `feature/m1a-trust-foundations`; logs under
`images/scratch/m1a/verify/`).

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all, images present) | `uv run pytest -q` | `244 passed, 4 xfailed` (the four `test_fs_tree_contents_per_generation[11..14]`, reason `tree walker lands in M1b`) |
| Tests without vm | `uv run pytest -q -m "not vm"` | `226 passed, 18 deselected, 4 xfailed` |
| vm tests | `uv run pytest -m vm -q` | `18 passed, 230 deselected` |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `26 files already formatted` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done` | exit 0 |
| Lockfile | `uv lock --check` | `Resolved 10 packages` (consistent) |
| Info | `uv run btrfska info <image>` for `sandbox.img` and the seven `m1_*` images | table above |
| Scope | `git diff --stat main..HEAD` | 21 files: `src/btrfska/{cli.py,substrate/{ondisk,csum,superblock}.py}`, `tests/…`, `corpus/{mutate.py,manifest.tsv,vm/README.md}`, `pyproject.toml`, `uv.lock`, `README.md`, `research.md` (+ this catalog) |
| `sandbox.img` after | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime still 2026-04-26 18:49:36 |

The default count went from 84 (end of M0) to 248 collected. Of those, 18 are
vm tests; in CI, without images, all but `test_manifest_lists_every_m1a_image`
skip.

**For M1b (node reader, chunk maps, tree walker).**
- Make the four strict xfails in `tests/test_ground_truth.py` pass. The
  expected inode inventories are in `tests/ground_truth/sandbox.json` under
  `fs_tree_by_generation`; adapt the placeholder
  `fs_tree_inventory(img, bytenr)` call to the real API.
- Use `ondisk.HEADER`, `ITEM`, `KEY_PTR`, `CHUNK`/`STRIPE`, and
  `csum.block_csum_ok(csum_type, node)` over `[32:nodesize]`. The csum type
  comes from the selected superblock (`Selection.selected.fields`).
- Generate `m1_badnode` once the DUP-mirror read policy is decided, and add
  a `flip-byte` operation to `corpus/mutate.py` behind the same guards.
- On s01 images the backup `fs_root` never changes (§10.7). Walk subvolumes
  through each backup `tree_root`'s ROOT_ITEMs to see `sv1` history.
- A gate refusal must stop the walkers too: `superblock.gate(...).refused`,
  or `unsupported_format=1` rows when overridden.

## 2026-09-15 — M0: reset and scaffolding

- **Branch:** `feature/m0-scaffolding` (from `main` at `b55dae2`). Implements
  plan.md §5 M0 tasks 1–11. No forensic logic.
- **Commits:**
  - `a5023b8` Freeze the prototype under legacy/
  - `e4d12ee` Untrack prototype output and ignore test caches
  - `a2a95f0` Add btrfska package skeleton and project config
  - `908f065` Apply ruff formatting to corpus scripts (no functional change)
  - `8be7fed` Add Apache License 2.0
  - `c51cc74` Rewrite README for btrfska and drop commands.txt
  - `67da6ea` Add read-only and CLI tests with a sandbox hash guard
  - `7f66173` Track a zstd-compressed sandbox.img fixture for CI
  - `1fe1a56` Add GitHub Actions CI
  - this catalog entry (the commit after `1fe1a56`)

**What was done.**
1. **Legacy frozen.** `main.py`, `utils/`, `tests/` moved with `git mv` to
   `legacy/` (all renames detected, R095–R100). Stray `__pycache__` removed.
   The only legacy edits are the four path constants: `SANDBOX_IMG` in
   `test_integration.py` and `test_targeted_scan.py` now resolves the repo
   root (`dirname` ×3). `TEST_OUTPUT` and `TEST_OUT` now point to
   `images/scratch/legacy-tests/{integration,targeted}`.
2. **Untracked:** `recovery_output/` (8 files, kept locally). `.gitignore`
   gains `recovery_output/`, `.pytest_cache/`, `.ruff_cache/`.
   `mnt_sandbox/` removed.
3. **Package** `src/btrfska/`:
   - `__init__.py` (`0.0.1`), `__main__.py`, `cli.py` (argparse, `--version`,
     `info IMAGE` printing path, size and sha256);
   - `substrate/__init__.py` (empty);
   - `substrate/image.py`: `open_image()` → `ImageHandle`, the single
     open site (`os.open(O_RDONLY)` + `mmap.ACCESS_READ`, size via `lseek`
     so block devices work later, `sha256()`, context manager).
4. **`pyproject.toml`** as specified (btrfska 0.0.1, Apache-2.0, `uv_build`,
   dev group pytest/ruff, pytest and ruff config). `uv lock` resolved
   pytest 9.1.1 and ruff 0.16.7.
5. **Corpus formatting commit** touches only
   `corpus/vm/probe_stale_metadata.py` (7 insertions, 6 deletions). The probe
   on `images/scenarios/s01_discard_none.img` printed `367 355 18 832` both
   before and after.
6. **LICENSE:** verbatim Apache-2.0 text from apache.org (11 358 bytes,
   sha256 `cfc7749b…bc523d30`).
7. **Tests:**
   - repo-root `conftest.py`: `REPO_ROOT`, a `sandbox_img` fixture, and an
     autouse session hash guard (expected hash checked at start, unchanged
     at end);
   - `tests/test_cli.py`: 3 tests;
   - `tests/test_readonly.py`: O_RDONLY via `fcntl`, mmap write →
     `TypeError`, size/sha256, the AST open-site scan, and 10 cases proving
     the scanner flags write opens.
8. **README** rewritten per task 8. `commands.txt` removed; its two
   "running at once" lines live in a legacy subsection with `legacy/` paths.
9. **Fixture:**
   - `tests/fixtures/sandbox.img.zst` is 14 963 bytes (`zstd -19` from a
     read-only read);
   - its round trip gives `07ca38d4…5876418`;
   - `tests/fixtures/SHA256SUMS` pins the hash.
10. **CI:** `.github/workflows/ci.yml` follows the task-10 outline step for
    step.

**Verification** (all run locally on the branch; logs under
`images/scratch/m0/`).

| Check | Command | Result |
|---|---|---|
| Legacy baseline (untouched tree) | `uv run --python 3.14 python -m unittest discover -s tests` | `Ran 37 tests`, `OK`; `git status` clean, no `test_output_*` left |
| Legacy after move | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` (same count); integration/targeted ran, output dirs removed on teardown |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `14 files already formatted` |
| Tests | `uv run pytest` | `54 passed` (17 new + 37 legacy), 0 skipped, so no `sandbox.img not found` in the `-ra` summary |
| Sandbox subset | `uv run pytest -m sandbox` | `1 passed, 53 deselected` |
| CLI | `uv run btrfska --help` / `uv run btrfska --version` | usage printed, exit 0 / `0.0.1` |
| uvx | `uvx --from . btrfska --version` | built the wheel, printed `0.0.1` |
| Info | `uv run btrfska info sandbox.img` | `size: 268435456 bytes`, `sha256: 07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418` |
| Shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done` | exit 0 (10 files) |
| CI equivalent, clean clone | `git clone --branch feature/m0-scaffolding . images/scratch/m0/ci-clone`, then every ci.yml step in it | `uv sync --locked` OK; ruff clean; `sh -n` OK; fixture restore `sandbox.img: OK`; `54 passed`; unittest `Ran 37 tests` OK; `--help` OK |
| Smoke (local, `/dev/kvm` present) | `corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh && corpus/vm/make_image.sh smoke_s01` | printed `images/scenarios/smoke_s01.img`; log has `=== SCENARIO-DONE` (1.5 s wall). Not a merge gate |
| Scope | `git status`, `git diff --name-status main..HEAD` | only planned paths changed; working tree clean apart from gitignored `images/` |
| `sandbox.img` | `sha256sum sandbox.img` | before: `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`; after: `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`; mtime still 2026-04-26 |

**Deviations and small additions** (none changes a plan decision, so
`plan.md` is not edited):
- `--version` prints the bare version (`0.0.1`), which matches the
  acceptance check literally.
- `pyproject.toml` also sets `description` and `readme`.
- `ImageHandle` exposes `fd`, so the O_RDONLY test can read the access mode
  with `fcntl`.
- `main()` turns `OSError`/`ValueError` into exit 1 with a message on
  stderr; a missing image is tested.
- The AST scan is slightly stricter than specified. It also flags
  `x.open(...)` calls in a write mode (`Path.open`, `io.open`) and treats a
  non-constant mode as a write.
- The conftest guard also checks the *expected* hash at session start, so a
  wrong fixture fails loudly.
- The legacy CLI line in README writes to `images/scratch/legacy-out` (the
  plan's canonical command), not `recovery_output`.
- "CI green on the PR" can only be checked once the branch is pushed. The
  clean-clone run above is the local equivalent. The action majors
  (`checkout@v7`, `setup-uv@v10`) were taken from the plan. On the first PR run, CI failed at job setup because `astral-sh/setup-uv` has no floating `v10` tag; the workflow now pins `setup-uv@v10.1.0` and CI passes (run 34904950286, 17 s). These pins were not otherwise
  re-checked here.

**Review fixes** (commits `1d402c2`, `e275410`, `631f904`; each test
written and seen failing before the fix):
- **Import mode:** pytest `addopts` gains `--import-mode=importlib`, plus
  `pythonpath = ["."]`. A throwaway `tests/test_crc32c.py` failed collection
  before the change and collected cleanly after.
- **Single hash source:** `conftest.py` parses `tests/fixtures/SHA256SUMS`
  (the file CI checks); `tests/test_cli.py` imports `SANDBOX_SHA256` from
  conftest. No Python file holds the hash literal any more.
- **Write scan** (`tests/test_readonly.py`):
  - resolves imports, so aliased `os.open` is caught;
  - flags write-capable APIs by qualified name (`os.fdopen`,
    `os.truncate`/`ftruncate`, `io.FileIO`, `shutil.copy*`/`move`,
    `tempfile.*`) and write-only method names on any receiver
    (`write_bytes`, `write_text`, `truncate`, …);
  - flags `mmap` unless `access` is literally `ACCESS_READ`.
  - One `WRITE_ALLOWLIST` holds only `substrate/image.py`; M4 `recover`
    writers join it explicitly.
  - Deviation: `copy`/`move` are matched only when they resolve to `shutil`,
    not on any receiver, because `dict.copy()` would be a false positive.
  - 24 new self-test cases (19 failed before the fix). A new test proves the
    allowlist matters only for `image.py`'s one `os.open` call; its read-only
    mmap passes the scan.
- **File-type gate** (`substrate/image.py`):
  - opens with `O_RDONLY | O_NONBLOCK`, so a FIFO cannot block;
  - then `fstat`s the fd and requires `S_ISREG`/`S_ISBLK`, otherwise closes
    it and raises `ValueError("not a regular file or block device: …")`;
  - restores blocking mode afterwards;
  - rejects empty images with `ValueError("empty image: …")`;
  - makes `close()` idempotent.
  - Tests use dirs under `images/scratch/`, not `tmp_path`: directory (was
    ENOMEM), FIFO under a 5 s `SIGALRM` guard (was a hang), empty file,
    symlink to a regular file, double close. The first four failed before
    the fix; the symlink case already passed.
  - `btrfska info images/scratch` now prints the clear error and exits 1.
- **Verification:**
  - `uv run pytest -q`: `84 passed` (54 + 30 new);
  - `uv run ruff check .`: `All checks passed!`;
  - `uv run ruff format --check .`: `14 files already formatted`;
  - `uv run --python 3.14 python -m unittest discover -s legacy/tests`:
    `Ran 37 tests`, `OK`;
  - `sandbox.img` sha256 is still `07ca38d4…5876418`, mtime still
    2026-04-26; no `test_readonly_*` scratch dirs are left behind.

**Follow-ups for M1.**
- ~~Test basename collisions between `tests/` and `legacy/tests/`~~: resolved
  by `--import-mode=importlib` (review fixes above).
- The hash guard runs under pytest only. The original `unittest` runner for
  `legacy/tests` has no guard.

## 2026-09-15 — Plan revision after research refresh

- **Branch:** `docs/plan-revision-2026-09` (PR #6). Docs only: `plan.md`,
  this entry, and after review small consistency edits to `research.md` and
  `README.md`. No code changed.
- **Context:** folds every finding of `research.md` §10 into `plan.md`,
  following the ranked recommendations in §10.6, and turns M0 into an
  executable task list.

**What changed in the plan, and why.**
1. **Novelty claims (§1).**
   - **C3** reworded to *full-state, multi-source, per-inode lifecycle
     timelines* (backup roots + scan-discovered old roots + reconstructed
     fragments).
   - **C4** reworded to *evidence-rule-derived tiers with provenance chains
     across anchored and unanchored artifacts, csum-tree verified*.
   - **C1/C6** made explicitly btrfs-specific, with ReFS (`forefst`, Prade
     2020) and F2FS (Oh & Hwang 2025) cited as CoW analogs.
   - **C5** now cites Toolan & Humphries FSI:DI 58:302198 and SecurityRonin's
     tamper findings.
   - Why: `SecurityRonin/btrfs-forensic` ships backup-root deletion diffs and
     graded findings (§10.1 claim table, §10.2). It is added to "exists
     elsewhere" together with btrfscue v0.7 subvolume restore.
2. **Substrate (§3.5, new).**
   - Decision: **split**. We own image open, superblock + mirrors, csum
     dispatch (4 types), node-header validation, incompat/compat_ro gate,
     chunk maps and backup roots.
   - The first draft kept dissect.btrfs for file streams + decompression
     behind an adapter module. **Superseded in the review round below:**
     all runtime parsing, extent reads and decompression are ours, and
     dissect.btrfs is a test oracle only.
   - Why: dissect.btrfs 1.10 validates no csum, header field or incompat bit
     and maps only via the current chunk tree (§10.2). §3.3 (License) and
     §4 verdicts were updated to match; superblock/tree-walker/chunk-map
     code moved from DELETE to REWRITE.
3. **M1 = trust layer** (csum dispatch, header checks, incompat gate that
   refuses unknown bits and RST/ETv2/REMAP `1<<17`, mirror selection,
   tree 11) (§10.3, §10.6 item 1).
   - Branch salvage as spec/tests (§10.5):
     - defect #8, the EXTENT_ITEM objectid-vs-offset fix;
     - gen 11–14 ground truth, which replaces "gen-13 state";
     - backup roots sorted by generation;
     - the hardening backlog.
   - M1 DoD images come from `corpus/vm/`: xxhash, sha256+BGT, blake2b, bad
     node, unknown incompat, mirror damage.
4. **Corpus from M0/M1 onward (§6.2).**
   - `corpus/vm/` is the only generator, with a `corpus/manifest.tsv` per
     image.
   - New matrix axes: **discard** (none / async quick-unmount / async idle /
     sync, plus a `nodiscard` control) and **block-group tree** (off/on),
     because host mkfs 6.6.3 defaults BGT off (§10.3, §10.4).
5. **Later research items.**
   - Remap tree and RAID stripe tree are gate-refused until picked up.
   - The `CONFIG_BTRFS_EXPERIMENTAL` guest kernel is deferred (§10.3,
     §10.6 items 4 and open question b).
6. **Baselines (M7):** SecurityRonin `recover_deleted`, a TSK `develop`
   build, btrfscue v0.7 `recover`, btrfs-progs ≥ 7.1 `restore` (§10.2,
   §10.6 item 6).
7. **M9 GUI (new, Track P).**
   - A read-only local web UI (`btrfska serve`, Starlette + Jinja2 + htmx)
     over `evidence.db`, after M6 and a stable schema.
   - Datasette, Qt and Tauri/Electron were considered and rejected, with
     reasons.
8. **Test policy (§6.1).**
   - `sandbox.img` is the primary regression image (read-only; sha256
     `07ca38d4…5876418` is asserted before/after every test session).
   - Extra images only under the gitignored `images/`, via `corpus/vm/`.
   - Nothing is created outside the repo.
9. **Research method (§7, new).**
   - EXP-NNN protocol: hypothesis → method → image/scenario → exact command →
     results → threats to validity.
   - Records go to `experiments/EXP-NNN.md` plus a committed regeneration
     script.
   - Numbers enter the paper only if a script regenerates them.
   - Guest-driven measurements need ≥ 5 runs with a per-column median and
     range (the §10.4 discard rows differ by 2 in columns 1–3 and by 4 in
     column 4); tolerances come from the measured range.
10. **M0 made executable** (11 ordered tasks):
    - legacy moved to `legacy/`, with its sandbox/output paths re-pointed so
      tests don't silently skip;
    - `src/btrfska` skeleton with a single read-only open site;
    - pyproject with `uv_build`, pytest, ruff;
    - LICENSE (Apache-2.0 after review), README rewrite;
    - CI outline;
    - exact commands and acceptance checks.

    M1 is broken into 11 ordered tasks.
11. Sections renumbered: §3.5 Substrate decision added (License stays §3.3,
    so research.md §7.4's pointer still holds); §7 Research Method inserted,
    so Paper Plan → §8, Risks → §9 (SecurityRonin marked as a realised risk),
    Working Conventions → §10. research.md §10.6's plan references were
    updated to the new numbering in the review round below.

**Checks made while revising (read-only).**
- PyPI `btrfska` → HTTP 404 (no collision); the name is kept.
- `sandbox.img` sha256 `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`
  (matches §10.4). `zstd -19` compresses it to 14 963 bytes, and the piped
  round-trip reproduces the same hash with no file written. This is the basis
  for the CI fixture (M0 task 9; tracking decided in the review round).
- dissect.btrfs 1.10 metadata: `requires-python >=3.10`, zstd via
  `backports.zstd` only below 3.14.
- `recovery_output/` (8 files) is still tracked in git → untracked in M0.
- There is no `.github/` yet.
- `mmap.ACCESS_READ` write raises `TypeError` (basis for the M0 read-only
  test).

**Open items for the owner** (as first drafted; status after review):
- (a) ~~approve tracking `tests/fixtures/sandbox.img.zst`~~ — resolved:
  tracked in M0 (task 9);
- (b) ~~tag `feature/m1-backup-roots` as `m1-prototype`~~ — done: annotated
  tag pushed to origin, pointing at the branch tip `1e9984e`; the branch is
  kept;
- (c) gen-12 contents of `sandbox.img` are not yet recorded anywhere
  (M1 task 1 captures them) — still open.

### Review round (2026-09-15)

A reviewer approved the revision with fixes; the manager took decisions
A–C. All changes are to `plan.md`, `research.md`, `README.md` and this
entry.

**Decisions.**
- **A. Substrate → dissect.btrfs as test oracle only** (plan §3.5).
  - Why: dissect maps only through its own current chunk tree and has no
    API to route streams through our validated reader or historical chunk
    maps. M1 needs our own extent reads anyway, so dissect's only unique
    runtime contribution was decompression.
  - All runtime parsing (own `struct` tables in `ondisk.py`), extent reads
    (`extents.py`) and decompression (`compress.py`: stdlib `zlib` and
    `compression.zstd`, own LZO1X in `lzo.py`) are ours.
  - dissect.btrfs 1.10 and `lzallright` 0.2 are dev/test oracles in
    `tests/oracle/`.
  - The fallback ladder is lzallright at runtime (stays Apache-2.0), then
    dissect.btrfs at runtime, which would make the tool AGPL-3.0-or-later.
  - "Adapter / AGPL boundary" wording is replaced by a *replacement
    boundary* (`extents.py` + `compress.py`).
- **Licence → Apache-2.0** (plan §3.3): chosen for DFIR/academic reuse and
  the patent grant. Every runtime dependency was checked: numpy BSD-3 (+0BSD/
  MIT/Zlib/CC0), xxhash BSD-2, crc32c LGPL-2.1+ (fine as a separate
  dependency; `google-crc32c` Apache-2.0 is the swap-in for frozen
  binaries), M8 Rust crates Apache/MIT, M9 Starlette/Jinja2 BSD-3 and htmx
  0BSD. Test-only use of AGPL dissect.btrfs does not make the package AGPL
  (not conveyed; dev group only; import-boundary test).
- **B.** `tests/fixtures/sandbox.img.zst` is tracked in M0; no sign-off
  pending (plan task 9, §9 risks).
- **C.** `m1-prototype` tag: done.

**LZO decoder evaluation** (scratch venv, seeded; details in plan §3.5).
- Candidates: `python-lzo` (GPL, rejected); `dissect.util` 3.24
  (Apache-2.0); `lzallright` 0.2.6 (MIT); `lzokay` 2.1.0 (MIT, 1 star).
- 2 000 round-trip vectors: dissect.util (pure and native) and lzallright
  all decode identically.
- Hostile input:
  - dissect.util native panics (`PanicException`, not an `Exception`) on a
    crafted lookbehind stream and on 58/300 bit flips;
  - dissect.util pure Python silently returns 4 bytes for the crafted
    stream;
  - lzallright raises `LZOError`.
- 139–160 of 300 bit flips decode to wrong bytes in every decoder, so LZO
  success is never content evidence.
- Choice: our own bounds-checked pure-Python LZO1X decoder (written from
  `Documentation/staging/lzo.rst`, not GPL source), with lzallright as
  oracle and fallback.

**Reviewer fixes.**
1. M0 acceptance made achievable:
   - `ruff format --check` (ruff 0.16.7) flags 14 files today: 13
     prototype files that move to the excluded `legacy/`, plus
     `corpus/vm/probe_stale_metadata.py`;
   - task 5 now ends with a formatting-only commit for `corpus/`;
   - the git-status allow-list gains `corpus/` and `conftest.py`.
2. §3.5 contradiction resolved by A (own `struct` tables, no cstruct).
3. Superseded by A.
4. AGPL wording fixed per A.
5. This entry now names the branch/PR; open items (a)/(b) resolved.
6. Jitter: §7 and the M2 DoD use a per-column median and range from ≥ 5
   runs, with tolerances taken from the measured range. The per-image probe
   comparison is exact. §7 template gains an environment record (host
   CPU/RAM/storage, host kernel, QEMU, guest kernel, btrfs-progs, Python +
   `uv.lock` hash, git commit, image sha256).
7. Minor fixes:
   - Task 1: the suites remove their own `test_output_*` dirs.
   - Task 2: only the four path constants change (makedirs already fine).
   - Task 3/8 ordering: `commands.txt` removal moved into task 8.
   - M0 `corpus/vm` touchpoint: CI `sh -n` syntax check (passes;
     shellcheck 0.9.0 fails on style notes, so it is not a gate) plus a
     documented local smoke command.
   - Reclaim axis added to the M7 matrix (reclaim × discard).
   - CI actions: `actions/checkout@v7` (v7.0.1) and `astral-sh/setup-uv@v10`
     (v10.1.0), verified via the GitHub API.
8. Cross-references:
   - research.md §10.6 now points at plan §8 (positioning, paper plan),
     §9 (risks), §6.2 and §3.3;
   - README says M0–M9;
   - research.md §1 item 4 already carried the TSK correction (PR #3065,
     `develop`, 2024-11-27, unreleased), so it is unchanged;
   - research.md §1 item 3, §2.2, §7.4, §10.2 and §10.6 note the
     test-oracle refinement;
   - §10.4 records the per-column jitter;
   - §10.5 and open question (c) record the tag.

**Verified while fixing (read-only).**
- Python 3.14.6: `compression.zstd` (libzstd 1.5.7) round-trips.
- Kernel v7.0 `fs/btrfs/lzo.c`: 4-byte total/segment headers, 4 419-byte
  segment bound for 4 KiB sectors, sector-tail padding, and it calls
  `lzo1x_decompress_safe`.
- All `corpus/vm` shell scripts pass `sh -n`.
- `git ls-remote` shows `refs/tags/m1-prototype`, which dereferences to
  `1e9984e`.

## 2026-09-15 — Research refresh (post-reset prior-art watch)

- **Branch:** `docs/research-refresh-2026-09` (PR #5): `research.md` §10,
  this entry, `.gitignore`, and the tracked rootless image generator
  `corpus/vm/` (`fetch_vm.sh`, `build_initramfs.sh`, `init`,
  `run_scenario.sh`, `make_image.sh`, `probe_stale_metadata.py`,
  `discard_table.sh`, `scenarios/`, `README.md`)
- **Context:** first prior-art watch since the 2026-08-17 reset. Five
  areas: literature Jul–Sep 2026 (plus retries of the §4.8 papers), tools and
  libraries, on-disk format evolution to kernel 7.0, rootless test-image
  generation, and the unmerged M1 branch. Full write-up with citations:
  `research.md` §10.

**What was searched.**
- Literature: DFRWS USA 2026 (FSI:DI vol. 57, all 42 Crossref entries) and
  EU 2026 (vol. 56); DFRWS APAC 2026 (program not yet fetchable); FSI:DI
  vols. 58–59; IEEE Access, MDPI, Springer, ACM DTRAP, arXiv; OpenAlex and
  Crossref keyword sweeps (btrfs, bcachefs, ZFS/APFS/F2FS/CoW forensics);
  Semantic Scholar/OpenAlex citations of Beyond Carving; author feeds
  (Wani/Bhat, Hilgert/Schwietert, Göbel/Baier, Shon, Dewald, Toolan);
  GitHub/crates.io/PyPI for new btrfs forensic/undelete tools.
- Tools: dissect.btrfs 1.10 (installed, source read, tested read-only on
  `sandbox.img` and the new scenario images), rustutils/btrfsutils,
  btrfs-progs 6.7–7.1 changelogs, TSK, btrfscue, btrfs-fuse, WinBtrfs,
  python-btrfs, commercial changelogs.
- Format: `btrfs_tree.h` / `btrfs.h` / `fs.h` diffs v6.0 → v7.0 → v7.3-rc3,
  remap-tree patch series and commits, `discard.c` / `disk-io.c` /
  `super.c` in v7.0, and the btrfs docs Status page.

**What was found (ranked by plan impact).**
1. **`SecurityRonin/btrfs-forensic`** (Rust, Apache-2.0, created 2026-07-16):
   crc32c node/superblock checks, backup-root-divergence tamper finding,
   kernel ORPHAN_ITEM listing, and `recover_deleted()` via backup-root FS_TREE
   diff. First dedicated open-source btrfs forensic library; narrows C3/C4
   wording; add to baselines.
2. **dissect.btrfs validates nothing** (no csum of any type, no node-header
   checks, no incompat-flag gate — an unknown flag opened silently; current
   chunk map only). No functional release since 2025-12. The substrate's
   trust layer is entirely ours.
3. **Remap tree merged in kernel 7.0** (incompat bit 17, tree 13, keys
   234–236), experimental-only (`CONFIG_BTRFS_EXPERIMENTAL`, not set on the
   host kernel). It changes relocation from COW-rewrite to address
   translation. C6 stands for mainstream images, strengthens for remap-tree
   images, and gains an explicit relocation log as new evidence.
4. **Discard semantics (v7.0 source + measurement):** async discard is
   auto-enabled on discard-capable devices since 6.2, data-only block groups
   only, 120 s delay, and the queue is purged unmounted; `discard=sync` trims
   everything at commit (measured: stale metadata 355 → 31).
5. **The Sleuth Kit has experimental btrfs on `develop`** (PR #3065, merged
   2024-11-27; unreleased) — corrects research.md §2.3. **btrfscue v0.7**
   (2026-07-04) adds `recover` and unreferenced-subvolume recovery.
6. **Toolan & Humphries now published**: FSI:DI 58:302198 (Sept 2026).
   Missed CoW analogs added: Prade et al. 2020 (ReFS), Oh & Hwang 2025 (F2FS
   address-table rebuild), Bonnet 2026 ReFS thesis + `forefst` (node-slack
   recovery and recoverability verdicts on ReFS).
7. Beyond Carving: 0 citations, code repo empty, no follow-up.
8. btrfs-progs 7.1 current; block-group tree on by default since 6.19;
   `mkfs --rootdir` gained `--subvol` (6.12) and `--compress` (6.13).

**Downloaded:** none. Toolan & Humphries 2026, Plum & Dewald 2018 (now gold
OA per OpenAlex), and Oh & Hwang 2025 were all blocked by publisher bot
protection (403). `docs/` unchanged at 18 PDFs (note: `docs/*.pdf` are
tracked in git, not ignored).

**Test-image generation feasibility (measured, `research.md` §10.4).**

- **New rule (project owner):** every disk image, mount point, VM tooling and
  image scratch file lives under the gitignored `images/` folder inside the
  repo (`images/scenarios/`, `images/vm/`, `images/scratch/`, `images/mnt/`),
  never in `/tmp` or elsewhere. `images/` was added to `.gitignore`; image
  files first created in a temp directory were moved into `images/` or deleted.
  `sandbox.img` is opened read-only (sha256 `07ca38d4…` unchanged after all
  tests).
- `sudo`: password required → no loop mounts. `unshare -r`: namespace works,
  but btrfs/loop mounting is denied. lklfuse: no package, no release
  binaries, LKL is based on kernel 6.12.
- `mkfs.btrfs --rootdir` (progs 6.6.3): works rootless, but produces only a
  fresh filesystem with host `st_ino` objectids → parser fixtures only.
- **QEMU + KVM works without root:** `/dev/kvm` has a seat ACL for the user;
  QEMU 8.2.2 unpacked from `apt-get download` debs; readable kernel from
  `linux-image-unsigned-7.0.0-31-generic`; busybox-static initramfs with the
  host's btrfs modules plus `btrfs-progs`. The generator is tracked in
  `corpus/vm/` (`fetch_vm.sh` → `build_initramfs.sh` → `run_scenario.sh`
  / `make_image.sh`; outputs under `images/`) and was re-run end to end from
  an empty `images/vm/`. Scenario `s01` (xxhash, zstd, subvolume, snapshot,
  delete, 6 commits, full balance) runs in **1.43 s** real
  (`time corpus/vm/run_scenario.sh …`); image generation 6 → 38, 3/3
  chunks relocated.
- **Discard datapoint:** after the same scenario, stale-generation metadata
  blocks were 355 (no discard) = 355 (`discard=async`, TRIM not yet run)
  vs **31 (`discard=sync`)**; copies of a deleted inline string went 18 → 2.
  TRIM is the dominant evidence destroyer → make it a corpus axis.
- **Discard table reproduced** with `corpus/vm/discard_table.sh`
  (`probe_stale_metadata.py`): 367/355/18/832, 367/355/18/832,
  43/31/2/107. Column 1 is one lower than first reported because the
  committed probe skips the superblock copy. The "no discard" guest also
  auto-mounts `discard=async`; QEMU just drops its TRIMs.
- `sandbox.img` has BLOCK_GROUP_TREE (compat_ro 0xb); host mkfs 6.6.3
  images do **not** (compat_ro 0x3; use `-O block-group-tree`). The owner-11
  orphan explanation rests on `sandbox.img` alone.

**M1 branch archaeology (`research.md` §10.5).** `feature/m1-backup-roots`
(commits `d870a98`, `1d48203`, `1e9984e`, 2026-08-14; forked from `c51fe91`,
never reintegrated after the reset) adds backup-root parsing + anchored
walking + 12 tests. Verified via `git archive` extract: **49/49 tests pass**.
Confirmed that `sandbox.img` backup slots hold **gens 13, 14, 11, 12**
(correction to the 2026-08-14 entry's "gen-13 state"). Verdict: code
superseded (hand-rolled CRC32c/superblock), but salvage as spec/tests: the
EXTENT_ITEM objectid-vs-offset bug fix (still present on `main`), the gen
11–14 ground truth, sort-by-generation, and the hardening backlog. Branch
left untouched.

## 2026-08-17 — Project reset: research consolidation, stack decision, doc rewrite

- **Branch:** `main`
- **Context:** After the 2026-08-14 research pass we confirmed that the
  project's headline capability (deleted-file recovery from raw Btrfs images)
  is heavily pre-implemented in open source and now also published
  ("Beyond Carving", IEEE Access, July 2026 — full text obtained and read).
  A deeper, verified research sweep was run over (a) every open-source tool
  and library that parses raw Btrfs images, (b) the complete academic
  landscape 2013–2026, and (c) the implementation-stack question.

**What was done.**

- Full verified survey of the tool/library landscape (results in
  `research.md` §2–§3). Highlights: Sleuth Kit **upstream has no Btrfs**
  (PR #413 closed unmerged 2024); `dissect.btrfs` (Fox-IT, AGPL-3.0) is the
  strongest raw-image Python substrate; `rustutils/btrfsutils` (MIT/Apache,
  2026) is the emerging permissive Rust option; `btrfs-rec` (lukeshu) is
  prior art for lost-branch reattachment.
- Full verification of the academic corpus (results in `research.md` §4–§6),
  including reading the full text of Pandey/Jain/Shetty "Beyond Carving"
  (IEEE Access 14:120632–120660, DOI 10.1109/ACCESS.2026.3713173, CC BY).
  Its coverage and its explicitly stated future work now define our novelty
  boundary.
- Stack research and decision (analysis in `research.md` §7, decision in
  `plan.md` §3): **Python orchestration + numpy/crc32c fast scan path now,
  Rust (PyO3/maturin) scan core next**; SQLite evidence catalog; pure-stdlib
  Python confirmed non-viable at TB scale (~15–40 h/TB vs ~20–75 min for the
  numpy path, I/O-bound).
- Migration decision (details in `plan.md` §4): treat most of the existing
  ~2,800-line prototype as *validated research scaffolding*, not product
  code. Reimplemented plumbing (superblock/chunk/tree walking, extraction)
  is superseded by existing libraries; the novel parts (orphan-item
  scanning, slack archaeology, targeted-scan region logic, the sandbox
  empirical findings) carry forward.
- Docs rewritten from scratch: this `catalog.md` (root), `research.md`
  (root), `plan.md` (root). Deleted: `docs/catalog.md`,
  `docs/research_report.md`, old `research.md` (superseded; all content
  incorporated).
- **Full-text read of all five original `docs/` PDFs** (not just abstracts):
  Beyond Carving (28 pp., read in full — algorithm, evaluation, and its
  stated future work now define our novelty boundary), Bhat & Wani 2018,
  Wani et al. 2020, Rodeh et al. 2013, Hilgert et al. 2018. Technical
  digests folded into `research.md` §4.6; two factual corrections captured
  in §8.4 (defrag heuristic was mis-attributed to Wani 2020; slack features
  split into corruption-signal W1/W2 vs payload W3/W4/W5). The plan's
  file-by-file DELETE/MIGRATE/REWRITE verdicts (`plan.md` §4) and the
  btrfs-specific evaluation axes (`plan.md` M7) derive from these reads.
- **Downloaded and read 13 more relevant papers into `docs/`** (18 total):
  MetaRecoverX 2026, DMPedia XFS/Btrfs 2026, Wani & Bhat dataset 2018,
  Juch 2014 thesis, Rodeh 2008, Hilgert 2017 pooled-storage (slides),
  Hilgert 2024 stacked FS, Beebe 2009 ZFS, Schwietert & Hilgert 2025 hiding
  corpus, Göbel 2024 IFIP + fishy 2018, "Mind the slack" 2026, Kim et al.
  2021. Per-paper digests grouped by theme in `research.md` §4.7. Six more
  relevant papers could not be downloaded (paywall/Cloudflare: the Toolan
  SSRN btrfs-hiding preprint, Plum & Dewald APFS, ExtSFR, IEEE ICPCSN 2025,
  Hilgert's Bonn PhD) — logged with citations in §4.8. Key new takeaway:
  Juch 2014 explicitly names our exact contribution (elder-tree
  reconstruction + node-fill-rate deleted-entry detection) as future work.

## 2026-08-14 — Second research pass ("we may be reimplementing prior art")

- **Branch:** `main` — **Commits:** `1b850c2` "added more research",
  `62d1660` "added docs and recovery output"
- First external prior-art audit (`docs/research_report.md`, then expanded
  `research.md`). Discovered the 2026 "Beyond Carving" IEEE Access paper,
  MetaRecoverX, the Toolan & Humphries hiding-techniques preprint, and the
  open-source overlap (btrfs-progs restore/find-root, btrfscue, TSK fork,
  davispuh/btrfs-data-recovery).
- Code-vs-spec audit found six correctness issues in the prototype
  (preserved in `research.md` §8): hardcoded CRC32c despite `csum_type`
  (xxhash/sha256/blake2b); `DEV_ITEM` UUID offset bug (reads FSID at +82 as
  device UUID); `ROOT_ITEM` "reserved region" check flags legitimate modern
  fields; MIXED_GROUPS filesystems break the targeted scan's
  no-metadata-in-DATA-chunks assumption; superblock mirrors never read;
  kernel `ORPHAN_ITEM` (0x30) items unparsed (terminology collision with
  Bhat & Wani "orphan-items").
- Committed sample recovery output (`recovery_output/`) from the sandbox.

## 2026-08-14 — M2: structure-directed targeted orphan scan

- **Branch:** `feature/m2-targeted-orphan-scan` — **Commits:** `c7ce1bc`
  (feature), `891215e`/`c51fe91` (PR merges), `452286a` (catalog doc)
- Replaced the blind full-image sweep with a structure-directed scan:
  - Chunk map now records chunk **type** (`btrfs_chunk.type` at offset 24 of
    the CHUNK_ITEM payload; DATA=0x1, SYSTEM=0x2, METADATA=0x4).
  - `build_scan_regions()` (`utils/chunk_parser.py`): candidate regions =
    everything except DATA chunks and the boot area — METADATA/SYSTEM chunks
    **plus unmapped gaps** left by removed/relocated chunks.
  - Generic anchored tree walker extracted to `utils/tree_walker.py`.
  - `utils/orphan_scan.py`: locates the extent tree via the root tree
    (`ROOT_ITEM` tree-root `bytenr` at offset 176, after the embedded
    160-byte inode item) and enumerates live metadata blocks.
  - Sweep refactored so targeted and full modes share
    `_process_candidate_block()`; CLI flags `--full-sweep`,
    `--scan-data-chunks`; scan-mode stats in the JSON report.
  - Tests: `tests/test_targeted_scan.py` (10 tests: region units + parity).

**Empirical findings on `sandbox.img` (256 MiB) — the project's key dataset:**

| Finding | Measurement |
|---|---|
| Chunk layout | Only 48 of 256 MiB mapped: 8 MiB DATA (0xD00000), 8 MiB SYSTEM (0x1500000), 32 MiB METADATA (logical 0x1D00000 → physical 0x2500000; physical ≠ logical) |
| Live metadata | Current extent tree (root 0x1D38000, gen 14) lists 10 live metadata blocks |
| **Relocated-chunk orphans** | **21 of 71 orphaned nodes lie OUTSIDE the current chunk map** (0x100000–0x130000, 0x500000–0x520000; owners 1–7, 10–11; gens 1–4; header bytenr == physical offset) — remnants of a removed chunk. A mapped-chunks-only scan would miss ~30% of evidence |
| Backup roots | Superblock `btrfs_root_backup` entries reference a complete gen-13 state (tree 0x1D28000, extent 0x1D10000, fs 0x1D20000, dev 0x1D2C000, csum 0x1D08000 — all CRC-valid, owner-correct), one transaction behind current gen 14 |

**Verification.** 37 tests pass. Targeted scan examines 15,867 of 16,379
blocks (512 DATA + boot skipped) and finds the **identical 71 orphaned
nodes, identical recovered files, 0 orphans outside regions** vs the full
sweep.

## 2026-05-12/13 — Brute-force gap closure + plan consolidation

- **Branch:** `main` — **Commits:** `a28daeb` "fixed gaps in brute force",
  `b75cfc2` "Updated plan.md", `e92e648`/`19eab5d` (commands.txt incl. mount
  workflow)
- Closed all items of the brute-force gap checklist (phases A–E of the old
  plan):
  - **Phase A (correctness):** CRC32c validation of every FSID-matching node
    (`utils/crc32c.py`, RFC 3720 vectors in tests); `otime` documented as
    birth time.
  - **Phase B (evidence sources):** leaf slack extraction; boot-sector
    (first 64 KiB) extraction; volume-slack extraction; orphaned extent-tree
    `EXTENT_DATA_REF` (0xB2) parsing; internal-node key-pointer scanning
    beyond `nritems`.
  - **Phase C (enrichment):** move/rename tagging (same inode, different
    names across generations); file-slack reporting; defrag-hazard
    heuristic; snapshot/subvolume indicator (owner ≥ 256).
  - **Phase D (completeness):** internal-node slack mining for residual leaf
    items; `ROOT_ITEM` reserved-field inspection; orphaned device-tree
    (`DEV_ITEM`) parsing.
  - **Phase E (tests/docs):** unit + integration tests, README, plan.
- Item-source mapping: B1–B5 from Bhat & Wani 2018, W1–W5 from Wani et al.
  2020, R1–R3 from Rodeh et al. 2013, H1 from Hilgert et al. 2018.

## 2026-04-28 — README, docs hygiene, journal study

- **Commits:** `b28f796`, `b679b27`, `6fc015b`, `72253de`, `25be300`,
  `5a94ec8`
- Added README; removed paper PDFs from git tracking; studied the four
  foundational papers; log-tree analysis explicitly scoped out for later.

## 2026-04-27 — Brute-force pipeline complete

- **Commits:** `ed97764` "Brute force files recovery implemented", `b66ccd0`
  (plan.md created, files under version control)
- End-to-end pipeline: raw-image sweep in nodesize steps → FSID prefilter →
  CRC32c validation → orphan classification (node gen < superblock gen) →
  item parsing → inline + regular extent extraction → JSON report.

## 2026-04-26 — Phase 1: first recovery (inline → large files → chunk map)

- **Commits:** `4638fd3`, `b99bbd1`, `32b2117`
- First working recovery: node-header/item parsing (`INODE_ITEM`,
  `INODE_REF`, `DIR_ITEM`, `DIR_INDEX`, `EXTENT_DATA`), filename recovery,
  inline-extent extraction (< 16 KiB files), then regular-extent extraction
  for large files via a logical→physical chunk map
  (`utils/chunk_parser.py`).

---

# Current code inventory (as of 2026-08-17)

Pure Python ≥ 3.14, zero third-party dependencies, ~2,830 lines.

| File | Lines | Role | Migration fate (see plan.md §4) |
|---|---|---|---|
| `main.py` | 201 | CLI + orchestration | Rewrite |
| `utils/btree.py` | 968 | Sweep, node/item parsing, extraction, slack mining | **Port** (orphan/slack logic is the novel core) |
| `utils/chunk_parser.py` | 281 | Chunk map + scan regions | Replace (library) / port region logic |
| `utils/constants.py` | 172 | On-disk constants | Replace (library) |
| `utils/crc32c.py` | 33 | Pure-Python CRC32c | Replace (`crc32c` C-ext / Rust) |
| `utils/superblock.py` | 93 | Primary superblock parse | Replace (library) + add mirrors/backup roots |
| `utils/tree_walker.py` | 87 | Generic anchored walker | Replace (library `BTree(root_offset=…)`) |
| `utils/orphan_scan.py` | 109 | Live-metadata set via extent tree | Port |
| `utils/inode_parser.py` | 132 | 160-byte inode item parser | Replace (library) |
| `utils/recovery_report.py` | 230 | Stats + JSON report | Rewrite into catalog/report layer |
| `tests/` (4 files) | 519 | 37 passing tests | Port assertions as golden tests |

Known defects carried on the books (from the 2026-08-14 audit, detailed in
`research.md` §8): CRC32c hardcode, DEV_ITEM UUID offset, ROOT_ITEM
reserved-region false positives, MIXED_GROUPS blind spot, superblock mirrors
ignored, kernel ORPHAN_ITEM (0x30) unparsed, single-stripe-only chunk
translation, no compression support.

# Assets

- `sandbox.img` (256 MiB, untracked) — primary test image; contains a
  complete gen-13 backup-root state, current gen-14 state, 71 orphaned nodes
  (21 outside the chunk map), subvolume owners. Build/mount commands in
  `commands.txt`.
- `recovery_output/` — sample recovery artifacts + `recovery_report.json`.
- `docs/*.pdf` — local copies of the foundational papers.
- `diagrams/` — architecture and format diagrams.
