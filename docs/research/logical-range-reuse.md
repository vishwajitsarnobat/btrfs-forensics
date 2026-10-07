# When does Btrfs give a new chunk a logical range an older chunk held?

- **Date:** 2026-10-07
- **Question:** GitHub issue #48. Claim C6 reads old file versions through one chunk map per
  generation (plan.md M5a, EXP-007). A single merged chunk map in which the newest record wins
  gives the same answer except where one logical range was mapped to different physical places at
  different times. When does Linux v7.0 do that, which guest operations cause it, and does the
  corpus already contain a case?
- **Sources:** Linux v7.0, fetched from
  `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/fs/btrfs/<file>?h=v7.0`
  (and `include/uapi/linux/btrfs_tree.h`). Every `file:line` below is at tag v7.0. The corpus
  check reads the images of the main checkout read-only through `btrfska catalog build`.
- **Not read:** the competitor `mbkn-btrfs-rescue`. That it uses one merged, newest-wins chunk
  map is how the issue describes it, UNVERIFIED here.

## 1. Answer in short

1. **The kernel never fills a hole in the logical address space.** A new chunk starts at the end
   of the chunk with the highest start that is in the in-memory mapping tree at that moment
   (`find_next_chunk`, `fs/btrfs/volumes.c:2000-2016`, called from `btrfs_create_chunk`,
   `volumes.c:5899`). Logical addresses only go down again when the chunk at the top is removed.
2. **Reuse happens exactly when the topmost chunk (of any type: data, metadata or system) has been
   removed from the mapping tree and another chunk is created before a higher one exists.** The new
   chunk then starts at the end of the highest surviving chunk, which is at or below the removed
   chunk's start, so it overlaps the removed chunk's range (fully or partly; lengths need not
   match). Removing several top chunks lowers the next start further. Removing a chunk that is not
   the topmost never leads to reuse of its range.
3. **Logical reuse alone does not make a merged map translate wrongly.** Device space is handed out
   first-fit, from the lowest hole on the *committed* device tree (`find_free_dev_extent`,
   `volumes.c:1808-1946`). When the removed chunk's device extent is the lowest hole that fits and
   the removal has been committed, the new chunk lands on the same physical bytes, so both maps
   translate the range identically; only the content differs. A merged newest-wins map translates a
   range *wrongly* only when the reuse also got different physical placement: a lower fitting hole
   appeared after the removed chunk was allocated, the allocation happened before the removal was
   committed, or the new chunk has a different profile or size.
4. **The corpus has no reuse.** On all 13 images checked (§5), no logical range is held by two
   different chunks in any map, and no chunk was rejected for a reused address.
5. **A scenario that reuses a range *and* moves it to other physical bytes** is in §4. It
   creates three 64 MiB data chunks Z, W and B, empties Z and B, removes both with
   `btrfs balance start -dusage=0`, and lets the next data chunk start at B's old logical address
   but on Z's old physical bytes.

## 2. The kernel rules, with citations

### 2.1 Where a new chunk starts

`find_next_chunk` takes the last node of `fs_info->mapping_tree` (an rbtree ordered by chunk
start, `btrfs_chunk_map_cmp`, `volumes.c:5753-5765`) and returns `map->start + map->chunk_len`
(`volumes.c:2000-2016`). It returns 0 if the tree is empty. `btrfs_create_chunk` uses that value as
`ctl.start` (`volumes.c:5899`) and `create_chunk` makes it the chunk's start
(`volumes.c:5810, 5818`). There is no search for a free logical range.

What is in the mapping tree:
- at mount, every CHUNK_ITEM of the chunk tree (`read_one_chunk` → `btrfs_add_chunk_map`,
  `volumes.c:7339, 7428`);
- every chunk created since (`create_chunk` → `btrfs_add_chunk_map`, `volumes.c:5838`);
- minus every chunk removed since (`btrfs_remove_chunk_map`, `volumes.c:5741-5751`).

So after a remount the next start is the highest end in the committed chunk tree, and in a
running filesystem it is the highest end of what is mapped right now, committed or not.

### 2.2 When a chunk leaves the mapping tree

`btrfs_remove_chunk` (`volumes.c:3397-3523`) deletes the DEV_EXTENTs (`btrfs_remove_dev_extents`),
the CHUNK_ITEM (`remove_chunk_item`) and the superblock system-array entry for a system chunk, then
calls `btrfs_remove_block_group`. That function deletes the BLOCK_GROUP_ITEM and then, **in the same
transaction, before any commit**, removes the chunk map from the mapping tree, unless the block
group is frozen (`block-group.c:1297-1347`; the comment at `block-group.c:1325-1340` says the map is
kept while frozen precisely so that "the same logical address range and physical device space
ranges" are not reused during a trim). A frozen block group's map is removed when the last
freezer lets go (`btrfs_unfreeze_block_group`, `block-group.c:4733-4760`). With `discard=sync`
the cleaner freezes the group before removal (`block-group.c:1765-1767`) and it is unfrozen after
the commit's discard (`btrfs_finish_extent_commit`, `extent-tree.c:3058-3075`), so under
`discard=sync` reuse waits for the commit; without discard it can happen in the same transaction.

`btrfs_remove_chunk` is reached in two ways:

1. **Relocation (balance, device shrink).** `btrfs_relocate_chunk` relocates the extents
   (`btrfs_relocate_block_group`) and then calls `btrfs_relocate_chunk_finish` →
   `btrfs_remove_chunk` (`volumes.c:3524-3560, 3562-3611`).
2. **Automatic removal of empty block groups.** `btrfs_delete_unused_bgs`
   (`block-group.c:1554-1817`) calls `btrfs_remove_chunk` (`block-group.c:1773`).

### 2.3 Balance: the order and what it allocates

- `__btrfs_balance` walks the chunk tree **from the highest chunk offset downward**: it starts at
  key offset `(u64)-1`, steps to the previous CHUNK_ITEM, and continues at `found_key.offset - 1`
  (`volumes.c:4357-4359, 4388-4389, 4519-4520`). So the topmost chunk is relocated first, and
  chunks created during the balance (which are above everything) are never visited.
- Relocating a block group first makes it read-only: `btrfs_inc_block_group_ro(bg, true)`
  (`relocation.c:5367`). For a data block group that succeeds without a new chunk when the space
  left in the data space info, after taking this group away, still covers what is used
  (`inc_block_group_ro`, `block-group.c:1430-1446`). Otherwise a chunk is forced
  (`block-group.c:3157`), and that chunk starts above the one being relocated, so the old
  chunk is not the topmost when it is removed.
- **A full balance therefore does not reuse logical ranges:** the copy target of each relocated
  chunk is a new chunk at the top, and the old chunk is removed only afterwards
  (`volumes.c:3588-3610`). The corpus confirms it (§5: after the balance of `s01` the three new
  chunks start at 63963136, 131072000 and 164626432, all above the old ones).
- **A balance that relocates the topmost chunk into free space of lower chunks does reuse.** The
  usage filter skips a chunk whose `used` is at or above the threshold; `usage=0` keeps exactly the
  chunks with `used == 0` (`chunk_usage_filter`, `volumes.c:3983-4005`; applied at
  `volumes.c:4140-4142`). An empty topmost data chunk is removed without any allocation, and the
  next chunk created takes its start.
- **Exception:** before relocating a data chunk, balance forces a new data chunk if the
  filesystem has no data in use at all (`btrfs_may_alloc_data_chunk`, `volumes.c:3705-3738`,
  called at `volumes.c:4491`). That chunk is created at the top first, so the empty chunk is no
  longer the topmost when it goes. A reuse scenario must keep some data in another data chunk.

### 2.4 Automatic removal of empty block groups

- A block group is queued as unused when its `used` drops to 0 on a free
  (`btrfs_update_block_group`, `block-group.c:3896-3900`; not with `discard=async`, where the
  discard code queues it after trimming, `discard.c:501, 774`), and at mount for every writable
  empty group (`block-group.c:2532-2539`).
- The queue is processed by the cleaner thread (`cleaner_kthread`, `disk-io.c:1479`), which the
  transaction thread wakes every commit interval (`disk-io.c:1550`); by the remount to read-only
  (`super.c:1369`); and by a final pass at unmount (`close_ctree`, `disk-io.c:4404`).
- `btrfs_delete_unused_bgs` keeps a group that is in use again, read-only (balance is acting on
  it), **the only group of its type** (`list_is_singular`, `block-group.c:1614-1631`), or needed by
  outstanding reservations (`block-group.c:1655-1673`). With `discard=async` the group must be fully
  trimmed first (`block-group.c:1603-1611`), so its old bytes are discarded before its range can be
  reused.

Exactly when the cleaner gets to an emptied group depends on timing (commit interval, reservations,
balance holding `reclaim_bgs_lock`, `block-group.c:1573`). `btrfs balance start -dusage=0`
reaches the same state deterministically, and if the cleaner was faster the balance simply finds
nothing to do.

### 2.5 Where a new chunk lands on the device

- `find_free_dev_extent` searches the device tree's **commit root** (`volumes.c:1845`; the comment
  at `volumes.c:1802-1806` says a device extent freed in the current transaction is not reported as
  available) from 1 MiB (`BTRFS_DEVICE_RANGE_RESERVED`, `volumes.c:1664-1672`) upward and returns
  the **first hole that is large enough** (`volumes.c:1883-1903`), else the largest. Ranges of
  chunks created in the running transaction are skipped through the device's `alloc_state`
  (`dev_extent_hole_check` → `btrfs_find_hole_in_pending_extents`, `volumes.c:1751-1764, 1569`).
- Consequence for reuse: if the removed chunk's device extent is the lowest hole that fits and
  its removal has been committed, the new chunk takes the same physical bytes; the range is reused
  logically *and* physically, with the same translation. Physical placement differs when
  (a) the allocation comes before the removal is committed (the old device extent is still in the
  commit root), (b) a lower hole large enough was freed after the removed chunk was allocated, or
  (c) the new chunk has a different size or profile (a DUP metadata chunk has two stripes; even
  then its first stripe can start at the same offset as the old data chunk).
- On a 512 MiB image a data chunk is 64 MiB: at most 10 % of the writable space
  (`init_alloc_chunk_ctl_policy_regular`, `volumes.c:5454-5456`), rounded up to 16 MiB
  (`decide_stripe_size_regular`, `volumes.c:5625-5634`). The corpus shows exactly that
  (`DATA|single`, length 67108864).

### 2.6 The remap tree (experimental, not in the corpus)

v7.0 has an incompat feature `REMAP_TREE`, only built with `CONFIG_BTRFS_EXPERIMENTAL`
(`fs.h:315-324`). With it, relocation remaps a block group in place instead of copying it to a new
logical address, and `btrfs_relocate_chunk` returns without `btrfs_remove_chunk`
(`volumes.c:3603-3608`; `relocation.c:5408-5422`); the balance walk skips chunks already fully
remapped (`volumes.c:4408-4414`). Whether a fully remapped block group's chunk map ever leaves the
mapping tree, which would decide whether its range can be reused, was not traced: UNVERIFIED. The
pinned `mkfs.btrfs` 6.6.3 cannot create such a filesystem, so it does not bear on the corpus.

## 3. How to see a reuse on an image

None of the three items that describe a chunk carries a generation: `struct btrfs_chunk`,
`struct btrfs_dev_extent` and `struct btrfs_block_group_item` have no such field
(`include/uapi/linux/btrfs_tree.h:641-669, 854-860, 1229-1233`). Time comes from the header
generation of the leaf that holds the item. With `btrfska`:

- **Chunk maps.** Two maps (`chunk_maps`, kinds `historical` and `current`) whose accepted chunks
  overlap in `[logical, logical + length)` with a different `type`, length or stripe set are a
  reuse. The older map's `root_generation` bounds when the first chunk existed, the newer one when
  the second did. A query over `chunks` and `stripes` is enough; the script used for §5 groups
  chunks by (logical, length, type, stripes) and reports every overlapping pair of distinct ones.
- **DEV_EXTENTs.** Two DEV_EXTENTs naming the same `chunk_offset` at different physical offsets,
  found in dev-tree leaves of different generations. The `dev_extents` map of M5a already rejects
  such an address ("more device extents than the profile has copies", "two or more device
  extents that no single dev-tree leaf holds together"), so a reuse shows up there as a rejected
  chunk with that reason.
- **BLOCK_GROUP_ITEMs.** Keyed `(logical, BLOCK_GROUP_ITEM, length)`; a different length or
  `flags` in leaves of different generations at the same logical start is another witness.
- **File data.** A stale file-tree leaf's EXTENT_DATA `disk_bytenr` inside the reused range: read
  through the map of the leaf's own time it gives the logged hash, through the newest map it gives
  other bytes. This is the measurement that separates the two designs.

## 4. Scenario for EXP-010

### 4.1 What it must produce

One logical range that, in two committed generations, belongs to two chunks **with different
physical placement**, and an older file version whose bytes lie in the first chunk and are not
overwritten. Then the per-generation map reads the file back, and a newest-wins map reads other
bytes. A second, simpler variant (§4.4) gives a reuse with the *same* physical placement, the case
in which both designs translate alike.

### 4.2 Expected layout (from the corpus, 512 MiB, pinned mkfs 6.6.3)

`mkfs.btrfs` leaves DATA at logical 13631488 (8 MiB, physical 13631488), SYSTEM DUP at 22020096,
METADATA DUP at 30408704 (32 MiB, stripes at 38797312 and 72351744). The first kernel data chunk
starts at logical 63963136, physical 105906176 (`m2_logtree`, `m4_deep`). With first-fit placement
the next data chunks are expected at:

| Chunk | Logical | Physical | Holds |
|---|---|---|---|
| Z | 63963136 | 105906176 | only `z.bin` (deleted) |
| W | 131072000 | 173015040 | `w.bin` (kept) |
| B | 198180864 | 240123904 | the tail of `b.bin` (deleted) |
| R (new) | 198180864 | 105906176 | `c.bin` |

R takes B's logical start (W is now the topmost chunk) but Z's physical bytes (the lowest hole of
64 MiB on the committed device tree). B's old bytes at 240123904 are not handed out again.
These numbers are a prediction from the rules in §2, not a measurement; the experiment must read
them from the image.

### 4.3 Guest script outline (`corpus/vm/scenarios/reuse.guest.sh`)

Mount options `commit=5`, no compression (so file sizes map to chunk usage), **no discard**
(`discard=async` trims the emptied groups before removal, §2.4; `discard=sync` delays the removal
past the commit, §2.2). Contents from `/dev/urandom` so that no two files share bytes; every
hash logged.

```sh
# 1. survivor in the mkfs data chunk
seq 1 20000 > $MNT/keep.txt; sync
# 2. Z: z.bin is large enough to fill the rest of the 8 MiB chunk and all of Z
head -c 80M /dev/urandom > $MNT/z.bin; sync
# 3. W: w.bin stays inside W
head -c 20M /dev/urandom > $MNT/w.bin; sync
# 4. B: b.bin fills the rest of W and spills into a new chunk B
head -c 80M /dev/urandom > $MNT/b.bin; sync
sha256sum $MNT/*.txt $MNT/*.bin
btrfs filesystem sync $MNT; sleep 6; sync      # one more commit: the b.bin generation is backed up
btrfs inspect-internal dump-tree -t chunk /dev/vda | grep -A4 CHUNK_ITEM
btrfs inspect-internal dump-tree -t extent /dev/vda | grep -A1 BLOCK_GROUP_ITEM   # used per group
# 5. empty Z and B; remove them (top first: B, then Z)
rm $MNT/z.bin $MNT/b.bin; sync
btrfs balance start -dusage=0 $MNT 2>&1 | tail -n 1   # 0 relocated is fine if the cleaner was first
sync; sleep 6; sync                            # commit: the freed device extents reach the commit root
btrfs inspect-internal dump-tree -t chunk /dev/vda | grep -A4 CHUNK_ITEM   # expect: no Z, no B
# 6. reuse: c.bin needs more than the free space of the mkfs chunk and W, so one new data chunk
head -c 100M /dev/urandom > $MNT/c.bin; sync
sha256sum $MNT/c.bin
btrfs inspect-internal dump-tree -t chunk /dev/vda | grep -A4 CHUNK_ITEM   # expect R at B's start
btrfs inspect-internal dump-tree -t dev /dev/vda | grep -A3 DEV_EXTENT
```

The script must print enough to show on the serial log whether the layout came out as planned
(chunk items before step 5, after step 5 and after step 6; `used` per block group before step 5).
The layout depends on how the data allocator spreads `z.bin`, `w.bin` and `b.bin` over the
chunks; the sizes above leave margins of several MiB, but the experiment, not this note, decides
whether they suffice. If Z does not end up empty after step 5 it is not removed, R lands in the
tail hole, and the run degenerates to the variant of §4.4; the check in §4.5 tells the two apart.

### 4.4 Variant: reuse with the same physical bytes (control)

Skip Z: fill the mkfs data chunk with a kept file, write `b.bin` into one new data chunk, delete
it, `balance -dusage=0`, commit, write `c.bin`. The new chunk takes B's logical start and, as the
lowest fitting hole, B's physical bytes too. Both designs translate the range alike, and `b.bin`'s
old bytes are overwritten wherever `c.bin` was written. Prediction: same physical offset; the
per-generation map gains nothing over a merged map here, and only data checksums (M6) can say that
the old version's bytes are gone.

### 4.5 Checks on the image

1. `catalog build --full-sweep`; in `chunks`/`stripes`, at least one pair of accepted chunks from
   different maps with overlapping logical ranges and different stripes (the query of §5). The
   older map's `root_generation` lies before the `rm` generation and the newer one after the
   `c.bin` generation.
2. The `dev_extents` map rejects B's address as reused (two DEV_EXTENTs for one `chunk_offset`
   in no common dev-tree leaf).
3. `recover --maps own` from a state between step 4 and step 5: `b.bin` is complete with the logged
   hash. A newest-wins read of the same extents (to be emulated: no such mode exists in `btrfska`
   today) yields other bytes for the part of `b.bin` in B. `--maps current` cannot place that part
   at all only if no current chunk covers it; with R present it is placed, wrongly, which is
   exactly the competitor's failure.
4. Image hash unchanged; every assertion relative to the image (CONTRIBUTING.md §5), five builds.

**Prediction to register before running:** in at least 4 of 5 builds the layout of §4.2 appears
(R at B's logical start, on Z's physical offset), and `b.bin` reads back with its logged hash
through its own map in every build where it appears. If the allocator spreads the files so that Z
is never emptied, report that and fall back to §4.4 as a control, not as a result for C6.

## 5. The corpus has no reuse

Method: `uv run btrfska catalog build IMG --db … --full-sweep` on every guest-built image of
`corpus/manifest.tsv` plus `sandbox.img` (the mutated copies change no chunk item and were left
out), images read from the main checkout; then a read-only query that lists every distinct
accepted chunk (logical, length, type, stripes) across all maps and every overlapping pair.

| Image | Maps | Distinct chunks | Overlapping pairs | Rejected chunks |
|---|---|---|---|---|
| `s01_discard_none_r1`, `s01_discard_async_r1` | 12 | 8 | 0 | 0 |
| `s01_discard_sync_r1` | 6 | 8 | 0 | 0 |
| `m1_xxhash`, `m1_sha256_bgt`, `m1_blake2b`, `m1_lzo`, `m1_zlib` | 12 | 8 | 0 | 0 |
| `m2_logtree`, `m4_deep` | 7 | 6 | 0 | 0 |
| `m3_wide`, `m5_delsubvol` | 6 | 5 | 0 | 0 |
| `sandbox.img` | 7 | 5 | 0 | 0 |

Why none can be there:
- The `s01` scenario and the `m1_*` images (built with the same default scenario) run one full
  balance. The three new chunks start at 63963136, 131072000 and 164626432, above every old chunk
  (§2.3); the old ranges 1–63963136 are left empty and never handed out again.
- `m2_logtree` and `m4_deep` grow one data chunk at the top (63963136) and remove nothing;
  `m3_wide`, `m5_delsubvol` and `sandbox.img` never leave the mkfs chunks.
- The two temporary chunks of `mkfs.btrfs` (logical 1 MiB and 5 MiB, physical equal to logical)
  are removed by `mkfs.btrfs` itself and lie below everything the kernel later allocates.

So nothing in the corpus can show the difference between per-generation maps and a newest-wins
merged map: on every image, every logical address that any map holds is held by one chunk only.
EXP-007's result for C6 stands, but it does not distinguish the two designs; EXP-010 is needed for
that.

## 6. What this means for C6 and the paper

- The claim "a merged newest-wins map is wrong" holds only for a reused logical range with
  different physical placement. In the kernel that needs the topmost chunk to go away (empty-group
  removal or a balance that relocates it into lower chunks) and, in addition, a placement change
  (§2.5). It is a real but narrow case; the paper must not imply it follows from every balance.
- Logical reuse with the same physical placement is the common form of reuse and is
  indistinguishable by translation; there the per-generation maps and a merged map read the same
  (possibly overwritten) bytes.
- Until EXP-010 has run, any statement that the per-generation design reads data a merged map
  misreads is a prediction, not a result.
