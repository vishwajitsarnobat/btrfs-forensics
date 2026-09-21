# The evidence database

`btrfska catalog build IMAGE --db PATH` reads an image once, read-only, and writes everything it
learned to one SQLite file. Everything after it (recovery, timelines, confidence tiers, the GUI)
queries that file and not the image. This document is the contract: every table and column is
listed here, and a test fails when one is not (`tests/test_catalog.py`).

- **Schema version: 6.** `PRAGMA user_version` and `scan_runs.schema_version` hold it. A change to
  the DDL in `src/btrfska/catalog/schema.py` bumps it and adds a line to [Versions](#versions).
- **One database, one image, one pass.** The path given to `--db` must not exist. A database is
  never overwritten; a rebuild is a new file. A pass that fails leaves no file. What the pass
  wrote never changes afterwards. The only later writer is `btrfska recover`, which appends to
  three tables of its own ([Recovery](#recovery-what-was-extracted-and-from-what)) through a
  connection that is refused every other change.
- **The image is never written.** The builder opens it through `substrate/image.py` (`O_RDONLY`,
  read-only map). Databases are created and opened only in `src/btrfska/catalog/db.py`; the
  read-only test bans `sqlite3.connect` everywhere else in `src/`. Open a database for reading with
  `btrfska.catalog.db.open_readonly`, or with any SQLite client using `file:PATH?mode=ro`.

## Conventions

- **u64 values are stored signed.** SQLite integers are signed 64-bit; btrfs objectids, addresses
  and generations are u64. Columns marked *u64* hold the two's-complement signed value: anything
  of 2^63 and above appears negative. That is how btrfs itself names the high objectids: `-6` is
  the log tree, `-9` the data-relocation tree. `btrfska.catalog.schema.u64()` converts back. Byte
  offsets into the image are below 2^63 and are stored as they are.
- **Keys are stored twice.** Signed storage keeps a value but not its order: objectid `-6` sorts
  before `0`, while btrfs sorts it last. Next to the readable `key_objectid`, `key_type` and
  `key_offset`, every key has `key_sort`: 17 bytes, objectid (big-endian), type, offset
  (big-endian). SQLite compares BLOBs bytewise, so `ORDER BY key_sort` and range conditions on it
  follow the btrfs key order exactly. `btrfska.catalog.schema.key_sort()` builds one.
- **Content is stored once.** DUP and RAID1 copies of a block are byte-identical. `contents` has
  one row per distinct block content (SHA-256 of the nodesize bytes), and items, key pointers and
  every parsed table hang off it. `nodes.content_id` says which content a physical copy holds; a
  copy that differs from its mirror gets its own content, so the difference stays visible. Join
  through the view `content_blocks` to get a content's logical identity and reachability.
- **Booleans** are 0 or 1. A three-valued check is 1 (passed), 0 (failed) or NULL (not checked,
  because its reference value was unknown).
- **Lists and maps** are JSON text (`problems`, `known_as`, `missing`, `gate_unsupported`).
- **Every row records an outcome, not a judgement to be trusted blindly.** An invalid candidate is
  kept with the checks it failed; nothing is dropped because it failed (plan.md §2).

## Tables

### `scan_runs`: the chain of custody (one row)

| Column | Meaning |
|---|---|
| `run_id` | always 1 |
| `schema_version` | the schema version this file was written with |
| `tool_version` | the btrfska version |
| `started_utc`, `finished_utc` | ISO 8601, UTC |
| `image_path` | the path as given |
| `image_size` | bytes |
| `image_sha256_before` | SHA-256 of the image before the pass |
| `image_sha256_after` | SHA-256 after the pass; NULL when `--no-rehash` was given. Equal to `image_sha256_before` on every build that exits 0 |
| `full_sweep` | 1 when DATA chunks were scanned too |
| `workers` | scan worker processes |
| `gate_status` | `OK`, or `OVERRIDDEN` when `--allow-unsupported` continued past the feature gate |
| `gate_unsupported` | JSON list of the unsupported incompat features |
| `unsupported_format` | 1 when the gate was overridden: every row of this database is then suspect |
| `fsid`, `tree_fsid` | hex; `tree_fsid` is `metadata_uuid` when that feature is set, and is what tree blocks carry |
| `generation` | *u64*, of the selected superblock |
| `nodesize`, `sectorsize` | bytes |
| `csum_type`, `csum_name` | 0 crc32c, 1 xxhash64, 2 sha256, 3 blake2b |
| `incompat_flags`, `compat_ro_flags` | *u64* |
| `scan_summary` | JSON: the counts `btrfska scan` prints, per class and per region |

### `superblocks`: every copy the image could hold

| Column | Meaning |
|---|---|
| `mirror` | 0, 1, 2 (at 64 KiB, 64 MiB, 256 GiB) |
| `image_offset` | byte offset of the copy |
| `present` | 0 when the image ends before the copy |
| `valid` | magic, bytenr, checksum and geometry all hold |
| `selected` | 1 for the copy every other table was read from |
| `foreign_fs` | 1 for a valid copy of a *different* filesystem: residue of an earlier mkfs |
| `magic_ok`, `bytenr_ok`, `csum_ok`, `geometry_ok` | the four checks |
| `generation` | *u64*; NULL when not present |
| `fsid` | hex; NULL when not present |
| `problems` | JSON list; on a valid copy these are warnings |

### `problems`: findings that belong to no single row

| Column | Meaning |
|---|---|
| `problem_id` | row id |
| `source` | `superblock` (copies disagree), `chunk_map`, `scan_plan`, `walk`, or `roots` (more root-tree candidates than `--max-states`: the older ones are in `nodes` and `root_items` but not in `states`), or `chunk_maps` (more chunk-tree roots than the bound of 4096 historical maps: the roots a superblock slot names and then the newest were built) |
| `detail` | the message |

### `chunk_maps`, `chunks` and `stripes`: the current chunk map and the historical ones

A balance gives every chunk a new logical address and removes the old chunks. What older states
point at then lies outside the current map, but the chunk-tree blocks that mapped it are usually
still on the disk. The build stores one map per chunk-tree root it finds (plan.md M5a). **No map
is merged into another, and none changes what the current map says.** Which map a recovery read
went through is recorded with the read (`provenance.read_record`, `artifacts.chunk_maps`).

| Column | Meaning |
|---|---|
| `chunk_maps.map_id` | row id; the current map is always 1 |
| `chunk_maps.name` | `current`; `historical:GEN@BYTENR` for the map under a superseded chunk-tree root (with `/levelN` appended when blocks claim that address and generation at several levels, which only a planted block does); `dev_extents` for the one map assembled from DEV_EXTENT items alone |
| `chunk_maps.kind` | `current`, `historical` or `dev_extents` |
| `chunk_maps.root_bytenr`, `chunk_maps.root_generation` | *u64*; the chunk-tree root the map was walked from. NULL for `dev_extents`, which has no place in time |
| `chunk_maps.root_level` | that root's level |
| `chunk_maps.known_as` | JSON list of the `current` and `backup:GEN` sources naming that chunk root; empty for a root only the scan found (a block of tree 3 that no block points to) |
| `chunk_maps.blocks`, `chunk_maps.missing` | for a historical map: distinct chunk-tree blocks found under the root, and referenced but not found. A map with `missing` above 0 may lack chunks. NULL otherwise |
| `chunk_maps.problems` | JSON list: what building the map found (rejected and overlapping chunks, stripes on a device the image does not hold) |
| `chunks.chunk_id` | row id |
| `chunks.map_id` | the map this chunk belongs to |
| `chunks.map_source` | that map's `name`, repeated for reading |
| `chunks.accepted` | 0 for a chunk rejected as invalid; it takes no part in address translation |
| `chunks.logical`, `chunks.length` | *u64* |
| `chunks.type` | *u64* block-group flags. In the `dev_extents` map they come from the BLOCK_GROUP_ITEM of the same address; without one, on a one-device filesystem, the type bits are 0 and the profile is `single` for one device extent and `DUP` for two |
| `chunks.type_name` | as `dump-tree` prints them, for example `METADATA\|DUP` |
| `chunks.num_stripes`, `chunks.sub_stripes` | from the item |
| `chunks.origin` | where the chunk was read: the superblock's system array, a chunk-tree leaf and slot, or the DEV_EXTENTs and the block-group item it was assembled from |
| `chunks.problems` | JSON list; non-empty exactly when `accepted` is 0. In the `dev_extents` map: device extents of different lengths or overlapping, a striped profile (a DEV_EXTENT does not record the stripe order, and none is guessed), more device extents than the profile has copies (the address was reused), a length the block group contradicts, or no block-group item on a filesystem with several devices |
| `stripes.chunk_id`, `stripes.stripe_index` | the stripe's chunk and position |
| `stripes.devid` | *u64* |
| `stripes.physical` | *u64* byte offset on that device |
| `stripes.dev_uuid` | hex; in the `dev_extents` map the uuid of the image's device of that id, zeros for a device the image does not hold |
| `stripes.dev_extents` | the second witness: how many scanned dev-tree leaves, of any generation, hold a DEV_EXTENT with this device and offset that names this chunk's logical address and the length one stripe of it takes. 0: the stripe rests on the CHUNK_ITEM alone |

### `regions`: what was scanned and what was skipped

Scanned and skipped ranges together cover the image exactly once.

| Column | Meaning |
|---|---|
| `region_id` | row id |
| `scanned` | 1 scanned, 0 skipped |
| `kind` | a chunk type such as `METADATA\|DUP`; `unmapped_gap` (no current chunk covers it, where removed chunks used to be); `reserved`; `superblock`; a skipped `DATA\|…` chunk |
| `start_offset`, `end_offset` | byte range `[start, end)` of the image |
| `chunk_logical` | *u64*; the chunk whose stripe this is, NULL for a gap |
| `stripe_index` | that stripe's index |

### `nodes`: every candidate tree block, one row per physical copy

A candidate is a sector-aligned offset whose 16 bytes at header +0x20 equal the tree fsid. It is
recorded whether or not it validates.

| Column | Meaning |
|---|---|
| `node_id` | row id, in physical order |
| `physical` | byte offset in the image; unique |
| `region_id` | the scanned region holding the header |
| `bytenr` | *u64*; the logical address the header claims. NULL when the image ends inside the header |
| `generation`, `owner` | *u64* header fields; `owner` is the tree the block belongs to |
| `level` | 0 for a leaf |
| `nritems` | header field |
| `valid` | 1 when no check failed |
| `status` | `live` (reached from the current state, log tree included), `backup_reachable` (from a backup root only), `unreferenced` (from neither), `invalid` |
| `orphan` | 1 for `backup_reachable` and `unreferenced` |
| `outside_map` | 1 when `physical` lies in no stripe of the current chunk map |
| `legacy_orphan` | the prototype's definition, kept for parity: checksum valid, generation below the superblock's, nodesize-aligned |
| `log_tree` | 1 when the walk of the superblock's log tree reached this copy |
| `bytenr_mapped` | 1 when the current chunk map covers `bytenr` |
| `maps_here` | 1 when a copy of `bytenr` lies at `physical`; 0 for stale blocks in removed chunks |
| `problems` | JSON list, for example a block cut by the image end |
| `content_id` | the content this copy holds; NULL for a block cut by the image end |

### `node_maps`: which historical map explains where a block lies

A tree block carries its own logical address and a checksum, so it tests a chunk map against
something the map was not built from. One row for every valid node that the current map does not
place where it was scanned (`maps_here` 0) and every historical or `dev_extents` map that does:
the map translates the header's `bytenr` to a copy at `physical`. A valid node outside the
current map with no row here lies where no surviving map says it should.

| Column | Meaning |
|---|---|
| `node_id` | the node |
| `map_id` | a map that places it there |

### `node_checks`: the validation record of every node

One row per node and check. Names, in order: `csum`, `bytenr`, `fsid`, `chunk_tree_uuid`,
`generation`, `level`, `nritems`, `written`, `layout`, `owner`, `parent_generation`, `first_key`
(defined in `substrate/node.py`). A scanned block has no referrer, so `bytenr`, `owner`,
`parent_generation` and `first_key` are NULL. A block cut by the image end has no rows.

| Column | Meaning |
|---|---|
| `node_id` | the node |
| `name` | the check |
| `ok` | 1, 0 or NULL |
| `detail` | why it failed; empty otherwise |

### `blocks` (view): logical blocks

Valid nodes grouped by (`bytenr`, `generation`, `level`, `owner`). DUP and RAID1 copies of one
block are one row here.

| Column | Meaning |
|---|---|
| `bytenr`, `generation`, `level`, `owner` | the block's identity |
| `copies` | physical copies found |
| `first_physical` | the lowest of their offsets |
| `live` | 1 when some copy is live |
| `backup_reachable` | 1 when some copy is reached from a backup root only |
| `outside_map` | 1 when every copy lies outside the current chunk map |

### `known_roots`: the roots the superblock and its backup slots name

| Column | Meaning |
|---|---|
| `known_root_id` | row id |
| `source` | `current` or `backup:GEN` |
| `tree` | `root`, `extent`, `chunk`, `dev`, `fs`, `csum` or `log` |
| `tree_id` | *u64* objectid of that tree |
| `bytenr`, `generation` | *u64*, as the superblock records them |
| `level` | as recorded |
| `indexed` | 1 when a valid scanned block matches it |
| `candidate` | 1 when that block is a candidate root (nothing references it) |

### `states`, `state_copies`, `state_trees`: historical root trees

A state is a candidate root-tree block: an owner-1 block that no block one level up points to. It
is evidence of one root tree, not proof of a whole committed filesystem state (README, `btrfska
roots`).

| Column | Meaning |
|---|---|
| `states.state_id` | row id |
| `states.bytenr`, `states.generation` | *u64*; the root-tree block |
| `states.level` | its level |
| `states.known_as` | JSON list of the `current` and `backup:GEN` sources naming this block; empty for a state beyond them |
| `states.root_tree_blocks`, `states.root_tree_missing` | distinct root-tree blocks found, and referenced but not found |
| `states.found`, `states.referenced` | the same over the root tree and every tree it names |
| `states.completeness` | `found / referenced`. Nothing below a missing block is known, so it overstates survival |
| `states.missing` | JSON map from failure class to count (`reused`, `mismatch`, `corrupt`, `overwritten`, `zeroed`, `unreadable`, `unmapped`, `unchecked`) |
| `states.chunk_root_bytenr`, `states.chunk_root_generation` | *u64*; the chunk tree root of this state, NULL when unknown |
| `states.chunk_root_level` | its level |
| `states.chunk_root_source` | `current`, `backup:GEN` or `inferred` |
| `states.chunk_root_differs` | 1 when it is not the current chunk root |
| `states.map_id` | the row of `chunk_maps` walked from that chunk root: the map of the state's own time, through which `recover` reads its file data first. NULL when no chunk root is known or its map was not built |
| `states.maps_current` | found blocks the current chunk map places where they were scanned |
| `states.maps_historical` | the same under the state's own chunk items; NULL unless the chunk root differs |
| `states.maps_neither` | found blocks neither places |
| `states.level_consistent` | 0 when a pointer names an indexed block only at another level (a planted higher block) |
| `states.problems` | JSON list |
| `state_copies.state_id`, `state_copies.physical` | where the root-tree block was scanned |
| `state_trees.state_id`, `state_trees.position` | the state, and the ROOT_ITEM's position in key order |
| `state_trees.tree_id`, `state_trees.key_offset` | *u64*; the ROOT_ITEM key |
| `state_trees.bytenr`, `state_trees.generation` | *u64*; the tree root it names |
| `state_trees.level` | that root's level |
| `state_trees.leaf` | *u64*; the root-tree leaf holding the ROOT_ITEM |
| `state_trees.slot` | its slot |
| `state_trees.status` | `found`, `skipped`, `not_scanned`, `changed`, `unchecked` or a failure class |
| `state_trees.blocks`, `state_trees.missing` | the tree's distinct blocks found, and referenced but not found |

### `walk_failures`: invalid nodes met by the anchored walks

| Column | Meaning |
|---|---|
| `walk_failure_id` | row id |
| `source` | `current` or `backup:GEN` |
| `tree_id` | *u64* |
| `bytenr` | *u64* |
| `failure_class` | as in `states.missing`; on an old backup root `reused` is expected, not damage |

### `contents`: distinct block contents

| Column | Meaning |
|---|---|
| `content_id` | row id |
| `sha256` | of the block's nodesize bytes, hex |
| `level`, `nritems` | from the header |
| `parsed` | 1 when some node holding this content is valid, so its items or key pointers were read. The bytes of a content that never validates are hashed, not interpreted |
| `first_key`, `last_key` | `key_sort` of the first and last item or key pointer; NULL when not parsed or empty |
| `slack_start`, `slack_len` | the block's slack: the bytes no current item or key pointer uses, as an offset in the block and a length. Internal node: from the end of key pointer `nritems` to the end of the block. Leaf: from the end of item `nritems` to the lowest item data. NULL when not parsed |
| `slack_nonzero` | non-zero bytes in the slack. The kernel zeroes the slack before every tree-block write (since v4.9; EXP-005), so anything above 0 was not written by a current kernel |
| `slack_class` | `zero`; `stale_structures`: the slack begins with a valid stale entry of the block's own kind, which is what `mkfs.btrfs` and kernels before 4.9 leave behind; `other`: non-zero bytes that do not begin with one, which is what data hidden in slack looks like. A description, not a verdict: forged stale entries would read as `stale_structures` (plan.md M6 decides) |

### `content_blocks` (view): what a content is

One row per content held by a valid node: `content_id`, its `bytenr`, `generation`, `level`,
`owner`, and as in `blocks`: `copies`, `first_physical`, `live`, `backup_reachable`,
`outside_map`.

### `items`: every item of every parsed leaf

| Column | Meaning |
|---|---|
| `content_id`, `slot` | the leaf content and the item's slot |
| `key_objectid`, `key_offset` | *u64* |
| `key_type` | 0–255 |
| `key_sort` | the key in btrfs order (see Conventions) |
| `type_name` | the key type's name, for example `INODE_ITEM`, or `UNKNOWN.n` |
| `data_offset`, `data_size` | where the payload lies in the block, relative to the end of the header, and its length |
| `data` | the payload bytes, exactly as on disk. An inline file extent's data is in here |

### `item_problems`: what did not parse

| Column | Meaning |
|---|---|
| `content_id` | the content |
| `slot` | the item; NULL for a finding about the block (an item that ends past the block, `nritems` above what fits) |
| `detail` | why. The raw item is in `items` all the same; a bad payload never stops a build |

### `stale_items` and `stale_key_ptrs`: what lies beyond `nritems`

Entries found in the slack of a parsed block (`substrate/slack.py`), on the 25-byte item grid and
on the 33-byte key-pointer grid, both anchored at the end of the block header and both searched
in leaves and in internal nodes (a leaf can be reallocated as a node, and the reverse). They are
**not** part of any tree: they are what an earlier state of the block left behind. On the
project's corpus every one of them is `mkfs.btrfs` bookkeeping (EXP-005); on a filesystem last
written by a kernel older than 4.9 they can be items of deleted files.

| Column | Meaning |
|---|---|
| `stale_items.content_id`, `stale_items.position` | the block content, and the header's byte offset in the block |
| `stale_items.slot` | its index on the item grid; at least `nritems` in a leaf |
| `stale_items.key_objectid`, `stale_items.key_type`, `stale_items.key_offset`, `stale_items.key_sort`, `stale_items.type_name` | the key, as in `items` |
| `stale_items.data_offset`, `stale_items.data_size` | where the header says its payload lies (relative to the end of the block header), and its length. A header counts only when its type is known and that range lies inside the block and behind the header |
| `stale_items.data_state` | `in_slack`: the payload still lies wholly in the slack; `overlaps_live`: live items now use that space; `empty`: a type without payload |
| `stale_items.data` | the payload bytes when `in_slack`; NULL otherwise |
| `stale_key_ptrs.content_id`, `stale_key_ptrs.position`, `stale_key_ptrs.slot` | as above, on the key-pointer grid |
| `stale_key_ptrs.key_objectid`, `stale_key_ptrs.key_type`, `stale_key_ptrs.key_offset`, `stale_key_ptrs.key_sort` | the pointer's key |
| `stale_key_ptrs.blockptr`, `stale_key_ptrs.ptr_generation` | *u64*; the child it named. A pointer counts only when the address is non-zero and sector-aligned and the generation is non-zero and not above the block's own |

### `key_ptrs` and `tree_edges` (view): internal nodes

| Column | Meaning |
|---|---|
| `key_ptrs.content_id`, `key_ptrs.slot` | the internal node content and the pointer's slot |
| `key_ptrs.key_objectid`, `key_ptrs.key_type`, `key_ptrs.key_offset`, `key_ptrs.key_sort` | the pointer's key: the first key of the child |
| `key_ptrs.blockptr` | *u64*; the child's logical address |
| `key_ptrs.ptr_generation` | *u64*; the generation the child must have |
| `tree_edges.parent_bytenr`, `tree_edges.parent_generation`, `tree_edges.parent_level`, `tree_edges.owner` | the parent block |
| `tree_edges.slot`, and the key columns | as in `key_ptrs` |
| `tree_edges.child_bytenr`, `tree_edges.child_generation` | what the pointer names |
| `tree_edges.child_found` | 1 when a valid scanned block has that address and generation, one level down |

### Parsed items

Each table has `content_id` and `slot` (the item it was parsed from); tables whose item packs
several entries add `entry`, the position within the item.

| Table and column | Meaning |
|---|---|
| `inodes.objectid` | *u64* inode number (the key objectid) |
| `inodes.generation`, `inodes.transid` | *u64*; creation and last-change transaction |
| `inodes.size`, `inodes.nbytes` | *u64* bytes |
| `inodes.nlink`, `inodes.uid`, `inodes.gid`, `inodes.mode` | as in `stat` |
| `inodes.rdev`, `inodes.flags`, `inodes.sequence` | *u64* |
| `inodes.atime_sec`, `inodes.ctime_sec`, `inodes.mtime_sec`, `inodes.otime_sec` | *u64* seconds since the epoch; `otime` is the creation time |
| `inodes.atime_nsec`, `inodes.ctime_nsec`, `inodes.mtime_nsec`, `inodes.otime_nsec` | nanoseconds |
| `inode_refs.objectid` | *u64*; the inode the name belongs to |
| `inode_refs.parent_objectid` | *u64*; the directory holding the name |
| `inode_refs.dir_index` | *u64*; its index in that directory |
| `inode_refs.name`, `inode_refs.name_raw` | the name as text (undecodable bytes replaced) and the exact bytes |
| `inode_refs.extended` | 1 for INODE_EXTREF, 0 for INODE_REF |
| `dir_entries.kind` | `DIR_ITEM`, `DIR_INDEX` or `XATTR_ITEM` |
| `dir_entries.dir_objectid` | *u64*; the directory (for XATTR_ITEM, the inode carrying the attribute) |
| `dir_entries.key_offset` | *u64*; the name hash, or the index for DIR_INDEX |
| `dir_entries.child_objectid`, `dir_entries.child_key_type`, `dir_entries.child_offset` | the key the entry points to: an inode, or a ROOT_ITEM for a subvolume |
| `dir_entries.file_type` | btrfs file type (1 regular, 2 directory, 7 symlink, 8 xattr) |
| `dir_entries.transid` | *u64* |
| `dir_entries.data_len` | bytes of xattr value following the name |
| `dir_entries.name`, `dir_entries.name_raw` | as in `inode_refs` |
| `file_extents.objectid`, `file_extents.file_offset` | *u64*; the inode and the offset in the file |
| `file_extents.generation` | *u64*; transaction that wrote the extent |
| `file_extents.ram_bytes` | *u64*; uncompressed size |
| `file_extents.compression`, `file_extents.encryption`, `file_extents.other_encoding` | 0 none; compression 1 zlib, 2 lzo, 3 zstd |
| `file_extents.extent_type`, `file_extents.extent_kind` | 0 `inline`, 1 `regular`, 2 `prealloc` |
| `file_extents.disk_bytenr`, `file_extents.disk_num_bytes` | *u64*; the extent on disk; `disk_bytenr` 0 is a hole. NULL for inline |
| `file_extents.extent_offset`, `file_extents.num_bytes` | *u64*; the part of the extent this file range uses. NULL for inline |
| `file_extents.inline_size` | bytes of inline data in the item; NULL otherwise |
| `root_items.tree_id`, `root_items.key_offset` | *u64*; the ROOT_ITEM key: which tree, and for a snapshot the transaction it was taken in |
| `root_items.bytenr`, `root_items.generation`, `root_items.level` | the tree root it names |
| `root_items.root_dirid`, `root_items.refs`, `root_items.flags`, `root_items.last_snapshot`, `root_items.bytes_used`, `root_items.drop_level` | from the item; `refs` 0 marks a deleted subvolume being cleaned up |
| `root_items.uuid`, `root_items.parent_uuid`, `root_items.received_uuid` | hex; NULL when zero or absent (legacy items) |
| `root_items.ctransid`, `root_items.otransid`, `root_items.otime_sec` | *u64*; NULL on legacy items |
| `extents.bytenr` | *u64*; the extent's logical address (the key objectid) |
| `extents.num_bytes` | *u64*; its length (the key offset). NULL for METADATA_ITEM, whose key offset is the level |
| `extents.refs`, `extents.generation`, `extents.flags` | *u64* from the item; flag 1 data, 2 tree block |
| `extents.tree_block`, `extents.level` | 1 for a tree block, and its level |
| `extent_backrefs.extent_bytenr` | *u64*; the extent referred to |
| `extent_backrefs.ref_type`, `extent_backrefs.ref_type_name` | 176 `TREE_BLOCK_REF`, 182 `SHARED_BLOCK_REF`, 178 `EXTENT_DATA_REF`, 184 `SHARED_DATA_REF`, 172 `EXTENT_OWNER_REF` |
| `extent_backrefs.inline` | 1 when packed inside the extent item, 0 for an item of its own |
| `extent_backrefs.root` | *u64*; the tree that references the extent (or, for an owner ref, that created it) |
| `extent_backrefs.parent` | *u64*; for shared references, the tree block holding the reference |
| `extent_backrefs.objectid`, `extent_backrefs.file_offset` | *u64*; for EXTENT_DATA_REF, the inode and file offset |
| `extent_backrefs.ref_count` | how many references of this kind |

## Recovery: what was extracted, and from what

`btrfska recover IMAGE --db DB --out DIR` appends to these three tables and to no other.
`catalog/db.py` opens the database for it with an SQLite authorizer that allows INSERT and UPDATE
on `recovery_runs`, `artifacts` and `provenance` and denies every other write, DELETE, DDL, PRAGMA
and ATTACH. Rows are never deleted: a second recovery adds a second run.

### `recovery_runs`: one row per `btrfska recover`

| Column | Meaning |
|---|---|
| `recovery_id` | row id |
| `tool_version` | the btrfska version |
| `started_utc`, `finished_utc` | ISO 8601, UTC; `finished_utc` NULL means the run did not end properly, and its artifacts are incomplete |
| `image_path` | the image path as given |
| `image_checked` | 1 when the image's SHA-256 was compared with `scan_runs.image_sha256_before` and matched (a mismatch stops the run before anything is written); 0 with `--no-rehash`. The size is always compared |
| `output_dir` | the directory that was created |
| `options` | JSON: `roots` (as given), `tree_id` (a number or `all`), `dedup`, `orphans`, `graph`, `maps` (`own` or `current`) |
| `summary` | JSON: `artifacts` (count per status), `by_source` (count per source kind and status), `orphan_leaves` (leaves no root tree leads to), `fragments` and `fragments_found` (fragments read with `--graph`, and how many there are; at most 4096 are read, newest first), `bytes_written`, `gaps` (per root and tree, the blocks the tree walk could not follow) |

### `artifacts`: one row per inode that was recovered, recorded or refused

| Column | Meaning |
|---|---|
| `artifact_id` | row id |
| `recovery_id` | the run |
| `source_kind` | how the inode was reached. `anchored_root`: a walk down from a cataloged root tree. `orphan_node`: a leaf read on its own (`recover --orphans`), either a file-tree leaf that no ROOT_ITEM in any scanned root-tree leaf leads to, or a leaf of a dropped log tree (`tree_id` -6). `orphan_item`: found by an anchored walk, in a tree that lists the inode under the kernel's ORPHAN_ITEM (unlinked while open). `orphan_graph` (`recover --graph`): assembled from blocks no root tree leads to, on the evidence `joined` records: every inode of a fragment, and an inode of a lone leaf that a join contributed to (a continuation in another leaf, or the name of a parent directory) |
| `source` | the root as the user names it: `current`, `backup:GEN` or `state:ID`; `orphan_node:BYTENR` for a lone leaf; `fragment:BYTENR@GEN` for a fragment, named after its top block: a file-tree internal node that no scanned key pointer, no ROOT_ITEM and no superblock slot names. A fragment is a tree version that was written within a transaction and replaced before the commit, or one whose root tree is lost. Its blocks were written at different moments of that transaction: it was never a committed state |
| `state_id` | the row of `states` that root is; NULL for `orphan_node` |
| `tree_id` | *u64*; the fs or subvolume tree (for a lone leaf, the owner in its header) |
| `root_bytenr`, `root_generation` | *u64*; that tree's root block under this root; for `orphan_node`, the leaf itself |
| `objectid` | *u64*; the inode number |
| `inode_generation`, `inode_transid` | *u64*; the transaction that created the inode, and the one that last changed it. NULL without an INODE_ITEM. Inode numbers are reused; (`objectid`, `inode_generation`) identifies a file |
| `kind` | `file`, `dir`, `symlink`, `other` (device, FIFO, socket), or `unknown` (items but no INODE_ITEM) |
| `path`, `path_raw` | the path inside the tree, as text (undecodable bytes replaced) and as the exact bytes, after the changes `problems` lists |
| `attached` | 1 when the parent chain reaches the tree's root directory; 0 for a path under `.btrfska-unattached/` (a missing parent, no name, or a cycle) |
| `names` | JSON list of every name: `parent`, `name`, `name_hex`, `index`, `extended` (1 from INODE_EXTREF). The file is written once, under the first. For an `orphan_item` inode, which has no name left, the names it had in other leaves of the same tree that hold its INODE_ITEM with the same creation generation, marked `former` with `leaf_generation` |
| `size` | *u64*; `i_size` |
| `mode` | file type and permission bits as in `stat`. Only the permission bits are applied to the output; setuid, setgid and sticky never are. Ownership is not applied: join `provenance` (role `inode_item`) to `inodes` for uid, gid and the four timestamps |
| `xattrs` | JSON list of `name` and `value_hex`. Recorded, not set on the output file |
| `symlink_target` | for a symlink; symlinks and special files are recorded, never created |
| `status` | `complete`: every byte was read, and `sha256` is set. `partial`: written as `NAME.partial` with a hole for each range in `missing`. `refused_encrypted`: an extent is encrypted, nothing was written. `duplicate`: the same file, unchanged, was already written in this run (`duplicate_of`). `recorded`: nothing to write (symlink, special file, an inode with no content). `failed`: the output file could not be created, or could not be given its name (it then stays as `NAME.partial`, and `problems` says why). A directory that was created is `complete` |
| `bytes_written` | the length of the output file, holes included |
| `sha256` | of the whole file content; only when `complete` |
| `extent_signature` | SHA-256 over `i_size` and every EXTENT_DATA item (offset and raw payload): equal signatures mean equal content without reading it |
| `duplicate_of` | the artifact of this run that holds the same tree, inode, `inode_generation` and `extent_signature` |
| `output_path` | relative to `output_dir`: `SOURCE/tree_ID/PATH`; NULL when nothing was written |
| `in_current` | 1 when the current tree of the same id holds this `objectid` with this `inode_generation`; 0 when it does not (deleted since, or the number was reused); NULL when the current tree could not be read completely |
| `chunk_maps` | JSON list of the chunk maps (`chunk_maps.name`) the file's extents were read through, in order of first use; empty when no extent was read from disk (inline data, holes, duplicates). With `--maps own`, a root whose chunk root is the current one is read through `current` alone; any other root through its own map (`states.map_id`; for a lone leaf the newest map not newer than the leaf), then, only for an extent that map does not place, through the newer maps, oldest first, and last through `dev_extents`. An extent is always placed by one map as a whole. `complete` still means that every byte was read: a range freed by a balance may have been overwritten or trimmed since, and only a data checksum (plan.md M6) or a known hash says whether the bytes are the file's |
| `joined` | JSON list of the joins the artifact rests on (`recover/graph.py`); empty unless `source_kind` is `orphan_graph`. Each has `kind` and `evidence` (the grounds, in words). `pointer`: `fragment_root`, `generation`, `level`, and the fragment's `leaves` and `gaps`; every block was reached through its parent's key pointer (address, generation, level, first key, owner), as in an anchored walk. `sibling`: `objectid` and the `leaves` (bytenr, generation), head first; the file's items continue in the next leaf of the same tree, the extents of all of them cover the file exactly, none is newer than the INODE_ITEM, no joined leaf was written before the INODE_ITEM's last change, and no other scanned leaf continues the file differently. `parent_path`: the directory `objectid`, its `name_hex` and `parent`, the `leaves` holding that name, and `dir_index_names_this_file` (whether a DIR_INDEX of that directory names this file under this name); the number has exactly one name and one creation generation in the scanned leaves of the tree. A join that would be ambiguous is not made: the artifact stays as `--orphans` gives it, and `problems` says why (`not joined with another leaf: …`, `no path: …`) |
| `missing` | JSON list of `[file offset, length, reason]`: an extent failure class of `substrate/extents.py` (`unmapped`, `unreadable`, a decode error, …), `overlap`, `short`, `inode_item_older_than_extent` (the whole file: an extent's generation is above the INODE_ITEM's `transid`. A commit always updates the inode item, so no committed tree holds this; a leaf written within a transaction can, and then the data is the new one while size and times are the old ones. What was written is neither version, so it is not `complete`), or `continues_elsewhere` (the last inode of a lone leaf: its remaining extent items may be in the next leaf, and with NO_HOLES a range without an item looks like a hole) |
| `problems` | JSON list: names that had to be changed, FT_ENCRYPTED on the directory entry, item payloads that did not parse, findings of the extent reader (at most 16 distinct ones; all are in `provenance.read_record`). Among them, for a read through a historical map: that the extent was not placed by the root's own map; that a newer map gives the same logical address to a different chunk (the address was reused); that a newer map has allocated the disk space read to another chunk, so the bytes may have been overwritten |

### `provenance`: the items each artifact was built from

One row per item. Together with `artifacts.root_bytenr` it is the chain from the root to the
bytes: the root names the tree, `parents-of` walks from the leaf up to it, the leaf and slot name
the item, and for an extent `read_record` names every physical range and copy that was read.

| Column | Meaning |
|---|---|
| `provenance_id` | row id |
| `artifact_id`, `seq` | the artifact, and the item's position in key order |
| `role` | `inode_item`, `inode_ref`, `inode_extref`, `xattr` or `extent_data` |
| `content_id`, `slot` | the item in `items` |
| `bytenr`, `generation` | *u64*; the leaf holding it |
| `physical` | the lowest image offset among the valid copies of that leaf |
| `block_status` | `live`, `backup_reachable` or `unreferenced`: the best status among those copies |
| `file_offset`, `length` | for `extent_data`: the file range it supplied, after clipping to `i_size` |
| `extent_sha256` | of the bytes it supplied; NULL for zeros (holes, prealloc) and failures |
| `error_kind` | why it supplied nothing; NULL otherwise |
| `read_record` | JSON: the extent reader's full record (kind, compression, addresses, `chunk_map`: the name of the map that placed the extent, the physical ranges with every copy and whether it matched, problems) |

## Reverse queries

`btrfska catalog query DB …` and `btrfska.catalog.query` answer four questions from the database
alone; the image is not needed. Rows are JSON objects, with integers as on-disk u64 values.

| Query | Answers |
|---|---|
| `parents-of BYTENR [--generation G]` | what references a tree block: internal nodes (`referrer` `node`), ROOT_ITEMs naming it as a tree root (`root_item`), superblock and backup slots (`superblock`) |
| `owners-of BYTENR` | what uses an extent: file extents of any generation pointing to it (`file_extent`), the extent tree's back-references (`extent_backref`), and, for a tree block, the blocks scanned at that address (`tree_block`) |
| `trees-covering OBJECTID TYPE OFFSET` | the leaves, of every tree and generation, whose key range holds the key; `exact` when the key is an item there |
| `items-in-generation G [--type T] [--limit N]` | the items of every leaf whose header generation is G |

Block rows carry `reach`: `live`, `backup_reachable` or `unreferenced`, and `outside_map`.

## Examples

```sql
-- blocks the kernel cannot have written as they are: what is in their slack?
SELECT b.bytenr, b.generation, b.owner, b.live, c.slack_class, c.slack_nonzero
FROM contents c JOIN content_blocks b USING (content_id) WHERE c.slack_nonzero > 0;

-- after `recover --root all --orphans`: file versions that no cataloged root can give
SELECT source, path, size, inode_generation, inode_transid FROM artifacts
WHERE source_kind = 'orphan_node' AND kind = 'file' AND status = 'complete';

-- orphans by class and by whether the current chunk map still places them
SELECT status, outside_map, COUNT(*) FROM nodes WHERE orphan GROUP BY 1, 2;

-- every physical copy of one logical block, with its validation record
SELECT n.physical, n.status, c.name, c.ok, c.detail
FROM nodes n JOIN node_checks c USING (node_id) WHERE n.bytenr = 30720000;

-- historical states beyond the backup roots, newest first
SELECT generation, completeness, maps_current, maps_historical
FROM states WHERE known_as = '[]' ORDER BY generation DESC;

-- the chunk maps of the image, newest first, and what each is anchored by
SELECT name, root_generation, known_as, blocks, missing FROM chunk_maps ORDER BY root_generation DESC;

-- stale blocks outside the current chunk map, and whether an older map explains their position
SELECT n.bytenr, n.generation, n.owner, COUNT(m.map_id) AS maps_placing_it
FROM nodes n LEFT JOIN node_maps m USING (node_id)
WHERE n.valid AND NOT n.maps_here GROUP BY n.node_id;

-- after a recovery: files whose content depended on a historical map
SELECT source, path, status, chunk_maps FROM artifacts WHERE chunk_maps NOT IN ('[]', '["current"]');

-- log-tree blocks: owner -6 is the log tree (see Conventions)
SELECT generation, COUNT(*) FROM nodes WHERE owner = -6 GROUP BY generation;

-- every name an inode ever had, in any surviving generation, live or not
SELECT DISTINCT b.generation, r.parent_objectid, r.name,
       CASE WHEN b.live THEN 'live' WHEN b.backup_reachable THEN 'backup' ELSE 'unreferenced' END
FROM inode_refs r JOIN content_blocks b USING (content_id)
WHERE r.objectid = 257 ORDER BY b.generation;

-- the history of one data extent: who pointed to it, generation by generation
SELECT b.generation, b.owner AS tree, f.objectid AS inode, f.file_offset, b.live
FROM file_extents f JOIN content_blocks b USING (content_id)
WHERE f.disk_bytenr = 13631488 ORDER BY b.generation;

-- items of one leaf in btrfs key order (key_sort, not the signed columns)
SELECT slot, type_name, key_objectid, key_offset FROM items WHERE content_id = 1 ORDER BY key_sort;
```

## Not stored yet

Confidence tiers on `artifacts` arrive with plan.md M6, and with them the decision whether a
block's slack content is tampering (`slack_class` only describes it). Log generations and the (owner,
generation, level) groups that `btrfska roots` prints are one `GROUP BY` over `nodes`. Stripe orders
are never guessed, so a striped chunk known only from DEV_EXTENTs stays rejected.

## Versions

- **1** (2026-09-21): first version. `scan_runs`, `superblocks`, `problems`, `chunks`, `stripes`,
  `regions`, `nodes`, `node_checks`, `known_roots`, `states`, `state_copies`, `state_trees`,
  `walk_failures`; view `blocks`.
- **2** (2026-09-21): `contents` and `nodes.content_id`; `items`, `item_problems`, `key_ptrs`; the
  parsed tables `inodes`, `inode_refs`, `dir_entries`, `file_extents`, `root_items`, `extents`,
  `extent_backrefs`; views `content_blocks` and `tree_edges`; `key_sort` on every key. Nothing of
  version 1 changed meaning. A version-1 database is refused; rebuild it from the image.
- **3** (2026-09-21): `recovery_runs`, `artifacts` and `provenance`, appended by `btrfska recover`
  through a connection that can change nothing else. Nothing of version 2 changed meaning. A
  version-2 database is refused; rebuild it from the image.
- **4** (2026-09-21): `contents.slack_start`, `slack_len`, `slack_nonzero`, `slack_class`; tables
  `stale_items` and `stale_key_ptrs`. Nothing of version 3 changed meaning. A version-3 database
  is refused; rebuild it from the image.
- **5** (2026-09-21): historical chunk maps (plan.md M5a). New tables `chunk_maps` and `node_maps`;
  `chunks.map_id`, `stripes.dev_extents`, `states.map_id`, `artifacts.chunk_maps`; the option
  `maps` in `recovery_runs.options`. `chunks` and `stripes` now hold every map, not only the
  current one: **a query that means the current map must say `WHERE map_id = 1`** (or `map_source
  = 'current'`, which worked before too). Nothing else changed meaning. A version-4 database is
  refused; rebuild it from the image.
- **6** (2026-09-21): the orphan graph (plan.md M5c). `artifacts.joined`; the `source_kind` value
  `orphan_graph` and the `source` form `fragment:BYTENR@GEN`; the `missing` reason
  `inode_item_older_than_extent`, which also applies to `--orphans`: such a file was `complete`
  before and is `partial` now; `graph`, `fragments` and `fragments_found` in `recovery_runs`.
  Nothing the scan writes changed. A version-5 database is refused; rebuild it from the image.
