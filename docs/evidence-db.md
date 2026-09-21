# The evidence database

`btrfska catalog build IMAGE --db PATH` reads an image once, read-only, and writes everything it
learned to one SQLite file. Everything after it (recovery, timelines, confidence tiers, the GUI)
queries that file and not the image. This document is the contract: every table and column is
listed here, and a test fails when one is not (`tests/test_catalog.py`).

- **Schema version: 2.** `PRAGMA user_version` and `scan_runs.schema_version` hold it. A change to
  the DDL in `src/btrfska/catalog/schema.py` bumps it and adds a line to [Versions](#versions).
- **One database, one image, one pass.** The path given to `--db` must not exist. A database is
  never overwritten or updated; a rebuild is a new file. A pass that fails leaves no file.
- **The image is never written.** The builder opens it through `substrate/image.py` (`O_RDONLY`,
  read-only map). Databases are created only in `src/btrfska/catalog/db.py`; the read-only test
  bans `sqlite3.connect` everywhere else in `src/`. Open a database for reading with
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
| `source` | `superblock` (copies disagree), `chunk_map`, `scan_plan` or `walk` |
| `detail` | the message |

### `chunks` and `stripes`: the current chunk map

| Column | Meaning |
|---|---|
| `chunks.chunk_id` | row id |
| `chunks.map_source` | which map this is; `current` in version 1 (historical maps come with plan.md M5) |
| `chunks.accepted` | 0 for a chunk item rejected as invalid; it takes no part in address translation |
| `chunks.logical`, `chunks.length` | *u64* |
| `chunks.type` | *u64* block-group flags |
| `chunks.type_name` | as `dump-tree` prints them, for example `METADATA\|DUP` |
| `chunks.num_stripes`, `chunks.sub_stripes` | from the item |
| `chunks.origin` | where the item was read (the superblock's system array, or a chunk-tree leaf and slot) |
| `chunks.problems` | JSON list; non-empty exactly when `accepted` is 0 |
| `stripes.chunk_id`, `stripes.stripe_index` | the stripe's chunk and position |
| `stripes.devid` | *u64* |
| `stripes.physical` | *u64* byte offset on that device |
| `stripes.dev_uuid` | hex |

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
-- orphans by class and by whether the current chunk map still places them
SELECT status, outside_map, COUNT(*) FROM nodes WHERE orphan GROUP BY 1, 2;

-- every physical copy of one logical block, with its validation record
SELECT n.physical, n.status, c.name, c.ok, c.detail
FROM nodes n JOIN node_checks c USING (node_id) WHERE n.bytenr = 30720000;

-- historical states beyond the backup roots, newest first
SELECT generation, completeness, maps_current, maps_historical
FROM states WHERE known_as = '[]' ORDER BY generation DESC;

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

`artifacts` and `provenance` arrive with the milestones that first write them (plan.md M4, M6).
Items beyond `nritems` and node slack are not parsed (M4). Log generations and the (owner,
generation, level) groups that `btrfska roots` prints are one `GROUP BY` over `nodes`. Only the
current chunk map is stored; historical maps come with M5 (`chunks.map_source`).

## Versions

- **1** (2026-09-21): first version. `scan_runs`, `superblocks`, `problems`, `chunks`, `stripes`,
  `regions`, `nodes`, `node_checks`, `known_roots`, `states`, `state_copies`, `state_trees`,
  `walk_failures`; view `blocks`.
- **2** (2026-09-21): `contents` and `nodes.content_id`; `items`, `item_problems`, `key_ptrs`; the
  parsed tables `inodes`, `inode_refs`, `dir_entries`, `file_extents`, `root_items`, `extents`,
  `extent_backrefs`; views `content_blocks` and `tree_edges`; `key_sort` on every key. Nothing of
  version 1 changed meaning. A version-1 database is refused; rebuild it from the image.
