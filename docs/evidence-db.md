# The evidence database

`btrfska catalog build IMAGE --db PATH` reads an image once, read-only, and writes everything it
learned to one SQLite file. Everything after it (recovery, timelines, confidence tiers, the GUI)
queries that file and not the image. This document is the contract: every table and column is
listed here, and a test fails when one is not (`tests/test_catalog.py`).

- **Schema version: 1.** `PRAGMA user_version` and `scan_runs.schema_version` hold it. A change to
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
```

## Not in version 1

Leaf items, key pointers, tree edges and the parsed inode, directory and extent tables arrive
with the second half of the milestone (plan.md M3b), and `artifacts` and `provenance` with the
milestones that first write them (M4, M6). Log generations and the (owner, generation, level)
groups that `btrfska roots` prints are not stored: both are one `GROUP BY` over `nodes`.

## Versions

- **1** (2026-09-21): first version. `scan_runs`, `superblocks`, `problems`, `chunks`, `stripes`,
  `regions`, `nodes`, `node_checks`, `known_roots`, `states`, `state_copies`, `state_trees`,
  `walk_failures`; view `blocks`.
