# btrfs-forensics (`btrfska`)

`btrfska` ("btrfs archaeology") is a strictly read-only, open-source forensic
engine for raw Btrfs images. Btrfs's copy-on-write design leaves behind
historical metadata: orphaned nodes, item remnants beyond `nritems`, backup
and superseded roots, free-space-tree state and relocated-chunk residue. The
goal is to catalog all of it, with provenance and confidence, and answer what
existed, when, what changed, what can be recovered, and whether anything was
hidden.

**Status:** M1 (substrate trust layer) and M2 (scan kernel, orphan
classification, old-root discovery, discard experiments EXP-000 and EXP-002),
M3 (the evidence catalog) and M4 (recovery) are done: `btrfska recover` extracts files from any
cataloged root, from leaves no root tree leads to (dropped log trees included) and from inodes
the kernel lists under ORPHAN_ITEM, each labelled with its source. M5 (reconstruction and
timelines): the catalog keeps the chunk maps of superseded chunk-tree roots and `recover` reads
a state from before a balance through the map of its own time; `recover --graph` joins orphan
blocks where a join can be justified; `btrfska timeline` follows every inode through every
cataloged state. The earlier prototype is frozen, still runnable, under `legacy/`.
- `btrfska recover IMAGE --db DB --out DIR [--root current|backup:GEN|state:ID|all]... [--tree ID|all] [--orphans|--graph]`
  extracts the files of a tree as the current, a backup or a discovered root saw them, and with
  `--orphans` also from leaves that no root tree leads to, one extent at a time, with a
  provenance record per file. It writes only below the new directory
  `DIR`, never to an image, and never passes off a partly read file as complete.
- `btrfska timeline DB [--tree ID|all] [--inode N] [--uncommitted] [--json]` follows every inode
  through every cataloged state: create, modify, rename, move, link, unlink, delete, by tree,
  inode number and creation generation.
- `btrfska scan IMAGE [--full-sweep] [--workers N] [--json]` finds tree
  blocks of the filesystem anywhere on the image, including chunks that have
  since been removed. It classifies each one as `live`, `backup_reachable`,
  `unreferenced` or `invalid`.
- `btrfska roots IMAGE [--full-sweep] [--json]` finds historical tree roots
  among those blocks. It reports every candidate root-tree block (a state)
  with the trees it names and how completely they survive (chunk and log
  trees excluded), checks that every
  superblock and backup root is rediscovered, and tells blocks reused by
  newer trees apart from damaged ones.
- `btrfska catalog build IMAGE --db PATH` reads the image once and writes an
  SQLite evidence database: every candidate tree block with its validation
  record, the current and the historical chunk maps, the superblock copies, the historical states and the
  chain of custody, every item of every valid block, parsed, and what lies
  beyond `nritems` in each block (its slack, and the stale items and key
  pointers in it). `btrfska
  catalog query DB …` answers reverse questions (what points to this block,
  what used this extent, which leaves hold this key, what was written in this
  generation) from the database alone. `btrfska catalog info DB` prints a
  database's scan run.
  Schema: [`docs/evidence-db.md`](docs/evidence-db.md).
- `btrfska info IMAGE` validates every superblock copy (all four checksum
  types), selects the best one, and reports disagreements and the backup
  roots by generation. It refuses unsupported or unknown incompat features
  (exit 2, `UNSUPPORTED_INCOMPAT <name>`; override with
  `--allow-unsupported`).
- `btrfska walk IMAGE --root {current,backup:GEN,bytenr:N}
  [--tree fs|root|chunk|extent|dev|csum|ID] [--linkage enforce|report]` walks
  one tree through the chunk map and prints one JSON line per item. Each line
  carries the root it was reached from and the validation record of every
  physical copy (DUP mirrors included); invalid nodes are reported instead of
  items. With `--linkage report`, a walk from an old root also uses blocks that
  are sound but are not the blocks their parents named, and flags them.
- `btrfska cat IMAGE --inode N [--root …] [--tree fs|ID]` reads one file of
  the current state, a backup root, a subvolume or a snapshot. It handles
  inline, regular and prealloc extents and holes, and zlib, zstd and LZO
  compression (LZO through btrfska's own bounds-checked decoder). The bytes
  go to stdout only when every extent reads, with a provenance record per
  extent on stderr. Data checksums are not verified yet (M6).

**Licence:** Apache-2.0 (see `LICENSE`).

## Quick start

From a fresh clone to a working checkout with every test image, in one
command and a few minutes (about 190 MB is downloaded once):

```sh
./setup.sh                  # environment, sandbox.img, test-image corpus, lint, all tests
./setup.sh --no-corpus      # without the generated images: no KVM or QEMU needed
```

It needs [uv](https://docs.astral.sh/uv/) (which provisions Python 3.14) and
`zstd`. Building the corpus also needs read/write access to `/dev/kvm`,
`qemu-system-x86_64`, `curl`, `ar`, `tar`, `cpio` and `gzip`, on any Linux
distribution; `uv run python corpus/build.py --check` says what is missing and
which package provides it. No root is used and nothing is written outside the
repository folder. [`corpus/vm/README.md`](corpus/vm/README.md) explains how
the images are made and what is pinned.

## Install and run

By hand, without `setup.sh`:

```sh
uv sync                     # create .venv from uv.lock
zstd -dc tests/fixtures/sandbox.img.zst > sandbox.img    # the primary regression image
uv run btrfska --help
uv run btrfska info sandbox.img
uv run btrfska walk sandbox.img --root backup:11 --tree fs
```

### `btrfska walk` output

`walk` writes one JSON object per line to stdout. A one-line summary, the
chunk-map problems (rejected chunks included) and any gate refusal go to
stderr. Every key below is always present; `null` means unknown or not
applicable.

Every record has these keys:
- `record`: `item`, `invalid_node` or `walk_problem`.
- `root`: where the walk started.
  - `source`: `current`, `backup:GEN` or `bytenr:N`.
  - `tree`: the `--tree` argument.
  - `tree_id`.
  - `bytenr`, `level` and `generation` of the start block, as the referrer
    records them.
  - `via`: how the start block was resolved (`superblock`, `backup slot N`,
    `ROOT_ITEM (…) in root tree … leaf … slot …` or `bytenr`).
- `chunk_map`: the source of the chunk map used (`current`).
- `unsupported_format`: `true` when `--allow-unsupported` overrode the gate.
- `node`: the tree block the record comes from.
  - `bytenr`: the block's logical address.
  - `level`, `generation` and `owner`: from the header of the copy used,
    else of the first readable copy (`null` when no copy was read).
  - `valid`: `true` when some copy passed every check.
  - `linkage_mismatch`: empty, except with `--linkage report` for a node that is
    used although it is not valid: the linkage checks its used copy fails
    (`level`, `owner`, `parent_generation`, `first_key`). See below.
  - `copies`: one object per physical copy, in mirror order.
  - `problems`: every failed check, as `mirror N: check: detail`, plus
    node-level findings such as a valid mirror that differs from the one
    used, or a mapping failure (then `copies` is empty).

Each entry of `copies` has these keys:
- `mirror`: 1-based, in stripe order.
- `devid`, `physical`: where the copy lives.
- `readable`: `false` when the bytes could not be read, because the device
  is missing or the copy lies beyond the image end.
- `used`: `true` for the copy whose items are reported.
- `valid`: `true` when no check failed.
- `checks`: every check, always in this order: `csum`, `bytenr`, `fsid`,
  `chunk_tree_uuid`, `generation`, `level`, `nritems`, `written`, `layout`,
  `owner`, `parent_generation`, `first_key`. Each value is `true`, `false`,
  or `null` when not checked (no reference value, or the copy is not
  readable).
- `problems`: `check: detail` for each failed check, or
  `readable: detail`.

**Integrity and linkage.** The checks answer two questions. Integrity: is this a
well-formed block of this filesystem (`csum`, `bytenr`, `fsid`,
`chunk_tree_uuid`, `generation`, `nritems`, `written`, `layout`, and a `level`
below 8)? Linkage: is it the block the referrer meant (`owner`,
`parent_generation`, `first_key`, and the `level` the referrer expects)? The
kernel uses a block only when both hold, and so does `walk` by default
(`--linkage enforce`). A walk from an old root often meets a sound block that is
newer than the old pointer says, because the address was written again. With
`--linkage report` such a block is used when no copy passes every check: its
items are emitted with `valid` `false` and `linkage_mismatch` naming the failed
checks, and its children are followed, each checked against its own pointer. A
copy that fails any integrity check is never used. What a flagged block holds
belongs to another state than the root's, so `--linkage report` is refused for
`--root current`, and `cat`, `tree`, `recover` and `catalog` never use it: a
recovery reports such a pointer as a gap and names the block that lies there.

Keys added by each record type:
- `item`: one leaf item of a valid leaf, or with `--linkage report` of a flagged one.
  - `slot`.
  - `key`: `objectid`, `type`, `type_name` and `offset`.
  - `size`: the item's data size.
  - `summary`: a cheap per-type decode.
- `invalid_node`: a block without any valid copy. It is reported in place of
  its items or children.
  - `parent`: the parent's logical address (`null` for the start block).
  - `parent_slot`: the pointer's slot in the parent.
- `walk_problem`: hop findings for a valid node, emitted before its items.
  - `parent`, `parent_slot`: as for `invalid_node`.
  - `problems`: for example, a last key not below the parent's next key, or
    a pointer to a block already reached, which is not followed.

### `btrfska cat` output

`btrfska cat IMAGE --inode N [--root current|backup:GEN|bytenr:N] [--tree fs|ID]`
writes the inode's bytes to stdout, and nothing else. They are written only
when every extent reads; otherwise stdout stays empty and the exit status is
1. The command opens no file other than the image. stderr carries one JSON
object per line: an `extent` record per extent in file order (implicit holes
included), then one `file` record, then a one-line summary or the error.

Both record types have:
- `record`: `extent` or `file`.
- `root`: as in `walk` (`source`, `tree`, `tree_id`, `bytenr`, `level`,
  `generation`, `via`).
- `inode`: the inode number read.
- `unsupported_format`: `true` when `--allow-unsupported` overrode the gate.

An `extent` record adds:
- `kind`: `inline`, `regular`, `prealloc`, `hole` (an explicit hole:
  `disk_bytenr` 0), `implicit_hole` (no item covers the range) or `invalid`.
- `file_offset`, `length`: the file range this extent supplies, clipped to
  the inode size.
- `leaf`, `slot`: where the EXTENT_DATA item was read (`null` for implicit
  holes).
- `generation`, `ram_bytes`, `disk_bytenr`, `disk_num_bytes`, `offset`,
  `num_bytes`: the item's fields (`null` when the kind has none).
- `compression`: `none`, `zlib`, `lzo`, `zstd` or `type N`.
- `chunk_map`: the source of the chunk map the data was read through.
- `ranges`: the logical ranges read, split at chunk ends and 64 KiB stripe
  boundaries. Each has `logical`, `length` and `copies`; each copy has
  `mirror`, `devid`, `physical`, `readable`, `used` (the copy whose bytes
  were used, the first readable one) and `matches` (whether it equals the
  used copy; `null` for the used copy and unreadable copies).
- `decoded_bytes`: the decompressor's output length. A compressed inline
  extent decodes a whole sector, more than `ram_bytes`.
- `sha256`: of the bytes supplied (`null` for zeros and failures).
- `error_kind`, `error_detail`: why the extent could not be read (`null` and
  `""` when it was): `unmapped`, `unreadable`, `malformed_item`,
  `invalid_extent`, `unsupported_encoding`, `unsupported_compression`,
  `corrupt_stream`, `truncated_stream`, `output_overrun`, `short_output`,
  `lzo_framing` or `lzo_<decoder error>`.
- `problems`: findings that do not change the bytes, such as a divergent
  mirror, non-zero bytes after a compressed stream or past `ram_bytes`, or
  an extent reaching past the sector that holds the end of the file (it is
  clipped to the inode size).

The `file` record adds `size` (the inode size, `null` without an
INODE_ITEM), `complete`, `extents` (the number of extent records), `errors`
(file-level failures: an unreadable tree, a missing inode, a directory,
overlapping extents) and `problems` (such as gaps on a filesystem without
NO_HOLES). Decoding success is not evidence of correct content: LZO has no
checksum and data checksums are verified from M6 on.

`cat` currently holds the whole file in memory before writing it, with a
peak of about twice the file size (explicit and implicit holes excepted).
Streaming reads arrive with the recovery engine (plan.md M4).

### `btrfska scan` output

`btrfska scan IMAGE [--full-sweep] [--workers N] [--json]` looks for tree
blocks of the filesystem anywhere on the image. It validates each one and
classifies it against anchored walks of the current state and of every
backup root. The command opens no file other than the image.

**Where it looks.** Every sector-aligned offset is probed in these regions:
- the stripes of every current chunk except DATA chunks. A region's `kind`
  is the chunk type, for example `METADATA|DUP`;
- `unmapped_gap`: ranges that no current chunk covers, where removed or
  relocated chunks used to be.

Three kinds of range are skipped:
- the first 68 KiB, as `reserved` (boot area and primary superblock);
- the other superblock copies, as `superblock`;
- a DATA chunk, but only when its block-group item agrees with it. The item
  is read from tree 11 when the block-group tree is enabled, else from the
  extent tree.

With MIXED_GROUPS, DATA chunks are scanned. `--full-sweep` scans DATA chunks
too. A candidate is an offset whose 16 bytes at header offset 0x20 equal the
tree fsid (metadata_uuid when it is set). `--workers N` (1 to 4, default 1)
scans 4 MiB pieces of the regions in worker processes; the output is
byte-identical. On candidate-dense input 4 workers are about as fast as one
(validation dominates and records are pickled back), so the default stays 1.

**Limitations.**
- **Reallocated DATA ranges.** The targeted plan skips DATA chunks, so it
  misses tree blocks left in a range that was metadata under an earlier chunk
  and is now allocated to a DATA chunk. Only `--full-sweep` finds them. The
  summary line `skipped as DATA: N bytes` says how much was left out.
- **Foreign filesystems.** The prefilter matches only the current fsid (or
  metadata_uuid). Tree blocks of a previous filesystem on the same device,
  and blocks written before the fsid was changed (`btrfstune -m` or `-u`),
  are not candidates at all.

**Memory.** Candidates are classified and printed one at a time. Memory grows
with the size of the reachable trees (the walked copies of the current state,
its log and the backup roots), not with the number of candidates. With
workers, at most N × 1024 records wait in the parent.

**Log trees.** When the superblock names a log tree (`log_root`, after an
fsync without a later commit), its blocks are walked as part of the current
state. Every log block must have owner `TREE_LOG` (−6) and generation equal
to the superblock generation + 1. Only the log root tree from the superblock
and the subvolume logs its ROOT_ITEMs name get that rule, and a scanned copy
is accepted above the superblock generation only when the log walk reached
that exact copy.

**What it prints.** Without `--json`, stdout carries a summary:
- the plan and the skipped ranges, and `skipped as DATA: N bytes`;
- candidate counts and the classes below;
- the legacy-compatible orphan count;
- the extent-tree content cross-check. The extent tree is reached through the
  same current root tree as the walks, so this checks content, not the root.
  Log blocks are never in the extent tree, so `log tree: N blocks (M live
  copies)` counts them separately;
- one line per region, and any problems.

With `--json`, stdout carries one JSON object per candidate in physical order,
and the summary goes to stderr. The Python API (`scan_image(...).summary`)
has the same counts, including `skipped_data_bytes`, `log_tree` and
`log_tree_blocks`.

Every key below is always present; `null` means unknown or not applicable.
Each record has:
- `record`: `node`.
- `unsupported_format`: `true` when `--allow-unsupported` overrode the gate.
- `physical`: the block's byte offset in the image.
- `bytenr`, `generation`, `owner`, `level`, `nritems`: header fields (`null`
  when the image ends inside the header).
- `bytenr_mapped`: `true` when the current chunk map covers `bytenr`.
- `maps_here`: `true` when one copy of `bytenr` lies at `physical`. It is
  `false` for stale blocks in removed chunks and for garbage.
- `valid`: `true` when every check passed.
- `checks`: the `walk` checks, in the same order: `csum`, `bytenr`, `fsid`,
  `chunk_tree_uuid`, `generation`, `level`, `nritems`, `written`, `layout`,
  `owner`, `parent_generation`, `first_key`. Without a referrer, `bytenr`,
  `owner`, `parent_generation` and `first_key` are `null`. Every check is
  `null` for a block cut by the image end.
- `problems`: `check: detail` for each failed check, or `truncated: …`.
- `region`: the region whose range holds `physical`. It has `kind`,
  `start`, `end`, `chunk` (the chunk's logical address, `null` for a gap)
  and `stripe`.
- `status`: one of these:
  - `invalid`: some check failed;
  - `live`: this copy is reached from the current state (every subvolume
    and snapshot included, and the log tree);
  - `backup_reachable`: reached from a backup root only;
  - `unreferenced`: reached from neither.
- `orphan`: `true` for `backup_reachable` and `unreferenced` nodes.
- `outside_map`: `true` when `physical` lies in no stripe of the current
  chunk map.
- `legacy_orphan`: the prototype's orphan definition, kept for parity: the
  csum validates, the generation is below the superblock's, and the offset
  is nodesize-aligned.
- `log_tree`: `true` when the walk of the superblock's log tree reached this
  copy. Its `generation` check is then the log rule (superblock generation +
  1), and its status is `live`.

The summary line `walk failures: current N; backup roots M (…)` counts the
invalid nodes the walks met, by the `roots` failure classes below. On an old
backup root, `reused` is expected and is not damage.

### `btrfska roots` output

`btrfska roots IMAGE [--full-sweep] [--workers N] [--json]` finds historical
tree roots among the scanned tree blocks, the idea of btrfs-progs
`btrfs-find-root`, and reports how much of each candidate root-tree block
(state) survives. The command opens no file other than the image.

**Method.**
- It scans as `scan` does, with the same regions and options. Every valid
  candidate is indexed by (bytenr, generation, level, owner) with its
  physical copies.
- A log block (owner −6) whose only failed check is its generation, equal to
  the superblock generation + 1, is indexed too. That covers superseded log
  commits no walk reaches. Other failing log candidates are rejected.
- A block is referenced when an internal block one level up, of an owner the
  kernel's owner check accepts and of the same or a newer generation, points
  to it with its bytenr and generation. The **candidate roots** are the blocks
  nothing references, at any level, so a planted higher-level block cannot
  hide the real roots of its generation. A block that only a newer parent
  points to is part of that newer tree, not a candidate.
- Every owner-1 candidate root, a **candidate root-tree block**, is one
  **state**: a historical root tree as far as that block reaches. On a
  multi-leaf root tree whose parent node is gone, a surviving old leaf that
  no newer parent uses is its own state, covering that leaf's ROOT_ITEMs
  only. Its trees are resolved
  through the index, never through a chunk map, so a state whose chunks have
  moved still resolves. A pointer or ROOT_ITEM is found when a valid scanned
  block has its bytenr, generation and level, an acceptable owner and the
  pointer's first key.
- **Completeness** = found / referenced distinct tree blocks. Referenced
  blocks are the blocks of the root tree reached from the candidate block,
  the tree root every ROOT_ITEM in its found leaves names, and every child
  pointer of a found block. ROOT_ITEMs naming tree 1 are not followed, and
  the chunk tree and the log tree are excluded (no ROOT_ITEM names them).
  With nothing missing, completeness 1 means every block of the root tree
  and of every ROOT_ITEM-named tree was found, nothing more. Nothing below a
  missing block is known, so it overstates survival.
- A state is evidence of one root tree, not proof of a whole committed
  filesystem state: a forged owner-1 block is a state too.
- Up to 64 states are evaluated: the superblock and backup ones first, then
  the newest.

With `--json`, stdout carries one JSON object per line and the summary goes
to stderr. Every key below is always present; `null` means unknown or not
applicable. Every record has `record` (its type) and `unsupported_format`
(`true` when `--allow-unsupported` overrode the gate).

- `rediscovery`: one per root the superblock or a backup slot names.
  - `source`: `current` or `backup:GEN`.
  - `tree`: `root`, `extent`, `chunk`, `dev`, `fs`, `csum` or `log`.
  - `tree_id`, `bytenr`, `generation`, `level`: as the superblock records
    them.
  - `indexed`: `true` when a valid scanned block matches it.
  - `candidate`: `true` when that block is a candidate root.
- `state`: one candidate root-tree block (state).
  - `bytenr`, `generation`, `level`: the root-tree block; `copies`: the
    physical offsets where it was scanned.
  - `known_as`: the `current` and `backup:GEN` sources that name this block;
    empty for a state beyond the superblock and backup roots.
  - `trees`: one object per ROOT_ITEM in its leaves, in key order:
    - `tree_id`, `key_offset`: the ROOT_ITEM key;
    - `bytenr`, `generation`, `level`: the tree root it names;
    - `leaf`, `slot`: where the ROOT_ITEM lies;
    - `status`: `found`, `skipped` (a ROOT_ITEM naming the root tree itself
      is not followed), `not_scanned` (a read through the current chunk map
      is valid but the scan plan skipped that range), `changed` (the bytes no
      longer match the scan record), `unchecked` (beyond the state's first
      256 missing blocks, not read) or a failure class;
    - `blocks`, `missing`: the tree's distinct blocks found, and referenced
      but not found.
  - `root_tree_blocks`, `root_tree_missing`: the same for the root tree.
  - `found`, `referenced`, `completeness`: the state totals.
  - `missing`: an object mapping each status of the missing blocks to its
    count. A state walk reads and classifies at most 256 distinct missing
    blocks; `unchecked` counts the further missing pointers without reading
    them. That count is not de-duplicated, so `referenced` is then an upper
    bound and `completeness` a lower one.
  - `chunk_root`: `null` when unknown, else an object:
    - `bytenr`, `generation`, `level`;
    - `source`: `current` or `backup:GEN` when those name the state, else
      `inferred`: the newest chunk-tree candidate root no newer than the
      state;
    - `differs_from_current`: `true` when it is not the current chunk root.
  - `maps_current`: found blocks the current chunk map places where they were
    scanned. `maps_historical`: the same under the CHUNK_ITEMs of the state's
    chunk tree, read through the index and independent of the
    sys_chunk_array (`null` unless `differs_from_current`). `maps_neither`:
    found blocks neither places. This is a read-only check. `catalog build`
    stores those maps (`chunk_maps`), and `recover` reads through them.
  - `level_consistent`: `false` when a pointer of this block names an
    indexed block of the pointer's bytenr and generation only at a level
    other than the block's level − 1 (for example a planted level-7 block
    over real leaves). A problem line gives the count.
  - `problems`: at most 32, then a count: malformed or inconsistent
    ROOT_ITEMs (for example one newer than the state), pointers to blocks
    already reached (not followed) and first-key mismatches.
- `group`: one per (owner, generation, level) of indexed blocks.
  - `owner`, `generation`, `level`.
  - `blocks`: distinct blocks; `copies`: physical copies.
  - `unreferenced`: blocks no internal block of the same generation points
    to.
  - `referenced_by_newer`: of those, blocks an internal block of a newer
    generation points to; they are not candidates.
  - `top`: `true` for the highest level of this owner and generation.
  - `candidates`: the unreferenced blocks that no newer parent points to, at
    any level.
  - `listed`: the bytenrs of the first 16 candidates.
- `log`: one per generation of log-tree blocks (owner −6).
  - `generation`, `blocks`, `copies`, `levels`, `candidates`, `listed`: as
    for groups.
  - `live`: blocks the walk of the superblock's log tree reached.
  - `superseded`: blocks of generation superblock + 1 that walk did not
    reach, such as an earlier log commit of the same transaction.
  - `committed`: `true` when the generation is not above the superblock's:
    a log left from a transaction that has since committed.
- `raw_block`: a RAID stripe tree (owner 12) or remap tree (owner 13)
  candidate, recorded unparsed (at most 256): `owner`, `physical`, `bytenr`,
  `generation`, `level`, `nritems`, `valid`.
- `walk_failure`: an invalid node met by the walk of the current state or a
  backup root: `source`, `tree_id`, `bytenr` and `class`.

**Failure classes**, for missing blocks and walk failures. For each copy, in
this order of precedence:
- `reused`: the copy is an intact tree block of this filesystem but not the
  one the referrer means, and newer. A newer tree, committed or not, took the
  address. On old backup roots this is expected, not damage.
- `mismatch`: intact, but not the block meant, and not newer.
- `corrupt`: this filesystem's fsid, but an integrity check (`csum`,
  `chunk_tree_uuid`, `nritems`, `written`, `layout`, level) fails.
- `overwritten`: no tree block of this filesystem is there.
- `zeroed`: the copy reads as zeros, for example trimmed by discard.
- `unreadable`: beyond the image end or on a missing device.
- `unmapped`: no chunk map places the address. For `roots`, neither the
  current chunk map nor the state's own chunk items place it, and no invalid
  scanned copy carries its bytenr and generation.

In `roots`, a missing block is classified from every source that has it, and
the class earliest in the list above wins:
- a read through the current chunk map;
- when the current map does not place the address, a read through the
  state's own chunk items, so a block of a pre-balance state is read where
  that state had it;
- up to 16 invalid scanned copies whose header carries the block's bytenr and
  generation, checked against what the referrer expects. A present but
  invalid block is therefore `corrupt` or `mismatch`, not `unmapped`.

### `btrfska catalog`

`btrfska catalog build IMAGE --db PATH [--full-sweep] [--workers N] [--max-states N] [--no-rehash]`
scans the image once, read-only, and writes everything `scan` and `roots`
compute, plus the superblock copies, the chunk maps (the current one, one per
superseded chunk-tree root the scan found, and one assembled from DEV_EXTENT
items; none is merged into another) and the scanned regions, to one SQLite file. Later analysis queries that file instead of reading the image
again. [`docs/evidence-db.md`](docs/evidence-db.md) documents every table and
column, with example queries.

- `PATH` must not exist. A database is never overwritten or updated, so the
  command can never write over an image or an earlier result; a build that
  fails leaves no file.
- The image's SHA-256 is recorded before and after the pass (`scan_runs`), with
  the tool version, the options and the feature-gate verdict. `--no-rehash`
  skips the second hash, which is then recorded as unknown. Exit status 1 if
  the image changed during the pass.
- A refused format (exit 2) or an image without a valid superblock (exit 2)
  creates no database. `--allow-unsupported` continues and marks the whole
  run with `unsupported_format`.
- Up to 4096 root trees are evaluated as states (`--max-states`; `btrfska roots` reports 64).
  A root tree that is not a state cannot be named to `recover`, so when an image has more
  candidates than the bound, `problems` says so.
- btrfs u64 values are stored as signed 64-bit integers, so the high objectids
  read as btrfs names them: owner `-6` is the log tree.

`btrfska catalog query DB QUERY …` answers four reverse questions from the
database alone; the image can be gone. One JSON object per line on stdout, the
row count on stderr. Integers are on-disk u64 values, as in `walk`.
- `parents-of BYTENR [--generation G]`: what references a tree block. `referrer`
  is `node` (an internal node's key pointer), `root_item` (a ROOT_ITEM naming
  it as a tree root) or `superblock` (the superblock or a backup slot).
- `owners-of BYTENR`: what uses an extent: `file_extent` rows from every
  surviving generation of every subvolume, `extent_backref` rows from the
  extent tree, and `tree_block` rows when tree blocks were scanned at that
  address.
- `trees-covering OBJECTID TYPE OFFSET`: the leaves, of every tree and
  generation, whose key range holds the key; `exact` says whether the key is
  an item there.
- `items-in-generation G [--type T] [--limit N]`: the items of every leaf whose
  header generation is G.

Rows that describe a block carry `reach` (`live`, `backup_reachable`,
`unreferenced`) and `outside_map`.

`btrfska catalog info DB [--json]` opens a database read-only and prints its
scan run, its row counts, the nodes per class and the number of distinct valid
blocks. It refuses a file of another schema version or of an unfinished build.

```sh
uv run btrfska catalog build sandbox.img --db images/scratch/sandbox.db
uv run btrfska catalog info images/scratch/sandbox.db
sqlite3 -readonly images/scratch/sandbox.db \
  "SELECT status, outside_map, COUNT(*) FROM nodes WHERE orphan GROUP BY 1, 2"
```

### `btrfska timeline`

`btrfska timeline DB [--tree ID|all] [--inode N] [--uncommitted] [--json]` says what happened to
every inode of every file tree, from the evidence database alone (the image is not needed, and
nothing is written). Every state the catalog holds is compared, in generation order: the current
root, the backup roots and the roots only the scan found.

- **Identity is tree, inode number and creation generation.** btrfs reuses inode numbers: on
  `sandbox.img` inode 257 is `target_file.txt`, created in generation 10 and deleted by 12, and
  then `large_target.txt`, created in 13 and deleted by 14. The number alone would make that one
  renamed file.
- **Versions, then events.** Each walk of a tree gives every inode an observation (names, size,
  mode, owner, link count, `transid`, extents). Equal consecutive observations are one version.
  Events are the differences between consecutive versions: `create` (its transaction is the
  INODE_ITEM's creation generation, exact), `rename`, `move`, `link`, `unlink`, `modify`, `attr`,
  `touch` (the inode item changed and nothing else above: times, link count, a directory's
  entries), and `delete` when a later state of the same tree, walked without a gap, no longer
  holds the identity. When every later walk has gaps the event is `not_seen`: absence from an
  incomplete walk proves nothing. `subvolume_deleted` is one event for a tree that a later
  state, whose whole root tree was found, no longer names. Several changes between two surviving
  states show as their net effect.
- **`modify` lists the byte ranges whose extent differs** between the two versions (`delta`:
  `offset`, `length`, `change` `added`, `removed` or `replaced`), comparing what the extent items
  point at (address and offset into it, compression, inline bytes), not how they are cut, and
  without reading data.
- **Time.** Generations order everything. `times` (`otime`, `mtime`, `ctime` as `[sec, nsec]`) are
  copied from the version's inode item: what the filesystem recorded, which a user can set.
- **`--uncommitted`** adds what was never a committed state: fragments and lone leaves
  (`recover --graph`'s sources) and log trees, each log tree filed under the subvolume that the
  ROOT_ITEM of its log root tree names. Such observations sort before the committed state of
  their generation, are marked `uncommitted_only`, and never prove a `delete`. A version whose
  inode item is older than an extent (see `recover`) is marked `inconsistent`. An identity seen
  only there ends with `never_committed`: a file written, fsynced and deleted within one
  transaction, for instance.
- When the database holds a recovery, an event carries the `sha256` of the complete artifact with
  the same tree, inode, creation generation and extent signature.

With `--json`, one object per event. Keys of every event: `event`, `tree_id`, `objectid`,
`created` (the creation generation), `transaction` (the generation the event happened in, when the
items say so exactly: the creation generation for `create`, the version's `transid` for a change;
`null` otherwise), `between` (the two sources that bound the event, older first; `null` for
`create`) and `generations` (theirs), `path`, `attached`, `kind`, `size`, `transid`,
`extent_signature`, `inconsistent`, `times`, `first_seen` and `last_seen` (`source` and
`generation` of the version the event leads to; for `delete` and `not_seen`, of the last version),
`seen_in` (how many sources showed that version), `uncommitted_only`, `sha256`, and `order_assumed`:
true when the two bounding sources have the same generation. Two root trees of one generation can
survive (one written in the middle of the transaction); generations cannot order them, so they are
taken in the order of their addresses, the one a superblock slot names last, and the event says
that this order is an assumption. Added by kind:
`create` has `reused_inode_number` and `previous_creation_generations`; `rename` and `move` have
`from` and `to` (`parent`, `name`, `path`); `link` and `unlink` have `name` (`parent`, `name`);
`modify` has `size_before` and `delta`; `attr` has `before` and `after` (`mode`, `uid`, `gid`);
`not_seen` has `reason`. A `subvolume_deleted` event has only `event`, `tree_id`, `between`,
`generations`, `order_assumed` and `null` for `objectid`, `created` and `transaction`. The summary and the first
gaps go to stderr.

### `btrfska recover`

`btrfska recover IMAGE --db DB --out DIR [--root ROOT]... [--tree ID|all] [--orphans] [--graph] [--maps own|current] [--no-dedup] [--no-rehash]`
extracts files. `DB` is the evidence database built from `IMAGE` (`catalog build`, best with
`--full-sweep`); the image's size and SHA-256 must match the ones recorded there (`--no-rehash`
skips the hash, and the run is recorded as not checked).

- `--root` is `current`, `backup:GEN`, `state:ID`, or `all` for every cataloged state, and may
  be repeated; the default is `current`. Every root tree the catalog knows is a state (`btrfska roots`, table `states`), so a
  root that only the scan discovered is recovered exactly like a backup root. `--tree` is a tree
  id (default 5, the top-level fs tree; 256 and above for a subvolume or snapshot) or `all` for
  every file tree the root names.
- **Metadata comes from the database, file data from the image.** The tree is walked in the
  database, so blocks the current chunk map no longer places are reached too. A pointer to a
  block that was not scanned as valid is reported as a `gap`; the files below it are absent.
  When a valid block of another generation, level or tree lies at that address, the gap names it
  and the linkage checks it fails. It is never followed: it belongs to another state.
- **`--maps`: which chunk map file data is read through.** A balance gives every chunk a new
  address and removes the old chunks, so the current chunk map cannot place what a state from
  before the balance points at. The chunk-tree blocks that could are usually still on the disk,
  and the catalog keeps one map per chunk-tree root it finds (`chunk_maps`). With `own`, the
  default, a root whose chunk root is the current one is read through the current map alone. Any
  other root is read through the map of its own time; an extent that map does not place is
  tried against the newer maps, oldest first, and last against the map assembled from
  DEV_EXTENT items. One map places an extent as a whole, the read record names it, and
  `artifacts.chunk_maps` lists the maps a file came through. Nothing is merged and the current
  map is never overridden. The file's problems say when an extent did not go through the
  root's own map, when a newer map gives the same address to a different chunk, and when a newer
  map has allocated the disk space again, so that the bytes may have been overwritten. `complete`
  still means that every byte was read: whether bytes from a freed chunk are the file's is for a
  data checksum to say (plan.md M6). With `current`, only the current map is used, and such an
  extent fails as `unmapped`.
- **`--orphans`: recovery without an anchor.** After the roots, every valid file-tree leaf that
  **no scanned root tree leads to** is read on its own (`source_kind` `orphan_node`): no
  ROOT_ITEM in any root-tree leaf the scan found, of any generation, names a tree that reaches
  it. Such leaves are versions written out in the middle of a transaction and replaced before
  its commit, or leaves whose root tree is gone. Leaves of **dropped log trees** count too: what
  `fsync` wrote between two commits, which no root tree ever named (the log the superblock still
  names is left alone; replaying it is plan.md M5). They go to `orphan_nodes/tree_log/`. One leaf at a time, never joined with another: a file whose
  items may continue in the next leaf is `partial` with the reason `continues_elsewhere`. Files
  go to `DIR/orphan_nodes/tree_ID/leaf_BYTENR_genG/`. With deduplication on, an orphan copy of
  something a root also gives is a `duplicate`, so after `--root all --orphans` the `complete`
  `orphan_node` files are exactly the versions no cataloged root can give. An inode a tree lists
  under the kernel's ORPHAN_ITEM (unlinked while open, not yet cleaned up) is labelled
  `orphan_item` with or without `--orphans`: its content is intact and it has no name, so the
  database is searched for the name it had (same inode number *and* creation generation), and it
  is written as `.btrfska-orphan-items/INODE_NAME`.
- **`--graph`: the orphan graph.** `--orphans` joins nothing, because a wrong join makes a file
  that never existed. `--graph` reads the same blocks and makes the joins that can be justified,
  writes the justification into every artifact it touches (`source_kind` `orphan_graph`, column
  `joined`), and refuses the rest. *Fragments* first: a file-tree internal node that no scanned key
  pointer, no ROOT_ITEM and no superblock slot names is walked like a tree, each child reached
  through its parent's pointer (`fragment:BYTENR@GEN`, output under
  `DIR/orphan_graph/tree_ID/fragment_BYTENR_genG/`). Most orphan leaves hang under one. A fragment
  is a tree version that was written within a transaction and replaced before the commit, or one
  whose root tree is lost; its blocks were written at different moments, and it was never a
  committed state. Then the leaves under no fragment, as with `--orphans`, plus two joins: a file
  cut by the end of its leaf is continued in another leaf of the same tree when the extents of
  both cover the file exactly, none is newer than the INODE_ITEM and the other leaf was not
  written before the INODE_ITEM's last change; and a parent directory the leaf does not hold is
  named from other leaves of the tree when its number has exactly one name there. Two candidates
  that differ mean no join, and the artifact's problems say so.
- **A file is not `complete` when one of its extents is newer than its INODE_ITEM** (`missing`
  reason `inode_item_older_than_extent`). A commit always updates the inode item, so no committed
  tree holds such a file; a leaf written in the middle of a transaction can, and then the data is
  already the new one while the size is still the old one. In blocks that were never committed
  the same is concluded when an extent reaches past the sector of the end of the file.
- **One extent at a time.** An extent is mapped in full first, then read and written in pieces
  of at most 1 MiB; memory does not grow with file size. Inline, regular and prealloc extents,
  holes (left sparse in the output), zlib, zstd and LZO are handled as in `cat`.
- **Output.** `DIR` must not exist. Files go to `DIR/SOURCE/tree_ID/PATH` (`backup:36` becomes
  `backup_36`). Everything is created with `O_CREAT | O_EXCL | O_NOFOLLOW` relative to a
  directory descriptor: nothing existing is ever opened for writing, no symlink is followed, so
  no path leaves `DIR` and no image can be written. Names come from an untrusted image: `/`, NUL,
  `.`, `..` and over-long names are replaced and the change is reported; an inode whose parents
  do not lead to the root directory goes under `.btrfska-unattached/`. Permission bits (never
  setuid, setgid or sticky) and atime/mtime are applied. Ownership and extended attributes are
  recorded, not applied. Symlinks, devices, FIFOs and sockets are recorded, never created.
- **Status of each file:** `complete` (every byte read; SHA-256 recorded); `partial` (written as
  `NAME.partial`, with a hole for every range that could not be read, each listed with its
  reason); `refused_encrypted` (an extent is encrypted: nothing is written, and stderr gets
  `btrfska recover: refused: inode N of ROOT: encrypted extent …`); `duplicate` (with several
  roots, a file that is unchanged since a root already written is not read again; `--no-dedup`
  writes every copy); `recorded` (a symlink or special file); `failed` (the output file could
  not be created or named).
- **Records.** Every inode gets a row in `artifacts`, one row in `provenance` per item it was
  built from (the INODE_ITEM, every INODE_REF and INODE_EXTREF name, every XATTR_ITEM, every
  EXTENT_DATA with the physical ranges that were read), and the run a row in `recovery_runs`
  ([`docs/evidence-db.md`](docs/evidence-db.md)). The database accepts these rows and no other
  change. `DIR/manifest.jsonl` has one JSON object per inode, so the directory explains itself
  without the database. Its keys: `artifact_id`, `recovery_id`, `source_kind`, `source`,
  `state_id`, `tree_id`, `root_bytenr`, `root_generation`, `objectid`, `inode_generation`,
  `inode_transid`, `kind`, `path`, `attached`, `names`, `size`, `mode`, `xattrs`,
  `symlink_target`, `status`, `bytes_written`, `sha256`, `extent_signature`, `duplicate_of`,
  `output_path`, `chunk_maps`, `joined`, `missing`, `problems`, and `inode` (the
  whole parsed INODE_ITEM: owner, link count, flags, the four timestamps).
- Exit status 0 when every file is complete; 1 when any is `partial`, `refused_encrypted` or
  `failed`, or on an error (unknown root, wrong image, `DIR` exists); 2 for a refused format.

```sh
uv run btrfska catalog build sandbox.img --db images/scratch/sandbox.db --full-sweep
uv run btrfska recover sandbox.img --db images/scratch/sandbox.db --out images/scratch/recovered \
    --root backup:13 --root backup:11      # two files deleted before the last commit
```

## Tests and lint

```sh
uv run ruff check . && uv run ruff format --check .   # lint (legacy/ excluded)
uv run pytest                                          # new tests + legacy tests (collected as unittest cases)
uv run pytest -m sandbox                               # sandbox-only subset
uv run python -m unittest discover -s legacy/tests     # legacy suite, original runner
uvx --from . btrfska --version
```

CI (`.github/workflows/ci.yml`) has two jobs. `test` runs the same lint and
tests, plus a `sh -n` syntax check of the shell scripts; it restores
`sandbox.img` from the tracked `tests/fixtures/sandbox.img.zst` and checks it
against `tests/fixtures/SHA256SUMS`. `corpus` runs `./setup.sh` on a clean
runner with KVM: it builds every image of `corpus/manifest.tsv` and runs the
whole suite, the `vm` tests included.

CI costs nothing: GitHub Actions is free for public repositories on the
standard hosted runners both jobs use. A pull request takes about four runner
minutes in total. The workflow still keeps usage small: it does not run for
changes under `docs/` only, a newer push to a pull request cancels the run it
supersedes (a run on `main` is never cancelled), and
the jobs stop after 10 and 15 minutes (GitHub's default limit is six hours).

### Test policy

- `sandbox.img` at the repo root is the primary regression image (sha256
  `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`). It is
  read-only and never mutated. `btrfska` opens images only through
  `src/btrfska/substrate/image.py` (`O_RDONLY`, read-only mmap), and the test
  session asserts the image's sha256 before and after every run.
- Markers: `sandbox` (needs `sandbox.img`, skipped when absent) and `vm`
  (needs the images of `corpus/manifest.tsv`, skipped when absent; build them
  with `uv run python corpus/build.py`, run them with `uv run pytest -m vm`).
- `corpus/manifest.tsv` is a recipe: one row per image with the command that
  builds it, the mkfs version and the guest kernel. It holds no image hash,
  because every mkfs draws a new filesystem UUID and two builds never have the
  same bytes. `corpus/build.py` records the hashes of what was built locally
  in `images/scenarios/SHA256SUMS`, and the `vm` tests fail when an image no
  longer matches that record, so a corpus image is never modified in place.
- Full policy: `plan.md` §6.1.

### Image rule

All images, mount points, VM tooling, tool builds and scratch outputs live
under the gitignored `images/` folder (`images/scenarios/`, `images/vm/`,
`images/tools/`, `images/scratch/`, `images/mnt/`). Nothing is created
outside the repo.

One image by hand (the corpus build does this for every manifest row):

```sh
corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh && corpus/vm/make_image.sh smoke_s01
```

## Legacy prototype

The prototype CLI and its tests live under `legacy/` as a reference until the
new pipeline reaches parity (`plan.md` §4.3). Run both at once:

```sh
uv run --python 3.14 python legacy/main.py sandbox.img -o images/scratch/legacy-out
uv run --python 3.14 python -m unittest discover -s legacy/tests -v
```

## Documentation

- [`CONTRIBUTING.md`](CONTRIBUTING.md): the rules for working on this
  repository (branch and pull-request workflow, definition of done,
  reproducibility, evidence and numbers, cost). Read it first.
- [`plan.md`](docs/plan.md): build plan (architecture, stack, migration,
  milestones, test policy, experiment protocol).
- [`research.md`](docs/research.md): verified prior-art and gap analysis.
- [`catalog.md`](docs/catalog.md): chronological development record.
- [`paper-draft.md`](docs/paper-draft.md): research paper draft starter at checkpoint M2 (what the
  evidence supports now, evaluation tables, claim-to-evidence traceability, gaps to submission).
- [`docs/evidence-db.md`](docs/evidence-db.md): the evidence database schema, every table and
  column, with example queries.
- [`docs/papers/`](docs/papers/README.md): the paper library, with an index of
  every PDF (citation, DOI, BibTeX key).
- [`experiments/`](experiments/): one `EXP-NNN.md` record and regeneration
  script per measured result (`plan.md` §7).
- [`corpus/vm/README.md`](corpus/vm/README.md): rootless QEMU scenario images.
