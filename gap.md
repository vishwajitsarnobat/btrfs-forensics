# Btrfs Forensics — Gap Analysis

> **Scope**: This document covers only the **brute-force scan stage** (the current implementation).
> Future stages (superblock backup roots, root tree walk, generation diff engine, extent backref analysis)
> are tracked separately in `optimized_recovery_research.md`.

---

## Why are internal nodes (level > 0) currently skipped?

A Btrfs internal node stores only **key-pointer pairs** (`btrfs_key_ptr`, 33 bytes each):

```
[ btrfs_disk_key (17 bytes) | child_block_number (8 bytes) | generation (8 bytes) ]
```

File data (`INODE_ITEM`, `DIR_ITEM`, `EXTENT_DATA`, etc.) only lives in **leaf nodes** (level = 0).
Skipping internal nodes for item extraction is therefore *correct*.

However, Bhat & Wani (2018) document an important exception:

> *"Internal nodes can provide significant forensic clues if they were previously allocated as
> leaf nodes. Since a major portion of the space within internal nodes remain unused, some
> remnants of previously allocated leaf node (now allocated as internal node) remain unaltered
> and hence can be retrieved."*

When a block is promoted from leaf → internal, the key-pointer array only fills the **front**
of the `nodesize` block (33 bytes × nritems). The unused tail of the block is never zeroed —
if it was previously a leaf, its item data area can still be physically intact.

The paper's 6-stage procedure explicitly includes:
1. Following key-pointer pairs **beyond `nritems`** in orphaned internal nodes (these point to
   child nodes that are themselves orphaned subtrees).
2. Scanning the **slack region** of internal nodes for residual leaf item structures.

The current implementation returns immediately for `level > 0` — both of these are unimplemented.

---

## Gap Table: Brute-Force Stage

Items are grouped by source paper.

### From Bhat & Wani (2018) — *Forensic analysis of B-tree file system (Btrfs)*

| # | Gap | Priority | Effort | Notes |
|---|---|:---:|:---:|---|
| B1 | **CRC32c node checksum validation** | 🔴 High | Low | Castagnoli CRC32c; 32-byte checksum at `header[0x00:0x20]`. Eliminates false-positive FSID matches. Python `crcmod` or manual implementation. |
| B2 | **Internal node key-ptr Orphan-Item scanning** | 🔴 High | Medium | Read key-pointer slots beyond `nritems` in orphaned internal nodes; follow child pointers for recursive orphan subtree discovery. |
| B3 | **Internal node slack mining** | 🟡 Medium | Medium | Treat bytes from `NODE_HEADER_SIZE + (nritems × 33)` to end of node as a raw region; scan for valid item structures using heuristics (known types, sane offsets, entropy). |
| B4 | **Move/rename artifact tagging** | 🟡 Medium | Low | When a `DIR_ITEM`/`DIR_INDEX` is recovered from an orphaned node, check if the same inode appears in `inode_map` at a different path → flag as a "moved file" artifact with original path recorded. |
| B5 | **`otime` documented as creation time** | 🟢 Low | Trivial | README currently says "reserved for future use". Fix to say "birth/creation time — unique to Btrfs, not available on most Linux filesystems." Code in `inode_parser.py` is already correct. |

### From Wani et al. (2020) — *Anti-forensic capabilities of Btrfs*

| # | Gap | Priority | Effort | Notes |
|---|---|:---:|:---:|---|
| W1 | **Leaf slack extraction** | 🔴 High | Low | The free space between the last item pointer and the first item-data byte in every leaf node. Calculate as `data_end - item_ptr_end` where `data_end = NODE_HEADER_SIZE + min(data_offset)` across all items, `item_ptr_end = NODE_HEADER_SIZE + nritems × 25`. Dump raw bytes to `leaf_slack_<offset>.bin`. |
| W2 | **File slack reporting** | 🟡 Medium | Low | For regular extents: `file_slack = disk_num_bytes - (offset + num_bytes)`. Report size in JSON and optionally extract the slack bytes. Requires knowing `sectorsize` to align. |
| W3 | **Boot sector extraction** | 🟡 Medium | Trivial | Read bytes `0x0000`–`0xFFFF` (first 64 KiB) before the superblock. These are never written by Btrfs but may contain data from a previous filesystem. Dump to `boot_sector.bin`. |
| W4 | **Volume slack extraction** | 🟢 Low | Trivial | `volume_slack_start = floor(image_size / nodesize) * nodesize`. Read remaining bytes and dump to `volume_slack.bin`. |
| W5 | **`btrfs_root_item` reserved field inspection** | 🟢 Low | Low | Parse `ROOT_ITEM` entries from scanned nodes; check padding/reserved bytes for non-zero values and flag in report. |

### From Rodeh, Bacik & Mason (2013) — *BTRFS: The Linux B-Tree Filesystem*

| # | Gap | Priority | Effort | Notes |
|---|---|:---:|:---:|---|
| R1 | **Orphaned extent-tree node scanning** | 🔴 High | Medium | Orphaned nodes with `owner = BTRFS_EXTENT_TREE_OBJECTID (2)` may contain `EXTENT_DATA_REF` items (type `0xB2`) that record `(root, objectid, offset, count)` for deleted file extents. This gives a second recovery path when the FS tree node is gone. Parse these items and add to extent reference table. |
| R2 | **Defragmentation hazard detection** | 🟡 Medium | Low | During sweep, if the ratio of orphaned FS-tree nodes is very low relative to total metadata blocks, and `bytes_used` is high, warn the investigator that defragmentation may have run and reduced recoverable data. Also check if any scanned extent addresses are suspiciously sequential (defrag fingerprint). |
| R3 | **Snapshot presence indicator** | 🟢 Low | Low | During sweep, count nodes with `owner >= 256` (subvolume IDs above the built-in trees). Non-zero count indicates snapshots or subvolumes exist; log in report as "snapshot-heavy filesystem → elevated recovery probability." |

### From Hilgert et al. (2018) — *Forensic analysis of multiple device BTRFS using TSK*

| # | Gap | Priority | Effort | Notes |
|---|---|:---:|:---:|---|
| H1 | **Device tree parsing** | 🟢 Low | Low | Walk nodes with `owner = BTRFS_DEV_TREE_OBJECTID (4)`; extract `DEV_ITEM` entries to confirm device UUID, total device size, and physical layout. Report device info in JSON output. |

---

## Implementation Order for Brute-Force Stage Completion

```
Phase A — Correctness & Confidence (do first, no new output files)
  [A1] B1  CRC32c checksum validation
  [A2] B5  Fix otime documentation in README

Phase B — New Evidence Sources (core additions)
  [B1] W1  Leaf slack extraction
  [B2] W3  Boot sector extraction
  [B3] R1  Orphaned extent-tree node scanning (EXTENT_DATA_REF)
  [B4] B2  Internal node key-ptr Orphan-Item scanning

Phase C — Metadata Enrichment (report quality)
  [C1] B4  Move/rename artifact tagging
  [C2] W2  File slack reporting
  [C3] R2  Defragmentation hazard detection
  [C4] R3  Snapshot presence indicator

Phase D — Low-value completeness
  [D1] B3  Internal node slack mining (heuristic)
  [D2] W4  Volume slack extraction
  [D3] W5  btrfs_root_item reserved field inspection
  [D4] H1  Device tree parsing
```

---

## What is explicitly OUT OF SCOPE for the brute-force stage

These belong to the next stage (optimized engine) per `optimized_recovery_research.md`:

- Superblock backup roots (4× historical tree walking)
- Root tree walk → subvolume/snapshot discovery
- Generation-indexed node catalog + diff engine
- Full extent backref reverse-mapping
- Cross-generation file timeline
- Checksum tree data validation
- Multi-device / RAID stripe reconstruction
- Compression decompression (zlib / lzo / zstd)