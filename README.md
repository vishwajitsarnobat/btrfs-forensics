# btrfs-forensics

A forensic tool for recovering deleted files from raw Btrfs disk images. It operates entirely on the raw binary image — no mounted filesystem required — by scanning for orphaned Copy-on-Write (CoW) B-tree nodes left behind after file deletion.

Zero third-party dependencies. Pure Python ≥ 3.14.

---

## Background

Btrfs uses a Copy-on-Write B-tree structure to manage all filesystem metadata. Whenever metadata is modified (e.g., a file is written or deleted), Btrfs does **not** overwrite the old node in place. Instead, it allocates a new node and writes the updated version there, leaving the old node intact on disk until the space is reclaimed by the garbage collector.

When a file is deleted, the corresponding B-tree leaf nodes — containing `INODE_ITEM`, `INODE_REF`, `DIR_ITEM`, `DIR_INDEX`, and `EXTENT_DATA` items — are CoW-copied and the old copies may linger in unallocated space for an indeterminate time. This tool finds and parses those lingering copies.

Additionally, Btrfs B-tree balancing and merging operations can leave **Orphan-Items**: item-pointer-sized slots in the item array of a leaf node that are beyond the `nritems` count but still contain valid-looking metadata from before the merge. These are found in both old and current-generation nodes.

### Key References

- Bhat, A. & Wani, M.A. (2018). *Forensic analysis of B-tree file system (Btrfs)*. Digital Investigation.
- Wani, M.A. et al. (2020). *An analysis of anti-forensic capabilities of B-tree file system (Btrfs)*.
- Rodeh, O., Bacik, J. & Mason, C. (2013). *BTRFS: The Linux B-Tree Filesystem*. ACM Transactions on Storage.
- Hilgert, J.N. et al. (2018). *Forensic analysis of multiple device BTRFS configurations using The Sleuth Kit*.
- [Btrfs On-Disk Format — official documentation](https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html)

---

## Features

### Core Recovery
- **Brute-force node scanning** — linear sweep of the entire disk image, `nodesize`-aligned
- **CRC32c (Castagnoli) checksum validation** — every FSID-matching node is verified against its stored CRC32c, eliminating false positives
- **Orphan-Item scanning** — finds metadata remnants beyond `nritems` in leaf nodes from B-tree balancing
- **Inline extent extraction** — recovers file data stored directly in B-tree nodes
- **Regular extent extraction** — translates logical→physical addresses via the chunk map and reads file data from disk
- **Extent deduplication** — identical `(disk_bytenr, offset, num_bytes)` extents are extracted only once

### Evidence Sources
- **Leaf slack extraction** — saves the free space between item pointers and item data in leaf nodes, which may contain bytes from deleted items
- **Boot sector extraction** — saves the reserved first 64 KiB of the partition (may contain data from a prior filesystem)
- **Volume slack extraction** — saves bytes after the last node-aligned offset
- **Orphaned extent-tree node scanning** — parses `EXTENT_DATA_REF` items (type `0xB2`) from orphaned extent tree leaves for `(root, inode, offset)` backrefs
- **Internal node key-pointer orphan scanning** — reads key-pointer slots beyond `nritems` in internal nodes for orphaned child pointers
- **Internal node slack mining** — scans the slack region of internal nodes for residual leaf item structures

### Metadata Enrichment
- **Move/rename detection** — identifies when an inode appears under different names across generations (file was moved/renamed)
- **File slack reporting** — reports `disk_num_bytes − (offset + num_bytes)` slack bytes in regular extents
- **Defragmentation hazard detection** — warns when the orphaned-node ratio is abnormally low relative to disk usage (suggests `btrfs defrag` was run)
- **Snapshot/subvolume indicator** — detects nodes with `owner ≥ 256` indicating subvolume/snapshot usage

### Additional Parsers
- **ROOT_ITEM reserved field inspection** — flags non-zero bytes in reserved regions of `btrfs_root_item` structures
- **Device tree parsing** — extracts device UUID, total size, and usage from orphaned `DEV_ITEM` entries

### Reporting
- Human-readable summary table to stdout
- Machine-readable `recovery_report.json` with full metadata for every artifact
- Generation-aware `(inode, generation)` keying prevents filename collisions across file lifetimes

---

## How It Works

The recovery pipeline runs in four stages.

### Stage 1 — Superblock Analysis (`utils/superblock.py`, `utils/chunk_parser.py`)

The tool reads the primary superblock at offset `0x10000` (64 KiB) and validates it via the `_BHRfS_M` magic number. It extracts:

| Field | Purpose |
|---|---|
| `FSID` | Filesystem UUID — used to fingerprint nodes on disk |
| `generation` | Current transaction ID — nodes older than this are "orphaned" |
| `nodesize` | Size of every B-tree node (usually 16 KiB) |
| `root_tree_addr` | Logical address of the Root Tree root |
| `chunk_tree_addr` | Logical address of the Chunk Tree root |

**Chunk map construction** happens in two steps:

1. **Bootstrap** (`parse_chunk_map`): The `sys_chunk_array` embedded in the superblock is parsed. This contains only SYSTEM chunks — just enough to locate the chunk tree itself.
2. **Full traversal** (`parse_chunk_tree`): The chunk tree is walked recursively (internal nodes → leaf nodes), and all `CHUNK_ITEM` entries are collected. This gives the complete logical→physical mapping covering DATA and METADATA chunks too.

---

### Stage 2 — Raw Disk Sweep (`utils/btree.py` — `sweep_for_orphans`)

The tool iterates over the entire raw image in `nodesize`-aligned steps, starting just after the superblock region. For each block it reads the 101-byte **node header** and checks:

1. **FSID match**: `header[0x20:0x36]` must equal the filesystem UUID from the superblock.
2. **CRC32c validation**: The full node is read and `crc32c(node_bytes[32:])` is compared to the stored checksum in bytes `0x00:0x04`. Mismatches are counted and rejected.
3. **Generation check**:
   - `node_gen < sb_gen` → **Orphaned node** (old CoW copy). Its items are parsed with full Orphan-Item scanning enabled.
   - `node_gen == sb_gen` and `level == 0` → **Current-generation leaf**. Only Orphan-Items (slots beyond `nritems`) are scanned.

**Specialized branching**: Orphaned extent-tree nodes (`owner == 2`) and device-tree nodes (`owner == 4`) are routed to dedicated parsers instead of the generic item parser. Internal nodes (`level > 0`) have their key-pointer slots scanned for orphaned children and their slack space mined for residual item structures.

---

### Stage 3 — Node Item Parsing (`parse_node_items`, `_parse_single_item`)

For each identified leaf node, item pointers (`btrfs_item`, 25 bytes each) are read.

#### Item type handlers

| Item Type | Key byte | What is extracted |
|---|---|---|
| `INODE_ITEM` (0x01) | | Full 160-byte `btrfs_inode_item`: size, nlink, uid/gid, mode, atime/ctime/mtime/otime. |
| `INODE_REF` (0x0C) | | Filename of the inode. Multiple refs in one item are handled. |
| `DIR_ITEM` (0x54) | | Target inode number and filename. Triggers move/rename detection. |
| `DIR_INDEX` (0x60) | | Same structure as `DIR_ITEM`, parsed identically. |
| `EXTENT_DATA` (0x6C) | | Inline (type=0) → data extracted immediately. Regular (type=1) → queued for second pass. |
| `ROOT_ITEM` (0x84) | | Reserved region inspected for non-zero bytes (anomaly indicator). |

**`otime`** is the file **creation/birth time** — unique to Btrfs and not available on most Linux filesystems via traditional `stat(2)`. It records when the inode was first created and is never updated.

**Inode → filename map**: Keyed by `(inode_number, generation)` to prevent collisions when the same inode number is reused across file lifetimes.

---

### Stage 4 — Second Pass: Regular Extent Extraction (`_extract_regular_extents`)

After the full sweep, all queued regular extent references are processed:

1. `disk_bytenr` is translated from logical → physical using the chunk map.
2. **Deduplication**: extents with identical `(disk_bytenr, offset, num_bytes)` are extracted only once.
3. Data is written to `<sanitized_filename>_gen<N>_<source>_extent.bin`.

---

## Codebase Structure

```
btrfs-forensics/
├── main.py                    # Entry point & CLI
├── utils/
│   ├── constants.py           # All Btrfs on-disk format constants and offsets
│   ├── crc32c.py              # Pure-Python CRC32c (Castagnoli) implementation
│   ├── superblock.py          # Superblock parsing
│   ├── chunk_parser.py        # Chunk map bootstrap + chunk tree traversal
│   │                          # + logical→physical address translation
│   ├── btree.py               # Raw sweep, node parsing, item handlers,
│   │                          # extent extraction, slack extraction,
│   │                          # internal node scanning, move detection
│   ├── inode_parser.py        # btrfs_inode_item (160 bytes) parser
│   └── recovery_report.py     # Statistics accumulator + JSON/text report
├── tests/
│   ├── test_crc32c.py         # CRC32c unit tests (RFC 3720 vectors)
│   ├── test_inode_parser.py   # Inode parser unit tests (binary fixtures)
│   └── test_integration.py    # Full pipeline integration test
└── plan.md                    # Implementation plan and checklist
```

---

## Usage

```bash
# Basic usage (scans sandbox.img, writes to recovery_output/)
python main.py

# Specify a custom image and output directory
python main.py /path/to/disk.img -o /path/to/output/

# Skip scanning current-generation nodes for Orphan-Items
python main.py disk.img --no-current-gen
```

### CLI Options

| Argument | Default | Description |
|---|---|---|
| `image` | `sandbox.img` | Path to the raw Btrfs disk image |
| `-o` / `--output` | `recovery_output` | Output directory for recovered files and the JSON report |
| `--no-current-gen` | *(off)* | If set, skips current-generation nodes entirely (only scans orphaned nodes) |

### Output

After a run the output directory contains:
- `<filename>_gen<N>_<source>_inline.bin` — recovered inline-extent files
- `<filename>_gen<N>_<source>_extent.bin` — recovered regular-extent files
- `leaf_slack_0x<offset>_gen<N>.bin` — leaf node slack regions with non-zero content
- `boot_sector.bin` — first 64 KiB of the partition (if non-zero)
- `volume_slack.bin` — trailing bytes after the last node-aligned offset (if non-zero)
- `recovery_report.json` — machine-readable report with all stats and per-file metadata

The `source` field in filenames is either `valid` (item was within `nritems`) or `orphan` (item was beyond `nritems`, found by Orphan-Item scanning).

---

## Running Tests

```bash
python -m unittest discover -s tests -v
```

---

## Setup

Requires Python ≥ 3.14. No third-party dependencies.

```bash
# Using uv (recommended)
uv sync
uv run python main.py

# Or plain Python
python main.py
```

---

## Known Limitations

- **Compression**: Inline extents with zlib/lzo/zstd compression are saved raw (not decompressed).
- **Multi-device / RAID**: Only single-stripe, single-device images are tested.
- **Space reuse**: Overwritten blocks cannot be recovered.
