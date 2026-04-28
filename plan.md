# Brute-Force Stage — Implementation Plan

Covers all gap items from `gap.md` that belong to the current brute-force scanner.
Items are ordered by phase (correctness → new evidence → enrichment → completeness).

---

## Files touched

| File | Changes |
|---|---|
| `utils/constants.py` | Add `BTRFS_EXTENT_TREE_OBJECTID`, `BTRFS_EXTENT_DATA_REF_KEY`, `KEY_PTR_SIZE` (already there), `BTRFS_ROOT_ITEM_KEY` (already there) |
| `utils/crc32c.py` | **[NEW]** Pure-Python CRC32c table + `crc32c(data)` function |
| `utils/btree.py` | Most of the changes live here |
| `utils/recovery_report.py` | New counters + new report fields |
| `utils/superblock.py` | Boot sector extraction call |
| `main.py` | Wire boot sector + defrag/snapshot reporting |

---

## Phase A — Correctness & Confidence

### A1 · CRC32c node checksum validation (B1)

**Source:** Bhat & Wani 2018 · **Effort:** Low · **Impact:** High

**What:** Every Btrfs node header starts with a 32-byte CRC32c checksum at `header[0x00:0x20]`.
The checksum covers **bytes 32 onward** (i.e., the full node starting after the checksum field).
False-positive FSID matches (another filesystem with the same UUID bytes in a data block) will fail this check.

**New file:** `utils/crc32c.py`
```python
# Pure-Python CRC32c (Castagnoli) — no dependencies
# Precompute table once at import time.
_TABLE = [...]   # 256-entry table built from polynomial 0x82F63B78

def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc = (crc >> 8) ^ _TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFFFFFF
```

**Changes to `utils/btree.py` — `sweep_for_orphans`:**

After the FSID match check, before accepting the node, add:
```python
# Read the full node to validate checksum
f.seek(current_offset)
node_bytes = f.read(nodesize)
computed = crc32c(node_bytes[32:])          # covers byte 32 → end
stored   = struct.unpack_from("<I", node_bytes, 0)[0]   # first 4 bytes of the 32-byte field
if computed != stored:
    report.checksum_failures += 1
    current_offset += nodesize
    continue
```

> [!NOTE]
> Btrfs stores a truncated CRC32c — only the lower 4 bytes of the 32-byte checksum field are the actual CRC, the rest is zeroed. The check is against `node_bytes[0:4]`, not the full 32 bytes.

**Changes to `utils/recovery_report.py`:**
- Add counter: `self.checksum_failures = 0`
- Print and save in summary/JSON

---

## Phase B — New Evidence Sources

### B1 · Leaf slack extraction (W1)

**Source:** Wani 2020 · **Effort:** Low · **Impact:** High

**What:** In every leaf node, the region between the end of the item-pointer array and the start of the first item-data byte is **free/slack space**. This gap can contain bytes left over from previously deleted items that were compacted out.

**Layout reminder:**
```
[NODE_HEADER (101 bytes)]
[item_ptr_0 ... item_ptr_{nritems-1}]  ← grows →
... SLACK REGION ...
← grows  [item_data_{nritems-1} ... item_data_0]
```

**Where:** Add `_extract_leaf_slack()` call at the end of `parse_node_items` (after valid items and orphan items are done).

**New function in `utils/btree.py`:**
```python
def _extract_leaf_slack(f, node_offset, nodesize, nritems, node_gen, report):
    """
    Extract and save the slack space between the item-pointer array and
    the first item-data byte in a leaf node.
    """
    if nritems == 0:
        return

    item_ptr_end = node_offset + NODE_HEADER_SIZE + (nritems * ITEM_POINTER_SIZE)

    # Find the earliest (smallest) data_offset among all valid items
    # — this is the start of the item-data region
    min_data_offset = nodesize  # worst case: no data
    for i in range(nritems):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(ITEM_POINTER_SIZE)
        if len(ptr_raw) < ITEM_POINTER_SIZE:
            break
        _, data_offset, data_size = struct.unpack("<17sII", ptr_raw)
        if data_size > 0:
            min_data_offset = min(min_data_offset, data_offset)

    # Absolute position of the first item-data byte
    first_data_byte = node_offset + NODE_HEADER_SIZE + min_data_offset

    slack_size = first_data_byte - item_ptr_end
    if slack_size <= 0:
        return

    f.seek(item_ptr_end)
    slack_bytes = f.read(slack_size)

    # Only save if non-zero (all-zero slack has no forensic value)
    if all(b == 0 for b in slack_bytes):
        return

    out_path = os.path.join(OUTPUT_DIR,
                            f"leaf_slack_0x{node_offset:X}_gen{node_gen}.bin")
    if not os.path.exists(out_path):
        with open(out_path, "wb") as out:
            out.write(slack_bytes)
        report.leaf_slacks_found += 1
        print(f"        [SLACK] Leaf slack {slack_size} bytes → {out_path}")
```

**Changes to `utils/recovery_report.py`:**
- Add `self.leaf_slacks_found = 0`
- Print/save in summary

---

### B2 · Boot sector extraction (W3)

**Source:** Wani 2020 · **Effort:** Trivial · **Impact:** Medium

**What:** The first 64 KiB of the partition (`0x0000`–`0xFFFF`) is reserved by Btrfs and never written to. It may contain data from a prior filesystem.

**Changes to `utils/superblock.py` — `parse_superblock`:**

At the very start of parsing, before seeking to the superblock:
```python
# ── Boot sector (pre-filesystem region) ──
with open(image_path, "rb") as f_boot:
    boot_bytes = f_boot.read(SUPERBLOCK_OFFSET)   # 0x10000 = 65536 bytes

if any(b != 0 for b in boot_bytes):
    boot_path = os.path.join(output_dir, "boot_sector.bin")
    with open(boot_path, "wb") as bf:
        bf.write(boot_bytes)
    print(f"[+] Boot sector non-zero — saved to {boot_path}")
else:
    print("[*] Boot sector is all zeros (no pre-filesystem data)")
```

> [!NOTE]
> `parse_superblock` currently doesn't take `output_dir`. Pass it as an argument, or handle this in `main.py` `run_recovery_engine` before calling `parse_superblock`.
> The cleaner approach: do it in `run_recovery_engine` in `main.py` directly since `output_dir` is already available there.

---

### B3 · Orphaned extent-tree node scanning for `EXTENT_DATA_REF` (R1)

**Source:** Rodeh 2013 · **Effort:** Medium · **Impact:** High

**What:** When a file is deleted, its `EXTENT_DATA_REF` back-pointer in the extent tree is removed. But the **extent tree leaf node** that held that back-pointer is CoW'd, leaving an orphaned node with `owner = 2` (`BTRFS_EXTENT_TREE_OBJECTID`). These orphaned nodes contain `EXTENT_DATA_REF` items (type `0xB2`) with fields:

```
root     (8 bytes) — subvolume tree ID that owned the file
objectid (8 bytes) — inode number
offset   (8 bytes) — byte offset in the file
count    (4 bytes) — reference count
```

The `EXTENT_ITEM_KEY` (type `0xA8`) in the same node records the extent's **logical address** as the key offset.

**Changes to `utils/btree.py` — `sweep_for_orphans`:**

In the main sweep loop, add a branch for orphaned extent-tree nodes:
```python
if node_gen < sb_gen:
    ...
    if node_owner == BTRFS_EXTENT_TREE_OBJECTID and level == 0:
        _parse_extent_tree_leaf(f, current_offset, nodesize,
                                node_gen, chunk_map, report)
    else:
        parse_node_items(...)
```

**New function `_parse_extent_tree_leaf` in `utils/btree.py`:**
```python
def _parse_extent_tree_leaf(f, node_offset, nodesize, node_gen, chunk_map, report):
    """
    Parse an orphaned extent-tree leaf node for EXTENT_DATA_REF items.
    These record (root, inode, file_offset) for extents that were
    referenced by deleted files.
    """
    f.seek(node_offset)
    header = f.read(NODE_HEADER_SIZE)
    nritems = struct.unpack_from("<I", header, NH_NRITEMS)[0]
    max_possible = (nodesize - NODE_HEADER_SIZE) // ITEM_POINTER_SIZE
    if nritems > max_possible:
        return

    current_extent_laddr = None  # logical address from the preceding EXTENT_ITEM key

    for i in range(nritems):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * ITEM_POINTER_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(ITEM_POINTER_SIZE)
        if len(ptr_raw) < ITEM_POINTER_SIZE:
            break
        key_raw, data_offset, data_size = struct.unpack("<17sII", ptr_raw)
        item_type  = key_raw[8]
        key_objid  = struct.unpack_from("<Q", key_raw, 0)[0]
        key_offset = struct.unpack_from("<Q", key_raw, 9)[0]

        abs_data = node_offset + NODE_HEADER_SIZE + data_offset

        if item_type == BTRFS_EXTENT_ITEM_KEY:
            # The key offset IS the logical address of this extent
            current_extent_laddr = key_offset

        elif item_type == BTRFS_EXTENT_DATA_REF_KEY and data_size >= 28:
            f.seek(abs_data)
            ref_data = f.read(28)
            if len(ref_data) < 28:
                continue
            ref_root     = struct.unpack_from("<Q", ref_data, 0)[0]
            ref_inode    = struct.unpack_from("<Q", ref_data, 8)[0]
            ref_offset   = struct.unpack_from("<Q", ref_data, 16)[0]
            ref_count    = struct.unpack_from("<I", ref_data, 24)[0]

            print(f"        [BACKREF] Extent 0x{current_extent_laddr or 0:X} "
                  f"→ root={ref_root} inode={ref_inode} offset={ref_offset} "
                  f"count={ref_count}")

            report.add_extent_backref({
                "extent_laddr":  current_extent_laddr,
                "root":          ref_root,
                "inode":         ref_inode,
                "file_offset":   ref_offset,
                "ref_count":     ref_count,
                "node_gen":      node_gen,
            })
```

**Changes to `utils/constants.py`:**
- Ensure `BTRFS_EXTENT_TREE_OBJECTID = 2` is present (it is)
- Ensure `BTRFS_EXTENT_DATA_REF_KEY = 0xB2` is present (it is, as `178`)
- Ensure `BTRFS_EXTENT_ITEM_KEY = 0xA8` is present (it is)

**Changes to `utils/recovery_report.py`:**
```python
self.extent_backrefs = []           # list of dicts
self.extent_backrefs_found = 0

def add_extent_backref(self, entry):
    self.extent_backrefs.append(entry)
    self.extent_backrefs_found += 1
```
- Include `extent_backrefs` in the JSON report
- Print `Extent Backrefs Found: N` in summary

---

### B4 · Internal node key-ptr Orphan-Item scanning (B2)

**Source:** Bhat & Wani 2018 · **Effort:** Medium · **Impact:** High

**What:** In orphaned internal nodes, read key-pointer pairs **beyond `nritems`**. Each extra key-ptr contains a `child_block_number` (logical address) of a child that was part of this node before the CoW — that child may itself be an orphaned leaf. These are logged as candidate orphan pointers (our linear sweep already covers the whole disk, but recording the relationship adds forensic context).

**Changes to `utils/btree.py` — `parse_node_items`:**

Replace the current `if level != 0: return` with:
```python
if level != 0:
    # Internal node — scan key-pointer slots beyond nritems for orphaned children
    if scan_orphan_items:
        _scan_internal_node_orphan_ptrs(f, node_offset, nodesize, nritems,
                                        node_gen, report)
    return
```

**New function `_scan_internal_node_orphan_ptrs`:**
```python
def _scan_internal_node_orphan_ptrs(f, node_offset, nodesize, nritems, node_gen, report):
    """
    In an orphaned internal node, read key-pointer pairs beyond nritems.
    Each such pair may point to an orphaned child leaf.
    Record the child logical addresses in the report.
    """
    max_possible_ptrs = (nodesize - NODE_HEADER_SIZE) // KEY_PTR_SIZE
    orphan_ptr_count = 0

    for i in range(nritems, max_possible_ptrs):
        ptr_off = node_offset + NODE_HEADER_SIZE + (i * KEY_PTR_SIZE)
        f.seek(ptr_off)
        ptr_raw = f.read(KEY_PTR_SIZE)
        if len(ptr_raw) < KEY_PTR_SIZE:
            break

        # btrfs_key_ptr: disk_key(17) + block_number(8) + generation(8)
        child_logical = struct.unpack_from("<Q", ptr_raw, 17)[0]
        child_gen     = struct.unpack_from("<Q", ptr_raw, 25)[0]

        # Sanity: child_logical should look like a plausible address (non-zero, aligned)
        if child_logical == 0 or child_logical % 4096 != 0:
            break  # hit padding/garbage, stop

        orphan_ptr_count += 1
        report.add_orphan_child_ptr({
            "parent_offset": node_offset,
            "parent_gen":    node_gen,
            "child_logical": child_logical,
            "child_gen":     child_gen,
            "slot":          i,
        })

    if orphan_ptr_count > 0:
        report.internal_orphan_ptrs_found += orphan_ptr_count
        print(f"        [INT-ORPHAN] {orphan_ptr_count} orphaned child pointers "
              f"in internal node @ 0x{node_offset:X}")
```

**Changes to `utils/recovery_report.py`:**
```python
self.internal_orphan_ptrs_found = 0
self.orphan_child_ptrs = []

def add_orphan_child_ptr(self, entry):
    self.orphan_child_ptrs.append(entry)
```

---

## Phase C — Metadata Enrichment

### C1 · Move/rename artifact tagging (B4)

**Source:** Bhat & Wani 2018 · **Effort:** Low · **Impact:** Medium

**What:** When we recover a `DIR_ITEM`/`DIR_INDEX` from an orphaned node, if the target inode already exists in `inode_map` under a **different name**, the orphaned entry is the pre-move path.

**Changes to `utils/btree.py` — `_parse_dir_entry`:**

After updating `inode_map`, add:
```python
existing = inode_map.get(target_inode)
if existing and existing != filename:
    print(f"        [MOVE] Inode {target_inode}: "
          f"'{filename}' → '{existing}' (file was moved/renamed)")
    report.add_move_artifact({
        "inode":         target_inode,
        "original_path": filename,
        "current_path":  existing,
    })
```

**Changes to `utils/recovery_report.py`:**
```python
self.move_artifacts = []
self.move_artifacts_found = 0

def add_move_artifact(self, entry):
    self.move_artifacts.append(entry)
    self.move_artifacts_found += 1
```

---

### C2 · File slack reporting (W2)

**Source:** Wani 2020 · **Effort:** Low · **Impact:** Medium

**What:** For regular extents, `disk_num_bytes - (offset + num_bytes)` bytes of slack follow the actual file data inside the allocated block. Record in the report entry.

**Changes to `utils/btree.py` — `_handle_regular_extent`:**

After computing `num_bytes`, add:
```python
file_slack = disk_num_bytes - (offset + num_bytes)
if file_slack > 0:
    print(f"            → File Slack:    {file_slack} bytes (unextracted)")
```

Add `"file_slack": file_slack` to the `report.add_recovered_file(...)` dict.

---

### C3 · Defragmentation hazard detection (R2)

**Source:** Rodeh 2013 · **Effort:** Low · **Impact:** Medium

**What:** After the sweep, compute a heuristic defrag indicator. If very few orphaned nodes were found relative to total FS nodes scanned, and disk utilization is high, defrag has likely run.

**Changes to `utils/btree.py` — `sweep_for_orphans`:** After the sweep loop:
```python
# ── Defrag hazard heuristic ──
if report.nodes_scanned > 0:
    orphan_ratio = report.orphan_nodes_found / report.nodes_scanned
    bytes_used_pct = sb_data["bytes_used"] / sb_data["total_bytes"]
    if orphan_ratio < 0.01 and bytes_used_pct > 0.5:
        print("\n[!] DEFRAG WARNING: Very low orphaned-node ratio "
              f"({orphan_ratio:.1%}) with {bytes_used_pct:.0%} disk usage.")
        print("    Online defragmentation may have run, reducing recoverable data.")
        report.defrag_warning = True
```

**Changes to `utils/recovery_report.py`:**
```python
self.defrag_warning = False
```
Print "⚠ Defrag Warning: YES" in summary if set.

---

### C4 · Snapshot presence indicator (R3)

**Source:** Rodeh 2013 · **Effort:** Low · **Impact:** Low

**What:** Subvolume/snapshot tree IDs are ≥ 256. During the sweep, count nodes with `owner >= 256` — non-zero count means the filesystem has used subvolumes/snapshots.

**Changes to `utils/btree.py` — `sweep_for_orphans`:** Inside the `if node_fsid == fsid:` branch:
```python
if node_owner >= 256:
    report.subvolume_nodes_seen += 1
```

After sweep:
```python
if report.subvolume_nodes_seen > 0:
    print(f"[*] Subvolume/snapshot nodes detected ({report.subvolume_nodes_seen} nodes). "
          "Recovery probability is elevated on snapshot-heavy filesystems.")
    report.has_snapshots = True
```

**Changes to `utils/recovery_report.py`:**
```python
self.subvolume_nodes_seen = 0
self.has_snapshots = False
```

---

## Phase D — Low-Priority Completeness

### D1 · Internal node slack mining (B3)

**Source:** Bhat & Wani 2018, Wani 2020 · **Effort:** Medium

**What:** For orphaned internal nodes, the region from `NODE_HEADER_SIZE + (nritems × KEY_PTR_SIZE)` to end of node may contain residual leaf item data. Scan this raw region for valid `btrfs_item`-sized chunks by looking for recognizable item types and sane offsets.

Add a call to `_mine_internal_node_slack(f, node_offset, nodesize, nritems, node_gen, report)` at the end of `_scan_internal_node_orphan_ptrs`.

The function reads the slack region, then slides a 25-byte window through it, treating each window as a potential `btrfs_item`. Accept it if `item_type` is known, `data_size` is non-zero and fits within some reasonable bound, and `data_offset + data_size < nodesize`.

---

### D2 · Volume slack extraction (W4)

**Source:** Wani 2020 · **Effort:** Trivial

**In `main.py` — `run_recovery_engine`:**
```python
aligned_end = (file_size // sb_data["nodesize"]) * sb_data["nodesize"]
if aligned_end < file_size:
    with open(image_file, "rb") as f:
        f.seek(aligned_end)
        vol_slack = f.read(file_size - aligned_end)
    if any(b != 0 for b in vol_slack):
        vs_path = os.path.join(output_dir, "volume_slack.bin")
        with open(vs_path, "wb") as vf:
            vf.write(vol_slack)
        print(f"[+] Volume slack {len(vol_slack)} bytes → {vs_path}")
```

---

### D3 · `btrfs_root_item` reserved field inspection (W5)

**Source:** Wani 2020 · **Effort:** Low

During item parsing in `_parse_single_item`, add a handler for `BTRFS_ROOT_ITEM_KEY (0x84)`. Read the 439-byte `btrfs_root_item` structure and check bytes in the known reserved/padding regions for non-zero values. Log in report if found.

---

### D4 · Device tree parsing (H1)

**Source:** Hilgert 2018 · **Effort:** Low

In `sweep_for_orphans`, when `node_owner == BTRFS_DEV_TREE_OBJECTID (4)`, parse `DEV_ITEM` entries (type `0xD8`) to extract device UUID, total device size, and physical layout. Add device info dict to report.

---

## Summary: New counters added to `RecoveryReport`

| Counter/Field | Phase |
|---|---|
| `checksum_failures` | A1 |
| `leaf_slacks_found` | B1 |
| `extent_backrefs`, `extent_backrefs_found` | B3 |
| `internal_orphan_ptrs_found`, `orphan_child_ptrs` | B4 |
| `move_artifacts`, `move_artifacts_found` | C1 |
| `defrag_warning` | C3 |
| `subvolume_nodes_seen`, `has_snapshots` | C4 |

## Open Questions

> [!IMPORTANT]
> **CRC32c implementation choice**: Use pure-Python table (no deps, ~20 lines) vs adding `crcmod` to `pyproject.toml`. Pure Python is ~100× slower but this tool is already I/O-bound so it doesn't matter. Recommend pure Python to keep zero dependencies.

> [!IMPORTANT]
> **Orphaned extent-tree node scanning**: Should `_parse_extent_tree_leaf` run in addition to `parse_node_items`, or instead of it? Extent-tree nodes don't have `INODE_ITEM`/`DIR_ITEM`/`EXTENT_DATA` items, so running `parse_node_items` on them wastes time. Recommend: branch on `node_owner` and call the right parser.

> [!IMPORTANT]
> **Leaf slack — which nodes?** Extract slack only from orphaned nodes (gen < sb_gen) or also from current-gen nodes? Current-gen slack might reflect currently-deleted items from the active session. Recommend: extract from both, label `source` accordingly.
