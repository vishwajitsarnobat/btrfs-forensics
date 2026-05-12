# Btrfs Forensics Plan

This file replaces `gap.md` and `optimized_recovery_research.md`.
It is the single planning document for the project and records:

- the project goal
- what has already been implemented
- what was originally missing in the brute-force stage
- what remains for the future optimized recovery engine

---

## 1. Goal

Build a forensic-safe Btrfs recovery tool that works directly on raw disk images, recovers deleted file metadata and content from orphaned CoW metadata blocks, and eventually moves beyond brute-force scanning into generation-aware historical reconstruction.

---

## 2. Current Status

| Area | Status | Notes |
|---|---|---|
| Brute-force scanner | **Implemented** | Raw node sweep, orphan item parsing, inline recovery, regular extent recovery, reporting |
| Original `gap.md` items | **Complete** | All brute-force-stage gap items are now implemented |
| Optimized structural engine | **Planned** | Backup-root walking, root-tree walking, generation diffing, full reverse mapping are still future work |
| Documentation consolidation | **Complete** | The deleted markdown files are consolidated here |
| Verification | **Passing** | `python3 -m unittest discover -s tests -v` currently passes with 27 tests |

The current codebase contains the major completed feature entry points in `utils/btree.py`, the new CRC32c implementation in `utils/crc32c.py`, expanded reporting in `utils/recovery_report.py`, and tests under `tests/`.

---

## 3. What Has Been Done

### 3.1 Completed Implementation Phases

| Phase | Status | Outcome |
|---|---|---|
| Phase 0 - bug fixes | Complete | Fixed inode/generation keying, extent deduplication, current-generation orphan scanning, JSON numeric serialization, and output-dir side effects |
| Phase A - correctness and confidence | Complete | Added CRC32c validation and corrected `otime` documentation |
| Phase B - new evidence sources | Complete | Added leaf slack extraction, boot sector extraction, orphaned extent-tree parsing, and internal-node orphan pointer scanning |
| Phase C - metadata enrichment | Complete | Added move/rename tagging, file slack reporting, defrag warning heuristic, and snapshot/subvolume indicator |
| Phase D - completeness | Complete | Added internal-node slack mining, volume slack extraction, ROOT_ITEM reserved-field inspection, and device-tree parsing |
| Phase E - tests and docs | Complete | Added CRC and inode parser unit tests, integration coverage, README rewrite, metadata cleanup, and doc consolidation |

### 3.2 Historical Brute-Force Gap Plan

The original `gap.md` was the plan for bringing the brute-force scanner up to parity with the reviewed research. That work is now complete.

#### Why internal nodes mattered

Skipping internal nodes for normal item extraction is correct because file items live in leaf nodes. The missing forensic opportunity was elsewhere:

- orphaned key-pointer slots beyond `nritems`
- internal-node slack that may still contain residual leaf data if the block used to be a leaf

Those cases are now covered by the implementation.

#### Original gap checklist and current result

| ID | Item | Source | Result |
|---|---|---|---|
| B1 | CRC32c node checksum validation | Bhat & Wani 2018 | Implemented via `utils/crc32c.py`; invalid metadata blocks are rejected and counted |
| B2 | Internal node key-pointer orphan scanning | Bhat & Wani 2018 | Implemented via `_scan_internal_node_orphan_ptrs()` |
| B3 | Internal node slack mining | Bhat & Wani 2018; Wani 2020 | Implemented via `_mine_internal_node_slack()` |
| B4 | Move/rename artifact tagging | Bhat & Wani 2018 | Implemented in directory-entry parsing and report output |
| B5 | Correct `otime` documentation | Bhat & Wani 2018 | Implemented in `README.md` |
| W1 | Leaf slack extraction | Wani 2020 | Implemented via `_extract_leaf_slack()` |
| W2 | File slack reporting | Wani 2020 | Implemented for regular extents and included in metadata/reporting |
| W3 | Boot sector extraction | Wani 2020 | Implemented for the first 64 KiB of the image |
| W4 | Volume slack extraction | Wani 2020 | Implemented for trailing non-aligned image bytes |
| W5 | `btrfs_root_item` reserved-field inspection | Wani 2020 | Implemented and reported as anomalies |
| R1 | Orphaned extent-tree scanning for `EXTENT_DATA_REF` | Rodeh et al. 2013 | Implemented via `_parse_extent_tree_leaf()` |
| R2 | Defragmentation hazard detection | Rodeh et al. 2013 | Implemented as an orphan-ratio heuristic warning |
| R3 | Snapshot/subvolume presence indicator | Rodeh et al. 2013 | Implemented via `owner >= 256` tracking |
| H1 | Device-tree parsing | Hilgert et al. 2018 | Implemented via orphaned device-tree leaf parsing |

### 3.3 Implemented Capabilities Today

#### Core recovery

- brute-force metadata node scanning across the image
- CRC32c-validated B-tree node acceptance
- orphan-item scanning in leaf nodes
- orphan-pointer scanning in internal nodes
- inline extent extraction
- regular extent extraction through logical-to-physical chunk mapping
- deduplication of duplicate recovered extents

#### Additional evidence sources

- leaf slack extraction
- internal-node slack mining
- boot sector extraction
- volume slack extraction
- orphaned extent-tree `EXTENT_DATA_REF` parsing
- orphaned device-tree parsing

#### Metadata and reporting

- generation-aware `(inode, generation)` filename tracking
- move/rename artifact detection
- file slack reporting
- ROOT_ITEM anomaly reporting
- defragmentation hazard warning
- snapshot/subvolume presence indicator
- human-readable summary output
- `recovery_report.json` with structured metadata

#### Verification and documentation

- `test_crc32c.py`
- `test_inode_parser.py`
- `test_integration.py`
- README aligned with implemented behavior

### 3.4 Current `RecoveryReport` Coverage

| Counter/Field | Meaning |
|---|---|
| `checksum_failures` | Nodes rejected by CRC32c validation |
| `leaf_slacks_found` | Non-zero leaf slack regions written out |
| `extent_backrefs_found` | `EXTENT_DATA_REF` backrefs recovered from orphaned extent-tree nodes |
| `internal_orphan_ptrs_found` | Key-pointer slots found beyond `nritems` in internal nodes |
| `move_artifacts_found` | Inodes observed under different names across generations |
| `defrag_warning` | Heuristic warning that evidence may have been reduced by defrag |
| `subvolume_nodes_seen` / `has_snapshots` | Evidence of subvolume or snapshot activity |
| `internal_slack_residuals` | Residual item structures found in internal-node slack |
| `root_item_anomalies` | Non-zero reserved bytes observed in `ROOT_ITEM` structures |
| `device_info` | Device metadata extracted from device-tree artifacts |

---

## 4. Landscape and Positioning

### 4.1 Existing tools

| Tool | Strength | Limitation |
|---|---|---|
| `btrfs-restore` | Walks the tree from a known root and extracts files | Requires a root pointer and does not analyze orphan items beyond `nritems` |
| `btrfs-find-root` | Finds candidate historical roots by scanning metadata | Reports roots only; does not recover file content or parse orphan artifacts |
| TSK / Autopsy Btrfs support | Can parse active Btrfs structures, including some multi-device cases | No generation-aware historical recovery and no orphan-item analysis |
| Commercial recovery tools | Active-tree parsing and generic carving | No published support for orphan-item analysis, generation diffs, or forensic slack extraction |

### 4.2 Capability comparison

| Capability | `btrfs-restore` | `btrfs-find-root` | TSK | Current project | Future target |
|---|:---:|:---:|:---:|:---:|:---:|
| Parse active tree | ✅ | ❌ | ✅ | ❌ | ✅ |
| Linear orphan-node scan | ❌ | ✅ | ❌ | ✅ | ✅ |
| Parse orphan items beyond `nritems` | ❌ | ❌ | ❌ | ✅ | ✅ |
| Scan internal orphan key-pointers | ❌ | ❌ | ❌ | ✅ | ✅ |
| Extract inline data | ✅ | ❌ | ✅ | ✅ | ✅ |
| Extract regular extents | ✅ | ❌ | ✅ | ✅ | ✅ |
| CRC32c node validation | ✅ | ✅ | ✅ | ✅ | ✅ |
| Leaf and volume slack extraction | ❌ | ❌ | ❌ | ✅ | ✅ |
| Orphaned extent-tree backref parsing | ❌ | ❌ | ❌ | Partial | ✅ |
| Walk backup roots | ❌ | ❌ | ❌ | ❌ | ✅ |
| Root-tree and subvolume discovery | ✅ | ❌ | ✅ | ❌ | ✅ |
| Generation diff engine | ❌ | ❌ | ❌ | ❌ | ✅ |
| Cross-generation file timeline | ❌ | ❌ | ❌ | ❌ | ✅ |
| Compression support | ✅ | ❌ | ✅ | Stub/raw only | ✅ |
| Multi-device / RAID support | ✅ | ❌ | ✅ | ❌ | Later |

The current project is already stronger than `btrfs-find-root` for forensic artifact extraction, but it is not yet a structural historical recovery engine like the future design intends.

---

## 5. Why Btrfs Leaves Recoverable Evidence

### 5.1 Copy-on-Write update chain

Every B-tree modification writes new metadata blocks instead of updating old ones in place. That means a delete operation usually leaves behind older versions of:

- the modified leaf
- its parent
- ancestors up to the old root

Those older blocks become orphaned and remain recoverable until their physical space is reused.

### 5.2 Balancing operations create residue

The main balancing operations are split, merge, and redistribution.

- Split duplicates metadata into new blocks while leaving the old full block behind.
- Merge can orphan both pre-merge siblings while reducing what remains in the new node.
- Redistribution is especially useful for recovery because moved items may remain physically present beyond the new `nritems` count.

### 5.3 Orphan-items are a forensic concept

In this project, "Orphan-Items" means item structures that still exist physically in a node but are no longer counted by `nritems`. This is separate from Btrfs's internal orphan-inode mechanism.

### 5.4 Snapshots increase evidence lifetime

Snapshots and shared extents delay block reclamation through reference counting. That generally improves the odds that historical metadata remains available long enough to recover.

---

## 6. Future Work

The brute-force stage is complete. The remaining roadmap is the optimized structural engine.

### 6.1 Roadmap phases

| Phase | Status | Planned work | Why it matters |
|---|---|---|---|
| P0 - historical entry points | Pending | Parse the 4 superblock backup roots and use them as direct historical starting points | Gives immediate access to recent filesystem history without blind scanning |
| P1 - structural discovery | Pending | Walk the root tree, discover subvolume roots, and build a generation-indexed node catalog | Adds structure and context to what is currently a flat scan |
| P2 - tree reconstruction and diffs | Pending | Reconstruct historical trees, diff generations, and expand extent-tree backref analysis into full reverse mapping | Identifies what changed and which files were deleted when |
| P3 - forensic intelligence | Pending | Cross-generation timelines, checksum-tree validation, predictive overwrite analysis, B-tree operation reconstruction | Raises evidentiary value and confidence scoring |
| P4 - completeness | Pending | Compression support, multi-device / RAID handling, and broader filesystem coverage | Makes the tool useful on more real-world images |

### 6.2 Detailed future items

| Priority | Item | Status | Notes |
|---|---|---|---|
| High | Superblock backup-root parsing | Pending | The superblock already stores recent historical roots that should be walked directly |
| High | Root-tree walk for subvolume discovery | Pending | Needed to enumerate filesystem trees instead of discovering nodes only by brute force |
| High | Generation-indexed node catalog | Pending | Enables historical reconstruction instead of one-node-at-a-time parsing |
| High | Generation diff engine | Pending | Core future feature for identifying deletes and modifications precisely |
| High | Full extent-tree backref analysis | Pending | Current orphaned extent-tree parsing is a partial step, not full reverse mapping |
| Medium | Log-tree analysis | Pending | Could recover recently fsynced but not fully committed state |
| Medium | Intelligent orphan-item correlation | Pending | Cross-reference orphan artifacts with inode and tree context rather than using only local heuristics |
| Medium | Checksum-tree data validation | Pending | Would allow confidence scoring for recovered file content |
| Medium | Cross-generation file timeline | Pending | Unique forensic reporting opportunity |
| Medium | Predictive overwrite analysis | Pending | Estimate whether deleted extents were likely reused |
| Medium | B-tree operation reconstruction | Pending | Explain whether split, merge, or redistribution produced an artifact |
| Low | Compression support | Pending | Inline and regular extents currently do not provide full decompression workflow |
| Low | Multi-device / RAID support | Pending | Important for wider Btrfs applicability but not required for the current single-image path |

### 6.3 What is not yet implemented

These items are still future work even after the brute-force plan was completed:

- walking historical trees from backup roots
- walking the live root tree to discover all subvolumes structurally
- reconstructing full historical trees by generation
- diffing trees across generations
- building per-file timelines across generations
- full extent reverse mapping from the extent tree
- checksum-tree-based validation of recovered data
- predictive overwrite confidence scoring
- compression-aware recovery
- multi-device and RAID reconstruction

---

## 7. Planned End State

The intended end state is a unified recovery engine that combines:

- brute-force orphan-node discovery
- structural tree walking from current and historical roots
- generation-aware tree reconstruction
- reverse mapping from extent metadata back to files
- richer artifact confidence and forensic timeline reporting

In short:

1. The current project already covers the brute-force recovery stage well.
2. The next major milestone is to stop treating discovered nodes in isolation and start reconstructing whole historical filesystem views.
3. The long-term differentiator is generation-aware recovery with timeline and confidence reporting that existing tools do not provide.

---

## 8. References

- Bhat, A. & Wani, M.A. (2018). *Forensic analysis of B-tree file system (Btrfs)*
- Wani, M.A. et al. (2020). *An analysis of anti-forensic capabilities of B-tree file system (Btrfs)*
- Rodeh, O., Bacik, J. & Mason, C. (2013). *BTRFS: The Linux B-Tree Filesystem*
- Hilgert, J.N. et al. (2018). *Forensic analysis of multiple device BTRFS configurations using The Sleuth Kit*
