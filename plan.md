# Btrfs Forensics Plan

- the project goal
- the current implemented state
- the brute-force work already completed
- the future hybrid reconstruction architecture
- the execution order for upcoming work

---

## 1. Goal

Build a forensic-safe Btrfs recovery tool that works directly on raw disk images, recovers deleted file metadata and content from orphaned Copy-on-Write metadata blocks, and evolves from a brute-force artifact extractor into a historical reconstruction engine.

The target end state is not just file carving. It is a recovery system that can:

- recover files and metadata from orphaned B-tree nodes
- reconstruct historical filesystem structure when possible
- correlate forward references and reverse references across Btrfs trees
- distinguish confirmed reconstructions from probable fragments and unattached artifacts
- produce a defensible forensic report with provenance and confidence

---

## 2. Current State

### 2.1 Codebase Status

| Area | Status | Notes |
|---|---|---|
| Brute-force metadata sweep | Implemented | Full raw-image scan for metadata nodes, orphan detection, item parsing, and extraction |
| Chunk-tree walking | Implemented | Recursive top-down chunk-tree traversal already exists and proves generic tree walking is viable |
| Original brute-force gap list | Complete | All items from the old `gap.md` are now implemented |
| Optimized structural recovery engine | Not implemented | Backup-root walking, root-tree walking, DB-backed cataloging, hybrid reconstruction, and generation diffing remain future work |
| Verification | Passing | `python3 -m unittest discover -s tests -v` currently passes with 27 tests |

### 2.2 What the Current Code Does

| Component | Current role |
|---|---|
| `main.py` | Entry point, orchestration, output handling |
| `utils/superblock.py` | Parses the primary superblock and bootstraps the chunk map |
| `utils/chunk_parser.py` | Walks the chunk tree recursively and builds logical-to-physical mappings |
| `utils/btree.py` | Performs the raw sweep, validates metadata nodes, parses items, extracts data, mines slack, and records artifacts |
| `utils/recovery_report.py` | Aggregates counters, metadata, and JSON/text reporting |
| `tests/` | Unit and integration coverage for CRC32c, inode parsing, and end-to-end pipeline behavior |

### 2.3 Current Scope Boundary

The current engine is strong at artifact extraction from raw metadata blocks, but it is still mostly node-local. It does not yet reconstruct full historical trees from anchored roots, build a persisted queryable metadata catalog, or correlate all cross-tree references into a unified reconstruction model.

---

## 3. Completed Work

The brute-force stage is complete.

### 3.1 Completed Phases

| Phase | Status | Outcome |
|---|---|---|
| Phase 0 - bug fixes | Complete | Fixed inode/generation keying, extent deduplication, current-generation orphan scanning, JSON numeric serialization, and output-dir side effects |
| Phase A - correctness and confidence | Complete | Added CRC32c validation and corrected `otime` documentation |
| Phase B - new evidence sources | Complete | Added leaf slack extraction, boot sector extraction, orphaned extent-tree parsing, and internal-node orphan pointer scanning |
| Phase C - metadata enrichment | Complete | Added move/rename tagging, file slack reporting, defrag warning heuristic, and snapshot/subvolume indicator |
| Phase D - completeness | Complete | Added internal-node slack mining, volume slack extraction, ROOT_ITEM reserved-field inspection, and device-tree parsing |
| Phase E - tests and docs | Complete | Added CRC and inode parser tests, integration coverage, README cleanup, and plan consolidation |

### 3.2 Implemented Capabilities Today

#### Core recovery

- brute-force metadata-node scanning across the disk image
- CRC32c-validated acceptance of candidate metadata nodes
- orphan-item scanning in leaf nodes
- orphan key-pointer scanning in internal nodes
- inline extent extraction
- regular extent extraction through chunk-map address translation
- extent deduplication during extraction

#### Additional evidence sources

- leaf slack extraction
- internal-node slack mining
- boot sector extraction
- volume slack extraction
- orphaned extent-tree `EXTENT_DATA_REF` parsing
- orphaned device-tree parsing

#### Metadata enrichment and reporting

- generation-aware `(inode, generation)` filename tracking
- move/rename artifact tagging
- file slack reporting
- ROOT_ITEM anomaly detection
- defragmentation hazard warning
- snapshot/subvolume presence indicator
- machine-readable `recovery_report.json`

### 3.3 Original Brute-Force Gap Checklist and Result

| ID | Item | Source | Result |
|---|---|---|---|
| B1 | CRC32c node checksum validation | Bhat & Wani 2018 | Implemented via `utils/crc32c.py` |
| B2 | Internal node key-pointer orphan scanning | Bhat & Wani 2018 | Implemented via `_scan_internal_node_orphan_ptrs()` |
| B3 | Internal node slack mining | Bhat & Wani 2018; Wani 2020 | Implemented via `_mine_internal_node_slack()` |
| B4 | Move/rename artifact tagging | Bhat & Wani 2018 | Implemented in directory-entry parsing and reporting |
| B5 | Correct `otime` documentation | Bhat & Wani 2018 | Implemented in `README.md` |
| W1 | Leaf slack extraction | Wani 2020 | Implemented via `_extract_leaf_slack()` |
| W2 | File slack reporting | Wani 2020 | Implemented for regular extents |
| W3 | Boot sector extraction | Wani 2020 | Implemented for the first 64 KiB of the image |
| W4 | Volume slack extraction | Wani 2020 | Implemented for non-aligned trailing bytes |
| W5 | `btrfs_root_item` reserved-field inspection | Wani 2020 | Implemented and reported as anomalies |
| R1 | Orphaned extent-tree scanning for `EXTENT_DATA_REF` | Rodeh et al. 2013 | Implemented via `_parse_extent_tree_leaf()` |
| R2 | Defragmentation hazard detection | Rodeh et al. 2013 | Implemented as a heuristic warning |
| R3 | Snapshot/subvolume presence indicator | Rodeh et al. 2013 | Implemented via `owner >= 256` tracking |
| H1 | Device-tree parsing | Hilgert et al. 2018 | Implemented via orphaned device-tree leaf parsing |

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

## 4. Why Btrfs Supports Historical Recovery

### 4.1 Copy-on-Write Preserves Old Metadata

Btrfs does not overwrite metadata blocks in place. A modification creates new metadata blocks and leaves the old ones behind until their space is reused. This is the core reason orphaned B-tree nodes can persist after deletion.

### 4.2 Balancing Operations Leave Recoverable Residue

Split, merge, and redistribution operations can leave behind:

- old leaf nodes that still contain pre-modification data
- item structures beyond the new `nritems` count
- residual data in internal-node slack if a block used to be a leaf

### 4.3 Snapshots and Shared References Extend Artifact Lifetime

Reference counting and snapshots can delay physical reuse of old blocks. That can preserve historical metadata much longer than on traditional overwrite-in-place filesystems.

### 4.4 Forward and Reverse References Exist in Different Structures

The future recovery engine should not assume child nodes store direct parent pointers. That is not the model.

Instead, reconstruction depends on combining multiple reference systems:

- internal metadata nodes contain child block pointers
- filesystem metadata leaves contain forward references to extents
- extent metadata stores reverse ownership/reference information
- root structures relate roots, subvolumes, and historical tree entry points
- chunk and device metadata map logical, physical, and device-level layout

These are not all equivalent, but together they create a cross-reference graph that can be indexed and queried for reconstruction.

---

## 5. Core Architectural Vision

The future engine should be hybrid.

It should not rely on only one of these:

- pure top-down root walking
- pure node-local brute-force parsing
- pure bottom-up tree guessing

It should combine all three evidence modes below.

### 5.1 Mode A - Anchored Top-Down Reconstruction

This is the highest-confidence mode.

Inputs:

- current superblock roots
- superblock backup roots
- root-tree discovered subvolume roots

Behavior:

- walk known roots through valid internal pointers
- reconstruct exact tree state where root chains survive
- compare multiple generations when multiple historical roots exist

Use when:

- valid root addresses are available
- checksum-valid paths can be followed end-to-end

Strength:

- strongest structural confidence

Weakness:

- fails when roots or key internal ancestors are missing

### 5.2 Mode B - Reverse Structural Reconstruction

This is the structural reverse-query mode.

Important distinction: this is not based on children storing explicit parent pointers. Instead, all parent-to-child edges found during scanning are persisted, then queried in reverse.

Behavior:

- scan all internal nodes and record every child pointer edge
- given a child logical address, query all known parents that referenced it
- build candidate historical subtrees or fragments

Use when:

- a child or subtree survives but its anchored root path is missing

Strength:

- can reconnect fragments even when the canonical top-down path is incomplete

Weakness:

- ambiguous across generations and snapshots; does not always yield one exact tree

### 5.3 Mode C - Reverse Semantic Reconstruction

This is the cross-reference mode centered on extent and metadata ownership.

Behavior:

- persist forward references from filesystem metadata to data extents
- persist reverse references and ownership data from extent metadata
- correlate both sides to recover which files or metadata structures referenced a given extent
- extend this beyond current `EXTENT_DATA_REF` support to additional metadata/tree-block reference forms

Use when:

- tree structure is incomplete but extent ownership survives in another tree

Strength:

- can recover ownership and provenance even when exact tree placement is missing

Weakness:

- may prove ownership without proving exact parent chain

### 5.4 Mode D - Fragment Assembly and Reconciliation

This mode merges evidence from all previous modes.

Behavior:

- combine anchored tree walks, reverse structural edges, and reverse semantic references
- reconcile generation, owner, key-range, and checksum evidence
- classify results by confidence instead of forcing exact reconstruction when the evidence does not support it

This is the correct way to interpret “bottom-up” for this project: not guessing trees from nothing, but assembling historical structure from persisted cross-references.

---

## 6. Persistent Catalog / Database Layer

The optimized engine should introduce a persisted queryable catalog.

### 6.1 Why a Database Is Needed

The expensive operation is the raw disk sweep. Once the image has been scanned, the tool should be able to query relationships many times without rescanning.

This is a natural fit for `sqlite3` because:

- it is dependency-free and consistent with the current project style
- it supports indexed reverse lookups and joins
- it is sufficient for a relationship graph of this size

### 6.2 Initial Target Schema

The first version does not need every table below on day one, but this is the target model.

| Table | Purpose |
|---|---|
| `nodes` | One row per checksum-valid metadata node with logical bytenr, physical offset, generation, owner, level, item count, and key range |
| `tree_edges` | Parent-to-child edges extracted from internal nodes, including slot, separator key, and provenance |
| `leaf_items` | Generic leaf item inventory keyed by node and item key |
| `inode_items` | Parsed inode metadata by `(inode, generation)` |
| `dir_entries` | Parsed directory references and names |
| `file_extents` | Forward references from filesystem metadata to data extents |
| `extent_items` | Extent-tree inventory of known extents |
| `extent_data_backrefs` | Reverse ownership/reference records for file data extents |
| `metadata_backrefs` | Metadata/tree-block reference records from extent metadata |
| `root_items` | Root definitions and referenced tree roots |
| `root_links` | `ROOT_REF` / `ROOT_BACKREF` style relationships between roots/subvolumes |
| `chunks` | Logical-to-physical mappings |
| `devices` | Device-tree records and device extents |
| `artifacts` | Output artifacts, provenance, and confidence classification |

### 6.3 Minimum Catalog Fields for Nodes

Each stored metadata node should at least record:

- logical bytenr
- physical offset
- checksum-valid state
- generation
- owner
- level
- `nritems`
- min key
- max key
- whether it was reachable from an anchored root walk
- provenance of how it was discovered

This catalog is the basis for both top-down and reverse reconstruction.

---

## 7. Roadmap

The roadmap below is the execution order for future work.

### Phase F0 - Catalog Foundation

Status: Pending

Goals:

- parse additional superblock recovery entry points, especially backup roots
- normalize metadata-node parsing into a reusable node record format
- introduce SQLite-backed catalog persistence
- store checksum-valid nodes, internal edges, leaf items, and chunk mappings

Why first:

- everything else depends on a stable, queryable corpus of evidence

Definition of done:

- a single raw-image scan can populate a persistent catalog that can answer basic reverse queries without rescanning the disk

### Phase F1 - Generic Metadata-Tree Walker

Status: Pending

Goals:

- generalize the existing recursive chunk-tree traversal pattern into a reusable metadata-tree walker
- support walking any tree given a logical root and chunk map
- separate tree walking from tree-specific item parsing

Why next:

- the code already proves this approach for the chunk tree; the same pattern should be reused rather than reimplemented ad hoc

Definition of done:

- the tool can walk arbitrary metadata trees by logical root and dispatch to tree-specific parsers

### Phase F2 - Root Discovery and Anchored Historical Walking

Status: Pending

Goals:

- parse superblock backup roots
- walk the current root tree
- discover active and historical subvolume roots
- parse root relationships and root metadata

Why next:

- anchored historical walks provide the highest-confidence reconstruction path and reduce dependence on blind inference

Definition of done:

- the tool can list discovered roots/subvolumes and walk at least current plus backup-root anchored tree states

### Phase F3 - Cross-Reference Expansion

Status: Pending

Goals:

- extend extent-tree parsing beyond current orphaned `EXTENT_DATA_REF` support
- parse additional metadata/tree-block reference forms from extent metadata
- store both forward extent references and reverse ownership/reference records
- correlate data extents and metadata extents across trees

Why next:

- this is the core of reverse semantic reconstruction and the strongest expression of the project’s hybrid design

Definition of done:

- given an extent logical address, the engine can answer who referenced it, from which tree context, and with what generation evidence when that information survives

### Phase F4 - Hybrid Reconstruction Engine

Status: Pending

Goals:

- combine anchored walks, reverse structural queries, and reverse semantic queries
- assemble historical subtrees, partial fragments, and unattached artifacts
- reconcile conflicting candidates using owner, generation, key-range, and checksum evidence

Why next:

- this is where the project moves from raw artifact extraction to actual reconstruction

Definition of done:

- the engine can produce confirmed trees where anchors exist and probable fragments where only partial evidence survives

### Phase F5 - Generation Diffing and Timelines

Status: Pending

Goals:

- compare anchored and reconstructed states across generations
- detect create, modify, move, rename, and delete events
- build per-file and per-inode historical timelines

Why next:

- once historical states exist, diffing them is the most direct way to explain what changed and when

Definition of done:

- the report can describe a file’s lifecycle across multiple generations with provenance and confidence

### Phase F6 - Validation and Confidence Improvements

Status: Pending

Goals:

- use checksum-tree data where possible to validate recovered content
- add overwrite-risk heuristics
- improve provenance tracing for every recovered object
- assign confidence to both structure and data

Definition of done:

- every important reported artifact includes evidence sources and a confidence tier

### Phase F7 - Broader Filesystem Coverage

Status: Pending

Goals:

- compression-aware recovery
- log-tree analysis
- multi-device / RAID handling
- broader real-world image coverage

Definition of done:

- the engine handles more than the current single-device, mostly uncompressed recovery path

---

## 8. Immediate Priority Order

The next concrete implementation order should be:

1. parse backup roots from the superblock and expose them in `superblock.py`
2. introduce a persistent SQLite catalog for scanned nodes and internal edges
3. generalize the chunk-tree walker into a reusable metadata-tree walker
4. parse and catalog root-tree structures and root relationships
5. expand extent-tree parsing beyond current `EXTENT_DATA_REF` support
6. build reverse structural and reverse semantic queries over the catalog
7. assemble fragments and add confidence scoring
8. implement generation diffing and historical reporting

This order keeps the architecture honest: catalog first, then anchored walking, then reverse reconstruction, then diffing.

---

## 9. Confidence Model

The future engine must never force certainty where the evidence is ambiguous.

### 9.1 Confidence Tiers

| Tier | Meaning |
|---|---|
| Confirmed | Supported by checksum-valid nodes and an anchored structural path or equivalent high-confidence cross-reference chain |
| Probable | Strongly supported by multiple consistent references, but missing a complete anchored path or containing generational ambiguity |
| Unattached Artifact | Valid local artifact or extent ownership evidence exists, but it cannot be placed confidently into a full historical tree |

### 9.2 Evidence That Raises Confidence

- checksum-valid metadata nodes
- anchored root-to-leaf traversal
- matching owner and generation context
- key-range consistency between parent and child
- agreement between forward references and reverse extent/backref evidence
- consistency across multiple surviving generations

### 9.3 Evidence That Lowers Confidence

- missing anchors
- conflicting parents across generations
- shared-reference ambiguity from snapshots
- stale or contradictory orphaned copies
- partial extent ownership without structural placement

---

## 10. Testing Strategy

The current test suite covers the brute-force stage. The future engine needs a broader matrix.

### 10.1 Current Verification

- `test_crc32c.py`
- `test_inode_parser.py`
- `test_integration.py`

### 10.2 Future Test Categories

| Area | Required coverage |
|---|---|
| Backup roots | Images where current root path is damaged but backup roots still recover historical state |
| Root-tree walking | Discovery of active subvolumes and historical roots |
| Reverse structural reconstruction | Internal-node edge cataloging and reverse parent query behavior |
| Reverse semantic reconstruction | Correlation between forward extent refs and reverse extent metadata |
| Split / merge / redistribution | Recovery behavior across the main B-tree balancing cases |
| Ambiguous parents | Multiple historical parents referring to related children across generations |
| Snapshots | Shared extents and generational ambiguity handling |
| Missing anchors | Recovery of probable fragments without a surviving root chain |
| Generation diffing | Detection of create, modify, move, rename, and delete events |
| Confidence tiers | Verified classification into confirmed, probable, and unattached outputs |

### 10.3 Verification Principle

Every future parser or reconstruction step should be testable independently before being integrated into full-image workflows.

---

## 11. Risks and Constraints

### 11.1 Ambiguity Is Normal

Because Btrfs preserves multiple historical copies, contradictory-looking metadata can all be valid for different generations. The engine must preserve provenance rather than collapsing everything into one guessed truth.

### 11.2 Reverse References Help, But Do Not Solve Everything

Extent and metadata reverse-reference information can prove ownership or relationship without always proving the exact full tree shape.

### 11.3 Partial Structure Is Still Valuable

Even when a full tree cannot be reconstructed, the tool can still produce valuable outputs:

- recovered file content
- recovered inode metadata
- ownership of data extents
- probable historical fragments
- warnings about evidence destruction, such as defragmentation

### 11.4 Overwrites Remain Final

If blocks have been reused, no reconstruction strategy can recover the destroyed historical bytes.

### 11.5 Current Practical Limits

The current project still has known future-work areas:

- full metadata/tree-block backref coverage is not implemented yet
- compression-aware recovery is incomplete
- multi-device and RAID handling is not implemented yet
- the log tree is not yet analyzed

---

## 12. Planned End State

The intended end state is a unified recovery engine that combines:

- brute-force orphan-node discovery
- anchored top-down tree walking
- reverse structural reconstruction from persisted internal edges
- reverse semantic reconstruction from forward and reverse extent references
- generation-aware tree and fragment assembly
- confidence-based reporting and timelines

In practical terms, the project should eventually answer questions like:

- what files and directories existed in a past generation?
- which recovered file content is confirmed versus only probable?
- which extents belonged to which file or metadata structure?
- what changed between two generations?
- what evidence survived only as fragments rather than complete trees?

---

## 13. References

- Bhat, A. & Wani, M.A. (2018). *Forensic analysis of B-tree file system (Btrfs)*
- Wani, M.A. et al. (2020). *An analysis of anti-forensic capabilities of B-tree file system (Btrfs)*
- Rodeh, O., Bacik, J. & Mason, C. (2013). *BTRFS: The Linux B-Tree Filesystem*
- Hilgert, J.N. et al. (2018). *Forensic analysis of multiple device BTRFS configurations using The Sleuth Kit*
