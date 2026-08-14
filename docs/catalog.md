# Btrfs Forensics — Development Catalog

A chronological catalog of every development milestone: commits, decisions,
empirical findings, and verification results. This file is the **master
timeline** for the project — new work is appended here before anything else,
so the history is never lost even if other docs are rewritten.

Render as HTML (e.g. `pandoc docs/catalog.md -o docs/catalog.html`) or read
directly on GitHub. Markdown is used as the source of truth because it is
diffable and reviewable in pull requests.

---

## How to Maintain This Catalog

For **every** feature or milestone:

1. Add a `### YYYY-MM-DD — <name>` entry at the top of the Timeline section.
2. Include: date, branch, commit hashes, what was done and why, empirical
   findings, and how it was verified (tests run, numbers measured).
3. Link related artifacts (`plan.md` phases, `README.md` features, tests).
4. Keep the branch-name convention: **one branch per feature**
   (`feature/<short-name>`), merged to `main` via a pull request.

---

## Timeline

### 2026-08-14 — M1: Superblock Backup Roots + Anchored Historical Walking

- **Branch:** `feature/m1-backup-roots`
- **Plan:** plan.md §8, Milestone 1 (implemented)

**Goal.** Recover complete historical filesystem states from the superblock's
backup roots instead of blind scanning — walking checksum-valid root-to-leaf
paths gives *anchored provenance* for recovered files.

**Empirical finding — backup-root layout (sandbox.img).**

The four `btrfs_root_backup` entries sit at **packed, unaligned** superblock
offsets `0xB2B / 0xBD3 / 0xC7B / 0xD23` (stride 0xA8 = 168 bytes) with the
standard field offsets (tree_root@0x00 … total_bytes@0x60, num_devices@0x70).
All four validated with CRC + owner checks and reference **four distinct
historical states**: fs trees at 0x1D5C000 (gen 11), 0x1D70000 (gen 12),
0x1D20000 (gen 13), 0x1D48000 (gen 14); the newest tree_root equals the live
root tree address.

**What was done.**

- `utils/backup_roots.py`: parses the 4 slots and validates every referenced
  root (CRC32c + expected owner via the chunk map) — garbage slots are never
  treated as evidence.
- `utils/anchored_walk.py`: walks a backup's fs tree into a file inventory
  (inode → name/size/has_data), walks the current fs tree via the live root
  tree for comparison, tags sweep-recovered artifacts with
  `provenance: "anchored"`, and reports files deleted since each generation.
- `main.py` runs the anchored analysis after the sweep (`--no-anchored` to
  skip); new stats in the summary + JSON (`historical_states`, backup-root
  counts, deleted-since).

**Result on sandbox.img.**

- gen 11 state: `target_file.txt` (31 B inline) — deleted by gen 12
- gen 13 state: `large_target.txt` (5 MiB regular extent) — deleted by gen 14
- gen 14 state: only the root dir (files gone) — coherent deletion timeline
- 5 sweep artifacts confirmed with anchored provenance; 2 files reported
  as deleted since a backup generation

**Verification.** `tests/test_m1_anchored.py` (12 tests): 4 backups parsed,
all valid, gens span 11–14, state inventories match the sweep findings,
deleted-since diff, provenance tagging. Full suite: **49 tests pass**.

---

### 2026-08-14 — M2: Structure-Directed Targeted Orphan Scan

- **Branch:** `feature/m2-targeted-orphan-scan`
- **Commit:** `c7ce1bc` — "M2: structure-directed targeted orphan scan"
- **Plan:** plan.md §8, Milestone 2 (implemented)

**Goal.** Replace the blind full-image sweep with an *optimized algorithm to
find orphan nodes* driven by how Btrfs actually stores metadata.

**What was done.**

- Recorded chunk `type` (DATA/SYSTEM/METADATA) in the chunk map —
  `btrfs_chunk.type` lives at **offset 24** of the CHUNK_ITEM payload
  (after length/owner/stripe_len; `num_stripes` remains at 44).
- Added `build_scan_regions()` (`utils/chunk_parser.py`): candidate physical
  regions = everything except DATA chunks and the reserved boot area. This
  covers METADATA/SYSTEM chunks **plus unmapped gaps** left by relocated or
  removed chunks.
- Extracted the reusable anchored tree walker (`utils/tree_walker.py`) from
  the chunk-tree traversal pattern.
- Added `utils/orphan_scan.py`: locates the extent tree via the root tree
  (`ROOT_ITEM` tree-root `bytenr` is at **offset 176**, after the embedded
  160-byte inode item) and enumerates currently-allocated metadata blocks
  (METADATA_ITEM / EXTENT_ITEM).
- Refactored the sweep in `utils/btree.py`: per-block logic extracted into
  `_process_candidate_block()` so targeted and full modes are identical.
- Added scan-mode stats to `utils/recovery_report.py` and the CLI flags
  `--full-sweep` / `--scan-data-chunks` in `main.py`.
- Tests: `tests/test_targeted_scan.py` (10 tests — region units + parity).

**Empirical findings on `sandbox.img` (256 MiB).**

- Only **48 of 256 MiB is mapped**: 8 MiB DATA (0xD00000), 8 MiB SYSTEM
  (0x1500000), 32 MiB METADATA (logical 0x1D00000 → physical 0x2500000,
  offset +0x80000 — physical ≠ logical).
- The current extent tree (root 0x1D38000, gen 14) lists **10 live metadata
  blocks** as METADATA_ITEMs; the complement within the metadata chunk is
  orphan territory.
- **21 of 71 orphaned nodes lie OUTSIDE the current chunk map**
  (0x100000–0x130000, 0x500000–0x520000; owners 1–7, 10–11; gens 1–4;
  header bytenr == physical offset). They are remnants of a since-removed
  chunk. A naive "scan mapped chunks only" approach would silently miss 30%
  of the evidence — which is why the gaps are kept in the candidate regions.
- **Backup roots are populated** in the superblock: they reference a complete
  gen-13 state (tree 0x1D28000, extent 0x1D10000, fs 0x1D20000, dev
  0x1D2C000, csum 0x1D08000 — all CRC-valid, owner-correct). One transaction
  behind the current gen 14. (Location: `btrfs_root_backup` entries in the
  superblock region around SB+0xB00; fields are packed/unaligned — verify
  offsets against the kernel struct when implementing M1.)

**Verification.** All 37 tests pass. Targeted run on `sandbox.img`: 15,867
blocks examined of 16,379 (512 DATA + 5 boot skipped), **identical 71
orphaned nodes, identical recovered files, 0 orphans outside regions**.

**Result parity**

| Metric | Full sweep | Targeted |
|---|---|---|
| Blocks examined | 16,379 | 15,867 |
| Orphaned nodes | 71 | 71 (identical offsets) |
| Recovered files | inline + 5 MiB extent | identical |
| Orphans outside regions | — | 0 |

---

### 2026-05-12 / 2026-05-13 — Gap Fixes and Planning

- **Branch:** `main`
- **Commits:**
  - `a28daeb` — "fixed gaps in brute force"
  - `b75cfc2` — "Updated plan.md"
  - `e92e648`, `19eab5d` — "Added commands, mount especially for ext4"

Closed the remaining gaps in the brute-force stage (Phase A–E per plan.md)
and consolidated the roadmap into `plan.md` (§1–§13): goal, current state,
completed work, the hybrid reconstruction vision (Modes A–D), the SQLite
catalog design, the F0–F7 roadmap, confidence model, and testing strategy.
The `commands.txt` file documents the sandbox build/mount workflow
(`mount -o loop,ro -t btrfs sandbox.img mnt_sandbox`).

---

### 2026-04-28 — Diagnostics, Journals, Docs Hygiene

- **Branch:** `main`
- **Commits:**
  - `b28f796` — "Added readme"
  - `b679b27` — "Unpushing docs" (docs removed from the remote)
  - `6fc015b` — "Remove docs from repo tracking"
  - `72253de`, `25be300` — "Minor diag fix"
  - `5a94ec8` — "Not implemented, but addressed some concepts based on extra
    journals"

Added the README, kept the paper PDFs (Bhat & Wani 2018; Wani et al. 2020;
Rodeh et al. 2013; Hilgert et al. 2018) out of git tracking, and studied the
journal papers for concepts (journal/log-tree analysis was scoped out — noted
as not implemented).

---

### 2026-04-27 — Brute-Force Pipeline Complete + Scaffolding

- **Branch:** `main`
- **Commits:**
  - `ed97764` — "Brute force files recovery implemented"
  - `b66ccd0` — "Added plan doc and version uploading python files for
    version control"

Full brute-force pipeline: raw-image sweep, FSID + CRC32c node validation,
orphan-node detection (gen < superblock gen), orphan-item scanning, inline
and regular extent extraction, and the JSON report. `plan.md` created.

---

### 2026-04-26 — Phase 1: Inline Recovery → Large Files → Chunk Map

- **Branch:** `main`
- **Commits:**
  - `4638fd3` — "Recovering file name, inline and general files in common
    .bin format"
  - `b99bbd1` — "This marks the end of phase 1, where I successfully
    implemented dealing with inline data recovery for small files (typically
    under 16KB)"
  - `32b2117` — "btree.py parses large files, added untested chunk_parser.py
    for large logical to physical address conversion"

Initial exploration of the Btrfs on-disk format: node header layout, item
pointers, INODE_REF/DIR_ITEM/EXTENT_DATA parsing, filename recovery, and
inline data extraction for small files (< 16 KiB). Then regular extents for
large files via a logical → physical chunk map (`utils/chunk_parser.py`).

---

## Reference Index

| Artifact | Purpose |
|---|---|
| `plan.md` | Living roadmap: goal, architecture vision, F0–F7 phases, confidence model |
| `README.md` | User-facing feature/usage documentation |
| `docs/catalog.md` | This file — master development timeline |
| `tests/` | Unit + integration verification for every feature |
| `commands.txt` | Sandbox image build / mount commands |
