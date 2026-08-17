# Development Catalog

The chronological record of everything done in this project — every milestone,
commit, decision, empirical finding, and verification result. **Update this
file immediately after doing something**; it is the project's memory and the
source for the paper's "implementation history" narrative.

Companion docs: [`research.md`](research.md) (full prior-art and gap analysis),
[`plan.md`](plan.md) (forward-looking build plan).

Maintenance rules:

1. Add a `## YYYY-MM-DD — <title>` entry at the **top** of the Timeline for
   each unit of work (feature, experiment, decision, doc rewrite).
2. Record: branch, commit hashes, what was done and why, empirical numbers,
   and how it was verified (tests, measurements).
3. One branch per feature (`feature/<short-name>`), merged to `main` via PR.

---

# Timeline (newest first)

## 2026-08-17 — Project reset: research consolidation, stack decision, doc rewrite

- **Branch:** `main`
- **Context:** After the 2026-08-14 research pass we confirmed that the
  project's headline capability (deleted-file recovery from raw Btrfs images)
  is heavily pre-implemented in open source and now also published
  ("Beyond Carving", IEEE Access, July 2026 — full text obtained and read).
  A deeper, verified research sweep was run over (a) every open-source tool
  and library that parses raw Btrfs images, (b) the complete academic
  landscape 2013–2026, and (c) the implementation-stack question.

**What was done.**

- Full verified survey of the tool/library landscape (results in
  `research.md` §2–§3). Highlights: Sleuth Kit **upstream has no Btrfs**
  (PR #413 closed unmerged 2024); `dissect.btrfs` (Fox-IT, AGPL-3.0) is the
  strongest raw-image Python substrate; `rustutils/btrfsutils` (MIT/Apache,
  2026) is the emerging permissive Rust option; `btrfs-rec` (lukeshu) is
  prior art for lost-branch reattachment.
- Full verification of the academic corpus (results in `research.md` §4–§6),
  including reading the full text of Pandey/Jain/Shetty "Beyond Carving"
  (IEEE Access 14:120632–120660, DOI 10.1109/ACCESS.2026.3713173, CC BY).
  Its coverage and its explicitly stated future work now define our novelty
  boundary.
- Stack research and decision (analysis in `research.md` §7, decision in
  `plan.md` §3): **Python orchestration + numpy/crc32c fast scan path now,
  Rust (PyO3/maturin) scan core next**; SQLite evidence catalog; pure-stdlib
  Python confirmed non-viable at TB scale (~15–40 h/TB vs ~20–75 min for the
  numpy path, I/O-bound).
- Migration decision (details in `plan.md` §4): treat most of the existing
  ~2,800-line prototype as *validated research scaffolding*, not product
  code. Reimplemented plumbing (superblock/chunk/tree walking, extraction)
  is superseded by existing libraries; the novel parts (orphan-item
  scanning, slack archaeology, targeted-scan region logic, the sandbox
  empirical findings) carry forward.
- Docs rewritten from scratch: this `catalog.md` (root), `research.md`
  (root), `plan.md` (root). Deleted: `docs/catalog.md`,
  `docs/research_report.md`, old `research.md` (superseded; all content
  incorporated).
- **Full-text read of all five original `docs/` PDFs** (not just abstracts):
  Beyond Carving (28 pp., read in full — algorithm, evaluation, and its
  stated future work now define our novelty boundary), Bhat & Wani 2018,
  Wani et al. 2020, Rodeh et al. 2013, Hilgert et al. 2018. Technical
  digests folded into `research.md` §4.6; two factual corrections captured
  in §8.4 (defrag heuristic was mis-attributed to Wani 2020; slack features
  split into corruption-signal W1/W2 vs payload W3/W4/W5). The plan's
  file-by-file DELETE/MIGRATE/REWRITE verdicts (`plan.md` §4) and the
  btrfs-specific evaluation axes (`plan.md` M7) derive from these reads.
- **Downloaded and read 13 more relevant papers into `docs/`** (18 total):
  MetaRecoverX 2026, DMPedia XFS/Btrfs 2026, Wani & Bhat dataset 2018,
  Juch 2014 thesis, Rodeh 2008, Hilgert 2017 pooled-storage (slides),
  Hilgert 2024 stacked FS, Beebe 2009 ZFS, Schwietert & Hilgert 2025 hiding
  corpus, Göbel 2024 IFIP + fishy 2018, "Mind the slack" 2026, Kim et al.
  2021. Per-paper digests grouped by theme in `research.md` §4.7. Six more
  relevant papers could not be downloaded (paywall/Cloudflare: the Toolan
  SSRN btrfs-hiding preprint, Plum & Dewald APFS, ExtSFR, IEEE ICPCSN 2025,
  Hilgert's Bonn PhD) — logged with citations in §4.8. Key new takeaway:
  Juch 2014 explicitly names our exact contribution (elder-tree
  reconstruction + node-fill-rate deleted-entry detection) as future work.

## 2026-08-14 — Second research pass ("we may be reimplementing prior art")

- **Branch:** `main` — **Commits:** `1b850c2` "added more research",
  `62d1660` "added docs and recovery output"
- First external prior-art audit (`docs/research_report.md`, then expanded
  `research.md`). Discovered the 2026 "Beyond Carving" IEEE Access paper,
  MetaRecoverX, the Toolan & Humphries hiding-techniques preprint, and the
  open-source overlap (btrfs-progs restore/find-root, btrfscue, TSK fork,
  davispuh/btrfs-data-recovery).
- Code-vs-spec audit found six correctness issues in the prototype
  (preserved in `research.md` §8): hardcoded CRC32c despite `csum_type`
  (xxhash/sha256/blake2b); `DEV_ITEM` UUID offset bug (reads FSID at +82 as
  device UUID); `ROOT_ITEM` "reserved region" check flags legitimate modern
  fields; MIXED_GROUPS filesystems break the targeted scan's
  no-metadata-in-DATA-chunks assumption; superblock mirrors never read;
  kernel `ORPHAN_ITEM` (0x30) items unparsed (terminology collision with
  Bhat & Wani "orphan-items").
- Committed sample recovery output (`recovery_output/`) from the sandbox.

## 2026-08-14 — M2: structure-directed targeted orphan scan

- **Branch:** `feature/m2-targeted-orphan-scan` — **Commits:** `c7ce1bc`
  (feature), `891215e`/`c51fe91` (PR merges), `452286a` (catalog doc)
- Replaced the blind full-image sweep with a structure-directed scan:
  - Chunk map now records chunk **type** (`btrfs_chunk.type` at offset 24 of
    the CHUNK_ITEM payload; DATA=0x1, SYSTEM=0x2, METADATA=0x4).
  - `build_scan_regions()` (`utils/chunk_parser.py`): candidate regions =
    everything except DATA chunks and the boot area — METADATA/SYSTEM chunks
    **plus unmapped gaps** left by removed/relocated chunks.
  - Generic anchored tree walker extracted to `utils/tree_walker.py`.
  - `utils/orphan_scan.py`: locates the extent tree via the root tree
    (`ROOT_ITEM` tree-root `bytenr` at offset 176, after the embedded
    160-byte inode item) and enumerates live metadata blocks.
  - Sweep refactored so targeted and full modes share
    `_process_candidate_block()`; CLI flags `--full-sweep`,
    `--scan-data-chunks`; scan-mode stats in the JSON report.
  - Tests: `tests/test_targeted_scan.py` (10 tests: region units + parity).

**Empirical findings on `sandbox.img` (256 MiB) — the project's key dataset:**

| Finding | Measurement |
|---|---|
| Chunk layout | Only 48 of 256 MiB mapped: 8 MiB DATA (0xD00000), 8 MiB SYSTEM (0x1500000), 32 MiB METADATA (logical 0x1D00000 → physical 0x2500000; physical ≠ logical) |
| Live metadata | Current extent tree (root 0x1D38000, gen 14) lists 10 live metadata blocks |
| **Relocated-chunk orphans** | **21 of 71 orphaned nodes lie OUTSIDE the current chunk map** (0x100000–0x130000, 0x500000–0x520000; owners 1–7, 10–11; gens 1–4; header bytenr == physical offset) — remnants of a removed chunk. A mapped-chunks-only scan would miss ~30% of evidence |
| Backup roots | Superblock `btrfs_root_backup` entries reference a complete gen-13 state (tree 0x1D28000, extent 0x1D10000, fs 0x1D20000, dev 0x1D2C000, csum 0x1D08000 — all CRC-valid, owner-correct), one transaction behind current gen 14 |

**Verification.** 37 tests pass. Targeted scan examines 15,867 of 16,379
blocks (512 DATA + boot skipped) and finds the **identical 71 orphaned
nodes, identical recovered files, 0 orphans outside regions** vs the full
sweep.

## 2026-05-12/13 — Brute-force gap closure + plan consolidation

- **Branch:** `main` — **Commits:** `a28daeb` "fixed gaps in brute force",
  `b75cfc2` "Updated plan.md", `e92e648`/`19eab5d` (commands.txt incl. mount
  workflow)
- Closed all items of the brute-force gap checklist (phases A–E of the old
  plan):
  - **Phase A (correctness):** CRC32c validation of every FSID-matching node
    (`utils/crc32c.py`, RFC 3720 vectors in tests); `otime` documented as
    birth time.
  - **Phase B (evidence sources):** leaf slack extraction; boot-sector
    (first 64 KiB) extraction; volume-slack extraction; orphaned extent-tree
    `EXTENT_DATA_REF` (0xB2) parsing; internal-node key-pointer scanning
    beyond `nritems`.
  - **Phase C (enrichment):** move/rename tagging (same inode, different
    names across generations); file-slack reporting; defrag-hazard
    heuristic; snapshot/subvolume indicator (owner ≥ 256).
  - **Phase D (completeness):** internal-node slack mining for residual leaf
    items; `ROOT_ITEM` reserved-field inspection; orphaned device-tree
    (`DEV_ITEM`) parsing.
  - **Phase E (tests/docs):** unit + integration tests, README, plan.
- Item-source mapping: B1–B5 from Bhat & Wani 2018, W1–W5 from Wani et al.
  2020, R1–R3 from Rodeh et al. 2013, H1 from Hilgert et al. 2018.

## 2026-04-28 — README, docs hygiene, journal study

- **Commits:** `b28f796`, `b679b27`, `6fc015b`, `72253de`, `25be300`,
  `5a94ec8`
- Added README; removed paper PDFs from git tracking; studied the four
  foundational papers; log-tree analysis explicitly scoped out for later.

## 2026-04-27 — Brute-force pipeline complete

- **Commits:** `ed97764` "Brute force files recovery implemented", `b66ccd0`
  (plan.md created, files under version control)
- End-to-end pipeline: raw-image sweep in nodesize steps → FSID prefilter →
  CRC32c validation → orphan classification (node gen < superblock gen) →
  item parsing → inline + regular extent extraction → JSON report.

## 2026-04-26 — Phase 1: first recovery (inline → large files → chunk map)

- **Commits:** `4638fd3`, `b99bbd1`, `32b2117`
- First working recovery: node-header/item parsing (`INODE_ITEM`,
  `INODE_REF`, `DIR_ITEM`, `DIR_INDEX`, `EXTENT_DATA`), filename recovery,
  inline-extent extraction (< 16 KiB files), then regular-extent extraction
  for large files via a logical→physical chunk map
  (`utils/chunk_parser.py`).

---

# Current code inventory (as of 2026-08-17)

Pure Python ≥ 3.14, zero third-party dependencies, ~2,830 lines.

| File | Lines | Role | Migration fate (see plan.md §4) |
|---|---|---|---|
| `main.py` | 201 | CLI + orchestration | Rewrite |
| `utils/btree.py` | 968 | Sweep, node/item parsing, extraction, slack mining | **Port** (orphan/slack logic is the novel core) |
| `utils/chunk_parser.py` | 281 | Chunk map + scan regions | Replace (library) / port region logic |
| `utils/constants.py` | 172 | On-disk constants | Replace (library) |
| `utils/crc32c.py` | 33 | Pure-Python CRC32c | Replace (`crc32c` C-ext / Rust) |
| `utils/superblock.py` | 93 | Primary superblock parse | Replace (library) + add mirrors/backup roots |
| `utils/tree_walker.py` | 87 | Generic anchored walker | Replace (library `BTree(root_offset=…)`) |
| `utils/orphan_scan.py` | 109 | Live-metadata set via extent tree | Port |
| `utils/inode_parser.py` | 132 | 160-byte inode item parser | Replace (library) |
| `utils/recovery_report.py` | 230 | Stats + JSON report | Rewrite into catalog/report layer |
| `tests/` (4 files) | 519 | 37 passing tests | Port assertions as golden tests |

Known defects carried on the books (from the 2026-08-14 audit, detailed in
`research.md` §8): CRC32c hardcode, DEV_ITEM UUID offset, ROOT_ITEM
reserved-region false positives, MIXED_GROUPS blind spot, superblock mirrors
ignored, kernel ORPHAN_ITEM (0x30) unparsed, single-stripe-only chunk
translation, no compression support.

# Assets

- `sandbox.img` (256 MiB, untracked) — primary test image; contains a
  complete gen-13 backup-root state, current gen-14 state, 71 orphaned nodes
  (21 outside the chunk map), subvolume owners. Build/mount commands in
  `commands.txt`.
- `recovery_output/` — sample recovery artifacts + `recovery_report.json`.
- `docs/*.pdf` — local copies of the foundational papers.
- `diagrams/` — architecture and format diagrams.
