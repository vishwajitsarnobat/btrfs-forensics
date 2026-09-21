# Paper draft starter — Btrfs filesystem-state archaeology

> **Working draft at checkpoint M2 (2026-09-15), `main` at `8034a75`; revised after the fact-check
> review of the same day (catalog.md checkpoint entry).** This file helps the authors
> start writing. It is not a submission. Every number in it is copied from a committed record and
> carries a pointer. `TODO` marks text or evidence that does not exist yet. `CHECK:` marks places
> where project documents disagree; both pointers are given and the paper must not take a side
> until the owner resolves it (consolidated list in Appendix A).
>
> **What the paper can already support (M0–M2).**
> - A strictly read-only reader for raw Btrfs images that validates every physical copy of every
>   tree block on all four checksum types, refuses unknown and unsupported incompat features, and
>   reads file content (inline, regular, prealloc, holes; zlib, zstd, LZO) with a record per extent
>   (EXP-001; catalog.md M1a–M1c).
> - A device scan of typed chunk stripes and unmapped gaps that classifies every tree-block copy as
>   `live`, `backup_reachable`, `unreferenced` or `invalid`. The default (targeted) plan skips DATA
>   chunks whose block-group item agrees; `--full-sweep` scans them too (catalog.md M2a; research.md
>   §10.10; `src/btrfska/scan/regions.py` docstring).
> - Old-root discovery that reports candidate root-tree blocks (states), their completeness and a
>   failure class for every missing block, including states that lie outside the current chunk map
>   (EXP-002; research.md §10.11).
> - Measurements of discard's effect on surviving metadata history on one generated scenario
>   (EXP-000, EXP-002) and of scan throughput (EXP-003).
>
> **Done since (M4, M5; 2026-09-21), each on one scenario and one host:** recovery from
> unreferenced blocks and orphan items (C1; EXP-005, EXP-006, EXP-008), historical chunk maps used
> for reading (C6; EXP-007), per-inode timelines (C3; `btrfska timeline`, no experiment record
> and no baseline yet).
>
> **What still needs M6–M7.** Recovery *rates* on an aged corpus,
> confidence tiers and data-checksum verification (C4, M6), hiding detection (C5, M6),
> baseline comparisons, an aged multi-scenario corpus and its public release (C7, M7). Today the
> evaluation is tree-level only, on small young images from one scenario.

The tool name `btrfska` is a placeholder (§13).

## Contents

1. [Status banner](#paper-draft-starter--btrfs-filesystem-state-archaeology) (above)
2. [Target venue and format](#2-target-venue-and-format)
3. [Working titles and abstracts](#3-working-titles-and-abstracts)
4. [Contributions and their status](#4-contributions-and-their-status)
5. [Section-by-section outline with draft prose seeds](#5-section-by-section-outline-with-draft-prose-seeds)
6. [Evaluation tables (copied from the experiment records)](#6-evaluation-tables-copied-from-the-experiment-records)
7. [Findings](#7-findings)
8. [Claim → evidence traceability](#8-claim--evidence-traceability)
9. [Figures and tables plan](#9-figures-and-tables-plan)
10. [Gap list to a submittable paper](#10-gap-list-to-a-submittable-paper)
11. [Threats to validity (consolidated)](#11-threats-to-validity-consolidated)
12. [References](#12-references)
13. [Writing guide for the authors](#13-writing-guide-for-the-authors)
- [Appendix A: `CHECK:` list](#appendix-a-check-list)

---

## 2. Target venue and format

**Primary: DFRWS (USA or EU), published in *Forensic Science International: Digital
Investigation* (FSI:DI).** Fallback: **IEEE Access**. Both come from plan.md §8. The accepted papers
of DFRWS APAC 2026 (19–22 Oct) were checked on 2026-09-21: none is about a file system
(research.md §11.1).

| Item | DFRWS (FSI:DI) | IEEE Access |
|---|---|---|
| Why | The venue of this literature: Hilgert et al. 2017/2018/2024, Schwietert & Hilgert 2025/2026, Oh & Hwang 2025, Toolan & Humphries 2026 (FSI:DI) | Where Beyond Carving appeared; fast, open access |
| Next deadline | Digital Forensics Conference Europe 2027 (formerly DFRWS EU): abstract 2 October 2026, full paper **9 October 2026**, both marked extended on the conference page on 2026-09-21 (research.md §11.4). **check** the DFRWS USA 2027 and APAC 2027 calls | Rolling submission |
| Page or word limit | 10 pages in the Europe 2027 call; **check** whether references and appendices count | **check** the author guide; there is an article processing charge (**check** amount) |
| Review model | Double-blind in the Europe 2027 call, so the tool name, repo URL and corpus DOI must be anonymised | **check** |
| Template | Elsevier FSI:DI two-column template; author–year citations, as in the DFRWS papers in `docs/papers/` (for example `docs/papers/schwietert_hilgert_mind_the_slack_2026.pdf`, "Carrier (2005)") | IEEE Access template, numbered citations |
| Artifact | **check** whether DFRWS runs artifact evaluation this cycle; plan.md §8 plans a `uvx`-installable tool, a Zenodo corpus and EXP scripts regardless | Code and data availability statement |

**Working budget (an assumption for planning, not a venue rule; replace once checked).** About
8 500 words of body text, 6–8 figures or tables in the body, about 50 references:

| Section | Words |
|---|---|
| Abstract | ≈ 200 (**check** the limit) |
| 1 Introduction (with contribution list) | 900 |
| 2 Background (Btrfs essentials) | 900 |
| 3 Related work and positioning | 1 100 |
| 4 Threat model and forensic-soundness requirements | 500 |
| 5 Method (as built) | 1 900 |
| 6 Evaluation | 1 900 |
| 7 Findings and discussion | 700 |
| 8 Limitations and threats to validity | 400 |
| 9 Future work and 10 Conclusion | 300 |

**Structure conventions for DFRWS papers**, taken from the DFRWS papers in `docs/papers/`
(`hilgert_stacked_filesystems_2024.pdf`, `schwietert_hilgert_datahiding_corpus_2025.pdf`):
- an explicit, numbered contribution list at the end of the introduction;
- a background section sized to what the method needs, not a filesystem tutorial;
- the evaluation set out by research questions, each answered with a table;
- a discussion that states forensic implications for practitioners;
- a limitations section;
- a statement that code and data are released (a URL or a placeholder in a blind review).

---

## 3. Working titles and abstracts

### 3.1 Title options

1. **What Copy-on-Write Leaves Behind: Validated Discovery of Superseded Btrfs States in Raw
   Images.** Fits the paper the current evidence supports.
2. **Filesystem-State Archaeology for Btrfs.** Short; fits the full paper (plan.md §1 thesis).
3. **Every Copy Counts: Provenance-Preserving Analysis of Btrfs Metadata History.** Stresses the
   validation and mirror findings.
4. **Reachability, Old Roots and Discard: How Much Btrfs Metadata History Survives, and Where.**
   A measurement-study framing, if the owner prefers it for the current evidence.
5. **btrfska: A Read-Only Evidence Engine for Btrfs Filesystem History.** A tool-paper framing,
   only once the name is final (§13) and the call is not blind.

Avoid "Beyond …" titles: they echo Beyond Carving (Pandey et al., 2026), which already goes beyond
the backup roots (§5.3, Appendix A item 1).

### 3.2 Abstract A — the paper the evidence supports now (M2)

> Btrfs never overwrites live metadata in place, so superseded tree blocks remain on disk until
> they are reused or trimmed. We present a strictly read-only analysis tool for raw Btrfs images
> that validates every physical copy of every tree block, refuses unsupported on-disk features, and
> scans the device's metadata chunks and the ranges that the current chunk map no longer covers,
> and in a full sweep its data chunks too. Each block is classified by reachability from the current
> state and the backup roots. Old-root discovery
> then reports every candidate root-tree block (state), how completely its trees survive, and why
> each missing block is missing. On generated 512 MiB images from one scenario that ends in a full
> balance (kernel 7.0), discovery finds 31 candidate root-tree blocks beyond the 4 backup-root
> states, 30 of them with every referenced block found; this survival depends on the balance and on
> the filesystem's short life. With synchronous discard, 2 of 35 candidate root-tree blocks and
> 8.7 % of the stale blocks remain (medians of 15 regenerations; the synchronous results were
> identical in 15/15 runs), while asynchronous discard
> followed by a quick unmount removes nothing. A prototype that assumes crc32c accepts no tree
> block on xxhash64, sha256 or blake2b images. The scan validates a fully metadata-dense image at
> 512 MB/s. File-level recovery is not evaluated here.

(≈ 210 words. Pointers: 31/30/35 EXP-002 §6.3 (measured with `--full-sweep`); 8.7 % EXP-000 §6;
2 of 35 EXP-002 §8; identical in 15/15 runs: the sync rows of EXP-000 §6 and EXP-002 §6.3 have
min = max; crc32c EXP-001 §6; 512 MB/s EXP-003 §6.1, median of the 100 % cold cell, 512.2. Scan
coverage: the targeted default skips agreeing DATA chunks, `src/btrfska/scan/regions.py` docstring.)

### 3.3 Abstract B — aspirational, for the full paper after M3–M7 (NOT supported yet)

> **Every bracketed value is a placeholder. Do not quote this abstract anywhere until each claim
> has an EXP record (§8).**
>
> Btrfs's copy-on-write design leaves a graph of historical metadata on disk: superseded tree
> blocks, item remnants beyond a node's item count, backup and discovered old roots, and residue of
> relocated chunks. Existing tools salvage files from historical roots or list deleted files from
> them. We instead reconstruct filesystem history as a validated evidence catalog in which every
> artifact carries its provenance and a confidence tier derived from explicit evidence rules. The
> method validates every tree-block copy, discovers old roots across every device range, rebuilds
> historical chunk maps, recovers content from anchored roots, unreferenced blocks and orphan items,
> and derives per-inode lifecycle timelines across all surviving states. On a public corpus of
> [N] generated images spanning checksum types, compression, discard modes, balance and aging, it
> recovers [X] % of deleted files byte-exactly against [Y] % for the best of [baselines], including
> files deleted more than four transactions before acquisition that anchored methods miss. Tiers
> are calibrated against ground truth: [Z] % of Confirmed artifacts are correct. We release the
> tool, the corpus and scripts that regenerate every table.

---

## 4. Contributions and their status

Status legend: **Supported now** (evidence exists and is committed), **Partially supported** (what
exists / what is missing), **Not yet** (which milestone). "Novelty" notes say what prior art already
covers, from research.md §6 and §10.1–§10.2.

### 4.1 Planned claims C1–C7 (plan.md §1)

| Claim | Status | Evidence now | Missing |
|---|---|---|---|
| **C1** Recovery from what no current tree references: whole superseded tree blocks (orphan nodes) and the kernel's ORPHAN_ITEM (0x30). **Narrowed on 2026-09-21 by EXP-005:** items beyond `nritems` and node slack are *not* a recovery source on a filesystem written by Linux 4.9 or later | **Partially supported** (M4 done, 2026-09-21): one scenario, one host | EXP-006 (N = 5 builds of a 93-generation, unbalanced history; hashes against the scenario's own log): the current and the four backup roots recover 0 of 24 deleted files, discovered states recover 21 (21–21), orphan file-tree leaves add none (a victim's leaf and its generation's root tree are allocated side by side and die together); **8 of 8 files that were fsynced and deleted within one transaction come back only from leaves of dropped log trees**, which no root tree ever named; a file unlinked while open comes back through the kernel's ORPHAN_ITEM with the name it had. Orphan file-tree leaves hold versions that were never committed (`sync` writes leaves, then the commit rewrites those that change). EXP-005: the kernel zeroes the slack of every tree block before it writes it (`prepare_eb_write`, v7.0 `fs/btrfs/extent_io.c:2215`; since v4.9). On 14 images, 2 078 kernel-written blocks (2 044 leaves, 34 internal nodes; live, backup-reachable, unreferenced, inside and outside the chunk map) hold 28.8 MB of slack with no non-zero byte; 1 500 superseded-successor pairs, none with content. The only slack content found is what `mkfs.btrfs` leaves behind (81 of 329 mkfs-written blocks): stale extent-, chunk- and device-tree items, never a file's. The prototype's "leaf slack" finds on `sandbox.img` are these mkfs remnants | Aged, balanced and discard-enabled filesystems (M7); how long dropped log leaves survive under churn; a baseline run (whether `btrfs-find-root -o` plus `btrfs restore` can read a dropped log tree is UNVERIFIED). Since M5, data extents of an older state are read through the chunk map of its own time (C6), and `recover --graph` joins orphan blocks on stated evidence: 88 % of the orphan leaves of the same scenario hang under tree versions that were written and replaced within a transaction, and **a leaf written within a transaction can hold new data next to a stale inode item**, so such files are no longer called complete (EXP-008: no wrong join among 22 logged files, 37 518 padding files and 2 875 multi-leaf files per build, N = 5). Slack recovery on a pre-4.9 filesystem is prior work (Bhat & Wani, 2018) and untested here; do not claim it |
| **C2** Free-space-tree forensics and overwrite-risk scoring | **Not yet (M6)**; plan.md §8 suggests a possible second paper | Nothing | Parser for FREE_SPACE_INFO/EXTENT/BITMAP, item keys 198–200 (0xC6–0xC8; kernel v7.0 `include/uapi/linux/btrfs_tree.h:266,272,280`), risk score, EXP |
| **C3** Full-state, multi-source, per-inode lifecycle timelines | **Partially supported** (M5 done, 2026-09-21): implemented and checked against ground truth on three fixed images; **no experiment record, no baseline run yet** | `btrfska timeline` compares every cataloged state (current, backup roots, roots only the scan found) and, on request, what was never committed (fragments, lone leaves, log trees filed under the subvolume their log root names). Identity is (tree, inode number, creation generation): on `sandbox.img` inode 257 is two files, each created and deleted between states the superblock names, where the prototype reports one renamed file. Events: create, modify with the byte ranges whose extent differs, rename, move, link, unlink, attr, delete bounded by two states, `not_seen` when the later walk has gaps. On `m4_deep` (one build): 21 of 24 victims have exactly one create and one delete, 18 of the deletes bounded to a single generation, each with the SHA-256 the guest logged; 8 of 8 files fsynced and deleted within one transaction appear as `never_committed` (catalog.md M5d; `tests/test_timeline.py`) | An EXP record with five builds; the comparison with SecurityRonin's `recover_deleted` and a Beyond Carving-style objectid-set diff on the same images (M7); aged and concurrent workloads. Several changes between two surviving states show as their net effect. Two root trees of one generation can survive and cannot be ordered by generation: such events are flagged `order_assumed`. Wall-clock times are copied from inode items and are user-settable. Positioning as corrected on 2026-09-15: Beyond Carving also diffs historical root trees it discovers by scanning, not only the backups (§5.3; research.md §10.12), and the prior-art re-run of 2026-09-21 found nothing new (research.md §11) |
| **C4** Evidence-rule-derived confidence tiers with provenance chains, csum-tree-verified content | **Not yet (M6)**, prerequisites exist | Per-copy validation records (12 checks), per-extent read records, failure classes (`reused`, `mismatch`, `corrupt`, `overwritten`, `zeroed`, `unreadable`, `unmapped`) (README; catalog.md M1b, M1c, M2b) | Tier rules, EXTENT_CSUM verification, calibration EXP |
| **C5** Hiding detection for the Toolan & Humphries and Schwietert & Hilgert technique lists | **Not yet (M6)** | Candidate hiding places reported as problems but never evaluated: divergent DUP mirror 2, csum bytes that crc32c does not cover, non-zero bytes past `ram_bytes`, slack after compressed streams (research.md §10.8, §10.9). A rule with evidence: a checksum-valid block with non-zero slack was not written by the kernel (EXP-005); on an honest image only mkfs-written blocks have it, 3 to 6 per image here, so the detector must recognise mkfs remnants or it raises false alarms on every image | Detector, fishy-generated images, false-positive rate |
| **C6** Btrfs orphaned/relocated-chunk forensics and historical chunk-map reconstruction | **Supported on one scenario** (M5a, EXP-007, 2026-09-21; N = 5 builds per discard mode) | One chunk map per surviving chunk-tree root, stored as evidence, never merged into the current map; every read names the map it went through. After a full balance (3 of 3 chunks relocated), without discard and with async discard and a quick unmount: 34 of 35 states have a chunk root other than the current one; 81 of 81 file versions that the current map leaves `unmapped` (two logged files, in a subvolume and its snapshot, across 34 states) read complete through the map of their state's own time and carry the SHA-256 the guest logged before the balance; every valid tree block outside the current map (172, range 172–174) is placed by the map of its own time, which checks the maps against the blocks' own header addresses; every stripe of every historical chunk (56) is confirmed by a DEV_EXTENT, and the map built from DEV_EXTENTs alone equals the CHUNK_ITEM maps (8 of 8 chunks). With `discard=sync` nothing is gained: no pre-balance state survives. On `sandbox.img` the 20 valid orphans outside the chunk map are blocks of the two temporary chunks `mkfs.btrfs` creates and removes, placed by the maps of generations 1 to 5: not traces of a balance | **Prior art to state:** rebuilding *a* chunk map by scanning is what `btrfs rescue chunk-recover` and btrfs-rec do for repair; chunk-recover keeps one record per key, the newest, and writes a new chunk tree (source read at v7.1, research.md §11.3). The claim is the superseded records, one map per generation, as evidence. **Open:** one scenario, seconds old, single device, SINGLE and DUP, one-leaf chunk trees; striped and multi-device rules are tested on forged items only; freed space that is reused inside a surviving chunk is invisible to the maps, so "every byte was read" needs the data checksums of M6 before it means "the file's bytes"; the stale remap tree as a relocation log is untouched. Use "20 valid" or "21 legacy-defined" for the sandbox, see Appendix A item 6 |
| **C7** First public Btrfs *image* corpus with per-file ground truth spanning checksum, compression and discard axes, and a systematic tool benchmark. Only this qualified "first" holds: Wani & Bhat (2018, *Data in Brief*) published a Btrfs forensic dataset as in-article tables without disk images, and Schwietert & Hilgert (2025) a data-hiding corpus with ground truth whose repository was offline on 2026-08-17 (research.md §4.3, §4.4, §5.1) | **Partially supported** | Rootless generator `corpus/vm/`, `corpus/manifest.tsv` (18 images; `m4_deep` logs a SHA-256 for each of its 33 deleted files), EXP scripts under `experiments/` | Matrix corpus (plan.md M7), per-file ground truth at scale, baseline harness, Zenodo release; cite both prior datasets. `CHECK:` repeat the corpus search of research.md §5.1 before submission |

### 4.2 Contributions that emerged from M0–M2

| # | Candidate contribution | Status | Evidence | Honest scope and what is missing |
|---|---|---|---|---|
| N1 | **A validated forensic read path** that records every check on every physical copy of every tree block and refuses unsupported incompat bits | **Partially supported**: btrfska's side has committed evidence; the comparison with dissect.btrfs 1.10 has no committed script (§8 row 5, Not ready) | EXP-001 (0 rejected blocks, 10/10 files byte-identical on four csum types); oracle tests, 152 of 152 file reads equal (catalog.md M1c, `uv run pytest -q tests/oracle`); walks equal `dump-tree` block by block (`test_walks_match_dump_tree_block_by_block`, catalog.md M1b); `m1_unknown_incompat` refused with exit 2; `m1_badnode_both` reported as `invalid_node` | The dissect.btrfs observations (no checksum, header-field or incompat-bit validation; an unknown incompat bit opens; zero-filled unmapped reads) come from manual tests in research.md §10.2 and §10.9, with no committed script. No comparison enters the paper until a small script and an EXP record are committed (plan.md §7). Validation of known formats is not novel in itself (btrfs-progs, rustutils validate); the contribution is a forensic read path that records every check per copy |
| N2 | **DUP-mirror provenance** and the kernel's read/repair policy | **Partially supported** | btrfska reads and validates every copy and reports divergent valid copies (`m1_badnode`, catalog.md M1b). Kernel policy read from v7.0 source: DUP reads mirror 1 and falls back only on failure; RAID1/1C3/1C4/10 pick a stripe by PID under the default `pid` policy; a fallback read on a read-write mount rewrites the failed mirror (research.md §10.8) | The kernel behaviour is read from source, not measured. On the corpus all 144 DUP pairs were identical (research.md §10.8), so no natural divergence was observed. The hiding-place hypothesis is untested (M6) |
| N3 | **Foreign superblock copies** as evidence of a previous filesystem | **Partially supported** | Selection anchors the fsid on the first valid copy, following btrfs-progs recover mode, and reports foreign copies (`m1_foreign_mirror`, catalog.md M1a review fixes; research.md §10.7) | btrfs-progs already skips foreign copies; the new part is reporting them as evidence. One synthetic image; no real reformatted device. Tree blocks of a foreign fsid are not scanned at all (README "Limitations"; planned M6) |
| N4 | **LZO decode success is not evidence of correct content** (measured) | **Supported now**, small | Committed harness `tests/oracle/lzo_hostile.py`, seeds 1–5: 227 (218–231) of 300 bit-flipped 4 KiB streams decode to wrong bytes within the bound in btrfska, lzallright and dissect.util native; dissect.util's native decoder raises a non-`Exception` panic on 37 (31–46) (catalog.md M1c review fixes table) | LZO has no integrity check by design, so the qualitative point is known; the contribution is the measurement and the design rule that follows (decode success never raises confidence). There is no EXP record yet: promote the harness to one. `TODO:` consider reporting the dissect.util panic upstream before publication |
| N5 | **Old-root discovery beyond the backup roots, including states outside the current chunk map** | **Partially supported** | 31 candidate root-tree blocks (states) beyond the 4 backup states on every s01 image without trims, 30 complete; generations 3–16 have no block the current chunk map places (EXP-002 §6.3, §6.5; research.md §10.11) | Discovering roots beyond the backups is **not new**: `btrfs-find-root` does it, and Beyond Carving's Algorithm 3 scans the chunk-mapped tree regions for root-tree blocks (`docs/papers/pandey_beyond_carving_2026.pdf` §VI.E.1). What is ours: scanning unmapped gaps (and DATA with `--full-sweep`), per-copy validation, the candidate definition (N8), completeness and failure classes. Survival is a balance and short-life artefact (EXP-002 §6.5). **Measured against find-root in EXP-004 (predictions registered first, all three held on 13 of 13 images): find-root printed 229 of 229 states inside the current chunk map and 0 of 133 outside it; an added image with a two-level root tree gave 11 of 11 and 0 of 1 (EXP-004 §6.7). The claim is therefore discovery *outside the current chunk map*, nothing more.** A Beyond Carving-style scan as a third column is still open (M7) |
| N6 | **Discard's effect on surviving metadata history** | **Supported now, as an observation** | EXP-000 (N = 15): sync keeps 8.7 % of stale blocks; async with a quick unmount equals no discard. EXP-002: under sync, 2 of 35 candidate root-tree blocks, 0 backup-reachable blocks, 6 of 14 distinct slot blocks survive; no block freed by the kernel during the scenario survives | Virtio TRIM on a sparse raw file, not an SSD; one scenario; quick unmount only; mechanism read from source. `TODO:` survey prior work on TRIM and SSD forensics (research.md has none) before claiming novelty |
| N7 | **Tools that assume crc32c silently find nothing on other checksum types** | **Supported for the legacy prototype only** | EXP-001: legacy accepts 0 blocks and lists 0 files on xxhash64, sha256 and blake2b images (rejects 368, 402, 368) | Framed as a regression proof of our own prototype, it is weak. Generalising needs baseline runs (M7). research.md §10.2 notes SecurityRonin's README mentions crc32c only, and §10.6 item 9 reads crc32c-only verification in the `btrfs-core` 0.1.5 crate source: neither was run, so do not claim they fail |
| N8 | **A candidate-root definition hardened against a planted higher-level block** | **Partially supported** | Candidates are unreferenced blocks at any level; a planted checksum-valid owner-1 level-7 block no longer hides the real roots of its generation, and is flagged `level_consistent: false` (catalog.md M2b review fix 4; `test_a_planted_higher_level_block_does_not_hide_the_root_tree_leaves_of_its_generation`) | One attack class, synthetic tests only. A residual vector is documented: a forged newer parent can still mark an older block as referenced (catalog.md M2b review fix 4). The "highest level per generation" rule it replaces is the one find-root and Beyond Carving use. Do **not** call it "forgery-resistant" (§13) |
| N9 | **Generation-based "stale" or "orphan" definitions are wrong in both directions** | **Supported now** | On `sandbox.img` the prototype's 71 generation-defined orphans reconcile as 8 live + 34 backup-reachable + 28 unreferenced + 1 invalid, and 2 current-generation unreferenced copies are missed (catalog.md M2a; `tests/test_scan_classify.py`). On none/async s01 images, 355 stale = 10 live + 24 backup-reachable + 316 unreferenced + 5 invalid (EXP-002 §6.1) | Small images; the kernel mechanism (`should_cow_block`, ctree.c:621-625) is read from source |
| N10 | **Backup roots reach little of the surviving history** | **Supported now, on this corpus** | 24–26 of 338–371 orphans (7 %) on the s01 images are backup-reachable; 34 of 64 (53 %) on `sandbox.img` (research.md §10.10) | Small quiescent images, one scenario, no discard. The comparison is to *backup-root* tools (SecurityRonin `recover_deleted`, `btrfs restore` without find-root), not to Beyond Carving (Appendix A item 1) |
| N11 | **Log-tree blocks need their own validation rule** (owner −6, generation exactly superblock + 1), which makes superseded log commits visible | **Supported, one image** | `m2_logtree`: the scan classifies exactly the blocks `dump-tree` names as live log blocks; log generation 9 holds 4 blocks, 2 live and 2 superseded (research.md §10.10, §10.11) | One crafted power-off image; research.md §6 rates G9 value "unproven". Probably a paragraph, not a headline |
| N12 | **Tree-block slack is empty on any modern filesystem, and what is not empty was not written by the kernel** | **Supported now** | EXP-005 (prediction registered from the v7.0 source before measuring): 0 non-zero slack bytes in 2 078 kernel-written blocks on 14 images; 24 pairs in which the kernel rewrote an mkfs-written leaf with stale slack, the successor empty in all 24; never-mounted controls show `mkfs.btrfs` 6.6.3 and 7.1 leave stale items in about a third of their blocks. Corrects the mechanism in Toolan & Humphries (2026): copy-on-write copies the slack (`copy_extent_buffer_full`, `ctree.c:511`), the write path zeroes it, for leaves as well as internal nodes | One kernel (7.0), one nodesize, 34 internal nodes on one image; kernels between 4.9 and 7.0 read from the commit history, not run; no pre-4.9 image, so "slack content survives on old filesystems" is inferred, not measured. Other btrfs-progs writers (`check --repair`, `btrfstune`, `convert`) are UNVERIFIED. One registered prediction failed (mkfs blocks were expected to be clean) and is reported as such |
| N13 | **Files that never were in a committed tree: dropped log trees and mid-transaction leaves as recovery sources** | **Supported, one scenario** | EXP-006: 8 of 8 fsynced-then-deleted files recovered, hash-exact, only from log-tree leaves that the next commit dropped (owner −6, not reached from the superblock's log root), in 5 of 5 builds; 0 of 8 under any of 78–80 root trees. Orphan file-tree leaves on every corpus image hold uncommitted versions (catalog.md M4d: `large_target.txt` at size 0 with its 5 MiB extent already attached) | One short scenario, no discard, no churn beyond its own; a log leaf does not say which subvolume it logged; no baseline tool was run on it. The definition of "orphan" matters: against the 4 backup roots many more files look orphan-only; here it is against every ROOT_ITEM in every root-tree leaf the scan found. An earlier version of our own tool got this wrong through a 64-state bound (catalog.md M4d) |

**Recommended headline set for the M2-stage paper:** N1, N5 (with N8 and N9 as method details), N6
and N10, with C6 as partially supported. N2, N3, N4 and N11 fit in discussion. Everything in §4.1
other than C6 and C7 is future work until M4–M6 land. **After M5 (2026-09-21):** C1 (EXP-005,
EXP-006, EXP-008) and C6 (EXP-007) have file-level results on one scenario each; C3 is built and
checked but has no experiment record yet; C2, C4 and C5 are still M6.

---

## 5. Section-by-section outline with draft prose seeds

Prose below is a seed, written to the evidence. Keep the qualifiers when editing.

### 5.1 Introduction

- Motivation: CoW filesystems keep superseded metadata; Btrfs is the default on several
  distributions (**`TODO:` cite a source; research.md has none**).
- The examiner's questions: what existed, when, what changed, what is recoverable, how
  confidently (plan.md §1).
- Gap: salvage and deleted-file listing exist; a validated account of *which historical metadata
  survives, where, and in what state* does not (research.md §6).
- Research questions for the M2-stage paper (§5.6).
- Contribution list (§4, recommended headline set).

**Seed.**
Copy-on-write filesystems never modify live metadata in place. When Btrfs changes a file, it
writes new copies of the tree blocks on the path from the changed leaf to the root and commits the
change by overwriting the superblock, the only structure written in place (Rodeh et al., 2013). The
superseded blocks remain on the device until the allocator reuses them or a discard trims them.
They are a record of earlier filesystem states, but the superblock names only the current state
and four backup roots.

Existing tools use this record in two ways. Salvage and deleted-file recovery locate historical
root-tree blocks by scanning and walk the trees they name: `btrfs-find-root` with `btrfs restore`,
and the method of Pandey et al. (2026). Forensic libraries such as `SecurityRonin/btrfs-forensic`
compare an older filesystem tree reached through a backup root with the current one. Each answers
"which files can I get back?". None reports how much of the metadata history survives, where it
lies on the device, whether each copy is intact, and why the rest is missing. Those are the facts
an examiner needs before trusting a recovered file. `TODO:` verify this sentence against each tool
once the M7 baselines run; soften it if one of them reports any of this.

**Contributions (current evidence).** `TODO:` final wording after the owner picks the headline set.
1. A read-only, validating reader and device scan (metadata chunks, unmapped gaps and, in a full
   sweep, data chunks) for Btrfs images that records every check
   on every physical copy and classifies each tree-block copy by reachability (N1, N9).
2. Old-root discovery that covers ranges outside the current chunk map, uses a candidate
   definition hardened against planted higher-level blocks, and reports completeness and a failure
   class for every missing block (N5, N8, C6 partial).
3. Measurements, on generated kernel-7.0 images, of how much metadata history survives without
   discard and with asynchronous or synchronous discard (N6, N10).
4. Scripts and a generator that regenerate every number (C7 partial).

### 5.2 Background (Btrfs on-disk essentials only)

Cover exactly what the method needs. Sources: Rodeh et al. 2013; research.md §4.6, §10.3, §10.7,
§10.8; kernel v7.0 line references as recorded in the catalog.

- **CoW B-trees.** Keys `(objectid, type, offset)`; leaves with items growing forward and data
  backward; internal nodes with key pointers that carry the child's bytenr and expected
  generation. Every modification copies the root-to-leaf path. A block already written to disk
  (header flag WRITTEN) is copied again on its next change, even in the transaction that created
  it, while a block created in the running transaction and not yet written is modified in place
  (`should_cow_block`, ctree.c:621-625). So one transaction can orphan its own blocks (research.md
  §10.10).
- **Trees.** Root tree (1), extent (2), chunk (3), dev (4), fs (5), csum (7), uuid (9), free space
  (10), block-group tree (11), subvolumes (≥ 256), log trees (owner −6). Only 1 is named directly by
  the superblock, together with the chunk and log roots.
- **Superblock and backup roots.** Copies at 64 KiB, 64 MiB, 256 GiB; the kernel mounts mirror 0
  only (disk-io.c:3333). Four `btrfs_root_backup` slots in a ring, so slot order is not generation
  order (disk-io.c:1596-1607; `sandbox.img` holds gens 13, 14, 11, 12 in slots 0–3). Each slot
  names six trees; subvolume trees are reachable only through each backup root tree's ROOT_ITEMs
  (research.md §10.7).
- **Chunk tree and logical→physical mapping.** The bootstrap `sys_chunk_array` in the superblock,
  then the chunk tree. A balance or chunk removal drops chunk items and device extents, so the
  current map no longer places blocks written before it (research.md §10.8).
- **Profiles.** SINGLE, DUP, RAID0/1/1C3/1C4/10/5/6; metadata is DUP by default on one device. Read
  policy per profile: `N2` background, research.md §10.8.
- **Checksums.** crc32c, xxhash64, sha256, blake2b-256 over `[0x20:]` of superblocks and tree
  blocks, and per data sector in the csum tree. They are unkeyed: they detect accidental damage,
  not forgery (§5.4).
- **Log tree.** Written at fsync, generation = last committed generation + 1, freed at commit
  (research.md §10.10).
- **Discard.** `discard=async` is enabled automatically since 6.2 on discard-capable devices, tracks
  data-only block groups, delays 120 s (10 s for unused groups) and drops its queue at unmount;
  `discard=sync` trims every range unpinned at each commit, metadata included (research.md §10.3;
  extent-tree.c:2997-3005).
- **Feature evolution.** Block-group tree (default in btrfs-progs ≥ 6.19); experimental remap tree
  and RAID stripe tree, which a reader must refuse rather than misread (research.md §10.3).

**Seed (backup roots).**
The superblock keeps four backup roots, written as a ring: each commit overwrites the slot after
the newest one. A backup root names the root, extent, chunk, device, filesystem and checksum tree
roots of a recent transaction. Two details matter for forensics. The slot order is not the
generation order, so tools must sort by generation. And the filesystem-tree slot names only
subvolume 5: on every image of our scenario, all four slots name the same generation-19 tree,
while the writes and deletions happen in a subvolume reachable only through each backup's root
tree (research.md §10.7).

### 5.3 Related work and positioning

Sources: research.md §2, §4, §6, §10.1, §10.2; plan.md §1 and §8.

- **Beyond Carving** (Pandey et al., 2026, IEEE Access). Deterministic deleted-file listing and
  extent-accurate recovery. **Its discovery is not bounded by the backup roots**
  (`docs/papers/pandey_beyond_carving_2026.pdf`; correction recorded in research.md §10.12). Algorithm 3 runs "for
  each candidate tree block b in mapped tree regions", keeps owner-1 blocks with a generation below
  the current one and, per generation, the highest-level block; §VI.E.1: the method "scans
  filesystem regions mapped to Btrfs tree blocks using the chunk tree". §X.G: discovery "does not
  depend on the active root pointer stored in the superblock"; a fallback to a backup superblock
  copy is named as an extension, not implemented. It processes each subvolume through each
  historical root tree's entries (§VI.E.2). Traversal prunes on generation, blockptr and level
  (Algorithm 2, §X.G); the paper describes no tree-block checksum validation. The chunk parser reads
  the first stripe of each chunk item (§X.H.7; its log prints "2 stripes detected, processing 1").
  Stated future work: deep leaf scanning, historical chunk trees, deleted subvolumes, checksum-tree
  validation (research.md §4.1). No code released: the repository is empty (research.md §10.1).
- **`SecurityRonin/btrfs-forensic`** (Rust, 2026). Graded findings, backup-root divergence,
  kernel ORPHAN_ITEM listing. `recover_deleted()` is backup-root-bounded (all four slots, FS tree 5
  only): it iterates the four `btrfs_root_backup` slots, reads each slot's `fs_root` as one node and
  diffs its inodes against the current FS tree. Chunks map through stripe 0. The superblock
  checksum is verified for crc32c and reported as `None` for the other types; node checksums are
  computed as crc32c and reported without gating recovery (source at commit `e6cd73f`, read
  2026-09-15: `forensic/src/lib.rs` `recover_deleted`, `core/src/crc.rs`, `core/src/node.rs`,
  `core/src/chunk.rs`; research.md §10.2, §10.12). Not run by us.
- **btrfs-progs `restore` and `btrfs-find-root`.** Salvage; find-root groups scanned blocks by
  generation and highest level (research.md §2.1).
- **btrfscue v0.7.** Indexes FSID-matching leaves into a database; recovers unreferenced
  subvolumes (research.md §2.4, §10.2).
- **The Sleuth Kit.** Experimental Btrfs on `develop` since PR #3065 (2024-11-27), unreleased;
  the FKIE fork (Hilgert et al., 2017, 2018) supports pooled and multi-device Btrfs (research.md
  §2.3, §10.2).
- **btrfs-rec** (`rebuild-trees`) for graph-based reattachment, cited as prior art for M5
  (research.md §2.5).
- **Bhat & Wani (2018); Wani & Bhat (2018).** Orphan items beyond the item count; recoverability
  depends on node merging vs redistribution, aging and file size (`CHECK:` size bands, Appendix A
  item 9). No historical reconstruction. Since Linux 4.9 the kernel zeroes that area on every
  write (EXP-005), so the technique applies to older filesystems only. The dataset paper used
  Fedora 23 with kernel 4.2; the 2018 analysis paper does not name its kernel (`CHECK:` ask the
  authors or find it before saying their results depend on a pre-4.9 kernel).
- **Wani, Bhat & Dehghantanha (2020).** Anti-forensic slack locations; W1/W2 corrupt the
  filesystem, W3–W5 hide silently (research.md §8.4).
- **Hilgert et al. (2017, 2018, 2024); Hilgert PhD (2025).** Pooled and multi-device analysis
  model; routes to deleted files via snapshots and the four backup roots.
- **Toolan & Humphries (2026, FSI:DI 58:302198).** Six Btrfs hiding techniques (the C5 target
  list), none detected by TSK 4.14, `btrfs check` or `dmesg`; they name a detection toolkit as
  future work. Their superblock reserved range is a pre-5.0 layout (research.md §10.13). **Schwietert & Hilgert (2025, 2026).** Hiding corpus and
  ghost slack on CoW filesystems.
- **CoW analogs.** ReFS: Prade et al. (2020), Bonnet (2026) `forefst` with node-slack scanning
  and recoverability verdicts. F2FS: Oh & Hwang (2025) address-table rebuild. APFS: Plum & Dewald
  (2018). ZFS: Beebe et al. (2009).
- **Low-tier Btrfs recovery papers.** MetaRecoverX (2026), Pratyashrit et al. (2026): carving
  with metadata; cite briefly.
- **Evaluation methodology.** Kim et al. (2021): before/after images, recovery rate, hash match.

**Positioning seed (Appendix A item 1 resolved on 2026-09-15).**
Historical-root discovery by scanning is established: `btrfs-find-root` does it for salvage, and
Pandey et al. (2026) use it to list deleted files per subvolume. Pandey et al. scan the regions the
current chunk tree maps to tree blocks, and both keep, per generation, the highest-level owner-1
block. find-root's range is now read from its source and measured (EXP-004): it enumerates the
metadata block groups of the *current* chunk map and reads them through that map, so on 13 images
it printed every state inside the map (229 of 229) and none outside it (0 of 133). Our discovery differs in four ways. It also scans ranges no current chunk covers,
where relocated and removed chunks used to be. On our scenario, the root-tree blocks of generations
17–34 lie in the current metadata block group, where a scan of chunk-mapped regions could reach
them, while the 13 states of generations 3, 6, 7 (two blocks) and 8–16 lie only outside the current
chunk map (EXP-002 §6.3, §6.5). It validates every copy and keeps invalid ones as evidence. It treats every
unreferenced block at any level as a candidate, so a planted higher-level block cannot hide the
real roots of its generation. And it reports, for every state, how many referenced blocks were
found and a failure class for each one that was not. `TODO:` whether Algorithm 3 as implemented
would miss states in unmapped gaps is inferred from the paper's text; the code is not released, so
state it as "by its description".

**Claim matrix (Table 1 draft).** ✓ = does it; ✗ = does not; ? = unknown or not checked; "—" = not
applicable. Every non-btrfska cell must be verified before submission.

| Capability | find-root + restore | Beyond Carving | SecurityRonin | btrfscue v0.7 | TSK develop | btrfska (M2) |
|---|---|---|---|---|---|---|
| Historical roots beyond the 4 backups | ✓ (scan) | ✓ (scan of chunk-mapped tree regions, Alg. 3; independent of the superblock root pointer, §X.G) | ✗ (backup-root-bounded: all four slots, FS tree 5 only; `forensic/src/lib.rs`) | ? | ? | ✓ (metadata chunks and unmapped gaps; DATA with `--full-sweep`) |
| Scans outside the current chunk map | ✗ (source and EXP-004: 0 of 133 outside-map states printed) | ✗ by its description | ✗ | ? | ? | ✓ |
| All four csum types validated | ✓ (prints the same root-tree blocks as btrfska on the crc32c, xxhash, sha256 and blake2b images, EXP-004) | ✗ (no tree-block checksum validation described; Alg. 2 prunes on generation, blockptr, level) | ✗ (superblock: crc32c, others `None`; node crc32c status does not gate recovery) | "crc32c-era assumptions" (research.md §2.4) | ? | ✓ (EXP-001) |
| Every mirror copy validated and reported | ✗ (research.md §10.8) | ✗ (first stripe only, §X.H.7) | ✗ (stripe 0, `core/src/chunk.rs`) | ✗ (no RAID) | ? | ✓ |
| Completeness and missing-block classes per state | ✗ | outcome taxonomy per file | ✗ | ✗ | ✗ | ✓ (tree level) |
| File-level deleted-file recovery | ✓ | ✓ | ✓ | ✓ | ? | ✗ (M4) |
| Timelines | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ (M5) |
| Confidence tiers with provenance | ✗ | taxonomy | severity grades | ✗ | ✗ | ✗ (M6; records exist) |

### 5.4 Threat model and forensic-soundness requirements

- **Setting.** An examiner holds a raw image of a Btrfs device (or devices). The tool must never
  mount or write the evidence.
- **Adversary and damage.** The image may hold accidental corruption, residue of an earlier
  filesystem, blocks from uncommitted transactions or log commits, and deliberately crafted
  structures. Btrfs checksums are unkeyed, so an attacker can plant checksum-valid blocks
  (`m1_foreign_mirror` recomputes a sha256 superblock csum; the planted level-7 block test).
- **Out of scope now.** Encrypted extents, remap-tree and RAID-stripe-tree images (refused),
  degraded RAID5/6 parity reconstruction, flash-level acquisition.

| Requirement | Mechanism | Evidence |
|---|---|---|
| R1 read-only | One open site, `O_RDONLY` + `ACCESS_READ` mmap; AST test bans other write-capable calls; session hash guard on `sandbox.img` | `tests/test_readonly.py`; catalog.md M0; every verification table (sha256 unchanged) |
| R2 validate before trust | 12 checks per copy; invalid nodes are records, never parsed for items | README "`btrfska walk` output"; catalog.md M1b |
| R3 provenance on every record | `root.via`, chunk-map source, per-copy checks, per-extent ranges and copies | README record schemas |
| R4 never collapse ambiguity | Every candidate emitted, invalid ones included; every candidate root reported; divergent mirrors reported | catalog.md M2a, M2b |
| R5 refuse loudly | Incompat gate: unknown bits and RST/ETv2/REMAP refused with `UNSUPPORTED_INCOMPAT`, exit 2 | `m1_unknown_incompat` (catalog.md M1a) |
| R6 bounded cost on hostile input | Streaming classification; at most 64 states and 256 classified missing blocks per state; memoised subtree walks; extent lengths bounded by the image size | `tests/test_scan_hostile.py`; `test_shared_subtrees_with_dangling_pointers_cost_one_walk_not_one_per_root`; `test_extent_lengths_beyond_the_image_are_rejected_quickly_in_bounded_memory` |
| R7 reproducibility | EXP records, committed scripts, manifest hashes, environment records | plan.md §7 |

**Seed.**
A checksum in Btrfs protects against accidental damage, not against an adversary: every algorithm
it supports is unkeyed, so anyone who alters a block can recompute its checksum. We therefore treat
a valid checksum as a necessary condition for trusting a block's contents, never as proof of where
the block came from. Structural relations do more of that work: a block is part of a state only if
a parent of its generation or a newer one points to it with its address and generation, and the
tool reports blocks whose level contradicts the blocks their pointers name.

### 5.5 Method (architecture as actually built)

Only layers 1 and 2 of plan.md §2 exist, plus the CLI's JSON records. Do not describe the SQLite
catalog, recovery engines, tiers or GUI as built. Code: 5 826 lines of Python under `src/btrfska/`
at `8034a75` (`find src/btrfska -name '*.py' | xargs wc -l`); 724 tests passing at the M2b review
verification (catalog.md M2b "Review fixes", `uv run pytest -q`). The 724 include the 37 tests of
the frozen prototype under `legacy/tests`, which `pyproject.toml` `testpaths` collects (`uv run
pytest --collect-only -q legacy`: 37), so 687 test btrfska.

**5.5.1 Substrate (layer 1).** `src/btrfska/substrate/`.
- `image.py`: the single read-only open site.
- `fs.py`: opens an image the way the kernel's `open_ctree` does, read-only: superblock selection
  and incompat gate, bootstrap map from the sys_chunk_array, chunk root, and the current chunk map
  cross-checked against the sys_chunk_array.
- `superblock.py`: all mirrors; magic, bytenr and csum checks; part of `btrfs_validate_super`'s
  geometry checks; selection follows btrfs-progs recover mode (anchor the fsid on the
  lowest-offset valid copy, then highest generation), not the kernel (mirror 0 only); foreign
  copies reported; backup roots sorted by generation; incompat gate.
- `csum.py`: the four checksum types, per kernel `btrfs_csum()`.
- `ondisk.py`: own `struct` layouts, every value asserted against kernel v7.0 headers.
- `chunks.py`: stripe math for every profile; invalid chunk items rejected and reported; RAID5/6
  data stripe only.
- `node.py`: `check_block` with 12 checks in order (`csum`, `bytenr`, `fsid`, `chunk_tree_uuid`,
  `generation`, `level`, `nritems`, `written`, `layout`, `owner`, `parent_generation`,
  `first_key`); every copy read and validated; the first valid copy in mirror order used; failure
  classes for referenced blocks.
- `tree.py`, `roots.py`: depth-first walks with per-hop expectations; shared or cyclic pointers not
  followed; root sets per backup generation and current; subvolumes via ROOT_ITEM/ROOT_REF/
  ROOT_BACKREF.
- `items.py`: payload parsers for the items the walker, inventories and `btrfska walk` read; they
  raise only `ItemError` and keep undecodable name bytes (surrogateescape).
- `extents.py`, `compress.py`, `lzo.py`: extent reads through any chunk map; zlib and zstd bounded
  by the kernel's limits; the btrfs LZO framing over an own bounds-checked LZO1X decoder; failures
  are classified records, never truncated or padded output. dissect.btrfs and lzallright are test
  oracles only, never imported under `src/` (`tests/test_import_boundary.py`).

**5.5.2 Scan kernel and regions (layer 2).** `src/btrfska/scan/`.
- `regions.py`: the device minus `reserved` (0–68 KiB) and the other superblock copies, split into
  chunk stripes (typed as dump-tree prints them) and `unmapped_gap`s. DATA chunks are skipped only
  when their block-group item (tree 11 or extent tree) agrees; scanned under MIXED_GROUPS and with
  `--full-sweep`. The summary reports the bytes skipped as DATA.
- `kernel_numpy.py`: at every sector-aligned offset, the 16 bytes at +0x20 are compared with the
  tree fsid as two u64 words through strided numpy views of the read-only map, 65 536 offsets per
  window; every hit is validated without referrer expectations and kept, invalid ones included.
  Frozen interface `iter_candidate_nodes(img, regions, ctx, chunk_map)`.
- `classify.py`: walks every tree of the current root set (all subvolumes, snapshots and the log
  tree) and of each backup root set; a (logical, physical) copy is reached when the walk read that
  copy and it passed every check. Classes `live`, `backup_reachable`, `unreferenced`, `invalid`.
  Log blocks are checked in a log context (owner −6, generation exactly superblock + 1).

**5.5.3 Old-root discovery.** `src/btrfska/scan/roots.py` (README "`btrfska roots` output").
1. Index every valid candidate by (bytenr, generation, level, owner) with its physical copies;
   index log blocks under the log rule; keep invalid candidates as (bytenr, generation, physical).
2. A block is *referenced* when an indexed internal block one level up, of an owner the kernel's
   owner check accepts and of the same or a newer generation, points to it with its bytenr and
   generation. *Candidate roots* are the valid blocks nothing references, at any level.
3. Every owner-1 candidate root is a *candidate root-tree block (state)*. Its ROOT_ITEMs are
   resolved through the index by (bytenr, generation, level) and an owner the kernel's owner check
   accepts, with no first key: a ROOT_ITEM carries none, so the walk of a named tree starts without
   one. Child pointers inside a tree must also match the pointer's first key. Resolution never goes
   through a chunk map, so states whose chunks have moved still resolve (`src/btrfska/scan/roots.py`
   `_resolve` l.534, `_outcome` l.546-566, `_walk` l.702-740 with the root pushed without a first
   key at l.709, `state` l.818-821).
4. *Completeness* = found / referenced distinct blocks of the root tree and of every tree its
   ROOT_ITEMs name, except ROOT_ITEMs naming tree 1; chunk and log trees are excluded.
5. Each missing block gets the most informative failure class from: a read through the current
   map; a read through the state's own chunk items when the current map does not place it; up to
   16 invalid scanned copies with its bytenr and generation. Three statuses are not failure classes
   and are emitted too: `not_scanned` (a read through a map is valid, but the scan plan skipped that
   range), `changed` (the indexed block's bytes no longer match the scan record) and `unchecked`
   (missing pointers beyond the first 256 per state, counted without a read and not de-duplicated,
   so `referenced` is then an upper bound and completeness a lower one) (roots.py:40-50, 558, 646,
   669-675; README "`btrfska roots` output").
6. Each state's chunk root is the superblock's or backup's when they name it, else inferred (the
   newest chunk-tree candidate root no newer than the state); its CHUNK_ITEMs check where found
   blocks would be placed. No historical map is kept.
7. Bounds: 64 states evaluated (superblock and backup states first), 256 classified missing blocks
   per state, memoised per subtree.

**Seed (candidate definition).**
`btrfs-find-root` and Pandey et al. (2026) keep, for each generation, the highest-level owner-1
block. On a well-formed image that is the root of that generation's root tree. On a hostile image
it is whatever block claims the highest level: one planted, checksum-valid level-7 block of
generation G turns every real generation-G root-tree leaf into a fragment and removes that state
from the report (catalog.md M2b, review fix 4). We define candidates structurally instead. A block
is referenced when an internal block one level up, of an acceptable owner and of the same or a newer
generation, points to it with its address and generation; every valid block that nothing
references is a candidate, at any level. The planted block is then reported as a state of its own,
flagged because its pointers name blocks at another level, and the real leaves remain states. A
forged *newer* parent can still claim an older block; that block's state is then reachable from
the forged candidate, which is reported too.

**Seed (states are evidence, not proof).**
A candidate root-tree block stands for a root tree only as far as that block reaches. A surviving
leaf of a multi-leaf root tree whose parent is gone covers that leaf's ROOT_ITEMs only, and a
forged owner-1 block is a state too. We therefore report states as evidence of one root tree, never
as proof of a whole committed filesystem state, and report completeness alongside each one.

### 5.6 Evaluation

**Research questions (M2 stage).**
- RQ1: Does the reader validate and read correctly across checksum types and compression, and how
  does a crc32c-only reader fail? (EXP-001; oracle tests)
- RQ2: Does the scan cover the offsets a simple independent probe reads, and how do its classes
  relate to generation-based staleness? (EXP-002 §6.1–§6.2; research.md §10.10)
- RQ3: How many candidate root-tree blocks (states) survive beyond the backup roots, how complete
  are they, and where do they lie? (EXP-002 §6.3, §6.6; research.md §10.11)
- RQ4: How does discard change surviving metadata history? (EXP-000; EXP-002)
- RQ5: Is the scan fast enough for large images, and what bounds it? (EXP-003)

**Corpus (Table 2 draft).** `corpus/manifest.tsv` rows plus `sandbox.img`: 512 MiB s01 images
(csum types, LZO and zlib, mutations, discard trio), `m2_logtree`, and the 256 MiB crc32c
`sandbox.img` (generator unknown, plan.md §6.1). Scenario s01: create 3 files in a subvolume, sync,
read-only snapshot, delete 2 files, 6 committed churn writes, full balance; superblock generation
6 → 38 (research.md §10.4). Host mkfs btrfs-progs v6.6.3, stock 7.0.0-31-generic guest kernel under
QEMU 8.2.2.

**Seed (RQ2).**
Equal counts between the scan and the probe show coverage, not correctness. The compatibility count
is computed from btrfska's own scan plan and fsid prefilter, so agreement on 48 of 48 images shows
that btrfska reads every offset the probe reads outside blocks 0–15, matches the same 16 bytes at
+0x20 and reads the generation from the same field. It does not validate btrfska's checks, its
reachability classes or its discovery (EXP-002 §2).

**Seed (RQ3).**
On every s01 image without trims, discovery finds 35 candidate root-tree blocks: the 4 backup-root
states (generations 35–38) and 31 beyond them, one per transaction from generation 8 to 34 plus
generations 3, 6 and two blocks of generation 7. Thirty of the 31 have every referenced block
found; the generation-3 state misses its checksum-tree root, which is present but invalid (an mkfs
block without the WRITTEN flag) and is classified `corrupt` (EXP-002 §6.3, §6.6). None of the
states of generations 3–16 has a block the current chunk map places where it was scanned; each is
placed by the chunk items of its own inferred chunk tree (research.md §10.11). This survival is not
a general rate. Generations 3–16 survive because the scenario's final full balance relocated and
deleted the chunks that held them, and nothing reallocated those ranges before unmount; generations
17–34 survive because the allocator, continuing from its last allocation in a young and mostly empty
metadata block group, never returned to the blocks they freed (EXP-002 §6.5, read from the source,
not measured). An aged filesystem, one without a balance, or one whose metadata block group wraps
around would keep fewer states.

**Seed (RQ4).**
Across 15 regenerations of each configuration, synchronous discard left 31 stale blocks against 355
without discard (medians), 8.7 % of them, while asynchronous discard with an unmount about a second
after the scenario left exactly as many as no discard (EXP-000 §6). The sync and async counts were
identical in 15/15 runs, the no-discard counts in 14/15 (EXP-000 §6: 44 of 45 images gave exactly
the row medians). Discovery shows what was lost. Under sync, identically in 15/15 runs (EXP-002
§6.3), 2 candidate root-tree blocks (states) survive, the live one and the mkfs-era generation-3
state, and no block the kernel freed during the scenario survives. The 26 superblock and backup
slot references name 14 distinct blocks; 14 of the 26 references, but only 6 of the 14 distinct
blocks, survive, and the 8 lost blocks read as zeros (EXP-002 §6.3). The images are sparse raw files
behind virtio-blk, where a trimmed range reads back as zeros; an SSD may return zeros, old data or
indeterminate data for a trimmed address.

**Seed (RQ5).**
On one core, full validation of a synthetic 10 GiB image scanned at 3 277.1 MB/s cold (median of
5 runs; 3 227.5–3 337.8). That image is sparse, so the same runs divided by its allocated bytes give
1 761.2 MB/s (1 734.7–1 794.0). On dense 1 GiB images, the rate is bounded by per-candidate
validation in Python, about 27 µs per candidate: 512.2 MB/s cold when every 16 KiB slot holds a tree
block (EXP-003 §6, §6.1).

**Planned M7 evaluation (not run).** File-level recovery rate and SHA-256 exact match per source
(anchored backup roots, discovered states, unreferenced nodes, orphan items), per matrix cell,
against the baselines of §10. `TODO`.

### 5.7 Findings and discussion

Draw from §7. Practitioner implications, each already supported:
- Acquire images; never mount evidence read-write (a fallback read repairs a failed mirror,
  research.md §10.8 — source reading).
- Record the discard mode observed on the image; sync discard removes the history a scan would
  otherwise find (EXP-000, EXP-002).
- Scan unmapped gaps, and use a full sweep after a balance: pre-balance states live outside the
  current chunk map (EXP-002 §6.5; README "Limitations").
- Do not equate "generation below the superblock" with "deleted" or "orphan" (N9).
- Treat LZO (and zlib, whose adler32 the kernel skips) decode success as no evidence of content
  (research.md §10.9).
- Sort backup roots by generation, not slot (research.md §10.5).

### 5.8 Limitations and threats to validity

Summarise §11 in about 400 words. Lead with: one scenario, young and small images, tree-level
only, virtio TRIM, coverage agreement rather than independent validation.

### 5.9 Future work

M3 catalog; M4 recovery from anchored roots, unreferenced nodes and orphan items; M5 timelines,
historical chunk maps, deleted subvolumes, integrity-vs-linkage split; M6 csum-tree verification,
tiers, FST and hiding detection, foreign-fsid discovery; M7 matrix corpus and baselines; remap-tree
relocation log (experimental); Rust scan core (M8).

### 5.10 Conclusion

**Seed.** `TODO:` write last. Keep to what §6 shows: validated reading, discovery across metadata chunks and unmapped gaps (full sweep) with
completeness and failure classes, and measured survival under three discard settings on one
scenario.

---

## 6. Evaluation tables (copied from the experiment records)

Rules for this section: tables are copied verbatim from the committed record named above each one,
including caveats. Regenerate from the repo root. Raw outputs go to the gitignored
`images/scratch/exp/EXP-NNN/`.

### 6.0 Environment summary

| Field | EXP-000 / EXP-002 | EXP-001 | EXP-003 |
|---|---|---|---|
| Record | `experiments/EXP-000.md` §4; `experiments/EXP-002.md` §4 | `experiments/EXP-001.md` §4 | `experiments/EXP-003.md` §4, §6.1 |
| Date (UTC) | 2026-09-15T04:59:23Z | 2026-09-15T01:24:25Z | 2026-09-15T02:33:04Z |
| Host CPU / threads / RAM | 13th Gen Intel(R) Core(TM) i5-1335U / 12 / 15.3 GiB | same | same |
| Image storage | `/dev/nvme0n1p2` (ext4), KINGSTON OM8SEP4512Q-AA, rotational 0 | same | same |
| Host kernel | 7.0.0-31-generic | same | same |
| QEMU / guest kernel | 8.2.2 / 7.0.0-31-generic | same (no guest booted by EXP-001) | irrelevant (no guest) |
| btrfs-progs (host mkfs / guest) | v6.6.3 / 6.6.3-1.1build2 | same | same |
| Python / uv | 3.14.6 / 0.11.28 | same | same; numpy 2.5.3 |
| `uv.lock` sha256 | `08dc30c6…f097` | `803bc2de…d0a1` | `08dc30c6…f097` |
| Git commit (dirty tracked files) | `1c13b22` (0); EXP-002 review re-measurement at `8daf05f` (0) | `2deef18` (0) | `013d597` (0); **§6.1 density sweep at `1640fea` with 16 tracked files modified** (uncommitted review fixes; EXP-003 §6.1 states the measured path was unchanged except one `if expect.log` branch) |
| Oracles | — | dissect.btrfs 1.10, dissect.util 3.24, lzallright 0.2.6 | — |

### 6.1 EXP-000 — Discard survival of stale metadata

Source: `experiments/EXP-000.md` §6. Regenerate:
```sh
corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh
experiments/env.sh sandbox.img > images/scratch/exp/EXP-000/env_before.txt
uv run python experiments/exp000.py run --runs 15
uv run python experiments/exp000.py table
```
Scenario s01 on fresh 512 MiB images, `mkfs.btrfs --csum xxhash`, stock 7.0 guest. Columns are
unvalidated probe counts (`corpus/vm/probe_stale_metadata.py`): `fsid_blocks` = 4 KiB-aligned
blocks with the superblock fsid at +0x20, superblock copies skipped; `stale_blocks` = those whose
header generation is below the primary superblock's; `needle_copies` = byte-exact occurrences of
the deleted inline file's content; `nonzero_blocks` = 4 KiB blocks with any non-zero byte.

N = 15 per row. Entries are median (min–max).

| Row | N | fsid_blocks | stale_blocks | needle_copies | nonzero_blocks |
|---|---|---|---|---|---|
| none | 15 | 367 (365–367) | 355 (353–355) | 18 (18–18) | 832 (828–832) |
| async | 15 | 367 (367–367) | 355 (355–355) | 18 (18–18) | 832 (832–832) |
| sync | 15 | 43 (43–43) | 31 (31–31) | 2 (2–2) | 107 (107–107) |

Carried from the record:
- 44 of 45 images gave exactly the row medians; the exception is run 6, `none`: 365/353/18/828.
  Report this as "identical in 15/15 runs" for async and sync and "14/15" for none, alongside the
  medians.
- Effect of `discard=sync` (medians, sync against none): 11.7 % of the fsid blocks remain (43/367),
  8.7 % of the stale blocks (31/355, so 91.3 % are gone), 11.1 % of the inline-string copies (2/18)
  and 12.9 % of the non-zero blocks (107/832). The effect (324 stale blocks) is more than 150 times
  the largest observed spread (2 blocks).
- **Caveat: the "none" row's guest also mounts with `discard=async`.** QEMU 8.2 virtio-blk
  advertises discard even without `discard=unmap`, and the drive's default `discard=ignore` drops
  the requests on the host. "None" means "no TRIM reaches the image file" (EXP-000 §3).
- **Caveat: async unmounts about a second after the scenario**; an idle filesystem can trim as
  much as sync (EXP-000 §7). Not measured.
- **Construct caveat:** stale is not recoverable and not "orphan"; invalid mkfs residue and 16 KiB
  nodes counted once per header are included (EXP-000 §7).

### 6.2 EXP-001 — Checksum-type coverage: legacy prototype vs btrfska

Source: `experiments/EXP-001.md` §6. Regenerate:
```sh
experiments/env.sh sandbox.img images/scenarios/m1_xxhash.img images/scenarios/m1_sha256_bgt.img images/scenarios/m1_blake2b.img > images/scratch/exp/EXP-001/env.txt
uv run python experiments/exp001.py --runs 2
```

N = 2 runs; both were identical. With zero spread, the median and range equal the single value
shown.

| Image | csum | Tool | Tree blocks accepted[^blocks] | Tree blocks rejected[^blocks] | Files listed per generation | Distinct files byte-identical / listed |
|---|---|---|---|---|---|---|
| `sandbox` | crc32c | legacy | 85 | 1 | gen 11: 1, gen 13: 1 | 2 / 2 |
| `sandbox` | crc32c | btrfska | 27 | 0 | backup:11: 1, backup:12: 0, backup:13: 1, backup:14: 0, current: 0 | 2 / 2 |
| `m1_xxhash` | xxhash64 | legacy | 0 | 368 | none | 0 / 0 |
| `m1_xxhash` | xxhash64 | btrfska | 23 | 0 | backup:35: 10, backup:36: 10, backup:37: 10, backup:38: 10, current: 10 | 10 / 10 |
| `m1_sha256_bgt` | sha256 | legacy | 0 | 402 | none | 0 / 0 |
| `m1_sha256_bgt` | sha256 | btrfska | 25 | 0 | backup:35: 10, backup:36: 10, backup:37: 10, backup:38: 10, current: 10 | 10 / 10 |
| `m1_blake2b` | blake2b | legacy | 0 | 368 | none | 0 / 0 |
| `m1_blake2b` | blake2b | btrfska | 23 | 0 | backup:35: 10, backup:36: 10, backup:37: 10, backup:38: 10, current: 10 | 10 / 10 |

[^blocks]: The two tools count different things, so their block numbers are not directly
    comparable. **Legacy** counts hits of its sweep over targeted image regions: each physical
    offset holding an fsid-matching block is one hit (legacy/utils/btree.py:516-517 records the
    offset). Accepted hits are orphans (generation below the superblock's), including stale blocks
    that no tree references any more, plus current-generation leaves. Rejected hits fail crc32c.
    Copies of one logical block at different physical offsets are not merged. **btrfska** counts
    distinct logical addresses reached by the anchored walks of §2. Blocks that no walk reaches are
    not counted, and a block is accepted when one of its physical copies passes every node check.
    Within a tool, accepted versus rejected per checksum type is the measured claim.

Carried caveats (EXP-001 §7): the sandbox reference is dissect.btrfs, which validates no checksum,
not independent ground truth; one small image per checksum type; the deleted s01 files are reached
only through snapshot 257, so neither tool is tested on files surviving only in unreferenced blocks;
"accepted" measures the checksum gate, not recovery.

### 6.3 EXP-002 — Scanning the discard trio: coverage agreement, classes, surviving history

Source: `experiments/EXP-002.md` §6. Regenerate:
```sh
# on the regenerated EXP-000 images, before `exp000.py clean`
uv run python experiments/exp002.py run images/scenarios/s01_discard_{none,async,sync}_r{1..15}.img
uv run python experiments/exp002.py table
# the three kept images (review re-measurement, §6.6)
R=images/scratch/exp/EXP-002/review
uv run python experiments/exp002.py run --results $R/results.jsonl images/scenarios/s01_discard_{none,async,sync}_r1.img
uv run python experiments/exp002.py table --results $R/results.jsonl
uv run btrfska roots images/scenarios/s01_discard_sync_r1.img --full-sweep
```
Only the three `_r1` images are kept (hashes in `corpus/manifest.tsv`); the other 42 were deleted
and a re-run needs `exp000.py run` first.

**6.1 Coverage agreement with the probe (pre-registered).** 48 of 48 images give equal counts on
both columns: the 45 regenerated images and the 3 earlier ones. This is coverage agreement as
defined in EXP-002 §2.

| Mode | Images | Probe fsid_blocks / stale_blocks | Compatibility count | Equal | Boot-area (blocks 0–15) fsid hits |
|---|---|---|---|---|---|
| none | 15 + 1 earlier | 367/355 on 15 images, 365/353 on run 6 | identical per image | 16/16 | 0 |
| async | 15 + 1 earlier | 367/355 on all | identical per image | 16/16 | 0 |
| sync | 15 + 1 earlier | 43/31 on all | identical per image | 16/16 | 0 |

**6.2 btrfska classes per mode (N = 15, full sweep).**

| Mode | N | Candidates | Valid | Invalid | Live | Backup-reachable | Unreferenced | Valid orphans outside the map | Legacy-compatible |
|---|---|---|---|---|---|---|---|---|---|
| none | 15 | 367 (365–367) | 362 (360–362) | 5 (5–5) | 22 (22–22) | 24 (24–24) | 316 (314–316) | 172 (170–172) | 355 (353–355) |
| async | 15 | 367 (367–367) | 362 (362–362) | 5 (5–5) | 22 (22–22) | 24 (24–24) | 316 (316–316) | 172 (172–172) | 355 (355–355) |
| sync | 15 | 43 (43–43) | 38 (38–38) | 5 (5–5) | 22 (22–22) | 0 (0–0) | 16 (16–16) | 16 (16–16) | 31 (31–31) |

Walk failures: none on the none and async images; on every sync image 12 backup-root failures, all
`zeroed`, and none for the current state.

**6.3 Old-root discovery per mode (N = 15, full sweep).**

| Mode | N | Root-tree candidates | Superblock + backup slot references indexed (of 26) | … of which candidate roots | Candidate root-tree blocks (states) beyond the backups | … complete (every referenced block found) | Backup-state completeness |
|---|---|---|---|---|---|---|---|
| none | 15 | 35 (35–35) | 26 (26–26) | 26 (26–26) | 31 (31–31) | 30 (30–30) | 1 (1–1) over 60 states |
| async | 15 | 35 (35–35) | 26 (26–26) | 26 (26–26) | 31 (31–31) | 30 (30–30) | 1 (1–1) over 60 states |
| sync | 15 | 2 (2–2) | 14 (14–14) | 14 (14–14) | 1 (1–1) | 0 (0–0) | 1 (1–1) over 15 states |

Every row of §6.2 and §6.3 for async and sync, and every row of §6.3, has min = max: report
"identical in 15/15 runs" alongside the medians. The none row of §6.2 varies only through run 6's
image (365/353 in §6.1).

**Slot references are not distinct blocks** (EXP-002 §6.3). The superblock (root and chunk) and the
four backup slots (six trees each) make 26 slot references, but they name only 14 distinct blocks.
The N = 15 runs recorded slot references only; the distinct-block counts come from the review
re-measurement of the three kept images: 14 of 14 distinct blocks indexed and candidate roots under
none and async, **6 of 14 under sync**. Under sync the lost blocks are the root, extent, chunk and
dev tree roots of backups 35, 36 and 37: 12 of the 26 slot references but 8 distinct blocks.

**6.6 Review re-measurement (2026-09-15), three kept images at `8daf05f`.**

| Image | Probe = compatibility count | Root-tree candidates | Slot references indexed / candidates (of 26) | Distinct blocks indexed / candidates (of 14) | States beyond the backups | … complete | Generation-3 state missing |
|---|---|---|---|---|---|---|---|
| `s01_discard_none_r1` | 367/355 = 367/355 | 35 | 26 / 26 | 14 / 14 | 31 | 30 | `corrupt` 1 (was `unmapped` 1) |
| `s01_discard_async_r1` | 367/355 = 367/355 | 35 | 26 / 26 | 14 / 14 | 31 | 30 | `corrupt` 1 (was `unmapped` 1) |
| `s01_discard_sync_r1` | 43/31 = 43/31 | 2 | 14 / 14 | 6 / 6 | 1 | 0 | `corrupt` 1 (was `unmapped` 1) |

Carried caveats (EXP-002 §6.5, §7), all of which must appear wherever these tables do:
- **Coverage agreement, not independent validation.** The compatibility count reuses btrfska's scan
  plan and fsid prefilter; it verifies the offsets read, the fsid match at +0x20 and the generation
  field at +0x50, not btrfska's checks, classes or discovery.
- **Balance and short-life artefact.** The 31 states survive because of the final full balance
  (generations 3–16, in deleted chunks nothing reallocated) and the young metadata block group
  (generations 17–34, allocator never came back). Not a general survival rate.
- **Not file-level recoverability.** Completeness counts tree blocks among scanned blocks; no file
  extent or data checksum is read. Most trees here are one block deep, so completeness is easy to
  reach and overstates survival below a missing block.
- **Not SSD behaviour; not async discard in general; not the `nodiscard` mount option; not other
  scenarios, sizes or kernels; not the cause of the run-6 jitter.**
- Discovery hypotheses were exploratory (no prediction registered): report them as observations.

### 6.4 EXP-003 — Scan kernel throughput

Source: `experiments/EXP-003.md` §6, §6.1. Regenerate:
```sh
uv run python experiments/bench_scan.py generate
experiments/env.sh sandbox.img > images/scratch/exp/EXP-003/env.txt
uv run python experiments/bench_scan.py run --runs 5
uv run python experiments/bench_scan.py allocated          # per non-hole byte
uv run python experiments/bench_scan.py sweep-generate     # density sweep images
experiments/env.sh sandbox.img > images/scratch/exp/EXP-003/env_sweep.txt
uv run python experiments/bench_scan.py sweep-run --runs 5
uv run python experiments/bench_scan.py clean
```
Image: synthetic, deterministic, 10 GiB (10 737 418 240 B), seed 3; 6 metadata, 80 data and 74
hole tiles; 11 151 tree blocks written (106 corrupted), 1.6 % of the image; 5 771 366 400 B
allocated; SHA-256 `acf9b2ef…25e1`. One process (`workers=1`), not pinned.

N = 5 per cell. Entries are median (min–max).

| Mode | Cache | N | MB/s | MiB/s | Wall s | CPU s | Pages cached before the run | Hits | Valid |
|---|---|---|---|---|---|---|---|---|---|
| prefilter | cold | 5 | 3743.1 (3505.4–4328.8) | 3569.7 (3343.0–4128.3) | 2.87 (2.48–3.06) | 1.73 (1.31–1.86) | 0.0000 (0.0000–0.0000) | 11151 | — |
| prefilter | warm | 5 | 6138.6 (3622.4–8364.7) | 5854.2 (3454.5–7977.2) | 1.75 (1.28–2.96) | 0.88 (0.55–1.78) | 0.8978 (0.8171–0.9259) | 11151 | — |
| full | cold | 5 | 3277.1 (3227.5–3337.8) | 3125.2 (3078.0–3183.2) | 3.28 (3.22–3.33) | 2.11 (2.01–2.14) | 0.0000 (0.0000–0.0000) | 11151 | 11045 |
| full | warm | 5 | 5691.0 (4430.1–7025.2) | 5427.3 (4224.9–6699.8) | 1.89 (1.53–2.42) | 1.07 (0.89–1.18) | 0.9092 (0.8735–0.9280) | 11151 | 11045 |

**Image bytes vs allocated (device) bytes.** 4.97 GiB of the image are holes, which read as zeros
without device I/O, so image bytes per second overstate the device rate. The same runs divided by
the 5 771 366 400 allocated bytes:

| Mode | Cache | N | Image MB/s | Allocated (non-hole) MB/s |
|---|---|---|---|---|
| prefilter | cold | 5 | 3743.1 (3505.4–4328.8) | 2011.6 (1884.2–2327.2) |
| prefilter | warm | 5 | 6138.6 (3622.4–8364.7) | 3299.8 (1947.2–4494.8) |
| full | cold | 5 | 3277.1 (3227.5–3337.8) | 1761.2 (1734.7–1794.0) |
| full | warm | 5 | 5691.0 (4430.1–7025.2) | 3058.5 (2380.9–3777.1) |

**Density sweep (EXP-003 §6.1).** Three dense 1 GiB images (allocated bytes = size, so image bytes
per second are device bytes per second); each 16 KiB slot holds a `sandbox.img` tree-block copy
with probability density %, random bytes elsewhere; 1 % of copies corrupted. Full validation, one
process. N = 5 per cell, median (min–max):

| Density | Cache | MB/s (image = device bytes) | Wall s | CPU s | Device read MB | Hits | Valid |
|---|---|---|---|---|---|---|---|
| 0 % | cold | 3451.7 (3362.5–3456.7) | 0.31 (0.31–0.32) | 0.11 (0.11–0.14) | 1073.7 | 0 | 0 |
| 0 % | warm | 65669.9 (55699.1–68240.6) | 0.02 (0.02–0.02) | 0.02 (0.02–0.02) | 0.0 | 0 | 0 |
| 10 % | cold | 2142.5 (2069.7–2159.2) | 0.50 (0.50–0.52) | 0.32 (0.32–0.33) | 1073.7 | 6476 | 6410 |
| 10 % | warm | 5685.7 (5056.6–6037.6) | 0.19 (0.18–0.21) | 0.19 (0.18–0.21) | 0.0 | 6476 | 6410 |
| 100 % | cold | 512.2 (501.0–529.7) | 2.10 (2.03–2.14) | 1.88 (1.85–1.94) | 1073.7 | 65536 | 64905 |
| 100 % | warm | 615.9 (576.0–628.2) | 1.74 (1.71–1.86) | 1.74 (1.71–1.86) | 0.0 | 65536 | 64905 |

Carried from the record: the validation bound is about 27 µs per candidate (1.74 s CPU for 65 536
candidates, warm); warm runs of the 10 GiB image were 7–18 % reclaimed, so warm medians understate a
fully cached scan; one consumer NVMe drive; tree blocks from one crc32c 16 KiB image (sha256 and
blake2b cost more per candidate); empty chunk map (real maps cost more per lookup); multi-worker
scaling not measured; the sweep ran on a dirty tree (§6.0). `CHECK:` EXP-003 §8 wording, Appendix A
item 7.

### 6.5 Supporting deterministic results (no EXP record yet)

These are pure parses of fixed images (plan.md §7 allows one run plus the image hash), regenerable
by committed commands. Promote the ones the paper uses to EXP records.

**Scan classes per image** (research.md §10.10; `uv run btrfska scan IMAGE`, targeted; image hashes
in `corpus/manifest.tsv`). Counts are physical copies.

| Image | Candidates | Valid | Invalid | Live | Backup-reachable | Unreferenced | Orphans outside the current chunk map | Legacy-compatible orphans |
|---|---|---|---|---|---|---|---|---|
| `sandbox.img` | 85 | 84 | 1 | 20 | 34 | 30 | 20 | 71 |
| `m1_xxhash` | 367 | 362 | 5 | 22 | 24 | 316 | 172 | 355 |
| `m1_sha256_bgt` | 401 | 395 | 6 | 24 | 26 | 345 | 181 | 387 |
| `m1_blake2b` | 367 | 362 | 5 | 22 | 24 | 316 | 172 | 355 |
| `m1_lzo` | 365 | 360 | 5 | 22 | 24 | 314 | 170 | 353 |
| `m1_zlib` | 367 | 362 | 5 | 22 | 24 | 316 | 172 | 355 |
| `m1_badnode_both` | 367 | 360 | 7 | 20 | 24 | 316 | 172 | 353 |

**Discovery per image** (research.md §10.11; `uv run btrfska roots IMAGE --full-sweep`).

| Image | Root-tree candidates | Slot references rediscovered (distinct blocks) | States beyond the backups (generations) | … complete | Walk failures |
|---|---|---|---|---|---|
| `sandbox.img` | 5 | 26/26 (18/18) | 1 (3) | 1 | none |
| `m1_xxhash`, `m1_blake2b`, `m1_lzo`, `m1_zlib`, `m1_badnode`, `m1_mirror_damage`, `m1_foreign_mirror` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
| `m1_sha256_bgt` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
| `m1_badnode_both` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 29 | 5 `corrupt` |
| `m2_logtree` | 5 | 24/27 (19/22) | 2 (3, 7) | 1 | 3 `reused` |
| `s01_discard_none_r1`, `s01_discard_async_r1` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
| `s01_discard_sync_r1` | 2 | 14/26 (6/14) | 1 (3) | 0 | 12 `zeroed` |

**Sandbox reconciliation** (catalog.md M2a; `uv run pytest -q tests/test_scan_classify.py`): the
prototype's 71 generation-defined orphans are 8 `live` + 34 `backup_reachable` + 28 `unreferenced`
+ 1 `invalid`.

**Oracle file reads** (catalog.md M1c; `uv run pytest -q tests/oracle`): 152 file reads across
`sandbox.img`, `m1_xxhash` (zstd), `m1_lzo`, `m1_zlib`; 0 mismatches, 0 incomplete reads.

**LZO hostile-input harness, bit flips** (catalog.md M1c review fixes; `uv run python
tests/oracle/lzo_hostile.py --seeds 1 2 3 4 5 --json images/scratch/exp/lzo_hostile.json`); median
(range) over 5 seeds, 300 streams per seed:

| Corpus | Decoder | Correct / returned | Wrong ≤ 4 KiB | > 4 KiB | `Exception` | non-`Exception` |
|---|---|---|---|---|---|---|
| bit_flips | btrfska | 0 (0–1) | 227 (218–231) | 0 (0–0) | 72 (68–82) | 0 (0–0) |
| bit_flips | lzallright 0.2.6 | 0 (0–1) | 227 (218–231) | 36 (32–41) | 39 (31–47) | 0 (0–0) |
| bit_flips | dissect.util 3.24 pure Python | 1 (0–1) | 267 (258–277) | 30 (22–41) | 1 (0–2) | 0 (0–0) |
| bit_flips | dissect.util 3.24 native | 0 (0–1) | 227 (218–231) | 36 (32–41) | 0 (0–2) | 37 (31–46) |

**Not paper-ready as numbers:** the hostile-walk timings (422.22 s → 2.82 s) and the memory peaks
(89.3 MB → 2.3 MB) were produced by scripts in the gitignored `images/scratch/` (catalog.md M2b and
M2a review fixes). The committed tests assert only bounds. Commit the scripts before quoting them
(plan.md §7).

---

## 7. Findings

Confidence: **High** = deterministic, committed script, several images or runs; **Medium** = one
scenario or one image, or mechanism read from source; **Low** = hypothesis.

**F1. A crc32c-only reader silently finds nothing on other checksum types.** The legacy prototype
validated every tree block with crc32c. On xxhash64, sha256 and blake2b images it rejected every
fsid-matching block (368, 402 and 368) and listed no file, without an error; btrfska accepted every
block its walks reached (23, 25, 23) and read all ten files of every root set byte-identically to
the guest SHA-256s. *Evidence:* EXP-001 §6. *Confidence:* High for these images and this prototype;
no other tool tested.

**F2. Backup roots reach little of the metadata history that survives.** On the s01 images, 24–26
of 338–371 valid orphans (7 %) are reachable from a backup root; on `sandbox.img`, 34 of 64 (53 %).
All four backup slots of every s01 image name the same generation-19 subvolume-5 tree, while the
scenario's changes happen in a subvolume reached only through each backup's root tree.
*Evidence:* research.md §10.10, §10.7. *Confidence:* High on these images; Medium as a general
statement (small quiescent images, one scenario).

**F3. "Generation below the superblock" is neither "orphan" nor "deleted".** It counts live blocks
unchanged since an older generation (8 on `sandbox.img`, 10 stale copies on the none/async s01
images) and misses current-generation orphans (2 on `sandbox.img`), because a block already written
to disk in the running transaction is copied again on its next change. *Evidence:* catalog.md M2a
reconciliation; EXP-002 §6.1; research.md §10.10 (ctree.c:621-625). *Confidence:* High for the
counts; Medium for the mechanism (source reading).

**F4. On one scenario, 31 candidate root-tree blocks (states) survive beyond the 4 backup states,
30 of them complete, and 13 of them only outside the current chunk map.** Those 13 are generations
3, 6, 7 (two blocks) and 8–16 (EXP-002 §6.3, "generations 3, 6, 7 (two root-tree blocks), and
8–34"; research.md §10.11). Generations 3–16 lie in
chunks the final full balance deleted and resolve through their own inferred chunk trees; generations
17–34 lie in the new metadata block group. *Evidence:* EXP-002 §6.3, §6.5; research.md §10.11.
*Confidence:* High that these states exist on these images (identical in 15/15 regenerations per
mode); **Low as a survival rate**: it depends on the balance and the short life.
`CHECK:` 8–13 vs 8–14 blocks per state, Appendix A item 5.

**F5. Synchronous discard removes the history the kernel frees; async with a quick unmount removes
nothing.** Sync kept 8.7 % of stale blocks (median, N = 15), 2 of 35 candidate root-tree blocks, 0
backup-reachable blocks and 6 of 14 distinct slot blocks; every surviving valid orphan is mkfs
residue (generations 2–5); the sync counts were identical in 15/15 runs. Async with an unmount about
a second later matched no discard on every count in all 15 runs. *Evidence:* EXP-000 §6; EXP-002 §6.2–§6.4. *Confidence:* High for these images
and virtio sparse-file TRIM; Medium for the mechanism (`btrfs_finish_extent_commit`, read from
source); Low for SSDs.

**F6. Coverage agreement with an independent probe is exact once skip ranges are made explicit.** On
48 of 48 images, btrfska's full-sweep candidates, counted under the probe's rules, equal the
probe's counts; the only range one tool reads and the other does not is blocks 0–15, which cannot
hold a tree block. *Evidence:* EXP-002 §2, §6.1. *Confidence:* High, for coverage only; it validates
neither checks nor classes.

**F7. Reuse is distinguishable from damage.** Missing blocks and walk failures separate `reused`
(an intact newer block at the address) from `corrupt`, `zeroed` and the other classes: 3 `reused`
on `m2_logtree`'s oldest backup root, 5 `corrupt` on `m1_badnode_both`, 12 `zeroed` under sync
discard. *Evidence:* research.md §10.11; EXP-002 §6.2. *Confidence:* High on these images and the
synthetic class tests; the classes have not been checked against an independent labelling.

**F8. The kernel reads DUP mirror 2 only when mirror 1 fails, and a read-write mount repairs the
failed mirror.** So a corrupt or altered second copy is invisible to normal reads, and merely reading
on a read-write mount can destroy the divergence. For RAID1/1C3/1C4/10, the default `pid` read
policy lets different processes read different copies. *Evidence:* research.md §10.8 (volumes.c,
disk-io.c:172-250, bio.c line references at v7.0). *Confidence:* Medium (source reading, not
measured); the hiding-place use is a Low-confidence hypothesis.

**F9. Most corrupt LZO streams still decode.** About three quarters of single-bit flips of a 4 KiB
LZO sector (227, range 218–231, of 300 per seed) decode to wrong bytes within the output bound in
btrfska, lzallright and dissect.util's native decoder; the native decoder also panics with a
non-`Exception` on 31–46 per seed. The kernel skips zlib's adler32 check too. *Evidence:* catalog.md
M1c review fixes table; research.md §10.9. *Confidence:* High (committed seeded harness).

**F10. A valid superblock copy of another filesystem can survive at a mirror offset and would win a
generation-only selection.** btrfska anchors the fsid on the first valid copy (btrfs-progs recover
rule) and reports the foreign copy as evidence of a previous filesystem. *Evidence:*
`m1_foreign_mirror`, catalog.md M1a review fix 1; research.md §10.7. *Confidence:* High for the
synthetic case; not observed on a real device.

**F11. mkfs leaves tree blocks the kernel would reject.** Every s01 image has 5 or 6 generation-1
blocks without the WRITTEN flag (btrfs-progs v6.6.3), and an empty fs-tree leaf; a probe counts
them, a validating scan must report them as invalid and never as orphans. *Evidence:* research.md
§10.10; EXP-002 §6.1. *Confidence:* High for btrfs-progs v6.6.3.

**F12. Log trees need a log context, which exposes superseded log commits.** Log blocks carry owner
−6 and generation exactly superblock + 1; with that rule, the scan's live log blocks equal
`dump-tree`'s on `m2_logtree`, and two superseded log leaves of the same transaction remain visible.
*Evidence:* research.md §10.10, §10.11. *Confidence:* Medium (one image, mechanism from source).

**F13. The legacy "Move/Rename" artifacts on `sandbox.img` are inode-number reuse.**
`target_file.txt` (INODE_ITEM generation 10) was deleted in transaction 12, and `large_target.txt`
is a new inode 257 created in generation 13. *Evidence:* research.md §10.9; catalog.md M1a gen-12
capture. *Confidence:* High; relevant to M5 timelines.

---

## 8. Claim → evidence traceability

Status: **Ready** (committed record and script), **Ready-det** (deterministic result, committed
command, no EXP record yet: promote), **Not ready** (numbers from scratch scripts or manual tests),
**Blocked** (needs a milestone), **CHECK** (documents disagree).

| # | Claim | Where in draft | Evidence | Regenerating command | Status |
|---|---|---|---|---|---|
| 1 | Legacy accepts 0 blocks and lists 0 files on xxhash64/sha256/blake2b; btrfska 23/25/23 accepted, 10/10 files | Abstract A; §5.6; F1 | `experiments/EXP-001.md` §6 | `uv run python experiments/exp001.py --runs 2` | Ready |
| 2 | 152/152 oracle file reads equal dissect.btrfs and guest SHA-256s | §4.2 N1; §6.5 | catalog.md M1c "Oracle results" | `uv run pytest -q tests/oracle` | Ready-det |
| 3 | Walks equal `dump-tree` block by block | §4.2 N1 | catalog.md M1b | `uv run pytest -m vm -q tests/test_vm_images.py -k walks_match_dump_tree_block_by_block` | Ready-det |
| 4 | Unknown incompat bit refused, exit 2 | §5.4 R5 | catalog.md M1a, M1c DoD table | `uv run btrfska info images/scenarios/m1_unknown_incompat.img` | Ready-det |
| 5 | dissect.btrfs validates no csum/header/incompat bit and zero-fills unmapped reads | §4.2 N1 | research.md §10.2, §10.9 | none committed | Not ready |
| 6 | Kernel DUP read and repair policy | §4.2 N2; F8 | research.md §10.8 | source reading (v7.0 line refs) | Ready as a source citation; not a measurement |
| 7 | Foreign superblock copy reported, not selected | §4.2 N3; F10 | catalog.md M1a review fix 1 | `uv run btrfska info images/scenarios/m1_foreign_mirror.img` | Ready-det (synthetic) |
| 8 | 227 (218–231) of 300 LZO bit flips decode to wrong bytes | §4.2 N4; F9 | catalog.md M1c review fixes | `uv run python tests/oracle/lzo_hostile.py --seeds 1 2 3 4 5 --json images/scratch/exp/lzo_hostile.json` | Ready-det (promote to EXP) |
| 9 | Coverage agreement on 48/48 images | §5.6 RQ2; F6 | `experiments/EXP-002.md` §6.1 | `uv run python experiments/exp002.py run …; … table` | Ready (the 45 regenerated images need `exp000.py run` first) |
| 10 | Classes per mode (e.g. none: 316 (314–316) unreferenced) | §6.3 | EXP-002 §6.2 | as 9 | Ready |
| 11 | 71 legacy orphans = 8 + 34 + 28 + 1 | F3; §6.5 | catalog.md M2a | `uv run pytest -q tests/test_scan_classify.py` | Ready-det |
| 12 | 24–26 of 338–371 orphans backup-reachable (7 %) | F2; §4.2 N10 | research.md §10.10 | `uv run btrfska scan images/scenarios/<image>.img` per image | Ready-det |
| 13 | 31 states beyond the backups, 30 complete | Abstract A; F4 | EXP-002 §6.3, §6.6; research.md §10.11 | `uv run btrfska roots images/scenarios/s01_discard_none_r1.img --full-sweep` | Ready; **CHECK** 8–13 vs 8–14 (Appendix A item 5) |
| 14 | Survival is a balance and short-life artefact | §5.6; §6.3 caveats | EXP-002 §6.5 | source reading (extent-tree.c lines) + `roots --json` placement fields | Ready as stated (mechanism not measured) |
| 15 | Pre-balance states 3–16 placed only by their own chunk items | F4; C6 | research.md §10.11 | `uv run btrfska roots images/scenarios/m1_xxhash.img --json --full-sweep` | Ready-det |
| 16 | Sync keeps 8.7 % of stale blocks; async quick unmount = none | Abstract A; F5 | EXP-000 §6 | `uv run python experiments/exp000.py run --runs 15; … table` | Ready |
| 17 | Sync: 2 of 35 states; 14 of 26 slot references, 6 of 14 distinct blocks | Abstract A; F5 | EXP-002 §6.3, §6.6, §8 | as 9, review command | Ready |
| 18 | 12.9 %, 11.7 %, 11.1 % remaining (other columns) | §6.1 | EXP-000 §6 | as 16 | Ready |
| 19 | Full validation 3 277.1 MB/s cold on 10 GiB sparse; 1 761.2 MB/s per allocated byte | §5.6 RQ5 | EXP-003 §6 | `bench_scan.py run --runs 5; … allocated` | Ready |
| 20 | 512.2 MB/s cold at 100 % density; ≈ 27 µs per candidate | Abstract A; §5.6 | EXP-003 §6.1 | `bench_scan.py sweep-generate; sweep-run --runs 5` | Ready, but measured on a dirty tree: re-run on a clean commit before submission |
| 21 | Planted level-7 block no longer hides roots | §5.5.3; N8 | catalog.md M2b review fix 4 | `uv run pytest -q tests/test_scan_roots.py -k planted` | Ready-det (synthetic) |
| 22 | Hostile walk 422.22 s → 2.82 s; memory 89.3 MB → 2.3 MB | not used | catalog.md M2b / M2a review fixes | scripts under `images/scratch/` (not committed) | Not ready |
| 23 | Beyond Carving scans chunk-mapped tree regions for historical roots (not backup-root-bounded), reads the first stripe only and describes no tree-block checksum validation | §5.3 | `docs/papers/pandey_beyond_carving_2026.pdf` Alg. 3, §VI.E.1, §X.G, §X.H.7; research.md §10.12 | — | Ready as a citation (Appendix A item 1 resolved 2026-09-15) |
| 24 | 21/71 orphans outside the chunk map | C6 | plan.md §1 C6; catalog.md 2026-08-14 vs M2a; **explained by catalog.md M5a: they are blocks of `mkfs.btrfs`'s two temporary chunks** | `uv run btrfska scan sandbox.img`; `uv run btrfska catalog build sandbox.img --db x.db` and table `node_maps` | **CHECK** the definition (Appendix A item 6) |
| 25 | File-level deleted-file recovery rate | Abstract B | none | — | Blocked (M4, M7) |
| 26 | Beyond-4-generations file recovered only from orphan nodes/items | Abstract B | none | — | Blocked (M4, M7); **CHECK** test design (Appendix A item 2) |
| 27 | Timelines, tiers, hiding detection, FST | Abstract B; §4.1 | none | — | Blocked (M5, M6) |
| 28 | Read-only guarantee | §5.4 R1 | `tests/test_readonly.py`; every catalog verification table | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | Ready-det |
| 29 | Which root-tree blocks `btrfs-find-root -a` prints vs `btrfska roots`: identical inside the current chunk map (229 of 229 states), none outside it (0 of 133) | §5.3 positioning; N5 | EXP-004 | `experiments/exp004.py` | Ready |
| 30 | SecurityRonin `recover_deleted` is backup-root-bounded (all four slots, FS tree 5), stripe 0, crc32c | §5.3 | source at `e6cd73f` (research.md §10.12) | source reading | Ready as a source citation; not run |

---

## 9. Figures and tables plan

The prototype's diagrams (`arch.png`, `cow.png`, `extract.png`, `future.png`, `leaf_layout.png`,
committed in `160233e` under `diagrams/`) were removed from the repository on 2026-09-21; they remain
in the git history. `arch.png` showed the legacy brute-force pipeline (stages 1–5), not the
architecture built in M1–M2, and `cow.png` was a generic two-box copy-on-write sketch. Every figure
below is drawn new; the copy-on-write figure needs the superblock, backup ring and chunk map.

| # | Figure or table | What it shows | Data source | Producible now? |
|---|---|---|---|---|
| F-1 | Architecture (as built) | Layers 1–2 and the CLI records in full; layers 3–6 greyed as planned; read-only boundary; oracles outside `src/` | plan.md §2; §5.5 of this file | Yes (new drawing) |
| F-2 | Btrfs essentials | Superblock at 64 KiB with the 4-slot backup ring; root tree → ROOT_ITEMs → subvolume trees; CoW path copy leaving superseded blocks; chunk map with an unmapped gap after a balance | §5.2 | Yes (new drawing) |
| F-3 | Surviving candidate root-tree blocks per generation, by discard mode | Strip per mode, x = generation 1–38; mark current/backup states, states beyond the backups, complete vs incomplete, placed by the current map vs only by their own chunk items; annotate the balance | `btrfska roots --json --full-sweep` on the three `_r1` images; `images/scratch/exp/EXP-002/review/results.jsonl` | Yes. Caption must carry the balance and short-life caveat |
| F-4 | Class composition per discard mode | Stacked bars: live, backup-reachable, unreferenced, invalid (medians, range as whiskers) | EXP-002 §6.2 | Yes |
| F-5 | Where orphans lie on the device | Physical offset axis of `m1_xxhash` with chunk stripes and unmapped gaps; orphans coloured by generation and class | `uv run btrfska scan images/scenarios/m1_xxhash.img --json --full-sweep` | Yes |
| F-6 | Throughput vs tree-block density | MB/s (log scale) vs density 0/10/100 %, cold and warm, 200 MB/s DoD line; separate markers for the 10 GiB sparse image per image byte and per allocated byte | EXP-003 §6, §6.1 | Yes, but only three densities: add more density points on a clean commit first (gap G13) |
| F-7 | Mirror read and repair policy | DUP: mirror 1, fallback to 2, repair on rw mount; RAID1: PID-selected copy; btrfska: every copy read and reported | research.md §10.8 | Yes (schematic; label "from kernel v7.0 source") |
| F-8 | LZO decode outcomes under hostile input | Stacked bars per decoder: wrong ≤ 4 KiB, > 4 KiB, exception, panic | catalog.md M1c review table | Yes (script committed); probably discussion or appendix |
| T-1 | Capability matrix vs prior art | §5.3 table | research.md §2, §10.2; papers | Draft exists; every non-btrfska cell needs verification |
| T-2 | Corpus | Image, csum, features, scenario, generator, SHA-256 prefix | `corpus/manifest.tsv`; EXP-001 §3; EXP-000 §3 | Yes |
| T-3 | EXP-001 csum coverage | §6.2 | EXP-001 | Yes |
| T-4 | EXP-000 + EXP-002 discard results | Merge §6.1 with §6.3 rows (states, distinct blocks) | EXP-000, EXP-002 | Yes |
| T-5 | Discovery per image | §6.5 | research.md §10.11 | Yes |
| F-9 | Recovery rate per source and per baseline | Bars per scenario and tool | — | No (M4, M7) |
| F-10 | Per-inode timeline example | Lifecycle of `deleted_big.txt` across states (s01: created at size 0 and grown to 288 894 bytes within generation 7, deleted in 9), or of sandbox inode 257 as two files | `uv run btrfska timeline DB --tree 256` | Data ready (M5d); figure not drawn |
| F-11 | Confidence-tier calibration | Precision per tier against ground truth | — | No (M6, M7) |

---

## 10. Gap list to a submittable paper

Ranked by importance for acceptance at DFRWS, except that **G5 and G9 are promoted to the top**:
both are cheap (documents and the images that already exist) and block the positioning and
discovery claims the rest builds on. IDs stay stable because other sections cite them. Milestones
from plan.md §5.

| ID (in rank order) | Gap | Why reviewers will ask | Milestone | Minimum to close |
|---|---|---|---|---|
| G5 | **Positioning against prior art** (cheap, blocking) | A reviewer who knows Beyond Carving will reject "backup-root-bounded" | now (docs) | Project docs corrected on 2026-09-15 (research.md §10.12; Appendix A items 1–3 resolved). The find-root column is decided by EXP-004 (2026-09-21). Remaining: verify the other cells of Table T-1 against the tools and papers |
| G9 | **Independent validation of classes and discovery** (cheap, blocking) | EXP-002's agreement is coverage only; the novelty of old-root discovery is unmeasured | discovery: done (EXP-004); classes: M3/M7 | EXP-004 validates discovery against an independent tool: inside the current chunk map the two agree block for block. Still open: label a sample of blocks from `dump-tree` or a second implementation to validate the reachability classes |
| G1 | **No file-level recovery result** | A forensic recovery paper without recovery rate and SHA-256 exact match (Kim et al., 2021; Beyond Carving) is a measurement note | M4 (+ M3 enabler) | Recovery from anchored backup roots, discovered states, unreferenced nodes and orphan items, each labelled by source; EXP with ground truth per file **2026-09-21: first result, EXP-006** (one scenario, N = 5; per-file SHA-256 against the scenario log, by source). Rates on a matrix corpus are still M7 |
| G2 | **No baseline comparison** | Every related paper benchmarks tools (research.md §5.2) | M7 | Harness running read-only on copies: `btrfs restore` + `btrfs-find-root` (btrfs-progs ≥ 7.1), `SecurityRonin/btrfs-forensic` `recover_deleted` (pinned), TSK `develop` (pinned commit), btrfscue v0.7 `recover`, PhotoRec, undelete-btrfs v1.0; Beyond Carving only if code appears (the repo was empty on 2026-09-15; otherwise compare analytically, or reimplement Algorithm 3's discovery rule and label it a reimplementation) |
| G3 | **One young, small, balance-ended scenario** | The 31-state result is explicitly an artefact (EXP-002 §6.5) | M7 | At least: no-balance scenario; aged filesystem (create/delete churn); larger image (8 GiB); repeat discovery and recovery; report how many states survive without the balance |
| G4 | **Beyond-4-generations test** | Headline differentiator in plan.md M7 | M4 + M7 | As redesigned in plan.md M7 (2026-09-15): delete a file, force > 4 commits, and separate (a) states a scan of current-chunk-mapped tree regions reaches, which a Beyond Carving-style scan could find (parity, not novelty), from (b) states only outside the current chunk map (after balance or reclaim) or recoverable only from unreferenced blocks (the differentiator); label each recovery by source |
| G6 | Timelines (C3) and historical chunk maps used for reading (C6) | The planned novelty core (plan.md §8 paper 1: C1, C3, C4, C6) | **Built (M5, 2026-09-21).** C6 has its experiment (EXP-007). C3 has tests against ground truth on three fixed images but **no EXP record and no baseline comparison**: that is the gap to close before the paper can carry a timeline number | `btrfska timeline` on sandbox generations 10→14 (done), on `m4_deep` against its log (done, one build), five builds and the two baselines (open, M7); outside-map orphans placed by reconstructed maps and pre-balance files read through them (done, EXP-007) |
| G7 | Confidence tiers with csum-tree verification (C4) | Needed to claim "how confidently" | M6 | Tier rules, EXTENT_CSUM verification, calibration EXP (precision of Confirmed) |
| G8 | Evidence catalog (M3) | Enabler for G1/G6/G7 and "scan once, query forever"; not evaluated by itself | M3 | `evidence.db` populated by one scan; reverse queries |
| G10 | Discard external validity | Virtio sparse-file TRIM ≠ SSD | M7 | `nodiscard` row, async idle ≥ 130 s row (plan.md M7), and if possible one real SSD with discard passed through; survey TRIM/SSD forensics literature (`TODO`, absent from research.md) |
| G11 | Corpus release (C7) and artifact | DFRWS values reproducibility; no public Btrfs image corpus with per-file ground truth across these axes was found, but Wani & Bhat (2018) and Schwietert & Hilgert (2025) published datasets that must be cited (research.md §5.1) | M7 | Zenodo DOI, manifest with per-file SHA-256 and operation logs, one command to regenerate the tables |
| G12 | Hiding detection (C5) and FST (C2) | Out of scope for paper 1 per plan.md §8 | M6 | Keep for paper 2; mention only as future work |
| G13 | Paper-readiness of existing numbers | plan.md §7 rule | now | Promote LZO harness, per-image scan/roots tables and oracle results to EXP records; commit the hostile-walk and memory scripts; re-run EXP-003 §6.1 on a clean commit with more density points; commit a dissect.btrfs validation script if N1's comparison is used |
| G14 | Blocked related work | Toolan & Humphries 2026 is the C5 target list; Plum & Dewald and Oh & Hwang are CoW analogs | done 2026-09-21, except the prior-art watch | The three papers and ExtSFR are read (research.md §10.13). Two project claims were corrected: ExtSFR is not database-backed and does verify by hash; the published superblock reserved range is a pre-5.0 layout. Remaining: re-run the prior-art watch before submission (plan.md §8) |

**Near-term experiment E-findroot: done on 2026-09-21 as [EXP-004](../experiments/EXP-004.md).**
All three registered predictions held; the plan below is kept as written.

*(Plan as written on 2026-09-15.)* A per-generation head-to-head of
`btrfs-find-root -a` against `btrfska roots --json --full-sweep` on the images that already exist:
a copy of `sandbox.img`, the `m1_*` images, `m2_logtree` and the three kept `s01_discard_*_r1` images
(`corpus/manifest.tsv`). It settles whether old-root discovery beyond the backups is new for any
generation, or only for states outside the current chunk map (G5, G9; N5).
- *Method.* Run find-root on copies under `images/scratch/exp/EXP-NNN/` and record the btrfs-progs
  version (host v6.6.3; also ≥ 7.1 once built, plan.md M7). Parse its per-generation output, join it
  with btrfska's states on generation and bytenr, and split every generation by whether the
  root-tree block is placed by the current chunk map or only by its own chunk items (`roots --json`
  placement fields). Pure parse of fixed images: one run plus image hashes (plan.md §7).
- *Registration.* `CHECK:` read which ranges `btrfs-find-root` scans in the btrfs-progs source, then
  register, before running, which of the s01 generations 3–16 (outside the current map) and 17–34
  (inside) it will report.
- *Output.* An EXP record with, per image and generation: find-root bytenr and level; btrfska
  bytenr, level and completeness; placement. A labelled reimplementation of Beyond Carving's
  Algorithm 3 discovery rule over the same scan may be added as a third column.

**Minimum experiment set for paper 1** (each an EXP record with ≥ 5 regenerations where a guest runs):
1. E-rec: file-level recovery rate and SHA-256 exact match per source on no-balance, aged
   (create/delete churn) and ≥ 8 GiB images, not only the young balance-ended s01 (G1, G3).
2. E-beyond4: the redesigned beyond-4-generations test, cases (a) inside and (b) only outside the
   current chunk map or only from unreferenced blocks (G4; plan.md M7).
3. E-baseline: the same images through every baseline in G2, with runtime and peak memory per tool
   next to btrfska's.
4. E-discard: discard × operation, with `nodiscard` and async-idle rows and at least one real SSD
   with discard passed through to the device (G10), extending EXP-000/002.
5. E-csum: EXP-001 over the checksum × compression × scenario matrix (plan.md M7).
6. E-tiers: tier calibration against ground truth (G7), if C4 is claimed.
7. E-perf: non-sparse 10 GiB and larger images, sha256/blake2b candidates, multi-worker scaling
   (EXP-003 follow-ups).
8. E-robust: hostile-input bounds as an EXP record (walk cost, memory, LZO harness) (G13).
9. E-fp: discovery false-positive rate on forged images: planted checksum-valid owner-1 blocks at
   other levels, forged newer parents (the residual vector of catalog.md M2b review fix 4) and
   blocks copied from another image; count reported states that are not real root trees, per
   forgery class (N8).
10. E-raid: RAID1, RAID1C3, RAID10 and RAID5/6 images (plan.md M7 lists only multi-device RAID1):
    per-copy validation and discovery per profile (§11 "Profiles and features").

**Corpus statement.** Every EXP record and the paper state the corpus size explicitly (images per
matrix cell and in total, image sizes, regenerations per cell) and point to each image's operations
log in the manifest (plan.md M7 manifest fields). `TODO:` fill in the numbers once the corpus exists.

---

## 11. Threats to validity (consolidated)

From EXP-000 §7, EXP-001 §7, EXP-002 §6.5 and §7, EXP-003 §7, research.md §10.8–§10.11 and the
catalog review subsections.

**Internal.**
- *Guest jitter.* Commit timing shifts a few blocks between regenerations (EXP-000 run 6:
  365/353/18/828). Tolerances come from measured per-column ranges, never a fixed ± N (plan.md §7);
  15 runs cannot bound rare outcomes (the review rerun's 16 `needle_copies` did not recur).
- *Coverage vs independent validation.* The EXP-002 compatibility count reuses btrfska's scan plan
  and prefilter; a shared bug would affect both sides of the btrfska comparison (EXP-002 §7).
- *Oracle independence.* The sandbox reference in EXP-001 is dissect.btrfs, which validates no
  checksum; the extent-tree cross-check uses the same current root tree as the walks (research.md
  §10.10).
- *Mechanisms read from source, not measured:* sync discard trimming at commit, the allocator's
  cursor behaviour behind the 31 states, DUP/RAID1 read policy and repair (EXP-002 §6.4–§6.5;
  research.md §10.8).
- *Benchmark conditions.* Hybrid CPU, process not pinned; warm caches 7–18 % reclaimed; cold state by
  `POSIX_FADV_DONTNEED`, not reboot; the density sweep ran on a tree with 16 uncommitted files
  (EXP-003 §6.1, §7).
- *Tests written after implementation* for some vm and oracle tests (catalog.md M1b, M1c
  deviations); expectations came from dump-tree, guest logs and oracles.

**External.**
- *One scenario* (s01: 38 transactions ending in a full balance), plus `sandbox.img` (unknown
  generator) and one power-off log-tree image.
- *Young, small, quiescent images* (256–512 MiB), no aging; survival of 31 states depends on the
  balance and short life and does not generalise (EXP-002 §6.5).
- *Discard semantics.* TRIM lands on a sparse raw file through QEMU virtio-blk `discard=unmap` and
  reads back as zeros; SSDs may return zeros, old data or indeterminate data, and the FTL may keep
  flash contents (EXP-000 §7). The "none" row still mounts `discard=async`. Async measured only with
  a quick unmount.
- *Software versions.* Stock Ubuntu 7.0.0-31 guest kernel; host btrfs-progs 6.6.3 mkfs (block-group
  tree off by default, unlike progs ≥ 6.19; mkfs residue without WRITTEN).
- *Profiles and features.* Single device, SINGLE/DUP only on the corpus; no RAID1/10/5/6, no
  MIXED_GROUPS image, no remap tree or RAID stripe tree (the stock kernel cannot create them).
- *Storage.* One consumer NVMe drive on ext4; HDD and network storage untested.
- *Historical extents.* No root set in the corpus reaches a compressed extent at a pre-balance
  address; historical *metadata* is exercised, historical *extent addresses* are not (research.md
  §10.9).

**Construct.**
- *Stale ≠ orphan ≠ recoverable.* Probe columns count unvalidated fsid matches (EXP-000 §7).
- *Tree-level only.* "Accepted" measures the checksum gate; completeness counts tree blocks among
  scanned blocks, excludes the chunk and log trees and ROOT_ITEMs naming tree 1, and overstates
  survival below a missing block; no file content or data checksum is read per state (EXP-001 §7,
  EXP-002 §6.5).
- *State ≠ committed filesystem state.* A candidate root-tree block can be an old leaf of a
  multi-leaf root tree or a forged block (EXP-002 §7).
- *Slot references ≠ distinct blocks* (26 vs 14; EXP-002 §6.3).
- *Counts are physical copies* in scan tables (a DUP block counts twice) but distinct logical blocks
  in EXP-001's btrfska rows.
- *Image bytes ≠ device bytes* for sparse images (EXP-003 §6).
- *Legacy comparisons* count different things (EXP-001 footnote).

---

## 12. References

### 12.1 BibTeX

Fields come from research.md (§2, §4, §10.1, §10.2) and, where noted, from the first pages of the
PDFs in `docs/papers/`. Entries whose note says "Crossref" were checked against `api.crossref.org` (and
doi.org) on 2026-09-15. `TODO` marks a missing field; never fill it from memory. Software entries give the
version or date research.md records.

```bibtex
@article{pandey2026beyond,
  author  = {Pandey, Krish and Jain, Misha and Shetty, Nisha P.},
  title   = {Beyond Carving: Deterministic Deleted File Recovery in {Btrfs}},
  journal = {IEEE Access},
  volume  = {14},
  pages   = {120632--120660},
  year    = {2026},
  doi     = {10.1109/ACCESS.2026.3713173},
  note    = {Open access, CC BY 4.0. Authors' version in docs/papers/}
}

@article{bhat2018forensic,
  author  = {Bhat, Wasim Ahmad and Wani, Mohamad Ahtisham},
  title   = {Forensic analysis of {B}-tree file system ({Btrfs})},
  journal = {Digital Investigation},
  volume  = {27},
  pages   = {57--70},
  year    = {2018},
  doi     = {10.1016/j.diin.2018.09.001}
}

@article{wani2018dataset,
  author  = {Wani, Mohamad Ahtisham and Bhat, Wasim Ahmad},
  title   = {Dataset for forensic analysis of {B}-tree file system},
  journal = {Data in Brief},
  volume  = {18},
  pages   = {2013--2018},
  year    = {2018},
  doi     = {10.1016/j.dib.2018.04.100}
}

@article{wani2020antiforensic,
  author  = {Wani, Mohamad Ahtisham and Bhat, Wasim Ahmad and Dehghantanha, Ali},
  title   = {An analysis of anti-forensic capabilities of {B}-tree file system ({Btrfs})},
  journal = {Australian Journal of Forensic Sciences},
  volume  = {52},
  number  = {4},
  pages   = {371--386},
  year    = {2020},
  doi     = {10.1080/00450618.2018.1533038}
}

@article{rodeh2013btrfs,
  author  = {Rodeh, Ohad and Bacik, Josef and Mason, Chris},
  title   = {{BTRFS}: The {Linux} {B}-Tree Filesystem},
  journal = {ACM Transactions on Storage},
  volume  = {9},
  number  = {3},
  pages   = {Article 9},
  year    = {2013},
  doi     = {10.1145/2501620.2501623},
  note    = {Crossref: vol. 9, issue 3, 32 pp. Article number from the ACM PDF in docs/papers/rodeh_btrfs_linux_btree_filesystem_2013.pdf, p. 1}
}

@article{rodeh2008btrees,
  author  = {Rodeh, Ohad},
  title   = {{B}-trees, Shadowing, and Clones},
  journal = {ACM Transactions on Storage},
  volume  = {3},
  number  = {4},
  pages   = {Article 2},
  year    = {2008},
  doi     = {10.1145/1326542.1326544},
  note    = {Crossref: vol. 3, issue 4, 27 pp., February 2008. Crossref carries no article number; 2 (2:1-2:27) from Semantic Scholar}
}

@article{hilgert2017pooled,
  author  = {Hilgert, Jan-Niclas and Lambertz, Martin and Plohmann, Daniel},
  title   = {Extending The Sleuth Kit and its underlying model for pooled storage file system forensic analysis},
  journal = {Digital Investigation},
  volume  = {22},
  pages   = {S76--S85},
  year    = {2017},
  doi     = {10.1016/j.diin.2017.06.003},
  note    = {DFRWS USA 2017. Crossref verified. docs/papers/ holds the slide deck, not the article}
}

@article{hilgert2018multidevice,
  author  = {Hilgert, Jan-Niclas and Lambertz, Martin and Yang, Shujian},
  title   = {Forensic analysis of multiple device {BTRFS} configurations using {The Sleuth Kit}},
  journal = {Digital Investigation},
  volume  = {26},
  pages   = {S21--S29},
  year    = {2018},
  doi     = {10.1016/j.diin.2018.04.020},
  note    = {DFRWS USA 2018. DOI read from the PDF in docs/papers/, not recorded in research.md: verify}
}

@article{hilgert2024stacked,
  author  = {Hilgert, Jan-Niclas and Lambertz, Martin and Baier, Daniel},
  title   = {Forensic implications of stacked file systems},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {48},
  pages   = {301678},
  year    = {2024},
  doi     = {10.1016/j.fsidi.2023.301678},
  note    = {DFRWS EU 2024. DOI read from the PDF in docs/papers/, not recorded in research.md: verify}
}

@phdthesis{hilgert2025phd,
  author  = {Hilgert, Jan-Niclas},
  title   = {Contemporary File System Forensic Analysis},
  school  = {University of Bonn},
  year    = {2025},
  note    = {Handle 20.500.11811/13313. Not obtained (host unreachable)}
}

@mastersthesis{juch2014btrfs,
  author  = {Juch, Andreas},
  title   = {Btrfs Filesystem Forensics},
  school  = {Technische Universit{\"a}t Wien},
  type    = {Diploma thesis},
  year    = {2014},
  note    = {Handle 20.500.12708/7491}
}

@incollection{toolan2025book,
  author    = {Toolan, Fergus},
  title     = {The {Btrfs} File System},
  booktitle = {File System Forensics},
  publisher = {Wiley},
  chapter   = {11},
  pages     = {303--352},
  year      = {2025},
  doi       = {10.1002/9781394289820.ch11},
  note      = {Crossref: chapter title and pages; the book record (10.1002/9781394289820) names the author}
}

@article{toolan2026hiding,
  author  = {Toolan, Fergus and Humphries, Georgina},
  title   = {Hiding data in {Btrfs} file systems},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {58},
  pages   = {302198},
  year    = {2026},
  doi     = {10.1016/j.fsidi.2026.302198},
  note    = {Crossref verified. Open access, CC BY 4.0. Read in full 2026-09-21 (research.md 10.13). Supersedes SSRN preprint 10.2139/ssrn.7138910}
}

@article{toolan2025symlink,
  author  = {Toolan, Fergus and Humphries, Georgina},
  title   = {Data hiding in symbolic link slack space},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {53},
  pages   = {301919},
  year    = {2025},
  doi     = {10.1016/j.fsidi.2025.301919}
}

@article{schwietert2025hiding,
  author  = {Schwietert, Anton and Hilgert, Jan-Niclas},
  title   = {Data hiding in file systems: Current state, novel methods, and a standardized corpus},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {54},
  pages   = {301984},
  year    = {2025},
  doi     = {10.1016/j.fsidi.2025.301984},
  note    = {DFRWS APAC 2025}
}

@article{schwietert2026slack,
  author  = {Schwietert, Anton and Hilgert, Jan-Niclas},
  title   = {Mind the slack? {Reassessing} the relevance of file slack in modern forensic investigations},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {57},
  pages   = {302123},
  year    = {2026},
  doi     = {10.1016/j.fsidi.2026.302123},
  note    = {DFRWS USA 2026. Crossref verified; ScienceDirect PII S2666281726000806; framework https://github.com/fkie-cad/mind-the-slack}
}

@inproceedings{goebel2018fishy,
  author    = {G{\"o}bel, Thomas and Baier, Harald},
  title     = {fishy -- A Framework for Implementing Filesystem-Based Data Hiding Techniques},
  booktitle = {Digital Forensics and Cyber Crime (ICDF2C 2018)},
  series    = {LNICST},
  publisher = {Springer},
  year      = {2018},
  doi       = {10.1007/978-3-030-05487-8_2},
  note      = {https://github.com/dasec/fishy}
}

@incollection{goebel2025generating,
  author    = {G{\"o}bel, Thomas and Baier, Harald and T{\"u}rr, Jan},
  title     = {Generating Usable and Assessable Datasets Containing Anti-Forensic Traces at the Filesystem Level},
  booktitle = {Advances in Digital Forensics XX},
  series    = {IFIP Advances in Information and Communication Technology},
  publisher = {Springer},
  pages     = {225--246},
  year      = {2025},
  doi       = {10.1007/978-3-031-71025-4_12},
  note      = {Crossref: issued 2025 (online 2025-01-07); earlier project docs said 2024}
}

@article{kim2021ext4,
  author  = {Kim, Hyungchan and Kim, Sungbum and Shin, Yeonghun and Jo, Wooyeon and Lee, Seokjun and Shon, Taeshik},
  title   = {Ext4 and {XFS} File System Forensic Framework Based on {TSK}},
  journal = {Electronics},
  volume  = {10},
  number  = {18},
  pages   = {2310},
  year    = {2021},
  doi     = {10.3390/electronics10182310}
}

@article{beebe2009zfs,
  author  = {Beebe, Nicole Lang and Stacy, Sonia D. and Stuckey, Dane},
  title   = {Digital forensic implications of {ZFS}},
  journal = {Digital Investigation},
  volume  = {6},
  pages   = {S99--S107},
  year    = {2009},
  doi     = {10.1016/j.diin.2009.06.006},
  note    = {DFRWS 2009. Author names from the article page of the PDF; its DFRWS cover page reads "Sonia Mandes"}
}

@inproceedings{plum2018apfs,
  author    = {Plum, TODO and Dewald, TODO},
  title     = {Forensic {APFS} File Recovery},
  booktitle = {Proceedings of the 13th International Conference on Availability, Reliability and Security (ARES 2018)},
  publisher = {ACM},
  year      = {2018},
  doi       = {10.1145/3230833.3232808},
  note      = {Tool AFRO, https://github.com/cugu/afro. Read in full 2026-09-21 (research.md 10.13)}
}

@article{prade2020refs,
  author  = {Prade, TODO and Gro{\ss}, TODO and Dewald, TODO},
  title   = {Forensic Analysis of the Resilient File System ({ReFS}) Version 3.4},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {32},
  pages   = {300915},
  year    = {2020},
  doi     = {10.1016/j.fsidi.2020.300915}
}

@article{oh2025f2fs,
  author  = {Oh, TODO and Hwang, TODO},
  title   = {Advanced forensic recovery of deleted file data in {F2FS}},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {54},
  pages   = {301976},
  year    = {2025},
  doi     = {10.1016/j.fsidi.2025.301976},
  note    = {DFRWS APAC 2025. Open access, CC BY-NC-ND. Read in full 2026-09-21 (research.md 10.13)}
}

@mastersthesis{bonnet2026refs,
  author  = {Bonnet, TODO},
  title   = {Forensic Analysis of the Resilient File System ({ReFS}) Version 3.14},
  school  = {University of Mons},
  year    = {2026},
  note    = {Thesis record UNVERIFIED (author statement only). Tool forefst: https://github.com/xbqt/forefst}
}

@article{oh2026ext4log,
  author  = {Oh, TODO},
  title   = {Ext4 Log Tracker: An enhanced approach to file event generation from Ext4 journal},
  journal = {Forensic Science International: Digital Investigation},
  volume  = {58},
  pages   = {302145},
  year    = {2026},
  doi     = {10.1016/j.fsidi.2026.302145}
}

@article{chaudhary2026metarecoverx,
  author  = {Chaudhary, Jagendra Singh and Panchal, Lucky and Tak, Mayank and Kumar, Milan},
  title   = {{MetaRecoverX}: Recovery of Deleted Data and Associate Metadata from {XFS} and {Btrfs} Filesystems},
  journal = {International Journal of Innovative Science and Research Technology},
  volume  = {11},
  number  = {4},
  pages   = {997--1003},
  year    = {2026},
  doi     = {10.38124/ijisrt/26apr738}
}

@inproceedings{pratyashrit2026recovery,
  author    = {Pratyashrit, Chulbul S. and Sharma, Aayush and Sathiyasuntharam, Velayudham},
  title     = {Recovery of Deleted Data and Associated Metadata from {XFS} and {Btrfs} Filesystems},
  booktitle = {DMPedia Lecture Notes in Multidisciplinary Research (IMPACT 2026)},
  volume    = {1},
  pages     = {347--353},
  year      = {2026},
  doi       = {10.65890/dmp.lnmr.IMPACT26.107}
}

@inproceedings{vaheedali2025xfsbtrfs,
  author    = {Vaheed Ali, Syed and TODO},
  title     = {Efficient Recovery of Deleted Data and Metadata from {XFS} and {Btrfs} Filesystem},
  booktitle = {ICPCSN 2025},
  publisher = {IEEE},
  year      = {2025},
  doi       = {10.1109/ICPCSN65854.2025.11035132},
  note      = {Full text not obtained}
}

@article{lee2020extsfr,
  author  = {Lee, Seokjun and Jo, Wooyeon and Eo, Soowoong and Shon, Taeshik},
  title   = {{ExtSFR}: scalable file recovery framework based on an {Ext} file system},
  journal = {Multimedia Tools and Applications},
  volume  = {79},
  number  = {23--24},
  pages   = {16093--16111},
  year    = {2020},
  doi     = {10.1007/s11042-019-7199-y},
  note    = {Crossref: issue of June 2020, online 2019-01-29. Read in full 2026-09-21 (research.md 10.13): no database; verifies by MD5}
}

@book{carrier2005fsfa,
  author    = {Carrier, Brian},
  title     = {File System Forensic Analysis},
  publisher = {TODO},
  year      = {2005}
}

@misc{securityronin2026btrfsforensic,
  author = {{SecurityRonin}},
  title  = {btrfs-forensic: {Btrfs} forensic library (crates btrfs-core 0.1.5, btrfs-forensic 0.1.3)},
  year   = {2026},
  howpublished = {\url{https://github.com/SecurityRonin/btrfs-forensic}},
  note   = {Apache-2.0; state as of 2026-09-15}
}

@misc{btrfsprogs,
  title  = {btrfs-progs: userspace utilities for {Btrfs} (restore, btrfs-find-root, inspect-internal)},
  howpublished = {\url{https://github.com/kdave/btrfs-progs}},
  note   = {Host v6.6.3 used for mkfs; baselines to use v7.1 or later}
}

@misc{btrfscue,
  author = {Blichmann, Christian},
  title  = {btrfscue v0.7},
  year   = {2026},
  howpublished = {\url{https://github.com/cblichmann/btrfscue}},
  note   = {Release 2026-07-04. Author given name from the repository owner handle: verify}
}

@misc{tsk_btrfs_develop,
  title  = {The Sleuth Kit, experimental {Btrfs} support on the develop branch (PR \#3065, merged 2024-11-27)},
  howpublished = {\url{https://github.com/sleuthkit/sleuthkit}},
  note   = {Unreleased as of sleuthkit-4.15.0}
}

@misc{dissectbtrfs,
  author = {{Fox-IT}},
  title  = {dissect.btrfs 1.10},
  year   = {2026},
  howpublished = {\url{https://github.com/fox-it/dissect.btrfs}},
  note   = {Used only as a test oracle}
}

@misc{btrfsrec,
  author = {TODO (lukeshu)},
  title  = {btrfs-rec (btrfs-progs-ng)},
  howpublished = {\url{https://www.lukeshu.com/blog/btrfs-rec.html}}
}

@misc{undeletebtrfs,
  author = {TODO (danthem)},
  title  = {undelete-btrfs v1.0},
  year   = {2025},
  howpublished = {\url{https://github.com/danthem/undelete-btrfs}},
  note   = {URL assembled from the owner/repo name in research.md §2.5: verify}
}

@misc{photorec,
  title  = {{TestDisk} and {PhotoRec}},
  howpublished = {TODO (URL)},
  note   = {Carving baseline}
}

@misc{lzallright,
  title  = {lzallright 0.2.6},
  howpublished = {TODO (URL)},
  note   = {MIT; test oracle for the LZO1X decoder}
}

@misc{linux70btrfs,
  title  = {Linux kernel v7.0, fs/btrfs and include/uapi/linux/btrfs\_tree.h},
  howpublished = {\url{https://github.com/torvalds/linux/tree/v7.0}},
  note   = {All kernel line references in this project are to tag v7.0}
}
```

Also cited in research.md, to add if used: Schneider et al. 2022 "Ambiguous file system partitions"
(FSI:DI 42, DOI `TODO`); ForTrace (Göbel et al., FSI:DI 40:301344, DOI `TODO`); Bhat, Al Zahrani &
Wani 2020 "Can computer forensic tools be trusted…" (all fields `TODO`); Leigh 2014 ZFS timelines
(thesis, `TODO`); Hraiz 2016 "Btrfs Forensic Analysis" (thesis, content UNVERIFIED).

### 12.2 Papers still missing

The three open-access papers of research.md §10.6 (d) (Toolan & Humphries 2026, Plum & Dewald 2018,
Oh & Hwang 2025) and ExtSFR (Lee et al., 2020) were obtained and read in full on 2026-09-21; their
digests and the corrections they forced are in research.md §10.13.

Still missing (research.md §4.8): Hilgert's PhD thesis (2025; open access, host unreachable from the
development network), Vaheed Ali et al. (ICPCSN 2025, closed), Hraiz (2016 thesis, ProQuest), Toolan
& Humphries 2025 (symlink slack, closed). None carries a claim of this draft.

---

## 13. Writing guide for the authors

### 13.1 Terminology

| Use | Meaning (source) | Avoid |
|---|---|---|
| **candidate** | A sector-aligned offset whose 16 bytes at header +0x20 equal the tree fsid (research.md §10.10) | "node found", "block" without qualification |
| **valid** candidate | Passes every check that needs no referrer | "correct", "authentic" |
| **live** / **backup-reachable** / **unreferenced** / **invalid** | Reached from the current state / from a backup root only / from neither / some check failed (README `scan`) | "allocated", "free" (these are allocator terms) |
| **orphan** | A *valid* copy that is backup-reachable or unreferenced. Invalid candidates are never orphans | "orphan" for any stale or unvalidated block |
| **unreferenced** | The subset of orphans that no current or backup walk reaches | using "unreferenced" and "orphan" interchangeably |
| **stale block** | The probe's unvalidated count: fsid match and generation below the primary superblock's (EXP-000 §2) | "orphan", "deleted", "recoverable" |
| **legacy-compatible orphan** | The prototype's definition: csum ok, generation below the superblock's, nodesize-aligned | quoting "71 orphans" without the definition |
| **orphan items** (Bhat & Wani) vs **kernel ORPHAN_ITEM (0x30)** vs **orphan node** | Items beyond `nritems` / the kernel's pending-deletion marker / an orphaned tree block (research.md §8.1 defect #6) | "orphan" without saying which |
| **candidate root** | A valid scanned block that no indexed internal block one level up, of an acceptable owner and of its generation or a newer one, points to, at any level | "root", "old root" alone |
| **candidate root-tree block (state)** | An owner-1 candidate root; evidence of one root tree as far as that block reaches, not proof of a whole committed state | "historical filesystem state", "snapshot", "generation recovered", "version" |
| **state beyond the backups** | A state whose root-tree block neither the superblock nor a backup slot names | "older than the backups" (not implied) |
| **complete** / **completeness** | Found / referenced distinct blocks of the root tree and every ROOT_ITEM-named tree, chunk and log trees and ROOT_ITEMs naming tree 1 excluded | "fully recovered", "intact filesystem" |
| **slot reference** vs **distinct block** | 26 references (superblock root + chunk, 4 × 6 backup trees) name 14 distinct blocks on s01 | "26 roots", "14 of 26 roots survive" |
| **coverage agreement** | Equal counts computed from btrfska's own plan and prefilter under the probe's rules | "validated against", "independently verified", "matches ground truth" |
| failure classes **reused**, **mismatch**, **corrupt**, **overwritten**, **zeroed**, **unreadable**, **unmapped** | README "Failure classes" | "damaged" for `reused`; "erased" or "wiped" for `zeroed` |
| **zeroed** | Reads as zeros through this block layer (virtio sparse-file TRIM) | "physically erased", SSD claims |
| discard rows **none**, **async (quick unmount)**, **sync** | "none" = no TRIM reaches the image file; the guest still mounts `discard=async` | "no discard option", "async discard" without the unmount qualifier |
| **root set** | The superblock's or one backup slot's trees plus every tree its root tree's ROOT_ITEMs name | "backup" alone |
| **foreign superblock copy** | A valid copy whose fsid differs from the anchored one | "corrupt superblock" |
| **hardened candidate definition** | Resists the planted higher-level block case; residual vector documented | "forgery-resistant", "tamper-proof", "secure" |
| **image bytes** vs **allocated (device) bytes** | EXP-003 §6 | "disk throughput" for sparse-image rates |

**General words to avoid:** "proves", "guarantees", "all history", "recovers files" for any M2
result, "generalises", "SSD" for virtio results, "verified content" before data-checksum
verification (M6), "backup-root-bounded" for Beyond Carving (§5.3; research.md §10.12), "novel" for
discovering roots beyond the backups.

### 13.2 How to cite experiment numbers

- Cite the record and section with every number: "(EXP-000 §6)", "(EXP-002 §6.3)". For
  deterministic per-image results without an EXP record, cite the image name and the command, and
  promote them to a record before submission (§8 "Ready-det").
- Guest-driven results: always "median (min–max), N = 15". Never quote a single run as a constant
  (plan.md §7). Claim effects only at the resolution the spread supports.
- Copy digits exactly as recorded (3 277.1, not 3.3 GB/s; 8.7 %, not "about 9 %"). Derived
  percentages are allowed only if the record states them.
- Carry the record's caveat into the same paragraph or caption (balance artefact, coverage
  agreement, virtio TRIM, sparse image).
- Say which unit a count is in: physical copies, distinct logical blocks or slot references.
- Pre-registered vs exploratory: EXP-002's agreement was pre-registered; its discovery results are
  observations.
- Kernel behaviour read from source is cited as "kernel v7.0 `file.c:lines`" and labelled "read from
  source, not measured".
- A number enters the paper only if a committed script regenerates it (plan.md §7).

### 13.3 Naming and anonymity

- **`btrfska` is a placeholder** name (plan.md §3.4). Use a macro (for example `\toolname`) in the
  LaTeX source so it can be renamed or anonymised in one place.
- If the venue is double-blind, remove the repository URL, the corpus DOI and the tool name from the
  submission, and describe the artifact as "available to reviewers on request" per the call's rules
  (**check**).

---

## Appendix A: `CHECK:` list

Places where committed documents disagree. Resolve before the related text enters the paper.
Resolved items stay in the list, marked, so that their numbers remain valid pointers.

1. **Resolved 2026-09-15.** Corrected in plan.md §1 (C3 row, "Not building" list), §5 M7 and §8,
   and in research.md §10.1 (claim table), §10.2, §10.6 item 2, §10.7, §10.10 and §10.11; the
   correction and its sources are recorded in research.md §10.12. Beyond Carving scans chunk-mapped
   tree regions (Algorithm 3, §VI.E.1), independently of the superblock's root pointer (§X.G); the
   backup-root-bounded tools are SecurityRonin `recover_deleted` and `btrfs restore` without
   find-root. The original finding follows.
   **Beyond Carving's old-root discovery is described as backup-root-bounded, but its paper scans
   for historical root-tree blocks.**
   - plan.md §1 (C3): "Both are existence-only and backup-root-bounded (≤ 4 generations)"; plan.md §8:
     "Beyond Carving answers *'what was deleted?'* from ≤ 4 backup roots"; research.md §10.10: "a tool
     bounded by the four backup roots (Beyond Carving, SecurityRonin, plan.md §1)"; research.md §10.11:
     "A tool bounded by the four backup roots (plan.md §1) sees generations 35–38 only".
   - Against: research.md §4.1 (Algorithm 3 "scan the image regions the chunk tree maps to tree
     blocks … per generation, retain the block with the highest level"), and the paper itself,
     `docs/papers/pandey_beyond_carving_2026.pdf` §VI.E.1 and Algorithm 3 ("scans
     filesystem regions mapped to Btrfs tree blocks using the chunk tree"; "for each candidate tree
     block b in mapped tree regions").
   - Draft position: SecurityRonin `recover_deleted` and `btrfs restore` without find-root are
     backup-root-bounded; Beyond Carving and find-root are not, but by their description they scan
     only chunk-mapped tree regions.
2. **Resolved 2026-09-15: plan.md M7 now separates states reachable by scanning the current chunk
   map from states only outside it or only in unreferenced blocks.**
   **The beyond-4-generations test design assumes Beyond Carving misses such files.** plan.md §5 M7:
   "confirm anchored methods (Beyond Carving's approach, `btrfs restore`, SecurityRonin
   `recover_deleted`) miss it". By item 1, a Beyond Carving-style scan may still find a state beyond
   the backups while it lies in a chunk-mapped region. Redesign the test (§10 G4).
3. **Resolved 2026-09-15: research.md §10.7 now attributes backup `fs_root` diffing to SecurityRonin
   only.**
   **Backup `fs_root` diffing attributed to Beyond Carving.** research.md §10.7: a diff of
   `backup_fs_root` states "is the method attributed to Beyond Carving and SecurityRonin
   `recover_deleted` in plan.md §1". Against: research.md §4.1 ("scoped per-subvolume") and the paper
   §VI.E.2, which extracts filesystem and subvolume roots from each historical root tree. The
   limitation applies to a one-FS_TREE backup diff (SecurityRonin, research.md §10.2), not to
   Beyond Carving as described.
4. **Resolved 2026-09-15: the heading `## 2026-09-15 — M1c: extent reads, decompression, oracles,
   EXP-001` now stands at catalog.md line 1283, directly above the unchanged entry text.**
   **M1c catalog entry had no heading.** plan.md §5 M1 status and `experiments/EXP-001.md` cite
   "catalog.md M1c entry", but in catalog.md the M1c text (from "- **Branch:**
   `feature/m1c-extent-reads`", line 1221 before the fix) followed the M2a entry's "For M2b" list
   without a `## 2026-09-15 — M1c …` heading, so it read as part of M2a.
5. **Blocks per surviving state.** `experiments/EXP-002.md` §6.3: "30 of them have every referenced
   block found (8–13 blocks each)"; research.md §10.11: "8–14 blocks each". Probably different scopes
   (EXP-002 covers the discard trio; §10.11 includes `m1_sha256_bgt`, which has a block-group tree),
   but neither says so.
6. **"21/71 orphans outside the chunk map".** plan.md §1 (C6) and catalog.md 2026-08-14 give 21 of 71
   (prototype definition). catalog.md M2a and research.md §10.10: btrfska finds 20 valid orphans
   outside the map on `sandbox.img`; the prototype's 21 includes the invalid empty generation-1
   fs-tree leaf. The paper must name the definition with the number. **Added 2026-09-21 (M5a):**
   whichever number is used, these blocks are not remnants of user activity. The historical chunk
   maps of generations 1 to 5 place all 20: they belong to the two temporary chunks `mkfs.btrfs`
   creates at 1 MiB and 5 MiB and removes. The sandbox therefore shows that blocks outside the
   current map exist and can be placed, not that a balance happened; s01 (EXP-007) shows that.
7. **EXP-003 "slowest cell".** `experiments/EXP-003.md` §8: "slowest cell 501.0 MB/s, 100 % cold";
   the §6.1 table gives that cell's median as 512.2 and 501.0 as its slowest run.
8. **Stale "Assets" and code inventory in catalog.md.** catalog.md bottom sections (dated
   2026-08-17) still describe `sandbox.img` as holding "a complete gen-13 backup-root state" and "71
   orphaned nodes (21 outside the chunk map)"; research.md §10.5 corrects it to four backup states
   (gens 11–14), and catalog.md M2a reconciles the 71.
9. **Bhat & Wani size bands.** research.md §4.6 and plan.md §5 M7: files "< 1 KiB and > 4 KiB recover
   best, 2–4 KiB worst". The paper's abstract (`docs/papers/bhat_wani_forensic_analysis_btrfs_2018.pdf`, p. 1): "files with size 3–4 KB have least chances of
   recovery". Read the body before citing either band.
10. **Toolan & Humphries citation.** research.md §4.4 and §4.8 cite the SSRN preprint (DOI
    10.2139/ssrn.7138910); research.md §10.1 and plan.md §1/§8 say to use FSI:DI 58:302198. Use the
    journal version.
11. **Resolved 2026-09-15 in research.md §4.4 (Schwietert & Hilgert, FSI:DI 57:302123).**
    **Author order of "Mind the slack?".** research.md §4.4 table: "Hilgert & Schwietert 2026";
    research.md §4.7 and the PDF (`docs/papers/schwietert_hilgert_mind_the_slack_2026.pdf`): Schwietert, Hilgert.
12. **dissect.btrfs as foundation.** research.md §1 item 3, §2.2 and §3 still present dissect.btrfs as
    the substrate to import; plan.md §3.5 makes it a test oracle only (annotated in research.md, but
    the §3 table is not).
13. **Number of gaps.** research.md §1 item 2 says "seven concrete gaps"; research.md §6 lists G1–G9.

---

*End of draft starter. Update the status banner and §4 whenever a milestone lands.*
