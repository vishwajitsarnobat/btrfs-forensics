# Research Reference — Btrfs Forensic Recovery

> **Verified:** 2026-08-17. Every claim below was checked against primary
> sources (repos, papers, full texts) on that date unless marked otherwise.
> Companion docs: [`plan.md`](plan.md) (build plan), [`catalog.md`](catalog.md)
> (development history).
>
> **Paper library:** 18 papers are downloaded and read in `docs/`. Per-paper
> digests: §4.1 (Beyond Carving), §4.6 (the 5 foundational originals), §4.7
> (the 13 newly downloaded, grouped by theme). §4.8 lists 6 relevant papers
> that could not be downloaded from this environment (paywall/Cloudflare),
> with verified citations + abstracts.
>
> **Refresh 2026-09-15:** see **§10** (new prior art incl. the
> `SecurityRonin/btrfs-forensic` Rust library; dissect.btrfs validates
> nothing; TSK `develop` now has experimental btrfs; remap tree merged in
> kernel 7.0 as experimental; discard/TRIM survival measurements; rootless
> QEMU/KVM image generation; M1-branch archaeology; ranked plan changes in
> §10.6). Items in §1–§8 contradicted by §10 are listed there; §10 wins.

---

## 1. Executive Summary

1. **The headline capability — "recover deleted files from a raw Btrfs
   image" — is published and implemented.** Pandey, Jain & Shetty, *Beyond
   Carving: Deterministic Deleted File Recovery in Btrfs*, IEEE Access
   14:120632–120660 (July 2026), is open access (CC BY); we obtained and
   read the full text (§4.1). Open-source, the capability exists as
   `btrfs-find-root` + `btrfs restore -t` (and wrappers), `btrfscue`, and
   the FKIE Sleuth Kit fork. Commercially, UFS Explorer and R-Studio ship it.
2. **But no tool or paper covers the whole space, and seven concrete gaps
   exist nowhere** (§6): orphan-item/slack metadata archaeology,
   free-space-tree forensics, generation diffing into timelines,
   confidence+provenance reporting, hiding detection, orphaned-chunk
   forensics, and modern-feature-complete recovery (zstd + non-crc32c csums
   + RAID in one tool). "Beyond Carving"'s own stated future work — deep
   leaf scanning, historical chunk-tree reconstruction, deleted-subvolume
   recovery — is precisely where our prototype already is.
3. **The strongest reusable foundation is `dissect.btrfs`** (Fox-IT, pure
   Python, AGPL-3.0): raw-image file-like I/O, multi-device, RAID math, all
   three compressions, and `BTree(root_offset=…)` opens a tree at **any
   bytenr** — exactly the primitive anchored historical walking needs. It
   has **no recovery logic and no checksum verification** — which is the
   space our contribution occupies (§2.2). **Refined in plan.md §3.5
   (2026-09-15):** dissect.btrfs maps only through its own current chunk
   tree, so it is kept as a test oracle only; all runtime parsing, extent
   reads and decompression are ours, and the tool is Apache-2.0 (§10.6).
4. **Sleuth Kit upstream has no Btrfs support at all** — PR #413 (2015) was
   closed unmerged in Oct 2024; only the dead FKIE fork (last push 2022) has
   it. "TSK can't parse Btrfs" is the standard baseline claim in this
   literature (§2.3). **Corrected in §10.2:** experimental Btrfs was merged
   on TSK `develop` 2024-11-27 (PR #3065), unreleased.
5. **Stack verdict (§7):** pure-stdlib Python is non-viable at TB scale
   (~15–40 h/TB); Python + numpy/mmap + `crc32c` C-ext reaches I/O-bound
   (~20–75 min/TB); the end-state is a Rust scan core under a Python
   research/API layer (PyO3/maturin) — the pattern Dissect itself already
   uses (Rust fast paths in `dissect.util`). SQLite is the right catalog.
6. **No public btrfs deleted-file benchmark corpus exists** (§5) — not at
   digitalcorpora.org, not at NIST CFReDS, and the Wani & Bhat "dataset" is
   tables inside the article, not images. Every paper self-builds
   before/after image pairs and reports recovery rate + hash-match rate.
   Releasing the first public btrfs recovery corpus is itself a publishable
   contribution.

---

## 2. Open-Source Landscape (verified per-repo)

Reusability verdicts: `library` (build on it) · `fork/extend` ·
`subprocess` (wrap the CLI) · `reference` (study the code/algorithm) ·
`benchmark` (compare against) · `irrelevant`.

### 2.1 btrfs-progs (kdave/btrfs-progs) — C, GPL-2.0, very active

<https://github.com/kdave/btrfs-progs>

- **`btrfs restore`** (`cmds/restore.c`): salvage files from an unmountable
  image, read-only. `-t <bytenr>` reads the root tree from an alternative
  address (feed it `btrfs-find-root` output); `-f <bytenr>` restores one
  subvolume tree; `-l` lists tree roots; `-D` dry-run listing; `-m/-x/-S`
  metadata/xattrs/symlinks; **decompresses zlib, lzo, zstd**.
- **`btrfs-find-root`**: scans metadata for tree blocks filtered by header
  owner/level/generation; caches `generation → {highest level, blocks}`; a
  generation whose top level has exactly one block is a candidate old root.
  This is the canonical old-root discovery algorithm; `-a` scans
  exhaustively.
- **`btrfs rescue chunk-recover`** (linear device scan → rebuild chunk
  tree), **`super-recover`** (pick best superblock mirror by generation),
  **`btrfs check --init-extent-tree`** (rebuild extent tree from reachable
  blocks), **`btrfs inspect-internal dump-tree -b <bytenr>`** (dump any
  block — our ground-truth/debug view).
- Libraries: `libbtrfsutil` (LGPL) is **ioctl/mounted-only** — useless for
  raw images. `libbtrfs` (GPL-2.0) is a legacy stub; the real parsing code
  in `kernel-shared/` has no stable library API.
- Does NOT do: orphan-item mining, deleted-file listing, confidence/
  provenance, free-space-tree analysis, generation diffing.
- **Verdict: subprocess + reference + primary benchmark.**

### 2.2 fox-it/dissect.btrfs — pure Python ≥3.10, **AGPL-3.0**, active

<https://github.com/fox-it/dissect.btrfs> · PyPI `dissect.btrfs` (v1.10,
2026-02; 37 releases since 2022; consumed by `dissect.target`)

Verified by reading `btrfs.py`, `tree.py`, `stream.py`:

- `Btrfs(fh)` takes **file-like objects, including a list of devices**
  (multi-device volumes by FSID). Superblock, sys-chunk-array, chunk tree,
  logical→physical mapping.
- RAID profiles implemented in `_get_stripe_read_info()`: RAID0, RAID1,
  RAID1C3/C4, DUP, RAID10, RAID5/6 stripe math (healthy reads; **degraded
  RAID56 parity rebuild raises `NotImplementedError`**).
- Subvolumes/snapshots, default subvolume, `INode` with full timestamps
  (incl. ns), `open()` file streams, symlink resolution.
- **Compression: zlib, lzo, zstd** all verified in `stream.py` (lzo has a
  Rust-accelerated path in `dissect.util`); inline and sparse extents.
- **`BTree(btrfs, root_offset=<any bytenr>)`** with full `Cursor`
  navigation (`search/find/iter/walk`) — arbitrary/historical root walking
  is directly supported. Superblock struct includes `backup_roots` bytes
  (no convenience API).
- Does NOT do: **any recovery** (live tree only), **any checksum
  verification** of nodes, xattr public API, degraded RAID56.
- **Verdict: library / fork-extend — the strongest Python substrate.**
  Constraint: AGPL-3.0 propagates to a tool that imports it.
  **Refined 2026-09-15 (plan.md §3.3, §3.5):** used as a test oracle only,
  not imported at runtime.

### 2.3 The Sleuth Kit — C/C++, CPL/IBM-PL, **no upstream Btrfs**

> **Corrected in §10.2:** experimental Btrfs was merged on TSK `develop`
> 2024-11-27 (PR #3065), unreleased. The statements below describe PR #413
> and the released versions only.

- Upstream `sleuthkit/sleuthkit`: **no `btrfs*` in `tsk/fs/`**; PR #413
  ("Btrfs support", basicmaster, 2015) **closed unmerged 2024-10-26**.
- `basicmaster/sleuthkit`: the PR fork — dead (last push 2015).
- `fkie-cad/sleuthkit`: Fraunhofer FKIE pooled-storage fork (Hilgert et al.
  DFRWS 2017/2018) with multi-device Btrfs — **last push 2022-10-19**, far
  behind upstream, never merged.
- **Verdict: benchmark + reference** (the pooled-storage model is required
  citation); not a foundation.

### 2.4 cblichmann/btrfscue — Go, BSD-2, alpha (v0.7, sporadic)

<https://github.com/cblichmann/btrfscue> — pipeline: `identify` (heuristic
FSID sampling) → `recon` (scan all FSID-matching leaves into a **bbolt** DB
— not SQLite) → `ls`/FUSE mount of the rescue view → `recover`. Indexes
stale-generation leaves, so it surfaces recently deleted files. No RAID, no
multi-device, no documented compression support, crc32c-era assumptions.
**Verdict: reference + benchmark** — closest tool in spirit; not a
foundation.

### 2.5 Other recovery/repair tools

| Tool | Facts (verified) | Verdict |
|---|---|---|
| **lukeshu btrfs-rec** (btrfs-progs-ng, Go, ~GPLv3) <https://www.lukeshu.com/blog/btrfs-rec.html> | `rebuild-mappings` ("better chunk-recover"), **`rebuild-trees` re-attaches lost branches via graph analysis** — unique among all tools; JSON output; read-only FUSE of broken fs. Slow (~65 min/256 GB), TREE_LOG ignored, low activity since ~2023 | reference (must-cite prior art for reconstruction) |
| **davispuh/btrfs-data-recovery** (scanner in **D**, fixer in Ruby, Unlicense) | Block census → **SQLite** (offset, csum validity, generation, ownership, mirrors); fixer repairs corruption from good mirror copies / previous-generation blocks. No deleted-file recovery | reference (catalog-schema precedent; public domain) |
| **shujianyang/btrForensics** (**C++** on TSK lib, MIT, dead 2018) | TSK-style `fls/istat/icat/subls` on raw btrfs images; live trees only | benchmark |
| **theY4Kman/btrfs-recon** (Python/Construct → PostgreSQL) | DB-backed metadata census + write-back fixes; incomplete, unlicensed, 9 stars | reference |
| **danthem/undelete-btrfs** (Bash, GPL-3.0, active) | Automates find-root→restore at 3 depths; regex-driven, segfaults on damaged trees | benchmark (the UX bar to beat) |
| **msedek/btrfs_fixes** (C, GPL-2.0) | Extent-tree corruption repair where `check --repair` segfaults; explicitly no orphan/deleted handling | irrelevant |
| **qdm12/btrfs-recover-scripts** (archived 2019) | restore wrapper | irrelevant |
| **TestDisk/PhotoRec** (GPL-2.0+) | TestDisk undelete supports FAT/NTFS/exFAT/ext2 — **not btrfs**; PhotoRec is FS-blind carving (no names/paths/timestamps; CoW fragmentation hurts it) | benchmark (carving baseline) |

### 2.6 Read-path reference implementations (format cross-checks)

| Implementation | Facts | Value |
|---|---|---|
| **Linux kernel `fs/btrfs`** (GPL-2.0) | Authoritative: orphan handling, log-tree replay, free-space tree, RST | reference |
| **WinBtrfs** (maharmstone/btrfs, C, **LGPL-3.0**, very active) | Complete independent reimplementation: zlib/lzo/zstd, RAID0/1/10/5/6 + 1C3/C4, **xxhash/sha256/blake2**, free-space tree, block-group tree | best second implementation for format questions |
| **adam900710/btrfs-fuse** (C, core MIT, Qu Wenruo) | Read-only FUSE: all 4 csum types with verified reads, **RAID56 parity rebuild**, all compressions; compact | best small C read path to study |
| **GRUB `fs/btrfs.c`** (GPL-3.0+) | Read-only incl. RAID5/6 Reed-Solomon rebuild, zstd | reference |
| **U-Boot `fs/btrfs`** (GPL-2.0+, Qu Wenruo rewrite) | Compact read-only path | reference |

### 2.7 Libraries by language (for the stack decision)

- **Python:** `dissect.btrfs` (§2.2) — only real candidate.
  `knorrie/python-btrfs` (LGPL-3.0, active) is **ioctl/mounted-only** —
  confirmed irrelevant for raw images (useful only to harvest ground truth
  from a mounted test image, and as struct-definition reference).
- **Rust:** **`rustutils/btrfsutils`** <https://github.com/rustutils/btrfsutils>
  (created 2026-03, active; libs **MIT/Apache-2.0**, CLI GPL-2.0): crates
  `btrfs-disk` (on-disk parse/write), `btrfs-fs` (high-level read-only),
  `btrfs-transaction` (experimental offline CoW write), claims full 7-phase
  `btrfs check` and chunk-recover. Young (13 ⭐), claims need independent
  testing — but the only permissively-licensed library-first offline
  implementation found. **`GodTamIt/btrfs-diskformat`** (BSD-2, `no_std`,
  zerocopy): struct layouts only, no I/O/logic. Other crates (`btrfs`,
  `libbtrfs`) are ioctl wrappers — irrelevant.
- **Go:** `btrfscue` (§2.4) and `btrfs-rec` (§2.5) as prior art;
  `dennwc/btrfs` is ioctl/send-stream only. Weakest ecosystem here.
- **C:** btrfs-progs internals (no stable API) or btrfs-fuse (MIT core).

### 2.8 Commercial (capability bar; benchmark-only)

- **UFS Explorer / Recovery Explorer** (SysDev Labs): claims full btrfs —
  deleted files, post-format, btrfs-native RAID incl. Synology SHR,
  compressed reads. Used as a baseline in Kim et al. 2021.
- **R-Studio**: baseline in Kim et al. 2021. **ReclaiMe Pro**: btrfs
  metadata scan + RAID reconstructor. **X-Ways**: advertises
  recoverable-vs-uncertain tiers for deleted files (crude confidence
  precedent).

---

## 3. What Can Be Reused, per Component

| Need | Best existing source | How |
|---|---|---|
| Superblock + mirrors + chunk map + logical→physical | `dissect.btrfs` | import |
| Walk any tree from any bytenr (anchored/historical walking) | `dissect.btrfs` `BTree(root_offset=…)` + `Cursor` | import |
| File extraction incl. zlib/lzo/zstd, sparse, multi-device | `dissect.btrfs` streams | import |
| Old-root discovery algorithm | `btrfs-find-root` | reimplement (algorithm is simple; ours must feed the catalog, not stdout) |
| Backup-root parsing | struct in dissect superblock / kernel `struct btrfs_root_backup` | thin code on top of dissect |
| Ground truth / debugging | `btrfs inspect-internal dump-tree`, mounted-image listings | subprocess in tests |
| Recovery baselines | `btrfs restore`, PhotoRec, btrfscue, undelete-btrfs, (UFS Explorer if licensed) | benchmark harness |
| Lost-branch reattachment ideas | `btrfs-rec` `rebuild-trees` | cite + study |
| Block-census SQLite schema ideas | davispuh scanner (public domain) | study |
| CRC32c/xxhash/sha256/blake2 | `crc32c` PyPI (SSE4.2), hashlib, `xxhash` PyPI; Rust `crc32c`/`crc-fast` | import |
| **Nothing exists** — must build | orphan/slack archaeology, FST forensics, generation diffing, confidence+provenance catalog, hiding detection, evaluation corpus | our code (port from prototype where it exists) |

---

## 4. Academic Corpus (verified citations)

### 4.1 The closest prior work — read in full (whole paper, 28 pp.)

**Pandey, Jain & Shetty, "Beyond Carving: Deterministic Deleted File
Recovery in Btrfs", IEEE Access 14:120632–120660, DOI
10.1109/ACCESS.2026.3713173** — received 2026-06-13, published 2026-07-14,
**open access (CC BY 4.0)**. PDF in `docs/`. Read cover to cover 2026-08-17.

**Who:** Manipal Institute of Technology, India — an **undergraduate**
CTF/security team (lead author Krish Pandey, B.Tech expected 2027; project
"Cryptonite"). The tool is **implemented in Python**. This matters for
positioning: it is a strong, well-engineered student project, not a
heavyweight lab program, and (their words) the paper's appendix output is
"heavily curated."

**Algorithm (their Algorithms 1–8), precisely:**
- Parse+validate superblock → current generation `Gc`; bootstrap chunk tree
  (logical→physical); read root tree; enumerate FS roots + subvolumes.
- **DiscoverHistoricalRoots (Alg. 3):** scan the image regions the chunk
  tree maps to tree blocks; parse each block header; keep a block as a
  historical root iff `header.owner == 1` (ROOT_TREE_OBJECTID) **and**
  `header.generation < Gc`; per generation, retain the block with the
  **highest level** (that is the root-tree root of that generation).
- **Per subvolume, three passes** over the same traversal engine:
  Pass A traverses the current FS tree → `PresentObjectIDs` + parent map;
  Pass B walks each historical FS tree (descending generation) → deleted
  candidates = objectids present historically but **absent from
  `PresentObjectIDs`**; Pass C reconstructs each candidate from inode +
  extent items, **bounded by the inode-declared size**.
- **Traversal (Alg. 2)** uses a `VisitedNodes` cache keyed by logical
  address (each CoW-shared node visited once) + prunes any child failing
  generation/blockptr/level validation (overwritten/reallocated blocks).
- **Deletion predicate:** `f` deleted wrt subvolume `s` iff ∃ `g < Gc` with
  `f`'s objectid in `s`'s FS tree at `g` and absent at `Gc`; **scoped
  per-subvolume**; rests on **objectid monotonicity**
  (`btrfs_get_free_objectid`, per-root `free_objectid` counter never reused).
- **Extent-accurate reconstruction (Alg. 8):** inline / single / multi
  (offset-sorted reassembly) / sparse (holes → zero-fill to inode size) /
  prealloc / compressed (per-extent compression-type field → decompress) /
  reflink-shared (resolved by logical address). Final truncate to inode
  size.

**Outcome taxonomy (their Table II/IV):** Complete · Overwritten-extent
(extent resolves but data block reused — undetectable without ground truth)
· Partial (some extents unmappable via current chunk tree) · Metadata-only ·
Failed. **This is a real, extent-resolvability-based confidence scheme** —
we must acknowledge it and differentiate (ours adds structural-provenance
confidence for *unanchored* artifacts they refuse to touch; see §6 note).

**Forensic soundness:** strictly read-only; deterministic (no RNG, no
host-state, reproducible SHA-256 per file); human-readable audit log
(schema in their Appendix A). Structured/machine-readable report is *their*
future work.

**Evaluation:** no public btrfs corpus exists, so self-built (Cases A–F).
Headline final image: 23 files, 9 deleted over 6 cycles → **6/9 full
integrity, 1/9 overwritten, 2/9 partial (missing chunk mapping), 0
metadata-only, 0 failed**. Case E (churn): 1000 files, 300 deleted, **300/300
recovered**; their Python analyzer **0.94 s vs 4.28 s** for
`btrfs-find-root -a`+`restore` (C) — faster because of the VisitedNodes
cache, higher peak RSS (310 vs 137 MiB). Case F: beats foremost/PhotoRec/
btrfscue/btrForensics/FKIE-TSK on byte-exact + path + metadata + deletion
classification (their Tables XIII–XIV).

**What it explicitly does NOT do (their §X + Table XIII caption) — our open
ground, in their own words:**
- **Orphan-item scanning is deliberately excluded** as an "edge case";
  Table XIII caption: orphan-item approaches "were characterized
  analytically rather than released as a recovery tool" [cites Wani & Bhat].
  → our G1 (they concede the data exists; they just don't mine it).
- **Deep leaf scanning** — leaves not reached via tree traversal — is
  §X.B **future work** ("cannot reliably reconstruct directory paths"). → G1.
- **Historical chunk-tree reconstruction** is §X.D **future work**; under
  block-group release/reallocation the current chunk tree can't map
  historical extents (their "Partial/missing chunk mapping" failures).
  → G6, and it is *exactly* our empirical 21/71-orphans-outside-the-chunk-map
  finding.
- **Deleted-subvolume recovery** is §X.E **future work** (whole-subvolume
  delete removes `root_item`; their Case C failed 2 files here). → G7.
- **Checksum-tree (EXTENT_CSUM) validation** is §X.H.6 **future work** (they
  verify only via external SHA-256; historical csum tree would turn
  "overwritten-extent" from undetectable into a detectable failure). → part
  of G4.
- **Multi-device/RAID** out of scope (single-device; SINGLE/DUP only,
  RAID1 partial). No **free-space-tree** forensics, no **log-tree**, no
  **per-file timelines** (they detect rename/move but discard the prior
  name — no lifecycle), no **hiding detection**. → G2, G3, G5, G9.

**Bottom line for us:** their contribution is *deterministic deleted-file
listing + extent-accurate content recovery from anchored historical roots*.
Our contribution begins where theirs ends — the artifacts they discard as
edge cases (orphan items, unanchored leaves), the reconstructions they defer
(historical chunk maps, deleted subvolumes), and the analyses they never
attempt (FST, timelines, hiding). We cite them as the state of the art and
position against their own stated future work.

### 4.2 Other 2025–2026 Btrfs recovery papers

| Work | Verified citation | Coverage / overlap |
|---|---|---|
| **MetaRecoverX** — Chaudhary, Panchal, Tak & Kumar | IJISRT 11(4):997–1003, Apr 2026, DOI 10.38124/ijisrt/26apr738 (OA; low-tier venue) | Signature-based **carving** (16+ types) + post-hoc metadata/EXIF + PDF/CSV reports; 85% btrfs recovery claimed; qualitative-only tool comparison. Not metadata-structure recovery — weak overlap |
| Pratyashrit, Sharma & Sathiyasuntharam | DMPedia LNMR IMPACT-26:347–353, 2026-03-13, DOI 10.65890/dmp.lnmr.IMPACT26.107 (OA, CC BY) | FS detection → free-block scan → content+metadata extraction → checksum verify → reports; XFS+Btrfs |
| Syed Vaheed Ali et al., "Efficient Recovery of Deleted Data and Metadata from XFS and Btrfs Filesystem" | ICPCSN 2025, IEEE, DOI 10.1109/ICPCSN65854.2025.11035132 | Same team lineage as above; methodology-level overlap |
| "Towards a practical usage for the Sleuth Kit supporting file system add-ons" | FSI:DI 50 (2024), S2666281724001239 (paywalled) | TSK add-on architecture demoed on ext4/XFS/**Btrfs**/F2FS |

### 4.3 Foundational Btrfs forensics (all verified)

| Work | Citation | Role |
|---|---|---|
| Bhat & Wani 2018, *Forensic analysis of B-tree file system (Btrfs)* | Digital Investigation 27:57–70, DOI 10.1016/j.diin.2018.09.001 | Source of the beyond-`nritems` "orphan-items" concept our prototype implements |
| Wani & Bhat 2018, *Dataset for forensic analysis of B-tree file system* | Data in Brief 18:2013–2018, DOI 10.1016/j.dib.2018.04.100 (OA, PMC5998747) | **Not disk images** — tables/records in-article only (§5.1); 6-step procedure + %-recovered baselines |
| Wani, Bhat & Dehghantanha 2020, anti-forensic capabilities of Btrfs | Aust. J. Forensic Sciences 52(4):371–386, DOI 10.1080/00450618.2018.1533038 | Slack/defrag/anti-forensics; source of our W1–W5 features |
| Rodeh, Bacik & Mason 2013 | ACM TOS 9(3), DOI 10.1145/2501620.2501623 | Design/format |
| Hilgert, Lambertz & Plohmann 2017 (pooled storage in TSK) | Digital Investigation 22:S76–S85 (DFRWS USA 2017, Best Paper; PDF on dfrws.org) | Pooled-storage model |
| Hilgert, Lambertz & Yang 2018 (multi-device Btrfs in TSK) | Digital Investigation 26:S21–S29 (DFRWS USA 2018, Best Paper) | Multi-device/RAID forensics |
| Toolan, *File System Forensics* (Wiley 2025), ch. 11 Btrfs | DOI 10.1002/9781394289820.ch11 | Textbook treatment; easy citation |
| Hilgert, *Contemporary File System Forensic Analysis* (PhD dissertation, Univ. Bonn, 2025) | bonndoc handle 20.500.11811/13313 | Evaluates Carrier's model against ZFS/**Btrfs**/MooseFS; consolidates the pooled/stacked-storage line |
| Hilgert et al. 2024, "Forensic implications of stacked file systems" | FSI:DI (DFRWS EU 2024), S266628172300197X (OA PDF on dfrws.org) | Extends the analysis model to stacked/distributed FS |
| Juch, *Btrfs filesystem forensics* (Diploma thesis, TU Wien, 2014) | repositum.tuwien.at 20.500.12708/7491 | Earliest btrfs forensics treatment (six artifact types); pre-dates Bhat & Wani |

### 4.3b CoW-analog recovery (APFS/ZFS — cite as related work)

| Work | Citation | Relevance |
|---|---|---|
| **Plum & Dewald 2018, "Forensic APFS File Recovery"** | ARES 2018, DOI 10.1145/3230833.3232808; tool "afro" | **Closest CoW analog to our approach**: deleted-file reconstruction from old APFS object-map/checkpoint versions ≈ btrfs generation recovery |
| Beebe, Stacy & Stuckey 2009, "Digital forensic implications of ZFS" | Digital Investigation, DOI 10.1016/j.diin.2009.06.006 | Foundational ZFS/CoW forensics |
| Leigh 2014, *Forensic Timeline Analysis of ZFS* | Honours thesis + BSDCan 2014 | Uberblock/TXG timelines — the ZFS mirror of generation diffing; non-peer-reviewed |

Post-2018 ZFS forensics: nothing credible found — the CoW-forensics
literature after 2018 is essentially the Hilgert line plus btrfs papers.

### 4.4 Anti-forensics / data hiding (all verified)

| Work | Citation | Relevance |
|---|---|---|
| **Toolan & Humphries 2026, "Hiding Data in Btrfs File Systems"** | SSRN preprint, DOI 10.2139/ssrn.7138910 | **Six btrfs hiding techniques** with exact offsets (list in §8.3), evaluated on capacity/stability/detection difficulty — the target list for our hiding-detection feature |
| Göbel, Baier & Türr 2024 | *Advances in Digital Forensics XX* (IFIP WG 11.9), Springer, pp. 225–246, DOI 10.1007/978-3-031-71025-4_12 | ForTrace+fishy generator for anti-forensic traces on NTFS/ext4/**Btrfs**; 3-level validation model; no hosted corpus |
| **Schwietert & Hilgert 2025** (Fraunhofer FKIE) | FSI:DI 54:301984, DOI 10.1016/j.fsidi.2025.301984 (DFRWS APAC 2025; OA PDF on dfrws.org) | Survey of 24 hiding publications + novel methods (snapshot misuse, lower file slack, volume-management slack) + standardized corpus with ground truth. **Corpus repo `fkie-cad/hide-and-seek-dataset` 404s as of 2026-08-17** — contact authors |
| Göbel & Baier 2018/2019, "fishy — A Framework for Implementing Filesystem-Based Data Hiding Techniques" | ICDF2C 2018, Springer LNICST, DOI 10.1007/978-3-030-05487-8_2; github.com/dasec/fishy | The hiding-technique implementation framework; the 2024 chapter adds its **Btrfs module** — our detector's adversarial test generator |
| Toolan & Humphries 2025, "Data hiding in symbolic link slack space" | FSI:DI, S2666281725000587 | Cross-FS symlink-slack study; **negative btrfs result** (btrfs never creates symlink slack) — worth citing |
| Hilgert & Schwietert 2026, "Mind the slack?" | FSI:DI (DFRWS USA 2026), S2666281726000806 | Empirical file-slack relevance across 12 FS implementations incl. CoW |
| Schneider et al. 2022, "Ambiguous file system partitions" | FSI:DI 42 (DFRWS EU 2022) | Guest FS hidden inside btrfs structures |
| Bhat, Al Zahrani & Wani 2020, "Can computer forensic tools be trusted…" | FSI | 4 commercial tools missed most anti-forensic attacks — motivates structural analysis |

### 4.5 Methodology analogs (ext4/XFS — design + evaluation templates)

| Work | Citation | Role |
|---|---|---|
| Kim, Kim, Shin, Jo, Lee & Shon 2021 | Electronics 10(18):2310, DOI 10.3390/electronics10182310 (OA) | **The evaluation template** (§5.2): before/after images, TSK + UFS Explorer + R-Studio baselines, recovery rate + hash-match accuracy |
| Lee, Jo, Eo & Shon, "ExtSFR" | Multimedia Tools & Appl. 79:16093–16111 (2019), DOI 10.1007/s11042-019-7199-y (paywalled) | DB-backed scalable ext recovery; 1 TB eval; criticized by Kim et al. for no hash verification |
| ForTrace framework | Göbel et al., FSI:DI 40:301344 (DFRWS EU 2022); github.com/dasec/ForTrace; ForTrace++ fork on GitLab | Synthetic user-trace dataset generation (btrfs arrived only via the 2024 IFIP work) |
| Carrier 2005, *File System Forensic Analysis* | book | Layer model (our scan regions = Carrier's layers) |
| Hargreaves & Patterson 2012 (timelines); Fairbanks 2012 (ext4); Buchholz & Spafford 2004 (metadata roles) | Digital Investigation | Cite for timeline/confidence framing |

### 4.6 Foundational-paper technical digests (load-bearing facts)

Distilled from full-text reads of the PDFs in `docs/`. These are the facts
the implementation and paper actually lean on.

**Rodeh, Bacik & Mason 2013 — the design (why orphans exist).**
- Btrfs is a *forest of CoW B-trees* anchored by the **superblock at fixed
  physical `0x10000`** — the **only block ever overwritten in place**;
  everything else is written to a new location. This is the mechanism behind
  orphan nodes: modifying any leaf CoWs the entire root→leaf path to fresh
  blocks and **leaves the old blocks intact** on disk until reclaimed.
- Key = `{objectid:u64, type:u8, offset:u64}` (17 B), lexicographically
  sorted, so all items of one object cluster. Leaf layout = items array
  growing forward + item-data growing backward, free space in the middle
  (this middle gap is "leaf slack"). Block header carries csum, fsid, flags,
  **generation**; internal-node pointers store the *expected* target
  generation so stale/misplaced blocks are detectable on read.
- **Ref-counts live in the extent tree, not in nodes** (so a refcount change
  doesn't CoW the node). An extent/metadata block is freed only when **all
  back-references reach zero** → deleted content survives as long as *any*
  snapshot/clone/old root still references it. Back-reference =
  `{root_objectid, generation, level, lowest_objectid}` (a logical hint
  resolved by lookup), and it doubles as the refcount. Extent items sorted
  by start address → range queries find every pointer into a disk region
  (the reverse-map operation our Mode-C reconstruction needs).
- Trees: root tree (index of all tree roots incl. subvolumes), fs trees
  (ref-counted, snapshottable), extent tree (free map + backrefs), checksum
  tree (per-page csums per extent), chunk tree (logical→physical) + device
  tree (physical→logical), transient reloc tree (defrag). Metadata defaults
  to RAID1 (DUP) even on one disk.
- Generations = checkpoint serial numbers (default 30 s commit); the commit
  ends by overwriting the superblock to point at the new tree-of-roots.

**Hilgert, Lambertz & Yang 2018 — multi-device + the recovery routes.**
- Concrete parse order (their Fig. 2): superblock `0x10000` → **system chunk
  array embedded in the superblock** (bootstrap logical→physical) → chunk
  tree → root tree → all other trees → fs-tree walk → inode → extent items →
  data. Chunk-item `type` = System/Metadata/Data; carries logical start
  (key offset), length, stripe_len, RAID level, num_stripes, sub_stripes,
  and per-stripe `{devid, physical offset, dev UUID}`.
- Logical→physical for striped chunks: `preStripeUnits = ⌊Δ/stripeLen⌋`,
  `targetStripe = preStripeUnits mod nStripes`,
  `phyOff = phyStripeOff + ⌊preStripeUnits/nStripes⌋·stripeLen + (Δ mod
  stripeLen)`. Single/RAID1 → `phyStripeOff + Δ`; RAID10 → pick one of each
  mirror pair then treat as RAID0. **RAID5/6 deliberately unsupported.**
- **Two practical routes to deleted files, both root-driven:** (1)
  **snapshots** — a file deleted in the live tree but present in a snapshot
  is fully recoverable (`icat`); called "an outstanding source." (2)
  **old root trees via the 4 `btrfs_root_backup` entries** in the
  superblock (each gives tree-root + chunk-root logical addrs + generation);
  `fls -T <oldroot>` lists a prior generation's files.
- **Critical limitation → our opening:** btrfs keeps only the **last 4**
  backup roots (ZFS keeps 128), so anchored old-root recovery reaches only
  **~4 generations back**, and fails entirely if the old *metadata* was
  overwritten. Deeper history survives only as **orphan nodes not referenced
  by any backup root** — which is exactly what free-space-scan / orphan
  archaeology (our G1), and not Beyond Carving's root-anchored method,
  reaches.

**Bhat & Wani 2018 — the Orphan-Items origin (Digital Investigation 27).**
- Defines **Orphan-Items**: `btrfs_item`s that persist *beyond*
  `ln_ItemCount` in a node — deemed invalid by btrfs but still holding a
  prior deleted entry. Detection: skip past `ItemCount` valid items, read
  residual item structures, validate `itm_DataOffset`/`itm_DataSize` against
  `sb_LeafSize` and `itm_Type` against known file/dir types, group by
  `itm_ObjectId`. Scanned in **both leaf and internal nodes** (a former leaf
  can be reallocated as an internal node — same block size, random
  allocation — leaving its old contents in the internal-node slack).
- 5-stage procedure: Superblock → Root-Tree → FS-Tree (recurse internal /
  compute first-orphan address in leaf) → Orphan-Item Analysis →
  Evidence-Extraction. Item-type hex codes they tabulate match our
  `constants.py` (INODE_ITEM 01, INODE_REF 0C, ORPHAN_ITEM 30, DIR_ITEM 54,
  DIR_INDEX 60, EXTENT_DATA 6C, ROOT_ITEM 84, …).
- **Recoverability heuristics (empirical, drive our corpus design):**
  recovery is *hard on a fresh FS and improves as it ages*; **merging**
  balancing destroys evidence, **redistribution** preserves it (they give
  the exact 10-item unbalancing conditions); files **< 1 KiB and > 4 KiB
  recover best, 2–4 KiB worst** (a 2–4 KiB inline file fills ~50–100% of a
  leaf → deletion forces merging). Orphan-Item byte corruption is tolerated
  (redundant `[disk block,len]`+`[file offset,len]` mapping).
- **What they do NOT do (our differentiation, confirmed):** no historical/
  temporal reconstruction (they extract a *single* deleted state; they
  acknowledge but never walk generation numbers / backup roots / snapshot
  roots); **no orphan-*node* carving** from unallocated space (they read
  orphan-items inside *live* nodes reached by walking the current tree); no
  csum-tree validation; no compression/RAID handling. Our prototype's
  raw-sweep orphan-*node* discovery already exceeds this paper; the plan's
  historical reconstruction + timelines exceed it further.

**Wani, Bhat & Dehghantanha 2020 — anti-forensics / slack (see §8.4 for the
corrections).** Establishes the five slack/reserved locations with exact
sizes (SB reserved 432 B at `0x10000`; SB mirrors at 64 MiB/256 GiB/1 PiB;
root_item/inode reserved 64 B/32 B; boot sector 64 KiB; regular-extent file
slack < block size; volume slack = trailing unallocated sectors) and the
key dichotomy: **checksum+scrub makes W1/W2/SB/root_item hiding
self-corrupting (detect as tamper), while W3/W4/W5 hide silently and evade
all existing tools (extract as payload).** Also: inline (leaf-resident)
small files are vulnerable to overwrite during node balancing; MAC-DTS
timestamps are forgeable and unprovenanced; sparse files can balloon and
destroy evidence when opened naively.

### 4.7 Local paper library — digests of newly downloaded papers (2026-08-17)

All PDFs below live in `docs/` and were read in full. Grouped by theme.
The five originals (Beyond Carving, Bhat & Wani 2018, Wani 2020, Rodeh 2013,
Hilgert 2018) are digested in §4.1 and §4.6. **18 papers total in `docs/`.**

#### A. Btrfs recovery tools & methods (the competitors and the antecedent)

**`metarecoverx_2026.pdf`** — Chaudhary, Panchal, Tak & Kumar, "MetaRecoverX:
Recovery of Deleted Data and Associated Metadata from XFS and Btrfs
Filesystems", IJISRT 11(4):997–1003, 2026 (OA). A Python tool (argparse CLI +
PyQt6 GUI) unifying signature carving (16+ types), metadata extraction
(Pillow/PyPDF2/python-docx EXIF+doc props), SHA-256 hashing, keyword search,
PDF/CSV reports. For btrfs it shells out to `btrfs-progs` to enumerate
subvolumes and "traverse B-tree leaf nodes for orphaned file references,"
falling back to raw block carving when traversal finds nothing. Eval: Ubuntu
24.04, XFS+Btrfs partitions, 8 file categories, 3 scenarios (rm / overwrite /
stress). Results: file recovery XFS 92% / **Btrfs 85%**; metadata XFS 88% /
**Btrfs 79%**; hash success 98/97%. **Relevance:** the closest sibling and
our most likely head-to-head baseline; it *mentions* orphan references but
does not implement true orphan-item/old-root recovery — it degrades to
carving, and its btrfs metadata number (79%) drops further across
snapshot/inode-reassignment boundaries. Reuse its scenario design + metric
definitions for comparability; **85/79% is the bar to beat**.

**`dmpedia_xfs_btrfs_recovery_2026.pdf`** — Pratyashrit, Sharma &
Sathiyasuntharam, DMPedia LNMR (IMPACT-26) 1:347–353, 2026 (OA). Allied
group / precursor to MetaRecoverX. Sequential workflow: read-only mount →
FS detection (`testdisk`) → FS-specific parsing (btrfs: B-trees, chunks,
snapshots) → deleted-file discovery → recovery (`btrfs restore` + "custom
scripts that traverse the B-tree and snapshots to locate metadata in leaf
nodes") → SHA-256 validation. Results: file recovery XFS 94.2% / Btrfs
87.8%; metadata XFS 89.5% / Btrfs 83.2%. Thin on on-disk mechanics (no
offsets). **Relevance:** cite for the workflow + comparative numbers and as
motivation ("btrfs metadata recovery across snapshots is unsolved");
differentiate on depth (they have no principled orphan-node algorithm).
Adopt their read-only-mount discipline + corruption scenario.

**`wani_bhat_dib_2018.pdf`** ⭐ — Wani & Bhat, "Dataset for forensic analysis
of B-tree file system", Data in Brief 18:2013–2018, 2018 (OA, the companion
to Bhat & Wani 2018). The direct antecedent of our approach: a **6-step
recovery procedure** extracting **Orphan_Items** (records persisting beyond a
node's `item_count`) from **both leaf and internal nodes**, validated against
a valid-entry lookup table, classified into directory-entry (names/paths) vs
extent-data (content) records. Files count double (dir entry + extent) in the
recovery-ratio metric. Env: Fedora Core 23, kernel 4.2, recovery tool in C;
use-cases built to force internal nodes (≥4 files), exercise inline vs
regular extents, and trigger each node-balancing mode. **This is the primary
method to cite and build on**; its use-case construction rules are a
ready-made evaluation matrix. Confirms (again, see §5.1) the "dataset" is
tables in the article, not downloadable images.

**`juch_btrfs_forensics_2014.pdf`** ⭐ — Andreas Juch, "Btrfs filesystem
forensics", Diploma thesis, TU Wien, 2014 (OA, 108 pp). The **best on-disk
reference** in the set: implements a btrfs driver for The Sleuth Kit.
Documents superblock at `0x10000` (only fixed structure, mirrored), key
triple `(object_id, type, offset)`, node header (level, `item_count`,
checksum), logical→physical via chunk tree (`pa = op + (la − ok)`) + reverse
via dev tree, inline vs regular extents, DIR_ITEM (name-hash) vs DIR_INDEX
(ordered), subvolume objectids 256≤x<UINT64_MAX. Defines six methods A1–A6.
**Crucial for our positioning:** Juch finds btrfs has **no inode table**, so
deleted inodes can't be found by table lookup — recovery "requires tree
forensics (or brute-force heuristics)"; he **deliberately did not implement
tree forensics** and explicitly names as future work "read deleted
files/metadata from *elder tree versions*" and "detect deleted entries by
analyzing node fill-rate" (items past `item_count`). **That future-work
paragraph is effectively our thesis statement** — Juch scopes our exact
contribution, and Wani & Bhat operationalized half of it (orphan-items) while
leaving elder-root reconstruction open. Empirical notes: `icat` = 100%
binary match on allocated files; zeroing-before-delete still leaves old
content readable due to CoW (in-place wipe tools silently fail on btrfs).

#### B. Forensic model & CoW-analog forensics (frame the method)

**`rodeh_btrees_shadowing_clones_2008.pdf`** — Ohad Rodeh, "B-trees,
Shadowing, and Clones", ACM TOS 3(4) Art. 15, 2008 (26 pp). The **theoretical
foundation** btrfs is built on. Solves combining strict shadowing (CoW) with
B-trees: remove leaf-chaining + use top-down B+-trees with proactive
split/merge on descent (bounds relaxed to ≈[b…3b]) so a modification shadows
each path node exactly once and never propagates above the immediate parent;
lock-coupling unifies locking + shadowing. The **clone algorithm** = btrfs's
mechanism: per-block refcounts in a free-space map, clone by copying only the
root + incrementing children's refcounts (lazy), sharing broken on write, 1
byte/block ⇒ 256 clones, clone-of-clone and single-file clone supported.
**Relevance:** the design rationale for our whole approach — old roots and
shadowed interior nodes persist until refcount 0 and reallocation, so deleted
files/old versions survive as unreferenced-but-intact subtrees; per-root
generation gives chronological ordering; refcount semantics define exactly
when a block becomes overwrite-eligible (our recoverability reasoning).

**`hilgert_dfrws_2017_pooled_storage.pdf`** — Hilgert, Lambertz & Plohmann,
"Extending The Sleuth Kit … for pooled storage file system forensic
analysis", Digital Investigation 22:S76–S85 (DFRWS USA 2017, Best Paper).
*(Note: retrieved artifact is the 31-slide presentation deck; the journal
article is not free-OA and dfrws.org is Cloudflare-blocked here.)* Inserts a
**Pool Analysis** step between Volume and File System analysis in Carrier's
model (detect members, detect config, reconstruct pool, tolerate incomplete
pools). Prototype for **ZFS** in the FKIE TSK fork; notably demonstrates
**accessing older versions of the ZFS CoW tree** (the ZFS analogue of our
old-root reconstruction). Btrfs named only as future work. **Relevance:**
cite for the extended forensic model and CoW-tree-including-old-versions
traversal principle.

**`hilgert_stacked_filesystems_2024.pdf`** — Hilgert, Lambertz & Baier,
"Forensic implications of stacked file systems", FSI:DI 48:301678 (DFRWS EU
2024, OA). Current DFRWS-EU **methodology template**: a six-axis evaluation
structure (identification, name correlation, data reconstruction, timestamps,
slack, file recovery) over MooseFS/GlusterFS/eCryptfs. **Relevance:** a
ready-made section skeleton + rubric for our results; its "deleted-upper-but-
intact-lower" recovery framing parallels our "deleted-in-live-tree-but-intact-
in-old-generation"; two-layer timestamp correlation maps to our multi-tree
cross-referencing.

**`beebe_zfs_forensics_2009.pdf`** — Beebe, Stacy & Stuckey, "Digital forensic
implications of ZFS", Digital Investigation 6:S99–S107 (DFRWS 2009, OA). First
forensic treatment of a CoW filesystem. CoW writes new blocks and doesn't
securely delete old ones ⇒ **numerous intact copies persist in unallocated
space**; the uberblock (128-entry ring, highest valid **TXG** = active)
enables chronological version ordering; no static inode/MFT table ⇒ recovery
traverses from roots, not fixed offsets; ditto blocks + snapshots/clones
multiply copies; compression + variable extents complicate hashing/carving.
**Relevance:** the canonical citation that CoW filesystems are *forensically
advantageous* for deleted-file recovery; every argument transfers to btrfs
(TXG↔generation, uberblock↔superblock/roots), and it pre-frames our
compression/variable-extent caveats.

#### C. Anti-forensics / data hiding (for the M6 detector)

**`schwietert_hilgert_datahiding_corpus_2025.pdf`** ⭐ — Schwietert & Hilgert,
"Data hiding in file systems: Current state, novel methods, and a
standardized corpus", FSI:DI 54:301984 (DFRWS APAC 2025, OA). Survey of 24
papers + novel methods + **the first public ground-truthed corpus**
(`github.com/fkie-cad/hide-and-seek-dataset`; each image ships a ground-truth
file giving **location, offset, length, and an extracted copy of the hidden
content** — adopt this as our detector's output schema). Consolidates the
btrfs hiding locations with offsets: 64 KiB pre-superblock region; **805 B per
superblock** (240 B @ `0x23B` + 565 B @ `0xDCB`); SB checksum = first 32 B
over content from `0x20`; **inode 160 B with 32 reserved bytes @ `0x50`**;
btrfs checksums cover BOTH metadata and data (the core anti-detection
challenge, shared only with ZFS). Novel btrfs methods: **snapshot hiding**
(snapshot sensitive files then delete from live FS; CoW keeps blocks),
RAID-mirror/parity hiding, lower file slack. 9 corpus scenarios (S1 file slack
… S7 hidden snapshots, S9 pooled-member slack). **Relevance:** our single most
useful evaluation asset + the survey backbone; scenarios S2/S5/S6/S7 are
directly btrfs. (Note §5.1: the GitHub link 404'd during the tool survey —
confirm availability or contact authors.)

**`goebel_generating_traces_filesystem_2024.pdf`** ⭐ — Göbel, Baier & Türr,
"Generating Usable and Assessable Datasets Containing Anti-Forensic Traces at
the Filesystem Level", IFIP DF XX, Springer 2024 (OA). The **most detailed
btrfs hiding recipe + parsing offsets** available: magic `_BHRfS_M` at
partition `0x10040`; chunk-tree logical addr @ SB `0x58`, bootstrap chunk map
@ SB `0x32B`; root-tree addr @ SB `0x50`; inode timestamp-nsec fields at inode
offsets `0x78/0x84/0x90/0x9c` (4 B each). Implements (in a **fishy** btrfs
module, exposed via **ForTrace**): (1) **timestamp hiding** in the 4-byte
nsec fields (max 16 B/inode; all-zero nsec = suspicious "cleared" state);
(2) **file slack** (recompute data-csum + node csum; inline files have no
slack; detect via `icat`>`istat` size delta); (3) pre-superblock 64 KiB;
(4) **node slack** — internal nodes fill only ~first 1000 B leaving ~15 KB
tail slack; leaf slack sits between the item-array and item-data. Uses a
3-level detectability model (Basic/Specialist/White-box). **Relevance:** the
concrete detection heuristics to implement in M6, plus a generator (fishy +
ForTrace) for our own labeled btrfs images.

**`goebel_fishy_framework_2018.pdf`** — Göbel & Baier, "fishy — A Framework
for Implementing Filesystem-Based Data Hiding Techniques", ICDF2C 2018,
Springer (OA; repo `github.com/dasec/fishy`). The framework the btrfs module
plugs into: modular Python, per-technique `write/read/clear`, JSON recovery
metadata (location/offset/length), Capacity/Detection/Stability ratings, and
a "detectable-by-fsck?" baseline. Originally ext4/FAT/NTFS. **Relevance:**
defines the C/D/S rating vocabulary + fsck-detectability baseline we should
reproduce; use its repo as a hidden-data generator.

**`hilgert_mind_the_slack_2026.pdf`** — Schwietert & Hilgert, "Mind the slack?
Reassessing the relevance of file slack in modern forensic investigations",
FSI:DI (DFRWS USA 2026, OA camera-ready; framework at
`anonymous.4open.science/r/mind-the-slack`). Cross-platform slack study over
12 FS. **Key btrfs findings:** btrfs is the **only Linux FS that preserves
slack through truncation** (metadata-only truncate leaves the block intact →
recoverable slack at the current block offset); **"ghost slack"** — any
append/overwrite triggers CoW, rewriting the block to a new offset and
leaving the **old block (with slack) as unreferenced data at the previous
offset**, visible only via raw imaging + unallocated-space carving. Metadata-
only ops (rename, fsck) don't trigger CoW. **Relevance:** two must-handle
detector cases (post-truncation live-block slack; CoW ghost slack in
unallocated space) — reinforces that our scan must cover unreferenced
regions, not just the live tree.

#### D. Evaluation methodology

**`kim_ext4_xfs_tsk_2021.pdf`** ⭐ — Kim, Kim, Shin, Jo, Lee & Shon, "Ext4 and
XFS File System Forensic Framework Based on TSK", Electronics 10(18):2310,
2021 (OA; downloaded from the `mdpi-res.com` CDN mirror). Our **evaluation
template**: self-built before/after disk-image pairs, baselines = original
TSK + UFS Explorer + R-Studio, metrics = **recovery rate + exact-recovery
accuracy via cryptographic hash match** (the field's correctness criterion,
which they introduced by criticizing prior work — incl. ExtSFR — for omitting
it). See §5.2 for the full protocol distilled from this paper.

### 4.8 Papers identified as relevant but NOT obtainable here

Blocked by paywalls or Cloudflare/host issues from this environment; verified
citations + abstracts are recorded. Fetch via an institutional/browser
session before finalizing the related-work section:

| Paper | Why it matters | Why it failed |
|---|---|---|
| **Toolan & Humphries, "Hiding Data in Btrfs File Systems", SSRN 2026** (DOI 10.2139/ssrn.7138910) | The definitive six-technique btrfs hiding list w/ exact byte counts | SSRN Cloudflare JS challenge; offsets reconstructed from Schwietert & Hilgert 2025 (§4.7 C, §8.3) |
| **Plum & Dewald, "Forensic APFS File Recovery", ARES 2018** (DOI 10.1145/3230833.3232808) | Closest CoW analog — recovers deleted files from old APFS checkpoint/object-map versions (tool `afro`) | ACM Cloudflare; no author OA copy found |
| **Kim et al. — verified obtained** (see §4.7 D) | — | (resolved) |
| **Lee et al., "ExtSFR", MTAP 79 (2019)** (DOI 10.1007/s11042-019-7199-y) | DB-backed scan-once-query-many precedent for our SQLite catalog | Springer paywall; no OA; sci-hub unreachable |
| **Vaheed Ali et al., IEEE ICPCSN 2025** (DOI 10.1109/ICPCSN65854.2025.11035132) | Companion to MetaRecoverX/DMPedia (XFS+Btrfs recovery) | IEEE paywall; no OA/sci-hub copy |
| **Hilgert, PhD "Contemporary File System Forensic Analysis", Bonn 2025** (handle 20.500.11811/13313) | Authority on multi-device btrfs pool reconstruction + CoW-tree traversal | Host `bonndoc.ulb.uni-bonn.de` unreachable (TCP timeout); companion works `hilgert_*` already in `docs/` cover much of it |

---

## 5. Datasets & Evaluation Norms

### 5.1 Public corpora: none usable

- **Wani & Bhat Data in Brief**: "Data is available within this article" —
  tables + supplementary DOCX; **no downloadable disk images**, no Mendeley
  record.
- **digitalcorpora.org**: FAT32/NTFS/ext3/HFS+ images only; no btrfs
  anywhere in their listings.
- **NIST CFReDS/CFTT**: deleted-file-recovery test images target
  FAT/NTFS/ext; no btrfs found in archive, portal bundle, or search.
- **Schwietert & Hilgert hiding corpus**: btrfs-relevant but targets
  *hiding detection*, and the published GitHub link is currently dead.

**Conclusion:** there is no citable public btrfs deleted-file-recovery
benchmark. We must generate our own — and releasing it (images + manifest +
per-file SHA-256 + operation log) fills a real gap.

### 5.2 How the field evaluates (synthesis of Kim 2021, ExtSFR, MetaRecoverX, Beyond Carving)

1. **Self-built ground-truth images**: 1–2 sizes (e.g. 1 GB + 100 GB),
   25–100 files of mixed types, imaged **before and after** deleting a
   controlled subset; scenario axes: simple deletion, partial overwrite,
   create/delete stress, (for us: snapshots, balance, defrag, compression,
   csum types, RAID).
2. **Baselines**: TSK (expected: "cannot parse btrfs" — itself a claim),
   PhotoRec-class carving, `btrfs restore`/find-root, btrfscue; 1–2
   commercial tools (UFS Explorer, R-Studio) if licensable. Beyond Carving
   used: foremost, PhotoRec, btrfscue, btrForensics, FKIE TSK,
   find-root+restore — our harness should match or exceed that set.
3. **Metrics**: recovery rate (recovered/deleted), **exact-recovery
   accuracy via SHA-256 match** (the de-facto correctness criterion since
   Kim et al.), metadata recovery rate (names/timestamps/permissions),
   runtime/scalability.

---

## 6. Gap Analysis — What Is Genuinely Open

Cross-referencing §2 (no tool does it) with §4 (no paper covers it):

| # | Gap | Evidence it's open | Confidence |
|---|---|---|---|
| G1 | **Orphan-item / slack metadata archaeology** — items beyond `nritems`, intra-node slack, kernel ORPHAN_ITEM (0x30) resurrection as a recovery source | No surveyed tool parses intra-leaf slack or orphan items; Beyond Carving scans whole valid blocks only (deep leaf scanning is its *future work*); only Bhat & Wani 2018 studied the artifact, without a maintained tool | High |
| G2 | **Free-space-tree forensics** (space_cache=v2, FREE_SPACE_INFO/EXTENT/BITMAP 0xDD–0xDF) — proving a block was freed, and overwrite-risk scoring | Zero tools, zero papers | High |
| G3 | **Generation diffing → per-file timelines** from multiple historical roots (backup roots + discovered old roots) | find-root finds roots, nothing diffs them; Beyond Carving diffs objectid *sets* (existence only), not full state/timeline with move/rename/content deltas | Medium-high (partially claimed by Beyond Carving) |
| G4 | **Confidence + provenance reporting** (per-artifact evidence chain, Confirmed/Probable/Unattached tiers spanning *anchored and unanchored* artifacts, csum-verified content) | **Partial overlap:** Beyond Carving has an extent-resolvability outcome taxonomy (Complete/Overwritten/Partial/Metadata-only/Failed) for anchored recoveries only; nobody scores confidence for unanchored orphan/slack artifacts or records a cross-mode provenance chain. davispuh block census, btrfs-rec JSON, X-Ways binary flag are the other partial gestures | Medium-high (differentiate from Beyond Carving's taxonomy, don't reinvent it) |
| G5 | **Hiding/anti-forensics detection** — flag non-zero reserved/slack regions, STRING_ITEM 0xFD, fake generations (target list = Toolan & Humphries's six techniques + Schwietert & Hilgert's methods) | Papers propose hiding; nobody ships detection | High |
| G6 | **Orphaned/relocated-chunk forensics** — metadata remnants outside the current chunk map (our sandbox: 21/71 orphans) + historical chunk-map reconstruction | Beyond Carving lists historical chunk-tree reconstruction as future work; chunk-recover rebuilds only for repair, not evidence | High |
| G7 | **Deleted-subvolume recovery** | Explicit Beyond Carving future work | Medium |
| G8 | **Public btrfs recovery benchmark corpus** | §5.1 — none exists | High |
| G9 | Log-tree (TREE_LOG) forensics — crash-window artifacts (DIR_LOG items) | btrfs-rec explicitly ignores it; no paper | Medium (value unproven) |

A dedicated literature sweep (2018–2026, incl. DFRWS 2023–2026 and FSI:DI
volumes, theses/dissertations) explicitly confirmed: **no academic work
exists** on btrfs free-space-tree/space_cache/log-tree forensics (G2, G9),
no dedicated paper names generation/transaction diffing as a forensic
technique (G3 — only Beyond Carving's objectid-set diff and pre-2018 ZFS
TXG work come close), and no systematic btrfs recovery-tool benchmark has
been published (supports G8).

What is **not** open (do not claim as novel): raw-image parsing without
mounting; anchored walking of current/backup/old roots; deterministic
deleted-file listing per se; chunk-tree rebuild for repair; carving;
SQLite-backed block census; multi-device/RAID parsing.

---

## 7. Stack Analysis

### 7.1 The workload

Scan = probe every nodesize-aligned (16 KiB) offset: 16-byte FSID compare
at header +0x20; crc32c only on hits; then parse hit nodes. 1 TB = 61M
probes. **I/O dominates**: 1 TB sequential ≈ 4–8 min NVMe, ~35 min SATA
SSD, ~2.5 h USB HDD. The only CPU question is keeping up with the disk.

### 7.2 Measured reality (analogous published benchmark: pattern-scan + CRC over large files)

| Approach | Throughput | 1 TB scan |
|---|---|---|
| Pure-Python byte loop | 6.4 MB/s | ~43 h — non-viable |
| Chunked stdlib `struct` | 18 MB/s | ~15 h — painful (≈ our current prototype) |
| numpy vectorized + C-ext CRC | 232 MB/s | ~75 min |
| numpy + multiprocessing (8 cores) | 900 MB/s | ~19 min — **I/O-bound** |
| Native (bulk_extractor/PhotoRec class) | disk-limited | I/O-bound |

(Source: robopenguins.com/python-optimization; bulk_extractor arXiv
2208.01639; PhotoRec ~500 GB/h on USB3 HDD.) The strided FSID prefilter
vectorizes perfectly (`mmap` + `np.frombuffer(...).reshape(-1, nodesize)[:,
32:48] == fsid`); hits are sparse so per-hit crc32c (`crc32c` PyPI —
SSE4.2, ~8–20 GB/s) is cheap. Note `zlib.crc32` is the wrong polynomial —
btrfs uses Castagnoli.

### 7.3 Ecosystem facts

- DFIR analysis tools are overwhelmingly Python (Dissect, plaso,
  Volatility 3); practitioners `pip install` into SIFT-class VMs; single
  static binaries are the norm only for *collection* agents.
- **Dissect itself ships Rust fast paths** (`dissect.util` LZ4/LZO wheels
  with pure-Python fallback) — the flagship "pure Python" framework already
  validates the hybrid pattern.
- PyO3/maturin is mainstream (polars, ruff, pydantic-core, cryptography);
  `maturin-action` CI produces abi3 wheels for Linux/macOS/Windows.
- Rust crates needed all exist and are production-grade: zerocopy/binrw,
  crc32c/crc-fast (cites btrfs), memmap2, rayon, rusqlite (bundled), clap.
- Go: viable but no Python-API story, verbose binary parsing,
  cgo-free SQLite ~25–100% slower on inserts; its DFIR wins are endpoint
  agents, not analysis libraries. Zig: pre-1.0, ecosystem too thin. C/C++:
  proven ceiling but memory-unsafe parsing of adversarial images and the
  community is drifting away (TSK's own btrfs merge was reverted).
- **SQLite is the right catalog**: insert-heavy build + indexed reverse
  lookups is exactly its shape (DuckDB wins only at analytical scans — keep
  it as an optional export target); single-file evidence artifact is
  hashable and chain-of-custody friendly; stdlib `sqlite3`/`rusqlite` both
  clean. Tune: WAL off during build, batched transactions, index after
  load.
- Reproducibility: `uv` lockfile + `uvx <tool>` one-liner is the strongest
  artifact-evaluation story; notebooks importing the tool directly
  regenerate the paper's tables from `evidence.db`.

### 7.4 Verdict (decision recorded in plan.md §3)

Python stays the research/API/logic layer. Stage 1: numpy+crc32c fast scan
path (days of work, makes TB experiments feasible). Stage 2: Rust scan+parse
kernel via PyO3/maturin with the numpy path as fallback. All-Rust CLI
rejected for now (kills notebook-driven research iteration and slows the
paper); all-Go and Zig rejected; building on dissect.btrfs adopted with the
AGPL-3.0 consequence accepted (see plan.md §3.3 for the license analysis).

> **Superseded 2026-09-15:** plan.md §3.5 now owns all runtime parsing,
> extent reads and decompression, keeps dissect.btrfs as a test oracle only,
> and plan.md §3.3 licenses the tool Apache-2.0 (see §10.6).

---

## 8. Prototype Audit (carried forward from 2026-08-14, still open)

### 8.1 Correctness defects in the current code

1. **CRC32c hardcoded** — superblock `csum_type` (offset 0xC4) supports
   crc32c/xxhash/sha256/blake2b (kernel ≥5.5); on any non-crc32c fs every
   node fails validation and the tool silently finds nothing. Superblock's
   own checksum never validated.
2. **DEV_ITEM UUID offset bug** — reads bytes 82:98 (the FSID) as the
   device UUID; `dev_uuid` is at 66:82.
3. **ROOT_ITEM "reserved region" false positives** — flags bytes 235:439,
   which hold real modern fields (uuid, times, generation_v2…); only the
   trailing `reserved2` is unused. Once fixed, this check becomes a hiding
   detector (G5).
4. **MIXED_GROUPS blind spot** — targeted scan skips DATA chunks; wrong
   when incompat flag MIXED_GROUPS is set (common < 10 GiB). Parse
   `incompat_flags` (SB 0xBC).
5. **Superblock mirrors ignored** (0x4000000, 0x4000000000 — constants
   exist, never read).
6. **Kernel ORPHAN_ITEM (0x30) unparsed** — the canonical deleted-inode
   marker; distinct from Bhat & Wani "orphan-items" (beyond-`nritems`).
   Disambiguate terminology in all docs.
7. Single-stripe chunk translation only (no RAID); no compression handling;
   no xattr (0x18), INODE_EXTREF (0x0D), EXTENT_CSUM (0x80),
   ROOT_REF/BACKREF (0x9C/0x90), SHARED_*_REF (0xB6/0xB8),
   TREE_BLOCK_REF (0xB0), BLOCK_GROUP_ITEM (0xC0), DEV_EXTENT (0xCC),
   FREE_SPACE_* (0xDD–0xDF), DIR_LOG_* (0x3C/0x48), STRING_ITEM (0xFD).
8. **EXTENT_ITEM address taken from the wrong key field** (added
   2026-09-15, found on `feature/m1-backup-roots` commit `1d48203`, §10.5).
   An EXTENT_ITEM key is `(logical address, EXTENT_ITEM 168, length in
   bytes)`: the *objectid* is the extent's logical start and the *offset*
   its length (METADATA_ITEM 169 stores the tree level in the offset
   instead). `legacy/utils/btree.py:888` sets
   `current_extent_laddr = key_offset`, so every EXTENT_DATA_REF backref it
   prints carries the extent length as its address. On `sandbox.img` the
   gen-13 extent tree (leaf 30474240) holds
   `key (13631488 EXTENT_ITEM 5242880)` for `large_target.txt`, whose
   EXTENT_DATA says `disk byte 13631488 nr 5242880`, so legacy would report
   address 0x500000 instead of 0xD00000. The M4 rewrite must use the
   objectid, and golden tests must not freeze legacy backref addresses
   (plan.md §4.1, §4.3).

### 8.2 What the prototype got right (the parts worth porting)

Beyond-`nritems` orphan-item scanning (leaf + internal), internal/leaf
slack mining, targeted-scan region derivation (typed chunks + unmapped
gaps), the `(inode, generation)` keying, move/rename tagging, and the
sandbox empirical results (catalog.md, 2026-08-14 entry) — especially the
**21/71 orphans outside the current chunk map** observation feeding G6.

### 8.3 Hiding-technique target list (Toolan & Humphries offsets → G5 detector)

| Technique | Location |
|---|---|
| Pre-superblock | 0x0–0x10000 |
| Superblock reserved | 0xF0 bytes at SB+0x23B |
| Superblock slack | 0x235 bytes at SB+0xDCB |
| Chunk-array slack | up to ~0x77F free bytes at SB+0x32B+used |
| INODE_ITEM reserved | 0x20 bytes at +0x50 |
| Internal-node slack | after key pointers |
| STRING_ITEM 0xFD | any leaf |
| Nanosecond timestamp fields | inode times |
| File/extent slack | past EOF within allocated extent |

Plus Schwietert & Hilgert 2025: snapshot misuse, lower file slack,
volume-management slack.

### 8.4 Corrections to prior internal claims (from full-text reads)

- **Defrag-hazard heuristic is mis-attributed.** The prototype's
  "defragmentation hazard" warning was credited to Wani et al. 2020, but
  that paper **never discusses defragmentation, balancing, TRIM, or
  snapshot rotation** — the word "defrag" does not appear. The CoW
  evidence mechanism it establishes is the *opposite* (CoW *preserves*
  stale copies). Action: do not port the heuristic as-cited (plan.md §4.2);
  re-derive defrag's evidence-destroying effect from Rodeh 2013 §5
  (the relocator/reloc-tree rewrites live extents and frees old copies) or
  drop it.
- **Slack features split into two forensic classes, not one** (Wani 2020,
  measured): leaf slack (W1) and internal-node slack (W2) hiding
  **corrupts the filesystem** (checksum+scrub self-corruption) — so these
  are *tamper/corruption-signal* indicators, not payload stores. Boot
  sector (W3, first 64 KiB), regular-extent **file slack** (W4, < block
  size), and **volume slack** (W5, trailing unallocated sectors — "the most
  secure") hide data **without corrupting the fs and are invisible to
  BFM/FTK/btrfsck auto-extraction** (only manual character-filtering finds
  them; `bmap` "fails miserably" on btrfs). So W3/W4/W5 are real
  hidden-payload extraction targets; W1/W2 are corruption flags. The
  detector (M6) must treat them differently.
- **Superblock/`btrfs_root_item` reserved-area hiding** is self-defeating
  (SB is reinitialised every commit → data lost on remount; root_item
  hiding corrupts the fs) — useful as a *corruption* signal, consistent
  with fixing prototype defect #3 into a detector rather than an extractor.

---

## 9. Maintenance

- Re-run the prior-art check before each milestone (DFRWS USA/EU/APAC
  seasons, FSI:DI issues, IEEE Access, the Wani/Bhat and Shon-group author
  feeds, btrfs-progs releases, rustutils/btrfsutils progress).
- Anything discussed in chat that matters must land in this file or
  catalog.md.
- Latest refresh: **§10 (2026-09-15)**. Append later refreshes as new dated
  top-level sections (§11, …) rather than rewriting §1–§8; fold confirmed
  plan changes into plan.md.
- Each refresh also re-checks: kernel `btrfs_tree.h` for new item types and
  tree objectids (remap tree = objectid 13 on current master), btrfs-progs
  mkfs defaults, discard/reclaim defaults (§10.3), and `dissect.btrfs`
  releases.
- Test images: generate only under the gitignored `images/` folder in the
  repo, using the rootless QEMU/KVM recipe (§10.4). Never write images to
  `/tmp` or outside the repo; open `sandbox.img` read-only.

---

## 10. Research Refresh — 2026-09-15

> **Scope:** post-reset prior-art watch covering Jul–Sep 2026 plus anything
> missed by the 2026-08-17 consolidation: (1) literature, (2) tools and
> libraries, (3) on-disk format evolution up to kernel 7.0, (4) rootless
> test-image generation on the development host, (5) archaeology of the
> unmerged `feature/m1-backup-roots` branch. Every claim was checked against a
> primary source on 2026-09-15 unless marked **UNVERIFIED**.
>
> **Image rule (project owner, 2026-09-15):** all disk images, mount points,
> VM tooling and image scratch files live **only** under the gitignored
> `images/` folder inside the repo — never `/tmp` or any other location.
> `sandbox.img` stays at the repo root and is opened read-only.

### 10.1 Prior-art watch (literature, Jul–Sep 2026 + missed items)

**Headline:** no new btrfs deleted-file-recovery *paper* appeared, and nobody
has published Beyond Carving's future work. The closest new overlap is a
*tool* (`SecurityRonin/btrfs-forensic`, §10.2). Claim-level impact is at
the end of this subsection.

**New or changed works (verified via Crossref / OpenAlex / GitHub unless
marked):**

| Work | Citation | Verification | Touches |
|---|---|---|---|
| **Toolan & Humphries, "Hiding data in Btrfs file systems"** — the §4.4/§4.8 SSRN preprint, **now published** | *FSI: Digital Investigation* 58:302198, Sept 2026, DOI 10.1016/j.fsidi.2026.302198 (Norwegian Police University College). OA per OpenAlex (CC BY) | Crossref verified. Abstract identical to the preprint (six techniques rated on capacity/stability/detection difficulty). 20 references (Bhat & Wani 2018, Wani 2020, fishy, Göbel 2024, Schwietert & Hilgert 2025); does **not** cite Beyond Carving. Full text **not obtained** (ScienceDirect 403), so §8.3 offsets remain reconstructed from Schwietert & Hilgert — any offset changes vs the preprint are UNVERIFIED | C5 (proposes hiding; still no detector) — **replace the SSRN citation with this DOI everywhere** |
| **Bonnet, "Forensic Analysis of the Resilient File System (ReFS) Version 3.14"**, master's thesis, Univ. of Mons, 2026 — tool **`forefst`** | <https://github.com/xbqt/forefst> (GPL-3.0; created 2026-05-16, pushed 2026-09-13); write-up xbpt.gitlab.io/refs (2026-08-24). Thesis record itself UNVERIFIED (author statement only) | Repo verified. Five ReFS deletion-recovery methods: trash-table queue, **two-checkpoint object-table diff**, low-confidence object-table orphan scan, stream snapshots, and **B+-tree node-slack scan as "the primary method"** plus full-volume orphan-page scan. Per-result recoverability verdict (full / extent-backed / metadata-only), INCOMPLETE flag on truncated scans, journal super-timeline, timestomp detection | CoW analogs of C1 (slack + orphan pages), C4 (verdicts), C3 (weak), C5 (timestomp) — **on ReFS, not btrfs** |
| **Prade, Groß & Dewald, "Forensic Analysis of the Resilient File System (ReFS) Version 3.4"** — *missed earlier* | *FSI: Digital Investigation* 32:300915, 2020, DOI 10.1016/j.fsidi.2020.300915 | Crossref verified | CoW-analog related work (§4.3b) |
| **Oh & Hwang, "Advanced forensic recovery of deleted file data in F2FS"** — *missed earlier* | *FSI: Digital Investigation* 54:301976, Oct 2025 (DFRWS APAC 2025), DOI 10.1016/j.fsidi.2025.301976, OA (CC BY-NC-ND per OpenAlex) | Crossref verified; abstract only (PDF blocked). Carves metadata to **rebuild the F2FS address table**, then recovers deleted data; tool benchmarked | Conceptual analog of C6 (address-map reconstruction from carved metadata) |
| Oh, "Ext4 Log Tracker: An enhanced approach to file event generation from Ext4 journal" | *FSI:DI* 58:302145, Sept 2026, DOI 10.1016/j.fsidi.2026.302145 (closed) | Crossref metadata: `api.crossref.org/works/10.1016/j.fsidi.2026.302145` (title, author, volume, article number) | Methodology analog for C3 (journal → file-event timeline) |
| Hornung, Jonker & van Beek, "Connecting File Timestamps: A Formal Approach" | Proc. Digital Forensics Doctoral Symposium, ACM, 2026-03-23, DOI 10.1145/3785318.3785319 | Crossref metadata: `api.crossref.org/works/10.1145/3785318.3785319` | Timeline framing only |
| Stoyanov et al., "Forensic analysis of container snapshot chains for post-event reconstruction"; Yoon & Hwang, "Forensic analysis of video data deletion and recovery in Honeywell surveillance file system" | *FSI:DI* 57:302114 / 57:302116, June 2026 (DFRWS USA 2026) | Crossref metadata: `api.crossref.org/works/10.1016/j.fsidi.2026.302114` and `…302116` | None (not CoW filesystems) |
| Hraiz, "Btrfs Forensic Analysis", thesis, Princess Sumaya Univ. for Technology, 2016 (ProQuest) | — | Existence via ProQuest listing; abstract not viewable — **UNVERIFIED** content | Possibly §4.3 foundational; obtain before submission |
| Aigbogun & Zhou, IEEE CARS 2025, DOI 10.1109/cars67163.2025.11337549 (F2FS and "emerging" FS) | closed | Whether btrfs is covered is UNVERIFIED | — |

**Venue sweeps with nothing relevant (negative results):**
- **DFRWS USA 2026** (FSI:DI vol. 57): all 42 Crossref entries plus the
  program (Wayback 2026-05-10) — only "Mind the slack?" (already in §4.7)
  touches filesystems.
- **DFRWS EU 2026** (vol. 56): no filesystem/CoW paper.
- **DFRWS APAC 2026** (19–22 Oct, Singapore): program not yet fetchable
  (dfrws.org 403, no archive) — **re-check in October**.
- FSI:DI vol. 58 and early 59: only Toolan & Humphries.
- IEEE Access, MDPI, Springer, ACM DTRAP: nothing.
- arXiv: API rate-limited; site-restricted search found nothing.
- OpenAlex/Crossref keyword sweeps ("btrfs", "bcachefs", "ZFS forensic",
  "copy-on-write forensic", "APFS forensic") since mid-2025: nothing beyond
  the table.
- Author feeds: Wani/Bhat, Hilgert (non-FS work only), Göbel/Baier
  ("Plug and Fake", FSI:DI 57:302122; IaC compromised-Linux datasets,
  DTRAP DOI 10.1145/3748268 — dataset methodology only), Shon, Dewald:
  no btrfs/CoW work.
- SANS DFIR Summit / OSDFCon 2026: no btrfs talk found (web search only).

**Beyond Carving watch.**
- **0 citations** (Semantic Scholar citations endpoint empty; OpenAlex
  W7168240764 cited_by_count 0 as of 2026-08-21).
- **Code:** `github.com/Vikaran101/btrfs-beyond-carving` was created
  2026-07-08 with the paper's tagline, but is an **empty repository**
  (GitHub API: HTTP 409 "Git Repository is empty"). The account is linked to
  Team Cryptonite (Krish Pandey) via its `Cryptonite_CSAW_ESC_2025` README.
  No code has been released.
- **No follow-up** implementing their future work (deep leaf scanning,
  historical chunk tree, deleted subvolumes, csum validation) was found.

**§4.8 retries.**
- **Toolan & Humphries:** now FSI:DI (above), but still blocked
  (ScienceDirect/SSRN/ResearchGate 403).
- **Plum & Dewald ARES 2018:** now listed **gold OA, CC BY** (OpenAlex
  `best_oa_location`, verified), but dl.acm.org returns 403 from here. Tool
  code: `github.com/cugu/afro`. Fetch from a browser session.
- **ExtSFR, Vaheed Ali ICPCSN 2025:** closed; not obtained.
- **Hilgert PhD:** bonndoc still times out.
- **Toolan & Humphries 2025 symlink slack:** FSI:DI 53:301919, DOI
  10.1016/j.fsidi.2025.301919, closed.
- **`fkie-cad/hide-and-seek-dataset`:** still 404.
- **New:** `github.com/fkie-cad/mind-the-slack` (MIT, created 2026-07-29,
  verified) is now the official home of the "Mind the slack?" framework,
  replacing the anonymous.4open.science link in §4.7.

**No PDFs were downloaded in this refresh.** Every relevant OA candidate
(Toolan & Humphries 2026, Plum & Dewald 2018, Oh & Hwang 2025) was blocked by
publisher bot protection; `docs/` still holds the 18 papers of 2026-08-17.
Note: the `docs/*.pdf` files are **tracked in git**, not ignored.

**Claim-by-claim status (literature + tools combined):**

| Claim | Status on 2026-09-15 |
|---|---|
| C1 orphan-item / slack archaeology | **Open for btrfs.** SecurityRonin lists kernel ORPHAN_ITEMs only; `forefst` does node-slack scanning on **ReFS** → phrase C1 as btrfs-specific and cite `forefst` / Prade 2020 as CoW analogs |
| C2 FST forensics | Open (nothing found) |
| C3 generation diffing → timelines | **Narrower.** Backup-root deletion diffs now exist in Beyond Carving (objectid sets) *and* SecurityRonin (`recover_deleted`, leaf diff over the 4 backups). The claim must rest on **full-state, multi-source (backups + discovered old roots + reconstructed fragments), per-inode lifecycle** timelines, not on "diffing generations" |
| C4 confidence + provenance | **Narrower.** Graded findings (SecurityRonin severity), extent-resolvability outcomes (Beyond Carving) and ReFS recoverability verdicts (`forefst`) exist. Ours must be the *evidence-rule-derived* tier with a per-artifact provenance chain spanning anchored and unanchored sources, plus csum-tree verification |
| C5 hiding detection | Open, but SecurityRonin's `BACKUP-ROOT-DIVERGENCE` / CRC-mismatch findings are a first tamper-detection slice → cite; the target list is now peer-reviewed (Toolan & Humphries FSI:DI 2026) |
| C6 relocated-chunk forensics | Open for btrfs (F2FS address-table rebuild is an analog); see §10.3 for the kernel changes that reshape it |
| C7 public corpus | Open (no btrfs corpus; hide-and-seek dataset still offline) |

### 10.2 Tools and libraries (state on 2026-09-15)

**New prior art that touches our claims (must cite + benchmark).**

- **`SecurityRonin/btrfs-forensic`** <https://github.com/SecurityRonin/btrfs-forensic>
  — Rust, **Apache-2.0**. Created 2026-07-16, last push 2026-08-26, 0 stars.
  Crates `btrfs-core` 0.1.5 and `btrfs-forensic` 0.1.3 (crates.io,
  2026-08-26). A from-scratch reader (superblock, sys_chunk_array, chunk
  tree, fs tree, zlib/lzo/zstd) plus an "anomaly auditor" that emits graded
  findings: `BTRFS-SUPERBLOCK-CRC-MISMATCH`, `BTRFS-CRC-MISMATCH`,
  `BTRFS-BACKUP-ROOT-DIVERGENCE` (possible rollback / tampering),
  `BTRFS-IMPOSSIBLE-GEOMETRY`, and `BTRFS-ORPHANED-INODE` (kernel
  ORPHAN_ITEM). `recover_deleted()` walks an older generation's FS_TREE
  reached through a `btrfs_root_backup`, diffs it against the current FS_TREE,
  and returns carved files with sha256 (verified from the README). Its README
  mentions **crc32c only**. Claims of 100 % line coverage and fuzzing are
  UNVERIFIED (not run).
  **Overlap:**
  - backup-root deleted-file recovery — not a novelty claim; research.md §6
    already lists it as "not open";
  - kernel ORPHAN_ITEM surfacing — a small slice of C1;
  - graded severity findings — a partial gesture towards C4 (severity, not
    evidence-based confidence; no provenance chain);
  - a backup-root-divergence tamper check — a slice of C5.
  **No** beyond-`nritems` / slack archaeology, orphan-node scanning, FST,
  timelines, historical chunk maps or corpus. Positioning: the first
  *dedicated* open-source btrfs forensic library — Python users can no
  longer be told "nothing exists".
- **The Sleuth Kit — correction to §2.3.** PR #3065 "BTRFS from basic master"
  (simsong) was **merged into `develop` on 2024-11-27** (verified via the
  GitHub API; `tsk/fs/btrfs.cpp`, `btrfs_csum.cpp`, `tsk_btrfs.h` exist on
  `develop`). It was later marked experimental (#3187, 2025-02-04), zstd
  flag added (#3225), memory fixes open (#3466, 2026-04). **No release ships
  it**: 4.14.0 notes say it does not include experimental btrfs, and the
  `sleuthkit-4.15.0` tag (2026-04-15) has no btrfs files. So "TSK upstream
  has no btrfs" must become "TSK has experimental btrfs on `develop`,
  unreleased". A TSK-`develop` build joins the baseline set. (Autopsy
  4.23.x therefore almost certainly lacks btrfs — inference.)
- **cblichmann/btrfscue v0.7** — released **2026-07-04** (GitHub release,
  verified). New `recover` command (recursive restore of files, directories
  and symlinks with logical→physical mapping and sparse holes), **recovers
  unreferenced subvolumes into `subvol_<ID>`** (touches G7 deleted-subvolume
  recovery), and FUSE multi-extent read fixes. §2.4's "alpha, sporadic" still
  holds, but it is now a stronger baseline.
- Minor: `Vikyek/btrfs-recovery-tool` (Python, GPL-3.0, 2026-06; ROOT_ITEM
  scan → `btrfs restore -t` wrapper); `am-fs-btrfs` 0.6.2 (Rust, MIT,
  2026-09-06, driver with C ABI — not examined); `danthem/undelete-btrfs`
  v1.0 (2025-12-27). **libyal `libfsbtrfs` does not exist** (404).

**dissect.btrfs** (PyPI verified: latest stable **1.10, 2026-02-24**; only
1.11.dev1/dev2 pre-releases 2026-03-18/19; no functional commits since
#31 zstd→stdlib `compression.zstd`, 2025-12-04). Source read + tested on
1.10:
- `BTree(btrfs, root_item=None, root_offset=None)` walks any bytenr, but
  `_read_node` validates **nothing** (bytenr, fsid, generation, owner, level,
  csum). A misaligned bytenr landing on a zero block produced a garbage item
  without error.
- **No checksum verification of any type**; `csum_type` is parsed but unused
  (crc32c only for dir-name hashes). Opens and reads the xxhash
  (`s01`) and sha256 (`rootdir_test`) images only because it ignores csums.
- **Incompat flags are not checked** — an injected unknown bit (1<<40)
  opened normally. Remap-tree / RST / encrypted images will therefore be
  **silently mis-read** rather than refused.
- Always maps through the **current** chunk tree; superblock mirrors not
  read; `super_roots` (backup roots) exposed only as a raw struct; no API for
  extent/csum/FST/block-group trees; mirror reads always take stripe 0 with
  no bad-copy fallback; degraded RAID56 → `NotImplementedError`; encrypted
  extents → `NotImplementedError`.
- Confirmed working: zstd extents in `s01` (10/10 read), subvolumes and
  snapshots, and backup-root historical walks on `sandbox.img` (gen 13 →
  `large_target.txt`, gen 11 → `target_file.txt`).
- Test images in `tests/_data` (27 gzipped, incl. all RAID profiles) are Git
  LFS — need `git lfs pull`.
- Verdict unchanged (substrate), but **the trust layer is entirely ours**:
  node validation wrapper, csum dispatch, incompat-flag gate, mirror
  selection, historical chunk maps. (Refined further by plan.md §3.5: test
  oracle only; see §10.6.)

**rustutils/btrfsutils** — **stalled**. Last push and release v0.13.0 on
2026-05-14, nothing since; 14 stars. Crates `btrfs-disk`, `btrfs-fs`
(new), `btrfs-transaction`, `btrfs-uapi`, `btrfs-stream` (MIT/Apache-2.0);
CLI/mkfs/tune GPL-2.0. It verifies all four csum types for tree blocks and
superblocks, parses backup roots, and knows the RST key and remap-tree
objectid; `restore` clone, chunk-recover, 7-phase check; RAID56 parity on
the write path only. Nothing forensic. Still the best permissive offline
reference, but not a dependency to bet on.

**btrfs-progs** — releases after the host's 6.6.3: 6.7 … 6.17.1, 6.19
(2026-02-13; there is no 6.18), 6.19.1, **7.0 (2026-05-09)**, **7.1
(2026-07-14)** (GitHub releases verified).
- mkfs `--rootdir` gains: `--subvol` 6.12, `--compress` 6.13, `--inode-flags`
  6.15, `--reflink` 6.16.1, hole detection 7.0; **block-group-tree on by
  default since 6.19** (`-O ^bgt` to disable).
- `rescue fix-data-checksum` (6.15); `check` detects missing orphan items of
  deleted subvolumes (6.16).
- 7.1 extends `OPEN_CTREE_PARTIAL` for partially damaged trees (commit
  08592de).
- `dump-tree` prints remap-tree items (commit 3dcd329, 2026-02) and fscrypt
  context items (7.1 "preliminary fscrypt").
- `btrfstune --convert-to-remap-tree` (7.0, experimental).
- `restore` / `find-root`: cosmetic changes only, **not deprecated, no
  undelete feature**.
- Host 6.6.3 is too old for any of this; a newer progs can be built from
  source rootless if needed.

**Others:** python-btrfs v15 (2025-04-11, no commits since; ioctl-only,
still irrelevant). btrfs-fuse: 2 commits in Jun–Jul 2026 (large-file read
offset fix, optional LZO). **WinBtrfs v1.10 (2026-09-01)**, the first release
since 2024 (FST bitmap and compressed-inline fixes). btrfs-rec: last commit
2024-04; a "WIP rewrite" fork (`KaiErikNiermann/btrfs-progs-ng`) appeared
2026-05-18. `dissect.target` wraps dissect.btrfs per subvolume (3.25.1,
2026-02-25).

**Commercial:** UFS Explorer changelog 10.15–10.22 (to 2026-09-10) has no
btrfs entries; a 2025-10-05 blog notes better btrfs RAID10 metadata reads
with missing drives. X-Ways 21.9 lists btrfs. R-Studio btrfs support not
found (2023 forum: "planned") — UNVERIFIED. ReclaiMe Pro unchanged. Magnet
AXIOM and Belkasoft: nothing found — UNVERIFIED.

### 10.3 On-disk format evolution, kernel 6.0 → 7.0 (→ 7.3-rc3)

Sources: `include/uapi/linux/btrfs_tree.h`, `btrfs.h`, `fs/btrfs/*.c` at
tags **v7.0** (host kernel) and master (**v7.3-rc3**; v7.2 is released),
commit messages via GitHub, btrfs docs [Status page](https://btrfs.readthedocs.io/en/latest/Status.html),
btrfs-progs v7.1 sources. Numeric values and the remap-tree / discard
claims below were re-checked directly against v7.0 source; the rest come
from a source-level sweep (file:line cited) and are marked where
unconfirmed. **Host fact:** `/boot/config-7.0.0-31-generic` has
`# CONFIG_BTRFS_EXPERIMENTAL is not set`, so the host (and our QEMU guest)
**cannot mount** RST, extent-tree-v2 or remap-tree filesystems.

| Feature | Kernel / status | On-disk (v7.0 values) | (i) must a recovery tool parse it? | (ii) evidence-survival effect |
|---|---|---|---|---|
| **Remap tree** (Mark Harmstone) | Merged in **7.0** ("for-6.20" pull; series v8 2026-01-07); **experimental-only** through 7.3-rc3 (`fs.h` `#ifdef CONFIG_BTRFS_EXPERIMENTAL` includes `INCOMPAT_REMAP_TREE`). progs: `btrfstune --convert-to-remap-tree` (7.0, experimental builds) | incompat **`1<<17`**; tree objectid **13**; keys **IDENTITY_REMAP 234, REMAP 235, REMAP_BACKREF 236** (`btrfs_remap_item{address}`); BG flags **REMAPPED `1<<11`, METADATA_REMAP `1<<12`**; `block_group_item_v2` (+`remap_bytes`, `identity_remap_count`); superblock **`remap_root`, `remap_root_generation`, `remap_root_level`** (`btrfs_tree.h:724-726`) | **Yes** for any image with the flag: logical→logical translation precedes chunk mapping; without it live data in REMAPPED groups is unreadable | Relocation **copies ranges and records old→new remaps instead of COW-rewriting every referencing tree block** (reads translated in `btrfs_map_block()`), so balance produces far fewer stale tree copies. When a group is fully remapped its **chunk stripes are removed and device extents freed**: at the end of a remap relocation by `fd6594b1446c` ("replace identity remaps with actual remaps when doing relocations"; per its commit message this reaches `last_identity_remap_gone()`, while the added code calls `btrfs_mark_bg_fully_remapped()`), on mount for groups left pending by an unfinished async discard by `2aef934b56b3` ("populate fully_remapped_bgs_list on mount"); the helpers `remove_chunk_stripes()` / `btrfs_last_identity_remap_gone()` themselves were introduced for the extent-deletion path by `979e1dc3d69e` ("handle deletions from remapped block group", extent-tree hole punching) — all three checked in the commit patches at `github.com/torvalds/linux/commit/<sha>.patch`, the chunk item remains with **`num_stripes = 0`** (`c3d6dda60c9d` "allow remapped chunks to have zero stripes"), and the source range is **discarded** — at commit for discard=sync, by the async worker via `btrfs_trim_fully_remapped_block_group()` (`7cddbb4339d4`). The remap root is **not** in `btrfs_root_backup` → historical remap trees must be found by scanning for owner 13 |
| **RAID stripe tree** | 6.7; experimental-only; format changed in 6.11 (`encoding` field removed, `2422547e99f9`) | incompat `1<<14`; tree 12; key **RAID_STRIPE 230** (array of `{devid, physical}`) | Yes, for data in DUP/RAID0/1/10 block groups when the flag is set (in practice zoned multi-device) | Deleted extents lose their stripe item; physical placement survives only in stale RST leaves |
| **Block-group tree** | 6.1, stable; **mkfs default since btrfs-progs 6.19**. `sandbox.img` has it (compat_ro 0xb), but host mkfs **6.6.3 defaults do not enable it**: every image under `images/scenarios/` has compat_ro **0x3** (FST + FST_VALID only; read as u64 LE at 0x10000 + 0xb4). Scenario images need `MKFS_ARGS="-O block-group-tree"` for tree-11 coverage | compat_ro `1<<3`; tree 11; `BLOCK_GROUP_ITEM` 192 moves out of the extent tree; root found via root tree | **Yes** — M2's live-set / region logic and any "extent-tree-only" assumption must also read tree 11 | Neutral/slightly positive (small, rarely COWed tree) |
| **Simple quotas** | 6.7 in code (`SIMPLE_QUOTA` in `INCOMPAT_SUPP_STABLE` at v6.7; docs say 6.8); stable, opt-in | incompat `1<<16`; inline ref **EXTENT_OWNER_REF 172** (`{root_id}`), placed first in EXTENT_ITEM | Yes — inline-ref parsers must accept type 172 or backref parsing breaks | **Positive:** stale extent-tree leaves name the subvolume that *created* a deleted data extent, permanently (survives reflink/snapshot sharing) — a new attribution source for C3/C4 |
| **extent-tree-v2** | Experimental, incomplete, no specific commits since 6.8 | incompat `1<<13` | Detect and refuse | None in real images |
| **fscrypt** | **Not merged** as of 7.3-rc3 (latest series "[PATCH v7 00/43]" 2026-05-13); prep only: `BTRFS_FT_ENCRYPTED 0x80` (6.2). progs 7.1 "preliminary fscrypt". Proposed `BTRFS_FSCRYPT_CTX_KEY` / `INCOMPAT_ENCRYPT` values UNVERIFIED | dir-entry type bit 0x80 | Mask 0x80 off `dir_item.type` | — |
| Block sizes / folios | `BTRFS_MIN/MAX_BLOCKSIZE` 4K/64K; mkfs sectorsize default 4K since progs 6.7, nodesize 16K; bs>ps experimental (6.18); large data folios default in 7.2 (in-memory only) | none new | Honour SB `sectorsize`/`nodesize`; **probe at 4K** (plan M2 already does) | None |
| New keys / csums | Since 6.0 only: objectids 12, 13; keys 172, 230, 234–236; `EXTENT_REF_V0` 180 dropped. **No new csum algorithm** (crc32c 0, xxhash64 1, sha256 2, blake2b 3 unchanged) | — | Add to item-type tables | — |
| Tree-log | No on-disk change 6.0–7.3 (behavioural fixes only: otime on replay 6.17, logging fixes, no global-reserve use 7.1) | unchanged | No change for G9 | Effect on fsync residue UNVERIFIED |
| Superblock / backup roots | `BTRFS_NUM_BACKUP_ROOTS` still **4**; `btrfs_root_backup` unchanged since 6.0; only new SB fields are the remap-root triple. 7.3 makes `rescue=usebackuproot` read-only and drops the legacy `usebackuproot` mount option | — | Unchanged for M1 | — |
| bcachefs | "Externally maintained" 6.17; removed from mainline **6.18** (`f2c61db29f27`) | — | — | CoW-FS context only |

**Discard, freed-block reuse, reclaim (verified in v7.0 source; explains the
§10.4 measurement).**
- **Auto-enable:** `discard=async` is enabled automatically since **6.2**
  (commit `63a7cb130718`) when any device advertises discard, unless zoned
  or an explicit `discard`/`nodiscard` is given (`super.c` ~776-797 v7.0).
  There is **no SSD/rotational test**, so virtio disks, thin LVs and
  sparse-file-backed VMs qualify.
- **Async timing** (`discard.c` v7.0): a partly used block group becomes
  discard-eligible **120 s** after queueing (`BTRFS_DISCARD_DELAY`, l.56); a
  fully unused block group after **10 s** (`BTRFS_DISCARD_UNUSED_DELAY`,
  l.57); pacing `iops_limit` 1000, `kbps_limit` 0 (l.816-817).
- **Async only tracks data-only block groups** (`btrfs_is_block_group_data_only`
  gates at l.116 and l.696). **Freed tree blocks inside a still-used
  METADATA/SYSTEM block group are never async-discarded** — they survive
  until reallocated. This is the structural reason orphan-node scanning
  stays viable on modern SSD installs.
- **Unmount drops the queue:** `close_ctree()` → `btrfs_discard_cleanup()`
  (`disk-io.c:4397` v7.0) → `btrfs_discard_purge_list()` (`discard.c:761`,
  l.823-827), which empties the lists *without* discarding; trim state is
  in memory only. Our async run unmounted within ~1 s, so nothing was
  trimmed (355 = 355 stale blocks).
- **`discard=sync`** discards every unpinned range, **metadata included**,
  at every transaction commit (`btrfs_finish_extent_commit()`), and trims
  deleted unused block groups at commit → the measured 355 → 31.
- **Freed tree blocks:** a written block is pinned until commit and then
  becomes allocatable; a block allocated and freed in the same transaction
  and never written is returned immediately; zoned mode always pins and
  resets whole zones.
- **Reclaim = relocation:** `bg_reclaim_threshold` defaults to 0 (off),
  except zoned (75); **dynamic and periodic reclaim** (6.11,
  `f5ff64ccf7bb`, `e4ca3932ae90`) are sysfs knobs, off by default (distro
  enablement UNVERIFIED). Each reclaim is a balance and destroys evidence
  the same way.
- TRIMmed LBAs reading back as zeros is device-dependent (DRAT/RZAT, thin
  provisioning); in our QEMU `discard=unmap` test on a sparse raw file they
  read as zeros.

**Must-parse additions for kernels 6.1–7.0** (on top of research.md §8.1
defect #7):
- `csum_type` 0–3; `sectorsize`/`nodesize` 4K–64K.
- Explicit incompat gate: known-stable → parse; RST `1<<14`, ETv2 `1<<13`,
  REMAP `1<<17` → specialised path or refuse with a report line; unknown →
  refuse.
- Block-group tree (11).
- Inline `EXTENT_OWNER_REF` 172 in EXTENT_ITEM (168) / METADATA_ITEM (169).
- `FT_ENCRYPTED` mask.
- RST 230 when flagged.
- Remap tree 13 / keys 234–236 / BG flags bits 11–12 / `block_group_item_v2`
  / zero-stripe chunks when flagged.

**Assessment for C6 (relocated-chunk forensics + historical chunk maps).**
- **Mainstream 6.1–7.0 images — unchanged, claim stands.** Remap-tree
  filesystems cannot be mounted on stock (non-experimental) kernels.
  Relocation still COW-rewrites referencing blocks and deletes old chunk
  items and device extents, so historical chunk-map reconstruction is still
  needed to translate outside-map orphans.
- **Remap-tree images — claim strengthens and gains a new evidence source.**
  - The current chunk tree no longer locates pre-relocation physical copies
    (zero-stripe chunk items), so historical chunk-map reconstruction becomes
    *mandatory*.
  - REMAP / REMAP_BACKREF items, live and in stale owner-13 leaves, form an
    **explicit on-disk relocation log** (old logical → new logical, with
    lengths).
  - Zero-stripe chunk items mark exactly which ranges were relocated.
- **Caveat:** remap relocation discards the source range on completion
  (`7cddbb4339d4`), so on TRIM-honouring media the old copies may be gone —
  the relocation *record* survives while the *content* may not.
- **UNVERIFIED (inferred from the raw copy):** relocated tree blocks keep
  their old logical `bytenr` in the header while sitting in a different
  physical range. Testing it needs an experimental-config kernel in the QEMU
  recipe (§10.4) — e.g. a self-built kernel with
  `CONFIG_BTRFS_EXPERIMENTAL=y`, which needs no root.
- Present remap-tree support in the paper as forward-looking / experimental.

### 10.4 Rootless test-image generation (measured on the development host)

Host: Linux Mint 22.3 (Ubuntu 24.04 base), kernel 7.0.0-31-generic,
btrfs-progs 6.6.3, user `vishwajit` (in `sudo` group, but sudo needs a
password, so no root). Each method was actually tried:

| Method | Result | Evidence |
|---|---|---|
| `sudo` / loop mount | **No** | sudo requires a password |
| User namespace (`unshare -r`, `unshare -rm`) | Namespace **works** (uid 0 inside; tmpfs mounts OK) but **btrfs cannot be mounted**: `losetup: failed to set up loop device: Permission denied`. Btrfs is not `FS_USERNS_MOUNT`, and loop devices need real root | tested |
| `mkfs.btrfs --rootdir DIR` (progs 6.6.3) | **Works** rootless (tested with `--csum sha256`). But it only builds a *fresh* filesystem (generation 7, no history, nothing deleted), and it **copies host `st_ino` values as objectids** (e.g. inode 28475956). So it breaks the objectid-monotonicity premise Beyond Carving relies on. 6.6.3 has no `--subvol`/`--compress` (see §10.2). Use it only for parser fixtures, never for deletion scenarios | tested |
| FUSE | `/dev/fuse` is `crw-rw-rw-`; `fusermount3` present; `libfuse3-3` installed; **no fuse3 dev headers** | tested |
| lklfuse (LKL) | **Not available.** No Debian/Ubuntu package (packages.debian.org: no results); `lkl/linux` has no release binaries and tracks kernel 6.12 (Makefile on `master`, last push 2026-08-18); a source build would need `flex`/`bison` (missing) plus fuse3 headers. Its 6.12 driver would also not exercise 7.0 format features | tested / GitHub API |
| **QEMU + KVM** | **WORKS — recommended.** `/dev/kvm` carries a logind seat ACL `user:vishwajit:rw-`, so no `kvm` group membership is needed. QEMU is not installed, but `apt-get download` + `dpkg -x` (no root) of `qemu-system-x86 qemu-system-common qemu-system-data seabios libfdt1 libpmem1 librdmacm1t64 libslirp0 libndctl6 libdaxctl1` gives a working QEMU 8.2.2 via `LD_LIBRARY_PATH`. `/boot/vmlinuz-7.0.0-31-generic` is mode 0600, but `apt-get download linux-image-unsigned-7.0.0-31-generic` supplies a readable copy. The host's `/lib/modules/7.0.0-31-generic` modules are world-readable: `btrfs.ko.zst` plus its deps `libblake2b`, `raid6_pq`, `xor` (from `modinfo -F depends`) are zstd-decompressed into a busybox-static initramfs, together with `/usr/bin/btrfs` and its shared libs | tested end-to-end |

**Working recipe — tracked generator in `corpus/vm/`.** The scripts are
tracked; everything they produce goes to the gitignored `images/` folder.
Details are in `corpus/vm/README.md`.

```sh
# one-time tooling (no root, idempotent): apt-get download + dpkg -x into images/vm/ of
#   qemu-system-x86 qemu-system-common qemu-system-data seabios libfdt1 libpmem1
#   librdmacm1t64 libslirp0 libndctl6 libdaxctl1, linux-image-unsigned-7.0.0-31-generic,
#   busybox-static, btrfs-progs (+ linux-modules-7.0.0-31-generic if the host lacks btrfs.ko)
corpus/vm/fetch_vm.sh
# initramfs: busybox + btrfs (+ldd libs) + zstd -d of xor/raid6_pq/libblake2b/btrfs modules
#   + corpus/vm/init + corpus/vm/scenarios/*.guest.sh -> images/vm/initramfs.cpio.gz
corpus/vm/build_initramfs.sh
# per image: host mkfs (any csum/features), guest mutates, host analyses
truncate -s 512M images/scenarios/sNN.img
mkfs.btrfs -q -f --csum xxhash images/scenarios/sNN.img     # add -O block-group-tree for tree 11
SCENARIO=s01 MOUNT_OPTS=compress=zstd,commit=5 corpus/vm/run_scenario.sh images/scenarios/sNN.img
#  = timeout 600 qemu-system-x86_64 -L <qemu>/usr/share/seabios -L <qemu>/usr/share/qemu \
#      -nic none -enable-kvm -cpu host -m 1024 -nographic -no-reboot \
#      -kernel vmlinuz-7.0.0-31-generic -initrd initramfs.cpio.gz \
#      -append "console=ttyS0 quiet panic=-1 scenario=s01 mountopts=compress=zstd,commit=5" \
#      -drive file=sNN.img,format=raw,if=virtio      # ,discard=unmap when DISCARD is set
# corpus/vm/make_image.sh NAME wraps truncate + mkfs (SIZE, CSUM, MKFS_ARGS) + run + log check
```

The guest `/init` (`corpus/vm/init`) inserts the modules and reads
`scenario=` and `mountopts=` from `/proc/cmdline`; nothing is hardcoded. It
mounts `/dev/vda` with those options and logs the effective options from
`/proc/mounts` (`=== MOUNTED`). It then sources `/scenarios/<name>.sh`
(busybox and `btrfs` commands: `subvolume create`, `snapshot -r`, `rm`,
`sync`, `balance start --full-balance`, …), which prints ground-truth
SHA-256s to the serial console. Finally it unmounts and runs `poweroff -f`.

**Measured scenario `s01`** (`corpus/vm/scenarios/s01.guest.sh`; 512 MiB,
xxhash csums, zstd; create 3 files in a subvolume, then `sync`, read-only
snapshot, delete 2 files, 6 committed churn writes, full balance).
- Timing: `time corpus/vm/run_scenario.sh images/scenarios/s01_timing.img`
  on a freshly formatted image took **1.43 s real** (0.94 s user, 0.30 s
  sys; 2026-09-15) from boot through scenario to poweroff.
- Result: superblock generation 6 → 38 and `incompat_flags` 0x341 → 0x371
  (COMPRESS_ZSTD set by the kernel). Gen 38 and 0x371 were re-checked on the
  regenerated images.
- The balance relocated 3/3 chunks (new logical chunk addresses;
  `backup_chunk_root` gen 30 vs 38 in different slots). This was observed in
  the first run and not re-checked.

So guest-driven scenarios give a real kernel history, relocation, and
modern-feature coverage. The xxhash + zstd + relocation combination is
exactly what the M1/M2 DoDs need.

**Discard / TRIM survival datapoint (same scenario, three images).**
Reproduce with:

```sh
corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh && corpus/vm/discard_table.sh
```

`discard_table.sh` runs `corpus/vm/scenarios/discard_{none,async,sync}.sh`
to build `images/scenarios/s01_discard_{none,async,sync}.img`. It then runs
`python3 corpus/vm/probe_stale_metadata.py <img>`, which prints four numbers:
1. **FSID blocks:** 4 KiB-aligned blocks whose header has the superblock
   FSID at +0x20, with superblock copies skipped.
2. **Stale blocks:** the subset of (1) whose header generation (+0x50) is
   below the superblock generation.
3. **Inline-string copies:** byte-exact occurrences of the deleted inline
   file's content `small secret` anywhere in the image.
4. **Non-zero blocks:** 4 KiB blocks containing any non-zero byte.

| Row (script) | Drive / mount options | FSID blocks | stale blocks | inline-string copies | non-zero 4 KiB blocks |
|---|---|---|---|---|---|
| no discard (`discard_none.sh`) | no `discard=unmap`; `compress=zstd,commit=5` | 367 | 355 | 18 | 832 |
| async (`discard_async.sh`) | `DISCARD=1` (virtio `discard=unmap`); same mount options, **no discard option** | 367 | 355 | 18 | 832 |
| sync (`discard_sync.sh`) | `DISCARD=1`; `compress=zstd,commit=5,discard=sync` | **43** | **31** | **2** | **107** |

The whole pipeline was re-run end to end on 2026-09-15: a fresh
`fetch_vm.sh` into an empty `images/vm/`, `build_initramfs.sh`, then
`discard_table.sh` (6.6 s for all three rows). Columns 2–4 matched the
first measurement (355/355/31, 18/18/2, 832/832/107) on that run.
- **Run-to-run jitter:** the rows are not bit-stable. In an independent
  review re-run of 4 repetitions, one "none" row gave 365/353/16/828 (the
  others 367/355/18/832): commit timing inside the guest shifts a few
  blocks, by 2 in columns 1–3 and by 4 in column 4. Report these as
  representative values, not constants; the spread is per column, so
  plan.md §7 requires a per-column median and range from ≥ 5 runs rather
  than a fixed "±2". The order-of-magnitude effect of `discard=sync` is the
  finding.
- **EXP-000 backfill (2026-09-15, M2b; `experiments/EXP-000.md`).** 15
  regenerations per row, run one at a time. Median (min–max):

  | Row | FSID blocks | stale blocks | inline-string copies | non-zero 4 KiB blocks |
  |---|---|---|---|---|
  | no discard | 367 (365–367) | 355 (353–355) | 18 (18–18) | 832 (828–832) |
  | async | 367 (367–367) | 355 (355–355) | 18 (18–18) | 832 (832–832) |
  | sync | 43 (43–43) | 31 (31–31) | 2 (2–2) | 107 (107–107) |

  - The medians equal the table above, so it stands as the medians.
  - One "no discard" run of 15 gave 365/353/18/828 (2 fewer `sv1` blocks). The
    async and sync rows never varied. The review rerun's 16 inline-string copies
    did not recur.
  - Sync keeps 8.7 % of the stale blocks (91.3 % gone).
  - The three representative images are `s01_discard_{none,async,sync}_r1` in
    `corpus/manifest.tsv`. The table's original images stay unlisted.
- Column 1 is one lower than first reported (368/368/44). The committed
  probe skips superblock copies (0x10000, and 64 MiB on these 512 MiB
  images); why the original ad-hoc probe (not kept) counted exactly one more
  block is **not verified** — it plausibly counted one superblock copy.
- Re-running the committed probe on the original images also gives
  367/367/43.

Notes on the rows:
- **The async row is enabled automatically by `DISCARD=1` alone.** No
  discard mount option is passed; the guest log shows the kernel's
  effective `discard=async` (auto-enable since 6.2, §10.3).
- **Caveat:** the "no discard" guest *also* mounts with `discard=async`
  (`=== MOUNTED` log line). QEMU 8.2 virtio-blk advertises discard even
  without `discard=unmap`; the drive's default `discard=ignore` drops the
  requests on the host. "No discard" therefore means "no TRIM reaches the
  image file", not "no discard mount option". A `nodiscard` mount row is a
  possible M7 addition.

Interpretation: with async discard, TRIM had not run before the unmount about
a second later, so the result matches no-discard (the kernel queue-delay
semantics are in §10.3). Synchronous discard destroyed **~91 % of stale
metadata** and ~89 % of the deleted inline string's copies. On TRIM-honouring
media (SSD, thin-provisioned or sparse images), discard is the dominant
evidence-destruction factor. It must be a first-class corpus axis (M7) and a
reported recoverability caveat.

Also observed: `sandbox.img` (sha256 `07ca38d4…`, crc32c, gen 14) has
`compat_ro_flags` 0xb = FREE_SPACE_TREE | FREE_SPACE_TREE_VALID |
**BLOCK_GROUP_TREE**, so block-group items in the golden fixture live in the
block-group tree (objectid 11).
- **Host mkfs 6.6.3 defaults do NOT enable BLOCK_GROUP_TREE.** Every image it
  produced (all of `images/scenarios/`, including the regenerated
  `s01_*` images) has compat_ro **0x3**, read as a u64 LE at 0x10000 + 0xb4.
  Scenario images therefore need `-O block-group-tree`
  (`MKFS_ARGS="-O block-group-tree" corpus/vm/make_image.sh …`) for tree-11
  coverage.
- Owner 11 among the 21 outside-map orphans (catalog 2026-08-14) is
  *consistent with* old block-group-tree blocks rather than an anomaly. That
  argument **rests on `sandbox.img` alone**: no scenario image has tree 11
  yet, and the orphan blocks themselves were not re-inspected.

### 10.5 Git archaeology: `feature/m1-backup-roots`

- **State:** 3 commits on top of `c51fe91` (the M2 merge), all 2026-08-14:
  `d870a98` "M1: superblock backup roots + anchored historical walking",
  `1d48203` "fix: review findings — backref address, full-sweep check,
  anchored CRC", `1e9984e` "docs: record review fixes, add hardening backlog".
  Local and `origin` branches exist. Merge base = `c51fe91`, so the branch
  forked **before** the 2026-08-17 reset commit `e0d3c7d` and was never
  reintegrated. 10 files, +660/−19.
- **Contents:** `utils/backup_roots.py` (145 lines): parses the 4
  `btrfs_root_backup` slots at SB+0xB2B/0xBD3/0xC7B/0xD23 (stride 0xA8 —
  matches kernel `struct btrfs_super_block.super_roots`), then validates
  tree/chunk/extent/fs roots by FSID + CRC32c + owner.
  `utils/anchored_walk.py` (195 lines): walks each backup fs tree into an
  inode inventory (INODE_ITEM size, INODE_REF / DIR_ITEM / DIR_INDEX names,
  EXTENT_DATA presence) with CRC validation of every node on the path; diffs
  it against the current fs tree ("deleted since gen g"); tags sweep artifacts
  whose `(inode, generation)` pair appears in a historical state as
  `provenance="anchored"`. `tests/test_m1_anchored.py` has 12 tests. Also
  (a) a **real bug fix in `utils/btree.py`**: EXTENT_ITEM logical address is
  the key *objectid*, not the key offset (the offset is the length) — `main`
  still carries this bug; (b) coverage check gated to targeted mode;
  (c) a plan "hardening backlog".
- **Verification (2026-09-15):** extracted with `git archive` into
  `images/scratch/m1/` (branches untouched). `python3 -m unittest discover -s
  tests` → **Ran 49 tests, OK**. `sandbox.img` hash unchanged.
  `dump-super -f sandbox.img` confirms the branch's finding: backup slots hold
  **gens 13, 14, 11, 12** (slot order ≠ generation order), all sharing chunk
  root gen 8. **Correction to catalog.md 2026-08-14:** `sandbox.img` holds
  four anchored states (gens 11–14), not only a gen-13 state. Gen 11 contains
  `target_file.txt` (31 B inline) and gen 13 contains `large_target.txt`
  (5 MiB), both deleted by gen 14.
- **Salvage verdict under the new plan:** the code itself is superseded (it
  sits on the DELETE-listed hand-rolled superblock, chunk-map and CRC32c
  modules and hardcodes crc32c — defect #1). Four things are worth carrying
  into M1/M4 as **spec and tests, not code**: (1) the EXTENT_ITEM
  objectid-vs-offset fix — add it to research.md §8.1 as defect #8, because
  `main` still has it and the M4 golden tests must not freeze the buggy
  backref addresses; (2) the gen 11–14 ground truth (which files each backup
  state holds) as M1 DoD assertions, stronger than the "gen-13" wording in
  plan.md M1; (3) the slot-order observation — backup slots are a
  round-robin ring (kernel `fs/btrfs/disk-io.c`: `backup_root_index =
  (next_backup + 1) % BTRFS_NUM_BACKUP_ROOTS`, re-seeded at mount to the slot
  after the newest backup), so the slot→generation mapping depends on mount
  history. Always sort by generation, never by slot;
  (4) the hardening backlog items — backup-root scan fallback, SB mirrors,
  richer second image, TREE_BLOCK_REF coverage — which plan.md M1/M7 mostly
  already cover. Recommend a `catalog.md` note and leaving the branch
  unmerged (optionally tag it `m1-prototype` for reference). **Done
  2026-09-15:** annotated tag `m1-prototype` pushed to origin, pointing at
  `1e9984e`; the branch is kept.

### 10.6 Impact on plan (recommended changes to plan.md, ranked)

> **Refined by plan.md (2026-09-15, after review).** Item 1's "trust layer
> over dissect.btrfs" and the §10.2 substrate verdict were narrowed to
> **dissect.btrfs as a test oracle only** (plan.md §3.5). Reasons:
> dissect maps every read through its own current chunk tree, with no API to
> route reads through a validated reader or a historical chunk map; M1 needs
> our own extent reads anyway; and zlib/zstd are in the Python 3.14 stdlib.
> The last piece, LZO1X, is decoded by our own bounds-checked decoder:
> dissect.util's native LZO decoder panicked on corrupt input
> (`PanicException`; 31–46 of 300 bit-flipped streams per seed in the
> committed harness `tests/oracle/lzo_hostile.py`, seeds 1–5, which
> supersedes the first scratch run's 58/300), and its pure-Python
> decoder silently accepted an out-of-range back-reference. All runtime
> parsing, extent reads and decompression are ours, and the tool is
> licensed **Apache-2.0** (plan.md §3.3). Item 9's AGPL concern is therefore
> moot unless the plan's runtime fallback is taken.

1. **M1 — add a node-validation trust layer over dissect.btrfs, and make it
   the M1 DoD.**
   - Rationale: dissect.btrfs 1.10 checks no csum, no header field and no
     incompat flag, and returns garbage silently for a bad bytenr (§10.2).
     Every confidence tier (C4) is meaningless without it.
   - Scope: wrap `_read_node` to verify bytenr / fsid / generation / owner /
     level + csum (all 4 types); superblock mirror selection by
     csum + generation; an **incompat-flag gate** (refuse or specialise on
     RST, ETv2, REMAP and unknown bits, with a report line); read tree 11
     (block-group tree) wherever block groups are needed.
   - DoD additions: an unknown-flag image is refused; a corrupted-node image
     reports a csum failure instead of items.
2. **plan §1 claims table + plan §8 positioning — re-word C3 and C4, and cite the new
   prior art.**
   - Rationale: backup-root deletion diffing is now shipped by
     `SecurityRonin/btrfs-forensic` (and Beyond Carving); graded findings /
     recoverability verdicts exist there and in `forefst` (ReFS).
   - C3 becomes "full-state, multi-source (backup + discovered old roots +
     reconstructed fragments) per-inode lifecycle timelines".
   - C4 becomes "evidence-rule-derived tiers with provenance chains spanning
     anchored *and* unanchored artifacts, csum-tree verified".
   - Keep C1/C6 explicitly btrfs-specific; cite Prade 2020 / Bonnet 2026 /
     Oh & Hwang 2025 as CoW analogs.
   - Update plan §9 Risks: "a Rust forensic library adds our anchored
     features" is now a realised risk — mitigation is to move M5 (orphan
     graph, historical chunk maps) earlier, as plan §9 already suggests.
3. **M7 corpus — adopt the rootless QEMU/KVM generator (§10.4) now, and add
   discard as a first-class axis.**
   - Rationale: measured stale-metadata survival is 355 → 31 under
     `discard=sync`; async discard is auto-enabled since 6.2 but only for
     data block groups, with a 120 s delay and dropped at unmount (§10.3).
   - Axes: {nodiscard, async with quick unmount, async after ≥ 2 min idle,
     sync} × {virtio discard=unmap on/off}; plus a reclaim/balance axis.
   - Pin and record the guest kernel (7.0.0-31) and host mkfs version per
     image. The generator scripts are now tracked in `corpus/vm/`; all their
     outputs (tooling, images, logs) stay under the gitignored `images/`
     per the project-owner rule.
   - Use the generator from M1 on for the xxhash/zstd/relocation DoD images
     (plan §6.2 already asks for this).
4. **M5/C6 — widen historical chunk-map reconstruction to also cover
   remap-tree evidence (optional, forward-looking).**
   - Parse REMAP 235 / REMAP_BACKREF 236 / IDENTITY_REMAP 234 and zero-stripe
     chunk items when `INCOMPAT_REMAP_TREE` is set, treating stale owner-13
     leaves as a relocation log.
   - Mark it experimental in the paper. Validating it needs a self-built
     `CONFIG_BTRFS_EXPERIMENTAL=y` guest kernel. Low effort once the gate
     from item 1 exists; strengthens C6's story.
5. **M1 — fold in the salvageable parts of `feature/m1-backup-roots`**
   (§10.5):
   - the EXTENT_ITEM objectid-vs-offset bug → add as research.md §8.1
     defect #8, and do not freeze buggy backref addresses into M4 golden
     tests;
   - the M1 DoD ground truth becomes "backup states gens 11–14; gen 11 has
     `target_file.txt`, gen 13 has `large_target.txt`", replacing
     "gen-13 state";
   - sort backup roots by generation, not slot.
   - Leave the branch unmerged; optionally tag it (done: `m1-prototype`,
     2026-09-15).
6. **M7 baselines — extend the harness.**
   - Add `SecurityRonin/btrfs-forensic` `recover_deleted`, btrfscue v0.7
     `recover`, a TSK `develop` build (experimental btrfs), and btrfs-progs
     ≥ 7.1 `restore`.
   - Fix research.md §2.3/§2.4 statements accordingly (done in §10.2; the
     §1 executive summary item 4 is now stale).
7. **M4/M6 parsers — handle the new item types.**
   - Accept inline EXTENT_OWNER_REF 172 (squota) and use it as a
     subvolume-attribution signal for deleted extents (C3/C4).
   - Mask FT_ENCRYPTED 0x80.
   - Refuse encrypted extents with a report line.
8. **plan §8 Paper plan — update citations and venues.**
   - Replace the SSRN Toolan & Humphries citation with FSI:DI 58:302198.
   - Add `fkie-cad/mind-the-slack` as the framework URL.
   - Re-check DFRWS APAC 2026 (19–22 Oct) accepted papers in October.
   - Re-run this watch before M5 starts.
9. **plan §3.3 License fallback note.**
   - rustutils/btrfsutils has stalled since 2026-05-14.
   - `btrfs-core` (Apache-2.0) is a second permissive Rust reader, but
     immature: 0.1.x, single/DUP chunks only, crc32c only. Verified in the
     0.1.5 crate source (`static.crates.io/crates/btrfs-core/btrfs-core-0.1.5.crate`):
     `src/chunk.rs` `SysChunk::logical_to_physical` maps "single-device
     single/DUP chunks" via `stripes[0]` ("Multi-device / striped RAID
     mapping is deferred to a later phase"); `src/crc.rs` verifies crc32c
     only and returns `None` (deferred) for xxhash64 / sha256 / blake2.
   - Re-evaluate both only if the AGPL licence becomes a problem; no change
     to the dissect decision. (Superseded: the plan now licenses the tool
     Apache-2.0 with dissect.btrfs as a test oracle only; see the note at the
     top of this section.)

**Open questions needing a human decision.**
- (a) ~~Adopt the QEMU generator scripts into a tracked `corpus/` path now?~~
  Resolved: tracked in `corpus/vm/` (outputs remain under `images/`).
- (b) Build a `CONFIG_BTRFS_EXPERIMENTAL=y` guest kernel to cover
  RST/remap-tree images (in or out of scope for paper 1)?
- (c) ~~Tag or delete `feature/m1-backup-roots`?~~ Resolved: tagged
  `m1-prototype` (pushed to origin) and the branch kept.
- (d) Obtain the three blocked OA papers (Toolan & Humphries 2026, Plum &
  Dewald 2018, Oh & Hwang 2025) via a browser session.
- (e) Should the `docs/*.pdf` files stay tracked in git (they are, contrary
  to earlier notes)?

### 10.7 Format notes from M1a (2026-09-15)

Observed while building the superblock trust layer (catalog.md, M1a entry).
Kernel references are to tag v7.0.

- **Superblock copies agree on healthy images.** On `sandbox.img` and the five
  generated `m1_*` images, mirror 0 (64 KiB) and mirror 1 (64 MiB) carry the
  same generation, and every field except `bytenr` and `csum` is identical.
  This is expected: the kernel writes every copy in the same commit, setting
  `bytenr` and recomputing the csum per copy (`disk-io.c:3795-3810`). A
  disagreement between copies therefore points to an interrupted commit,
  damage or tampering, and `btrfska info` reports it.
- **Edge rule.** The kernel ignores a copy whose last byte is the device's
  last byte: `bytenr + BTRFS_SUPER_INFO_SIZE >= size` rejects it
  (`volumes.c:1356`, and `disk-io.c:3806` when writing). btrfska follows the
  same rule.
- **Where the feature bits live.** Incompat and compat_ro bits are defined in
  `include/uapi/linux/btrfs.h:298-339`, not in `btrfs_tree.h`. Bit 15 is
  unassigned in v7.0. The mount masks are in `fs/btrfs/fs.h:286-330`; RST,
  extent-tree-v2 and remap tree are in `INCOMPAT_SUPP` only under
  `CONFIG_BTRFS_EXPERIMENTAL`.
- **`dump-super` prints csum bytes in disk order.** It does not print the
  integer value. For `sandbox.img` it shows `0xeadc2eaa`; the CRC-32C value
  stored little-endian in those bytes is `0xaa2edcea`. Cross-checks against
  btrfs-progs must compare bytes.
- **Backup roots track subvolume 5 only.** In every s01 image (`m1_xxhash`,
  `m1_sha256_bgt`, `m1_blake2b`, `m1_lzo`, `m1_zlib`), all four backup slots
  (gens 35–38) name the same `backup_fs_root` (gen 19). The scenario's
  writes and deletions all happen inside subvolume `sv1`, whose tree is
  reachable only through ROOT_ITEMs in each backup's `tree_root`. Two
  consequences:
  - a diff of `backup_fs_root` states sees nothing of a deletion in any other
    subvolume. That is the method attributed to Beyond Carving and
    SecurityRonin `recover_deleted` in plan.md §1. Per-subvolume history needs
    a walk of each backup's root tree (M1 task 7);
  - the deletions already predate all four backup roots. Inferred from the
    scenario order: the deletion commit precedes the six churn commits, and
    those precede the balance, which had rewritten the chunk root by gen 30.
    So even this small scenario is a natural beyond-4-generations case
    (plan.md M7).
- **Foreign superblock copies are residue of a prior filesystem**
  (2026-09-15, M1a review). mkfs writes only the mirrors that fit the new
  filesystem, and other tools that reformat a disk overwrite only their own
  metadata. So a valid copy at 64 MiB or 256 GiB whose fsid differs from the
  primary's can be left over from an earlier btrfs on the same device.
  It survives because nothing else writes those offsets unless data lands on
  them. btrfs-progs already treats such copies as foreign: in recover mode
  `btrfs_read_dev_super` (v7.1 `kernel-shared/disk-io.c:2037-2056`) anchors
  the fsid (and metadata_uuid when `METADATA_UUID` is set) on the first
  accepted copy and skips any copy that differs, because the copies "contain
  data of different filesystems". Selecting by generation alone would let
  such residue override the live filesystem's identity and roots. The kernel
  is not exposed to this, since it mounts mirror 0 only (`disk-io.c:3333`).
  btrfska follows the progs rule, never selects a foreign copy, and reports
  it as `foreign superblock at <offset> (fsid …, generation …)`. For an
  examiner this is positive evidence: the device held another filesystem
  before, with that fsid and at least that generation. The foreign copy's
  own backup roots and sys_chunk_array may point at metadata that still
  survives. Synthetic case: `m1_foreign_mirror` (corpus/manifest.tsv).

### 10.8 Tree-walking notes from M1b (2026-09-15)

Observed while building the validated node reader, chunk maps and anchored
walker (catalog.md, M1b entry). Kernel references are to tag v7.0;
btrfs-progs is the host's v6.6.3.

- **Every backup root is fully walkable on the current corpus.** A root set
  here means the superblock's or a backup slot's trees plus every ROOT_ITEM in
  that set's root tree. On `sandbox.img` (backup gens 11–14) and the five s01
  images (gens 35–38), every tree of every root set walks with every node
  valid on both DUP copies:
  - `sandbox.img`: 27 distinct tree blocks, 10 per root set;
  - s01 images: 23–25 distinct tree blocks, 11–12 per root set.

  No block of any backup-root tree had been reused. Threat to validity: these
  images are small, quiescent after their last commit and use no discard. No
  survival rate generalises from them; M7 must measure how fast churn
  overwrites the four backup states.
- **DUP copies were bit-identical.** All 144 distinct tree blocks across the
  six images have two copies, and no pair differs. A valid but divergent pair
  is therefore unusual; btrfska reports it (`mirror 2 is valid but differs
  from mirror 1`).
- **What the kernel and btrfs-progs do not surface.**
  - Which copy the kernel reads depends on the profile (corrected after the
    M1b review; checked against v7.0 source):
    - **DUP.** `map_blocks_dup` (volumes.c:6751-6765) sets mirror 1 for
      every read. `btrfs_read_extent_buffer` (disk-io.c:211-250) moves to
      mirror 2 only when mirror 1 fails. So the kernel never reads a damaged
      or altered mirror 2 unless mirror 1 fails; scrub would still find it.
    - **RAID1, RAID1C3, RAID1C4 and RAID10.** `map_blocks_raid1`
      (l.6731-6749) and `map_blocks_raid10` (l.6767-6793) pick the stripe
      with `find_live_mirror` (l.6276-6342). Its read policy
      (`/sys/fs/btrfs/<FSID>/read_policy`) defaults to `pid`, which sets
      `preferred_mirror = first + current->pid % num_stripes` (l.6302-6304).
      Different processes therefore read different copies, and some readers
      *do* see a divergent second mirror.
    - The other policies, `round-robin` and `devid`, exist only with
      `CONFIG_BTRFS_EXPERIMENTAL` (volumes.h:322-332, sysfs.c:1322-1343,
      volumes.c:1271-1287). Without it the policy is always `pid`. The host's
      Ubuntu `7.0.0-31-generic` kernel leaves that option unset.
  - With crc32c, bytes 4–31 of the 32-byte csum field lie outside the
    checksum, so two copies can differ there and both validate (synthetic
    test `test_valid_copies_differing_outside_the_checksum_are_reported`).
  - Candidate hiding places for the M6 detector (hypothesis, not yet
    measured):
    - an altered **DUP** mirror 2. The "never read unless mirror 1 fails"
      argument holds for DUP only; under the default `pid` policy some
      RAID1/1C3/1C4/10 readers see an altered copy;
    - the unchecked crc32c csum bytes, on any profile.
  - **A read-write mount can destroy this evidence.** Say a tree block's read
    succeeds only after another mirror failed its checksum or validation.
    `btrfs_read_extent_buffer` then calls `btrfs_repair_eb_io_failure`
    (disk-io.c:172-202, called at l.246-247), which rewrites the failed
    mirror with the good copy. Only a read-only superblock stops it
    (`sb_rdonly`, l.180; `btrfs_repair_io_failure`, bio.c:952). Data reads
    repair the same way (bio.c:222).
    - Consequence: on a rw mount, merely reading a file or listing a
      directory can overwrite a corrupt or altered copy, and with it the
      divergence.
    - An altered copy whose checksum was recomputed is valid, so it is never
      repaired: it is served to whichever readers pick it.
    - Forensic soundness therefore requires working on an image, never a rw
      mount of the evidence. btrfska opens images read-only and never writes.
  - btrfs-progs `dump-tree` reports a bad copy only as `checksum verify failed
    on L wanted <stored> found <computed>`, without mirror or physical
    address. On `m1_badnode` it then silently prints the other copy. btrfska
    records mirror, devid, physical offset and every check per copy.
- **`sv1` history per generation** (the open point of §10.7). In all four
  `m1_xxhash` backup root sets, and in the current one, the ROOT_ITEMs are
  identical:
  - subvolume 5: gen 19, leaf 64208896;
  - 256 `sv1`: gen 34, leaf 65159168;
  - 257 `snap_before_delete`: read-only, gen 34, leaf 65126400.

  `sv1` holds `keep.txt` (108 894 B) and `churn_1..6` (5 B each). Only the
  snapshot still names `deleted_big.txt` (288 894 B, three extents) and
  `deleted_inline.txt` (13 B, inline). The `sv1` leaf's generation (34) is newer
  than every inode transid in it (≤ 15), consistent with the full balance
  rewriting the leaf. So per-subvolume backup walking cannot reach the
  pre-deletion `sv1` leaf either. It can survive only as an unreferenced
  block (M2 scan), and the deleted names only through the snapshot.
- **Backup roots preserve a pre-balance chunk map.**
  - Backup gens 35–37 name chunk root 131104768 (gen 30, 5 items) and dev root
    64847872 (gen 30). Gen 38 and the superblock name chunk root 131121152
    (gen 38, 4 items).
  - The extra gen-30 items are the mkfs `DATA|single` chunk at logical
    13631488 (8 MiB, devid 1, physical 13631488) and its DEV_EXTENT. The
    balance moved its data into the chunk at 164626432 and dropped it.
  - Older metadata that points into 13631488..22020096 is unmapped under the
    current map. Historical chunk maps (M5, C6) can be built from backup chunk
    roots while those survive.
  - btrfska M1b walks every root set through the current map, which is
    correct for these images: every tree block lives in chunks that the gen-30
    and gen-38 maps share.
- **Backup roots taken mid-balance record the relocation.**
  - Root trees of gens 35–37 also hold the balance status item (`BALANCE
    TEMPORARY_ITEM 0`).
  - They also hold a DATA_RELOC tree (gen 32) whose inode 259 is an orphan
    with extents at file offsets 0, 28 672, 61 440 and 73 728. Those extents
    sit at disk bytes 164626432 (28 672 B), 164655104 (32 768 B), 164687872
    (12 288 B) and 164700160 (4 096 B): the relocated `keep.txt` extent and
    the three `deleted_big.txt` extents named by the snapshot.
  - Gen 38 (balance finished) has neither.
  - Hypothesis for M5, to check against `fs/btrfs/relocation.c`: a reloc
    inode's file offset is the original address minus the source block-group
    start. The old addresses would then be 13631488 + offset, so a mid-balance
    backup root links old and new data locations.
- **Parent-pointer generation is an equality.** The kernel rejects a child
  whose generation differs from its parent pointer's in either direction
  ("parent transid verify failed", disk-io.c:410-417). In a historical walk,
  a child newer than its pointer is exactly the signature of an overwritten
  backup-root block, so btrfska reports which direction it failed.

### 10.9 Extent-read notes from M1c (2026-09-15)

Observed while building extent reads, decompression, the oracles and EXP-001
(catalog.md, M1c entry; experiments/EXP-001.md). Kernel references are to tag
v7.0. Raw probe output: `images/scratch/m1c/probe_extents.txt`.

- **Compressed inline extents hold a whole sector.** On `m1_xxhash` (zstd),
  `m1_zlib` and `m1_lzo`, every compressed inline extent (seven per image:
  `churn_1..6`, 5 B, and `deleted_inline.txt`, 13 B) decodes to 4 096 bytes,
  while `ram_bytes` is 5 or 13. The kernel keeps only min(ram_bytes,
  sectorsize) of that output (`uncompress_inline`, inode.c:7129-7168). The
  bytes past `ram_bytes` were zero on all three images.
  - Hypothesis for M6: bytes past `ram_bytes` inside a compressed inline
    stream are invisible to any reader that follows the kernel. That makes
    them a hiding place on a crafted image and possibly a residue source.
    Whether the write path can ever compress non-zero bytes past EOF is
    still to be checked in the compression write path (inode.c).
  - btrfska reports them as `N non-zero bytes past ram_bytes in the decoded
    sector`.
- **Compressed extents carry slack.** Regular compressed extents are padded
  to whole sectors:
  - the zlib and zstd streams on these images end 462–3 929 bytes before the
    end of their extent;
  - every LZO extent's total length is below its sector-aligned size.

  All of this slack was zero. Non-zero slack is also invisible to kernel
  reads, so it joins §10.8's candidates for the M6 detector; btrfska reports
  it.
- **zlib extents are read without their adler32 check.**
  `zlib_decompress_bio` (zlib.c:373-382) inflates raw deflate after a valid
  zlib header, so a corrupted adler32 trailer is accepted. btrfska does the
  same (`test_zlib_adler32_is_not_checked_like_the_kernel`). dissect.btrfs
  calls `zlib.decompress`, which checks it, so it would refuse bytes the
  kernel serves (not exercised on the corpus). zlib adds no integrity check
  to what LZO lacks.
- **Kernel extent reads stop once the read is filled.** The bio paths stop
  when `ram_bytes` of output exist and ignore later LZO segments or zstd
  input. btrfska stops the same way for LZO, but requires the end of a zlib
  or zstd stream; no extent in the corpus hit that difference.
- **The LZO worst-case segment is 4 421 bytes for a 4 KiB sector.** That is
  the v7.0 macro (`include/linux/lzo.h:21`, `x + x/16 + 64 + 3 + 2`). The
  header comment of `fs/btrfs/lzo.c` and the earlier plan text say 4 419.
  The kernel's segment-length check uses the macro.
- **`Documentation/staging/lzo.rst` first-byte erratum.** It says first
  bytes 18..21 copy "0..3 literals" and 22..255 copy "4..238". The count is
  byte − 17, so 1..4 and 5..238; lzallright agrees on hand-assembled streams
  (`tests/test_lzo.py`).
- **dissect.btrfs reads unmapped addresses as zeros.** Its `ChunkStream`
  fills any read below its lowest chunk with zero bytes, without an error.
  - On `m1_xxhash`, logical 13 631 488 reads as 4 096 zero bytes. That is
    the pre-balance data chunk that the gen-30 backup chunk root still names
    (§10.8).
  - btrfska raises `UnmappedAddress` there and records such an extent as
    `unmapped`.
  - For a historical extent whose chunk has since moved, this is the
    difference between a reported error and silently empty evidence.
  - Other differences from the kernel read path: dissect's LZO loop ignores
    the total-length header and stops at a zero segment length, and an
    inline extent ends its extent list.
  - None of this produced a byte difference in the oracle: all 152 file
    reads were equal.
- **Compressed extents in historical generations.** On the s01 images, every
  backup root set (gens 35–38) and the current state name the same `sv1` and
  snapshot leaves. The 50 file reads per image are therefore 10 distinct
  files read five times, all equal to the guest SHA-256s.
  - Their extents all lie in the post-balance data chunk, which the current
    map covers.
  - No root set in this corpus reaches a compressed extent at a pre-balance
    address; that case needs M5's historical chunk maps.
  - Threat to validity: this corpus exercises historical *metadata* only,
    not historical extent addresses.
- **Corrupt LZO usually decodes.** The committed harness
  (`tests/oracle/lzo_hostile.py`, seeds 1–5, 300 single-bit flips of a
  4 KiB sector per seed) found:
  - 218–231 flips per seed (median 227, about three quarters) decode to
    wrong bytes within the bound, identically in btrfska, lzallright and
    dissect.util native;
  - btrfska raises `LzoError` on the other 68–82 flips (1 flip at most
    decodes correctly);
  - lzallright's output bound is only a size hint: 32–41 flips per seed
    returned more than 4 KiB, where btrfska raises `output_overrun`;
    otherwise the two agree on 300 of 300 flips;
  - dissect.util's native decoder raises a non-`Exception` panic on 31–46
    flips per seed and on the crafted stream;
  - the corpora added in the M1c review (truncation, one inserted or deleted
    byte, random byte streams and instruction-level random streams, 300
    each per seed) agree between btrfska and lzallright on every stream.
    One inserted byte gives 9–14 wrong decodes and one deleted byte 32–71,
    in both decoders alike. Before the review fix, btrfska accepted an end
    marker with a copy length other than 3, which the kernel rejects. Only
    the instruction-level corpus exposed it (6–11 streams per seed); the
    byte-level corpora never produced that marker.

  Decode success is therefore never evidence of correct content (plan.md
  §3.5); data checksums are (M6).
- **Legacy failure modes (EXP-001).**
  - On the xxhash64, sha256 and blake2b images, legacy's hardcoded crc32c
    rejects every fsid-matching block (368, 402 and 368), so it reports no
    node and no file (defect #1).
  - On `sandbox.img` its 10 "Move/Rename Artifacts" pair `target_file.txt`
    and `large_target.txt` on inode 257. That is inode-number reuse, not a
    rename:
    - `target_file.txt` (INODE_ITEM generation 10) was deleted in
      transaction 12;
    - `large_target.txt` is a new inode 257 created in generation 13.

    The INODE_ITEM `generation` field separates reuse from rename, and M5
    timelines must use it.
  - It lists `large_target.txt` four times; three entries are
    de-duplication markers with no output file (`output_path` "(duplicate)",
    legacy/utils/btree.py:659-666).

### 10.10 Scan notes from M2a (2026-09-15)

Observed with the scan kernel, targeted regions and orphan classification
(catalog.md, M2a entry). Kernel references are to tag v7.0. Raw summaries:
`images/scratch/m2a/scans/`. Definitions:
- a **candidate** is a sector-aligned offset whose header fsid matches;
- a candidate is **valid** when it passes every check that needs no
  referrer;
- **live**, **backup_reachable** and **unreferenced** mean the copy is
  reached from the current state, from a backup root only, or from neither;
- **orphans** are the last two.

- **Orphans per image** (`btrfska scan IMAGE`, targeted; `--full-sweep`
  finds the same valid nodes on every image below):

  | Image | Candidates | Valid | Invalid | Live | Backup-reachable | Unreferenced | Orphans outside the current chunk map | Legacy-compatible orphans |
  |---|---|---|---|---|---|---|---|---|
  | `sandbox.img` | 85 | 84 | 1 | 20 | 34 | 30 | 20 | 71 |
  | `m1_xxhash` | 367 | 362 | 5 | 22 | 24 | 316 | 172 | 355 |
  | `m1_sha256_bgt` | 401 | 395 | 6 | 24 | 26 | 345 | 181 | 387 |
  | `m1_blake2b` | 367 | 362 | 5 | 22 | 24 | 316 | 172 | 355 |
  | `m1_lzo` | 365 | 360 | 5 | 22 | 24 | 314 | 170 | 353 |
  | `m1_zlib` | 367 | 362 | 5 | 22 | 24 | 316 | 172 | 355 |
  | `m1_badnode_both` | 367 | 360 | 7 | 20 | 24 | 316 | 172 | 353 |

  Counts are physical copies: a DUP block that survives on both stripes
  counts twice.
- **Backup roots reach little of the surviving history.**
  - On `sandbox.img`, 34 of 64 orphans (53 %) are reachable from a backup
    root.
  - On the s01 images, only 24–26 of 338–371 orphans (7 %) are. Their
    generations are 30–37, while the orphans outside the chunk map are
    generations 2–23.
  - So a tool bounded by the four backup roots (Beyond Carving,
    SecurityRonin, plan.md §1) sees about one orphan in fourteen on these
    images.
  - Threat to validity: small, quiescent images with one scenario and no
    discard.
- **Orphans outside the chunk map on generated images** (`m1_xxhash`,
  `m1_sha256_bgt`) all lie in two unmapped gaps below the current metadata
  chunk: 69632–67108864 and 67112960–105906176.
  - No header bytenr of theirs maps under the current chunk map.
  - 18 (xxhash) and 19 (sha256) claim their own physical offset: residue of
    mkfs's temporary chunk at 1 MiB, whose logical and physical addresses
    are equal.
  - The other 154 and 162 claim addresses the current map no longer has:
    the pre-balance metadata DUP stripes (§10.8).
  - Owners (xxhash; sha256 adds 11 block-group-tree blocks):

    | Tree | Blocks |
    |---|---|
    | root | 25 |
    | extent | 25 (23 on sha256) |
    | chunk | 11 |
    | dev | 7 |
    | fs | 9 |
    | csum | 6 |
    | uuid | 6 |
    | free space | 27 |
    | `sv1` (256) | 52 |
    | snapshot (257) | 2 |
    | data reloc | 2 |

  - A historical chunk map (M5) is needed to read their pointers. The 52
    `sv1` blocks are the candidates for the pre-deletion `sv1` leaf that
    §10.8 expected to survive only unreferenced. That is not yet verified
    (M4/M5).
  - On `sandbox.img`, all 20 valid orphans outside the map claim their own
    physical offset. They lie in 0x100000–0x12c000 and 0x500000–0x520000,
    generations 1–4, in 8 trees.
- **mkfs leaves tree blocks the kernel would reject.**
  - Every s01 image has 5 or 6 generation-1 blocks at 1081344–1163264 whose
    header flags are 0x0100000000000000: backref revision 1, WRITTEN not set.
    They were made with host btrfs-progs v6.6.3.
  - The kernel's tree-checker rejects such a block (tree-checker.c:2033-2036,
    2186-2189). `sandbox.img` (mkfs version unknown) has the WRITTEN flag on
    its blocks at the same offsets.
  - Both corpora hold an empty generation-1 fs-tree leaf at 1114112, which
    tree-checker.c:2047-2080 rejects (tree 5 must never be empty).
  - These blocks are mkfs residue, not filesystem history. A scan must
    report them as invalid candidates, never drop them (they are evidence of
    the mkfs), and never count them as orphans.
- **Orphans of the current generation exist.**
  - `sandbox.img` holds an unreferenced generation-14 fs-tree leaf (logical
    30605312, 3 items) on both DUP stripes, although the superblock
    generation is 14.
  - A block already written in the running transaction is copied again on
    its next change (ctree.c:621-625 `should_cow_block`: WRITTEN set means
    COW). So one transaction can orphan its own blocks.
  - "generation < superblock generation" is therefore wrong in both
    directions.
    - It misses these 2 orphans.
    - It counts 8 live blocks as orphans: chunk root generation 8, uuid tree
      generation 7, data reloc tree generation 5 and dev tree generation 13,
      two DUP copies each, all unchanged since their generation.
  - The legacy 71 on `sandbox.img` reconcile as 8 live + 34 backup-reachable
    + 28 unreferenced + 1 invalid (catalog.md, M2a).
- **The extent tree adds nothing to the walker on this corpus.** On every
  image above, the tree blocks the current extent tree lists (METADATA_ITEM,
  and EXTENT_ITEM with TREE_BLOCK) equal the logical addresses the current
  walks reach: 10 on sandbox, 11 on the s01 images, 12 on `m1_sha256_bgt`.
  - It is a content cross-check, not an independent one: the extent tree is
    reached through the same current root tree as the walks, so a forged or
    damaged root tree misleads both.
  - Log trees get no extent-tree reference (extent-tree.c:5392), so their
    blocks are counted apart (`m2_logtree` below).
  - The cross-check stays in the scan summary. A difference would point to
    a dropping subvolume or damage.
- **A damaged live block stays visible.** On `m1_badnode_both`, the corrupt
  `sv1` leaf (65159168, both copies) is 2 invalid candidates. The current
  and all four backup walks report it as invalid, and live drops from 22 to
  20.
- **Log trees (M2a review).** Verified against tag v7.0:
  - **Owner.** Every log block has header owner `BTRFS_TREE_LOG_OBJECTID`,
    which is −6 (btrfs_tree.h:92; −7 is `TREE_LOG_FIXUP`). The log root is
    allocated with it (disk-io.c:861-867, 887), and COW copies take the
    root id (ctree.c:520, extent-tree.c:5308). The kernel skips the owner
    check for log trees (tree-checker.c:2270); btrfska checks it exactly.
  - **Keys.** The log root tree names each subvolume log with a ROOT_ITEM
    keyed (TREE_LOG, ROOT_ITEM, subvolume id) (disk-io.c:865-867, 942;
    tree-log.c:7720-7744). The objectid is the log id, not the subvolume id.
  - **Generation: exactly superblock + 1, not ≤.** Log blocks take the
    running transaction id (extent-tree.c:5306), which is the last committed
    generation + 1 (transaction.c:392-393). btrfs_sync_log writes
    `super_for_commit` (tree-log.c:3577-3579) only under `tree_log_mutex`,
    which a commit holds from copying its superblock until it is written
    (transaction.c:2535-2581, tree-log.c:3554-3560). So the superblock on
    disk is the previous transaction's, and replay reads the log root with
    transid generation + 1 (disk-io.c:2017-2019). Logs are freed at every
    commit, so no older log block stays reachable. Subvolume logs are read
    with their ROOT_ITEM generation (disk-io.c:988, tree-log.c:7744). The
    tree-checker's `≤ super_gen + 1` (tree-checker.c:1151-1163, 1248-1268)
    is an upper bound on inode and root item fields, not on log headers.
  - **log_root_transid.** The superblock field is `__unused_log_root_transid`
    (btrfs_tree.h:695). v7.0 never writes it (0 on `m2_logtree`), and there
    is no `log_root_transid` function.
  - **Corpus image `m2_logtree`.** Scenario `logtree`, mounted with
    `commit=300`: commit two files, then fsync new files in fs tree 5 and
    `sv1` and append to one, then sysrq `o`, which powers off with no sync
    and no unmount. The superblock is generation 8 with log_root 30982144.
    Three more runs gave the same generation and log_root.
    - `btrfska scan` classifies the log root tree leaf 30982144 and the
      `sv1` log leaf 30965760 (8 items) as `live`, `log_tree`, on both DUP
      stripes: 4 copies, 2 blocks. That equals the blocks `btrfs
      inspect-internal dump-tree -t 18446744073709551610` names.
    - Two further generation-9 leaves (30932992 and 30949376, 2 copies
      each) are the first fsync's log commit, superseded in the same
      transaction. Nothing reaches them, so they stay `invalid` on their
      generation check. Forensically they are uncommitted history one log
      commit old, and M4/M5 can read them.
    - Totals: 89 candidates, 80 valid, 24 live (4 in the log), 30
      backup-reachable, 26 unreferenced; extent tree 10 blocks, walks 0 extra.
      Backup root 5's walks hit reused blocks (owner and parent-generation
      failures). That is expected: backup roots are not live.
- **Forensic consideration: metadata residue in reallocated DATA ranges.**
  The targeted plan skips DATA chunks whose block-group item agrees. When a
  range held tree blocks under an earlier chunk (a removed or relocated
  metadata chunk) and a DATA chunk is later allocated over it, those blocks
  survive until data overwrites them.
  - A targeted scan misses them. In the M2a review, a valid fs-tree leaf
    planted 1 MiB into the sandbox DATA chunk was not found targeted and was
    found `unreferenced` with `--full-sweep`
    (`tests/test_scan_hostile.py`).
  - The scan now prints `skipped as DATA: N bytes (use --full-sweep …)` and
    reports `skipped_data_bytes` (8 388 608 on sandbox, 75 497 472 on
    `m2_logtree`).
  - An examiner should run `--full-sweep` whenever the chunk history shows
    balance or chunk removal. Old-root discovery (M2b) can bound the
    affected ranges from historical chunk trees.
- **Limitation: blocks of a foreign filesystem are not candidates.** The
  prefilter matches only the current fsid or metadata_uuid. It misses tree
  blocks of a previous filesystem on the same device (a reformat) and blocks
  written before `btrfstune -m` or `-u` changed the tree fsid. These are
  high-value evidence of re-formatting or identity changes. An optional
  foreign-FSID discovery mode feeding the foreign-superblock finding is
  planned (plan.md M6).
- **Memory.** On the 39 765-candidate flood from the review (sandbox with
  fsid-matching garbage in every sector of the trailing gap), a
  `scan --json` run peaked at 89.3 MB of Python heap with one worker and
  267.6 MB with four. Streaming classification, running counters and a
  bounded worker window bring this to 2.3 MB and 16.6 MB (tracemalloc).
  Memory is now bounded by the reachable trees, not by the candidates.

### 10.11 Old-root discovery and discard notes from M2b (2026-09-15)

Observed with `btrfska roots` and EXP-000/EXP-002 (catalog.md, M2b entry).
Kernel references are to tag v7.0. Raw outputs: `images/scratch/m2b/roots/`
and `images/scratch/exp/EXP-00{0,2}/`. Definitions (README, `btrfska roots`):
- a **candidate root** is a valid scanned block that no block of its owner and
  generation points to, at the highest level of that owner and generation;
- a **state** is a root-tree candidate. Its trees are resolved through the
  scanned blocks by (bytenr, generation, level, owner, first key), never
  through a chunk map;
- **completeness** is found / referenced distinct blocks, an upper bound.

- **Discovery per image** (`btrfska roots IMAGE --full-sweep`; deterministic
  per image):

  | Image | Root-tree candidates | Superblock + backup roots rediscovered | States beyond the backups (generations) | … complete | Walk failures |
  |---|---|---|---|---|---|
  | `sandbox.img` | 5 | 26/26 | 1 (3) | 1 | none |
  | `m1_xxhash`, `m1_blake2b`, `m1_lzo`, `m1_zlib`, `m1_badnode`, `m1_mirror_damage`, `m1_foreign_mirror` | 35 | 26/26 | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
  | `m1_sha256_bgt` | 35 | 26/26 | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
  | `m1_badnode_both` | 35 | 26/26 | 31 (3, 6, 7 ×2, 8–34) | 29 | 5 `corrupt` |
  | `m2_logtree` | 5 | 24/27 | 2 (3, 7) | 1 | 3 `reused` |
  | `s01_discard_none_r1`, `s01_discard_async_r1` | 35 | 26/26 | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
  | `s01_discard_sync_r1` | 2 | 14/26 | 1 (3) | 0 | 12 `zeroed` |

- **Most of the history of a small quiescent image survives, far beyond the
  backup roots.**
  - On every s01 image without trims, one root-tree state per transaction
    from generation 8 to 34 survives, plus generations 3, 6 and two
    generation-7 blocks. That is 31 states beyond the 4 backup states.
  - 30 of the 31 have every referenced block found: 8–14 blocks each (the
    root-tree leaf and each named tree's root, all leaves here).
  - The generation-7 pair is one transaction writing its root tree twice,
    consistent with a WRITTEN block being copied again in the running
    transaction (ctree.c:621-625, §10.10).
  - A tool bounded by the four backup roots (plan.md §1) sees generations
    35–38 only.
  - Threats to validity: one scenario, 512 MiB, quiescent after the last
    commit. Churn reuses these blocks, as the `reused` walk failures on
    `m2_logtree` show. File content was not read per state (M4/M5).
- **Pre-balance states resolve without the current chunk map.**
  - States 3–16 on the s01 images have no block that the current chunk map
    places where it was scanned.
  - Each state's inferred chunk tree is the newest chunk-tree candidate root
    no newer than the state: generations 3, 6, 17, 23, 24, 29 and 30 occur.
    Their CHUNK_ITEMs, read through the index without the sys_chunk_array,
    place every found block where it lies (`maps_neither` 0 in every state).
  - Generations 17 and 18 straddle the balance: 5 of 10 and 10 of 13 blocks
    map under the current map, all under their own chunk items.
  - This is the input historical chunk-map reconstruction (M5, C6) needs.
    btrfska only checks placement and keeps no historical map.
- **The sandbox keeps less.** Its only extra state is generation 3 (7 of 7
  blocks, chunk root generation 3). None of generations 4–10 was found. The
  sandbox generator is unknown (§10.4), so no cause is claimed.
- **The mkfs-era generation-3 state misses one tree on every s01 image.**
  Its csum tree root is the generation-1 leaf at 1130496. That leaf is a scan
  candidate but invalid (WRITTEN unset, §10.10), so it is not indexed.
  - The fallback read through the current chunk map finds the address
    unmapped, and the state reports it as `unmapped`.
  - Limitation: missing blocks are classified through the current chunk map
    only. An invalid scanned copy at the named address is not consulted; the
    M3 catalog, which stores every candidate, can join them.
- **Reuse is not damage, and the classes separate them.**
  - `m2_logtree`: backup root 5's root, extent and dev tree blocks (30441472,
    30474240, 30457856) now hold intact generation-7 blocks of trees 10, 1
    and 256. All 3 walk failures are `reused`, as the M2a review asked.
  - `m1_badnode_both`: the damaged `sv1` leaf is `corrupt` in the current
    walk and all four backup walks (5 failures). Every state naming it drops
    to 9 of 10 (generation 34 to 11 of 12).
  - Sync discard: the 12 unreachable backup-root blocks read as zeros,
    `zeroed`.
- **Superseded log commits are visible.** On `m2_logtree`, log generation 9
  (superblock + 1) holds 4 blocks, 8 copies: 2 live, reached by the log walk,
  and 2 superseded by the second fsync's log commit. The log rule indexes all
  8 copies; no log candidate was rejected. No log block of a committed
  transaction survives on the corpus.
- **Owner 12 and 13.** No RAID stripe tree or remap tree block exists on the
  corpus. The stock guest kernel cannot create either (§10.4).
- **Sync discard removes the history the kernel frees (EXP-002).** On all
  15 sync images:
  - 2 root-tree states survive: the live one and the mkfs generation-3 state;
  - the root, extent, chunk and dev tree roots of backups 35–37 read as
    zeros. Their fs and csum roots are shared with the live state, hence 14
    of 26 roots;
  - `backup_reachable` falls from 24 to 0 and valid orphans from 340 to 16.
    All 16 are mkfs residue of generations 2–5, outside the current chunk
    map.

  Consistent with the source: under `DISCARD_SYNC`,
  `btrfs_finish_extent_commit` trims every range unpinned at each commit,
  which includes COW-freed tree blocks (extent-tree.c:2994-3005). It also
  trims every block group deleted in the transaction (l.3058-3063), such as
  those the balance emptied (block-group.c:1755-1767). Blocks mkfs freed in
  userspace were never pinned by the kernel. This mechanism is read from the
  source, not measured.
  - Async discard with an unmount about a second later matched no discard
    on every count in all 15 runs.
  - Threats to validity: virtio-blk TRIM on a sparse raw file reads back as
    zeros, whereas SSDs differ; one small scenario; quick unmount
    (`experiments/EXP-002.md` §6.5).
- **Probe reconciliation (EXP-002).** The probe and btrfska's full sweep read
  the same 4 KiB offsets except blocks 0–15, which only the probe reads. The
  kernel places no tree block below 64 KiB (block-group.c:2277-2330), and on
  the corpus those blocks hold no fsid match. With invalid candidates
  included and the probe's generation rule, the counts agree on 48 of 48
  images.
