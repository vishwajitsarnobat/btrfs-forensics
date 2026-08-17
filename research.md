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
   space our contribution occupies (§2.2).
4. **Sleuth Kit upstream has no Btrfs support at all** — PR #413 (2015) was
   closed unmerged in Oct 2024; only the dead FKIE fork (last push 2022) has
   it. "TSK can't parse Btrfs" is the standard baseline claim in this
   literature (§2.3).
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

### 2.3 The Sleuth Kit — C/C++, CPL/IBM-PL, **no upstream Btrfs**

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
| Kim, Kim, Shin, Jo, Lee & Shon 2021 | Electronics 10(18):2310, DOI 10.3390/electronics10182310 (OA) | **The evaluation template** (§5.3): before/after images, TSK + UFS Explorer + R-Studio baselines, recovery rate + hash-match accuracy |
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
