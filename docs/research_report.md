# Btrfs Forensics — External Research & Prior-Art Audit

> Date: 2026-08-14
> Scope: everything published (papers, journals, conferences, theses, repos,
> tools, commercial products) that overlaps with this project's goal —
> *offline deleted-file recovery from raw Btrfs images*.
> Companion docs: [`plan.md`](../plan.md) (roadmap), [`catalog.md`](catalog.md)
> (development history), [`README.md`](../README.md) (features).

---

## 1. Executive Summary

1. **The project's end-goal is already an active, crowded research topic.** In
   the last 18 months alone there are at least three independent efforts that
   overlap heavily with this project (Pandey et al. 2026 "Beyond Carving",
   MetaRecoverX 2026, Pratyashrit et al. 2026) plus mature open-source and
   commercial implementations (`btrfs restore` + `btrfs-find-root`, `btrfscue`,
   The Sleuth Kit's `btrfs.cpp`, X-Ways, UFS Explorer, DMDE, R-Studio).
2. **The single most important paper to read is *"Beyond Carving: Deterministic
   Deleted File Recovery in Btrfs"* (IEEE Access, Jan 2026).** Its abstract
   describes exactly this project's roadmap (parse raw image → superblock →
   root tree → walk trees → recover deleted files). Full text is paywalled
   (ResearchGate 403), but it must be read before investing in M1–M4.
3. **M1 (backup roots + anchored walking) is substantially already
   implemented** in `btrfs-progs` (`btrfs restore -t <bytenr>`,
   `btrfs-find-root`, superblock `btrfs_root_backup` handling) and in the
   `btrfs-undelete` script lineage (2012→present). The project's differentiator
   must be forensic *reporting, correlation, and confidence*, not raw walking.
4. **M3 (SQLite catalog) and M4 (hybrid reconstruction) have direct published
   analogs** for ext4/XFS (Kim et al. 2021, Electronics 10(18):2310; ExtSFR,
   Lee et al. 2019/2020) — the concept is established; the novelty is applying
   it to Btrfs orphan-node graphs.
5. **Several implementation correctness issues were found** (see §4): hardcoded
   CRC32c despite `csum_type` support for xxhash/sha256/blake2b; a
   `DEV_ITEM` UUID/FSID offset bug; a `ROOT_ITEM` "reserved region" check that
   flags legitimate modern fields as anomalies; an incorrect assumption that
   metadata nodes never live in DATA chunks (false for mixed-block-group
   filesystems < 10 GiB); no superblock-mirror fallback; and no parsing of the
   kernel's own `ORPHAN_ITEM` (0x30) items — which are *the* canonical
   "deleted inode" markers and are different from this project's Bhat & Wani
   "orphan-items" concept (terminology collision, §4.1).
6. **Genuinely open ground remains:** free-space-tree forensics
   (space_cache=v2, default since 2021 — nobody has published recovery work on
   it), orphan `FREE_SPACE_*` item parsing, `SHARED_*_REF` snapshot-backref
   correlation, log-tree forensics, and generation-diffed timeline
   reconstruction for Btrfs specifically.

---

## 2. Academic Literature

### 2.1 Already cited by the project (for completeness)

| Work | Venue | Notes |
|---|---|---|
| Bhat & Wani 2018, *Forensic analysis of B-tree file system (Btrfs)* | Digital Investigation 27:57–70 | Source of the "orphan-items beyond nritems" concept |
| Wani, Bhat & Dehghantanha 2020, *An analysis of anti-forensic capabilities of B-tree file system (Btrfs)* | Australian J. Forensic Sciences 52(4) | Defrag/overwrite anti-forensics |
| Rodeh, Bacik & Mason 2013, *BTRFS: The Linux B-Tree Filesystem* | ACM TOS 9(3) | Format + design |
| Hilgert et al. 2018, *Forensic analysis of multiple device BTRFS configurations using The Sleuth Kit* | Digital Investigation 26:S21–S28 | Multi-device/RAID in TSK |
| Btrfs On-disk Format docs | btrfs.readthedocs.io | Primary spec used |

### 2.2 Missed — directly on-topic (read these first)

| # | Work | Why it matters to this project |
|---|---|---|
| **A1** | **Pandey, Jain & Shetty 2026, "Beyond Carving: Deterministic Deleted File Recovery in Btrfs", IEEE Access (Jan 2026)** | Offline, deterministic deleted-file recovery by fully parsing the raw filesystem image (superblock → root tree → trees). This is the project's stated end-state. **Must read before M1–M4.** ResearchGate: `publication/409809779` |
| **A2** | **Chaudhary et al. 2026, "MetaRecoverX: Recovery of Deleted Data and Associated Metadata from XFS and Btrfs Filesystems", IJISRT 11(4), DOI 10.38124/ijisrt/26apr738** | Python tool doing deep carving (16+ file types) + metadata extraction on Btrfs, ~85% Btrfs recovery rate, SHA-256 verification, PyQt6 GUI, PDF/CSV reports. Direct competitor. |
| **A3** | **Pratyashrit et al. 2026, "Recovery of Deleted Data and Associated Metadata from XFS and Btrfs Filesystems", DMP-LNMR (IMPACT-26), DOI 10.65890/dmp.lnmr.IMPACT26.107** | End-to-end framework: FS detection → free-block scan → content + metadata extraction (inodes, timestamps, xattrs) → checksum verification → structured reports. Very close to this project's approach + F6. |
| **A4** | **Wani & Bhat 2018, "Dataset for forensic analysis of B-tree file system", Data in Brief 18:2013–2018 (open access, PMC5998747)** | The companion dataset paper to Bhat & Wani 2018. Documents the 6-step recovery procedure, orphan-items in **both leaf and internal nodes**, and *percentage-of-data-recovered* baselines. Natural validation corpus for the sandbox results. Not currently cited. |
| **A5** | **Kim et al. 2021, "Ext4 and XFS File System Forensic Framework Based on TSK", Electronics 10(18):2310 (open access)** | Closest published analog to **M3+M4**: metadata derivation from journals + database-backed framework + recovery-rate comparison vs commercial tools, for ext4/XFS. Validates the catalog+reconstruction design; read before building the SQLite layer. |
| **A6** | **Lee et al. 2019/2020, "ExtSFR: Scalable File Recovery Framework Based on an Ext File System", Multimedia Tools and Applications 79:16093–16111** | Database-backed scalable recovery framework for Ext2/3/4; precedent for the "scan once, query many times" catalog idea. |
| **A7** | **Hilgert, Lambertz & Plohmann 2017, "Extending The Sleuth Kit and its underlying model for pooled storage file system forensic analysis", Digital Investigation 22:S76–S85** | Foundation paper behind the 2018 Btrfs-in-TSK paper the project cites. Pooled-storage/RAID model; also useful for the multi-device plan (F7). |

### 2.3 Missed — anti-forensics, data hiding, and adversarial (relevant to claims & F6)

| # | Work | Why it matters |
|---|---|---|
| **B1** | **Toolan & Humphries 2026, "Hiding Data in Btrfs File Systems", SSRN 7138910** | Proposes **six new data-hiding techniques in Btrfs** (2026). Directly relevant to the slack-space / boot-sector / volume-slack extraction features — hidden data can be planted in exactly the regions this tool extracts. |
| **B2** | **Göbel, Türr & Baier 2024, "Generating Usable and Assessable Datasets Containing Anti-Forensic Traces at the Filesystem Level", IFIP WG 11.9 ICDF (Springer)** | ForTrace tool + in-depth analysis of anti-forensic data hiding in Btrfs (also NTFS/ext4). Useful for building adversarial test corpora. |
| **B3** | **Göbel & Baier 2025, "Data hiding in file systems: current state, novel methods…", FSI:DI** | Survey + new hiding methods; extends B2. |
| **B4** | **Schneider et al. 2022, "Ambiguous file system partitions", FSI:DI 42 (DFRWS EU)** | Shows a guest FS can be hidden *inside* a Btrfs host FS's structures. Relevant to boot-sector/partition-level claims and to partition ambiguity when carving raw images. |
| **B5** | **Joun et al. 2023, "Discovering spoliation of evidence through identifying traces on deleted files in macOS", FSI:DI (DFRWS USA)** | Universal methodology for tracking deleted-file traces; adaptable to Btrfs for F5/F6 provenance work. |

### 2.4 Missed — foundational / adjacent methodology

| # | Work | Relevance |
|---|---|---|
| **C1** | Carrier 2005, *File System Forensic Analysis* | The field's layer model; the "targeted scan regions" idea maps to Carrier's layer abstraction. |
| **C2** | Buchholz & Spafford 2004, "On the role of file system metadata in digital forensics", Digital Investigation 1(4) | Metadata-roles framework; good citation for the confidence model (plan §9). |
| **C3** | Hargreaves & Patterson 2012, "An automated timeline reconstruction approach…", Digital Investigation 9:S69–S79 | Precedent for F5 (generation diffing / timelines). |
| **C4** | Fairbanks 2012, "An analysis of ext4 for digital forensics", Digital Investigation 9:S118–S130 | Methodology template for a "what survives deletion" study — the paper Bhat/Wani themselves cite. |
| **C5** | Kim, Park, Lee & Lee 2012, "Forensic Analysis of Android Phone Using Ext4 File System Journal Log" | Journal/log-based recovery precedent (relevant to the scoped-out log tree, F7). |
| **C6** | *The Btrfs File System*, chapter 11 in *File System Forensics* (Wiley, 2025), DOI 10.1002/9781394289820.ch11 | Recent book chapter covering Btrfs forensics; easy background and citation. |
| **C7** | Nodler 2024, *Deleted File Recovery in Ext4 File Systems* (thesis, OhioLINK) | Recent DFR methodology + evaluation approach. |

### 2.5 Adjacent / watch list

- **XFS**: Vaheed Khan et al., *Efficient Recovery of Deleted Data and Metadata from XFS* (five forensic analysis methods — methodology transfers); *XFS Forensic Scanner* (IJERT 2026).
- **ZFS**: CoW filesystem with far *less* published deleted-file recovery (commercial-only so far: UFS Explorer, R-Studio). A "Btrfs vs ZFS CoW artifact persistence" comparative study is an open research niche.
- **DFRWS archives** (dfrws.org) and **FSI:DI** are the two venues to monitor for new Btrfs work; the Kashmir group (Wani/Bhat) Scholar profile is the author-level watch.

---

## 3. Existing Tools & Repositories (the "already implemented" landscape)

### 3.1 Open source — direct overlap

| Tool | What it does vs. this project |
|---|---|
| **`btrfs-progs` — `btrfs restore`** | Walks current roots and salvages files from damaged FS; `-t <bytenr>` lets you point at a specific historical root (exactly M1's anchored walking); `-l/--list-roots` lists subvolume roots; `-m` restores metadata, `-x` xattrs. Read-only. |
| **`btrfs-progs` — `btrfs-find-root`** | Scans the device for all historical tree roots by generation — the same evidence this project plans to harvest from backup roots (M1). Pairing it with `btrfs restore -t` is the community-standard deleted-file workflow. |
| **`btrfs-undelete` (Jörg Walter 2012; forks: `danthem/undelete-btrfs`, gist forks)** | Shell-script wrapper over `btrfs-find-root` + `btrfs restore -t` to undelete recently deleted files. Crude but functional. |
| **`btrfscue` (cblichmann/btrfscue, Go)** | Heuristic FSID detection (`identify`), full-image metadata scan into a DB (`recon`), `ls`/FUSE-mount of recovered metadata, `recover` command. Recovers *recently deleted files and directories*. Very close to this project's architecture (scan → catalog → recover). |
| **The Sleuth Kit `tsk/fs/btrfs.cpp`** | Full Btrfs implementation in TSK (from Hilgert's work): superblock, chunk tree, root tree, fs trees, file/extent recovery, `tsk_recover -e` for deleted files, RAID/pool handling. Direct benchmark; also proves "works on raw images, no mount" is not a differentiator by itself. |
| **`btrForensics` (shujianyang/btrForensics)** | Forensic analysis tool for Btrfs built on the TSK library. |
| **`btrfs check --init-extent-tree` / `--mode=lowmem` / `--repair`** | Rebuilds the extent tree from scratch by scanning all nodes — a *write-mode* analog of this project's extent-tree reconstruction ideas; also documents that reconstruction of metadata graphs from raw blocks is well-trodden. |
| **`btrfs rescue chunk-recover`** | Rebuilds a damaged chunk tree by scanning devices — relevant to the project's chunk-map reconstruction from orphaned `CHUNK_ITEM`s. |
| **`davispuh/btrfs-data-recovery`, `msedek/btrfs_fixes`** | Community extent-tree/repair tooling for severe corruption cases. |

### 3.2 Commercial (state of the art for the same problem)

| Product | Notes |
|---|---|
| **X-Ways Forensics** | Native Btrfs support; **distinguishes "100% recoverable vs uncertain" deleted files** — i.e., a confidence tier, directly comparable to plan §9. |
| **UFS Explorer / R-Studio / DMDE / DiskGenius / EaseUS / Reclaime / Hetman / Recoverit** | All advertise Btrfs deleted-file recovery; UFS Explorer in particular reconstructs directory trees and unlinked metadata chunks. |
| **TestDisk/PhotoRec** | PhotoRec can carve Btrfs partitions but lacks metadata reconstruction (the gap this project targets). |

> **Takeaway:** raw-image Btrfs deleted-file recovery with metadata is *already
> sold commercially and implemented in at least four open-source codebases*.
> The defensible niche is: (a) forensic-grade provenance/confidence reporting,
> (b) the orphan-node/orphan-item graph as a *historical reconstruction*
> engine rather than a salvage tool, and (c) pure-Python, zero-dependency,
> auditable code.

---

## 4. Implementation Correctness Concerns (found by cross-checking code vs. spec)

### 4.1 Terminology collision — "orphan item" means two different things

- **This project** (following Bhat & Wani 2018): "orphan items" = item-pointer
  slots **beyond `nritems`** in a leaf, left by node balancing. ✓ implemented.
- **The kernel/Btrfs itself**: `BTRFS_ORPHAN_ITEM_KEY = 0x30` (48) — items
  inserted into the fs tree for **inodes with nlink=0 pending deletion**
  (deleted-but-open files, crash-recovery markers). These are the *canonical
  "deleted inode" artifact* and are **not parsed** by `btree.py`
  (`BTRFS_ORPHAN_ITEM_KEY` exists in `constants.py` but has no handler).
  Also `BTRFS_ORPHAN_OBJECTID = -5` for orphan root tracking in the root tree.
- **Action:** disambiguate in docs (e.g., "Orphan-Items (Bhat & Wani)" vs
  "orphan inode items (0x30)"), and add a 0x30 parser — it is a cheap, direct
  deleted-file signal that also marks aborted deletions.

### 4.2 Checksums: CRC32c is hardcoded; Btrfs supports 4 algorithms

- Superblock field `csum_type` (offset 0xC4, 2 bytes). Since kernel 5.5 /
  `mkfs.btrfs --csum`, valid values are **crc32c (default), xxhash, sha256,
  blake2b**.
- `utils/crc32c.py` + `btree.py:500` always verify with CRC32c. On a
  non-CRC32c filesystem **every node fails CRC and the tool silently finds
  nothing**. The superblock's own checksum (bytes 0x00–0x20) is also never
  validated.
- **Action:** read `csum_type`; dispatch; at minimum detect and warn. Also
  validate the superblock checksum before trusting the superblock.

### 4.3 Mixed block groups break the targeted-scan assumption

- `build_scan_regions()` skips DATA chunks because "Btrfs never allocates
  metadata nodes there" (README). This is only true when the **MIXED_GROUPS
  incompat flag is unset**. Filesystems **smaller than ~10 GiB** commonly use
  mixed block groups (data+metadata in one block group), so metadata nodes CAN
  live inside DATA-typed chunks.
- On `sandbox.img` (256 MiB, separate DATA/SYSTEM/METADATA chunks) this is
  fine — but on small real disks the targeted scan would silently miss orphans.
- **Action:** parse `incompat_flags` (SB offset 0xBC) and auto-include DATA
  chunks when MIXED_GROUPS is set (or warn loudly).

### 4.4 `DEV_ITEM` UUID/FSID offset bug

- Per on-disk spec: `devid@0, total@8, used@16, io_align@24, io_width@28,
  sector@32, type@36, generation@44, start_offset@52, dev_group@60,
  seek_speed@64, bandwidth@65, dev_uuid@66 (16B), fsid@82 (16B)`.
- `_parse_dev_tree_leaf()` reads `dev_uuid = dev_data[82:98]` → it prints the
  **filesystem UUID** as the device UUID. Cosmetic, but wrong in reports.

### 4.5 `ROOT_ITEM` "reserved region" check flags legitimate data

- `_parse_single_item()` flags non-zero bytes in `root_item[235:439]` as
  anomalies. The modern `btrfs_root_item` uses most of that range for real
  fields (generation_v2, uuid/parent_uuid/received_uuid, ctransid/otransid/
  stransid/rtransid, ctime/otime/stime/rtime, send_transid, received_* etc.).
  Only a trailing `reserved`/`reserved2` area is genuinely unused.
- **Action:** compute the real reserved ranges from the kernel struct
  (`fs/btrfs/transaction.h`) and flag only those; otherwise this feature is a
  false-positive machine on any modern filesystem.

### 4.6 Superblock mirrors ignored

- `constants.py` defines `SUPERBLOCK_MIRROR_1 = 0x4000000` and
  `SUPERBLOCK_MIRROR_2 = 0x4000000000`, but `superblock.py` reads only the
  primary at `0x10000` and never falls back. `btrfs-progs` tries all three
  mirrors + backup roots. For forensic robustness (damaged primary SB), add
  mirror fallback — cheap and already half-declared in constants.

### 4.7 Unparsed on-disk item types (gaps vs. the format)

| Type | Name | Relevance |
|---|---|---|
| 0x30 | `ORPHAN_ITEM` | Deleted-inode markers (see 4.1) — **should be a headline feature** |
| 0x0D | `INODE_EXTREF` | Hard-link names beyond INODE_REF capacity |
| 0x18 | `XATTR_ITEM` | Extended attributes (A2/A3 competitors extract these) |
| 0x3C/0x48 | `DIR_LOG_ITEM`/`DIR_LOG_INDEX` | Log-tree directory entries (crash-recovery artifacts; F7 log tree) |
| 0x80 | `EXTENT_CSUM` | Checksum tree — needed for F6 "validate recovered content" |
| 0x90/0x9C | `ROOT_BACKREF`/`ROOT_REF` | Subvolume/snapshot parentage — planned for M3 `root_links` table; parse now |
| 0xB0 | `TREE_BLOCK_REF` | Metadata backrefs — core of F3 reverse-semantic mode |
| 0xB6/0xB8 | `SHARED_BLOCK_REF`/`SHARED_DATA_REF` | Snapshot shared-extent backrefs — essential for snapshot recovery; currently only `EXTENT_DATA_REF` (0xB2) is parsed |
| 0xC0 | `BLOCK_GROUP_ITEM` | Allocation/type flags per block group (needed to *prove* 4.3) |
| 0xCC | `DEV_EXTENT` | Physical→logical reverse map — needed for chunk-map reconstruction (M4, `chunk-recover` analog) |
| 0xDD–0xDF | `FREE_SPACE_INFO/EXTENT/BITMAP` | Free-space tree items (space_cache=v2) — **nobody has published forensic work here; open niche** |

### 4.8 Multi-device / RAID chunk handling is single-stripe only

- `parse_chunk_leaf()` records one map entry per stripe with the *same logical
  range*, and `translate_logical_to_physical()` returns the first match —
  correct only for single-device, non-RAID. Known limitation in the README
  (F7), but the stripe data *is* being read, so RAID1/10 logical→physical
  translation is close; striping (RAID0/5/6) needs per-stripe math.

---

## 5. Plan-Level Findings (already implemented / needs repositioning)

| Plan item | Status vs. outside world | Recommendation |
|---|---|---|
| **M1** backup roots + anchored walking | **Already exists**: `btrfs restore -t`, `btrfs-find-root`, superblock backup-root handling, `btrfs-undelete`, `btrfscue`, TSK, X-Ways | Keep, but position as *forensic reporting + graph correlation*, not novel walking. Add superblock-mirror fallback (4.6). |
| **M2** targeted scan | Genuinely good optimization; aligned with Carrier's layer model | Add MIXED_GROUPS handling (4.3) and incompat-flag parsing. |
| **M3** SQLite catalog | Direct published analogs for ext4/XFS (A5, A6); `btrfscue` already persists a metadata DB | Read Kim et al. 2021 first; mirror its evaluation methodology (recovery rate vs commercial tools). |
| **M4** hybrid reconstruction | "Beyond Carving" (A1) appears to implement this exact goal | **Read A1 before building.** Differentiate via orphan-node graph + confidence provenance. |
| **F3** cross-reference expansion | `SHARED_*_REF`, `TREE_BLOCK_REF`, `DEV_EXTENT`, free-space tree all unparsed (4.7) | These are the highest-value additions; also the least-published. |
| **F5** generation diffing | Precedent: C3 (timelines), Kim et al. 2021 file-event generation | Straightforward once anchored states exist (backup-root gen-13 vs current gen-14 already on `sandbox.img`). |
| **F6** validation/confidence | X-Ways already ships "recoverable vs uncertain" tiers | Cite C2; implement EXTENT_CSUM validation (4.7). |
| **F7** compression/log/RAID | A2/A3 competitors already extract xattrs; log tree untouched in literature | Log-tree forensics is an open niche — crash-recovery artifacts (DIR_LOG_*, orphan items) have no published Btrfs treatment. |

---

## 6. Recommended Reading Order & Next Actions

1. **Read (24h):** A1 "Beyond Carving" (IEEE Access 2026) — get via IEEE Xplore
   or interlibrary; determine overlap with M1–M4 before writing more code.
2. **Read (this week):** A4 (dataset paper — use as validation corpus), A5
   (Kim et al. — catalog + evaluation design), B1 (Btrfs data hiding — recheck
   slack/boot/volume-slack claims).
3. **Fix (small, high-value):** 4.2 (csum_type dispatch), 4.4 (DEV_ITEM UUID
   offset), 4.5 (ROOT_ITEM reserved ranges), 4.6 (mirror fallback), 4.1
   (parse 0x30 orphan inode items + rename docs to disambiguate).
4. **Add (medium, differentiating):** 4.3 (MIXED_GROUPS-aware scan regions),
   free-space-tree parsing (open niche), `SHARED_*_REF` snapshot backrefs.
5. **Benchmark:** run this tool, `btrfs restore`, `btrfscue`, and TSK
   `tsk_recover -e` on the same image; publish a recovery-rate comparison in
   the README (mirrors A5's methodology).

---

## 7. Reference Index (external)

| Kind | Item |
|---|---|
| Paper (must-read) | Pandey, Jain & Shetty, *Beyond Carving: Deterministic Deleted File Recovery in Btrfs*, IEEE Access, Jan 2026 — ResearchGate `publication/409809779` |
| Paper (competitor) | Chaudhary et al., *MetaRecoverX…*, IJISRT 11(4), DOI 10.38124/ijisrt/26apr738 |
| Paper (competitor) | Pratyashrit et al., *Recovery of Deleted Data and Associated Metadata from XFS and Btrfs Filesystems*, DMP-LNMR IMPACT-26, DOI 10.65890/dmp.lnmr.IMPACT26.107 |
| Dataset | Wani & Bhat, *Dataset for forensic analysis of B-tree file system*, Data in Brief 18 (2018) — PMC5998747 (open access) |
| Framework analog | Kim et al., *Ext4 and XFS File System Forensic Framework Based on TSK*, Electronics 10(18):2310 (2021, open access) |
| Framework analog | Lee et al., *ExtSFR*, Multimedia Tools & Applications 79 (2019/2020) |
| TSK foundation | Hilgert et al., *Extending The Sleuth Kit…pooled storage…*, Digital Investigation 22 (2017) |
| Anti-forensics | Toolan & Humphries, *Hiding Data in Btrfs File Systems*, SSRN 7138910 (2026) |
| Anti-forensics | Göbel, Türr & Baier, IFIP WG 11.9 ICDF 2024 (Springer); Göbel & Baier, FSI:DI (2025) |
| Anti-forensics | Schneider et al., *Ambiguous file system partitions*, FSI:DI 42 (2022) |
| Tool | `btrfscue` — github.com/cblichmann/btrfscue |
| Tool | `btrfs-undelete` — github.com/danthem/undelete-btrfs (Jörg Walter 2012 lineage) |
| Tool | The Sleuth Kit `tsk/fs/btrfs.cpp` — sleuthkit.org |
| Tool | `btrForensics` — github.com/shujianyang/btrForensics |
| Tool | `btrfs-progs` — `btrfs restore`, `btrfs-find-root`, `btrfs check`, `btrfs rescue chunk-recover` |
| Commercial | X-Ways Forensics (Btrfs support, recoverable/uncertain tiers), UFS Explorer, R-Studio, DMDE, DiskGenius, EaseUS, Reclaime, Hetman, Recoverit |
| Spec | btrfs.readthedocs.io On-disk Format (note: header csum_type at SB 0xC4; MIXED_GROUPS/block-group-tree incompat flags at SB 0xBC; backup roots at SB 0xB2B) |
