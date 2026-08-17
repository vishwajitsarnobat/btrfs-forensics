# Btrfs Forensics — Team Research Dossier

> **Date:** 2026-08-14
> **Audience:** the whole team (eng + research)
> **Purpose:** everything published that touches *offline deleted-file recovery
> from raw Btrfs images* — papers, journals, theses, conferences, repos, tools,
> commercial products — with what it means for our plan and our code.
>
> Companion docs: [`plan.md`](../plan.md) (roadmap), [`catalog.md`](catalog.md)
> (development history), [`README.md`](../README.md) (features).
> First-pass audit: `docs/research_report.md`. This file is the expanded,
> team-facing version.

---

## 1. TL;DR for the Team

1. **Our end-goal is already an active research topic, and 2026 alone has
   produced at least three overlapping independent efforts.** We are not
   first; we need to be *better* and *forensically defensible*.
2. **The single most important artifact to read: *"Beyond Carving:
   Deterministic Deleted File Recovery in Btrfs"* (IEEE Access, accepted/in
   press, Jan 2026)** — Pandey, Jain & Shetty (Manipal Institute of Technology,
   India). Abstract: *"a novel offline deleted-file recovery algorithm for the
   B-tree File System (Btrfs) that operates by fully parsing the raw filesystem
   image…"* — i.e., literally our roadmap. Full text is paywalled
   (ResearchGate `publication/409809779`); obtain it before M1–M4.
3. **M1 (backup roots + anchored walking) is already implemented** in
   `btrfs-progs` (`btrfs restore -t <bytenr>`, `btrfs-find-root`,
   superblock `btrfs_root_backup` handling), in the `btrfs-undelete` script
   lineage (2012→now), in **`btrfscue`** (Go), and in **The Sleuth Kit's
   `tsk/fs/btrfs.cpp`**. Our differentiator must be forensic *reporting,
   correlation, confidence* — not raw walking.
4. **M3 (SQLite catalog) has a direct existing precedent** — `davispuh/
   btrfs-data-recovery` ships `btrfs-scanner`, which scans all blocks into a
   SQLite DB with `isValid`, `generation`, `owner`, `refs` tables and answers
   "how many corrupted/unreferenced blocks" queries. Read it before designing
   our catalog.
5. **Six code-level correctness issues found** (details in §5): hardcoded
   CRC32c (Btrfs supports xxhash/sha256/blake2b), `DEV_ITEM` UUID/FSID offset
   bug, `ROOT_ITEM` "reserved region" false positives, mixed-block-group blind
   spot in the targeted scan, ignored superblock mirrors, and no handling of
   the kernel's *own* `ORPHAN_ITEM` (0x30) items — a different concept from
   our Bhat & Wani "orphan-items".
6. **Open research niches where we can still be first:** free-space-tree
   forensics (space_cache=v2, default since 2021 — nobody has published on
   it), orphan `FREE_SPACE_*` item recovery, `SHARED_*_REF` snapshot-backref
   correlation, and Btrfs log-tree forensics (crash-recovery artifacts).
7. **Anti-forensic side is directly relevant:** the 2026 SSRN paper *"Hiding
   Data in Btrfs File Systems"* documents **six** hiding techniques that
   target exactly the areas our slack/boot/volume-slack features extract
   (pre-superblock, superblock reserved/slack, chunk-array slack, inode-item
   reserved bytes, internal-node slack, STRING_ITEM 0xFD). We should be able
   to *detect* those, not just extract residual data.
8. **"Is there nothing useful left in our plan?"** → No. Full answer in
   **§4.1** (strategic assessment): the *capabilities* exist elsewhere, but the
   *research program* — orphan-graph reconstruction, generation diffing,
   free-space-tree forensics, confidence+provenance, hiding detection — is
   still open. Read §4.1 before arguing about scope.

---

## 2. The Competitive Landscape (2026)

### 2.1 Direct prior art — papers

| Work | What it does | Overlap with us | Priority |
|---|---|---|---|
| **Pandey, Jain & Shetty, *Beyond Carving: Deterministic Deleted File Recovery in Btrfs*, IEEE Access (Jan 2026)** | Offline recovery from raw image; parses superblock → root tree → walks trees → recovers deleted files | Our entire M1–M4 | 🔴 read first |
| **Chaudhary et al., *MetaRecoverX*, IJISRT 11(4) 2026, DOI 10.38124/ijisrt/26apr738** | Python tool: deep carving (16+ file types), metadata extraction (timestamps, perms, SHA-256 verify, EXIF), PyQt6 GUI, PDF/CSV reports; ~85% Btrfs recovery | Our core + reporting + F6 | 🟠 read |
| **Pratyashrit et al., *Recovery of Deleted Data and Associated Metadata from XFS and Btrfs Filesystems*, DMP-LNMR (IMPACT-26) 2026, DOI 10.65890/dmp.lnmr.IMPACT26.107** | FS detection → free-block scan → content+metadata extraction (inodes, timestamps, xattrs) → checksum verify → structured reports | Our core + F6 | 🟠 read |
| **Kim et al., *Ext4 and XFS File System Forensic Framework Based on TSK*, Electronics 10(18):2310, 2021 (open access)** | Journal-derived metadata + DB-backed framework + recovery-rate benchmark vs commercial tools, for ext4/XFS | Direct analog of our M3+M4 + evaluation methodology | 🟡 read for M3/M4 |
| **Lee et al., *ExtSFR: Scalable File Recovery Framework…Ext*, Multimedia Tools & Appl. 79:16093–16111** | DB-backed scalable ext2/3/4 recovery framework | Catalog idea (M3) precedent | 🟡 skim |
| **Wani & Bhat, *Dataset for forensic analysis of B-tree file system*, Data in Brief 18 (2018), open access (PMC5998747)** | 6-step recovery procedure, orphan-items in leaf AND internal nodes, %-recovered baselines | Our orphan-item scan; validation corpus | 🟢 use as dataset |

### 2.2 Existing open-source tools (the "already implemented" landscape)

| Tool | Capabilities | Notes for us |
|---|---|---|
| **`btrfs-progs` — `btrfs restore`** | Walk current roots, salvage files; `-t <bytenr>` points at an arbitrary historical root; `-l` lists subvolume roots; `-m` metadata, `-x` xattrs; read-only | M1 anchored walking exists here |
| **`btrfs-progs` — `btrfs-find-root`** | Scans device for all historical tree roots by generation | Exactly M1's evidence harvest; pairs with `restore -t` |
| **`btrfs-undelete` (Jörg Walter 2012; `danthem/undelete-btrfs`; gist forks)** | Shell wrapper: `btrfs-find-root` → `btrfs restore -t` | Community-standard deleted-file workflow |
| **`btrfscue` (cblichmann, Go)** | `identify` (FSID heuristic) → `recon` (full-image scan → metadata DB) → `ls`/FUSE mount → `recover`; recovers recently deleted files/dirs | Closest open architecture to ours (scan → catalog → recover) |
| **The Sleuth Kit `tsk/fs/btrfs.cpp`** | Full Btrfs: superblock, chunk tree, root tree, fs trees, file/extent recovery, `tsk_recover -e` deleted files, RAID/pool | Direct benchmark; raw-image, no-mount is *not* a differentiator |
| **`davispuh/btrfs-data-recovery`** | `btrfs-scanner`: block scan → **SQLite** DB (`blocks`, `refs` tables; `isValid`, generation, owner); `btrfs-fixer.rb` repairs; counts corrupted/unreferenced blocks via SQL | **Direct precedent for M3 SQLite catalog** — read before designing ours |
| **`btrForensics` (shujianyang)** | Btrfs forensic analysis tool on top of TSK library | Benchmark |
| **`btrfs check --init-extent-tree` / `--mode=lowmem` / `--repair`** | Rebuilds extent tree from scratch; repair modes | Write-mode analog of our extent-tree reconstruction ideas |
| **`btrfs rescue chunk-recover`** | Rebuilds damaged chunk tree by scanning devices | Relevant to chunk-map reconstruction from orphaned `CHUNK_ITEM`s |
| **`msedek/btrfs_fixes`** | Custom repair tools for severe extent-tree corruption | Case-study of extent-tree reconstruction |
| **`qdm12/btrfs-recover-scripts`** | Time-reference based restore scripts (find a recent file, restore from its generation) | Generation-rollback pattern |

### 2.3 Commercial (the bar we must beat or complement)

| Product | Notes |
|---|---|
| **X-Ways Forensics** | Native Btrfs; **distinguishes "100% recoverable vs uncertain" deleted files** — a confidence tier like our §9 model |
| **UFS Explorer** | Reconstructs directory trees + unlinked metadata chunks on Btrfs |
| **R-Studio / DMDE / DiskGenius / EaseUS / Reclaime / Hetman / Recoverit** | Advertise Btrfs deleted-file recovery |
| **TestDisk/PhotoRec** | Carves Btrfs partitions; no metadata reconstruction (the gap we target) |

> **Positioning takeaway:** raw-image Btrfs deleted-file recovery with metadata
> is *already* implemented commercially and in ≥4 open-source codebases. Our
> defensible niche: (a) forensic-grade provenance + confidence tiers, (b) the
> orphan-node / orphan-item graph as a *historical reconstruction* engine, not
> a salvage tool, (c) pure-Python, zero-dependency, auditable, testable code.

---

## 3. Full Academic Corpus (annotated)

### 3.1 Already cited by us (baseline)

| Work | Venue | Notes |
|---|---|---|
| Bhat & Wani 2018, *Forensic analysis of B-tree file system (Btrfs)* | Digital Investigation 27:57–70 | Source of our "orphan-items beyond nritems" concept |
| Wani, Bhat & Dehghantanha 2020, *An analysis of anti-forensic capabilities of B-tree file system (Btrfs)* | Australian J. Forensic Sciences 52(4):371–395 | Defrag/overwrite anti-forensics; 4 CFTs couldn't detect most AF attacks (see Forensic Focus roundup) |
| Rodeh, Bacik & Mason 2013, *BTRFS: The Linux B-Tree Filesystem* | ACM TOS 9(3) | Design + format |
| Hilgert et al. 2018, *Forensic analysis of multiple device BTRFS configurations using The Sleuth Kit* | Digital Investigation 26:S21–S28 (DFRWS USA 2018, **Best Paper**) | Multi-device/RAID in TSK |
| Btrfs On-disk Format docs | btrfs.readthedocs.io | Our primary spec |

### 3.2 Missed — directly on-topic (read these first)

| # | Work | Why |
|---|---|---|
| **A1** | **Pandey, Jain & Shetty 2026, "Beyond Carving…", IEEE Access** | Our roadmap, published. Get full text via IEEE Xplore / Manipal portal (`researcher.manipal.edu` lists it as accepted/in-press). |
| **A2** | **Chaudhary et al. 2026, "MetaRecoverX…", IJISRT** | Direct competitor, Python, ~85% Btrfs recovery. |
| **A3** | **Pratyashrit et al. 2026, "Recovery of Deleted Data…XFS and Btrfs", DMP-LNMR** | Direct competitor, end-to-end + checksum verify. |
| **A4** | **Wani & Bhat 2018, "Dataset for forensic analysis of B-tree file system", Data in Brief 18** | Companion dataset paper; 6-step recovery procedure; orphan-items from BOTH leaf and internal nodes; recovery-ratio baselines. Use as our validation corpus. |
| **A5** | **Kim et al. 2021, "Ext4 and XFS File System Forensic Framework Based on TSK", Electronics 10(18):2310** | Closest published analog to M3+M4; DB-backed framework + commercial-tool benchmark methodology. |
| **A6** | **Lee et al., "ExtSFR", Multimedia Tools & Applications 79** | Catalog precedent for ext. |
| **A7** | **Hilgert, Lambertz & Plohmann 2017, "Extending The Sleuth Kit…pooled storage…", Digital Investigation 22:S76–S85** | Foundation of the 2018 paper; pooled-storage/RAID model — useful for F7. |
| **A8** | **Hilgert, Lambertz & Baier 2024, "Forensic implications of stacked file systems", FSI:DI 48:301678** | DFRWS EU 2024; stacked/overlay FS implications — relevant to our slack/boot extraction claims. |

### 3.3 Missed — anti-forensics, data hiding, adversarial

| # | Work | Why it matters |
|---|---|---|
| **B1** | **Toolan & Humphries 2026, "Hiding Data in Btrfs File Systems", SSRN 7138910 (preprint, FSI:DI submission)** | **Six new Btrfs hiding techniques** with exact offsets. We extracted the full text — see §5.3 for the offsets and what it means for our code. |
| **B2** | **Göbel, Türr & Baier 2024, "Generating Usable and Assessable Datasets Containing Anti-Forensic Traces at the Filesystem Level", IFIP WG 11.9 ICDF (Springer)** | ForTrace + Btrfs hiding analysis; test-corpus generation. |
| **B3** | **Schwietert & Hilgert 2025, "Data hiding in file systems: Current state, novel methods, and a standardized corpus", FSI:DI (DFRWS APAC 2025)** | Survey + first standardized data-hiding corpus (NTFS/ext/FAT + novel methods incl. snapshot misuse). Directly relevant to our slack/boot claims and to F6 detection. |
| **B4** | **Schneider et al. 2022, "Ambiguous file system partitions", FSI:DI 42 (DFRWS EU)** | A guest FS can hide inside a Btrfs host FS's structures — partition-ambiguity + boot-sector relevance. |
| **B5** | **Joun et al. 2023, "Discovering spoliation of evidence through identifying traces on deleted files in macOS", FSI:DI (DFRWS USA)** | Universal deleted-file trace methodology; adaptable for F5/F6 provenance. |
| **B6** | **Bhat, Al Zahrani & Wani 2020, "Can computer forensic tools be trusted in digital investigations?", FSI** | 4 CFTs failed to detect most anti-forensic attacks — supports our argument for structural (not tool-based) analysis. |

### 3.4 Missed — foundational / methodology (cite in the paper)

| # | Work | Relevance |
|---|---|---|
| **C1** | Carrier 2005, *File System Forensic Analysis* | Layer model; our targeted-scan regions = Carrier's layers |
| **C2** | Buchholz & Spafford 2004, "On the role of file system metadata in digital forensics", Digital Investigation 1(4) | Metadata-roles framework → our confidence model (§9) |
| **C3** | Hargreaves & Patterson 2012, "An automated timeline reconstruction approach…", Digital Investigation 9:S69–S79 | Precedent for F5 generation diffing / timelines |
| **C4** | Fairbanks 2012, "An analysis of ext4 for digital forensics", Digital Investigation 9:S118–S130 | The paper Bhat/Wani build on; methodology template |
| **C5** | Kim, Park, Lee & Lee 2012, "Forensic Analysis of Android Phone Using Ext4 File System Journal Log" | Journal/log-based recovery precedent (log tree, F7) |
| **C6** | *The Btrfs File System*, ch. 11 in *File System Forensics* (Wiley 2025), DOI 10.1002/9781394289820.ch11 | Recent book chapter; easy citation + background |
| **C7** | Nodler 2024, *Deleted File Recovery in Ext4 File Systems* (thesis, OhioLINK) | Recent DFR methodology + evaluation |
| **C8** | "Towards a practical usage for the Sleuth Kit supporting file system add-ons", FSI:DI 50 (2024) | TSK add-on practicality (ext4/XFS/F2FS gaps) — context for TSK-benchmarking |

### 3.5 Watch list / adjacent

- **ZFS:** CoW filesystem with *less* published deleted-file recovery (mostly
  commercial). A Btrfs-vs-ZFS CoW artifact-persistence comparison is an open
  niche.
- **XFS:** Vaheed Khan et al., *Efficient Recovery of Deleted Data and Metadata
  from XFS* (five forensic analysis methods — methodology transfers); *XFS
  Forensic Scanner* (IJERT 2026).
- **Venues to monitor:** DFRWS USA/EU/APAC (dfrws.org), FSI:DI, IEEE Access,
  Data in Brief (Kashmir group datasets), and the Wani/Bhat Scholar profile.

---

## 4. Plan Audit — What's Already Done Elsewhere

| Plan item | Outside world | Verdict |
|---|---|---|
| **M1** backup roots + anchored walking | `btrfs restore -t` + `btrfs-find-root` + superblock backup roots (btrfs-progs); `btrfs-undelete`; `btrfscue`; TSK | Already implemented. Keep, but position as forensic reporting + graph correlation, and add superblock-mirror fallback (§5.6). |
| **M2** targeted scan | Good optimization; maps to Carrier's layer model; aligns with TSK chunk-driven reads | Keep. Add MIXED_GROUPS awareness (§5.4) and incompat-flag parsing. |
| **M3** SQLite catalog | `davispuh/btrfs-data-recovery` (`btrfs-scanner`) is a direct SQLite precedent; Kim et al. 2021 and ExtSFR for ext4/XFS | Read `btrfs-scanner` before designing schema; mirror Kim et al.'s benchmark methodology. |
| **M4** hybrid reconstruction | "Beyond Carving" (A1) appears to implement this exact goal | **Read A1 before building.** Differentiate via orphan-node graph + provenance. |
| **F3** cross-reference expansion | `SHARED_*_REF`, `TREE_BLOCK_REF`, `DEV_EXTENT`, free-space-tree items all unparsed (§5.7) | Highest-value additions; least published. |
| **F5** generation diffing | Precedent: C3 timelines; Kim et al. 2021 file-event generation | Do once anchored states exist (gen-13 backup root vs gen-14 current already in sandbox). |
| **F6** validation/confidence | X-Ways ships recoverable/uncertain tiers; B5 spoliation methodology | Cite C2; implement `EXTENT_CSUM` (0x80) validation; add hiding-detection (B1/B3). |
| **F7** compression/log/RAID | Competitors already extract xattrs (A2/A3); log tree untouched in literature | Log-tree forensics = open niche; xattr extraction is table stakes now. |

---

## 4.1 Strategic Assessment — "Is There Nothing Useful Left in Our Plan?" (Q&A, 2026-08-14)

> **Trigger:** the team asked, *"We already have implemented M2 and M1, so
> according to you there is nothing useful we are doing in our plan?"*
> This section is the durable, full answer. It is written here so it does not
> live only in chat.

### 4.1.1 Correction — M1 is only partially implemented

Per `plan.md` §2.1 (and this is our own roadmap's status, not an external
claim):

| M1 step | Status |
|---|---|
| Generic metadata-tree walker (M1 step 2, extracted for M2) | ✅ Done (`utils/tree_walker.py`) |
| Parse `btrfs_root_backup` entries from the superblock (M1 step 1) | ❌ Pending |
| Walk the historical gen-13 state with anchored provenance (M1 step 3) | ❌ Pending |

**Key nuance:** the pending half of M1 is the *least novel as a capability*
(`btrfs restore -t` + `btrfs-find-root` already do anchored historical
walking) but the *most novel as a research contribution* (forensic
reconstruction with provenance, not just salvage).

### 4.1.2 Capability ≠ Research Contribution

The research says: **the raw abilities in the plan already exist elsewhere.**
`btrfs restore -t` + `btrfs-find-root` do anchored historical walking; TSK
(`tsk/fs/btrfs.cpp`) and `btrfscue` recover deleted files from raw images;
`davispuh/btrfs-data-recovery` has a SQLite block catalog; X-Ways even ships
confidence tiers. And the 2026 "Beyond Carving" paper (A1) appears to be this
project's entire roadmap.

**If the goal were merely *"build a tool that recovers deleted Btrfs files"*
then yes — most of it is pre-implemented, and the honest answer to the team's
question would be "mostly."**

**But that is not what the plan is building.** The plan is a research program
(reconstruction engine, catalog, confidence, timelines), and *as a research
program* most of it is still open. The distinction is the whole point:

### 4.1.3 What is still genuinely open (our defensible niche)

1. **Orphan-node / orphan-item graph as a historical-reconstruction engine
   (M4 + F5).** Nobody — not TSK, not `btrfscue`, not the 2026 papers — treats
   orphaned nodes + orphan-items as a cross-tree, generation-aware
   reconstruction graph. The 2026 papers do *file recovery*; we would do
   *filesystem-state archaeology* (which files/dirs existed in a past
   generation, with what ownership and confidence).
2. **M2 is a real contribution, not a re-implementation.** Parity-verified
   targeted scanning with an empirical discovery — **21 of 71 orphaned nodes
   live *outside* the current chunk map** (remnants of a removed/relocated
   chunk, owners 1–7 & 10–11, gens 1–4). That observation appears in no paper
   we found. Orphaned-chunk forensics is publishable on its own.
3. **Generation diffing / timelines (F5).** Zero published Btrfs treatment.
   The sandbox is *built* for it: a complete gen-13 backup-root state vs the
   current gen-14 state already exist on `sandbox.img`.
4. **Free-space-tree forensics (space_cache=v2, objectid 10).** Default since
   2021 (btrfs-progs 5.15 / kernel 5.15); its items (`FREE_SPACE_INFO` 0xDD,
   `FREE_SPACE_EXTENT` 0xDE, `FREE_SPACE_BITMAP` 0xDF) are unparsed by us and
   unpublished by everyone. Recently-freed blocks = deleted-data evidence.
   Wide-open niche.
5. **Confidence + provenance reporting (F6).** X-Ways has a crude
   recoverable/uncertain flag; no open-source tool has a
   Confirmed / Probable / Unattached model with per-artifact evidence
   provenance like plan §9.
6. **Hiding *detection*.** The 2026 SSRN paper (B1) documents six Btrfs hiding
   techniques in exactly the regions our slack / boot-sector / volume-slack
   extraction touches. Turning extraction features into *detection* features
   (flag non-zero reserved regions, STRING_ITEM 0xFD, chunk-array slack) is
   novel and directly relevant to F6.

### 4.1.4 What the research says to *change*, not abandon

1. **Reposition M1:** don't sell it as "anchored walking" (exists elsewhere);
   sell it as "historical state reconstruction with anchored provenance."
   Walking is plumbing; reconstruction is the contribution.
2. **Fix the six code issues** in §5 (CRC32c hardcode / `csum_type` dispatch,
   `DEV_ITEM` UUID offset, `ROOT_ITEM` reserved-region false positives,
   MIXED_GROUPS blind spot, superblock mirrors, orphan-inode 0x30 parsing).
   The CRC32c hardcode in particular silently breaks on any non-CRC32c
   filesystem.
3. **Benchmark honestly:** run our tool vs `btrfs restore`, `btrfscue`, and
   TSK `tsk_recover -e` on the same image (mirroring Kim et al. A5). Expect to
   win on *orphan-item coverage and metadata correlation*, not on raw file
   count — and that is the defensible story.
4. **Read "Beyond Carving" (A1) before M4.** If it truly covers deterministic
   reconstruction, M4 must differentiate on the orphan graph + confidence,
   not on the fact of reconstruction itself.

### 4.1.5 Verdict (one paragraph, for the team)

The plan is not useless — **the headline is.** The value is in (a) the
reconstruction engine built on the orphan-node / orphan-item graph,
(b) the publishable dataset (sandbox findings formatted per Wani & Bhat A4,
including the relocated-chunk orphans), and (c) the unclaimed niches:
free-space-tree forensics, generation diffing, log-tree analysis, and
hiding-detection. Everything else — raw walking, chunk maps, file carving —
is capability that already exists elsewhere and should be treated as plumbing
we reimplement for auditability, not as novelty.

---

## 5. Implementation Audit (code vs. spec — fix list)

Cross-checked `utils/*.py` against the official On-disk Format doc and the
2026 hiding-paper offsets.

### 5.1 🔴 Checksums: CRC32c is hardcoded

- Superblock `csum_type` at offset **0xC4** (2 bytes). Since kernel 5.5 /
  `mkfs.btrfs --csum`, valid values: **crc32c (default), xxhash, sha256,
  blake2b**.
- `utils/crc32c.py` + `btree.py:500` always verify CRC32c → on any non-CRC32c
  filesystem **every node fails and we silently find nothing**. Superblock
  checksum (bytes 0x00–0x20) is never validated either.
- **Fix:** read `csum_type`; dispatch; at minimum warn. Validate superblock
  checksum before trusting it.

### 5.2 🔴 `DEV_ITEM` UUID/FSID offset bug

- Spec: `devid@0, total@8, used@16, io_align@24, io_width@28, sector@32,
  type@36, generation@44, start_offset@52, dev_group@60, seek_speed@64,
  bandwidth@65, dev_uuid@66 (16B), fsid@82 (16B)`.
- `_parse_dev_tree_leaf()` reads `dev_uuid = dev_data[82:98]` → prints the
  **filesystem UUID** as the device UUID. Cosmetic but wrong in reports.

### 5.3 🔴 `ROOT_ITEM` "reserved region" check = false-positive machine

- `_parse_single_item()` flags non-zero bytes in `root_item[235:439]` as
  anomalies. The modern `btrfs_root_item` (439 B) uses that range for real
  fields: `flags, refs, drop_progress, level, generation_v2, uuid,
  parent_uuid, received_uuid, ctransid/otransid/stransid/rtransid,
  ctime/otime/stime/rtime, send_transid, received_*`, etc. Only trailing
  `reserved2` is genuinely unused.
- **Fix:** compute real reserved ranges from the kernel struct
  (`fs/btrfs/transaction.h`). Note the irony: the *hiding* paper (B1) says
  exactly these superblock/inode reserved areas are where data hiders plant
  bytes — so a *correct* reserved-region check is a **feature**, not a bug.

### 5.4 🔴 Mixed block groups break the targeted scan

- `build_scan_regions()` excludes DATA chunks on the assumption metadata never
  lives there. False when the **MIXED_GROUPS incompat flag** is set
  (filesystems < ~10 GiB commonly mix metadata+data in one block group). On
  `sandbox.img` it's fine (separate DATA/SYSTEM/METADATA chunks), but on small
  real disks we'd silently miss orphans.
- **Fix:** parse `incompat_flags` (SB 0xBC); auto-include DATA chunks when
  MIXED_GROUPS is set, or warn loudly.

### 5.5 🟠 Terminology collision — "orphan item" means two things

- **Us** (Bhat & Wani): item-pointer slots **beyond `nritems`** in a leaf. ✓
  implemented.
- **Kernel/Btrfs**: `BTRFS_ORPHAN_ITEM_KEY = 0x30` (48) — items marking
  **inodes with nlink=0 pending deletion** (deleted-but-open files,
  crash-recovery markers). `BTRFS_ORPHAN_OBJECTID = -5` for orphan root
  tracking in the root tree. **Not parsed** — `BTRFS_ORPHAN_ITEM_KEY` exists
  in `constants.py` but has no handler.
- **Fix:** disambiguate in docs ("Orphan-Items (Bhat & Wani)" vs "orphan inode
  items 0x30"); add a 0x30 parser — cheap, direct deleted-file signal.

### 5.6 🟠 Superblock mirrors ignored

- `constants.py` defines `SUPERBLOCK_MIRROR_1 = 0x4000000` and
  `SUPERBLOCK_MIRROR_2 = 0x4000000000`, but `superblock.py` reads only the
  primary at `0x10000`. btrfs-progs tries all mirrors + backup roots.
- **Fix:** mirror fallback (cheap; constants already exist).

### 5.7 🟡 Unparsed on-disk item types (gaps vs. the format)

| Type | Name | Why it matters |
|---|---|---|
| 0x30 | `ORPHAN_ITEM` | Deleted-inode markers — should be a headline feature (§5.5) |
| 0x0D | `INODE_EXTREF` | Hard-link names beyond INODE_REF capacity |
| 0x18 | `XATTR_ITEM` | xattrs — competitors (A2/A3) extract these; we don't |
| 0x3C/0x48 | `DIR_LOG_ITEM`/`DIR_LOG_INDEX` | Log-tree directory entries — crash-recovery artifacts (F7) |
| 0x80 | `EXTENT_CSUM` | Checksum tree — needed for F6 validation |
| 0x90/0x9C | `ROOT_BACKREF`/`ROOT_REF` | Subvolume/snapshot parentage — planned for M3 `root_links`; parse now |
| 0xB0 | `TREE_BLOCK_REF` | Metadata backrefs — core of F3 reverse-semantic mode |
| 0xB6/0xB8 | `SHARED_BLOCK_REF`/`SHARED_DATA_REF` | Snapshot shared-extent backrefs — essential; we only parse `EXTENT_DATA_REF` (0xB2) |
| 0xC0 | `BLOCK_GROUP_ITEM` | Per-block-group type flags — needed to prove §5.4 |
| 0xCC | `DEV_EXTENT` | Physical→logical reverse map — needed for chunk-map reconstruction (M4) |
| 0xDD–0xDF | `FREE_SPACE_INFO/EXTENT/BITMAP` | Free-space tree items (space_cache=v2) — **open niche, nobody has published** |
| 0xFD | `STRING_ITEM` | "Testing only" — but B1 shows it's a hiding technique; we should *detect* it |

### 5.8 🟡 Multi-device / RAID is single-stripe only

- `parse_chunk_leaf()` records one map entry per stripe with the *same logical
  range*; `translate_logical_to_physical()` returns the first match — correct
  only for single-device. Known limitation (F7), but stripe data is already
  read, so RAID1/10 translation is close; RAID0/5/6 needs per-stripe math.

### 5.9 Anti-forensic offsets we should be *checking* (from B1, full text)

The 2026 hiding paper gives exact hiding locations we currently don't inspect:

| Hiding technique | Location | Our gap |
|---|---|---|
| Pre-superblock | 0x00000–0x10000 (64 KiB before SB #1) | We extract as `boot_sector.bin` ✓ (but don't *flag* non-zero as suspicious) |
| Superblock reserved | **0xF0 bytes at SB+0x23B** | Not inspected |
| Superblock slack | **0x235 bytes at SB+0xDCB** | Not inspected (this is the "current unused" tail of the SB) |
| Chunk-array slack | **0x800 alloc, ~0x81 used → 0x77F free at SB+0x32B** | Not inspected |
| INODE_ITEM reserved | **0x20 bytes at inode_item+0x50** | `inode_parser.py` doesn't flag non-zero reserved |
| Internal-node slack | end of internal nodes | We *mine* it for residual items ✓ but don't flag hidden data |
| STRING_ITEM (0xFD) | any leaf | Not parsed at all |
| Nanosecond timestamps | inode ns fields | Not validated |
| File slack (extent level) | extent slack | We report file slack ✓ but don't flag non-zero slack bytes as evidence |

> **Opportunity:** make the tool a *hiding-detector* — a "non-zero in reserved
> region" report is exactly what B1/B3's detection side needs. Our existing
> `root_item_anomalies` counter is the seed of this feature, once the region
> check is fixed (§5.3).

---

## 6. What the Sandbox Tells Us vs. the Literature

- Our empirical findings (71 orphan nodes, 21 outside current chunk map,
  gen-13 backup root state, 10 live metadata blocks) are exactly the kind of
  data the Wani & Bhat dataset paper (A4) tabulates. We should publish ours in
  the same format — it's both validation and a contribution.
- The 21 nodes *outside* the chunk map (owners 1–7, 10–11, gens 1–4) are
  consistent with **tree relocation** (`btrfs balance`) remnants — the
  `TREE_RELOC` (-8) / `DATA_RELOC` (-9) trees and orphaned `CHUNK_ITEM`s. The
  literature doesn't cover orphaned-chunk forensics; that's a publishable
  angle, and `btrfs rescue chunk-recover` is our reference implementation for
  rebuilding the chunk map from those artifacts.

---

## 7. Recommended Action Plan (ordered)

1. **Read (this week):** A1 "Beyond Carving" (IEEE Access — get full text);
   A4 dataset paper (use as validation corpus); A5 Kim et al. (M3/M4 design +
   evaluation); B1 hiding paper (already have full text — offsets in §5.9).
2. **Fix (small, high-value):**
   - §5.1 csum_type dispatch + superblock checksum validation
   - §5.2 DEV_ITEM UUID offset
   - §5.3 ROOT_ITEM reserved ranges (compute from kernel struct) → then turn
     it into a hiding-detector
   - §5.6 superblock mirror fallback
   - §5.5 parse 0x30 orphan inode items + rename docs to disambiguate
3. **Add (medium, differentiating):**
   - §5.4 MIXED_GROUPS-aware scan regions
   - free-space-tree parsing (open niche) + orphan `FREE_SPACE_*` items
   - `SHARED_BLOCK_REF`/`SHARED_DATA_REF` snapshot backrefs (F3 core)
   - §5.9 reserved-region / slack hiding detection
4. **Benchmark:** run us vs `btrfs restore`, `btrfscue`, TSK `tsk_recover -e`
   on the same image; publish a recovery-rate table (mirrors Kim et al. A5).
5. **Publish:** sandbox dataset in Wani & Bhat (A4) format; orphaned-chunk
   forensics (relocated-chunk orphans) as a paper angle.

---

## 8. Reference Index (external links)

**Papers (must-read):**
- A1: Pandey, Jain & Shetty, *Beyond Carving: Deterministic Deleted File
  Recovery in Btrfs*, IEEE Access 2026 — ResearchGate `publication/409809779`
  (paywalled)
- A2: Chaudhary et al., *MetaRecoverX*, IJISRT 11(4) 2026 —
  doi.org/10.38124/ijisrt/26apr738
- A3: Pratyashrit et al., DMP-LNMR IMPACT-26 2026 —
  doi.org/10.65890/dmp.lnmr.IMPACT26.107
- A4: Wani & Bhat, *Dataset…*, Data in Brief 18 (2018) — PMC5998747 (open)
- A5: Kim et al., Electronics 10(18):2310 (2021) — open access
- A7: Hilgert et al., Digital Investigation 22 (2017); A8: FSI:DI 48 (2024)

**Anti-forensics:**
- B1: Toolan & Humphries, *Hiding Data in Btrfs File Systems*, SSRN 7138910
  (2026) — full text obtained
- B2: Göbel, Türr & Baier, IFIP WG 11.9 ICDF 2024 (Springer)
- B3: Schwietert & Hilgert, FSI:DI 2025 (DFRWS APAC 2025)

**Tools:**
- btrfs-progs (`btrfs restore`, `btrfs-find-root`, `btrfs check`, `btrfs
  rescue chunk-recover`) — github.com/kdave/btrfs-progs
- `btrfscue` — github.com/cblichmann/btrfscue
- `btrfs-undelete` — github.com/danthem/undelete-btrfs (Jörg Walter 2012)
- `davispuh/btrfs-data-recovery` — SQLite `btrfs-scanner` + `btrfs-fixer.rb`
- The Sleuth Kit `tsk/fs/btrfs.cpp` — sleuthkit.org
- `btrForensics` — github.com/shujianyang/btrForensics
- `msedek/btrfs_fixes`; `qdm12/btrfs-recover-scripts`
- Commercial: X-Ways Forensics, UFS Explorer, R-Studio, DMDE, DiskGenius,
  EaseUS, Reclaime, Hetman, Recoverit

**Spec:**
- On-disk Format: btrfs.readthedocs.io/en/latest/dev/On-disk-format.html
  (csum_type @ SB 0xC4; incompat_flags @ SB 0xBC incl. MIXED_GROUPS; backup
  roots @ SB 0xB2B; SB mirrors @ 0x10000/0x4000000/0x4000000000;
  CHUNK_ITEM type @ 24, num_stripes @ 44; DEV_ITEM uuid @ 66, fsid @ 82;
  STRING_ITEM 0xFD; ORPHAN_ITEM 0x30; FREE_SPACE_* 0xDD–0xDF)

---

## 9. Maintenance Notes

- Update this dossier whenever new Btrfs forensics work lands (DFRWS seasons,
  FSI:DI issues, arXiv, Kashmir group releases).
- Before starting any M1–M4 milestone, re-check A1 ("Beyond Carving") — it may
  have already been published with full text by then; do not build blind.
- Keep the audit section (§5) in sync with code changes: each fix should move
  its row to a "fixed" list with a catalog.md link.

---

## 10. Conversation Capture (what was said in chat, preserved here)

> Rule: anything discussed in chat that matters must also live in this file.
> This section logs the research conversation verbatim (condensed), with
> pointers to the sections that carry the full detail.

### 10.1 2026-08-14 — Initial research request: "explore papers/repos/journals we may have missed"

**What was delivered:** full survey of academic literature, open-source tools,
commercial products, plus a code-vs-spec audit. Stored in:
`docs/research_report.md` (first pass) and this file (expanded).

**Headline findings (all detailed above):**

- "Beyond Carving: Deterministic Deleted File Recovery in Btrfs" (IEEE Access,
  Jan 2026, Pandey/Jain/Shetty, Manipal) is the closest prior work to our
  roadmap — read it before M1–M4 (§2.1, A1).
- M1-style anchored walking already exists in `btrfs-progs` (`btrfs restore -t`,
  `btrfs-find-root`), `btrfs-undelete`, `btrfscue`, and TSK (§2.2).
- M3's SQLite catalog has a direct precedent (`davispuh/btrfs-data-recovery`
  `btrfs-scanner`) and published analogs for ext4/XFS (Kim et al. 2021;
  ExtSFR) (§2.1, §2.2).
- Competitors in 2026: MetaRecoverX (IJISRT) and Pratyashrit et al.
  (DMP-LNMR) (§2.1).
- Commercial tools already ship confidence tiers (X-Ways recoverable/uncertain)
  and Btrfs recovery (UFS Explorer, R-Studio, DMDE, etc.) (§2.3).
- Anti-forensic work is directly relevant: Toolan & Humphries SSRN 2026
  (six hiding techniques, full text obtained — offsets in §5.9), Göbel et al.
  2024, Schwietert & Hilgert 2025, Schneider et al. 2022 (§3.3).
- Code audit found six issues to fix (§5): CRC32c hardcode, `DEV_ITEM` UUID
  offset, `ROOT_ITEM` reserved-region false positives, MIXED_GROUPS blind
  spot, ignored superblock mirrors, unparsed orphan-inode 0x30 items.

### 10.2 2026-08-14 — Follow-up: "We already implemented M2 and M1, so is nothing useful left?"

**Answer (preserved in full at §4.1):**

- Correction: M1 is only partially implemented (walker done; backup-root
  parsing + anchored historical walking pending) — see §4.1.1.
- Capability ≠ research contribution: the *abilities* exist elsewhere, but the
  *research program* (reconstruction, catalog, confidence, timelines) is still
  open — §4.1.2.
- Still genuinely open: orphan-graph reconstruction engine (M4/F5),
  publishable M2 relocated-chunk-orphan discovery, Btrfs generation diffing,
  free-space-tree forensics, confidence+provenance reporting, hiding
  detection — §4.1.3.
- What to change: reposition M1 as reconstruction-with-provenance, fix the
  six code issues, benchmark honestly vs existing tools, read "Beyond Carving"
  before M4 — §4.1.4.
- Verdict: the plan is not useless — the headline is; the value is in the
  reconstruction engine, the publishable dataset, and the unclaimed niches —
  §4.1.5.

### 10.3 Key quotes worth keeping

- *"The 2026 papers do file recovery; we would do filesystem-state
  archaeology."* (§4.1.3.1)
- *"Walking is plumbing; reconstruction is the contribution."* (§4.1.4.1)
- *"The plan is not useless — the headline is."* (§4.1.5)
- *"Recently-freed blocks = deleted-data evidence"* (free-space tree, §4.1.3.4).
