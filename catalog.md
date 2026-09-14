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

## 2026-09-15 — Plan revision after research refresh

- **Branch:** `main` working tree (docs only: `plan.md`, this entry); no code
  changed.
- **Context:** folds every finding of `research.md` §10 into `plan.md`,
  following the ranked recommendations in §10.6, and turns M0 into an
  executable task list.

**What changed in the plan, and why.**
1. **Novelty claims (§1).**
   - **C3** reworded to *full-state, multi-source, per-inode lifecycle
     timelines* (backup roots + scan-discovered old roots + reconstructed
     fragments).
   - **C4** reworded to *evidence-rule-derived tiers with provenance chains
     across anchored and unanchored artifacts, csum-tree verified*.
   - **C1/C6** made explicitly btrfs-specific, with ReFS (`forefst`, Prade
     2020) and F2FS (Oh & Hwang 2025) cited as CoW analogs.
   - **C5** now cites Toolan & Humphries FSI:DI 58:302198 and SecurityRonin's
     tamper findings.
   - Why: `SecurityRonin/btrfs-forensic` ships backup-root deletion diffs and
     graded findings (§10.1 claim table, §10.2). It is added to "exists
     elsewhere" together with btrfscue v0.7 subvolume restore.
2. **Substrate (§3.5, new).**
   - Decision: **split**. We own image open, superblock + mirrors, csum
     dispatch (4 types), node-header validation, incompat/compat_ro gate,
     chunk maps and backup roots.
   - dissect.btrfs is kept only for file streams + zlib/lzo/zstd, behind a
     single `substrate/dissect_adapter.py` (the AGPL boundary), with a
     byte-equality drift test.
   - Fallback: pin 1.10.* → vendor stream module → own streams.
   - Why: dissect.btrfs 1.10 validates no csum, header field or incompat bit
     and maps only via the current chunk tree (§10.2). §3.3 (License) and
     §4 verdicts were updated to match; superblock/tree-walker/chunk-map
     code moved from DELETE to REWRITE.
3. **M1 = trust layer** (csum dispatch, header checks, incompat gate that
   refuses unknown bits and RST/ETv2/REMAP `1<<17`, mirror selection,
   tree 11) (§10.3, §10.6 item 1).
   - Branch salvage as spec/tests (§10.5):
     - defect #8, the EXTENT_ITEM objectid-vs-offset fix;
     - gen 11–14 ground truth, which replaces "gen-13 state";
     - backup roots sorted by generation;
     - the hardening backlog.
   - M1 DoD images come from `corpus/vm/`: xxhash, sha256+BGT, blake2b, bad
     node, unknown incompat, mirror damage.
4. **Corpus from M0/M1 onward (§6.2).**
   - `corpus/vm/` is the only generator, with a `corpus/manifest.tsv` per
     image.
   - New matrix axes: **discard** (none / async quick-unmount / async idle /
     sync, plus a `nodiscard` control) and **block-group tree** (off/on),
     because host mkfs 6.6.3 defaults BGT off (§10.3, §10.4).
5. **Later research items.**
   - Remap tree and RAID stripe tree are gate-refused until picked up.
   - The `CONFIG_BTRFS_EXPERIMENTAL` guest kernel is deferred (§10.3,
     §10.6 items 4 and open question b).
6. **Baselines (M7):** SecurityRonin `recover_deleted`, a TSK `develop`
   build, btrfscue v0.7 `recover`, btrfs-progs ≥ 7.1 `restore` (§10.2,
   §10.6 item 6).
7. **M9 GUI (new, Track P).**
   - A read-only local web UI (`btrfska serve`, Starlette + Jinja2 + htmx)
     over `evidence.db`, after M6 and a stable schema.
   - Datasette, Qt and Tauri/Electron were considered and rejected, with
     reasons.
8. **Test policy (§6.1).**
   - `sandbox.img` is the primary regression image (read-only; sha256
     `07ca38d4…5876418` is asserted before/after every test session).
   - Extra images only under the gitignored `images/`, via `corpus/vm/`.
   - Nothing is created outside the repo.
9. **Research method (§7, new).**
   - EXP-NNN protocol: hypothesis → method → image/scenario → exact command →
     results → threats to validity.
   - Records go to `experiments/EXP-NNN.md` plus a committed regeneration
     script.
   - Numbers enter the paper only if a script regenerates them.
   - Guest-driven measurements need ≥ 5 runs with median and range (the
     §10.4 discard table jitters by ~±2 blocks).
10. **M0 made executable** (11 ordered tasks):
    - legacy moved to `legacy/`, with its sandbox/output paths re-pointed so
      tests don't silently skip;
    - `src/btrfska` skeleton with a single read-only open site;
    - pyproject with `uv_build`, pytest, ruff;
    - AGPL LICENSE, README rewrite;
    - CI outline;
    - exact commands and acceptance checks.

    M1 is broken into 11 ordered tasks.
11. Sections renumbered: §3.5 Substrate decision added (License stays §3.3,
    so research.md §7.4's pointer still holds); §7 Research Method inserted,
    so Paper Plan → §8, Risks → §9 (SecurityRonin marked as a realised risk),
    Working Conventions → §10. research.md §10.6 references to the old §7/§8
    refer to the pre-revision numbering.

**Checks made while revising (read-only).**
- PyPI `btrfska` → HTTP 404 (no collision); the name is kept.
- `sandbox.img` sha256 `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`
  (matches §10.4). `zstd -19` compresses it to 14 963 bytes, and the piped
  round-trip reproduces the same hash with no file written. This is the basis
  for the proposed CI fixture (M0 task 9, owner sign-off).
- dissect.btrfs 1.10 metadata: `requires-python >=3.10`, zstd via
  `backports.zstd` only below 3.14.
- `recovery_output/` (8 files) is still tracked in git → untracked in M0.
- There is no `.github/` yet.
- `mmap.ACCESS_READ` write raises `TypeError` (basis for the M0 read-only
  test).

**Open items for the owner:**
- (a) approve tracking `tests/fixtures/sandbox.img.zst`;
- (b) tag `feature/m1-backup-roots` as `m1-prototype`;
- (c) gen-12 contents of `sandbox.img` are not yet recorded anywhere
  (M1 task 1 captures them).

## 2026-09-15 — Research refresh (post-reset prior-art watch)

- **Branch:** `docs/research-refresh-2026-09` (PR #5): `research.md` §10,
  this entry, `.gitignore`, and the tracked rootless image generator
  `corpus/vm/` (`fetch_vm.sh`, `build_initramfs.sh`, `init`,
  `run_scenario.sh`, `make_image.sh`, `probe_stale_metadata.py`,
  `discard_table.sh`, `scenarios/`, `README.md`)
- **Context:** first prior-art watch since the 2026-08-17 reset. Five
  areas: literature Jul–Sep 2026 (plus retries of the §4.8 papers), tools and
  libraries, on-disk format evolution to kernel 7.0, rootless test-image
  generation, and the unmerged M1 branch. Full write-up with citations:
  `research.md` §10.

**What was searched.**
- Literature: DFRWS USA 2026 (FSI:DI vol. 57, all 42 Crossref entries) and
  EU 2026 (vol. 56); DFRWS APAC 2026 (program not yet fetchable); FSI:DI
  vols. 58–59; IEEE Access, MDPI, Springer, ACM DTRAP, arXiv; OpenAlex and
  Crossref keyword sweeps (btrfs, bcachefs, ZFS/APFS/F2FS/CoW forensics);
  Semantic Scholar/OpenAlex citations of Beyond Carving; author feeds
  (Wani/Bhat, Hilgert/Schwietert, Göbel/Baier, Shon, Dewald, Toolan);
  GitHub/crates.io/PyPI for new btrfs forensic/undelete tools.
- Tools: dissect.btrfs 1.10 (installed, source read, tested read-only on
  `sandbox.img` and the new scenario images), rustutils/btrfsutils,
  btrfs-progs 6.7–7.1 changelogs, TSK, btrfscue, btrfs-fuse, WinBtrfs,
  python-btrfs, commercial changelogs.
- Format: `btrfs_tree.h` / `btrfs.h` / `fs.h` diffs v6.0 → v7.0 → v7.3-rc3,
  remap-tree patch series and commits, `discard.c` / `disk-io.c` /
  `super.c` in v7.0, and the btrfs docs Status page.

**What was found (ranked by plan impact).**
1. **`SecurityRonin/btrfs-forensic`** (Rust, Apache-2.0, created 2026-07-16):
   crc32c node/superblock checks, backup-root-divergence tamper finding,
   kernel ORPHAN_ITEM listing, and `recover_deleted()` via backup-root FS_TREE
   diff. First dedicated open-source btrfs forensic library; narrows C3/C4
   wording; add to baselines.
2. **dissect.btrfs validates nothing** (no csum of any type, no node-header
   checks, no incompat-flag gate — an unknown flag opened silently; current
   chunk map only). No functional release since 2025-12. The substrate's
   trust layer is entirely ours.
3. **Remap tree merged in kernel 7.0** (incompat bit 17, tree 13, keys
   234–236), experimental-only (`CONFIG_BTRFS_EXPERIMENTAL`, not set on the
   host kernel). It changes relocation from COW-rewrite to address
   translation. C6 stands for mainstream images, strengthens for remap-tree
   images, and gains an explicit relocation log as new evidence.
4. **Discard semantics (v7.0 source + measurement):** async discard is
   auto-enabled on discard-capable devices since 6.2, data-only block groups
   only, 120 s delay, and the queue is purged unmounted; `discard=sync` trims
   everything at commit (measured: stale metadata 355 → 31).
5. **The Sleuth Kit has experimental btrfs on `develop`** (PR #3065, merged
   2024-11-27; unreleased) — corrects research.md §2.3. **btrfscue v0.7**
   (2026-07-04) adds `recover` and unreferenced-subvolume recovery.
6. **Toolan & Humphries now published**: FSI:DI 58:302198 (Sept 2026).
   Missed CoW analogs added: Prade et al. 2020 (ReFS), Oh & Hwang 2025 (F2FS
   address-table rebuild), Bonnet 2026 ReFS thesis + `forefst` (node-slack
   recovery and recoverability verdicts on ReFS).
7. Beyond Carving: 0 citations, code repo empty, no follow-up.
8. btrfs-progs 7.1 current; block-group tree on by default since 6.19;
   `mkfs --rootdir` gained `--subvol` (6.12) and `--compress` (6.13).

**Downloaded:** none. Toolan & Humphries 2026, Plum & Dewald 2018 (now gold
OA per OpenAlex), and Oh & Hwang 2025 were all blocked by publisher bot
protection (403). `docs/` unchanged at 18 PDFs (note: `docs/*.pdf` are
tracked in git, not ignored).

**Test-image generation feasibility (measured, `research.md` §10.4).**

- **New rule (project owner):** every disk image, mount point, VM tooling and
  image scratch file lives under the gitignored `images/` folder inside the
  repo (`images/scenarios/`, `images/vm/`, `images/scratch/`, `images/mnt/`),
  never in `/tmp` or elsewhere. `images/` was added to `.gitignore`; image
  files first created in a temp directory were moved into `images/` or deleted.
  `sandbox.img` is opened read-only (sha256 `07ca38d4…` unchanged after all
  tests).
- `sudo`: password required → no loop mounts. `unshare -r`: namespace works,
  but btrfs/loop mounting is denied. lklfuse: no package, no release
  binaries, LKL is based on kernel 6.12.
- `mkfs.btrfs --rootdir` (progs 6.6.3): works rootless, but produces only a
  fresh filesystem with host `st_ino` objectids → parser fixtures only.
- **QEMU + KVM works without root:** `/dev/kvm` has a seat ACL for the user;
  QEMU 8.2.2 unpacked from `apt-get download` debs; readable kernel from
  `linux-image-unsigned-7.0.0-31-generic`; busybox-static initramfs with the
  host's btrfs modules plus `btrfs-progs`. The generator is tracked in
  `corpus/vm/` (`fetch_vm.sh` → `build_initramfs.sh` → `run_scenario.sh`
  / `make_image.sh`; outputs under `images/`) and was re-run end to end from
  an empty `images/vm/`. Scenario `s01` (xxhash, zstd, subvolume, snapshot,
  delete, 6 commits, full balance) runs in **1.43 s** real
  (`time corpus/vm/run_scenario.sh …`); image generation 6 → 38, 3/3
  chunks relocated.
- **Discard datapoint:** after the same scenario, stale-generation metadata
  blocks were 355 (no discard) = 355 (`discard=async`, TRIM not yet run)
  vs **31 (`discard=sync`)**; copies of a deleted inline string went 18 → 2.
  TRIM is the dominant evidence destroyer → make it a corpus axis.
- **Discard table reproduced** with `corpus/vm/discard_table.sh`
  (`probe_stale_metadata.py`): 367/355/18/832, 367/355/18/832,
  43/31/2/107. Column 1 is one lower than first reported because the
  committed probe skips the superblock copy. The "no discard" guest also
  auto-mounts `discard=async`; QEMU just drops its TRIMs.
- `sandbox.img` has BLOCK_GROUP_TREE (compat_ro 0xb); host mkfs 6.6.3
  images do **not** (compat_ro 0x3; use `-O block-group-tree`). The owner-11
  orphan explanation rests on `sandbox.img` alone.

**M1 branch archaeology (`research.md` §10.5).** `feature/m1-backup-roots`
(commits `d870a98`, `1d48203`, `1e9984e`, 2026-08-14; forked from `c51fe91`,
never reintegrated after the reset) adds backup-root parsing + anchored
walking + 12 tests. Verified via `git archive` extract: **49/49 tests pass**.
Confirmed that `sandbox.img` backup slots hold **gens 13, 14, 11, 12**
(correction to the 2026-08-14 entry's "gen-13 state"). Verdict: code
superseded (hand-rolled CRC32c/superblock), but salvage as spec/tests: the
EXTENT_ITEM objectid-vs-offset bug fix (still present on `main`), the gen
11–14 ground truth, sort-by-generation, and the hardening backlog. Branch
left untouched.

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
