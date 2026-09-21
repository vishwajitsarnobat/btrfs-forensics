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

## 2026-09-21 — EXP-004 addendum: the two-level root tree

- **Branch:** `docs/exp004-multilevel-addendum` (from `main` at `6c944a2`). `experiments/EXP-004.md`
  §6.6–§6.7 and §8, one sentence in paper-draft.md N5. No code change.
- **Why:** EXP-004 listed one untested case: every root tree in its images was a single leaf, so
  find-root's "highest level per generation" rule and btrfska's "nothing references it" rule could
  not disagree. `m3_wide` (M3b) has a two-level root tree.
- **Result.** The committed script, unchanged, on `m3_wide`: P1, P2 and P3 hold. btrfska indexes 25
  root-tree blocks (10 nodes, 15 leaves); 12 are states; find-root printed 11, exactly the states
  inside the current chunk map, and none of the 13 leaves a node references. Totals are now 14 of
  14 images, 240 of 240 inside, 0 of 134 outside.
- **Still untested:** a root-tree leaf whose parent node was lost. Here every parent survives.
- **Side observation.** Without a final balance only one state (the mkfs-era one) lies outside the
  current chunk map, against 13 on the s01-type images. Outside-map states come from chunk
  relocation, as EXP-004 §6.6 cautions; how often that happens in practice is still M7's question.
- **Verification:** the numbers were read from the run's `results.jsonl`; find-root ran on a
  scratch copy, which it left unchanged; `m3_wide.img` still matches its build record.

## 2026-09-21 — M3b: contents, items, tree edges and the four reverse queries (completes M3)

- **Branch:** `feature/m3b-items-and-queries` (from `main` at `2ad52ea`). New
  `src/btrfska/catalog/content.py` and `query.py`, `tests/test_catalog_content.py`,
  `corpus/vm/scenarios/wide.guest.sh`; changed `catalog/schema.py` (version 2), `build.py`, `cli.py`,
  `substrate/items.py` (extent parser), `corpus/manifest.tsv`, `docs/evidence-db.md`, `README.md`,
  plan.md M3b, `tests/test_items.py`, `tests/test_vm_images.py`.
- **Planned first** (`618526e`): contents keyed by SHA-256, keys stored readable and sortable, the
  parsed tables, the new extent parser, the definition of done.
- **Schema version 2.** `contents` (one row per distinct block content) and `nodes.content_id`;
  `items` with the raw payload; `item_problems`; `key_ptrs`; parsed tables `inodes`, `inode_refs`,
  `dir_entries`, `file_extents`, `root_items`, `extents`, `extent_backrefs`; views `content_blocks`
  and `tree_edges`. Nothing of version 1 changed meaning; a version-1 file is refused.
- **Key order.** Signed storage (M3a decision 5) keeps a u64's value but not its order: objectid −6
  sorts before 0. Every key is therefore also stored as `key_sort`, 17 big-endian bytes that SQLite
  compares bytewise, which is the btrfs key order. `trees-covering` and any `ORDER BY` on keys use
  it. A test sorts 2 000 keys, high objectids included, both ways and compares.
- **New parser: `items.extent_item` and `items.extent_ref`.** EXTENT_ITEM and METADATA_ITEM with
  inline TREE_BLOCK_REF, SHARED_BLOCK_REF, EXTENT_DATA_REF, SHARED_DATA_REF and EXTENT_OWNER_REF
  (172), and the standalone reference items. The extent's address is the key objectid; the key
  offset is its length, or the level for METADATA_ITEM: prototype defect #8 is not carried over.
  EXTENT_DATA_REF starts right after the type byte, the other kinds after an 8-byte value
  (`btrfs_extent_inline_ref_size`). Hostile input raises only `ItemError` (4 000 random payloads).
- **Reverse queries** (`catalog/query.py`, `btrfska catalog query DB …`): `parents-of` (internal
  nodes, ROOT_ITEMs and superblock slots that name a block), `owners-of` (file extents of every
  surviving generation, the extent tree's back-references, tree blocks at that address),
  `trees-covering` (leaves whose key range holds a key), `items-in-generation`.
- **New corpus image `m3_wide`.** Every tree in the existing images is a single leaf, so there was
  no key pointer anywhere (`key_ptrs` 0 on all 14) and `parents-of` could not be tested on real
  data. Scenario `wide`: 48 subvolumes, 1 500 files, deletions between commits, a read-only
  snapshot, no balance. Root tree and fs tree reach level 1; 959 key pointers, every child found.
  It is also the corpus's first history without a final balance (paper-draft.md G3).
- **Numbers** (Fedora 44, single runs, indicative): `sandbox.img` 0.34 s, 364 KiB, 53 contents for
  85 nodes, 302 items; `s01_discard_none_r1` 0.69 s, 1.2 MiB, 2 728 items; `m3_wide` 1.13 s,
  5.4 MiB, 20 018 items, 10 074 directory entries. `item_problems` is 0 on all three.
- **Verification: the definition of done.** On `sandbox.img` and four corpus images the database
  is built from a copy, **the copy is deleted**, and every valid node reached by an independent
  walk of the current and the four backup roots is then checked against the database: its items
  (slot, key, offset, size and payload bytes) or key pointers are identical; `trees-covering`
  returns the leaf, exact, for its first and last key; `parents-of` returns the walk's parent, or
  a ROOT_ITEM or superblock slot for a tree root; `items-in-generation` contains every walked
  item. On `m3_wide` this exercises real parent edges.
- **Oracle.** `extent_backrefs` of the live extent tree equal `btrfs inspect-internal dump-tree -t
  extent` reference for reference on `m3_wide` (which has SHARED_DATA_REFs from its snapshot) and
  `s01_discard_none_r1`. The tool sees only a scratch copy; the test skips without btrfs-progs.
- `uv run pytest`: 810 passed, 0 skipped. Ruff and format clean. `sandbox.img` and all 15 corpus
  images unchanged. A fresh clone of the branch built the corpus and passed with `./setup.sh`.
- **Limits.** Items beyond `nritems` and node slack are not parsed (M4). The database holds every
  item payload once per distinct content, so its size follows the image's metadata, not the image.
  Content ids and the block index are held in memory during the build.

## 2026-09-21 — M3a: the evidence database, built in one pass

- **Branch:** `feature/m3a-evidence-catalog` (from `main` at `c13b098`). New package
  `src/btrfska/catalog/` (`schema.py`, `db.py`, `build.py`, `cli.py`), `docs/evidence-db.md`,
  `tests/test_catalog.py`; changed `cli.py` (registers the subcommand), `tests/test_readonly.py`,
  `README.md`, plan.md M3.
- **Planned first.** The design went into plan.md M3 in its own commit (`6573af5`) before any code:
  one database per image, written once; one write site; the physical copy as the unit of
  evidence; parsed content stored once per distinct block; u64 stored signed; scan once; no empty
  speculative tables; the split into M3a (this entry) and M3b (items, edges, reverse queries).
- **What it does.** `btrfska catalog build IMAGE --db PATH` opens the image read-only, scans it
  once and writes: `scan_runs` (chain of custody: path, size, SHA-256 before and after, tool and
  schema version, options, gate verdict, superblock geometry, the scan summary), `superblocks`,
  `chunks` and `stripes`, `regions` (scanned and skipped, covering the image exactly once),
  `nodes` and `node_checks` (every candidate, valid or not, with all twelve checks), `known_roots`,
  `states`, `state_copies`, `state_trees`, `walk_failures`, `problems`, and the view `blocks`.
  `btrfska catalog info DB` prints a database's scan run and counts.
- **One stream.** The builder wraps the classified scan stream in a generator that writes each
  candidate and hands its record to `index_records`, so classification, old-root discovery and the
  database come from a single pass. `scan` and `roots` each rescan (M2b, "Repeated work").
- **Forensic soundness.** `catalog/db.py` is the only module that creates or opens a database. It
  refuses any path that exists (a file, a symlink, a directory), so it cannot overwrite an image or
  an earlier result, and it imports nothing from the image layer (a test asserts both). The
  read-only test now also bans `sqlite3.connect` everywhere else in `src/`; until now SQLite was a
  write path the test did not know about. Readers get `mode=ro`. A failed build removes its file; a
  database without a finished scan run is refused on opening.
- **u64.** Stored as two's-complement signed integers; `-6` is the log tree and `-9` the data
  relocation tree, as btrfs names them. `schema.s64` refuses anything that is not a u64.
- **Numbers** (Fedora 44, single runs, indicative). `sandbox.img`: 0.33 s, 135 KB, 85 nodes, 1 020
  checks, 26 known roots, 5 states, 38 state trees. The project's golden numbers are now one query
  each: 71 legacy orphans of which 21 outside the map; 20 live, 34 backup-reachable, 30
  unreferenced, 1 invalid; 52 distinct valid blocks.
- **Verification.** For `sandbox.img` and 13 corpus images (all four checksum types, the log tree,
  damaged nodes, a zeroed primary superblock, the discard trio) the database equals independent
  `scan_image` and `discover_image` runs row for row: nodes, every check, classes, states, state
  trees, known roots, walk failures and the distinct-block count. Also tested: a second build to
  the same path is refused and leaves the file byte-identical; a build that fails midway leaves
  no file; an image without a valid superblock and a refused format create no database;
  `--allow-unsupported` records `OVERRIDDEN`; every table and column of the DDL is documented in
  `docs/evidence-db.md`. `uv run pytest`: 782 passed, 0 skipped (35 new in `test_catalog.py`, 5 in
  `test_readonly.py`). Ruff and format clean. `sandbox.img` and all 14 corpus images unchanged.
- **Not done yet (M3b).** No leaf items, key pointers or tree edges, so the four reverse queries of
  the milestone's definition of done are not answerable yet. The builder holds the block index in
  memory, as `roots` does; on a very large image that is the limit, not the database.

## 2026-09-21 — EXP-004: old-root discovery against btrfs-find-root

- **Branch:** `feature/exp004-findroot` (from `main` at `1da2165`). New `experiments/EXP-004.md`,
  `experiments/exp004.py`, `tests/test_exp004.py`; results applied in paper-draft.md (N5, §5.3,
  Table T-1, traceability row 29, G5, G9), plan.md §8 and research.md §10.14. No change under `src/`.
- **Why:** the paper draft ranks this as cheap and blocking (G5, G9). `btrfs-find-root` has found
  old roots since 2011, so old-root discovery can be claimed only where find-root cannot do it.
- **Registered first.** find-root's scan range was read from its source: the metadata block groups
  of the *current* chunk map, read through that map, keeping per generation the owner-1 blocks at
  the highest level seen. Three predictions were committed in `7201bfe` before anything ran: P1,
  find-root prints exactly btrfska's root-tree blocks inside the current map; P2, nothing outside
  it; P3, every btrfska state inside the map is also in find-root's output.
- **Method.** 14 corpus images and `sandbox.img`. find-root (pinned btrfs-progs 6.6.3) ran on a
  sparse copy that was hashed before and after; btrfska ran `discover_image(full_sweep=True)` on
  the original. The script was committed (`9923af6`) and the measurement repeated on a clean tree.
- **Result: all three predictions held on 13 of 13 comparable images.** find-root printed 229 of
  229 states inside the current chunk map and 0 of 133 outside it; it printed no block btrfska had
  not indexed. On the s01-type images find-root reaches generations 17–38 (18 generations beyond
  the four backups) and btrfska adds generations 3–16, written before the final balance.
- **Consequence for the paper.** "Finds roots older than the backup roots" is not new and is not
  claimed. What is claimed is discovery **outside the current chunk map**, plus what btrfska records
  about any root (per-copy validation, completeness, failure classes), whose value this experiment
  does not measure.
- **Side results.** `m1_mirror_damage` (primary superblock zeroed): find-root cannot open it;
  btrfska reads a mirror and reports the same 35 states as on the undamaged image (one image).
  `m1_unknown_incompat`: both tools refuse. find-root left its copy unchanged on 15 of 15 images.
  The host's find-root 7.1 printed the same lines as the pinned 6.6.3 on the two images tried.
- **Not shown:** whether outside-map states yield recoverable files (E-rec); how often such states
  exist without a final balance (M7, G3); multi-level root trees, where find-root's
  highest-level rule and btrfska's no-parent rule could select different blocks inside the map.
- **Verification:** ruff and format clean; `uv run pytest` 742 passed, 0 skipped (7 new tests for
  the output parser and the P1 rule, none needing an image); `sandbox.img` and all 14 corpus
  images unchanged (`sha256sum -c`).

## 2026-09-21 — Four blocked papers read in full: two corrections and one finding

- **Branch:** `docs/four-paper-digests` (from `main` at `63793f9`). Docs only: research.md (new
  §10.13, corrections in §4.4, §4.7, §4.8, §8.3, §10.1, §10.6), paper-draft.md (§5.3, G14, §12.1
  notes, §12.2), plan.md (M4, M6, M7). No CI run: the change is under `docs/` only.
- **What was read, cover to cover:** Toolan & Humphries 2026 (hiding data in Btrfs), Plum & Dewald
  2018 (APFS recovery), Oh & Hwang 2025 (F2FS recovery), Lee et al. 2020 (ExtSFR). Until now the
  project cited all four from abstracts and second-hand descriptions.
- **Correction 1: ExtSFR is not database-backed.** research.md called it a "DB-backed
  scan-once-query-many precedent for our SQLite catalog". The paper has no database; "scalable"
  means 64-bit offsets for 1 TB images. No database-backed recovery catalog has been found in the
  literature read so far, so M3 cites no precedent and stays an engineering choice.
- **Correction 2: ExtSFR verifies by hash.** research.md said Kim et al. 2021 criticised it for
  omitting hash verification. ExtSFR counts MD5-exact files; Kim et al.'s objection (their p. 3)
  is that it predates Ext4 journal checksum v3.
- **Finding: the published superblock "reserved area" is a pre-5.0 layout.** Toolan & Humphries
  give 0xF0 bytes at 0x23B. Against our v7.0 tables (`substrate/ondisk.py`, asserted by
  `tests/test_ondisk.py`), 0x23B–0x263 hold `metadata_uuid`, `nr_global_roots`, `remap_root`,
  `remap_root_generation` and `remap_root_level`; only the 199 bytes at 0x264–0x32A are reserved.
  Every other offset in the paper agrees with our tables. For the M6 detector, reserved ranges
  must be derived from the feature flags.
- **What else the papers change:** Toolan & Humphries tested TSK 4.14, `btrfs check` and `dmesg`
  against six techniques and none detected any; they name a detection toolkit as future work
  (supports C5). They report that internal-node slack does not survive copy-on-write, which is
  UNVERIFIED against the kernel and is now an M4 task before slack is claimed as a recovery source
  (C1). Plum & Dewald measure recovery over every file *state*, not only deleted files, which is the
  right metric for timelines and is added to M7 with ExtSFR's three counts per tool. Oh & Hwang
  rebuild an address table from carved metadata, the analog of C6; they keep only the newest
  version of a block and evaluate the best case (unmounted right after deletion).
- **Verification:** every number quoted in §10.13 was read from the paper's text or tables; the
  offset comparison was run against `ondisk.SUPERBLOCK` and `ondisk.INODE_ITEM`; links resolve.
- **Still missing:** Hilgert's PhD thesis, Vaheed Ali et al. 2025, Hraiz 2016 (research.md §4.8).

## 2026-09-21 — CONTRIBUTING.md: the working rules in one place

- **Branch:** `docs/contributing-rules` (from `main` at `b569d4c`). New `CONTRIBUTING.md`; a link
  in `README.md`; plan.md §10 now points to it. No code change.
- **Why:** the rules the project runs on were spread over plan.md §6, §7 and §10, several catalog
  entries and decisions taken while the repository was set up on 2026-09-20 and 2026-09-21. Three
  people and several parallel work sessions need one short page that says what is not negotiable.
- **What it fixes in writing:** (1) one feature, one branch, one pull request: plan, implement in
  small commits, test, catalog entry, describe for a reader who was not there, review the whole
  diff and wait for CI, merge, delete the branch; when to ask the maintainer; (2) plain human
  writing and no tool attribution anywhere; (3) the definition of done, including a from-scratch
  `./setup.sh` run when a build script changes; (4) anyone can rebuild everything on any Linux
  distribution, no root, nothing outside the repository, everything that decides on-disk bytes
  pinned by hash; (5) read-only evidence, numbers only from committed scripts, guest runs never
  quoted as constants, tests assert claims relative to the image; (6) `main` is never
  force-pushed again, where documents and papers live, what is never deleted; (7) the project
  spends nothing.
- **Verification:** links resolve; ruff clean; `uv run pytest` 735 passed.

## 2026-09-21 — History rewrite: two commit messages corrected, cited hashes remapped

- **Branch:** `docs/remap-commit-hashes` (from `main` at `d70ff99`). Docs and experiment records
  only; new `docs/commit-hash-map-2026-09-21.tsv`.
- **What happened.** Two commits of 2026-08-14 ("M2: structure-directed targeted orphan scan" and
  "docs: add development catalog and link it from plan/readme") ended with two tool-attribution
  trailer lines that credited a third party as co-author, and GitHub listed that account as a
  contributor. The lines were removed from both messages with `git filter-branch --msg-filter`, and
  `main`, `feature/m1-backup-roots` and the tag `m1-prototype` were force-pushed. Ten branches that
  were already merged into `main` were deleted, because they still held the old commits.
- **Nothing but those two messages changed.** Checked before the push, on a fresh clone: for all
  158 commits of `main` and all 22 of `feature/m1-backup-roots`, the tree, author, committer, both
  dates and the subject are identical before and after; exactly two message bodies differ; the tip
  tree of the rewritten `main` equals the tree GitHub had. No file content, at any commit, changed.
- **Consequence: commit hashes.** A commit's hash covers its message and its parents, so the two
  edited commits and every commit after the first of them have new hashes: 146 in total. The 15
  commits before it keep theirs. `main` went from `0ae9978` to `d70ff99`, and `m1-prototype` now
  points at `26715ba` (was `1e9984e`).
- **Remap.** 160 citations of those commits in this catalog (134), `paper-draft.md`, `research.md`,
  `plan.md` and the EXP-000 to EXP-003 records were replaced by the new hash at the same length.
  That includes the `git_commit:` lines of the experiments' environment records: each now names
  the commit with the same tree and the same subject as the one that was measured. The full
  old-to-new map is tracked in `docs/commit-hash-map-2026-09-21.tsv`. The old hashes still appear
  on the pages of pull requests #1 to #18, which GitHub does not rewrite.
- **Verification.** Apart from this entry and the map file, which name old hashes on purpose, no
  token in `docs/`, `experiments/`, `corpus/`, `tests/`, `src/` or `README.md` is a prefix of a
  rewritten commit's old hash; all 118 commit hashes cited before the remap resolve to a commit. `uv run pytest` and ruff are unaffected (no
  code change).
- **For anyone with an older clone:** re-clone, or `git fetch && git reset --hard origin/main` on a
  clean working tree. A branch made before 2026-09-21 must be rebased onto the new `main`.

## 2026-09-21 — CI guards: time limits, cancelled superseded runs, no run for docs-only changes

- **Branch:** `chore/ci-guards` (from `main` at `8bae6f9`). `.github/workflows/ci.yml`, a note in
  `README.md`. No code or test change.
- **Why:** the project uses only GitHub's free allowance. The `corpus` job added in the previous
  entry boots QEMU guests, and a GitHub job that hangs runs for six hours by default.
- **Cost, as checked on 2026-09-21** (GitHub Docs, "GitHub Actions billing"): Actions is free for
  public repositories on standard GitHub-hosted runners, which is what both jobs use
  (`ubuntu-24.04`), so the 34 runs so far consumed no paid minutes. A private repository on the
  Free plan would get 2,000 minutes and 500 MB of artifact storage a month, and 10 GB of cache per
  repository; without a payment method, usage is blocked when the quota is used up, never billed.
  The repository's caches (uv and the pinned guest packages) hold 466 MiB.
- **Guards.** `timeout-minutes` 10 for `test` (it takes about 1 minute) and 15 for `corpus` (about
  2.5); a `concurrency` group per ref with `cancel-in-progress`, so pushing again to a pull request
  stops the run it supersedes; `paths-ignore: docs/**` on both triggers, so a change that touches
  only `docs/` (research notes, the paper draft, the papers) starts no run. No test or script reads
  anything under `docs/`; `README.md` is read by `tests/test_cli.py` and is not ignored.
- **Verification:** the workflow parses and both jobs pass on the pull request.

## 2026-09-21 — One-command setup: recipe manifest, corpus/build.py, setup.sh, corpus CI job

- **Branch:** `feature/one-command-corpus` (from `main` at `27820cf`). New: `setup.sh`,
  `corpus/build.py`, `tests/test_corpus_build.py`. Changed: `corpus/manifest.tsv`,
  `tests/test_vm_images.py`, `tests/test_discard_trio.py`, `.github/workflows/ci.yml`, `README.md`,
  `corpus/vm/README.md`, plan.md §6.1–§6.2. No change under `src/`.
- **Why:** the goal is that anyone can clone the repository and reach a complete, tested checkout
  in a few minutes by running the scripts provided. Two things stood in the way. Building the
  corpus meant copying fourteen commands out of the manifest by hand, in the right order. And the
  manifest recorded the sha256 of one particular build of each image, which no one can reproduce:
  every mkfs draws a new filesystem UUID, so twelve tests failed on any rebuilt corpus (previous
  entry). The first host's images no longer exist, so those hashes described nothing obtainable.

**What changed.**
- `corpus/manifest.tsv` is now a recipe: `name`, `command`, `mkfs`, `guest_kernel`, `note`. The
  `sha256` column is gone, `host_mkfs` became `mkfs` (the pinned 6.6.3), and every `command` is
  purely executable (the prose that followed the three discard commands moved to `note`). Rows are
  in build order.
- `corpus/build.py` checks the host (each missing tool is named with the package that provides it
  on Debian/Ubuntu, Fedora, Arch and openSUSE; `/dev/kvm` access is checked), fetches the pinned
  bundle, builds the initramfs and runs every row's command. It skips images that exist
  (`--force` rebuilds, names select rows, `--check` only checks the host) and records the sha256 of
  what it built in the gitignored `images/scenarios/SHA256SUMS` (`sha256sum -c` format).
- The two hash tests now compare each local image with that local record
  (`test_local_image_is_unchanged_since_it_was_built`, `test_trio_image_is_unchanged_since_it_was_built`)
  and skip when an image has no record. Their purpose is kept: an image modified after it was built
  fails. The EXP-000/001/002 records still cite the hashes of the instances they measured; those
  are evidence of what was measured, not something to rebuild.
- `setup.sh`: `uv sync --locked`, restore and verify `sandbox.img`, `corpus/build.py`, ruff, the
  whole test suite. `--no-corpus` skips the images for hosts without KVM.
- CI gets a second job, `corpus`, that runs `./setup.sh` on a clean `ubuntu-24.04` runner with KVM
  enabled (the pinned `.deb` files are cached by the hash of `guest.lock`) and fails if any vm test
  was skipped for a missing image. plan.md §6.1 said vm tests were local only; it is revised, and
  §6.2 gains the reproducibility target every later scenario and baseline tool must keep.

**Finding: the first build on a second host class changed the numbers, as plan.md §7 predicts.**
- On the GitHub-hosted runner (nested KVM, Ubuntu's QEMU 8.2.2) the whole corpus built and 729 of
  734 tests passed. The five failures were all in `tests/test_discard_trio.py`: the guest made one
  more transaction commit than on either development host, so the s01 images ended at generation
  39, not 38, and the no-discard and async images held 363/351/16/824 blocks
  (`probe_stale_metadata.py` columns), not 367/355/18/832. The sync image's class counts were
  unchanged (43/38/22/0/16), only its backup generations moved up by one. EXP-000 had already
  seen 365/353/18/828 once in 15 runs on the first host.
- Those tests asserted EXP-002's numbers as constants, which was sound while three kept images
  were the test subjects, and is not once everyone rebuilds them. They now assert the claims
  themselves, relative to each image's own superblock generation G and its own probe output:
  btrfska's full sweep covers exactly the blocks the probe counts; the classes partition the valid
  candidates; without trims the four backup states G…G−3 are complete and at least 20 older states
  survive (EXP-002 measured 31), all complete except the mkfs-era generation-3 leaf; under
  `discard=sync` fewer than 20 % of the stale blocks survive, nothing is reached from an older
  backup only, and exactly the root, extent, chunk and dev roots of backups G−3…G−1 read as zeros
  (12 walks). The measured numbers stay in EXP-000 and EXP-002, where N and the spread are stated.
- Consequence for the paper: a count from one guest run is host-dependent. EXP-000's medians held
  on two x86-64 hosts with different QEMU versions (8.2.2, 10.2.2) and did not hold on a slower,
  nested-virtualisation runner. Any table built from guest runs should name the host class, and a
  cross-host repetition belongs in the M7 experiment set.

**Verification** (Fedora 44, QEMU 10.2.2, NVMe; single runs, timings indicative).
- Corpus from an empty `images/` folder, 190 MB download included: 14 images in 92 s; each
  guest-driven image takes 1.0–1.2 s and each derived image about 2.1 s.
- **Fresh clone of the branch into an empty folder, then `./setup.sh`: 14 images built, 734 passed,
  0 skipped, 143 s in total.**
- A second `corpus/build.py` run builds nothing (14 already present). Flipping one byte of
  `m1_zlib.img` makes its unchanged-since-built test fail; restoring the image makes
  `sha256sum -c SHA256SUMS` pass for all 14.
- `tests/test_corpus_build.py` (7 tests, no image or VM needed): the manifest has exactly the five
  columns and no 64-hex string, every command runs a tracked script and names its own image, a
  derived image comes after its source, the build record round-trips in `sha256sum` format, the
  host check names the missing tool, and an unknown image name is refused before anything runs.
- Ruff and format clean; `sh -n` clean on `setup.sh` and every corpus script; `sandbox.img` sha256
  unchanged.

## 2026-09-21 — corpus/vm runs on any Linux distribution

- **Branch:** `feature/portable-corpus-vm` (from `main` at `713abfc`). Changes under `corpus/vm/`
  and `experiments/env.sh`, a note in research.md §10.4. No change under `src/` or `tests/`.
- **Why:** development moved to a new machine (Fedora 44, kernel 7.2.5, QEMU 10.2.2, btrfs-progs
  7.1) and none of the first host's images survive. `corpus/vm/fetch_vm.sh` needed `apt-get` and
  `dpkg`, so no image could be generated. The generator must work for anyone who clones the
  repository, on whatever distribution they run.

**corpus/vm no longer depends on the host distribution.**
- The old pipeline was tied to an Ubuntu host in three ways: packages came from `apt-get download`
  and `dpkg -x`; QEMU 8.2.2 was unpacked from Ubuntu packages and ran against host libraries; and
  the guest's `btrfs` binary got its shared libraries from the host through `ldd` ("same distro").
  It also formatted images with whatever `mkfs.btrfs` the host had. None of this was a design
  choice: `apt-get download` was the rootless way to get the tools on the first host (research.md
  §10.4).
- Now: `corpus/vm/guest.lock` pins twelve `.deb` files by SHA-256 (values from Ubuntu's signed
  `Packages` indices, 2026-09-20): guest kernel `7.0.0-31.31~24.04.1` and its modules,
  `busybox-static`, `btrfs-progs 6.6.3-1.1build2` (the build the EXP-000/001/003 environment
  records name) and the eight library packages in the closure of `btrfs` and `mkfs.btrfs`
  (`readelf -d`). `fetch_vm.sh` uses `curl`, `sha256sum`, `ar` and `tar`, against a fixed
  `snapshot.ubuntu.com` timestamp. `build_initramfs.sh` takes libraries and modules from the bundle
  only. `run_scenario.sh` uses the host's `qemu-system-x86_64` (`QEMU` overrides). The new
  `pinned.sh` runs a bundle tool on the host through the bundle's loader, and `make_image.sh`
  formats with it (`MKFS=mkfs.btrfs` selects the host's). `experiments/env.sh` reports host QEMU,
  the pinned mkfs and guest versions and the lock file's sha256.
- The guest stays Ubuntu's stock kernel on purpose: it is the experimental variable and must be
  pinned. Only the host became irrelevant.

**Verification** (Fedora 44, host QEMU 10.2.2; one run, plan.md §7 applies to any number quoted).
- `LD_DEBUG=libs` on the pinned `btrfs`: every library initialised comes from `images/vm/tools`.
  A first version passed only `usr/lib` to the loader, and `liblzo2` (packaged under `/lib`) was
  then silently taken from the host; both library directories are passed now.
- A fresh pinned-mkfs image has generation 6 and incompat 0x341, as research.md §10.4 records.
- `corpus/vm/discard_table.sh`, twice: none 367 355 18 832; async 367 355 18 832; sync 43 31 2 107.
  These equal the EXP-000 medians (N = 15, QEMU 8.2.2, Ubuntu 24.04 base host) in every column.
  This is a spot check on a new host, not a new EXP record.
- All 14 manifest images regenerated, the five derived ones with the manifest's hard-coded
  `flip-byte` offsets. `uv run pytest -m vm`: 59 passed, 12 failed. The 12 are exactly the
  manifest-sha256 assertions (`test_local_image_matches_manifest_sha256` ×11 and
  `test_manifest_lists_the_discard_trio`): a regenerated image has a new filesystem UUID, so its
  hash cannot equal the recorded instance's. `corpus/manifest.tsv` is not changed here: the first
  host's images no longer exist, so the recorded hashes describe instances nobody can rebuild (the
  EXP-001/002 records cite them).
- Ruff and format clean; `sh -n` clean on every `corpus/vm` script and on `experiments/env.sh`.
  `uv run pytest` with all images present: 712 passed, 12 failed (the 12 manifest-sha256
  assertions above), 0 skipped; `sandbox.img` sha256 unchanged. The manifest design is changed in
  the next entry so that a rebuilt corpus passes.

## 2026-09-21 — Repository layout and paper library

- **Branch:** `chore/repo-structure` (from `main` at `0cadef8`). No change under `src/`, `tests/`,
  `corpus/` or `experiments/`.
- **Why:** the repository root held four large documents next to the code, `docs/` held PDFs under
  publisher download names, and four requested papers had arrived. Anyone opening the repository
  should find the code at the root and everything to read in one place.

**Layout.** Entries below this one keep the old paths, as written at the time.
- `plan.md`, `research.md`, `catalog.md` and `paper-draft.md` moved from the root to `docs/`. The
  basenames are unchanged, so prose citations such as "plan.md §5" still hold. `README.md` stays at
  the root: GitHub shows it there and `tests/test_cli.py` reads it.
- `recovery_output/` (8 files of legacy prototype output) removed from the index. The M0 entry
  records this as done, but no commit ever did it: the files were still tracked at `0cadef8`. They
  are regenerable with `legacy/main.py` and stay gitignored.
- `diagrams/` (five prototype-era PNGs) deleted. `paper-draft.md` §9 already ruled out reusing them:
  `arch.png` and `future.png` show the abandoned brute-force pipeline and `leaf_layout.png` draws a
  leaf as a flowchart. They remain in the history (`160233e`).
- `major-project.jpg` (the signed project proposal) stays at the root.

**Paper library.** All PDFs moved to `docs/papers/` and named
`firstauthor[_secondauthor]_short_topic_year.pdf`. A new index, `docs/papers/README.md`, lists every
file with its citation, DOI, BibTeX key and open-access status, grouped by theme. Renames:

  | Old name (in `docs/`) | New name (in `docs/papers/`) |
  |---|---|
  | `00-An analysis of anti-forensic capabilities of B-tree file system _Btrfs_.pdf` | `wani_antiforensic_btrfs_2020.pdf` |
  | `Beyond_Carving_Deterministic_Deleted_File_Recovery.pdf` | `pandey_beyond_carving_2026.pdf` |
  | `btrfs-journal.pdf` | `rodeh_btrfs_linux_btree_filesystem_2013.pdf` |
  | `dmpedia_xfs_btrfs_recovery_2026.pdf` | `pratyashrit_dmpedia_xfs_btrfs_recovery_2026.pdf` |
  | `Forensic analysis of B-tree file system (Btrfs) - 1-s2.0-S1742287618302135-main.pdf` | `bhat_wani_forensic_analysis_btrfs_2018.pdf` |
  | `hilgert_dfrws_2017_pooled_storage.pdf` | `hilgert_pooled_storage_tsk_slides_2017.pdf` |
  | `hilgert_mind_the_slack_2026.pdf` (first author is Schwietert) | `schwietert_hilgert_mind_the_slack_2026.pdf` |
  | `metarecoverx_2026.pdf` | `chaudhary_metarecoverx_2026.pdf` |
  | `paper_forensic_analysis_of_multiple_device_btrfs_configurations_using_the_sleuth_kit.pdf` | `hilgert_multidevice_btrfs_tsk_2018.pdf` |
  | `wani_bhat_dib_2018.pdf` | `wani_bhat_btrfs_dataset_2018.pdf` |


  The other eight PDFs kept their names. References in `research.md` and `paper-draft.md` follow the
  new names.
- **Four papers added** (the blocked list of research.md §4.8 and paper-draft.md G14):
  `toolan_humphries_hiding_data_btrfs_2026.pdf`, `plum_dewald_apfs_recovery_2018.pdf`,
  `oh_hwang_f2fs_recovery_2025.pdf` and `lee_extsfr_2020.pdf`. **They are filed, not yet read:** the
  UNVERIFIED notes on the research.md §8.3 offsets and the "Full text not obtained" BibTeX notes
  still stand until each paper is digested into research.md §4.
- **Still missing:** Hilgert's PhD thesis (open access, but `bonndoc.ulb.uni-bonn.de` timed out again
  on 2026-09-20), Vaheed Ali et al. 2025 (closed access, no repository copy per OpenAlex) and Hraiz
  2016 (ProQuest). None blocks a milestone.

**Verification.** `uv run ruff check .` and `uv run ruff format --check .` clean; every relative
link in `README.md` and `docs/*.md` resolves; `uv run pytest` passes with `sandbox.img` present
(vm-marked tests skip where no image has been generated); `sandbox.img` sha256 unchanged.

## 2026-09-15 — Checkpoint: paper draft starter

- **Branch:** `docs/paper-draft` (from `main` at `8034a75`). Docs only: `paper-draft.md` (new), this
  entry, a pointer in `README.md`. No code, experiment record or research note changed. Not pushed.
- **Why:** the project stops at M2 to start the research paper. The draft starter lets the authors
  write from the evidence that exists without over-claiming.

**What `paper-draft.md` contains.**
- Status banner (what M0–M2 support, what needs M3–M7); target venue (DFRWS/FSI:DI, fallback IEEE
  Access; deadlines and limits marked "check"); five title options; abstract A for the current
  evidence and a clearly labelled aspirational abstract B with placeholders.
- Contribution status: C1–C7 plus eleven contributions that emerged (N1–N11). Only C6 and C7 among
  the planned claims are partially supported; C1–C5 are not yet.
- Section outline with prose seeds (introduction to conclusion), the as-built method, research
  questions RQ1–RQ5.
- Evaluation tables copied verbatim from EXP-000, EXP-001 (with its counting footnote), EXP-002
  (coverage agreement, slot references vs distinct blocks, candidate root-tree blocks, balance
  caveat) and EXP-003 (image vs allocated bytes, density sweep), with the environment summary and
  regenerating commands.
- Thirteen findings with confidence notes, a 28-row claim → evidence traceability table, a figures
  plan (the prototype-era `diagrams/arch.png` is not the built architecture), a ranked gap list
  (G1–G14) with the minimum experiment set, consolidated threats to validity, BibTeX with `TODO` for
  every missing field, the blocked papers, and a terminology guide.

**Inconsistencies found (Appendix A of the draft, 13 items; no doc was edited to resolve them).**
- **Beyond Carving is not backup-root-bounded.** plan.md §1 (C3), §8 and research.md §10.10–§10.11
  say it is; its Algorithm 3 (`docs/Beyond_Carving_…pdf`, historical root tree discovery) scans the
  chunk-mapped tree regions for owner-1 blocks and keeps the highest level per generation, as
  research.md §4.1 records. This also affects the M7 beyond-4-generations test design and
  research.md §10.7's attribution of `backup_fs_root` diffing.
- The M1c catalog entry has no `##` heading (its text follows the M2a entry).
- EXP-002 §6.3 "8–13 blocks" vs research.md §10.11 "8–14 blocks" per surviving state.
- plan.md §1 "21/71 outside the chunk map" (prototype definition) vs btrfska's 20 valid orphans.
- EXP-003 §8 "slowest cell 501.0" is the slowest run of a cell whose median is 512.2.
- Smaller items: stale catalog "Assets" section, Bhat & Wani size bands (research.md vs the paper's
  abstract), the SSRN vs FSI:DI Toolan & Humphries citation, "Mind the slack?" author order,
  dissect.btrfs still named a foundation in research.md §3, "seven" vs nine gaps.

**Paper-readiness notes recorded in the draft (plan.md §7).** The hostile-walk timings and memory
peaks in the M2a/M2b review fixes come from scripts under the gitignored `images/scratch/` and cannot
be quoted until committed; the dissect.btrfs "validates nothing" observations have no committed
script; the EXP-003 density sweep ran on a tree with 16 uncommitted files; the LZO harness,
per-image scan and roots tables and oracle results should become EXP records.

**Verification.** Every table in the draft was copied from the committed record it cites. Two DOIs
not recorded in research.md (Hilgert et al. 2018, 2024) were read from the PDFs in `docs/` and are
marked "verify". Scratch files (`pdftotext` output) are under `images/scratch/paper/`.
`sandbox.img` was only read to confirm its sha256 (`07ca38d4…5876418`, unchanged). Section 6 of the
draft was checked by script: every result-table row appears verbatim in its source record; only the
environment summary table is composed from the env records.

**Review round (fact-check, 2026-09-15).** A fact-checking review approved the draft with fixes, all
applied on `docs/paper-draft` (PR #14). Docs only; no code changed.
- **Numbers and claims in `paper-draft.md`.**
  - F4: 13, not 14, states lie only outside the current chunk map (generations 3, 6, 7 ×2, 8–16;
    EXP-002 §6.3).
  - C7 is qualified as the first public *image* corpus with per-file ground truth across the
    checksum, compression and discard axes, and cites Wani & Bhat 2018 and Schwietert & Hilgert 2025.
  - N1 drops the dissect.btrfs comparison from its heading and the unsourced "most-used", and is
    now Partially supported (no committed comparison script).
  - Abstract A no longer says "scans the whole device": the targeted default skips agreeing DATA
    chunks.
  - Results identical across runs are reported as "identical in 15/15 runs" next to the medians.
- **Btrfs facts.**
  - Free-space-tree item keys are 198–200 (0xC6–0xC8), per kernel v7.0
    `include/uapi/linux/btrfs_tree.h:266,272,280` (read on GitHub, not copied). Fixed in the draft,
    research.md §6 and §8.1, and plan.md M6; no other `0xDD`–`0xDF` remains in the docs.
  - COW: only a block already written to disk (WRITTEN) is copied again; a dirty unwritten block is
    modified in place (ctree.c:621-625).
  - The DISCARD_SYNC citation is extent-tree.c:2997-3005, fixed in the draft, research.md §10.11
    and EXP-002 §6.4.
- **Method vs code** (read in `src/btrfska/scan/roots.py`).
  - ROOT_ITEMs resolve by (bytenr, generation, level) and an acceptable owner, with no first key
    (the walk of a named tree starts without one, l.709). Also fixed in research.md §10.11.
  - `roots` emits `not_scanned`, `changed` and `unchecked`.
  - `substrate/fs.py` and `substrate/items.py` are now listed.
  - `uv run pytest --collect-only -q` collects 724 tests, of which 37 are legacy tests.
- **Beyond Carving positioning corrected at its source.** Its Algorithm 3 scans chunk-mapped tree
  regions (§VI.E.1), independently of the superblock root pointer (§X.G). It reads the first stripe
  only (§X.H.7) and describes no tree-block checksum validation. Corrected in plan.md §1, the M7
  beyond-4-generations test (redesigned into (a) inside and (b) only outside the current chunk map
  or only unreferenced) and §8; research.md §10.1, §10.2, §10.6, §10.7, §10.10 and §10.11. The dated
  note is research.md §10.12.
- **SecurityRonin** `recover_deleted` (source at `e6cd73f`) is described as backup-root-bounded
  (all four slots, FS tree 5 only), stripe 0, superblock crc32c only, node crc32c not a gate.
- **BibTeX checked against Crossref/doi.org.**
  - `rodeh2008btrees`: DOI 10.1145/1326542.1326544, Article 2 (from Semantic Scholar; Crossref
    carries no article number).
  - `rodeh2013btrfs`: Article 9 (from the ACM PDF in `docs/`).
  - `goebel2024generating` renamed `goebel2025generating`, year 2025.
  - `toolan2025book`: "The Btrfs File System", pp. 303–352, Fergus Toolan.
  - `hilgert2017pooled`: DOI 10.1016/j.diin.2017.06.003.
  - `schwietert2026slack`: FSI:DI 57:302123, DOI 10.1016/j.fsidi.2026.302123.
  - `lee2019extsfr` renamed `lee2020extsfr`, with the full title and year 2020.
  - Toolan and Humphries first names added (Fergus, Georgina).
  - The same errors are fixed in research.md §4.3–§4.8 and §10.1.
- **Starter improvements.**
  - G5 and G9 promoted to the top of the gap list.
  - New near-term experiment E-findroot: `btrfs-find-root -a` per generation against
    `btrfska roots` on the existing images.
  - The minimum experiment set gains:
    - real-SSD discard;
    - no-balance, aged and ≥ 8 GiB images;
    - the discovery false-positive rate on forged images;
    - baseline runtimes;
    - RAID profiles;
    - a corpus-size and operations-log statement.
  - The same experiments are in plan.md §8 "Paper-readiness experiments".
- **Catalog.** The missing `## 2026-09-15 — M1c: …` heading is added above the unchanged M1c
  entry (Appendix A item 4 resolved). Appendix A items 1–4 and 11 are marked resolved.
- **Scratch.** Kernel headers, SecurityRonin sources and the edit script are under the gitignored
  `images/scratch/` (`kernel/`, `secronin/`, `paper/`).

## 2026-09-15 — M2b: old-root discovery, discard experiments (EXP-000, EXP-002), M2 closeout

- **Branch:** `feature/m2b-old-roots-discard` (from `main` at `0e27f52`). This is the second of
  two M2 PRs. It covers old-root discovery, the EXP-000 backfill (plan.md §7), the discard trio
  (EXP-002) and the M2 closeout. Not pushed.
- **Commits:**
  - `03475b2` Add old-root discovery: candidate roots per owner and generation, root-tree states with completeness, reuse told apart from damage
  - `c095b8f` Add btrfska roots with a documented JSON schema and report walk failures by class in the scan summary
  - `1c13b22` Name repeated discard-table runs and add the EXP-000 and EXP-002 scripts
  - `ef88e4d` Add the representative discard-trio images to the manifest, with vm tests for probe agreement and discovery per discard mode
  - `ffd4672` Record EXP-000 (discard table, N = 15) and EXP-002 (probe agreement on 48 images, surviving history per discard mode)
  - `4a66ad8` Record M2b discovery and discard findings in research notes and close M2 in the plan and README
  - this catalog entry (the commit after `4a66ad8`)
  - review fixes (see "Review fixes" at the end of this entry): `58e21c4`, `3c9219b`, `91f355f`,
    `8daf05f`, `06db7de`, `434811c` and the commit that adds that subsection

**What was done.**
- **Tests first.**
  - `tests/test_scan_roots.py` failed at collection (`ModuleNotFoundError: No module named
    'btrfska.scan.roots'`, `images/scratch/m2b/verify/roots_tests_before.txt`).
  - The five new CLI tests failed with `SystemExit: 2` (no `roots` command), IndexError (no README
    section) and a missing summary line.
  - The manifest test of the trio failed with `KeyError: 's01_discard_none_r1'`.
  - One expectation was corrected after the first run (Deviations).
1. **Failure classes** (`substrate/node.py`). `node_failure(node, expect)` says why a referenced
   block cannot be used. Per copy, in precedence order:
   - `reused`: every integrity check passes (csum, fsid, chunk_tree_uuid, nritems, written,
     layout, level below 8), a linkage check (bytenr, level, owner, parent_generation, first_key)
     fails, and the copy is newer than the referrer expects;
   - `mismatch`: the same, but not newer;
   - `corrupt`: the fsid matches and an integrity check fails;
   - `overwritten`: no fsid;
   - `zeroed`: all zero bytes;
   - `unreadable`, and `unmapped` (no copies).

   `NodeCopy` gains its header generation, owner, level and a zero flag, and `Visit` gains the
   `Expect` it was read with. `owner_ok` is now public.
2. **Walk failures** (`scan/classify.py`). `walk_root_set` records (tree id, logical, class) per
   invalid node, and `Reachability.walk_failures` adds the root set. The scan summary gains
   `walk failures: current N; backup roots M (class n, …)` and the dict key `walk_failures`. The
   M2a review asked for exactly this: reuse under old backup roots reported apart from damage.
3. **Old-root discovery** (`scan/roots.py`).
   - `index_records` builds a `BlockIndex`: numpy columns (bytenr, generation, level, owner,
     physical) of every valid candidate, one row per physical copy. Log blocks (owner −6) whose
     only failed check is a generation of exactly superblock + 1 are indexed; other failing log
     candidates count as `log_rejected`. Owner-12 and owner-13 candidates are kept raw, unparsed
     (at most 256).
   - `discover` produces:
     - groups per (owner, generation, level);
     - candidate roots;
     - root-tree states with their trees, completeness, chunk root and a chunk-item placement
       check;
     - rediscovery of every superblock and backup root (`known_roots`);
     - log generations.
   - `discover_image` runs the scan plan, the walks and discovery.
   - 13 tests: the failure classes on synthetic blocks; a synthetic four-state history covering
     groups, states, completeness, rediscovery, inferred chunk roots and placement under
     historical chunk items; backup-walk classes; the index log rule and raw owners; the
     adversarial tests below; sandbox and M1 ground truth; `m2_logtree`.
4. **`btrfska roots IMAGE [--full-sweep] [--workers N] [--json] [--allow-unsupported]`.**
   - The text summary goes to stdout, or to stderr with `--json`.
   - The JSON records are `rediscovery`, `state`, `group`, `log`, `raw_block` and `walk_failure`.
   - README.md gains "`btrfska roots` output"; `test_readme_documents_every_roots_key` checks
     every key and value.
5. **Corpus scripts.** `corpus/vm/discard_table.sh` takes `RUN=<n>` and names images
   `s01_discard_<row>_r<n>`; the three scenario scripts take `NAME`. The defaults are unchanged.
6. **EXP-000** (`experiments/exp000.py`, `experiments/EXP-000.md`) and **EXP-002**
   (`experiments/exp002.py`, `experiments/EXP-002.md`).
7. **Corpus.** `corpus/manifest.tsv` gains `s01_discard_{none,async,sync}_r1`, and
   `tests/test_discard_trio.py` (vm, 7 tests) checks agreement, classes and discovery on them.
8. **Docs.**
   - research.md §10.4 gains the EXP-000 note, and §10.11 is new;
   - plan.md M2 is marked done with DoD evidence, and §7 marks the backfill done;
   - the README status is updated.

**Design decisions.**
- **Candidate root** (as revised by the review fixes; the original definition, the unreferenced
  blocks at the highest level of an owner and generation, let one planted level-7 block hide the
  real roots of its generation).
  - A block is *referenced* when an indexed internal block one level up, of an acceptable owner
    and of the block's generation or a newer one, points to it with its bytenr and generation.
  - Candidates are the unreferenced blocks at any level. A block only a newer parent points to is
    `referenced_by_newer`, part of that newer tree, not a candidate.
  - An owner-1 candidate is a *candidate root-tree block (state)*: evidence of one root tree, not
    proof of a whole committed filesystem state. `level_consistent` flags a block whose pointers
    name indexed blocks at another level. Every candidate is reported; nothing is collapsed.
- **Resolution through the index, not a chunk map.** A pointer or ROOT_ITEM (bytenr, generation,
  level) is found when a valid scanned block has exactly those values, an owner `owner_ok`
  accepts and the pointer's first key. Pre-balance states therefore resolve although their chunks
  are gone. No chunk map is built, and none is used for reading.
- **Completeness** = found / referenced distinct blocks. Referenced blocks are those named by
  found blocks: root-tree blocks, every ROOT_ITEM's tree root, child pointers. ROOT_ITEMs naming
  tree 1 are not followed, and the chunk and log trees are excluded (no ROOT_ITEM names them), so
  with nothing missing completeness 1 means every block of the root tree and of every
  ROOT_ITEM-named tree was found, nothing more. Nothing is known below a missing block, so it
  overstates survival; the README and EXP-002 say so.
- **Missing blocks** get a failure class from a read through the current chunk map, from a read
  through the state's own chunk items when the current map does not place the address, and from
  invalid scanned copies with the block's bytenr and generation; the most informative class wins
  (review fix; originally the current map only). A valid read is `not_scanned` (a skipped range),
  and bytes that no longer match the index are `changed`.
- **Reused against corrupt.** Generation newer than the superblock is not an integrity failure:
  an intact block from an uncommitted log or transaction at that address is `reused`. Damage is
  only a failed integrity check with this filesystem's fsid.
- **Chunk root of a state.** It is the superblock's or backup slot's when they name the state,
  else `inferred`: the newest chunk-tree candidate root no newer than the state. When it differs
  from the current one, its CHUNK_ITEMs are read through the index (sys_chunk_array-independent)
  and only used to check where each found block would be placed. That feeds M5.
- **Bounds.**
  - At most 64 states are evaluated, the superblock and backup ones first, then the newest.
  - At most 32 problems per state (then a count) and 16 listed bytenrs per group.
  - Walks are memoised per subtree, not per tree root (review fix), and at most 256 missing blocks
    per state are read and classified; the rest count as `unchecked`.
  - Levels must drop by one per hop.
- **Probe compatibility count** (EXP-002). It is derived from the scan plan per image, not
  assumed.

**Discovery per image** (`btrfska roots IMAGE --full-sweep`; outputs in
`images/scratch/m2b/roots/`):

| Image | Root-tree candidates | Slot references rediscovered (distinct blocks) | Candidate root-tree blocks (states) beyond the 4 backups (generations) | … complete | Walk failures |
|---|---|---|---|---|---|
| `sandbox.img` | 5 | 26/26 (18/18) | 1 (3: 7/7 blocks) | 1 | none |
| `m1_xxhash`, `m1_blake2b`, `m1_lzo`, `m1_zlib`, `m1_badnode`, `m1_mirror_damage`, `m1_foreign_mirror` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 30 (gen 3: 5/6) | none |
| `m1_sha256_bgt` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 30 (gen 3: 6/7) | none |
| `m1_badnode_both` | 35 | 26/26 (14/14) | 31 | 29 (gen 34: 11/12 `corrupt`; gen 3: 5/6) | 5 `corrupt` (backup states 9/10) |
| `m2_logtree` | 5 | 24/27 (19/22; backup:5 root, extent, dev: `reused`) | 2 (3, 7) | 1 | 3 `reused` |
| `s01_discard_none_r1`, `s01_discard_async_r1` | 35 | 26/26 (14/14) | 31 (3, 6, 7 ×2, 8–34) | 30 | none |
| `s01_discard_sync_r1` | 2 | 14/26 (6/14) | 1 (3) | 0 | 12 `zeroed` |

The distinct-block counts come from the review re-measurement; every other count was unchanged by
the review fixes. The generation-3 state's missing block (gen 3: 5/6 and 6/7) is `corrupt` since the
review fixes, `unmapped` before. Survival of the 31 states is partly a balance artefact (EXP-002
§6.5).

- On `m2_logtree`, log generation 9 has 4 blocks (8 copies): 2 live and 2 superseded. The log rule
  indexes all 8 copies and rejects none.
- No owner-12 or owner-13 block exists on the corpus.
- Pre-balance states 3–16 have no block the current chunk map places where it was scanned. Their
  inferred chunk trees (generations 3, 6, 17, 23, 24, 29 and 30) place every found block
  (`maps_neither` 0 everywhere).

**EXP-000** (`experiments/EXP-000.md`; N = 15, median (min–max)):

| Row | fsid_blocks | stale_blocks | needle_copies | nonzero_blocks |
|---|---|---|---|---|
| none | 367 (365–367) | 355 (353–355) | 18 (18–18) | 832 (828–832) |
| async | 367 (367–367) | 355 (355–355) | 18 (18–18) | 832 (832–832) |
| sync | 43 (43–43) | 31 (31–31) | 2 (2–2) | 107 (107–107) |

- The medians equal research.md §10.4 (367/355/18/832, 367/355/18/832, 43/31/2/107), so its
  numbers did not change; §10.4 now cites these ranges.
- Only run 6 of the none row differed: 365/353/18/828.
- The "no discard" caveat is recorded: that guest mounts `discard=async`, and the host drops the
  TRIMs.
- Wall time was 4.72–6.03 s per run of three guests.
- 84 of 90 per-run files were deleted afterwards. Run 1 of each row is kept (all three rows sit on
  their medians), and `images/scenarios/` is 251 M.

**EXP-002** (`experiments/EXP-002.md`).

*Probe reconciliation.*
- **Skip ranges.** The probe skips exactly the 4 KiB blocks at 0x10000, 64 MiB and 256 GiB.
  btrfska's full sweep skips [0, 0x11000) and the superblock copies inside the image. The only
  difference is blocks 0–15 (bytes 0–0xFFFF), read by the probe only. No tree block can lie there:
  a regular device holds no device extent below the 1 MiB `BTRFS_DEVICE_RANGE_RESERVED` (v7.0
  fs.h:104-108, volumes.c:1664-1671), and mkfs places its first chunk at 1 MiB (btrfs-progs v6.6.3
  mkfs/common.c:388). `exclude_super_stripes` (block-group.c:2277-2330), cited here before the
  review, concerns logical addresses.
- **Compatibility count.** It takes every full-sweep candidate, invalid ones included, and
  compares the header generation with the *primary* superblock's generation. The probe's rule is
  applied to blocks 0–15 and their hits added. The fsid and generation sources are checked equal
  per image.
- **Result: coverage agreement on 48 of 48 images** (45 regenerated, 3 earlier): equal
  fsid_blocks and stale_blocks. The count reuses btrfska's scan plan and FSID prefilter, so this
  verifies that btrfska reads the probe's offsets, matches the same fsid bytes and reads the same
  generation field. It is not an independent re-implementation. The boot-area supplement was 0
  everywhere.
- **Block by block.**
  - The 5 invalid candidates on every image are mkfs generation-1 blocks at 1081344–1146880 with
    WRITTEN unset; the tree-5 leaf is also empty. The probe counts them; btrfska reports them
    `invalid`.
  - Stale is not orphan. On none and async, 355 stale copies are 10 `live` (unchanged since an
    older generation), 24 `backup_reachable`, 316 `unreferenced` and 5 invalid. The 12
    generation-38 copies are live.

*Classes per mode (N = 15, full sweep):*

| Mode | Candidates | Valid | Invalid | Live | Backup-reachable | Unreferenced | Valid orphans outside the map |
|---|---|---|---|---|---|---|---|
| none | 367 (365–367) | 362 (360–362) | 5 (5–5) | 22 (22–22) | 24 (24–24) | 316 (314–316) | 172 (170–172) |
| async | 367 (367–367) | 362 (362–362) | 5 (5–5) | 22 (22–22) | 24 (24–24) | 316 (316–316) | 172 (172–172) |
| sync | 43 (43–43) | 38 (38–38) | 5 (5–5) | 22 (22–22) | 0 (0–0) | 16 (16–16) | 16 (16–16) |

*Discovery per mode (N = 15):*

| Mode | Root-tree candidates | Slot references indexed / candidates (of 26) | Distinct blocks indexed / candidates (of 14; kept image) | States beyond the backups | … complete |
|---|---|---|---|---|---|
| none | 35 (35–35) | 26 / 26 | 14 / 14 | 31 (31–31) | 30 (30–30) |
| async | 35 (35–35) | 26 / 26 | 14 / 14 | 31 (31–31) | 30 (30–30) |
| sync | 2 (2–2) | 14 / 14 | 6 / 6 | 1 (1–1) | 0 (0–0) |

- Under sync, backups 35–37 lose their root, extent, chunk and dev tree roots, all `zeroed`: 12
  of the 26 slot references, but 8 distinct blocks (root ×3, extent ×3, chunk 131104768 and dev
  64847872). The 26 slot references name 14 distinct blocks; 6 of the 14 survive under sync.
- The 16 surviving valid orphans are all mkfs residue (generations 2–5). No block the kernel freed
  survives.
- This is consistent with `btrfs_finish_extent_commit` under `DISCARD_SYNC`
  (extent-tree.c:2994-3005, 3058-3063), read from the source, not measured.
- EXP-002 §6.4–6.5 states what the numbers do and do not show: not file-level recoverability, not
  SSD FTL behaviour, not async discard with idle time, one small scenario.

**Deviations** (with rationale):
- **All owners are grouped.** The plan says "group root-tree-owned blocks by (owner, level,
  generation)". Discovery groups every owner, so chunk-tree candidates can serve as inferred chunk
  roots and every superblock root can be checked for rediscovery; states are built only for
  owner 1.
- **No historical chunk maps, but a placement check.** A historical state's CHUNK_ITEMs build a
  transient `ChunkMap` object whose only use is to ask where a found block's bytenr would lie. It is
  never stored or used to read (plan M5 builds maps). The chunk root of a state neither the
  superblock nor a backup slot names is a labelled inference.
- **Missing blocks were classified through the current chunk map only** (superseded by the
  review fixes). On every s01 image the generation-3 state's csum root, the invalid mkfs leaf at
  1130496, read as `unmapped` although an invalid scanned copy exists. It now reads `corrupt`.
- **EXP-000 N = 15, not 5.** The first 5 runs had no spread, so 10 more estimated how often the
  known jitter occurs (1 in 15). CPU cost was about a minute of sequential guests.
- **Image names.** Per-run images are `s01_discard_<row>_r<n>`. The earlier
  `s01_discard_{none,async,sync}.img`, which fed research.md §10.4, were not created here and were
  left in place and unlisted; EXP-002 measured them for agreement only.
- **Richer `roots` options.** The task named `btrfska roots IMAGE [--json]`. `--full-sweep`,
  `--workers` and `--allow-unsupported` were added for parity with `scan`. The default is targeted,
  as for `scan`; EXP-002 and the tables use `--full-sweep`.
- **EXP-002 hypothesis split.** The agreement was pre-registered in plan.md. The discovery results
  were measured without a prior prediction and are labelled observations.
- **Scan summary change.** `btrfska scan` prints one more line (walk failures); no existing line
  changed.
- **Expectation corrected after the first run.** The M1 rediscovery test required every
  current-state tree to be `found`. On `m1_badnode_both` the damaged `sv1` leaf is correctly
  `corrupt`, so the test now takes the expected damaged trees per image. No code changed.
- **Two scans per image in EXP-002** (`scan_image`, then `discover_image`). Adequate at 512 MiB;
  M3's scan-once catalog removes it.

**Adversarial tests** (`tests/test_scan_roots.py`):
- **Forged root trees.** One level-2 root-tree block has 100 pointers to one level-1 node, whose 99
  pointers go to one leaf and whose last pointer goes back to itself one level too low. The leaf's
  ROOT_ITEMs name the root tree itself (skipped), a tree newer than the state (problem), a leaf as
  level 1 (`mismatch`) and a malformed 10-byte item (problem). Result: 4 of 6 blocks; problems
  capped at 32 plus a count; no re-walk of repeated pointers.
- **Flood.** 50 000 same-generation root-tree fragments: peak Python heap below 16 MiB
  (tracemalloc); 64 states evaluated; all 50 000 counted as candidates, 16 listed.
- **Log candidates.** Owner −6 at superblock + 2 is rejected; owner −6 at superblock + 1 with a
  failed csum is rejected, as is a truncated one; owner 5 at superblock + 1 is not a log. An owner
  −6 block at superblock + 1 failing only its generation is indexed, live or superseded by the log
  walk; one at generation 40 counts as a committed log.
- **Failure classes.** Synthetic `reused` (a newer tree and an uncommitted log block), `mismatch`
  (wrong level, older than the pointer), `corrupt`, `overwritten`, `zeroed`, `unmapped` and
  `unreadable`.

**M2 closeout** (plan.md §5 M2 DoD):

| DoD bullet | Status | Evidence |
|---|---|---|
| sandbox parity: 71 orphans, 21 outside map, identical offsets | met (M2a) | `test_sandbox_legacy_compatible_orphans_are_the_legacy_offsets`: 71 legacy-compatible orphans with identical offsets and header fields, 21 outside the map; reconciled as 8 live + 34 backup-reachable + 28 unreferenced + 1 invalid (M2a entry) |
| discard trio: exact per-image agreement with the probe; cross-run numbers as median and range next to EXP-000 | met (M2b), as coverage agreement | EXP-002: 48 of 48 images give equal fsid_blocks and stale_blocks under the documented compatibility count, which reuses btrfska's scan plan and prefilter (coverage, not an independent re-implementation); classes and discovery as median (range) over N = 15 next to EXP-000's N = 15 table; `tests/test_discard_trio.py` (vm) |
| ≥ 200 MB/s single-core on a synthetic 10 GiB image under `images/` | met (M2a) | EXP-003: slowest run 3 227.5 MB/s of image, 1 734.7 MB/s per allocated byte; 512 MB/s on a 100 % metadata 1 GiB image |
| benchmark script committed | met (M2a) | `experiments/bench_scan.py` |
| (task) old-root discovery, owner-13 and owner-12 blocks recorded | met (M2b) | `scan/roots.py`, `btrfska roots`; raw owner-12/13 records (none on the corpus: the stock kernel cannot create them) |
| (task) discard axis first use (EXP-002) | met (M2b) | `experiments/EXP-002.md` |

**Verification** (local, branch `feature/m2b-old-roots-discard` at `4a66ad8`; logs in
`images/scratch/m2b/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img; stat -c '%y' sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all) | `uv run pytest -q` | `717 passed in 66.91s` (was 684) |
| vm tests | `uv run pytest -m vm -q` | `70 passed, 647 deselected` |
| Tests without vm | `uv run pytest -m "not vm" -q` | `647 passed, 70 deselected` |
| New and CLI tests | `uv run pytest -q tests/test_scan_roots.py tests/test_discard_trio.py tests/test_cli.py` | `71 passed` |
| Read-only and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; `grep` for `dissect`/`lzallright` imports under `src/`: 0 |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `65 files already formatted` |
| Lockfile | `uv lock --check` | `Resolved 15 packages` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| corpus shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done` | exit 0 |
| Roots, sandbox | `uv run btrfska roots sandbox.img` | exit 0; sample below |
| Roots, JSON | `uv run btrfska roots sandbox.img --json --full-sweep \| wc -l` | `79` |
| Scan, `m2_logtree` | `uv run btrfska scan images/scenarios/m2_logtree.img \| grep 'walk failures'` | `walk failures: current 0; backup roots 3 (reused 3)` |
| Image hashes | `runs.jsonl` (at generation) against `results.jsonl` (at measurement) | 45 of 45 equal; `env_after.txt` re-hashes the 3 kept images |
| `sandbox.img` after | `sha256sum sandbox.img; stat -c '%y' sandbox.img` | unchanged hash and mtime |

**`btrfska roots` samples** (`images/scratch/m2b/verify/roots_*.txt`; long problem lines cut). These
are the outputs at `4a66ad8`; since the review fixes the `rediscovered:` line also counts distinct
blocks, and the generation-3 state's missing block reads `corrupt` (samples in "Review fixes"):
```
$ uv run btrfska roots sandbox.img
btrfska roots: targeted, 85 candidates, 84 valid copies of 52 tree blocks indexed
skipped as DATA: 8388608 bytes (use --full-sweep to include reallocated ranges)
log candidates: 0 indexed one generation ahead, 0 rejected
groups: 48 (owner, generation, level); candidate roots: 52
root tree candidates: 5 (5 evaluated, 1 beyond the superblock and backup roots)
rediscovered: 26/26 superblock and backup roots are candidate roots (26 indexed)
state generation 14 bytenr 30720000 level 0 [backup:14, current]: trees 8/8 found, blocks 9/9 (completeness 1.000); chunk root 22036480 generation 8 (backup:14); blocks placed by the current chunk map 9, by neither 0
state generation 13 bytenr 30572544 level 0 [backup:13]: trees 8/8 found, blocks 9/9 (completeness 1.000); chunk root 22036480 generation 8 (backup:13); blocks placed by the current chunk map 9, by neither 0
state generation 12 bytenr 30883840 level 0 [backup:12]: trees 8/8 found, blocks 9/9 (completeness 1.000); chunk root 22036480 generation 8 (backup:12); blocks placed by the current chunk map 9, by neither 0
state generation 11 bytenr 30801920 level 0 [backup:11]: trees 8/8 found, blocks 9/9 (completeness 1.000); chunk root 22036480 generation 8 (backup:11); blocks placed by the current chunk map 9, by neither 0
state generation 3 bytenr 5324800 level 0 [not a superblock or backup root]: trees 6/6 found, blocks 7/7 (completeness 1.000); chunk root 1048576 generation 3 (inferred, differs from current); blocks placed by the current chunk map 0, by the state's chunk items 7, by neither 0
log trees: none
raid stripe tree blocks: 0; remap tree blocks: 0
walk failures: current 0; backup roots 0

$ uv run btrfska roots images/scenarios/m2_logtree.img
btrfska roots: targeted, 89 candidates, 84 valid copies of 49 tree blocks indexed
log candidates: 8 indexed one generation ahead, 0 rejected
root tree candidates: 5 (5 evaluated, 2 beyond the superblock and backup roots)
rediscovered: 24/27 superblock and backup roots are candidate roots (24 indexed)
not rediscovered: backup:5 root 30441472 generation 5 (not indexed)
not rediscovered: backup:5 extent 30474240 generation 5 (not indexed)
not rediscovered: backup:5 dev 30457856 generation 5 (not indexed)
log generation 9: 4 blocks (8 copies), candidate roots 4, live 2, superseded 2
walk failures: current 0; backup roots 3 (reused 3)
problem: backup:5: tree 1 node 30441472 is invalid: mirror 1: owner: owner 10 != expected 1; mirror 1: parent_generation: generation 7 != parent pointer generation 5 (newer: rewritten after the parent); …

$ uv run btrfska roots images/scenarios/s01_discard_sync_r1.img --full-sweep
btrfska roots: full sweep, 43 candidates, 38 valid copies of 26 tree blocks indexed
root tree candidates: 2 (2 evaluated, 1 beyond the superblock and backup roots)
rediscovered: 14/26 superblock and backup roots are candidate roots (14 indexed)
not rediscovered: backup:35 root 65208320 generation 35 (not indexed)
…
state generation 38 bytenr 65437696 level 0 [backup:38, current]: trees 9/9 found, blocks 10/10 (completeness 1.000); chunk root 131121152 generation 38 (backup:38); blocks placed by the current chunk map 10, by neither 0
state generation 3 bytenr 5308416 level 0 [not a superblock or backup root]: trees 4/5 found, blocks 5/6 (completeness 0.833; missing unmapped 1); chunk root 1048576 generation 3 (inferred, differs from current); blocks placed by the current chunk map 0, by the state's chunk items 5, by neither 0
walk failures: current 0; backup roots 12 (zeroed 12)
```

**Research notes.** research.md §10.4 gains the EXP-000 ranges, and §10.11 records:
- discovery per image;
- 31 surviving states beyond the backups;
- pre-balance states resolving through their own chunk items;
- reuse apart from damage;
- superseded log commits;
- sync discard removing all history the kernel freed;
- the probe reconciliation.

**For M3 (evidence catalog).**
- **Store every candidate**, invalid ones included, with its checks. Discovery now keeps invalid
  copies as (bytenr, generation, physical) to classify missing blocks; a `nodes` table with the
  checks would let classification and discovery share one store.
- **Rows are ready.**
  - `BlockIndex` columns match the planned `nodes(bytenr, phys, gen, owner, level, …)`.
  - `State`, `TreeRef`, `Group`, `LogGeneration`, `Rediscovery` and `walk_failures` are flat,
    frozen dataclasses (JSON through `asdict`) for `roots` and `provenance` rows.
  - The failure classes (`node.FAILURE_CLASSES`) are a fixed vocabulary for the "why not
    reachable" column.
- **Scan once.** `btrfska scan` and `btrfska roots` each scan and walk again, and EXP-002 does
  both per image. The catalog should run the scan and the walks once and feed classification and
  discovery from the stored rows.
- **M5 inputs already identified.** The historical chunk roots per state (generations 3, 6, 17,
  23, 24, 29 and 30 on the s01 images) place every found block, and pre-balance states 3–16
  resolve entirely outside the current map.
- **Corpus.** The discard trio `s01_discard_{none,async,sync}_r1` is in the manifest. Test
  tolerances for regenerated trio images come from EXP-000's ranges (none: 2 blocks in columns
  1–2, 4 in column 4); per-image counts are exact.

### Review fixes (2026-09-15)

The PR review approved M2b with seven fixes. All are applied, test-first where code changed (each
new test was run and seen to fail before the fix).

**Commits.**
- `58e21c4` Memoise discovery walks per subtree with a cap on classified missing blocks, and report every unreferenced block as a candidate root
- `3c9219b` Classify missing blocks through the state's own chunk items and invalid scanned copies
- `91f355f` Report superblock and backup rediscovery per slot reference and per distinct block in the roots summary
- `8daf05f` Record distinct-block rediscovery and the new state fields in EXP-002 measurements, with a results path per run
- `06db7de` Correct the reserved-range citation and define completeness and candidate root-tree blocks in the code docs
- `434811c` Reword M2b findings after review: coverage agreement, slot references against distinct blocks, candidate root-tree blocks, completeness scope and the balance artefact
- this subsection (the commit after `434811c`)

**1. Hostile walk cost** (`scan/roots.py`).
- **Problem.** Walks were memoised per tree root. Each dangling pointer cost a full
  `NodeReader.read`, and a walk's missing set was uncapped.
- **Change.** The caches now work per subtree:
  - reference outcomes per (bytenr, generation, level, owner class, first key);
  - each found internal node's pointers, parsed once and resolved against the index with numpy;
  - (found, missing) counts per subtree, for the per-tree figures;
  - missing-block classes, read once per reference and chunk root.

  A state walk visits each distinct found block once and keeps at most `MAX_MISSING` = 256
  classified missing blocks. The rest count as `unchecked` without a read; that count is not
  de-duplicated. Reads per run are at most 64 × 256.
- **Test.** `test_shared_subtrees_with_dangling_pointers_cost_one_walk_not_one_per_root` uses the
  review's shape scaled down: 64 roots, 40 shared level-1 nodes, 40 dangling pointers each. It
  asserts reads ≤ 2 × 256, under 5 s and a peak heap under 8 MiB.
- **Measured** (`images/scratch/m2b-review/hostile_walk.py`, tracemalloc on, nodesize 4 KiB):

  | Shape (roots × shared level-1 × dangling) | Before | After |
  |---|---|---|
  | 64 × 40 × 40 (the test) | 39.05 s, 15.2 MiB, 102 400 reads | 1.77 s, 1.9 MiB, 256 reads |
  | 64 × 121 × 121 (the review's image, 185 allocated blocks) | 422.22 s, 130.7 MiB, 937 024 reads | 2.82 s, 3.5 MiB, 256 reads |

- **Design note.** Per-tree `blocks` and `missing` come from the subtree counts. They count a tree
  as a tree: a block that two parents of one tree name is counted twice there, which only forged
  input produces. State totals stay exactly de-duplicated. Exact per-tree distinct counts over
  shared DAGs would cost roots × shared blocks again.

**2. Slot references against distinct blocks.**
- **Problem.** "14 of 26 roots" counted superblock and backup slot references. They name 14
  distinct blocks, and under sync 8 of those are lost (root ×3, extent ×3, chunk 131104768, dev
  64847872); 6 survive.
- **Change.** The `roots` summary now reads, for example, `rediscovered: 14/26 superblock and
  backup root slot references are candidate roots (14 indexed), naming 14 distinct blocks: 6/14
  candidate roots (6 indexed)`.
- **Tests.** `test_the_rediscovery_line_counts_slot_references_and_distinct_blocks` (synthetic
  shared slots); the sandbox summary test (26/26, 18/18); and the vm test
  `test_the_sync_summary_counts_surviving_slot_references_and_distinct_blocks` (14/26, 6/14).
- **Docs.** Every occurrence is reworded: EXP-002 §6.3, §7 and §8, research.md §10.11, and the
  tables and the EXP-002 part of this entry.

**3. The 31 surviving states are partly a balance artefact.**
- Generations 3–16 lie in the chunks the scenario's final full balance deleted (`maps_current` 0
  in every one of those states, re-checked on the kept images). Nothing reallocated those ranges.
- Generations 17–34 lie in the 64 MiB metadata block group the balance created. Every root-tree
  block of generations 17–38 lies in its first 1.41 MiB. The allocator continues from its last
  allocation (v7.0 extent-tree.c:4235-4241, 4451-4466, 4620-4622), so it never revisited the freed
  blocks. This is read from the source, not measured.
- Added to EXP-002 §6.5 and §7, research.md §10.11 and plan.md M2. Survival depends on the balance
  and on the filesystem's short life and is not generalised.

**4. Candidate definition.**
- **Problem.** Candidates were the unreferenced blocks at the highest level of an owner and
  generation, so one planted owner-1 level-7 block of generation G hid every real generation-G
  root leaf. Old leaves referenced only by newer parents also became extra states.
- **Change.**
  - Candidates are the blocks no indexed internal block one level up, of an acceptable owner and
    of the same or a newer generation, points to, at any level.
  - Groups gain `referenced_by_newer`.
  - States gain `level_consistent`, false when a pointer names an indexed (bytenr, generation)
    only at another level; a problem line gives the count.
  - A tie between inferred chunk roots prefers a level-consistent block.
- **Tests.**
  - `test_a_planted_higher_level_block_does_not_hide_the_root_tree_leaves_of_its_generation`: 2
    states; the planted one is flagged, the real one complete.
  - `test_old_leaves_of_a_multi_leaf_root_tree_that_newer_parents_still_use_are_not_states`: B40
    is `referenced_by_newer`, and there is no generation-40 state.
  - The synthetic history now lists the fragment O90 as a state, and L90B (referenced by the newer
    R90) is no longer one.
- **Wording.** "Candidate root-tree block (state)" is defined in README, research.md §10.11,
  EXP-002 §2 and the code docs.
- **Numbers.** Unchanged on the whole corpus. Every owner-1 block is level 0, no block of any owner
  is referenced only by a newer parent, and no state is level-inconsistent, on sandbox, the nine m1
  images, `m2_logtree` and the trio.
- **Residual vector.** A forged newer parent can still mark an older block as referenced. It is
  then itself a candidate state, and that state reaches the block.

**5. Missing-block classes outside the current map.**
- **Change.** A missing block the current map does not place is read through the state's own chunk
  items (the historical map already built for the placement check). Invalid scan candidates are
  kept as (bytenr, generation, physical), 24 bytes each, with the stat `invalid_copies`; up to 16
  copies with the block's bytenr and generation are checked against the referrer's expectations.
  The most informative class wins.
- **Tests.**
  - `test_missing_blocks_outside_the_current_map_use_the_state_chunk_items_and_invalid_copies`:
    `zeroed` and `corrupt` through the state's chunk items, `corrupt` through an invalid copy only,
    and a control that stays `unmapped`.
  - `test_a_present_but_invalid_block_of_an_old_state_is_not_reported_unmapped` (sandbox): a
    scratch copy of `sandbox.img` whose generation-3 csum leaf (1130496) is damaged. Before the fix
    it read `'unmapped' != 'corrupt'`.
  - The vm trio tests now expect `corrupt`.
- **Outcome.** On the 10 s01-derived images (the nine m1 images, `m2_logtree` and the trio), the
  generation-3 csum root is `corrupt`, not `unmapped`. A diff of every `roots --json` record against
  the pre-review outputs (`images/scratch/m2b/roots/`) shows no other change; sandbox is identical.

**6. Coverage agreement and the reserved range.**
- EXP-002 §1, §2, §6.1, §6.4, §7 and §8, `exp002.py`, plan.md M2, research.md §10.11, the trio test
  name and this entry now call the 48/48 result coverage agreement. The compatibility count reuses
  btrfska's prefilter, so it verifies the offsets read, the fsid match at +0x20 and the generation
  field at +0x50, not an independent count.
- Blocks 0–15 hold no tree block because of the 1 MiB device reservation:
  - Linux v7.0 (read with `git show v7.0:…`, nothing checked out or copied): fs.h:104-108
    `BTRFS_DEVICE_RANGE_RESERVED (SZ_1M)`; volumes.c:1664-1671 `dev_extent_search_start`;
    volumes.c:8257-8266, the warning for older mkfs layouts;
  - btrfs-progs v6.6.3: kernel-shared/ctree.h:207 `BTRFS_BLOCK_RESERVED_1M_FOR_SUPER`;
    mkfs/common.c:388 (first system chunk at 1 MiB); kernel-shared/volumes.c:751-757 and 1293.
- `exclude_super_stripes` (block-group.c:2277-2330; `SUPER_INFO_OFFSET` is 64 KiB, fs.h:80)
  concerns logical addresses. The same misreading is corrected in the `scan/regions.py` docstring.

**7. "Complete".** Everywhere it is used (README, `roots` help, `scan/roots.py`, EXP-002,
research.md §10.11 and this entry), completeness excludes the chunk tree, the log tree and
ROOT_ITEMs naming tree 1. With nothing missing it equals every block of the root tree and of every
ROOT_ITEM-named tree.

**EXP-002 re-measurement.** Three kept images at `8daf05f`:
- **Commands.** `exp002.py run --results images/scratch/exp/EXP-002/review/results.jsonl …_r1.img`,
  then `table`.
- **Results.** Every count equals the original measurement: SHA-256, probe columns, compatibility
  count, classes, walk failures, and each state's found, referenced and completeness. The only
  change is the generation-3 class. Distinct blocks: 14/14 (none, async) and 6/14 (sync). The 42
  deleted images cannot be re-measured.

**Verification** (branch at `434811c`; logs in `images/scratch/m2b-review/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img; stat -c '%y' sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all) | `uv run pytest -q` | `724 passed in 74.10s` (was 717) |
| vm tests | `uv run pytest -m vm -q` | `71 passed, 653 deselected in 18.44s` (was 70) |
| Read-only and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; `grep` for `dissect`/`lzallright` imports under `src/`: 0 |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `65 files already formatted` |
| Lockfile | `uv lock --check` | `Resolved 15 packages` |
| Roots, sandbox | `uv run btrfska roots sandbox.img` | exit 0; sample below |
| Roots, m1 | `uv run btrfska roots images/scenarios/m1_xxhash.img` | exit 0; sample below |
| `sandbox.img` after | as before | unchanged hash and mtime |

```
$ uv run btrfska roots sandbox.img
btrfska roots: targeted, 85 candidates, 84 valid copies of 52 tree blocks indexed
skipped as DATA: 8388608 bytes (use --full-sweep to include reallocated ranges)
log candidates: 0 indexed one generation ahead, 0 rejected
groups: 48 (owner, generation, level); candidate roots: 52
root tree candidates: 5 (5 evaluated, 1 beyond the superblock and backup roots)
rediscovered: 26/26 superblock and backup root slot references are candidate roots (26 indexed), naming 18 distinct blocks: 18/18 candidate roots (18 indexed)
state generation 14 bytenr 30720000 level 0 [backup:14, current]: trees 8/8 found, blocks 9/9 (completeness 1.000); chunk root 22036480 generation 8 (backup:14); blocks placed by the current chunk map 9, by neither 0
…
state generation 3 bytenr 5324800 level 0 [not a superblock or backup root]: trees 6/6 found, blocks 7/7 (completeness 1.000); chunk root 1048576 generation 3 (inferred, differs from current); blocks placed by the current chunk map 0, by the state's chunk items 7, by neither 0
log trees: none
raid stripe tree blocks: 0; remap tree blocks: 0
walk failures: current 0; backup roots 0

$ uv run btrfska roots images/scenarios/m1_xxhash.img
btrfska roots: targeted, 367 candidates, 362 valid copies of 188 tree blocks indexed
skipped as DATA: 67108864 bytes (use --full-sweep to include reallocated ranges)
groups: 167 (owner, generation, level); candidate roots: 188
root tree candidates: 35 (35 evaluated, 31 beyond the superblock and backup roots)
rediscovered: 26/26 superblock and backup root slot references are candidate roots (26 indexed), naming 14 distinct blocks: 14/14 candidate roots (14 indexed)
state generation 38 bytenr 65437696 level 0 [backup:38, current]: trees 9/9 found, blocks 10/10 (completeness 1.000); chunk root 131121152 generation 38 (backup:38); blocks placed by the current chunk map 10, by neither 0
…
state generation 3 bytenr 5308416 level 0 [not a superblock or backup root]: trees 4/5 found, blocks 5/6 (completeness 0.833; missing corrupt 1); chunk root 1048576 generation 3 (inferred, differs from current); blocks placed by the current chunk map 0, by the state's chunk items 5, by neither 0
walk failures: current 0; backup roots 0
```

**For M3.**
- Keep invalid candidates with their checks in the catalog; discovery already depends on them.
- A state walk still visits each state's found blocks once per state. On large filesystems with 64
  evaluated states, the catalog should store per-subtree counts and memberships instead of
  recomputing them per state.
- `unchecked` should become rows too, so a state beyond the cap can be classified on demand.

## 2026-09-15 — M2a: scan kernel, targeted regions, orphan classification

- **Branch:** `feature/m2a-scan-kernel` (from `main` at `f3cb71b`). This is
  the first of two M2 PRs. It covers plan.md §5 M2:
  - the scan kernel;
  - targeted regions with the MIXED_GROUPS fix, tree-11 input and
    `--full-sweep`;
  - orphan classification;
  - sandbox parity;
  - the performance DoD (EXP-003).

  Old-root discovery, the discard trio (EXP-002) and the EXP-000 backfill
  are M2b.
- **Commits:**
  - `93521ff` Plan scan regions from typed chunk stripes and unmapped gaps, skipping DATA only when block groups agree
  - `7696aa5` Add the numpy scan kernel: strided fsid prefilter, every candidate validated and kept
  - `15b3bf0` Classify scanned nodes as live, backup-reachable or unreferenced, with sandbox legacy parity
  - `a725d88` Add btrfska scan with a per-node JSON schema documented in the README
  - `013d597` Add the EXP-003 scan benchmark: a deterministic sparse 10 GiB image, cold and warm runs
  - `6588ebb` Record EXP-003: the numpy scan kernel at 3.2-8.4 GB/s on a synthetic 10 GiB image
  - `5397405` Record M2a scan findings in research notes and the M2 status
  - this catalog entry (the commit after `5397405`)

**What was done.**
- **Tests first.** Every module was written after its tests and seen
  failing:
  - `test_scan_regions`, `test_scan_kernel` and `test_scan_classify` failed
    at collection with ModuleNotFoundError;
  - the eight `scan` CLI tests failed with `invalid choice: 'scan'` and, for
    the README sync test, IndexError.

  Three expectations were corrected after the first run (see Deviations).
- **Legacy reference.** `images/scratch/m2a/legacy_scan.py` ran the
  prototype's `build_scan_regions` and `sweep_for_orphans`, targeted and
  full sweep, on `sandbox.img`.
  - Both modes: 71 orphans at identical offsets, 1 checksum failure, 14
    current-generation leaves.
  - Blocks scanned: 15 867 targeted, 16 379 full.
  - Its regions, counts and the 71 offsets with their header fields are
    frozen in `tests/ground_truth/sandbox_legacy_scan.json`.
  - `test_golden_legacy_offsets_match_a_live_legacy_run` re-runs the
    prototype while `legacy/` exists.
- **Kernel references.** v7.0 files already in
  `images/scratch/review-m1b/kernel/`, cited by line in code, none copied:
  - `block-group.c`: 1053-1058, 2277-2330, 2429;
  - `volumes.c`: 4023-4030, 7271-7276;
  - `tree-checker.c`: 2047-2080;
  - `ctree.c`: 621-625;
  - `fs.h`: 108.

1. **`scan/regions.py`** (`build_regions`, `plan_scan`, `stripe_extents`,
   `read_block_groups`) splits the image into scanned `Region`s and skipped
   ranges that together partition it.
   - A region is `(start, end, kind, chunk, stripe)`. `kind` is the chunk
     type as dump-tree prints it (`METADATA|DUP`) or `unmapped_gap`.
   - A stripe's device length is the chunk length divided by the data
     stripes, (num_stripes − nparity) / ncopies.
   - Only stripes on this image's device (devid and device uuid) count;
     rejected chunk items never exclude a range.
   - **Skipped ranges:**
     - `reserved`: 0–68 KiB, the boot area and primary superblock;
     - `superblock`: the other superblock copies, which the kernel
       excludes from every block group;
     - DATA-only chunks, but only when the block-group item agrees on
       length, type and profile.
   - **Block-group items** are read from tree 11 when compat_ro
     BLOCK_GROUP_TREE is set, else from the extent tree.
   - **MIXED_GROUPS:** DATA chunks are scanned.
   - **Physically overlapping chunks** are scanned and reported.
   - **`--full-sweep`** also scans DATA chunks.
   - 20 tests (2 vm):
     - the sandbox layout;
     - partition of the image;
     - full sweep;
     - MIXED_GROUPS and DATA|METADATA;
     - block-group agreement, including a missing item, a wrong type and a
       wrong length;
     - device lengths for DUP, RAID1, RAID0, RAID10, RAID5 and RAID6;
     - stripes on another device;
     - an overlap;
     - rejected chunks;
     - clipping and a 4 KiB image;
     - legacy parity on the sandbox;
     - tree-11 and extent-tree input on `m1_sha256_bgt` and `m1_xxhash`
       (vm).
2. **`scan/kernel_numpy.py`**: `iter_candidate_nodes(img, regions, ctx,
   chunk_map, *, workers=1)` → `NodeRecord`, and `iter_prefilter_hits`.
   - **Prefilter.** The 16 bytes at header +0x20 are compared as two u64s
     with the tree fsid (`ctx.fsid`, metadata_uuid when set). The compare
     runs through strided `np.ndarray` views of the read-only map, 65 536
     offsets per window, at sectorsize alignment.
   - **Checks.** Every hit gets `check_block(block, ctx, None,
     NO_EXPECTATIONS)` and the chunk-map lookup of its header bytenr.
   - **Records.** A `NodeRecord` is flat and frozen, JSON-ready through
     `asdict`: physical, bytenr, generation, owner, level, nritems, all
     checks, valid, bytenr_mapped, maps_here, region and problems.
   - **Truncated blocks.** A block cut by the image end is a record with no
     checks and `truncated: N of nodesize bytes before the image end`. An
     fsid cut by the end is not a candidate.
   - **Region normalisation.** Regions are sorted and clipped, and each
     offset is probed once, for the first region holding it. A node belongs
     to the region holding its header, even when it extends past the
     region's end.
   - **Workers.** `workers` 2–4 scan 256 MiB pieces in processes that open
     the image through `open_image`; records come back in order. More than
     4 is a ValueError, and the default is 1.
   - **Map lifetime.** numpy views die inside each window's function, so
     the image can be closed while an iteration is suspended (tested).
   - 18 tests. Among them the adversarial cases:
     - overlapping and unsorted regions;
     - regions beyond the image;
     - a truncated final block;
     - a header and an fsid cut by the image end;
     - a node straddling a region end;
     - unaligned region starts;
     - an fsid match followed by random bytes;
     - a foreign fsid.

     The rest cover workers equal to one process, the worker bound, JSON
     readiness and mapping here, elsewhere and unmapped.
3. **`scan/classify.py`**: `reachability`, `classify`, `summarize` and
   `scan_image`.
   - **Live set.** The M1b walker walks every tree of a root set: the slot
     or superblock trees, every ROOT_ITEM of its root tree (all subvolumes
     and snapshots), and the log tree if the superblock names one.
   - **Pairs.** A (logical, physical) pair is reached when the walk's copy
     at that offset passed every check.
   - **Statuses.** `live` (current state), `backup_reachable` (a backup
     root only), `unreferenced`, or `invalid`.
   - **Flags.** `outside_map` (no stripe of the current map) and
     `legacy_orphan` (csum ok, generation below the superblock's,
     nodesize-aligned).
   - **Extent-tree cross-check.** The tree blocks the current extent tree
     lists are compared with the walked logical addresses.
   - 14 tests, 5 of them vm: the pure classification, the summary, sandbox
     parity and reconciliation, targeted equal to full sweep, every live
     copy found, and the live legacy run.
4. **`btrfska scan IMAGE [--full-sweep] [--workers N] [--json]
   [--allow-unsupported]`.**
   - The gate is shared with `walk`.
   - The summary goes to stdout, or to stderr with `--json`, which writes
     one `node` record per candidate in physical order.
   - README.md gains "`btrfska scan` output";
     `test_readme_documents_every_scan_key` checks it.
   - 8 tests. `--workers 2` output is byte-identical to one process.
5. **Dependency.** `numpy>=2.3` (BSD) is a runtime dependency; the lock
   resolves numpy 2.5.3.
6. **EXP-003** (`experiments/bench_scan.py`, `experiments/EXP-003.md`).
7. **Docs.** research.md §10.10 is new, plan.md M2 has a status line, and
   the README status is updated.

**Design decisions.**
- **Orphan definition.** An orphan is a *valid* node whose copy is not
  reached from the current state.
  - It is a physical-copy notion: a stale copy claiming a live logical
    address is still unreferenced.
  - Invalid candidates are never orphans, but they are always emitted, with
    every check.
- **Backup roots are not live.** Backup-reachable nodes are a separate orphan
  class, because the kernel may reuse their blocks at any time.
  `orphans = backup_reachable + unreferenced`.
- **The live set comes from walks, not the extent tree.** Walks validate
  every hop and give physical copies. The prototype's extent-tree live set
  (`orphan_scan.py`) is kept only as a cross-check. It agreed exactly on
  every image here (see below), so it adds no information on this corpus;
  it stays in the summary to flag a dropping subvolume, a log tree or damage.
- **Parity is asserted on the legacy definition** through `legacy_orphan`,
  and the reachability classes are reconciled against it (table below),
  never fitted to it.
- **Regions follow the kernel's placement rules** (superblock exclusion,
  stripe lengths). They trust a DATA exclusion only when two sources agree
  (chunk item and block-group item).
- **The frozen interface** is `iter_candidate_nodes(img, regions, ctx,
  chunk_map)`. `NodeRecord` holds primitives, a `Region` and `Check`s, so M3
  can store it as a `nodes` row and M8 can swap the kernel.

**Sandbox parity and reconciliation** (`uv run pytest -q
tests/test_scan_classify.py`, all green).
- **Legacy-compatible orphans** (csum ok, generation < 14, nodesize-aligned):
  71, with offsets, bytenr, generation, owner and level identical to the
  legacy golden file, in the same order.
- **Outside the current map:** 21 of them, with block starts in
  0x100000–0x12c000 and 0x500000–0x520000. Each claims bytenr == physical,
  unmapped.
- **Targeted equals full sweep:** same records, statuses and flags (85
  candidates), and 0 orphans outside the targeted regions.
- **Regions.** After nodesize snapping, btrfska's regions together with the
  64 MiB superblock hole equal legacy's `[[81920, 13631488], [22020096,
  268435456]]`.

How the 71 legacy orphans classify under reachability:

| Class | Legacy orphans | Blocks (logical → physical copies) | Why the definitions differ |
|---|---|---|---|
| `live` | 8 | chunk root 22036480 (gen 8) → 22036480, 30425088; uuid tree 30457856 (gen 7) → 38846464, 72400896; data reloc tree 30556160 (gen 5) → 38944768, 72499200; dev tree 30588928 (gen 13) → 38977536, 72531968 | Unchanged since an older generation, but named by the current state. Legacy's "generation < superblock generation" counts them as orphans |
| `backup_reachable` | 34 | 17 blocks × 2 DUP copies: generation 5 (csum 30523392), 9 (dev 30621696), 11 (5 blocks), 12 (4), 13 (6) | Reached only from backup roots 11–14; not live |
| `unreferenced`, outside map | 20 | 0x100000–0x12c000 and 0x500000–0x520000 except 1114112; generations 1–4 | Removed mkfs chunks; nothing names them |
| `unreferenced`, in map | 8 | 22020096 (gen 5, chunk) → 22020096, 30408704; 30408704 (gen 13, fs) → 38797312, 72351744; 30425088 (gen 13, fs) → 38813696, 72368128; 30818304 (gen 12, fs) → 39206912, 72761344 | Freed by later transactions |
| `invalid` | 1 | 1114112: empty generation-1 fs-tree leaf, outside the map | Its csum is good (legacy checks nothing else), but `nritems` fails: tree 5 must never be empty (tree-checker.c:2047-2080) |
| **Total** | **71** | | |

Not in the legacy 71:
- the 12 live generation-14 copies;
- 2 unreferenced generation-14 fs-tree leaf copies (logical 30605312 →
  38993920, 72548352). Legacy excludes the current generation, but a block
  WRITTEN in the running transaction is COWed again (ctree.c:621-625).

btrfska's totals on the sandbox: 85 candidates, 84 valid, 1 invalid; 20 live;
64 orphans (34 backup-reachable, 30 unreferenced); 20 valid orphans outside
the map. The legacy "21 outside the map" includes the invalid empty leaf.

**EXP-003 summary** (`experiments/EXP-003.md`). Synthetic 10 GiB sparse image
(seed 3; 6 metadata, 80 data and 74 hole tiles; 11 151 sandbox tree-block
copies, 106 corrupted; SHA-256 `acf9b2ef…`, reproduced by `generate
--verify`). N = 5 per cell, one process, median (range):

| Mode | Cache | MB/s (image bytes; sparse image, per-allocated-byte figures in the review fixes below) | Pages cached before the run |
|---|---|---|---|
| prefilter | cold | 3743.1 (3505.4–4328.8) | 0 % |
| prefilter | warm | 6138.6 (3622.4–8364.7) | 82–93 % |
| full validation | cold | 3277.1 (3227.5–3337.8) | 0 % |
| full validation | warm | 5691.0 (4430.1–7025.2) | 87–93 % |

- **DoD.** The ≥ 200 MB/s target is met: the slowest single run reached
  3 227.5 MB/s in image bytes, and a fully metadata-dense 1 GiB image still
  scans at 512 MB/s cold (density sweep in the review fixes below). Every run found exactly 11 151 candidates and 11 045 valid
  blocks.
- **Cache state.** Cold means `POSIX_FADV_DONTNEED`, confirmed by
  `mincore()`. Warm runs had partly reclaimed caches; a 99.9 %-cached
  profiled run reached 12 157 MB/s.
- **Bottleneck.**
  - Cold: device reads (wall exceeds CPU by 1.1–1.2 s).
  - Whole run: kernel page-fault and page-cache work (27.5 s system versus
    5.8 s user CPU).
  - In the process: per-candidate Python validation, about 61 µs per
    candidate (0.68 s of 0.95 s). The numpy prefilter takes 0.19 s.
  - No optimisation was needed. A dense image would be bounded by
    validation, about 270 MB/s extrapolated and not measured.
- **No parallel benchmark** was run (`--workers` exists but is off by
  default).

**Scan results on the corpus** (targeted; research.md §10.10 has the full
table and analysis):

| Image | Candidates | Valid | Live | Backup-reachable | Unreferenced | Orphans outside map | Legacy-compatible |
|---|---|---|---|---|---|---|---|
| `sandbox.img` | 85 | 84 | 20 | 34 | 30 | 20 | 71 |
| `m1_xxhash` | 367 | 362 | 22 | 24 | 316 | 172 | 355 |
| `m1_sha256_bgt` | 401 | 395 | 24 | 26 | 345 | 181 | 387 |

**Deviations** (with rationale):
- **Parity on the legacy definition.** The DoD's "71 orphans, 21 outside
  map" is the prototype's definition (generation, not reachability). btrfska
  asserts it through the compatibility flag `legacy_orphan`, with identical
  offsets. The reachability orphans (64 on sandbox) are reconciled in the
  table above.
- **Superblock copies are cut out of regions.** Legacy probed the 64 MiB
  mirror and counted it as its one checksum failure. The kernel never places
  a tree block over a superblock copy (block-group.c:2277-2330). The
  reserved area is 0–68 KiB, where legacy skipped 0–80 KiB (64 KiB +
  nodesize).
- **Probing is at 4 KiB,** as plan.md M2 asks. On the sandbox it finds the
  same 85 candidates as a nodesize probe would.
- **Block-group input** is used to confirm a DATA exclusion. That is the
  instruction's "if block-group info is needed": chunk types alone could
  hide a range behind one altered item.
- **The live set lives in `scan/classify.py`**, not `scan/live_set.py`
  (plan.md §4.1 names that file); the plan's status line says so. The
  extent-tree walk is a cross-check, not the live set.
- **Expectations corrected after the first run.** None of these changed
  code:
  - The sandbox reconciliation had assumed 0 invalid candidates. The
    diagnosis found the empty generation-1 fs-tree leaf failing `nritems`,
    so the classes became 28 unreferenced + 1 invalid and 20/20 outside the
    map.
  - The first test used an exclusive 0x520000 bound. The catalog's
    "0x500000–0x520000" names block starts.
  - The CLI test's guessed METADATA region counts (32/32/10/22) became
    30/30/9/21. The new numbers were confirmed by counting the `--json`
    records independently of `summarize`.
- **Log-tree blocks** carry generation = superblock generation + 1. The
  scan's generation check (node.py, unchanged) would mark them invalid, and
  the log walk would not descend. No corpus image has a log tree; this is
  left for M2b/M3.
- **Walk cost.** Walks are deduplicated only by root bytenr: snapshots that
  share subtrees re-walk them. `classify` returns a list, and
  `build_regions` is O(intervals × stripes). All are adequate for this
  corpus; M3's catalog is the place to stream and share.
- **EXP-003 specifics.**
  - Warm runs were not fully cached (82–93 %); this is reported, not
    hidden.
  - The environment record's QEMU and guest lines are irrelevant (no guest
    runs).
  - The 10 GiB image was deleted after the runs (`bench_scan.py clean`); it
    is regenerable and hash-verified.

**Verification** (local, branch `feature/m2a-scan-kernel` at `5397405`;
logs in `images/scratch/m2a/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img; stat -c '%y' sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all) | `uv run pytest -q` | `673 passed` (was 613) |
| vm tests | `uv run pytest -m vm -q` | `51 passed, 622 deselected` |
| Tests without vm | `uv run pytest -m "not vm" -q` | `622 passed, 51 deselected` |
| New scan modules | `uv run pytest -q tests/test_scan_regions.py tests/test_scan_kernel.py tests/test_scan_classify.py` | `52 passed` |
| Read-only scan and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; no `dissect` or `lzallright` import under `src/` (grep: 0) |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `57 files already formatted` |
| Lockfile | `uv lock --check` | `Resolved 15 packages` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Scan, sandbox | `uv run btrfska scan sandbox.img` | exit 0; output below |
| Scan, full sweep | `uv run btrfska scan sandbox.img --full-sweep` | exit 0; `full sweep, 8 regions, 268361728 bytes`; same classes |
| Scan, JSON | `uv run btrfska scan sandbox.img --json \| wc -l` | `85` |
| Scan, `m1_xxhash` | `uv run btrfska scan images/scenarios/m1_xxhash.img` | exit 0; output below |
| Scan, `m1_sha256_bgt` | `uv run btrfska scan images/scenarios/m1_sha256_bgt.img` | exit 0; output below |
| `sandbox.img` after | `sha256sum sandbox.img; stat -c '%y' sandbox.img` | unchanged hash and mtime |

**`btrfska scan` samples** (`images/scratch/m2a/verify/scan_*.txt`; empty
region lines omitted from the m1 samples):
```
$ uv run btrfska scan sandbox.img
btrfska scan: targeted, 7 regions, 259973120 bytes probed at 4096-byte alignment
skipped: reserved 0-69632
skipped: DATA|single 13631488-22020096
skipped: superblock 67108864-67112960
candidates: 85 (valid 84, invalid 1)
live: 20
orphans: 64 (backup_reachable 34, unreferenced 30)
outside current chunk map: 20 valid nodes (20 orphans)
header bytenr not mapping to the node's physical offset: 20 valid nodes
legacy-compatible orphans (csum ok, generation < 14, nodesize-aligned): 71 (21 outside current chunk map)
extent tree: 10 tree blocks; reached only by walks: 0; listed only by the extent tree: 0
region unmapped_gap 69632-13631488: candidates 21, valid 20, live 0, orphans 20
region SYSTEM|DUP 22020096-30408704 (chunk 22020096 stripe 0): candidates 2, valid 2, live 1, orphans 1
region SYSTEM|DUP 30408704-38797312 (chunk 22020096 stripe 1): candidates 2, valid 2, live 1, orphans 1
region METADATA|DUP 38797312-67108864 (chunk 30408704 stripe 0): candidates 30, valid 30, live 9, orphans 21
region METADATA|DUP 67112960-72351744 (chunk 30408704 stripe 0): candidates 0, valid 0, live 0, orphans 0
region METADATA|DUP 72351744-105906176 (chunk 30408704 stripe 1): candidates 30, valid 30, live 9, orphans 21
region unmapped_gap 105906176-268435456: candidates 0, valid 0, live 0, orphans 0

$ uv run btrfska scan images/scenarios/m1_xxhash.img
btrfska scan: targeted, 7 regions, 469688320 bytes probed at 4096-byte alignment
skipped: DATA|single 307232768-374341632
candidates: 367 (valid 362, invalid 5)
live: 22
orphans: 340 (backup_reachable 24, unreferenced 316)
outside current chunk map: 172 valid nodes (172 orphans)
legacy-compatible orphans (csum ok, generation < 38, nodesize-aligned): 355 (177 outside current chunk map)
extent tree: 11 tree blocks; reached only by walks: 0; listed only by the extent tree: 0
region unmapped_gap 69632-67108864: candidates 102, valid 97, live 0, orphans 97
region unmapped_gap 67112960-105906176: candidates 75, valid 75, live 0, orphans 75
region METADATA|DUP 105906176-173015040 (chunk 63963136 stripe 0): candidates 91, valid 91, live 10, orphans 81

$ uv run btrfska scan images/scenarios/m1_sha256_bgt.img
candidates: 401 (valid 395, invalid 6)
live: 24
orphans: 371 (backup_reachable 26, unreferenced 345)
outside current chunk map: 181 valid nodes (181 orphans)
legacy-compatible orphans (csum ok, generation < 38, nodesize-aligned): 387 (187 outside current chunk map)
extent tree: 12 tree blocks; reached only by walks: 0; listed only by the extent tree: 0
```

**Research notes.** research.md §10.10 records:
- orphans per image;
- how few orphans backup roots reach on the s01 images (24–26 of
  338–371);
- what the orphans outside the map on generated images are: pre-balance
  metadata stripes and mkfs residue, with owners and generations;
- mkfs generation-1 blocks without the WRITTEN flag;
- current-generation orphans;
- the extent-tree cross-check agreeing everywhere.

**For M2b.**
- **Old-root discovery** can group `NodeRecord`s with owner 1 by (level,
  generation) straight from `scan_image`. Most history lies outside the
  current map, and none of those headers map: 154 and 162 blocks on the s01
  images claim pre-balance logical addresses. Reading their pointers needs
  a historical chunk map, for example from the generation-30 backup chunk
  root (§10.8).
- **Discard trio.** `probe_stale_metadata.py` counts every 4 KiB block with
  the fsid, skipping only the superblock blocks; column 2 applies
  generation < superblock generation without a checksum. Exact equality
  therefore needs:
  - `--full-sweep`, since the probe also reads DATA chunks;
  - counting *all* candidates, invalid ones included;
  - the probe's own generation rule, not `legacy_orphan`, which
    additionally requires csum and nodesize alignment.

  The reserved-range difference (0–68 KiB versus the probe's single skipped
  block at 64 KiB) must be checked on those images.
- **Log trees.** Decide how a log tree (generation = superblock + 1) is
  validated before a crashed image enters the corpus. Done in the review
  fixes below.

### Review fixes

PR #11 was approved with fixes (three medium, three low). Each code fix was
written test-first and the tests were seen failing. All commits are local on
`feature/m2a-scan-kernel`, on top of `1640fea`, and are not pushed:
- `d173604` Validate log-tree blocks in a log context: owner TREE_LOG, generation superblock + 1
- `9d6c278` Add the m2_logtree corpus image: fsynced log trees left by a power-off without commit
- `216bc93` Stream worker scan results in order through a bounded window of 4 MiB pieces
- `97210d8` Stream scan classification, classify log-tree copies live and report bytes skipped as DATA
- `7c1f535` Add the EXP-003 density sweep and per-allocated-byte throughput to the scan benchmark
- `84dea39` Document log trees, scan limitations, bounded memory and the EXP-003 density sweep
- this subsection (the commit after `84dea39`)

**Sources.** Kernel tag v7.0 files fetched into
`images/scratch/m2a-fixes/kernel/`: `disk-io.c`, `tree-log.c`,
`transaction.c`, `ctree.c`, `extent-tree.c`, `tree-checker.c`,
`btrfs_tree.h`, `ctree.h`. They are cited by line only, never copied. Raw
logs are in `images/scratch/m2a-fixes/{logtree,memory,verify}/` and
`images/scratch/exp/EXP-003/`.

1. **Log-tree blocks could never be classified live (medium).**
   - **Verified facts.** Two of the review's premises were corrected
     against the source; the defect itself was real.
     - **Owner.** `BTRFS_TREE_LOG_OBJECTID` is −6 (btrfs_tree.h:92); −7 is
       `TREE_LOG_FIXUP`. Every log block carries it as header owner
       (disk-io.c:861-867, 887; ctree.c:520; extent-tree.c:5308).
     - **Keys.** The log root tree's ROOT_ITEM keys are (TREE_LOG,
       ROOT_ITEM, subvolume id) (disk-io.c:865-867, 942;
       tree-log.c:7720-7744). So the walk already expected owner −6, not the
       subvolume id. The owner was simply never checked: `_owner_ok`
       skipped TREE_LOG, as the kernel does (tree-checker.c:2270).
     - **Generation: exactly superblock + 1.** Log blocks take the running
       transid (extent-tree.c:5306), which is the committed generation + 1
       (transaction.c:392-393). btrfs_sync_log writes `super_for_commit`
       under `tree_log_mutex` after the previous commit's superblock
       (tree-log.c:3554-3580, transaction.c:2535-2581). Replay reads the log
       root with transid generation + 1 (disk-io.c:2017-2019), and logs are
       freed at every commit.
     - **log_root_transid.** v7.0 has no `log_root_transid` function. The
       superblock field is `__unused_log_root_transid` (btrfs_tree.h:695)
       and is 0 on disk.
   - **Actual defects.**
     - The node generation check (≤ superblock) failed every log block, so
       the log walk stopped at its root. The pre-fix scan of `m2_logtree`
       reported `tree 18446744073709551610 node 30982144 is invalid: …
       generation 9 > superblock generation 8`
       (`logtree/scan_before_fix.txt`).
     - The log root had no expected generation.
     - Subvolume logs (tree id TREE_LOG) were searched for ROOT_ITEMs as if
       they were root trees.
     - Scanned log copies failed the context-free generation check.
   - **Fix.**
     - `Expect.log` and `TreeRoot.log`. The walker propagates the log
       context to children.
     - In a log context `check_block` requires generation ==
       superblock + 1, and the owner check is exact for TREE_LOG.
     - `classify.walk_root_set` anchors the log only at the superblock's
       `log_root`, with generation + 1. Only ROOT_ITEMs keyed
       (TREE_LOG, …) in that tree name subvolume logs, and their leaves are
       not searched. A ROOT_ITEM keyed like a log inside the ordinary root
       tree gets no log context.
     - A scanned copy has its generation check redone in the log context
       only when the log walk reached that exact (logical, physical) copy.
       Its status is then `live`, with the new record key `log_tree`.
     - Log blocks are left out of `walk_only`, since they have no
       extent-tree reference (extent-tree.c:5392). The summary adds
       `log tree: N blocks (M live copies)`.
   - **Corpus image `m2_logtree`** (manifest row, SHA-256 `2c8b95df…3b16`).
     - Scenario `corpus/vm/scenarios/logtree.guest.sh`, mounted with
       `commit=300`: commit two files, fsync new files in fs tree 5 and
       `sv1` and append to one, then `echo o > /proc/sysrq-trigger`.
     - `make_image.sh` gains `DONE_MARKER`, because the guest never reaches
       its umount.
     - Result: superblock generation 8, log_root 30982144. Three more
       generated runs gave the same generation and log_root (the images
       were deleted).
     - Oracle: `btrfs inspect-internal dump-tree -t 18446744073709551610`
       names leaves 30982144 and 30965760, and the scan classifies exactly
       those 2 blocks, 4 DUP copies, as `live`/`log_tree`.
     - Two superseded generation-9 log leaves from the first fsync's log
       commit (30932992 and 30949376, 2 copies each) remain `invalid` on
       generation: nothing reaches them.
   - **Tests** (failing first):
     - `test_node` ×2 and `test_tree` ×1: TypeError, no `log` in `Expect`;
     - `test_scan_classify`: ImportError on `walk_root_set`, then the
       synthetic log walk, scanned log copy and streaming tests;
     - vm `test_m2_logtree_log_blocks_are_live_log_tree_copies`, with the
       dump-tree oracle;
     - the manifest SHA-256.
2. **Memory was O(candidates) (medium).**
   - **Fix.**
     - `classify` is a generator, and `Tally` keeps running counters.
       `ScanResult.classified` is a one-shot stream, and `.summary` needs it
       exhausted.
     - `cmd_scan` prints each record while the image is open.
     - Workers: a pool initializer opens the image once per process, and
       jobs are 4 MiB pieces. At most `workers` pieces are pending ahead of
       the one being yielded, so the parent holds at most 4 × 1024 records.
       Output order is physical.
     - The classify docstring states the remaining bound: the reachable
       trees, not the candidates.
   - **Test** `tests/test_scan_hostile.py` (sandbox marker). A copy of
     `sandbox.img` has fsid-matching garbage in all 39 680 sectors of the
     trailing gap, 39 765 candidates in all. `scan --json` runs under
     tracemalloc with workers 1 and 4; each peak must stay below 16 MiB, and
     both outputs must be byte-identical (SHA-256 of stdout, equal stderr).
     It failed first with `--workers 1: peak 78441738 bytes`. The sandbox
     CLI test now compares `--workers 4` with one process.
   - **Measured on the review's `flood.img`** (`memory/peak.py`, 5
     sequential runs each; `/usr/bin/time -v` for RSS):

     | Version | Workers | tracemalloc peak | Wall s median (range) | Max RSS |
     |---|---|---|---|---|
     | before (`1640fea`) | 1 | 89.3 MB | 1.39 (1.37–1.42) | 384 MB |
     | before (`1640fea`) | 4 | 267.6 MB | 2.93 (2.64–3.24) | 308 MB (parent) |
     | after | 1 | 2.3 MB | 1.40 (1.37–1.53) | 296 MB |
     | after | 4 | 16.6 MB | 1.31 (1.24–1.35) | 53 MB (parent) |

     RSS includes the image's file-backed pages (about 250 MB of a mapped
     256 MB image), so the heap peak is the comparable figure. Four workers
     are now about as fast as one, not faster, so the default stays 1
     (README, kernel docstring). The `--workers 1` and `--workers 4` JSON
     are byte-identical (`cmp`, 39 765 lines).
3. **Targeted mode misses metadata in reallocated DATA ranges (medium).**
   - The README has a limitation paragraph, and the `regions.py` docstring
     is corrected: it no longer implies that a skipped DATA range holds no
     tree blocks.
   - New summary line `skipped as DATA: N bytes (use --full-sweep to include
     reallocated ranges)`, or `(full sweep)` with 0 bytes, and the summary
     field `skipped_data_bytes`. There is no JSON summary record: `--json`
     prints the summary lines on stderr, and the field is in
     `scan_image(...).summary`, the dict M3 stores.
   - Tests (failing first): a valid fs-tree leaf is planted 1 MiB into the
     sandbox DATA chunk. Targeted, it is not found and 8 388 608 bytes are
     reported; with `--full-sweep` it is found `unreferenced` in
     `DATA|single`. Also the summary field, targeted and full, and the
     sandbox CLI lines.
   - research.md §10.10 records it as a forensic consideration.
4. **Foreign-FSID limitation (low).** Noted in the README limitations and
   research.md §10.10. plan.md M6 gains an optional foreign-FSID discovery
   mode that feeds the foreign-superblock finding.
5. **EXP-003 headline (low).**
   - **Non-hole throughput.** `bench_scan.py allocated` recomputes the
     N = 5 runs per allocated byte (5 771 366 400 of 10 GiB):

     | Cell | Image MB/s | Allocated MB/s |
     |---|---|---|
     | prefilter cold | 3743.1 | 2011.6 (1884.2–2327.2) |
     | prefilter warm | 6138.6 | 3299.8 (1947.2–4494.8) |
     | full cold | 3277.1 | 1761.2 (1734.7–1794.0) |
     | full warm | 5691.0 | 3058.5 (2380.9–3777.1) |

   - **Density sweep** (`sweep-generate`, `sweep-run --runs 5`; EXP-003
     §6.1). Dense 1 GiB images: pool tree blocks at density %, random bytes
     elsewhere. Full validation, one process, sequential; `mincore()`
     showed 0 % cached cold and 100 % warm. N = 5 median (range), MB/s:

     | Density | Cold | Warm |
     |---|---|---|
     | 0 % | 3451.7 (3362.5–3456.7) | 65669.9 (55699.1–68240.6) |
     | 10 % | 2142.5 (2069.7–2159.2) | 5685.7 (5056.6–6037.6) |
     | 100 % | 512.2 (501.0–529.7) | 615.9 (576.0–628.2) |

     These replace the review's single runs (100 %: 262 cold and 287 warm;
     10 %: 803 and 2 384, on sparse images). Validation costs about 27 µs
     per candidate. Every run's hits and valid counts equal the
     generator's.
   - The 3 GiB of sweep images were deleted (`bench_scan.py clean`);
     `sweep-generate --verify` rebuilds their hashes.
6. **Wording (low).** The extent-tree check is now called a content
   cross-check that is not independent of the current root tree, in
   `classify.py`, the README and research.md §10.10. The only "independent"
   was in the PR #11 description, which was not edited (no remote
   changes); replacement text is in
   `images/scratch/m2a-fixes/pr_body_changes.md`.

**Deviation.** The review asked for owner −7. The kernel's value is −6, and
btrfska already used −6 (`ondisk.TREE_LOG_OBJECTID = _U64 - 6`).

**Verification** (local, at `84dea39`; logs in
`images/scratch/m2a-fixes/verify/`):

| Check | Command | Result |
|---|---|---|
| Tests (all) | `uv run pytest -q` | `684 passed` (was 673) |
| vm tests | `uv run pytest -m vm -q` | `53 passed, 631 deselected` |
| Read-only and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; grep for `dissect`/`lzallright` imports under `src/`: 0 |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `58 files already formatted` |
| Lockfile | `uv lock --check` | `Resolved 15 packages` |
| Scan, sandbox | `uv run btrfska scan sandbox.img` | exit 0; classes unchanged (85/84/1, live 20, orphans 64); `skipped as DATA: 8388608 bytes`; `log tree: 0 blocks` |
| Scan, flood | `uv run btrfska scan images/scratch/m2a-review/flood.img` | exit 0; `candidates: 39765 (valid 84, invalid 39681)`, same classes as sandbox |
| Scan, `m2_logtree` | `uv run btrfska scan images/scenarios/m2_logtree.img` | exit 0; 89 candidates (80 valid), live 24, orphans 56 (30/26), `log tree: 2 blocks (4 live copies)`, walks-only 0, `skipped as DATA: 75497472 bytes`; 3 `backup:5` problems (reused blocks under an old backup root) |
| `sandbox.img` after | `sha256sum sandbox.img; stat -c '%y' sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |

**For M2b.**
- The superseded log leaves on `m2_logtree` show that a log commit leaves
  generation sb + 1 residue that no walk reaches. Old-root discovery should
  group owner −6 blocks by generation, as for owner 1.
- Run the discard trio with `--full-sweep` as well: reallocated DATA ranges
  are exactly where balance leaves stale metadata.
- The oldest backup root on small images names reused blocks (`backup:5`
  problems on `m2_logtree`). That is expected, but the summary should
  separate it from damage.

## 2026-09-15 — M1c: extent reads, decompression, oracles, EXP-001

- **Branch:** `feature/m1c-extent-reads` (from `main` at `2af52df`). This is
  the last of three M1 PRs. It covers plan.md §5 M1 task 8 (extent reads,
  decompression, `cat`, oracles) and task 11 (EXP-001), and closes the M1
  DoD.
- **Commits:**
  - `f2d57c6` Add a bounds-checked LZO1X decoder with the dissect.util vectors and hostile-stream tests
  - `51279c9` Split chunk-map ranges at chunk ends and 64 KiB stripe boundaries
  - `d807770` Decompress zlib, zstd and btrfs-framed LZO extents within the kernel's bounds
  - `3081445` Read extents and assemble file content with a provenance record per extent
  - `6fe1bd2` Add btrfska cat: file bytes to stdout, extent records to stderr
  - `36e7141` Add the dissect.btrfs and lzallright oracles and the LZO hostile-input harness
  - `6604a99` Add EXP-001: checksum-type coverage of the legacy prototype and btrfska, with an environment record script
  - `242b3f7` Cite the LZO harness counts and the 4 421-byte worst case in the plan, and mark M1 done
  - `2deef18` Record M1c extent-read, oracle and legacy findings
  - `461209d` Report i_size clipping only when an extent reaches past the sector holding EOF
  - `3a7e957` Update the README status for M1 and document the cat records
  - `02e192e` Record EXP-001: legacy accepts no tree block on non-crc32c images
  - this catalog entry (the commit after `02e192e`)

**What was done.**
- **Tests first.** Each unit test module was written and seen failing before
  its implementation:
  - `test_lzo`, `test_compress` and `test_extents` failed with
    ModuleNotFoundError;
  - the `pieces` tests failed with AttributeError;
  - the `cat` tests with `invalid choice: 'cat'`;
  - the clipping test on an assertion.

  The oracle tests are the exception (see Deviations).
- **Kernel references** are tag v7.0, fetched from GitHub torvalds/linux into
  `images/scratch/m1c/kernel/`: `fs/btrfs/lzo.c`, `compression.[ch]`,
  `zlib.c`, `zstd.c`, `inode.c`, `tree-checker.c`, `volumes.h`,
  `include/linux/lzo.h` and `Documentation/staging/lzo.rst`.
  `lib/lzo/lzo1x_decompress_safe.c` (GPL) was fetched by mistake and deleted
  unread, so the decoder stays written from lzo.rst and dissect.util's
  Apache-2.0 code.

1. **`substrate/lzo.py`.** An LZO1X decoder written from lzo.rst.
   - `decompress(src, max_out)` raises only `LzoError(kind, detail)`. Its kinds
     follow the kernel's `LZO_E_*` codes: `input_overrun`, `output_overrun`,
     `lookbehind_overrun`, `missing_end_marker`, `trailing_input`, and
     `unsupported_version` for LZO-RLE.
   - Every read, copy and back-reference is checked before it happens.
   - `tests/test_lzo.py` (45 tests):
     - the four dissect.util 3.24 vectors (Apache-2.0, attributed; the
       8 334-hex-digit "larger" stream is in `tests/fixtures/lzo_larger.hex`);
     - the crafted lookbehind stream (`lookbehind_overrun`) and all nine
       truncations of it;
     - a missing end marker, output bound, trailing input and version byte;
     - hand-assembled instructions of every opcode class, cross-checked with
       lzallright before use;
     - 3 000 random streams and 1 800 bit-flipped vectors that raise only
       `LzoError` and never exceed the bound.
2. **`substrate/compress.py`.** `decompress(compression, data, min_out=,
   max_out=, sectorsize=, inline=)` returns `Decoded(data, slack)` or raises
   `DecodeError(kind, detail)`.
   - **zlib** follows `zlib_decompress_bio`: it inflates raw deflate after a
     valid header, so the adler32 trailer is not checked.
   - **zstd** decodes one frame with `compression.zstd`.
   - Both are capped with `max_length`, and a one-byte probe tells a stream
     that ends exactly at the cap from one that overruns it.
   - **LZO** uses the btrfs framing: a LE32 total, then LE32 segment headers
     that skip a sector tail of fewer than 4 bytes.
     - Regular extents: the total may not exceed min(128 KiB, extent) nor
       leave a whole sector unused (`lzo_decompress_bio`).
     - Each segment is at most `lzo1x_worst_compress` = 4 421 bytes and
       decodes to at most one sector; reading stops once `min_out` is
       reached.
     - Inline extents hold exactly one segment filling the item
       (`lzo_decompress`).
   - `tests/test_compress.py` (40 tests) covers:
     - sector-tail padding framing: 0–5 bytes left, of which 1–3 are
       padded;
     - a straddling header, invalid totals and an oversized or overrunning
       segment;
     - decoder kinds surfacing as `lzo_<kind>`;
     - overrun, short, truncated and corrupt input for zlib and zstd;
     - a property test of 600 random or bit-flipped inputs per codec, in
       regular and inline modes.
3. **`ChunkMap.pieces(logical, length)`** splits a range at chunk ends and, in
   striped profiles (RAID0/10/5/6), at 64 KiB boundaries.
   - `BTRFS_STRIPE_LEN` is verified as `SZ_64K` in v7.0 `volumes.h:45`.
   - 8 tests, including RAID0/10/5/6 splits that `copies()` accepts piece by
     piece.
4. **`substrate/extents.py`.**
   - `read_extent(reader, item, leaf)` → `(ExtentRead, bytes | None)`:
     - handles inline, regular, compressed and prealloc extents, and explicit
       holes (`disk_bytenr` 0);
     - honours `offset`, `num_bytes` and `ram_bytes`;
     - reads through `reader.chunk_map`, whichever map that is.
   - `read_file(reader, root, inode, no_holes=)` → `FileRead`:
     - walks the fs tree and inserts implicit holes, reported as problems
       when NO_HOLES is unset;
     - clips to i_size;
     - reports overlaps, a missing inode and a directory as errors.
   - `FileRead.chunks()` raises `IncompleteRead` before yielding anything
     when any error exists.
   - `tests/test_extents.py` (29 tests) uses synthetic images under
     `images/scratch/`: every kind, offset handling for all three codecs,
     holes, clipping, overlap, decode failure, nine invalid-extent cases,
     a RAID0 stripe crossing, a divergent DUP copy, a missing-device fallback,
     JSON-readiness and 300 garbage items.
5. **`btrfska cat IMAGE --inode N [--root current|backup:GEN|bytenr:N]
   [--tree fs|ID] [--allow-unsupported]`.**
   - It writes the file bytes to stdout only when the read is complete.
   - stderr carries one JSON `extent` record per extent, one `file` record,
     then a summary or `btrfska cat: error: …`.
   - Exit codes: 0 read, 1 incomplete or unknown root, 2 refused.
   - The gate handling is shared with `walk` (`_open_checked`).
   - README.md gains "`btrfska cat` output"; `test_readme_documents_every_cat_key`
     checks every record key.
   - The read-only AST scan still passes: `cat` writes only to
     `sys.stdout.buffer` and opens nothing.
6. **Oracles** (`tests/oracle/`).
   - `dissect.btrfs==1.10.*` and `lzallright==0.2.*` join the `dev` group;
     the lock resolves to dissect.btrfs 1.10, dissect.util 3.24,
     dissect.cstruct 4.7 and lzallright 0.2.6.
   - Every oracle module calls `pytest.importorskip`.
7. **LZO hostile-input harness** `tests/oracle/lzo_hostile.py`: the plan
   §3.5 experiment as a committed, seeded script (results below).
8. **EXP-001** (`experiments/exp001.py`, `experiments/env.sh`,
   `experiments/EXP-001.md`).
9. **Docs.**
   - research.md §10.9 is new, and its §10.6 LZO count is updated.
   - plan.md §3.5 and §9 now cite the harness counts and the 4 421-byte worst
     case, and M1 gains a DoD status line.
   - The README status is updated.

**Design decisions.**
- **Read records are flat, frozen dataclasses** (`ExtentRead`, `DataRange`,
  `DataCopy`), JSON-ready through `dataclasses.asdict`. One record describes:
  - the source item (leaf, slot, generation);
  - the extent fields;
  - the chunk-map source;
  - every physical range with every copy (mirror, devid, physical, readable,
    used, matches);
  - the decoder output length, the SHA-256 of the supplied bytes, an error
    kind and detail, and non-fatal problems.

  M3's `file_extents` and `provenance` rows can store it as is.
- **The kernel read path sets the bounds.** A regular compressed extent must
  decode to exactly `ram_bytes`. A compressed inline extent decodes up to one
  sector and must cover min(ram_bytes, sectorsize); the probe showed that the
  kernel compresses the whole sector (research.md §10.9).
- **Non-zero bytes are reported, never returned.** That covers bytes past
  `ram_bytes` in an inline stream, and slack after a compressed stream or the
  LZO total. They are problems, never content.
- **Data copies.** Every copy of a data range is read; the first readable one
  is used and the others are compared with it. Data checksums arrive in M6,
  so no copy can be preferred on evidence yet.
- **Clipping at i_size** is a problem only when an extent reaches past the
  sector that holds EOF. A partial last sector is normal, and reporting it
  made every non-aligned file noisy (seen in the `cat` samples below).
- **Hostile values fail cleanly.** Compressed `ram_bytes` and
  `disk_num_bytes` outside (0, 128 KiB] (`BTRFS_MAX_UNCOMPRESSED`,
  `BTRFS_MAX_COMPRESSED`) are `invalid_extent`, so a hostile `ram_bytes` of
  2^63 cannot allocate. Zero runs are yielded in pieces of at most 1 MiB.

**Oracle results** (all M1 images present and matching `corpus/manifest.tsv`,
so none were regenerated). Command: `uv run pytest -q tests/oracle`, rows
dumped to `images/scratch/m1c/oracle/parity_rows.txt`.

| Image | Root sets compared | File reads (distinct files) | Compression | With guest/script SHA-256 | Equal to dissect.btrfs | Equal to ground truth |
|---|---|---|---|---|---|---|
| `sandbox.img` | backup:11–14, current | 2 (2): `target_file.txt` gen 11, `large_target.txt` gen 13 | none | 0 (no scenario log) | 2 | n/a |
| `m1_xxhash` | backup:35–38, current | 50 (10) | zstd | 50 | 50 | 50 |
| `m1_lzo` | backup:35–38, current | 50 (10) | lzo | 50 | 50 | 50 |
| `m1_zlib` | backup:35–38, current | 50 (10) | zlib | 50 | 50 | 50 |

- The reads cover 152 files: 0 mismatches and 0 incomplete reads.
- dissect's own directory walk lists exactly the regular files btrfska
  inventories, in every subvolume of every root set.
- **Deleted files.** The s01 deleted files (`deleted_big.txt`, 288 894 B in
  3 extents; `deleted_inline.txt`, 13 B compressed inline) read from
  snapshot 257 in every root set.
- **Backup generations.** dissect reached every backup generation once its
  `_root_tree` was swapped (test-only), so no root set fell back to guest
  hashes only.
- **dissect discrepancies:** no byte differences. There are behavioural ones
  (research.md §10.9):
  - dissect zero-fills reads of unmapped logical addresses: logical 13 631 488
    on `m1_xxhash` reads as zeros, where btrfska raises `UnmappedAddress`;
  - it checks the zlib adler32, which the kernel skips;
  - its LZO loop ignores the total length.
- **LZO against lzallright** (`test_lzo_oracle.py`): 2 000 seeded round
  trips are identical, and 1 000 bit-flipped sectors agree once an lzallright
  output over 4 KiB counts as a failure.

**LZO harness results** (`uv run python tests/oracle/lzo_hostile.py --seeds 1 2
3 4 5 --json images/scratch/m1c/lzo_hostile/results.json`, 20.7 s wall,
deterministic per seed). Per seed: 2 000 round-trip vectors, the crafted
stream, a half-truncated compressed sector, and 300 bit flips of one 4 KiB
sector. Entries are median (range) over the 5 seeds.

| Decoder | Round trip identical | Crafted stream | Truncated | Flips: correct | Flips: wrong bytes ≤ 4 KiB | Flips: > 4 KiB | Flips: `Exception` | Flips: non-`Exception` |
|---|---|---|---|---|---|---|---|---|
| btrfska | 2000 (all) | `LzoError` | `LzoError` | 0 (0–1) | 227 (218–231) | 0 (0–0) | 72 (68–82), all `LzoError` | 0 |
| lzallright 0.2.6 | 2000 (all) | `LZOError` | `LZOError` | 0 (0–1) | 227 (218–231) | 36 (32–41) | 39 (31–47) | 0 |
| dissect.util 3.24 pure Python | 2000 (all) | returns 4 bytes | `IndexError` | 1 (0–1) | 267 (258–277) | 30 (22–41) | 1 (0–2) | 0 |
| dissect.util 3.24 native | 2000 (all) | `PanicException` | `ValueError` | 0 (0–1) | 227 (218–231) | 36 (32–41) | 0 (0–2) | 37 (31–46) |

- btrfska and lzallright agree on 300 of 300 flips in every seed, with an
  output over 4 KiB counted as a failure.
- plan.md §3.5's earlier single scratch-run counts (58/300 panics, 139–160
  wrong) are superseded by these.

**EXP-001 summary** (`experiments/EXP-001.md`; `uv run python
experiments/exp001.py --runs 2`; the two runs were identical; recorded at
`2deef18` with a clean tree):

| Image | csum | Tool | Tree blocks accepted | Tree blocks rejected | Files listed per generation | Distinct files byte-identical / listed |
|---|---|---|---|---|---|---|
| `sandbox` | crc32c | legacy | 85 | 1 | gen 11: 1, gen 13: 1 | 2 / 2 |
| `sandbox` | crc32c | btrfska | 27 | 0 | backup:11: 1, backup:12: 0, backup:13: 1, backup:14: 0, current: 0 | 2 / 2 |
| `m1_xxhash` | xxhash64 | legacy | 0 | 368 | none | 0 / 0 |
| `m1_xxhash` | xxhash64 | btrfska | 23 | 0 | backup:35–38 and current: 10 each | 10 / 10 |
| `m1_sha256_bgt` | sha256 | legacy | 0 | 402 | none | 0 / 0 |
| `m1_sha256_bgt` | sha256 | btrfska | 25 | 0 | backup:35–38 and current: 10 each | 10 / 10 |
| `m1_blake2b` | blake2b | legacy | 0 | 368 | none | 0 / 0 |
| `m1_blake2b` | blake2b | btrfska | 23 | 0 | backup:35–38 and current: 10 each | 10 / 10 |

- Legacy's 85 accepted blocks on the sandbox are 71 orphans and 14
  current-generation leaves.
- The sandbox reference is dissect.btrfs (no scenario log). Image SHA-256s
  were unchanged by both tools.
- Before the result was recorded, a first version of the stricter "identical
  every time" rule counted legacy's `(duplicate)` markers as mismatches (1/2
  on the sandbox). Root cause: legacy de-duplicates extents and writes no
  output for later entries (legacy/utils/btree.py:659-666). Fixed in
  `6604a99` (amended) before the recorded run.

**M1 DoD, bullet by bullet** (all met):

| DoD bullet | Status | Evidence |
|---|---|---|
| Backup states gens 11–14 of `sandbox.img` walked with anchored provenance; task-1 ground-truth tests green | met (M1b) | `tests/test_ground_truth.py` (incl. `test_fs_tree_contents_per_generation[11..14]`) in the 601 passing tests; every `walk` record carries `root.via` (`backup slot N`); in this milestone `cat --root backup:13` reads `large_target.txt` through slot 0 |
| `m1_xxhash`, `m1_sha256_bgt`, `m1_blake2b` fully walked; legacy finds nothing on non-crc32c images | met (M1b + M1c) | EXP-001 above: btrfska accepts 23/25/23 blocks and rejects 0; legacy accepts 0 and rejects 368/402/368. Block-by-block `dump-tree` agreement: M1b `test_walks_match_dump_tree_block_by_block` (vm, passing) |
| `m1_unknown_incompat` refused, exit ≠ 0, `UNSUPPORTED_INCOMPAT` line | met (M1a/M1b) | `uv run btrfska info images/scenarios/m1_unknown_incompat.img` exits 2 with `gate: REFUSED` and `UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40`; `walk` the same (exit 2); `cat` has a synthetic test (`test_cat_applies_the_incompat_gate`) |
| `m1_badnode` reports a csum failure for that node instead of items | met (M1b, with the two-image deviation) | `walk images/scenarios/m1_badnode_both.img --tree 256` exits 0 with one `invalid_node` for 65159168: csum false on both copies, `mirror 1: csum: stored 6024af66d4ba356f computed 04ee33fa2966cb51` (and mirror 2), 0 items. `m1_badnode`, one corrupt copy: mirror 1 reported `csum` false, and the items come from mirror 2 under the mirror policy |
| `m1_mirror_damage` selects mirror 1 and reports it | met (M1a) | `info` exits 0: `mirror 0 @ 65536: INVALID (magic mismatch, csum mismatch)`, `selected: mirror 1 (generation 38)`, `kernel would mount: mirror 0 (invalid: …)`, `disagreements: mirror 0 invalid: magic mismatch, csum mismatch` |
| Task-8 oracle tests green: every file on `sandbox.img`, `m1_xxhash`, `m1_lzo`, `m1_zlib` byte-identical to dissect.btrfs and guest SHA-256s; LZO property tests pass | met (M1c) | Oracle table above (152/152), `uv run pytest -q tests/oracle` 11 passed; `sandbox.img` has no guest SHA-256s (no scenario log), so dissect is its only oracle; LZO property tests in `test_lzo.py` and `test_compress.py` pass |
| Import-boundary and read-only tests pass; `sandbox.img` hash unchanged | met | 53 passed; `sha256sum sandbox.img` unchanged before and after, mtime 2026-04-26 18:49:36 |

The plan has no per-milestone status markers, so M1 gained a single line:
"**Status 2026-09-15: done.**"

**Deviations** (with rationale):
- **LZO worst case is 4 421 bytes, not 4 419.** The v7.0 `lzo.h:21` macro
  (`x + x/16 + 64 + 3 + 2`) gives 4 421; the `lzo.c` comment and plan §3.5
  said 4 419. The plan is corrected.
- **LZO bounds are stricter than the kernel in two places.**
  - A segment may decode to at most one sector, as plan §3.5 specifies; the
    kernel's buffer is 4 421 bytes.
  - Bytes after the end marker are an error (`trailing_input`, the kernel's
    `LZO_E_INPUT_NOT_CONSUMED`).
- **LZO-RLE streams are refused.** A stream whose first byte is 17 and that
  is at least 5 bytes long is a versioned stream (lzo.rst); btrfska raises
  `unsupported_version`. btrfs never writes one, and refusing is louder than
  guessing at an untested encoding.
- **zlib and zstd must reach their end of stream.** The kernel's bio paths
  stop once `ram_bytes` are produced. No corpus extent hits the difference;
  a truncated stream with full output is reported rather than trusted.
- **A regular compressed extent must decode to exactly `ram_bytes`.** More
  output is `output_overrun`, although the kernel ignores it. The probe
  found exact lengths on every regular extent.
- **`cat` is minimal.**
  - It takes `--inode` only (no path lookup) and never writes files.
  - `read_file` walks the whole fs tree per inode (no key search); M3's
    catalog replaces repeated walks.
- **Oracle tests were not seen failing first.** They exercise code that
  already had failing-first unit tests. Their expectations come from
  dissect.btrfs, lzallright and the guest logs, not from btrfska. Mutation
  check: the harness found and classified every lzallright/btrfska
  disagreement (all over-bound outputs).
- **Skip check.** `uv run --no-dev` still used the synced venv. The skip was
  therefore shown by blocking the imports
  (`sys.modules['dissect'] = sys.modules['lzallright'] = None`); both oracle
  modules skip.
- **dissect reads backup generations** through a private attribute swap
  (`Btrfs._root_tree`), in tests and the EXP-001 script only.
- **`experiments/env.sh` arrives with EXP-001**, not EXP-000 as plan §7
  says, because EXP-001 is the first record to need it.
- **A clipping-report change came after EXP-001 ran** (`461209d`). It changes
  only `problems` strings, none of EXP-001's metrics.

**Verification** (local, branch `feature/m1c-extent-reads` at `02e192e`, all
M1 images present; logs in `images/scratch/m1c/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all) | `uv run pytest -q` | `601 passed` (was 461) |
| vm tests | `uv run pytest -m vm -q` | `44 passed, 557 deselected` |
| Tests without vm | `uv run pytest -m "not vm" -q` | `557 passed, 44 deselected` |
| Oracle subset | `uv run pytest -q tests/oracle` | `11 passed` |
| Oracles absent | the same tests with `dissect`/`lzallright` imports blocked | `2 skipped` |
| New unit modules | `uv run pytest -q tests/test_lzo.py tests/test_compress.py tests/test_extents.py` | `114 passed` |
| `cat` and `pieces` | `uv run pytest -q tests/test_cli.py -k cat`; `… tests/test_chunks.py -k pieces` | `7 passed`; `8 passed` |
| Read-only scan and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; `grep -rn 'dissect\|lzallright' src/` finds only the attribution in `lzo.py`'s docstring, no import |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `48 files already formatted` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Lockfile | `uv lock --check` | `Resolved 14 packages` |
| Shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init experiments/env.sh; do sh -n "$f"; done` | exit 0 |
| `sandbox.img` after | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime unchanged |

**`btrfska cat` samples** (`images/scratch/m1c/verify/cat_samples.txt`; long
lines trimmed with `…`; taken before `461209d`, whose clip message would now
be absent for the partial last sector):
```
$ uv run btrfska cat sandbox.img --root backup:13 --inode 257 | sha256sum
dbbe5517996826bd5861ac22b745d21d11219055d89243ca1aea0ad31f552b12  -
{"record":"extent","root":{"source":"backup:13","tree":"fs","tree_id":5,"bytenr":30539776,"level":0,"generation":13,"via":"backup slot 0"},"inode":257,"unsupported_format":false,"kind":"regular","file_offset":0,"length":5242880,"leaf":30539776,"slot":7,"generation":13,"compression":"none",…,"disk_bytenr":13631488,…,"chunk_map":"current","ranges":[{"logical":13631488,"length":5242880,"copies":[{"mirror":1,"devid":1,"physical":13631488,"readable":true,"used":true,"matches":null}]}],"decoded_bytes":null,"sha256":"dbbe55179968…",…}
{"record":"file",…,"inode":257,"unsupported_format":false,"size":5242880,"complete":true,"extents":1,"errors":[],"problems":[]}
btrfska cat: inode 257, 5242880 bytes, 1 extents

$ uv run btrfska cat images/scenarios/m1_lzo.img --tree 257 --inode 258 | sha256sum     # deleted_big.txt from the snapshot
44969d026ed4164dbe77d48d4d359e98ac4057008cafd61723be72bff83e5fd4  -                    # = guest SHA-256
extent 0: regular lzo, disk 164691968+77824 -> 131072 decoded, physical 307298304
extent 131072: regular lzo, disk 164769792+69632 -> 131072 decoded
extent 262144: regular lzo, disk 164839424+16384 -> 28672 decoded, 26750 supplied
btrfska cat: inode 258, 288894 bytes, 3 extents

$ uv run btrfska cat images/scenarios/m1_xxhash.img --root backup:35 --tree 257 --inode 259 | od -c
0000000   s   m   a   l   l       s   e   c   r   e   t  \n                                 # inline zstd, decoded_bytes 4096
btrfska cat: inode 259, 13 bytes, 1 extents

$ uv run btrfska cat sandbox.img --inode 257 | wc -c                                   # exit 1
0
btrfska cat: error: no INODE_ITEM for inode 257 in the tree at 30703616
```

**Research notes.** research.md §10.9 records:
- compressed inline extents holding a whole sector;
- zero slack after compressed streams;
- the kernel skipping the zlib adler32 check;
- read-stop semantics;
- the 4 421-byte worst case;
- an lzo.rst first-byte erratum;
- dissect.btrfs zero-filling unmapped addresses;
- historical generations reaching only post-balance extent addresses;
- how often corrupt LZO still decodes;
- legacy failure modes, among them "Move/Rename" artifacts that are really
  inode-number reuse.

**For M2 (scan kernel).**
- **Validating scanned blocks.** A physical block from the scan is validated
  with `node.check_block(block, ctx, None, expect)`.
- **Content through any map.** Content from a scanned or historical tree goes
  through `extents.read_file(NodeReader(img, chunk_map, ctx), TreeRoot(...),
  inode, no_holes=)`, and a `ChunkMap` built from other chunk items works
  unchanged. An extent in a chunk the map lacks is `unmapped`, never zeros.
- **No oracle for historical extents.** dissect.btrfs zero-fills such reads,
  so only guest SHA-256s can check them.
- **What the s01 corpus limits.** All four backup roots of every s01 image
  name the same `sv1` and snapshot leaves (gen 34). The pre-deletion `sv1`
  leaf and the pre-balance data addresses survive only as unreferenced
  blocks, which is exactly M2's target.
- **EXP-000 inputs.** `experiments/env.sh` now exists for EXP-000, and the
  discard trio images are under `images/scenarios/`.
- **Legacy's targeted scan** on the sandbox accepts 85 blocks (71 orphans and
  14 current leaves) and rejects 1 on crc32c. On every non-crc32c image it
  rejects all fsid-matching blocks. The M2 parity gate (71/21) compares
  against the sandbox only.
- **Detector candidates for M6.** Non-zero bytes past `ram_bytes` in inline
  streams and slack after compressed streams are already reported as
  problems.
- **CI.** CI's `uv sync --locked` installs the dev group, so the oracle LZO
  tests and the sandbox parity test run there (about 6 s); the vm parity tests
  skip.

### Review fixes

PR #10 was approved with fixes. Each code fix was written test-first and
the tests were seen failing. All commits are local on
`feature/m1c-extent-reads`, on top of `5a4c6cc`:
- `4182b80` Reject LZO end markers whose copy length is not 3
- `b89c812` Extend the LZO harness with truncation, insertion, deletion and random-stream corpora
- `db9b595` Bound uncompressed extent lengths by the image size and map read pieces lazily
- `9ea0bc5` Note in-memory file reads and qualify the EXP-001 block counts
- `c532192` Cite the extended LZO harness results
- this subsection (the commit after `c532192`)

1. **LZO end marker with any length code (medium).**
   - **Defect.** `lzo.py` treated every `0001HLLL` instruction at distance
     16384 as the end of the stream. The kernel accepts it only with copy
     length 3, that is `11 00 00`.
   - **Sources.** v7.0 `lib/lzo/lzo1x_decompress_safe.c`
     (sha256 `f481e9df6835eea59c555017e4446cbf6f8d4062d0c04a52fa99d4de5846be04`):
     - line 208 jumps to `eof_found` at that distance;
     - line 274 returns `LZO_E_ERROR` when `t != 3`.

     lzokay (MIT) `lzokay.cpp:284` checks `lblen != 3` the same way, and
     lzo.rst says the marker takes 3 bytes. This GPL file was fetched into
     `images/scratch/m1c/review/` only to confirm this one condition after
     the decoder existed. Just those lines were read, no code was taken from
     it, and it has been deleted, as has `lzodefs.h`. The `lzo.py` docstring
     says so.
   - **Fix.** A new kind, `invalid_end_marker`
     (`lzo_invalid_end_marker` through `compress.py`).
   - **Tests** (`test_lzo.py`, 45 → 50):
     - `13 41 42 15 00 00` and `13 41 42 10 01 00 00` (the two review
       repros), plus lengths 4 and 9;
     - the length-3 form after literals still decodes.

     The four repros failed before the fix (`4 failed, 46 passed`), and
     lzallright raises `LZOError` on all four.
2. **Harness corpora.**
   - `tests/oracle/lzo_hostile.py` now has six corpora of `--mutations`
     (300) streams each:
     - bit flips, drawn from the seed exactly as before, so their counts are
       unchanged;
     - truncation, one inserted byte and one deleted byte. Every second
       position is drawn from the last 8 bytes;
     - `random_bytes`: a literal run and 1–16 low-biased bytes;
     - `random_instructions`: 0–6 instructions with every field random and
       a random `0001HLLL` terminator.
   - Each stream records the btrfska/lzallright agreement and lists every
     disagreement as hex.
   - **The byte-level corpora did not find the bug.** A first run with only
     uniform positions, and a second with tail positions and the
     `random_bytes` corpus, both agreed 300/300 in every corpus and seed
     against the pre-fix decoder (`images/scratch/m1c/review/run_prefix.py`
     loads `5a4c6cc`'s `lzo.py`). No single-byte edit of `11 00 00` yields
     another length code with distance 16384. Only `random_instructions`
     exposed it.
   - `test_every_hostile_corpus_agrees_with_lzallright` (seeds 11 and 12,
     400 streams per corpus) fails against the pre-fix decoder: 399/400 and
     382/400 on `random_instructions`.

   **Results** (`uv run python tests/oracle/lzo_hostile.py --seeds 1 2 3 4 5
   --json images/scratch/m1c/review/lzo_hostile_fixed.json`, 25.1 s wall;
   median (range) over seeds 1–5, 300 streams per corpus per seed; for the
   random corpora the first column counts returned bytes):

   | Corpus | Decoder | Correct / returned | Wrong ≤ 4 KiB | > 4 KiB | `Exception` | non-`Exception` |
   |---|---|---|---|---|---|---|
   | bit_flips | btrfska | 0 (0–1) | 227 (218–231) | 0 (0–0) | 72 (68–82) | 0 (0–0) |
   | bit_flips | lzallright 0.2.6 | 0 (0–1) | 227 (218–231) | 36 (32–41) | 39 (31–47) | 0 (0–0) |
   | bit_flips | dissect.util 3.24 pure Python | 1 (0–1) | 267 (258–277) | 30 (22–41) | 1 (0–2) | 0 (0–0) |
   | bit_flips | dissect.util 3.24 native | 0 (0–1) | 227 (218–231) | 36 (32–41) | 0 (0–2) | 37 (31–46) |
   | truncation | btrfska | 0 (0–0) | 0 (0–0) | 0 (0–0) | 300 (300–300) | 0 (0–0) |
   | truncation | lzallright 0.2.6 | 0 (0–0) | 0 (0–0) | 0 (0–0) | 300 (300–300) | 0 (0–0) |
   | truncation | dissect.util 3.24 pure Python | 59 (54–70) | 0 (0–0) | 0 (0–0) | 241 (230–246) | 0 (0–0) |
   | truncation | dissect.util 3.24 native | 0 (0–0) | 0 (0–0) | 0 (0–0) | 300 (300–300) | 0 (0–0) |
   | insertion | btrfska | 0 (0–0) | 12 (9–14) | 0 (0–0) | 288 (286–291) | 0 (0–0) |
   | insertion | lzallright 0.2.6 | 0 (0–0) | 12 (9–14) | 63 (57–71) | 225 (220–229) | 0 (0–0) |
   | insertion | dissect.util 3.24 pure Python | 71 (70–78) | 152 (139–158) | 57 (50–65) | 17 (7–32) | 0 (0–0) |
   | insertion | dissect.util 3.24 native | 21 (13–23) | 12 (9–14) | 63 (57–71) | 74 (26–93) | 132 (119–176) |
   | deletion | btrfska | 0 (0–0) | 41 (32–71) | 0 (0–0) | 259 (229–268) | 0 (0–0) |
   | deletion | lzallright 0.2.6 | 0 (0–0) | 41 (32–71) | 22 (9–23) | 240 (209–250) | 0 (0–0) |
   | deletion | dissect.util 3.24 pure Python | 59 (50–60) | 185 (157–200) | 20 (11–25) | 40 (21–75) | 0 (0–0) |
   | deletion | dissect.util 3.24 native | 0 (0–0) | 41 (32–71) | 22 (9–23) | 114 (78–137) | 119 (95–172) |
   | random_bytes | btrfska | 0 (0–0) | 0 (0–0) | 0 (0–0) | 300 (300–300) | 0 (0–0) |
   | random_bytes | lzallright 0.2.6 | 0 (0–0) | 0 (0–0) | 0 (0–0) | 300 (300–300) | 0 (0–0) |
   | random_bytes | dissect.util 3.24 pure Python | 0 (0–0) | 0 (0–0) | 0 (0–0) | 300 (300–300) | 0 (0–0) |
   | random_bytes | dissect.util 3.24 native | 0 (0–0) | 0 (0–0) | 0 (0–0) | 19 (18–25) | 281 (275–282) |
   | random_instructions | btrfska | 0 (0–1) | 0 (0–0) | 0 (0–0) | 300 (299–300) | 0 (0–0) |
   | random_instructions | lzallright 0.2.6 | 0 (0–1) | 0 (0–0) | 0 (0–0) | 300 (299–300) | 0 (0–0) |
   | random_instructions | dissect.util 3.24 pure Python | 8 (6–13) | 0 (0–0) | 0 (0–0) | 292 (287–294) | 0 (0–0) |
   | random_instructions | dissect.util 3.24 native | 2 (0–3) | 0 (0–0) | 0 (0–0) | 24 (22–27) | 274 (272–277) |

   - **Agreement.** btrfska and lzallright now agree on 300 of 300 streams
     in every corpus and seed. Every btrfska failure is `LzoError`.
     - The only residual difference is the documented one-sector bound:
       lzallright's over-4 KiB outputs, which btrfska rejects as
       `output_overrun`.
     - Against the pre-fix decoder, `random_instructions` agreed on
       289/294/293/292/293. All 39 disagreements were btrfska returning
       bytes where lzallright raised `LZOError`. The fixed decoder raises
       `invalid_end_marker` on all 39, with copy lengths 4–9 (35 streams)
       and 39, 51, 584 and 623 (zero-run lengths).
     - btrfska's counts on the other five corpora are identical before and
       after the fix.
   - **Also observed.** dissect.util's pure-Python decoder returns the
     original sector for 54–70 truncated streams per seed: its loop ends
     once the output length is reached, before any end marker.
   - **Docs updated.** plan.md §3.5 ("Beyond bit flips") and research.md
     §10.9. The bit-flip numbers cited in plan.md §3.5 and §9, research.md
     and the table above are unchanged.
3. **Unbounded piece list for hostile striped extents (low-medium).**
   - **Bound.** An uncompressed regular extent whose `disk_num_bytes` or
     `num_bytes` exceeds the image size is now `invalid_extent`, rejected
     before any mapping or allocation.
     - Rationale: every readable copy comes from the one image, so a longer
       extent cannot be read without aliasing.
     - The kernel's allocator limit `BTRFS_MAX_EXTENT_SIZE` (128 MiB, v7.0
       `fs.h:66`) is deliberately not used. `check_extent_data_item`
       (`tree-checker.c:306-321`) enforces only alignment and end overflow,
       so the kernel would still read a longer extent.
     - Compressed extents keep their existing caps: `ram_bytes` and
       `disk_num_bytes` in (0, 128 KiB]. `BTRFS_MAX_COMPRESSED` and
       `BTRFS_MAX_UNCOMPRESSED` are re-verified as `SZ_128K` at v7.0
       `compression.h:35` and `:40`.
     - Holes and prealloc read no disk bytes and yield zeros in 1 MiB
       pieces, so they are not bounded.
   - **Laziness.** `ChunkMap.pieces` is now a generator. `_read` maps and
     reads one piece at a time and stops at the first unmapped or unreadable
     piece. An unmapped piece after readable ones now keeps the ranges read
     so far in the record.
   - **Tests.**
     - `test_extent_lengths_beyond_the_image_are_rejected_quickly_in_bounded_memory`
       covers three cases of 2^48 lengths in a 2^48-byte RAID0 chunk of a
       128 MiB image. It asserts `invalid_extent`, no ranges, under 2 s and
       a tracemalloc peak under 4 MiB. Before the fix it failed with
       `MemoryError` at `extents.py:94` (run under `ulimit -v 3000000`).
     - `test_pieces_are_produced_lazily` takes the first 3 of 2^31 pieces.
       It also failed with `MemoryError` before the fix.
     - `test_a_striped_read_stops_at_the_first_unreadable_piece` passed
       before and after: the read result was already the same, and only the
       work done changed. It is kept as a regression guard.
     - Existing `pieces` tests now wrap the generator in `tuple()`.
     - `test_extents.py` 29 → 33; `test_chunks.py` pieces tests 8 → 9.
4. **In-memory reads (doc).** The `read_file` docstring and README "`btrfska
   cat` output" now state that content is held fully in memory, with a peak
   of about 2× the file size, and that streaming arrives with the recovery
   engine. plan.md M4 gains a "Streaming extent reads" bullet.
5. **EXP-001 block counts (doc).** The results table's accepted and
   rejected headers carry a `[^blocks]` footnote. Legacy counts physical
   scan hits (`legacy/utils/btree.py:516-517`), stale orphans included and
   copies not merged. btrfska counts distinct logical blocks reached by
   anchored walks. The two numbers are therefore not directly comparable.

**Verification** (local, at `c532192`; logs in
`images/scratch/m1c/review/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all) | `uv run pytest -q` | `613 passed` (was 601) |
| vm tests | `uv run pytest -m vm -q` | `44 passed, 569 deselected` |
| Tests without vm | `uv run pytest -m "not vm" -q` | `569 passed, 44 deselected` |
| Oracle subset | `uv run pytest -q tests/oracle` | `13 passed` (was 11) |
| Read-only scan and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; no `dissect` or `lzallright` import under `src/` |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `48 files already formatted` |
| `sandbox.img` after | `sha256sum sandbox.img` | unchanged hash and mtime |

## 2026-09-15 — M1b: validated node reader, chunk maps, anchored tree walking

- **Branch:** `feature/m1b-validated-tree-walking` (from `main` at `dd90a1b`).
  This is the second of three M1 PRs. It covers plan.md §5 M1 tasks 5–7, the
  `walk` half of task 10 and the `m1_badnode` image of task 9.
- **Commits:**
  - `0a1313c` Add chunk maps with stripe math for every profile and chunk item checks
  - `c0dc969` Add the node reader: every copy validated, each check recorded
  - `9296801` Add item payload parsers with never-raising JSON summaries
  - `64ad3b0` Walk trees from any root with per-hop checks; resolve backup roots and subvolumes
  - `c43617e` Add btrfska walk: JSON lines per item with root and copy provenance
  - `09512df` Explain why superblock selection passes a wiped primary that btrfs-progs stops at
  - `c5ea61d` Add a flip-byte operation to corpus/mutate.py for corrupt tree-block copies
  - `f38f309` Add the m1_badnode images and vm tests for chunk maps, full walks and sv1 history
  - `cf1f6e6` Record M1b tree-walking notes, the mirror policy and the README status
  - this catalog entry (the commit after `cf1f6e6`)

**What was done.** Unit, synthetic and sandbox tests were written first and
seen failing (ImportError, or `invalid choice: 'walk'` for the CLI and
`flip-byte`) before the implementation.
1. **`substrate/chunks.py` (task 6).**
   - `parse_chunk()` records every `btrfs_check_chunk_valid` failure
     (tree-checker.c:825-1014): stripe counts per profile, ncopies/nparity,
     alignment, sector_size, stripe_len, type and profile bits, mixed groups
     and item size.
   - `parse_sys_chunk_array()` is bounds-checked: a truncated key or item, a
     non-CHUNK_ITEM key and a non-SYSTEM chunk are reported, never raised.
   - `ChunkMap(source, chunks, devices)` sorts chunks and flags overlaps,
     invalid chunks, zero-stripe REMAPPED chunks (tolerated; their addresses
     raise `UnmappedAddress`) and stripes on missing devices or with a foreign
     device uuid.
   - `copies(logical, length)` follows volumes.c:6632-6849:
     - SINGLE, DUP and RAID1/1C3/1C4 return every stripe in stripe order;
     - RAID0 returns one stripe, RAID10 its sub_stripes mirrors;
     - RAID5/6 return the data stripe with rotated parity (parity
       reconstruction is unsupported);
     - striped reads may not cross a 64 KiB stripe boundary;
     - an unmapped range raises `UnmappedAddress` naming the map's source.
2. **`substrate/node.py` (task 5).**
   - `check_block(block, ctx, logical, expect)` returns one `Check(name, ok,
     detail)` per check, in order: csum, bytenr, fsid (tree fsid),
     chunk_tree_uuid, generation ≤ superblock, level (< 8, equal to the
     expected level), nritems, WRITTEN flag, layout, owner (kernel
     `btrfs_check_eb_owner` rule), parent_generation and first_key.
   - The layout check follows tree-checker.c: keys strictly ascending, item
     data contiguous from the block end and clear of the item headers; for
     nodes, non-null sector-aligned pointers.
   - A check whose reference is unknown records `ok=None`.
   - `parse_items()` and `parse_key_ptrs()` clamp nritems and never slice
     outside the block.
   - `read_node(img, chunk_map, logical, ctx, expect)` returns a
     `ValidatedNode`; `NodeReader` bundles the three inputs.
   - Property test: 900 seeded rounds (random blocks, mutated leaves and
     nodes, and mutated blocks with a recomputed csum so the layout checks see
     the damage). Nothing raises, and every mutated block with a stale csum
     fails a check.
3. **`substrate/tree.py`, `roots.py`, `fs.py`, `items.py` (task 7).**
   - `fs.open_filesystem()`:
     - selects the superblock and applies the gate (`UnsupportedFormat`);
     - builds the bootstrap map from the sys_chunk_array;
     - reads the chunk root to learn the chunk tree uuid;
     - walks the chunk tree into `ChunkMap(source="current")`, cross-checked
       against the sys_chunk_array.
   - `tree.walk(reader, bytenr, expect)` is depth-first in key order. Each
     child is read with level − 1, the tree owner, the pointer's generation
     and its key. The `Visit` records hop problems: a pointer already reached
     (cycle or shared block, not followed) or keys at or above the parent's
     next key. Invalid nodes are yielded, never descended.
   - `tree.fs_tree_inventory(reader, bytenr, expect)` raises `IncompleteTree`
     rather than return a partial inventory.
   - `roots.root_sets(fields)` lists the backup sets by generation, then
     current. `resolve_tree()` resolves slot trees from the slot fields and
     numeric ids from the set's root tree ROOT_ITEM (highest key offset).
     `subvolumes()` pairs ROOT_ITEM, ROOT_REF and ROOT_BACKREF and reports
     one-sided refs.
   - `items.py` parses inode, ref/extref, dir/xattr, file extent, root item
     (legacy 239 B too) and root ref items, raising only `ItemError`. Names
     keep undecodable bytes (surrogateescape). `summary()` never raises.
   - The four ground-truth tests are ordinary tests now: xfail markers
     removed, real API used. Each resolves `backup:GEN` → slot → fs root,
     checks bytenr and generation, compares the inventory and asserts both
     DUP copies valid.
4. **CLI (task 10, `walk` half).** `btrfska walk IMAGE [--root
   current|backup:GEN|bytenr:N] [--tree fs|root|chunk|extent|dev|csum|ID]
   [--allow-unsupported]`:
   - stdout carries one JSON line per record:
     - `item`: key with type name, size, cheap summary, `slot`;
     - `invalid_node`: the node instead of its items;
     - `walk_problem`: hop findings;
   - every record carries `root` (source, tree, tree_id, bytenr, level,
     generation, `via`), `node` (bytenr, level, generation, owner, valid,
     each copy's mirror/devid/physical/used/valid/checks/problems),
     `chunk_map` and `unsupported_format`;
   - stderr carries a one-line summary, chunk-map problems, and on refusal
     `gate: REFUSED` with `UNSUPPORTED_INCOMPAT` lines;
   - exit status: 0 when walked (invalid nodes are records, not errors), 1 for
     an unknown root or tree, 2 when refused or `NO_VALID_SUPERBLOCK`.
5. **Corpus (task 9).** `corpus/mutate.py flip-byte OFFSET...` inverts bytes
   at physical offsets, behind the existing output guards. Two derived images
   are added to `corpus/manifest.tsv`.
6. **Doc nit.** The `superblock.select` docstring now explains the one
   difference from btrfs-progs recover mode (v7.1 `disk-io.c:2029-2033`).
   Progs stops when mirror 0 has the expected bytenr but a zero magic (device
   removal wipes only the magic); btrfska falls back and reports mirror 0
   invalid.

**Design decisions.**
- **Mirror handling.**
  - `read_node` reads every physical copy of a tree block and validates each
    on its own. It uses the first valid copy in mirror order and keeps every
    copy's checks in `ValidatedNode.copies` as provenance.
  - If no copy is valid, the node is flagged: the header of the first
    readable copy is reported, and `items` and `key_ptrs` raise `InvalidNode`.
  - Valid copies whose bytes differ are reported (`mirror 2 is valid but
    differs from mirror 1`). With crc32c this is possible in the 28 csum-field
    bytes the checksum does not cover.
  - Why: the kernel reports neither the copy it did not read nor which copy
    it did. Which copy it reads depends on the profile (corrected in the
    review fixes below):
    - DUP: mirror 1, falling back to mirror 2 only when mirror 1 fails
      (`map_blocks_dup`, volumes.c:6751-6765);
    - RAID1/1C3/1C4/10: `find_live_mirror` (volumes.c:6276-6342) picks by
      PID under the default `pid` read policy, so different readers see
      different copies.

    btrfs-progs warns without saying which copy. A forensic tool must never
    hide that one copy is corrupt, and a divergent second copy is itself
    evidence (research.md §10.8).
  - Cost: two reads per DUP block, negligible at tree-block scale. plan.md
    §3.5 and M1 task 5 now state the policy.
- **Parent generation is checked for equality**, as the kernel does
  (disk-io.c:410-417), not as the brief's "child generation ≤ parent
  pointer generation". An older child is as inconsistent as a newer one. The
  failure detail names the direction: newer means rewritten after the parent.
  The check is part of each copy's validation, so a stale mirror with a wrong
  generation falls back to the other copy exactly as a csum failure does.
- **Designed for M1c/M2/M3.**
  - `ChunkMap.copies()` is the only translation, so extent reads can take any
    map (current now, historical or reconstructed in M5).
  - `check_block(block, ctx, None, expect)` validates raw physical blocks for
    the M2 scan kernel without a logical address.
  - `ValidatedNode`, `Visit` and the CLI's record shape carry the provenance
    an M3 evidence row needs.

**dump-tree cross-check** (btrfs-progs v6.6.3, only ever on byte-identical
0444 copies in `images/scratch/m1b/ro/`, sha256 checked; outputs in
`images/scratch/m1b/dump/`):
```sh
cp --sparse=always images/scenarios/m1_xxhash.img images/scratch/m1b/ro/ && chmod 0444 images/scratch/m1b/ro/m1_xxhash.img   # likewise sandbox-ro, m1_sha256_bgt, m1_blake2b, m1_badnode, m1_badnode_both
btrfs inspect-internal dump-tree -t chunk images/scratch/m1b/ro/<image>.img
btrfs inspect-internal dump-tree -t root  images/scratch/m1b/ro/<image>.img
btrfs inspect-internal dump-tree -b 30801920 images/scratch/m1b/ro/sandbox-ro.img   # and 30883840, 30572544, 30720000 (gens 11-14)
btrfs inspect-internal dump-tree -b 65208320 images/scratch/m1b/ro/m1_xxhash.img    # and 65273856, 65323008 (gens 35-37)
btrfs inspect-internal dump-tree -b 65159168 images/scratch/m1b/ro/m1_xxhash.img    # sv1; 64208896 fs, 65126400 snapshot, 64962560 data reloc
btrfs inspect-internal dump-tree -b 131104768 images/scratch/m1b/ro/m1_xxhash.img   # gen-30 chunk root; 64847872 gen-30 dev root
btrfs inspect-internal dump-tree -b 65159168 images/scratch/m1b/ro/m1_badnode.img   # and m1_badnode_both.img
```
- **Chunk maps match dump-tree exactly** (`test_chunk_map_matches_dump_tree`:
  logical, length, stripe_len, type, num_stripes, sub_stripes, every
  stripe's devid and offset; `problems == ()`):

  | Image | DATA\|single | SYSTEM\|DUP | METADATA\|DUP |
  |---|---|---|---|
  | `sandbox.img` | 13631488 (8 MiB) → 13631488 | 22020096 (8 MiB) → 22020096, 30408704 | 30408704 (32 MiB) → 38797312, 72351744 |
  | `m1_xxhash`, `m1_sha256_bgt`, `m1_blake2b` | 164626432 (64 MiB) → 307232768 | 131072000 (32 MiB) → 240123904, 273678336 | 63963136 (64 MiB) → 105906176, 173015040 |

  The sandbox map is also committed in `tests/ground_truth/sandbox.json`, so
  CI checks it without btrfs-progs.
- **Walks match dump-tree block by block**
  (`test_walks_match_dump_tree_block_by_block`). For every distinct tree root
  of every root set of the three csum images, our (bytenr, nritems,
  generation) sequence equals `dump-tree -b <root> --follow`: at least 20
  roots per image.
- **Corrupt copies agree with dump-tree.** The stored and computed xxhash64
  values match progs' `wanted 0x6024af66d4ba356f found 0x04ee33fa2966cb51`.
  Progs prints it once on `m1_badnode` (then prints the leaf from mirror 2)
  and twice plus `ERROR: failed to read tree block 65159168` on
  `m1_badnode_both`.

**Per-generation inventories.**
- `sandbox.img`: every tree of every root set is valid on both copies, and
  the fs trees match `tests/ground_truth/sandbox.json`.

  | Root set | Root tree | fs tree (slot and ROOT_ITEM agree) | Contents |
  |---|---|---|---|
  | backup:11 (slot 2) | 30801920 | 30785536 gen 11, 8 items | dir 256 (30 B) → `target_file.txt` 257, 31 B inline |
  | backup:12 (slot 3) | 30883840 | 30867456 gen 12, 2 items | dir 256 only (0 B) |
  | backup:13 (slot 0) | 30572544 | 30539776 gen 13, 8 items | dir 256 (32 B) → `large_target.txt` 257, 5 242 880 B regular at 13631488 |
  | backup:14 (slot 1) | 30720000 | 30703616 gen 14, 2 items | dir 256 only |
  | current | 30720000 | 30703616 gen 14 | same as gen 14 |

  Only subvolume 5 exists in any generation.
- **`m1_xxhash` `sv1` history.** The four backup sets (gens 35–38, slots 2, 3,
  0, 1) and current share the ROOT_ITEMs below. Sizes are asserted against
  the guest script (`seq 1 20000` = 108 894 B, `seq 1 50000` = 288 894 B,
  `small secret\n` = 13 B, `genN\n` = 5 B).

  | Subvolume | Leaf (gen) | Contents in every generation |
  |---|---|---|
  | 5 | 64208896 (19) | dir 256 → `sv1` 256, `snap_before_delete` 257 |
  | 256 `sv1`, parent 5, otransid 7 | 65159168 (34) | `keep.txt` 108 894 B, `churn_1..6` 5 B each |
  | 257 `snap_before_delete`, read-only, otransid 8 | 65126400 (34) | `keep.txt`, `deleted_big.txt` 288 894 B (3 extents), `deleted_inline.txt` 13 B |

  Gens 35–37 differ from 38 and current in the root tree: a `BALANCE
  TEMPORARY_ITEM` and a gen-32 DATA_RELOC tree with orphan inode 259 (4
  extents). They also name the gen-30 chunk root 131104768, which still
  holds the pre-balance data chunk 13631488 (research.md §10.8).
- **All backup roots were fully walkable.** No tree block in any root set of
  `sandbox.img` or the five s01 images is invalid or has a divergent copy.
  That is 144 distinct tree blocks, all DUP pairs
  (`images/scratch/m1b/explore.py` → `explore.txt`).

**New images** (derived from `m1_xxhash`; host mkfs btrfs-progs v6.6.3,
guest kernel 7.0.0-31-generic via the source):

| Name | Generator | Damage | sha256 |
|---|---|---|---|
| `m1_badnode` | `uv run python corpus/mutate.py images/scenarios/m1_xxhash.img images/scenarios/m1_badnode.img flip-byte 107118591` | last byte of mirror 1 of the `sv1` leaf 65159168 (physical 107102208 + 16383, inside item 0's data) | `d189151f5e0c2a7b750cf9ed03a152a52d6e0a51bcc2d35de9fb3c808ab381d6` |
| `m1_badnode_both` | `… images/scenarios/m1_badnode_both.img flip-byte 107118591 174227455` | the same byte in both copies (mirror 2 at 174211072 + 16383) | `35d4f05d0e24f87c3e186d9127277a552903b10cc1881ef2fd47848b8d8fe99d` |

- `m1_badnode`: the leaf is valid through mirror 2; mirror 1 fails only
  `csum`; all 37 items are walked in every root set. The `sv1` leaf is shared
  by all five sets.
- `m1_badnode_both`: the node is an `invalid_node` record with `csum` false
  on both copies and no items. `fs_tree_inventory` raises `IncompleteTree`;
  the snapshot tree is unaffected.

**Deviations** (the one plan change is the mirror-policy lines in plan.md
§3.5 and M1 task 5):
- **Parent generation equality** instead of "≤" (see design decisions).
- **Two badnode images.** The plan names one `m1_badnode`. The mirror policy
  needs both cases: one corrupt copy (reported, other copy used) and both
  corrupt (`m1_badnode_both`, csum failure instead of items).
- **API names.** `fs_tree_inventory` keeps its placeholder name; its signature
  is `(reader, bytenr, expect)`, not `(img, bytenr)`, and the ground-truth
  test was updated. The walker needs the chunk map and validation context, so
  an image handle alone is not enough.
- **Physical reads.** The plan says `read_node(logical|physical)`. A logical
  read maps through the chunk map. A physical block (M2) is validated with
  `check_block(block, ctx, None, expect)`; no second reader is added before
  M2 needs one.
- **Tree resolution in backup sets.** Slot trees come from the slot fields,
  which the superblock csum covers. Numeric ids go through the set's root
  tree. `test_sandbox_backup_trees_resolve_through_slots_and_root_items_alike`
  shows both agree for fs, extent and csum in gens 11–14.
- **`subvolumes()` returns `(subvolumes, problems)`** so root-tree walk
  problems are not dropped.
- **Backup roots walk through the current chunk map.** Historical maps are M5.
  On these images every tree block is in chunks the old and new maps share.
- **Multi-device.** Only the superblock's own device (dev_item devid and
  uuid) is readable; other stripes are copies flagged `missing_device`.
  RAID5/6 reads return the data stripe only.
- **Empty backup slots** (tree_root 0) are skipped by `root_sets`.
- **`walk` exits 0 when it finds invalid nodes.** They are evidence records,
  counted in the stderr summary, not errors.
- **Test order for the vm tests.** The M1b vm tests were written after the
  implementation and the badnode images existed, so they were not seen
  failing first. Their expectations come from dump-tree output and the guest
  script, not from btrfska.

**Verification** (local, branch `feature/m1b-validated-tree-walking`, all M1
images present; logs in `images/scratch/m1b/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all) | `uv run pytest -q` | `446 passed` (was `288 passed, 4 xfailed`); no xfails left |
| Tests without vm | `uv run pytest -q -m "not vm"` | `408 passed, 38 deselected` |
| vm tests | `uv run pytest -m vm -q` | `38 passed, 408 deselected` (was 21) |
| Read-only scan and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; `grep -rn 'dissect\|lzallright' src/` finds nothing |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `37 files already formatted` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done` | exit 0 |
| Lockfile | `uv lock --check` | `Resolved 10 packages` |
| `sandbox.img` after | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime unchanged |

**`btrfska walk` samples** (full output in
`images/scratch/m1b/verify/walk-samples.txt`; long lines trimmed with `…`):
```
$ uv run btrfska walk sandbox.img --root backup:11 --tree fs | head -1
{"record":"item","root":{"source":"backup:11","tree":"fs","tree_id":5,"bytenr":30785536,"level":0,"generation":11,"via":"backup slot 2"},"chunk_map":"current","unsupported_format":false,"node":{"bytenr":30785536,"level":0,"generation":11,"owner":5,"valid":true,"copies":[{"mirror":1,"devid":1,"physical":39174144,"used":true,"valid":true,"checks":{"csum":true,"bytenr":true,"fsid":true,"chunk_tree_uuid":true,"generation":true,"level":true,"nritems":true,"written":true,"layout":true,"owner":true,"parent_generation":true,"first_key":null},"problems":[]},{"mirror":2,"devid":1,"physical":72728576,"used":false,"valid":true,…}],"problems":[]},"slot":0,"key":{"objectid":256,"type":1,"type_name":"INODE_ITEM","offset":0},"size":160,"summary":{"generation":3,"transid":10,"size":30,"nbytes":16384,"nlink":1,"uid":1000,"gid":1000,"mode":"40755","flags":0}}

$ uv run btrfska walk sandbox.img --root backup:13 --tree fs      # EXTENT_DATA record, stderr summary
…"key":{"objectid":257,"type":108,"type_name":"EXTENT_DATA","offset":0},"size":53,"summary":{"generation":13,"ram_bytes":5242880,"compression":0,"encryption":0,"other_encoding":0,"type":"regular","disk_bytenr":13631488,"disk_num_bytes":5242880,"offset":0,"num_bytes":5242880}
btrfska walk: 1 nodes (0 invalid), 8 items, 0 walk problems

$ uv run btrfska walk images/scenarios/m1_badnode.img --tree 256 | head -1     # node section
…"copies":[{"mirror":1,"devid":1,"physical":107102208,"used":false,"valid":false,"checks":{"csum":false,"bytenr":true,…},"problems":["csum: stored 6024af66d4ba356f computed 04ee33fa2966cb51"]},{"mirror":2,"devid":1,"physical":174211072,"used":true,"valid":true,…}],"problems":["mirror 1: csum: stored 6024af66d4ba356f computed 04ee33fa2966cb51"]}…
btrfska walk: 1 nodes (0 invalid), 37 items, 0 walk problems

$ uv run btrfska walk images/scenarios/m1_badnode_both.img --root backup:35 --tree 256      # exit 0
btrfska walk: 1 nodes (1 invalid), 0 items, 0 walk problems
{"record":"invalid_node","root":{"source":"backup:35","tree":"256","tree_id":256,"bytenr":65159168,"level":0,"generation":34,"via":"ROOT_ITEM (256 132 0) in root tree 65208320 leaf 65208320 slot 12"},…,"node":{"bytenr":65159168,…,"valid":false,"copies":[{"mirror":1,…,"used":false,"valid":false,"checks":{"csum":false,…}},{"mirror":2,…,"used":false,"valid":false,"checks":{"csum":false,…}}],"problems":["mirror 1: csum: stored 6024af66d4ba356f computed 04ee33fa2966cb51","mirror 2: csum: stored 6024af66d4ba356f computed 04ee33fa2966cb51"]},"parent":null,"parent_slot":null}

$ uv run btrfska walk images/scenarios/m1_unknown_incompat.img                     # exit 2
gate: REFUSED
UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40
```

**Research notes.** research.md §10.8 records:
- all backup roots are fully walkable on the current corpus (with the
  small-image threat);
- DUP copies are identical. The kernel reads DUP mirror 1 first
  (RAID1/1C3/1C4/10 pick a copy by PID), and crc32c leaves csum bytes 4–31
  unchecked: two hiding-place hypotheses, the first scoped to DUP in the
  review fixes;
- the `sv1` per-generation result, with deletions visible only through the
  snapshot;
- backup chunk roots preserving the pre-balance data chunk;
- mid-balance backup roots recording the relocation;
- why parent-generation equality matters in historical walks.

**For M1c (extents, decompression, oracles, EXP-001).**
- **Reading extents.** Read through `fs.chunk_map.copies(disk_bytenr + offset,
  length)`. Split ranges at 64 KiB stripe boundaries for RAID0/10/5/6
  (`MappingError` otherwise). Keep `PhysicalCopy.mirror` in the per-extent
  read record. Data chunks here are SINGLE, so there is one copy; data
  checksums are not verified yet.
- **What `items.file_extent()` returns.** Inline items have the 21-byte head
  plus `inline_size`; the data starts at `ondisk.FILE_EXTENT_INLINE_DATA_START`.
  Regular and prealloc items include `offset`, `num_bytes`, `ram_bytes`,
  `disk_bytenr` and `disk_num_bytes`. The inventory's regular-extent entries
  omit `offset` and `ram_bytes` to match the committed ground truth; extend
  both together if needed.
- **Oracle targets.**
  - `sandbox.img`: gen 11 `target_file.txt` (31 B inline, uncompressed,
    backup root only) and gen 13 `large_target.txt` (5 MiB regular at
    13631488, backup root only).
  - `m1_xxhash` `sv1`: `keep.txt` is zstd (disk 28 672 B, ram 110 592 B);
    `churn_*` are zstd inline (23 B stored, 5 B ram).
  - Snapshot 257 holds `deleted_big.txt` (3 zstd extents) and
    `deleted_inline.txt` (31 B stored, 13 B ram) with the guest SHA-256s.
    Current-tree-only oracles must include snapshot 257.
- **Relocation.** The DATA_RELOC tree of gens 35–37 names the relocated data
  extents. It is an orphan inode, so skip it (or treat it as evidence) when
  listing files.
- **EXP-001.** The csum-type half is ready: `btrfska walk` validates every
  node on `m1_xxhash`, `m1_sha256_bgt` and `m1_blake2b` (23–25 distinct
  blocks, all valid). The legacy tool still needs running against them.

### Review fixes (2026-09-15)

The M1b review approved the branch with six fixes. Every code fix was
test-first: the new tests were run and seen failing (ZeroDivisionError,
`DID NOT RAISE MappingError`, missing `rejected`/`readable`, missing README
section) before the fix. Kernel references were re-read in v7.0
(`git tag v7.0`, raw files from GitHub torvalds/linux, kept in
`images/scratch/m1b-review-fixes/kernel/`; `volumes.c` is byte-identical to
the M1a copy).

1. **ZeroDivisionError on a REMAPPED RAID10 chunk (high).** A
   `SYSTEM|RAID10|REMAPPED` bootstrap chunk with 2 stripes and sub_stripes 0
   passed `parse_chunk`, because `btrfs_check_chunk_valid` skips
   `valid_stripe_count` for REMAPPED chunks (tree-checker.c:1002-1009). Its
   first lookup then divided by zero, and `btrfska walk` crashed with a
   traceback inside `open_filesystem`.
   - Why the check matters here: the kernel maps a REMAPPED address that is
     covered by an identity remap item through the chunk's own stripes
     (relocation.c:5164-5165, volumes.c:6914-6930); an address with no remap
     item at all fails translation with `-ENOENT` (relocation.c:5123-5171).
     Stripe geometry therefore matters.
   - `ChunkMap.copies()` now raises `MappingError` (`geometry is not
     computable`) whenever the stripe math cannot run, whatever problems the
     chunk records:
     - RAID10 with num_stripes not a non-zero multiple of sub_stripes;
     - RAID5/6 with num_stripes ≤ nparity;
     - more than one profile bit.
     A chunk without stripes still raises `UnmappedAddress`.
   - `parse_chunk` now runs the stripe-count check on every chunk that has
     stripes, flagging `(checked although REMAPPED)`.
   - It also adds `num_stripes N is not a multiple of sub_stripes 2` for
     RAID10. The allocator adds RAID10 devices in pairs (`devs_increment 2`,
     volumes.c:54-66); the kernel checker does not test this.
   - Tests:
     - `test_remapped_chunks_with_stripes_still_get_stripe_count_checks`,
       `test_raid10_stripes_must_be_a_multiple_of_sub_stripes`;
     - `test_uncomputable_geometry_raises_mapping_error_even_without_problems`
       (6 cases);
     - `test_random_chunk_geometry_translates_or_raises_mapping_error`: 3 000
       random parsed and directly built chunks, over 1 000 successful
       translations, only `MappingError` allowed;
     - `test_sys_chunk_array_garbage_never_raises`, which now also translates
       inside every accepted chunk;
     - the end-to-end regression
       `test_remapped_raid10_without_sub_stripes_opens_and_walks_without_a_traceback`
       (`open_filesystem` and `btrfska walk`, exit 0).
2. **False translation on a REMAPPED RAID6 chunk with one stripe (medium).**
   Data stripes came out as -1, and Python's floor division and modulo
   returned a physical offset without flagging anything.
   - Fixed by the same guard. `parse_chunk` also flags `num_stripes N <
     nparity M`; the kernel checks only `==`, tree-checker.c:910-914.
   - Test: `test_remapped_raid6_with_one_stripe_never_translates` asserts
     `MappingError` and that no copy is returned.
3. **An invalid chunk still claimed address space (medium).** `ChunkMap`
   now keeps chunks with problems in `rejected`. Only valid chunks take part
   in lookup and overlap resolution; overlaps between valid chunks are still
   reported and the later chunk ignored.
   - Each rejected chunk is a map problem, `chunk L (origin, TYPE, length N)
     is invalid and rejected: …`. `walk` prints map problems on stderr as
     `chunk map: …`.
   - A lookup that lands only in a rejected chunk raises `UnmappedAddress`
     naming it: `… not in any valid chunk … (rejected chunk L is invalid:
     …)`. That text is also the `invalid_node` record's problem.
   - `btrfska info` does not open the chunk tree, so it shows no chunk
     problems before or after.
   - Test: `test_an_invalid_chunk_does_not_claim_address_space`. A corrupt
     64 GiB item at 1 GiB (bad stripe_len) and a valid chunk at 3 GiB: the
     valid chunk translates, the corrupt one is reported, and no overlap is
     claimed.
4. **Mirror-read statement corrected (medium, paper-critical).** "The kernel
   reads mirror 1 and falls back silently" holds for DUP only.
   - Updated here (design decisions, research notes) and in research.md
     §10.8. plan.md §3.5 states btrfska's own policy only, so it is
     unchanged.
   - Verified in v7.0:
     - DUP: `map_blocks_dup` (volumes.c:6751-6765) sets mirror 1. The retry
       loop in `btrfs_read_extent_buffer` (disk-io.c:211-250) tries the next
       mirror only after a failure.
     - RAID1/1C3/1C4: `map_blocks_raid1` (l.6731-6749) calls
       `find_live_mirror` (l.6276-6342); RAID10 goes through
       `map_blocks_raid10` (l.6767-6793).
     - Default read policy `pid`: `first + current->pid % num_stripes`
       (l.6302-6304). `round-robin` and `devid` exist only under
       `CONFIG_BTRFS_EXPERIMENTAL` (volumes.h:322-332, sysfs.c:1322-1343,
       volumes.c:1271-1287), which the host kernel (`7.0.0-31-generic`)
       leaves unset.
     - Repair on fallback: `btrfs_repair_eb_io_failure` (disk-io.c:172-202,
       called at l.246-247) rewrites the failed mirror unless the superblock
       is read-only (l.180; `btrfs_repair_io_failure`, bio.c:952). Data reads
       repair through bio.c:222.
   - research.md now scopes the "altered mirror 2" hiding place to DUP and
     states that a read-write mount can destroy the divergence.
5. **Integrity vs linkage (low, plan only).** plan.md M5 gains a task to
   split integrity checks (csum, bytenr, fsid, chunk-tree uuid, layout) from
   linkage checks (parent generation, first key, owner, expected level). A
   historical walk would then expose items from integrity-valid nodes with a
   `linkage_mismatch` flag and a confidence penalty. No code change.
6. **`walk` JSON schema (low).**
   - Every copy now has `readable`, and `checks` always carries all 12
     `CHECK_NAMES` keys in order, `null` when not checked (all of them for an
     unreadable copy).
   - README.md gains "`btrfska walk` output", the full JSON-lines schema.
   - Tests:
     - `test_unreadable_copies_carry_every_check_as_null`;
     - `test_walk_records_follow_the_documented_schema`: exact key sets on
       item and invalid_node records from `sandbox.img`;
     - `test_readme_documents_every_walk_key`.

Sample after the fix (`images/scratch/m1b-review-fixes/verify/`, the item 1
image, exit 0; before the fix, the same walk crashed with ZeroDivisionError):
```
$ uv run btrfska walk images/scratch/m1b-review-fixes/verify/remapped_raid10.img --tree root
chunk map: chunk tree node 1073741824: logical 1073741824 is not in any valid chunk of the sys_chunk_array chunk map (rejected chunk 1073741824 is invalid: num_stripes 2 sub_stripes 0 invalid for RAID10 (checked although REMAPPED))
chunk map: sys_chunk_array chunk 1073741824 is not in the chunk tree; kept
chunk map: chunk 1073741824 (sys_chunk_array, SYSTEM|REMAPPED|RAID10, length 1073741824) is invalid and rejected: num_stripes 2 sub_stripes 0 invalid for RAID10 (checked although REMAPPED)
btrfska walk: 1 nodes (1 invalid), 0 items, 0 walk problems
{"record":"invalid_node",…,"node":{"bytenr":1073758208,…,"valid":false,"copies":[],"problems":["logical 1073758208 is not in any valid chunk of the current chunk map (rejected chunk 1073741824 …"]},…}
```

**Verification after the fixes** (local, all M1 images present):

| Check | Command | Result |
|---|---|---|
| Tests (all) | `uv run pytest -q` | `461 passed` (was 446) |
| vm tests | `uv run pytest -m vm -q` | `38 passed, 423 deselected` |
| Read-only scan and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; `grep -rn 'dissect\|lzallright' src/` finds nothing |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `37 files already formatted` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Lockfile | `uv lock --check` | `Resolved 10 packages` |
| `sandbox.img` | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 unchanged |

## 2026-09-15 — M1a: on-disk tables, checksums, superblock trust gate

- **Branch:** `feature/m1a-trust-foundations` (from `main` at `b1b845f`).
  This is the first of three M1 PRs. It covers plan.md §5 M1 tasks 1–4, the
  task-9 images these need (plus `m1_lzo` and `m1_zlib`), and the `info`
  half of task 10.
- **Commits:**
  - `45e32ca` Record defect #8 and the sandbox.img ground truth
  - `89ed86b` Add on-disk struct tables checked against kernel v7.0 headers
  - `e407a44` Add checksum dispatch for crc32c, xxhash64, sha256 and blake2b-256
  - `074b7fe` Add superblock mirrors, best-copy selection and the incompat gate
  - `b2dab62` Show superblock copies, gate verdict and backup roots in btrfska info
  - `5e4784e` Add the M1a corpus images, corpus/mutate.py and the image manifest
  - `6a85779` Add an import-boundary test keeping test oracles out of src/
  - `835589f` Record M1a format notes and update the README status
  - this catalog entry (the commit after `835589f`)

**What was done.** Each module's tests were written and seen failing
(ImportError or assertion) before the implementation.
1. **Ground truth (task 1).**
   - research.md §8.1 gains **defect #8**: legacy uses the EXTENT_ITEM key
     offset as the address, but the offset is the length. Evidence is below.
   - `tests/ground_truth/sandbox.json` holds the superblock copies, the four
     backup roots by slot, and the gen 11–14 fs-tree contents.
   - `tests/test_ground_truth.py` asserts the superblock facts (green) and
     has four strict xfails for the per-generation fs trees
     (`reason="tree walker lands in M1b"`).
2. **`substrate/ondisk.py` (task 2).**
   - A small `Layout` (named little-endian `struct` fields, `.size`,
     `.offset()`, `.unpack_from()`).
   - Layouts: superblock, backup root, header, key, item, key pointer, dev
     item, chunk and stripe, inode item/ref/extref, dir item, root item/ref,
     file extent item, dev extent, extent item and inline refs (incl. owner
     ref 172), block group item v1/v2, free-space info, remap item.
   - Constants: objectids 1–13 and the negative ones, all item keys incl.
     172, 230 and 234–236, incompat/compat_ro/block-group bits, csum table,
     mirror offsets, FT and extent constants.
   - `flag_names()` names unknown bits `UNKNOWN_BIT_<n>`.
3. **`substrate/csum.py` (task 3).**
   - `compute()` and `block_csum_ok()` follow kernel `btrfs_csum()`
     (`fs.c:44-62`): crc32c stored as LE u32, XXH64 seed 0 stored as LE u64,
     SHA-256, and BLAKE2b with `digest_size=32`.
   - The test proves the BLAKE2b result is not a truncated BLAKE2b-512; the
     test value was checked with `printf abc | b2sum -l 256`.
   - Runtime deps: `crc32c>=2.9` (locked 2.9.post0) and `xxhash>=4.0`
     (locked 4.0.1).
4. **`substrate/superblock.py` (task 4).**
   - `read_copies()` covers all three mirror slots; slots that do not fit
     the image are marked not present.
   - `parse_copy()` checks magic, then bytenr (only when the magic matches),
     then csum (unknown csum types reported).
   - `select()` takes the valid copy with the highest generation, lowest
     mirror on a tie. Each disagreement is reported: invalid copy, older
     generation, or same generation with differing fields (named). This is
     btrfs-progs recover-mode behaviour (`btrfs_read_dev_super` with
     `SBREAD_RECOVER`), not the kernel's: the kernel mounts mirror 0 only.
     The review fixes below add the progs fsid anchor.
   - `backup_roots()` returns the slots sorted by generation, each keeping
     its slot.
   - `gate()` refuses EXTENT_TREE_V2, RAID_STRIPE_TREE, REMAP_TREE and
     unknown bits, with `UNSUPPORTED_INCOMPAT <name>` lines;
     `allow_unsupported` gives status `OVERRIDDEN`.
   - The compat_ro BLOCK_GROUP_TREE bit is noted ("block groups are read
     from tree 11"). Unknown compat_ro bits are listed but do not refuse.
   - A property-style test feeds 300 random and 300 mutated blocks; none
     raises, and no mutated block validates.
5. **CLI (task 10, `info` half).** `btrfska info IMAGE [--allow-unsupported]`
   prints:
   - path, size and sha256;
   - each superblock copy (valid with generation and csum, `INVALID
     (reasons)`, or not present);
   - the selected copy and the disagreements;
   - the fields: fsid, generation, roots, csum type, compat/compat_ro/incompat
     flags;
   - the backup roots by generation;
   - `gate:` and any `UNSUPPORTED_INCOMPAT` lines.

   Exit 0 when OK or overridden, 2 when refused (gate or
   `NO_VALID_SUPERBLOCK`), 1 on I/O errors.
6. **Corpus (task 9).**
   - Five images generated with `corpus/vm/make_image.sh`; two derived with
     the new `corpus/mutate.py`.
   - `mutate.py` only reads its source and creates the output with `open(...,
     "xb")`. It refuses an existing path or symlink, a path outside `images/`
     (after resolving `..`), any file named `sandbox.img`, and output equal to
     the source. All-zero 1 MiB chunks stay sparse.
   - `corpus/manifest.tsv` has seven rows; `corpus/vm/README.md` documents
     both.
   - `tests/test_vm_images.py` (18 tests, `@pytest.mark.vm`) skips when an
     image is absent.
7. **Import boundary.** `tests/test_import_boundary.py` scans `src/` for
   `dissect`/`lzallright` imports: static imports plus `import_module` and
   `__import__` with a string. It includes 8 scanner self-tests. Plan task 8
   lists this test, but it is part of the M1a DoD, so it lands here.
8. **Shared helpers.** `tests/helpers.py` provides the synthetic superblock
   builder, sparse scratch images and a scratch-dir context under
   `images/scratch/`. No test uses `/tmp` or `tmp_path`.

**Ground-truth capture** (btrfs-progs v6.6.3, host; outputs in
`images/scratch/m1a/`). To rule out any write by btrfs-progs, dump-tree ran on
a byte-identical read-only copy, not on `sandbox.img` itself:

```sh
cp sandbox.img images/scratch/m1a/sandbox-ro.img && chmod 0444 images/scratch/m1a/sandbox-ro.img
sha256sum images/scratch/m1a/sandbox-ro.img     # 07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418
btrfs inspect-internal dump-super -fa images/scratch/m1a/sandbox-ro.img
btrfs inspect-internal dump-tree -t root images/scratch/m1a/sandbox-ro.img
btrfs inspect-internal dump-tree -t 5 -b 30785536 images/scratch/m1a/sandbox-ro.img   # gen 11
btrfs inspect-internal dump-tree -t 5 -b 30867456 images/scratch/m1a/sandbox-ro.img   # gen 12
btrfs inspect-internal dump-tree -t 5 -b 30539776 images/scratch/m1a/sandbox-ro.img   # gen 13
btrfs inspect-internal dump-tree -t 5 -b 30703616 images/scratch/m1a/sandbox-ro.img   # gen 14
btrfs inspect-internal dump-tree -b 30474240 images/scratch/m1a/sandbox-ro.img        # gen-13 extent tree (defect #8)
```

- **Superblock** (`dump-super -fa`): two copies, both `[match]`.
  - bytenr 65536, csum `0xeadc2eaa`, generation 14;
  - bytenr 67108864, csum `0x4abd0664`, generation 14;
  - the 256 GiB mirror does not fit.
  - Shared fields: root 30720000, chunk_root 22036480,
    chunk_root_generation 8, total_bytes 268435456, bytes_used 163840,
    csum_type 0, compat_ro 0xb (FST, FST_VALID, BGT), incompat 0x361.
- **Backup roots** (slot: tree_root gen / fs_root):
  - 0: 30572544 **13** / 30539776;
  - 1: 30720000 **14** / 30703616;
  - 2: 30801920 **11** / 30785536;
  - 3: 30883840 **12** / 30867456.

  All four share chunk_root 22036480 gen 8 and backup_total_bytes
  268435456.
- **Gen 11** (leaf 30785536, 8 items):
  - inode 256 is a dir (size 30) with DIR_ITEM/DIR_INDEX 2
    `target_file.txt` → 257;
  - inode 257 has size 31, nbytes 31, and INODE_REF index 2
    `target_file.txt`;
  - XATTR `security.selinux`;
  - `EXTENT_DATA 0` `type 0 (inline)`, `inline extent data size 31 ram_bytes
    31 compression 0`.
- **Gen 12** (not asserted on the old branch; captured now), full leaf:
  ```
  leaf 30867456 items 2 free space 16061 generation 12 owner FS_TREE
      item 0 key (256 INODE_ITEM 0) itemoff 16123 itemsize 160
          generation 3 transid 12 size 0 nbytes 16384
          block group 0 mode 40755 links 1 uid 1000 gid 1000 rdev 0
          sequence 3 flags 0x0(none)
      item 1 key (256 INODE_REF 256) itemoff 16111 itemsize 12
          index 0 namelen 2 name: ..
  ```
  So the gen-12 state is the root directory only, now empty (size 0).
  `target_file.txt` was deleted in transaction 12, not "by gen 14".
- **Gen 13** (leaf 30539776, 8 items):
  - inode 256 dir (size 32) → `large_target.txt` 257;
  - inode 257 has size 5242880 and INODE_REF `large_target.txt`;
  - `EXTENT_DATA 0` `type 1 (regular)`, disk byte 13631488, nr 5242880,
    ram 5242880, no compression.
- **Gen 14** (leaf 30703616): 2 items, the root dir only (size 0).
- **Defect #8 evidence** (gen-13 extent tree): `item 0 key (13631488
  EXTENT_ITEM 5242880) ... extent data backref root FS_TREE objectid 257`.
  The objectid is the address that EXTENT_DATA points to; the offset is the
  length.
- **Plan values checked.** Slot order 13, 14, 11, 12; chunk-root gen 8;
  total_bytes 268435456; newest backup tree_root == SB root 30720000; gen 11
  inode 257 31 B inline; gen 13 5 242 880 B; gen 14 root only. All are
  correct, and none is wrong. research.md §10.5's "both deleted by gen 14"
  is loose for `target_file.txt`, which is already gone at gen 12.

**Constant sources.** Linux tag `v7.0` (tag object `3131ff5a1174`), fetched as
`https://raw.githubusercontent.com/torvalds/linux/v7.0/<path>` into
`images/scratch/m1a/kernel/`:
- `include/uapi/linux/btrfs_tree.h`: structs l.473–1354, objectids l.38–130,
  keys l.143–377, csum enum l.386–391;
- `include/uapi/linux/btrfs.h`: feature bits l.298–339, sizes l.33 and
  l.62–63;
- `fs/btrfs/fs.h`: SB offset/size and static_assert l.80–82, masks l.286–330;
- `fs/btrfs/fs.c`: csum sizes and names l.12–17, `btrfs_csum()` l.44–62;
- `fs/btrfs/disk-io.h`: mirrors l.26–43;
- `fs/btrfs/disk-io.c`: `btrfs_check_super_csum` l.153–169, backup ring
  l.1596–1607, SB write l.3795–3810;
- `fs/btrfs/volumes.c`: `btrfs_read_disk_super` edge rule l.1356 and
  magic/bytenr check l.1378–1379.

Every size, offset and value is asserted in `tests/test_ondisk.py` with its
file:line.

**Checksum library choice: `crc32c` (ICRAR) 2.9.post0, as planned.** Checked
2026-09-15:

| | `crc32c` 2.9.post0 | `google-crc32c` 1.8.0 |
|---|---|---|
| Licence | LGPL-2.1-or-later (plan §3.3: fine as a separate, unmodified dep) | Apache-2.0 |
| cp314 wheels | 24: manylinux/musllinux x86_64, aarch64, riscv64; macOS; Windows; free-threaded `cp314t` too | 5; no musllinux or `cp314t` |
| Last release | 2026-09-11 | 2025-12-16 |
| `memoryview` input | accepted (zero-copy over the image mmap) | `TypeError: argument 1 must be read-only bytes-like object, not memoryview` |
| Speed (16 KiB blocks, this host) | ~20.8 GB/s, `hardware_based=True` | ~24.7 GB/s |
| `crc32c(b"123456789")` | `0xe3069283` | `0xe3069283` |

`crc32c` is simpler for us: it hashes mmap slices without copying, and it has
wheels for every platform and free-threaded build we might meet. The
`google-crc32c` swap stays documented in plan §3.3 for a frozen binary.
`xxhash` 4.0.1 (BSD-2-Clause) has cp314 and cp314t wheels.

**Generated images** (under `images/scenarios/`; host mkfs btrfs-progs
v6.6.3; guest kernel `7.0.0-31-generic`; QEMU 8.2.2; scenario s01; all
512 MiB):

| Name | Generator | Superblock | sha256 |
|---|---|---|---|
| `m1_xxhash` | `CSUM=xxhash corpus/vm/make_image.sh m1_xxhash` | xxhash64, gen 38, compat_ro 0x3, incompat 0x371 | `8f4190c9dc500bbdaa15f65fc7994ec8d5476a19b35aa07456f5bab336e98bf7` |
| `m1_sha256_bgt` | `CSUM=sha256 MKFS_ARGS="-O block-group-tree" corpus/vm/make_image.sh m1_sha256_bgt` | sha256, gen 38, compat_ro 0xb (BGT), incompat 0x371 | `f29c1e819d00f77816c3d7181eb38a3ea01c8ceffa7e9e16b6d0161cb93800b6` |
| `m1_blake2b` | `CSUM=blake2 corpus/vm/make_image.sh m1_blake2b` | blake2b, gen 38, compat_ro 0x3 | `909d7573e9725b2fec2dc07c7caaa6f9c3895de30feca759ea65ba89abc470db` |
| `m1_lzo` | `CSUM=xxhash MOUNT_OPTS=compress-force=lzo,commit=5 corpus/vm/make_image.sh m1_lzo` | xxhash64, incompat 0x369 (COMPRESS_LZO) | `fb6f3a0ad7a96244897a4b3e78d084899f8638b4ea0eeda7f584d2965efe7190` |
| `m1_zlib` | `CSUM=xxhash MOUNT_OPTS=compress-force=zlib,commit=5 corpus/vm/make_image.sh m1_zlib` | xxhash64, incompat 0x361 | `91a0140dd93310323281d99a3b79f130e0b02093fdea2282d570a49b924fbfc4` |
| `m1_unknown_incompat` | `uv run python corpus/mutate.py images/scenarios/m1_xxhash.img images/scenarios/m1_unknown_incompat.img set-incompat-bit 40` | both copies valid, incompat 0x10000000371 | `aa6d133f6600803eecf50506b86fd15ac74030c98b19c270b6e88427fd9f63c7` |
| `m1_mirror_damage` | `uv run python corpus/mutate.py images/scenarios/m1_xxhash.img images/scenarios/m1_mirror_damage.img zero-primary-sb` | mirror 0 zeroed, mirror 1 valid | `22472b300e20aca37c333e6e2030448ffbaedda237c46f63ebdb124325b546a7` |

- All five guest logs end in `=== SCENARIO-DONE`, and the balance line reads
  "had to relocate 3 out of 3 chunks".
- Guest-printed SHA-256s are identical across the five runs:
  - `keep.txt` `f6351f5e…9587a`;
  - `deleted_big.txt` `44969d02…3e5fd4`;
  - `deleted_inline.txt` `df6ff35a…5db2`.
- The five s01 generations are bit-unstable across reruns (§7). The manifest
  pins this run, and `test_local_image_matches_manifest_sha256` fails if an
  image is regenerated without updating the manifest.

**`btrfska info` per image** (full outputs in `images/scratch/m1a/info/`):

| Image | Copies | Selected / disagreements | csum type | compat_ro | Gate | Exit |
|---|---|---|---|---|---|---|
| `sandbox.img` | m0 valid `eadc2eaa`, m1 valid `4abd0664`, m2 not present | mirror 0 (gen 14) / none | 0 crc32c | 0xb, BGT note | OK | 0 |
| `m1_xxhash` | m0 `076c0ab4c57738b5`, m1 `103e07ea76928450` valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | OK | 0 |
| `m1_sha256_bgt` | m0 `215d22af…abebd9c`, m1 `4ab60866…17497132` valid | mirror 0 (gen 38) / none | 2 sha256 | 0xb, BGT note | OK | 0 |
| `m1_blake2b` | m0 `a6b01c3d…441ec5dd`, m1 `c34dd59f…7299a54e` valid | mirror 0 (gen 38) / none | 3 blake2b | 0x3 | OK | 0 |
| `m1_lzo` | both valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | OK | 0 |
| `m1_zlib` | both valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | OK | 0 |
| `m1_unknown_incompat` | both valid | mirror 0 (gen 38) / none | 1 xxhash64 | 0x3 | `REFUSED` + `UNSUPPORTED_INCOMPAT UNKNOWN_BIT_40` | 2 |
| same, `--allow-unsupported` | | | | | `OVERRIDDEN (--allow-unsupported: derived rows are unsupported_format=1)` + the same line | 0 |
| `m1_mirror_damage` | m0 `INVALID (magic mismatch, csum mismatch)`, m1 valid | **mirror 1** (gen 38) / `mirror 0 invalid: magic mismatch, csum mismatch` | 1 xxhash64 | 0x3 | OK | 0 |

The vm test `test_superblock_csums_agree_with_dump_super` also checks that
`btrfs inspect-internal dump-super -a` prints the same csum bytes with
`[match]` for every copy on the three non-crc32c csum images.

**Deviations** (none changes a plan decision; `plan.md` is not edited):
- **dump-tree ran on a read-only copy.** It ran on a hash-identical 0444
  copy of `sandbox.img` under `images/scratch/`, not on the file itself,
  so btrfs-progs could not write the evidence.
- **`m1_unknown_incompat` sets bit 40 in every copy.** The plan says "bit
  1<<40 set and superblock csum recomputed". Both copies get the bit, each
  with a recomputed csum. Patching only the primary would make best-copy
  selection report a disagreement, which mixes two effects into a test aimed
  at the gate. Both mutated images derive from `m1_xxhash` (the plan names no
  source), so the csum recompute is exercised on a non-crc32c type.
- **`m1_badnode` is deferred to M1b.** Metadata in the s01 images is DUP.
  Whether one or both copies of the leaf must be flipped depends on whether
  M1b's node reader falls back to the second stripe, and M1b owns that
  decision. `m1_lzo` and `m1_zlib` were trivial and are added now.
- **mkfs csum name.** `m1_blake2b` uses `CSUM=blake2`, the btrfs-progs 6.6.3
  mkfs spelling.
- **Device-end rule.** A superblock copy that ends exactly at the image end is
  treated as not present, as the kernel does (`volumes.c:1356`).
- **Unknown compat_ro bits are reported but not refused.** compat_ro only
  forbids writing, and the plan's gate specifies incompat bits only.
- **`NO_VALID_SUPERBLOCK`.** An image without any valid superblock exits 2
  with this line; the plan does not specify this case.
- **Bytenr check needs the magic.** The bytenr problem is reported only when
  the magic matches, so a zeroed copy reads "magic mismatch, csum mismatch"
  rather than three reasons.
- **Import-boundary test moved forward.** It lands here (plan task 8) because
  it is in the M1a DoD. The dissect.btrfs and lzallright oracles are not yet
  in the `dev` group.
- **Placeholder walker API.** The strict-xfail fs-tree tests import
  `btrfska.substrate.tree.fs_tree_inventory`, a placeholder name. M1b may
  rename it, but must make the four tests pass and remove the marker.
- **Sparse copies are coarser.** `mutate.py` keeps only all-zero 1 MiB
  chunks sparse, so derived images use 17–18 MiB on disk against ~10 MiB for
  their source (apparent size identical, 536 870 912 B).
- **Header citation.** research.md §10.3 cites `btrfs_tree.h` for
  incompat-bit values; they are defined in `btrfs.h`. This is recorded in
  §10.7, and §10.3 is not rewritten.

**Research notes.** Added as research.md §10.7:
- superblock copies agree on all healthy images, so a disagreement is
  evidence;
- the kernel's device-end rule;
- the feature bits live in `btrfs.h`;
- dump-super prints csum bytes in disk order;
- in every s01 image all four `backup_fs_root` slots are the same gen-19
  subvolume-5 tree. Deletions inside other subvolumes are invisible to
  `backup_fs_root` diffing, and the scenario's deletions already predate all
  four backups.

**Verification** (local, branch `feature/m1a-trust-foundations`; logs under
`images/scratch/m1a/verify/`).

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests (all, images present) | `uv run pytest -q` | `244 passed, 4 xfailed` (the four `test_fs_tree_contents_per_generation[11..14]`, reason `tree walker lands in M1b`) |
| Tests without vm | `uv run pytest -q -m "not vm"` | `226 passed, 18 deselected, 4 xfailed` |
| vm tests | `uv run pytest -m vm -q` | `18 passed, 230 deselected` |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `26 files already formatted` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done` | exit 0 |
| Lockfile | `uv lock --check` | `Resolved 10 packages` (consistent) |
| Info | `uv run btrfska info <image>` for `sandbox.img` and the seven `m1_*` images | table above |
| Scope | `git diff --stat main..HEAD` | 21 files: `src/btrfska/{cli.py,substrate/{ondisk,csum,superblock}.py}`, `tests/…`, `corpus/{mutate.py,manifest.tsv,vm/README.md}`, `pyproject.toml`, `uv.lock`, `README.md`, `research.md` (+ this catalog) |
| `sandbox.img` after | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime still 2026-04-26 18:49:36 |

The default count went from 84 (end of M0) to 248 collected. Of those, 18 are
vm tests; in CI, without images, all but `test_manifest_lists_every_m1a_image`
skip.

### Review fixes (2026-09-15)

The reviewer approved PR #8 with fixes. They checked the code against
btrfs-progs `kernel-shared/disk-io.c` and kernel v7.0 `fs/btrfs/disk-io.c`.
Every fix is test-first: the new tests were run and seen failing
(AttributeError or assertion) before the code changed. Kernel line numbers
refer to the v7.0 files in `images/scratch/m1a/kernel/`. btrfs-progs line
numbers refer to tag `v7.1` (identical in the checked-out `v7.1-56-g4d02bee`).

- **Commits:**
  - `25fac0a` Check superblock geometry against the kernel's validate_super rules
  - `aff550a` Anchor superblock selection on the first valid copy's fsid
  - `140b914` Validate mutate.py patches before creating the output
  - `c9a0351` Tighten the ground-truth xfails to ImportError and zip copies strictly
  - `be2addc` Add the m1_foreign_mirror image and note foreign superblock residue
  - this catalog update

1. **HIGH: a foreign mirror could win selection.**
   - **Before:** `select()` took the highest generation among csum-valid
     copies, whatever their fsid. A leftover 64 MiB copy of an earlier
     filesystem with a higher generation would have been reported as this
     image's identity and roots.
   - **Progs rule:** in recover mode, `btrfs_read_dev_super`
     (l.2022-2064) sets the fsid from the first accepted copy, and the
     metadata_uuid too when that copy has `METADATA_UUID` set (l.2037-2045).
     It then skips every later copy whose fsid or metadata_uuid differs
     (l.2046-2056), with the comment "contain data of different
     filesystems".
   - **Now:** `superblock.same_filesystem()` implements that rule. The
     lowest-offset valid copy anchors the identity. Only copies of the same
     filesystem compete on generation.
   - **Foreign copies:** valid copies of another filesystem go to
     `Selection.foreign`. They are reported as `mirror N foreign superblock
     at <offset> (fsid …[, metadata_uuid …], generation …)`, and `info` marks
     the copy line `(foreign fsid …)`.
   - **Differing fields:** an older same-filesystem copy now also names the
     other fields that differ: `mirror 0 generation 5 != selected generation
     6, differs in: root`.
   - **Tests:** synthetic cases cover a higher-generation foreign mirror,
     anchoring on mirror 1 when mirror 0 is damaged, metadata_uuid anchoring
     with and without the feature bit, and the CLI marker.
   - **Image:** `m1_foreign_mirror` (new `corpus/mutate.py transplant-sb`
     op). `m1_sha256_bgt`'s mirror-1 copy is placed into mirror 1 of a copy
     of `m1_xxhash`, with generation 1000 and the csum recomputed as
     sha256. sha256
     `a5c3e65a6b34f1668b432f6ed70d2135f4a67e515e7c752294cffe49b2f40ea2`.
   - **Oracle:** host btrfs-progs v6.6.3 `dump-super -a` prints
     `csum_type 2 (sha256)`, `[match]`, fsid
     `55692877-4e8d-4649-a76d-370de1420992` and generation 1000 for that copy.
     The vm test `test_superblock_csums_agree_with_dump_super` now includes
     the image.
   - **Research:** research.md §10.7 gains a dated note on foreign copies as
     evidence of a prior filesystem.
2. **MEDIUM: policy attribution.**
   - **Kernel:** it reads only mirror 0 at mount, via `open_ctree` →
     `btrfs_read_disk_super(bdev, 0, false)` (`disk-io.c:3333`).
     Highest-generation selection is btrfs-progs recover behaviour.
   - **Now:** the module docstring, the `select()` docstring and the
     catalog bullet above say so.
   - **CLI:** `btrfska info` prints `kernel would mount: mirror 0 (valid,
     generation N)` or `(invalid: reasons)` whenever the selection is not
     mirror 0, or when mirror 0 carries any problem. Warnings count, because
     the kernel rejects on every check btrfska mirrors.
   - **Tests:** a synthetic CLI test, and the vm test on `m1_mirror_damage`.
3. **MEDIUM: geometry sanity.**
   - **Scope:** `superblock.geometry_problems()` mirrors the
     `btrfs_validate_super` checks (`disk-io.c:2360-2580`) that matter to a
     read-only reader.
   - **When:** checks run only when the magic matches, like the bytenr check.
   - **New fields:** `SuperblockCopy.geometry_ok` joins `valid`. Every
     violation is recorded in `problems`.
   - **New constants** (asserted in `test_ondisk.py`): `MIN_BLOCKSIZE` 4096
     (`fs.h:59-62`, non-debug), `MAX_METADATA_BLOCKSIZE` 65536
     (`btrfs_tree.h:380`), and `MIN_SYS_CHUNK_ARRAY_SIZE` 97 = disk_key +
     btrfs_chunk with its embedded stripe (`disk-io.c:2554-2555`).

   | Check (v7.0 `disk-io.c`) | btrfska | Why |
   |---|---|---|
   | sectorsize power of two, 4096 ≤ s ≤ 65536 (l.2404-2408) | invalidates | all later slicing uses it |
   | nodesize power of two, sectorsize ≤ n ≤ 65536 (l.2417-2421) | invalidates | node reads slice by it |
   | root/chunk_root/log_root level < 8 (l.2384-2398) | invalidates | bounds walker recursion |
   | sys_chunk_array_size ≤ 2048 and ≥ 97 (l.2548-2561) | invalidates | the bootstrap chunk map is sliced from it |
   | known csum_type (`open_ctree` l.3345-3351) | invalidates (unchanged) | without a csum nothing is trusted |
   | root/chunk_root/log_root aligned to sectorsize (l.2429-2443) | warns | identity, backup roots and sys array stay usable; the node reader bounds-checks addresses; skipped when sectorsize is itself invalid |
   | num_devices == 0 (l.2527-2530) / > 2^31 (l.2524-2526) | warns | no slicing depends on it |

   - **Not mirrored:** super flags (l.2372), `leafsize == nodesize`
     (l.2422), the host page-size limit (l.2410), fsid vs the mounted device
     set (l.2445-2467), feature dependencies (l.2473-2508), `bytes_used`
     and stripesize (l.2514-2523), and `validate_sys_chunk_array` (l.2542;
     M1b parses the array).
   - **Output:** a valid copy with warnings prints `valid, … (warnings: …)`.
   - **Tests:** parametrised negatives (13 invalidating, 5 warning-only),
     plus a truncated-image test with sizes 1, 65536 and 69631, all below
     64 KiB + 4096. The truncated test passed at once: `read_copies()`
     already marks such slots not present. It stays as a guard.
   - **Helper change:** `tests/helpers.make_block` now builds realistic
     geometry (4096/16384, sys array 97, aligned root) and accepts
     field overrides.
4. **MEDIUM: xfails could mask M1b failures.**
   - **Now:** `xfail(strict=True, raises=ImportError, …)`.
   - **Probe:** `images/scratch/review-fixes/test_xfail_raises_probe.py`
     shows the marker works. The missing-module case gives `1 xfailed`; an
     AssertionError under the same marker gives `1 failed`.
5. **LOW: tree fsid.**
   - **Now:** `superblock.tree_fsid()` follows `btrfs_sb_fsid_ptr`
     (`volumes.c:734-740`): metadata_uuid when `METADATA_UUID` is set, else
     fsid. `info` prints `tree fsid:`.
   - **Tests:** synthetic with and without the bit; sandbox asserts tree
     fsid == fsid.
6. **LOW: mutate.py created the output before validating.**
   - **Now:** `main()` computes every patch and runs `check_patches()`
     before `open(dst, "xb")`.
   - **Test:** `test_invalid_source_leaves_no_output`.
7. **LOW: straddling patches.**
   - **Now:** `write_patched()` applies only the overlap of each patch with
     each chunk, and asserts the chunk length is unchanged.
     `check_patches()` refuses a patch past the image end.
   - **Tests:** a unit test with a 16-byte chunk: a patch inside one chunk,
     one straddling a boundary, one spanning three chunks, and one ending at
     EOF. A second test covers the past-EOF refusal.
8. **NIT.** `test_two_valid_copies_and_mirror_2_beyond_the_image` asserts
   the ground truth has two copies, then zips `copies[:2]` with
   `strict=True`. Mirror 2's absence is asserted just above.

**`btrfska info` after the fixes** (full outputs in
`images/scratch/review-fixes/info/`):
```
$ uv run btrfska info images/scenarios/m1_mirror_damage.img      # exit 0
  mirror 0 @ 65536: INVALID (magic mismatch, csum mismatch)
  mirror 1 @ 67108864: valid, generation 38, csum xxhash64 103e07ea76928450
  mirror 2 @ 274877906944: not present (beyond image end)
selected: mirror 1 (generation 38)
kernel would mount: mirror 0 (invalid: magic mismatch, csum mismatch)
disagreements:
  mirror 0 invalid: magic mismatch, csum mismatch
fsid: 554bf995-913e-4d56-9f61-5ce4f5e03ebf
tree fsid: 554bf995-913e-4d56-9f61-5ce4f5e03ebf

$ uv run btrfska info images/scenarios/m1_foreign_mirror.img     # exit 0
  mirror 0 @ 65536: valid, generation 38, csum xxhash64 076c0ab4c57738b5
  mirror 1 @ 67108864: valid, generation 1000, csum sha256 41c053c6…16204d498 (foreign fsid 55692877-4e8d-4649-a76d-370de1420992)
  mirror 2 @ 274877906944: not present (beyond image end)
selected: mirror 0 (generation 38)
disagreements:
  mirror 1 foreign superblock at 67108864 (fsid 55692877-4e8d-4649-a76d-370de1420992, generation 1000)
fsid: 554bf995-913e-4d56-9f61-5ce4f5e03ebf
tree fsid: 554bf995-913e-4d56-9f61-5ce4f5e03ebf
gate: OK
```
With selection by generation alone, `m1_foreign_mirror` would have reported
generation 1000 and `m1_sha256_bgt`'s fsid and roots.

**Verification** (logs in `images/scratch/review-fixes/verify/`):

| Check | Command | Result |
|---|---|---|
| `sandbox.img` before | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime 2026-04-26 18:49:36 |
| Tests | `uv run pytest -q` | `288 passed, 4 xfailed` (was 244 + 4) |
| vm tests | `uv run pytest -m vm -q` | `21 passed, 271 deselected` (was 18) |
| Tests without vm | `uv run pytest -q -m "not vm"` | `267 passed, 21 deselected, 4 xfailed` |
| Read-only scan and import boundary | `uv run pytest -q tests/test_readonly.py tests/test_import_boundary.py` | `53 passed`; `grep -rn 'dissect\|lzallright' src/` finds nothing |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `26 files already formatted` |
| Legacy runner | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` |
| Lockfile | `uv lock --check` | `Resolved 10 packages` |
| Scope | `git diff --stat c46f240..HEAD` | 14 files, +712/−64: `src/btrfska/{cli.py,substrate/{ondisk,superblock}.py}`, `corpus/{mutate.py,manifest.tsv,vm/README.md}`, `research.md`, `tests/…` (+ this catalog) |
| `sandbox.img` after | `sha256sum sandbox.img` | `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`, mtime unchanged |

**For M1b (node reader, chunk maps, tree walker).**
- Tree block headers must carry `superblock.tree_fsid(fields)`, not `fsid`.
  Validate node headers against it.
- The fs-tree xfails now accept only ImportError. Once the walker module
  exists, a wrong inventory fails the run.
- Make the four strict xfails in `tests/test_ground_truth.py` pass. The
  expected inode inventories are in `tests/ground_truth/sandbox.json` under
  `fs_tree_by_generation`; adapt the placeholder
  `fs_tree_inventory(img, bytenr)` call to the real API.
- Use `ondisk.HEADER`, `ITEM`, `KEY_PTR`, `CHUNK`/`STRIPE`, and
  `csum.block_csum_ok(csum_type, node)` over `[32:nodesize]`. The csum type
  comes from the selected superblock (`Selection.selected.fields`).
- Generate `m1_badnode` once the DUP-mirror read policy is decided, and add
  a `flip-byte` operation to `corpus/mutate.py` behind the same guards.
- On s01 images the backup `fs_root` never changes (§10.7). Walk subvolumes
  through each backup `tree_root`'s ROOT_ITEMs to see `sv1` history.
- A gate refusal must stop the walkers too: `superblock.gate(...).refused`,
  or `unsupported_format=1` rows when overridden.

## 2026-09-15 — M0: reset and scaffolding

- **Branch:** `feature/m0-scaffolding` (from `main` at `0d7e435`). Implements
  plan.md §5 M0 tasks 1–11. No forensic logic.
- **Commits:**
  - `3a88a50` Freeze the prototype under legacy/
  - `c536ce7` Untrack prototype output and ignore test caches
  - `c822a39` Add btrfska package skeleton and project config
  - `a103e22` Apply ruff formatting to corpus scripts (no functional change)
  - `ba5f19f` Add Apache License 2.0
  - `9f26797` Rewrite README for btrfska and drop commands.txt
  - `bc60d4c` Add read-only and CLI tests with a sandbox hash guard
  - `964cc42` Track a zstd-compressed sandbox.img fixture for CI
  - `38057bb` Add GitHub Actions CI
  - this catalog entry (the commit after `38057bb`)

**What was done.**
1. **Legacy frozen.** `main.py`, `utils/`, `tests/` moved with `git mv` to
   `legacy/` (all renames detected, R095–R100). Stray `__pycache__` removed.
   The only legacy edits are the four path constants: `SANDBOX_IMG` in
   `test_integration.py` and `test_targeted_scan.py` now resolves the repo
   root (`dirname` ×3). `TEST_OUTPUT` and `TEST_OUT` now point to
   `images/scratch/legacy-tests/{integration,targeted}`.
2. **Untracked:** `recovery_output/` (8 files, kept locally). `.gitignore`
   gains `recovery_output/`, `.pytest_cache/`, `.ruff_cache/`.
   `mnt_sandbox/` removed.
3. **Package** `src/btrfska/`:
   - `__init__.py` (`0.0.1`), `__main__.py`, `cli.py` (argparse, `--version`,
     `info IMAGE` printing path, size and sha256);
   - `substrate/__init__.py` (empty);
   - `substrate/image.py`: `open_image()` → `ImageHandle`, the single
     open site (`os.open(O_RDONLY)` + `mmap.ACCESS_READ`, size via `lseek`
     so block devices work later, `sha256()`, context manager).
4. **`pyproject.toml`** as specified (btrfska 0.0.1, Apache-2.0, `uv_build`,
   dev group pytest/ruff, pytest and ruff config). `uv lock` resolved
   pytest 9.1.1 and ruff 0.16.7.
5. **Corpus formatting commit** touches only
   `corpus/vm/probe_stale_metadata.py` (7 insertions, 6 deletions). The probe
   on `images/scenarios/s01_discard_none.img` printed `367 355 18 832` both
   before and after.
6. **LICENSE:** verbatim Apache-2.0 text from apache.org (11 358 bytes,
   sha256 `cfc7749b…bc523d30`).
7. **Tests:**
   - repo-root `conftest.py`: `REPO_ROOT`, a `sandbox_img` fixture, and an
     autouse session hash guard (expected hash checked at start, unchanged
     at end);
   - `tests/test_cli.py`: 3 tests;
   - `tests/test_readonly.py`: O_RDONLY via `fcntl`, mmap write →
     `TypeError`, size/sha256, the AST open-site scan, and 10 cases proving
     the scanner flags write opens.
8. **README** rewritten per task 8. `commands.txt` removed; its two
   "running at once" lines live in a legacy subsection with `legacy/` paths.
9. **Fixture:**
   - `tests/fixtures/sandbox.img.zst` is 14 963 bytes (`zstd -19` from a
     read-only read);
   - its round trip gives `07ca38d4…5876418`;
   - `tests/fixtures/SHA256SUMS` pins the hash.
10. **CI:** `.github/workflows/ci.yml` follows the task-10 outline step for
    step.

**Verification** (all run locally on the branch; logs under
`images/scratch/m0/`).

| Check | Command | Result |
|---|---|---|
| Legacy baseline (untouched tree) | `uv run --python 3.14 python -m unittest discover -s tests` | `Ran 37 tests`, `OK`; `git status` clean, no `test_output_*` left |
| Legacy after move | `uv run python -m unittest discover -s legacy/tests` | `Ran 37 tests`, `OK` (same count); integration/targeted ran, output dirs removed on teardown |
| Lint | `uv run ruff check .` | `All checks passed!` |
| Format | `uv run ruff format --check .` | `14 files already formatted` |
| Tests | `uv run pytest` | `54 passed` (17 new + 37 legacy), 0 skipped, so no `sandbox.img not found` in the `-ra` summary |
| Sandbox subset | `uv run pytest -m sandbox` | `1 passed, 53 deselected` |
| CLI | `uv run btrfska --help` / `uv run btrfska --version` | usage printed, exit 0 / `0.0.1` |
| uvx | `uvx --from . btrfska --version` | built the wheel, printed `0.0.1` |
| Info | `uv run btrfska info sandbox.img` | `size: 268435456 bytes`, `sha256: 07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418` |
| Shell syntax | `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done` | exit 0 (10 files) |
| CI equivalent, clean clone | `git clone --branch feature/m0-scaffolding . images/scratch/m0/ci-clone`, then every ci.yml step in it | `uv sync --locked` OK; ruff clean; `sh -n` OK; fixture restore `sandbox.img: OK`; `54 passed`; unittest `Ran 37 tests` OK; `--help` OK |
| Smoke (local, `/dev/kvm` present) | `corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh && corpus/vm/make_image.sh smoke_s01` | printed `images/scenarios/smoke_s01.img`; log has `=== SCENARIO-DONE` (1.5 s wall). Not a merge gate |
| Scope | `git status`, `git diff --name-status main..HEAD` | only planned paths changed; working tree clean apart from gitignored `images/` |
| `sandbox.img` | `sha256sum sandbox.img` | before: `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`; after: `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`; mtime still 2026-04-26 |

**Deviations and small additions** (none changes a plan decision, so
`plan.md` is not edited):
- `--version` prints the bare version (`0.0.1`), which matches the
  acceptance check literally.
- `pyproject.toml` also sets `description` and `readme`.
- `ImageHandle` exposes `fd`, so the O_RDONLY test can read the access mode
  with `fcntl`.
- `main()` turns `OSError`/`ValueError` into exit 1 with a message on
  stderr; a missing image is tested.
- The AST scan is slightly stricter than specified. It also flags
  `x.open(...)` calls in a write mode (`Path.open`, `io.open`) and treats a
  non-constant mode as a write.
- The conftest guard also checks the *expected* hash at session start, so a
  wrong fixture fails loudly.
- The legacy CLI line in README writes to `images/scratch/legacy-out` (the
  plan's canonical command), not `recovery_output`.
- "CI green on the PR" can only be checked once the branch is pushed. The
  clean-clone run above is the local equivalent. The action majors
  (`checkout@v7`, `setup-uv@v10`) were taken from the plan. On the first PR run, CI failed at job setup because `astral-sh/setup-uv` has no floating `v10` tag; the workflow now pins `setup-uv@v10.1.0` and CI passes (run 34904950286, 17 s). These pins were not otherwise
  re-checked here.

**Review fixes** (commits `f2ce4d4`, `0bfaa12`, `0da22ba`; each test
written and seen failing before the fix):
- **Import mode:** pytest `addopts` gains `--import-mode=importlib`, plus
  `pythonpath = ["."]`. A throwaway `tests/test_crc32c.py` failed collection
  before the change and collected cleanly after.
- **Single hash source:** `conftest.py` parses `tests/fixtures/SHA256SUMS`
  (the file CI checks); `tests/test_cli.py` imports `SANDBOX_SHA256` from
  conftest. No Python file holds the hash literal any more.
- **Write scan** (`tests/test_readonly.py`):
  - resolves imports, so aliased `os.open` is caught;
  - flags write-capable APIs by qualified name (`os.fdopen`,
    `os.truncate`/`ftruncate`, `io.FileIO`, `shutil.copy*`/`move`,
    `tempfile.*`) and write-only method names on any receiver
    (`write_bytes`, `write_text`, `truncate`, …);
  - flags `mmap` unless `access` is literally `ACCESS_READ`.
  - One `WRITE_ALLOWLIST` holds only `substrate/image.py`; M4 `recover`
    writers join it explicitly.
  - Deviation: `copy`/`move` are matched only when they resolve to `shutil`,
    not on any receiver, because `dict.copy()` would be a false positive.
  - 24 new self-test cases (19 failed before the fix). A new test proves the
    allowlist matters only for `image.py`'s one `os.open` call; its read-only
    mmap passes the scan.
- **File-type gate** (`substrate/image.py`):
  - opens with `O_RDONLY | O_NONBLOCK`, so a FIFO cannot block;
  - then `fstat`s the fd and requires `S_ISREG`/`S_ISBLK`, otherwise closes
    it and raises `ValueError("not a regular file or block device: …")`;
  - restores blocking mode afterwards;
  - rejects empty images with `ValueError("empty image: …")`;
  - makes `close()` idempotent.
  - Tests use dirs under `images/scratch/`, not `tmp_path`: directory (was
    ENOMEM), FIFO under a 5 s `SIGALRM` guard (was a hang), empty file,
    symlink to a regular file, double close. The first four failed before
    the fix; the symlink case already passed.
  - `btrfska info images/scratch` now prints the clear error and exits 1.
- **Verification:**
  - `uv run pytest -q`: `84 passed` (54 + 30 new);
  - `uv run ruff check .`: `All checks passed!`;
  - `uv run ruff format --check .`: `14 files already formatted`;
  - `uv run --python 3.14 python -m unittest discover -s legacy/tests`:
    `Ran 37 tests`, `OK`;
  - `sandbox.img` sha256 is still `07ca38d4…5876418`, mtime still
    2026-04-26; no `test_readonly_*` scratch dirs are left behind.

**Follow-ups for M1.**
- ~~Test basename collisions between `tests/` and `legacy/tests/`~~: resolved
  by `--import-mode=importlib` (review fixes above).
- The hash guard runs under pytest only. The original `unittest` runner for
  `legacy/tests` has no guard.

## 2026-09-15 — Plan revision after research refresh

- **Branch:** `docs/plan-revision-2026-09` (PR #6). Docs only: `plan.md`,
  this entry, and after review small consistency edits to `research.md` and
  `README.md`. No code changed.
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
   - The first draft kept dissect.btrfs for file streams + decompression
     behind an adapter module. **Superseded in the review round below:**
     all runtime parsing, extent reads and decompression are ours, and
     dissect.btrfs is a test oracle only.
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
   - Guest-driven measurements need ≥ 5 runs with a per-column median and
     range (the §10.4 discard rows differ by 2 in columns 1–3 and by 4 in
     column 4); tolerances come from the measured range.
10. **M0 made executable** (11 ordered tasks):
    - legacy moved to `legacy/`, with its sandbox/output paths re-pointed so
      tests don't silently skip;
    - `src/btrfska` skeleton with a single read-only open site;
    - pyproject with `uv_build`, pytest, ruff;
    - LICENSE (Apache-2.0 after review), README rewrite;
    - CI outline;
    - exact commands and acceptance checks.

    M1 is broken into 11 ordered tasks.
11. Sections renumbered: §3.5 Substrate decision added (License stays §3.3,
    so research.md §7.4's pointer still holds); §7 Research Method inserted,
    so Paper Plan → §8, Risks → §9 (SecurityRonin marked as a realised risk),
    Working Conventions → §10. research.md §10.6's plan references were
    updated to the new numbering in the review round below.

**Checks made while revising (read-only).**
- PyPI `btrfska` → HTTP 404 (no collision); the name is kept.
- `sandbox.img` sha256 `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`
  (matches §10.4). `zstd -19` compresses it to 14 963 bytes, and the piped
  round-trip reproduces the same hash with no file written. This is the basis
  for the CI fixture (M0 task 9; tracking decided in the review round).
- dissect.btrfs 1.10 metadata: `requires-python >=3.10`, zstd via
  `backports.zstd` only below 3.14.
- `recovery_output/` (8 files) is still tracked in git → untracked in M0.
- There is no `.github/` yet.
- `mmap.ACCESS_READ` write raises `TypeError` (basis for the M0 read-only
  test).

**Open items for the owner** (as first drafted; status after review):
- (a) ~~approve tracking `tests/fixtures/sandbox.img.zst`~~ — resolved:
  tracked in M0 (task 9);
- (b) ~~tag `feature/m1-backup-roots` as `m1-prototype`~~ — done: annotated
  tag pushed to origin, pointing at the branch tip `26715ba`; the branch is
  kept;
- (c) gen-12 contents of `sandbox.img` are not yet recorded anywhere
  (M1 task 1 captures them) — still open.

### Review round (2026-09-15)

A reviewer approved the revision with fixes; the manager took decisions
A–C. All changes are to `plan.md`, `research.md`, `README.md` and this
entry.

**Decisions.**
- **A. Substrate → dissect.btrfs as test oracle only** (plan §3.5).
  - Why: dissect maps only through its own current chunk tree and has no
    API to route streams through our validated reader or historical chunk
    maps. M1 needs our own extent reads anyway, so dissect's only unique
    runtime contribution was decompression.
  - All runtime parsing (own `struct` tables in `ondisk.py`), extent reads
    (`extents.py`) and decompression (`compress.py`: stdlib `zlib` and
    `compression.zstd`, own LZO1X in `lzo.py`) are ours.
  - dissect.btrfs 1.10 and `lzallright` 0.2 are dev/test oracles in
    `tests/oracle/`.
  - The fallback ladder is lzallright at runtime (stays Apache-2.0), then
    dissect.btrfs at runtime, which would make the tool AGPL-3.0-or-later.
  - "Adapter / AGPL boundary" wording is replaced by a *replacement
    boundary* (`extents.py` + `compress.py`).
- **Licence → Apache-2.0** (plan §3.3): chosen for DFIR/academic reuse and
  the patent grant. Every runtime dependency was checked: numpy BSD-3 (+0BSD/
  MIT/Zlib/CC0), xxhash BSD-2, crc32c LGPL-2.1+ (fine as a separate
  dependency; `google-crc32c` Apache-2.0 is the swap-in for frozen
  binaries), M8 Rust crates Apache/MIT, M9 Starlette/Jinja2 BSD-3 and htmx
  0BSD. Test-only use of AGPL dissect.btrfs does not make the package AGPL
  (not conveyed; dev group only; import-boundary test).
- **B.** `tests/fixtures/sandbox.img.zst` is tracked in M0; no sign-off
  pending (plan task 9, §9 risks).
- **C.** `m1-prototype` tag: done.

**LZO decoder evaluation** (scratch venv, seeded; details in plan §3.5).
- Candidates: `python-lzo` (GPL, rejected); `dissect.util` 3.24
  (Apache-2.0); `lzallright` 0.2.6 (MIT); `lzokay` 2.1.0 (MIT, 1 star).
- 2 000 round-trip vectors: dissect.util (pure and native) and lzallright
  all decode identically.
- Hostile input:
  - dissect.util native panics (`PanicException`, not an `Exception`) on a
    crafted lookbehind stream and on 58/300 bit flips;
  - dissect.util pure Python silently returns 4 bytes for the crafted
    stream;
  - lzallright raises `LZOError`.
- 139–160 of 300 bit flips decode to wrong bytes in every decoder, so LZO
  success is never content evidence.
- Choice: our own bounds-checked pure-Python LZO1X decoder (written from
  `Documentation/staging/lzo.rst`, not GPL source), with lzallright as
  oracle and fallback.

**Reviewer fixes.**
1. M0 acceptance made achievable:
   - `ruff format --check` (ruff 0.16.7) flags 14 files today: 13
     prototype files that move to the excluded `legacy/`, plus
     `corpus/vm/probe_stale_metadata.py`;
   - task 5 now ends with a formatting-only commit for `corpus/`;
   - the git-status allow-list gains `corpus/` and `conftest.py`.
2. §3.5 contradiction resolved by A (own `struct` tables, no cstruct).
3. Superseded by A.
4. AGPL wording fixed per A.
5. This entry now names the branch/PR; open items (a)/(b) resolved.
6. Jitter: §7 and the M2 DoD use a per-column median and range from ≥ 5
   runs, with tolerances taken from the measured range. The per-image probe
   comparison is exact. §7 template gains an environment record (host
   CPU/RAM/storage, host kernel, QEMU, guest kernel, btrfs-progs, Python +
   `uv.lock` hash, git commit, image sha256).
7. Minor fixes:
   - Task 1: the suites remove their own `test_output_*` dirs.
   - Task 2: only the four path constants change (makedirs already fine).
   - Task 3/8 ordering: `commands.txt` removal moved into task 8.
   - M0 `corpus/vm` touchpoint: CI `sh -n` syntax check (passes;
     shellcheck 0.9.0 fails on style notes, so it is not a gate) plus a
     documented local smoke command.
   - Reclaim axis added to the M7 matrix (reclaim × discard).
   - CI actions: `actions/checkout@v7` (v7.0.1) and `astral-sh/setup-uv@v10`
     (v10.1.0), verified via the GitHub API.
8. Cross-references:
   - research.md §10.6 now points at plan §8 (positioning, paper plan),
     §9 (risks), §6.2 and §3.3;
   - README says M0–M9;
   - research.md §1 item 4 already carried the TSK correction (PR #3065,
     `develop`, 2024-11-27, unreleased), so it is unchanged;
   - research.md §1 item 3, §2.2, §7.4, §10.2 and §10.6 note the
     test-oracle refinement;
   - §10.4 records the per-column jitter;
   - §10.5 and open question (c) record the tag.

**Verified while fixing (read-only).**
- Python 3.14.6: `compression.zstd` (libzstd 1.5.7) round-trips.
- Kernel v7.0 `fs/btrfs/lzo.c`: 4-byte total/segment headers, 4 419-byte
  segment bound for 4 KiB sectors, sector-tail padding, and it calls
  `lzo1x_decompress_safe`.
- All `corpus/vm` shell scripts pass `sh -n`.
- `git ls-remote` shows `refs/tags/m1-prototype`, which dereferences to
  `26715ba`.

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
(commits `5cee53f`, `44225e1`, `26715ba`, 2026-08-14; forked from `9b9cfd3`,
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

- **Branch:** `main` — **Commits:** `160233e` "added more research",
  `d2177e3` "added docs and recovery output"
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

- **Branch:** `feature/m2-targeted-orphan-scan` — **Commits:** `0addd8d`
  (feature), `48f8b0a`/`9b9cfd3` (PR merges), `9955b53` (catalog doc)
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
