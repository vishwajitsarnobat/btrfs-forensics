# Build Plan — Btrfs Filesystem-State Archaeology

> Written 2026-08-17 from the verified research in [`research.md`](research.md).
> History lives in [`catalog.md`](catalog.md). This plan is forward-looking
> only; update it when decisions change, and log every completed step in the
> catalog.

---

## 1. What We Are Building (and Not Building)

**Thesis.** Btrfs's copy-on-write design leaves behind a graph of historical
metadata — orphaned nodes, beyond-`nritems` item remnants, backup and
superseded roots, free-space-tree state, relocated-chunk residue. Existing
tools *salvage files*; published work ("Beyond Carving", IEEE Access 2026)
now also *lists deleted files deterministically* from historical roots.
**Nobody reconstructs filesystem history as an evidence graph with
provenance and confidence.** That is the product and the paper.

**Product one-liner:** an open-source forensic engine that ingests a raw
Btrfs image, builds a queryable evidence catalog of *every* metadata
artifact ever left on disk, and answers: *what existed, when, what changed,
what can be recovered, how confidently, and was anything hidden?*

**Explicit novelty claims** (each mapped to a verified gap in research.md §6):

| Claim | Gap | Beats prior art how |
|---|---|---|
| C1. Orphan-item & slack archaeology as a recovery source (beyond-`nritems` items, node slack, kernel ORPHAN_ITEM 0x30) | G1 | Beyond Carving scans whole valid blocks only — deep leaf scanning is *their stated future work*; we already have it working |
| C2. Free-space-tree forensics: prove blocks were freed; overwrite-risk scoring | G2 | Zero tools, zero papers (sweep-confirmed) |
| C3. Full-state generation diffing → per-file timelines (create/modify/rename/delete + content deltas) | G3 | Beyond Carving diffs objectid *sets* (existence only) |
| C4. Confidence tiers (Confirmed/Probable/Unattached) with per-artifact provenance chains, csum-verified content | G4 | Only X-Ways's binary flag exists |
| C5. Hiding detection targeting the Toolan & Humphries + Schwietert & Hilgert technique lists, evaluated against fishy-generated images | G5 | Papers propose hiding; nobody ships detection |
| C6. Orphaned/relocated-chunk forensics + historical chunk-map reconstruction | G6 | Our sandbox discovery (21/71 orphans outside chunk map); their future work |
| C7. First public btrfs deleted-file benchmark corpus + systematic tool benchmark | G8 | None exists (verified: no btrfs at digitalcorpora/CFReDS) |

**Not building (exists elsewhere; reuse or benchmark instead):** raw-image
tree parsing/extraction plumbing (dissect.btrfs), old-root salvage
(`btrfs restore`/find-root), carving (PhotoRec), chunk repair
(chunk-recover, btrfs-rec), write-mode repair of any kind. The tool stays
**strictly read-only** (forensic soundness).

---

## 2. Architecture

Six layers; each independently testable.

```
┌──────────────────────────────────────────────────────────────┐
│ 6. Interfaces: CLI (argparse) · JSON/text reports · notebooks │
├──────────────────────────────────────────────────────────────┤
│ 5. Analysis: confidence & provenance · csum verification ·   │
│    FST/overwrite-risk · hiding detection                     │
├──────────────────────────────────────────────────────────────┤
│ 4. Reconstruction: anchored historical walks · orphan graph  │
│    assembly · generation diff → timelines · subvol recovery  │
├──────────────────────────────────────────────────────────────┤
│ 3. Evidence catalog (SQLite): nodes, edges, items, roots,    │
│    chunks, backrefs, artifacts — all with provenance         │
├──────────────────────────────────────────────────────────────┤
│ 2. Scan kernel: strided FSID prefilter + csum validation +   │
│    targeted regions + old-root discovery                     │
│    (numpy/mmap now → Rust/PyO3 later; identical interface)   │
├──────────────────────────────────────────────────────────────┤
│ 1. Substrate: dissect.btrfs — image/devices, superblock,     │
│    chunk map, BTree(root_offset=…), file streams incl.       │
│    zlib/lzo/zstd  + our thin extensions (mirrors, backup     │
│    roots, csum_type dispatch)                                │
└──────────────────────────────────────────────────────────────┘
```

Design rules:

- **Scan once, query forever**: the image is read in one pass (plus targeted
  re-reads); everything else queries the catalog.
- **Provenance on every row**: how was this artifact discovered (anchored
  walk from which root / scan hit at which physical offset / slack region of
  which node), csum status, generation, owner.
- **Never collapse ambiguity**: contradictory metadata from different
  generations are all recorded; confidence tiers express uncertainty instead
  of guessing.
- Scan kernel has a frozen interface (`iter_candidate_nodes(image, regions)
  → NodeRecord`) so the numpy implementation can be swapped for Rust without
  touching layers 3–6.

## 3. Stack Decision

### 3.1 Decision

- **Language:** Python ≥ 3.11 for everything except the scan kernel's fast
  path. Rust (PyO3/maturin) scan core in M8; the numpy path remains as
  fallback. No Go/Zig/C++ (research.md §7).
- **Core deps:** `dissect.btrfs` (substrate), `numpy` (scan kernel),
  `crc32c` (SSE4.2 CRC32c), `xxhash` (csum dispatch); stdlib `sqlite3`,
  `argparse`. Dev: `pytest`, `ruff`, `uv`; CI via GitHub Actions.
- **Packaging:** `pyproject.toml` + uv lockfile, src layout, published to
  PyPI so reviewers run `uvx <tool> scan image.dd`.
- **Catalog:** SQLite, single-file `evidence.db` (hashable, chain-of-custody
  friendly). Build-phase tuning: batched transactions, indexes after load.
  Optional DuckDB/Parquet export for notebook analytics.
- **Rationale** (full analysis research.md §7): pure-stdlib Python is
  15–40 h/TB (non-viable); numpy+crc32c is I/O-bound (~20–75 min/TB);
  Python keeps research iteration and the DFIR/pip ecosystem; Rust core
  later gives bulk_extractor-class performance and a paper-citable
  memory-safety story. Dissect itself validates the hybrid pattern.

### 3.2 Two-track structure

- **Track R (research/paper):** everything through M7 in Python. The paper
  does not wait for Rust.
- **Track P (product):** M8 Rust core + wheels + optional standalone CLI.

### 3.3 License

Importing `dissect.btrfs` (AGPL-3.0) makes the tool **AGPL-3.0**. Accepted:
it is genuinely open source, standard in DFIR (all of Dissect), and doesn't
hinder the paper. Our novel modules (layers 2–6) are original code, so if a
permissive license ever becomes a goal, the substrate can be swapped
(candidates: our legacy parser, or Rust `rustutils/btrfsutils`
MIT/Apache — re-evaluate its maturity then). Document this boundary: keep
all dissect imports inside `substrate/`.

### 3.4 Naming

Repo stays `btrfs-forensics`. Working package/CLI name: **`btrfska`**
("btrfs archaeology") — placeholder; decide before first release (check
PyPI collision then).

---

## 4. Migration of the Current Prototype — What to Delete vs Keep

Principle: **most of the prototype is a re-implementation of things
dissect.btrfs and btrfs-progs already do correctly — that code is dead
weight and goes.** Only the parts that encode *our novel logic* or *validated
empirical results* are worth carrying. Nothing is physically deleted until
its replacement passes the same tests, but the verdicts below say plainly
what survives.

Step 0: `git mv` current `main.py utils/ tests/` → `legacy/` (a frozen
reference kept runnable for cross-checks during migration, then dropped to a
git tag once M4's parity gate passes — see end of section). Everything in
the "DELETE" rows below is thrown away at that point and not ported.

### 4.1 Verdict per file

Three verdicts: **DELETE** (redundant reimplementation — the capability
exists in a maintained library/tool; keep nothing), **MIGRATE** (novel or
hard-won logic — port carefully with byte-identical behaviour, golden-
tested), **REWRITE** (the *concept* survives but the code is replaced).

| Current file | Lines | Verdict | Why / what replaces it |
|---|---|---|---|
| `utils/crc32c.py` | 33 | **DELETE** | Pure-Python CRC32c reimplements the `crc32c` PyPI C-ext (SSE4.2, ~1000× faster) and is anyway wrong-by-omission (no xxhash/sha256/blake2b). Keep only the RFC-3720 test vectors as an oracle. |
| `utils/superblock.py` | 93 | **DELETE** | dissect.btrfs parses the superblock; ours reads only the primary (misses mirrors) and doesn't validate its checksum. |
| `utils/constants.py` | 172 | **DELETE** | On-disk constants/offsets live in dissect's cstruct definitions; maintaining our own table is a bug source (it already caused the DEV_ITEM offset defect). |
| `utils/inode_parser.py` | 132 | **DELETE** | dissect parses `btrfs_inode_item`; ours is a hand-rolled duplicate. |
| `utils/tree_walker.py` | 87 | **DELETE** | Superseded by dissect's `BTree(root_offset=…)` + `Cursor`, which already does arbitrary-root walking with validation. |
| `utils/chunk_parser.py` — chunk map + logical→physical | ~200 of 281 | **DELETE** | dissect builds the chunk map and translates addresses (incl. multi-device); single-stripe-only is a defect we don't want to carry. |
| `utils/chunk_parser.py` — `build_scan_regions()` (typed chunks + unmapped gaps) | ~80 of 281 | **MIGRATE** | Novel: the typed-region + relocated-chunk-gap logic behind the 21/71 finding. Port to `scan/regions.py`, add the MIXED_GROUPS fix. |
| `utils/btree.py` — raw sweep loop | ~200 of 968 | **REWRITE** | Concept (nodesize-strided FSID+csum sweep) survives; code replaced by the numpy/mmap kernel (`scan/kernel_numpy.py`). Pure-Python loop is non-viable at scale (research.md §7). |
| `utils/btree.py` — orphan-item scan (beyond `nritems`), internal key-ptr scan, leaf/internal slack mining | ~400 of 968 | **MIGRATE** | **This is the crown jewels** — the exact capability Beyond Carving dismisses as an "edge case" and never implements. Port to `recover/orphans.py` + `recover/slack.py`, byte-for-byte, golden-tested against legacy output. |
| `utils/btree.py` — item parsing + inline/regular extract | ~350 of 968 | **REWRITE** | Parsing/extraction replaced by dissect structs + streams (gains zlib/lzo/zstd we lack). **Keep the ideas:** `(inode, generation)` keying, move/rename tagging, extent dedup — reimplement on top of dissect. |
| `utils/orphan_scan.py` — live-metadata set via extent tree | 109 | **MIGRATE** | Useful (the "what's currently allocated" complement that defines orphan territory). Reparent onto dissect's walker in `scan/live_set.py`. |
| `utils/recovery_report.py` | 230 | **REWRITE** | Flat counters → the SQLite evidence catalog + provenance/confidence report (M3/M6). Concept of a machine-readable report survives; the shape changes entirely. |
| `main.py` | 201 | **REWRITE** | New CLI (subcommands: scan/catalog/recover/timeline/detect-hiding) over the new pipeline. |
| `tests/` (4 files) | 519 | **MIGRATE** | Port assertions as golden tests: the 71/21/gen-13 numbers, RFC-3720 CRC vectors, inode fixtures, targeted-scan parity. These *are* the regression safety net for everything above. |

**Tally:** of ~2,830 lines, roughly **~1,000 lines DELETE** (crc32c,
superblock, constants, inode_parser, tree_walker, chunk map/translate —
all redundant with dissect.btrfs), **~590 lines MIGRATE** (orphan/slack
archaeology, scan regions, live-set, tests — the novel core), **~750 lines
REWRITE** (sweep loop, item parse/extract, report, CLI — concepts kept,
code replaced). Net: the majority of the prototype is redundant plumbing;
the defensible ~590 lines is what the paper is actually about.

### 4.2 Also delete (non-code)

- `docs/research_report.md`, `docs/catalog.md` — already removed (superseded
  by root `research.md`/`catalog.md`).
- `commands.txt` — fold the sandbox build/mount recipe into the new corpus
  generator (M7) and README, then delete.
- `recovery_output/` — regenerated artifacts; keep out of git (add to
  `.gitignore`), don't carry forward.
- Prototype's "defrag hazard" heuristic — **do not migrate as-is**: it was
  mis-attributed to Wani 2020 (which never discusses defrag; see research.md
  §8.4). Re-derive from first principles or drop.

### 4.3 Migration-done gate (end of M4)

New pipeline on `sandbox.img` reproduces the legacy report (same 71 orphans,
same 21 outside-map, same recovered files) **plus** compression,
csum-dispatch, superblock mirrors, and backup-root walking. When that gate
is green, tag `legacy-final` and delete `legacy/`.

---

## 5. Milestones

Each milestone = one feature branch + PR + catalog.md entry. Estimates
assume one focused developer.

### M0 — Reset & scaffolding (~2–3 days)
- Move prototype to `legacy/`; src layout `src/btrfska/…`; pyproject + uv;
  pytest + ruff + CI (lint, tests on sandbox fixture); AGPL-3.0 LICENSE;
  README rewrite pointing at the three docs.
- **DoD:** `uv run pytest` green (legacy tests still runnable);
  `uvx --from . btrfska --help` works.

### M1 — Substrate + anchored walking (~1 week)
- `substrate/`: wrap dissect.btrfs (image open incl. multi-device;
  chunk map; `BTree` access). Extensions: read SB mirrors (pick best by
  generation à la `super-recover`), parse the 4 `btrfs_root_backup` entries,
  `csum_type` dispatch (crc32c/xxhash/sha256/blake2b) + verify node and
  superblock csums (dissect doesn't).
- Anchored walks: current roots + backup roots + any user-supplied bytenr;
  enumerate subvolumes via ROOT_ITEM/ROOT_REF/ROOT_BACKREF.
- Ground truth in tests via `btrfs inspect-internal dump-tree` subprocess.
- **DoD:** walking the sandbox gen-13 backup state lists the same files the
  legacy sweep finds for gen 13, with anchored provenance; works on a
  xxhash-formatted test image (legacy tool finds nothing there — regression
  proof for defect #1).

### M2 — Scan kernel v1 (~1 week)
- `scan/kernel_numpy.py`: mmap + `np.frombuffer` strided FSID compare +
  csum validation via dispatch + multiprocessing over image chunks; probe
  at sectorsize (4 KiB) alignment, not just nodesize, to catch odd layouts.
- Port targeted regions (typed chunks + unmapped gaps) with the
  MIXED_GROUPS fix (parse incompat_flags); `--full-sweep` fallback.
- Old-root discovery: from scan hits, group root-tree-owned blocks by
  (owner, level, generation) — find-root's algorithm feeding our catalog
  instead of stdout.
- **DoD:** sandbox parity (71 orphans, 21 outside map, identical offsets);
  ≥200 MB/s single-core on a synthetic 10 GiB image; benchmark script
  committed.

### M3 — Evidence catalog (~1 week)
- SQLite schema (versioned, documented in-repo):
  `nodes(bytenr, phys, dev, gen, owner, level, nritems, csum_ok, discovery,
  …)`, `tree_edges(parent, slot, child, key…)`, `items(node, slot, key,
  raw, parsed_kind, beyond_nritems)`, `roots`, `chunks(current|historical,
  source)`, `extent_backrefs`, `inodes`, `dir_entries`, `file_extents`,
  `artifacts(path, sha256, source, confidence…)`, `provenance(subject,
  evidence, method)`, `scan_runs` (image hash, tool version, params —
  chain of custody).
- Reverse queries: parents-of(bytenr), owners-of(extent), trees-covering
  (key), items-in-generation(g).
- **DoD:** one scan of sandbox populates `evidence.db`; all M1/M2 outputs
  flow through it; reverse queries answered without re-reading the image.

### M4 — Recovery engines (~1–2 weeks)
- Anchored recovery: extract files from any cataloged root via dissect
  streams (compression handled), `-m`-style metadata, xattrs (0x18),
  INODE_EXTREF (0x0D).
- Archaeology port: beyond-`nritems` orphan items (leaf + internal),
  node-slack residual mining, kernel ORPHAN_ITEM (0x30) resurrection —
  golden-tested against legacy outputs.
- Cross-generation dedup of recovered content (by extent tuple + sha256).
- **DoD:** migration-done criterion (§4) met; deleted files recoverable
  from (a) anchored historical roots, (b) orphan nodes, (c) orphan items,
  each labeled with its source.

### M5 — Reconstruction & timelines (~2 weeks; novelty core)
- Orphan graph: reconcile scanned nodes + edges by owner/generation/
  key-range/csum into candidate historical subtrees; reattach fragments
  (cite btrfs-rec's rebuild-trees as prior art, ours is read-only evidence
  assembly).
- Generation diffing: full-state diff between any two cataloged states
  (backup roots, discovered old roots, reconstructed fragments) →
  per-inode event timeline (create/modify/rename/move/delete, content
  delta via extent comparison). Sandbox gen-13 vs gen-14 is the first test.
- Deleted-subvolume recovery (orphaned fs-tree roots without ROOT_ITEM).
- Historical chunk-map reconstruction from orphaned CHUNK_ITEMs/DEV_EXTENTs
  (unlocks the 21 outside-map orphans → C6).
- **DoD:** `btrfska timeline <image>` renders the sandbox's known history;
  a balance/relocation test image yields reconstructed historical chunk
  maps and correctly-translated outside-map orphans.

### M6 — Confidence, validation, hiding detection (~1–2 weeks)
- EXTENT_CSUM (0x80) verification of recovered content where the csum tree
  (current or historical) survives.
- FST forensics: parse FREE_SPACE_INFO/EXTENT/BITMAP (0xDD–0xDF); classify
  every recovered extent as free/allocated-now; overwrite-risk score.
- Confidence tiers (Confirmed/Probable/Unattached) computed from evidence
  rules (anchored path, csum, gen/owner consistency, backref agreement);
  every reported artifact carries its provenance chain.
- Hiding detection: the §research.md 8.3 target list (reserved regions,
  SB/chunk-array slack, STRING_ITEM 0xFD, ns-timestamp anomalies, inode
  reserved bytes) with correct reserved-range definitions (fixes defect #3
  into a feature). Validate against images generated with **fishy**'s btrfs
  module.
- **DoD:** every artifact in the report has tier + provenance; detector
  finds ≥ the fishy-plantable techniques on generated images with measured
  false-positive rate on clean corpus images.

### M7 — Evaluation & corpus (~2 weeks, overlaps paper writing)
- Corpus generator (scripted, reproducible): scenario matrix =
  {1 GiB, 100 GiB} × {simple delete, overwrite, create/delete stress,
  snapshot+delete, balance, defrag, zstd/lzo/zlib, xxhash/sha256 csums,
  MIXED_GROUPS small fs, multi-device RAID1} with per-file manifest +
  SHA-256 + operation log; before/after image pairs.
- **btrfs-specific recoverability axes** (grounded in Bhat & Wani 2018,
  research.md §4.6 — these are what make the corpus a btrfs contribution,
  not a generic one): file-size bands **<1 KiB / 1–2 KiB / 2–4 KiB /
  >4 KiB** (2–4 KiB inline expected worst; <1 KiB and >4 KiB best);
  **merge- vs redistribution-forcing** deletion patterns (their 10-item
  unbalancing conditions); **filesystem aging** (fresh vs aged image — aged
  expected to yield more orphan-items); inline vs regular vs
  multi-extent layout. Report recovery rate per band to validate/refute
  their heuristics on a modern kernel — a citable result in itself.
- **Beyond-4-generations test:** delete a file, then force >4 commits so it
  falls outside the 4 backup roots; confirm anchored methods (Beyond
  Carving, `btrfs restore`) miss it while our orphan-node scan recovers it
  (research.md §4.6 Hilgert limitation → our headline differentiator).
- Baseline harness (containerized): `btrfs restore`(+find-root),
  undelete-btrfs, PhotoRec, btrfscue, FKIE-TSK `tsk_recover -e`,
  btrForensics; commercial (UFS Explorer/R-Studio) if licensed — matches
  the Beyond Carving + Kim et al. baseline sets.
- Metrics: recovery rate, SHA-256 exact-match accuracy, metadata recovery
  rate (name/times/mode), runtime; per scenario.
- Publish corpus (Zenodo DOI) — contribution C7.
- **DoD:** one command regenerates corpus + all baseline numbers + our
  numbers into the paper's tables (notebook-driven).

### M8 — Rust scan core + product polish (Track P, after paper submission)
- `rust/scan-core`: memmap2 + rayon + crc32c/crc-fast + zerocopy structs
  (seed layouts from `btrfs-diskformat`), PyO3 module via maturin; numpy
  path stays as fallback; abi3 wheels in CI.
- Perf table (Python fallback vs Rust) — goes into the tool paper/README.
- Later/optional: standalone Rust CLI, degraded-RAID reads, log-tree (G9)
  as a follow-up research item.

---

## 6. Testing Strategy

- **Golden fixtures:** `sandbox.img` numbers (71/21/gen-13) are regression
  anchors for every refactor.
- **Generated matrix images** (M7 generator, used from M1 on in small
  sizes): each defect from research.md §8.1 gets a dedicated image
  (xxhash image, MIXED_GROUPS image, multi-mirror-corruption image, …).
- **Differential testing:** our anchored listings vs `dump-tree` output and
  vs a mounted copy (`python-btrfs`/find over loop mount) on healthy
  images.
- **Property tests** on parsers (random valid+corrupt nodes must never
  crash — adversarial-input safety, also a paper claim).
- CI runs the full suite on small images; 100 GiB scenarios run in a
  scheduled/manual job.

## 7. Paper Plan

- **Primary target:** DFRWS EU/USA (FSI:DI) — the natural venue for this
  literature (deadline check needed); fallback IEEE Access (where Beyond
  Carving landed; fast OA).
- **Paper 1 (tool + method):** "filesystem-state archaeology" — C1, C3, C4,
  C6 + evaluation vs the full baseline set on the released corpus (C7).
  Structure maps to milestones: background/format (existing docs),
  method = layers 2–5, evaluation = M7, related work = research.md §2/§4.
  Explicit positioning paragraph against Beyond Carving: they answer *"what
  was deleted?"*; we answer *"what happened?"* — and our recovery source
  set strictly contains theirs (their future work is our M4/M5).
- **Possible paper 2 (spin-off):** hiding detection + FST forensics
  (C2, C5) evaluated against fishy/ForTrace-generated anti-forensic images
  — fits the DFRWS anti-forensics thread (Göbel/Schwietert/Toolan line).
- **Artifact:** `uvx` installable tool + Zenodo corpus + notebooks that
  regenerate every table/figure from `evidence.db`.
- Re-run the prior-art watch (research.md §9) before submission.

## 8. Risks

| Risk | Mitigation |
|---|---|
| Beyond Carving team ships their future work first | Our M4/M5 are already prototyped; move M5 early, publish corpus fast (C7 is uncontested) |
| dissect.btrfs API drift / AGPL concerns | Substrate isolation layer (§3.3); pin versions |
| Scan performance disappoints on real HDD images | Kernel interface frozen — Rust core can be pulled forward |
| Ambiguity explosion in orphan graph on real-world images | Confidence tiers are the *product* of ambiguity, not a failure; cap reconstruction depth, report Unattached honestly |
| Corpus scenarios not representative | Mirror published methodology (Kim et al.) + add btrfs-specific axes; solicit feedback via DFRWS artifact review |
| Single maintainer bandwidth | Track R before Track P; every milestone independently shippable |

## 9. Working Conventions

- One branch per feature (`feature/<name>`), PR to `main`, catalog.md entry
  with every merge (numbers + verification).
- Read-only guarantee: no code path may ever write to an evidence image;
  enforced by opening images `O_RDONLY` in one place (substrate) and a test
  asserting image hash before/after every integration test.
- Every empirical claim destined for the paper gets a script/notebook that
  reproduces it from a committed or generated image.
