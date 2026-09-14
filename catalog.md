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

## 2026-09-15 — M0: reset and scaffolding

- **Branch:** `feature/m0-scaffolding` (from `main` at `b55dae2`). Implements
  plan.md §5 M0 tasks 1–11. No forensic logic.
- **Commits:**
  - `a5023b8` Freeze the prototype under legacy/
  - `e4d12ee` Untrack prototype output and ignore test caches
  - `a2a95f0` Add btrfska package skeleton and project config
  - `908f065` Apply ruff formatting to corpus scripts (no functional change)
  - `8be7fed` Add Apache License 2.0
  - `c51cc74` Rewrite README for btrfska and drop commands.txt
  - `67da6ea` Add read-only and CLI tests with a sandbox hash guard
  - `7f66173` Track a zstd-compressed sandbox.img fixture for CI
  - `1fe1a56` Add GitHub Actions CI
  - this catalog entry (the commit after `1fe1a56`)

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
  (`checkout@v7`, `setup-uv@v10`) are taken from the plan and were not
  re-checked here.

**Follow-ups for M1.**
- `tests/` and `legacy/tests/` are both rootless test dirs collected in
  pytest's default `prepend` import mode, so a new test file with the same
  basename as a legacy one (e.g. `test_crc32c.py`) will fail collection. Use
  distinct names or switch to `--import-mode=importlib`.
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
  tag pushed to origin, pointing at the branch tip `1e9984e`; the branch is
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
  `1e9984e`.

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
