# Build Plan — Btrfs Filesystem-State Archaeology

> Written 2026-08-17 from the verified research in [`research.md`](research.md);
> **revised 2026-09-15** after the research refresh (research.md §10), then
> amended the same day after review: all runtime parsing, extent reads and
> decompression are ours, dissect.btrfs is a test oracle only, and the
> licence is Apache-2.0 (§3.3, §3.5).
> History lives in [`catalog.md`](catalog.md). This plan is forward-looking
> only; update it when decisions change, and log every completed step in the
> catalog.

---

## 1. What We Are Building (and Not Building)

**Thesis.** Btrfs's copy-on-write design leaves behind a graph of historical
metadata — orphaned nodes, beyond-`nritems` item remnants, backup and
superseded roots, free-space-tree state, relocated-chunk residue. Existing
tools *salvage files*. Published work ("Beyond Carving", IEEE Access 2026)
*lists deleted files deterministically* from historical roots, and
`SecurityRonin/btrfs-forensic` (Rust, 2026-07) ships backup-root deletion
diffs with graded anomaly findings. **Nobody reconstructs btrfs filesystem
history as a validated evidence graph with provenance and confidence.** That
is the product and the paper.

**Product one-liner:** a strictly read-only, open-source forensic engine that
ingests a raw Btrfs image, builds a queryable evidence catalog of *every*
metadata artifact ever left on disk, and answers: *what existed, when, what
changed, what can be recovered, how confidently, and was anything hidden?*
CLI first; a local GUI over the catalog once the CLI is solid (M9).

**Explicit novelty claims** (each mapped to a verified gap in research.md §6,
re-checked against new prior art in research.md §10.1–§10.2):

| Claim | Gap | Beats prior art how |
|---|---|---|
| C1. **Btrfs** recovery from what no current tree references: whole superseded blocks (orphan nodes) and kernel ORPHAN_ITEM 0x30 resurrection. Narrowed by EXP-005 (2026-09-21): beyond-`nritems` items and node slack are empty on every block the kernel has written since v4.9, so they are a recovery source for older filesystems only and a tampering signal (C5) everywhere else | G1 | Beyond Carving scans whole valid blocks only — deep leaf scanning is *their stated future work*, and EXP-005 shows there is nothing to find there on a modern filesystem; SecurityRonin only *lists* kernel ORPHAN_ITEMs. Node-slack recovery exists for **ReFS** (`forefst`, Bonnet 2026; Prade et al. 2020) — cited as the CoW analog, not claimed |
| C2. Free-space-tree forensics: prove blocks were freed; overwrite-risk scoring | G2 | Zero tools, zero papers (re-swept 2026-09-15) |
| C3. **Full-state, multi-source, per-inode lifecycle timelines**: diffs across backup roots *and* scan-discovered old roots *and* reconstructed orphan fragments → create/modify/rename/move/delete with content deltas | G3 | Beyond Carving diffs objectid *sets* over the historical root trees it discovers by scanning the chunk-mapped tree regions, so it is **not** bounded by the backup roots (research.md §10.12, corrected 2026-09-15); SecurityRonin `recover_deleted()` is backup-root-bounded (all four backup slots, FS tree 5 only). Both are existence-only; neither "diffing generations" nor discovering roots beyond the backups is claimed per se |
| C4. **Evidence-rule-derived confidence tiers** (Confirmed/Probable/Unattached) with a per-artifact provenance chain spanning anchored *and* unanchored artifacts, csum-tree-verified content | G4 | SecurityRonin has severity grades (no provenance, no evidence rules); Beyond Carving has an extent-resolvability taxonomy for anchored recoveries only; `forefst` has ReFS recoverability verdicts; X-Ways has a binary flag. None scores unanchored orphan/slack artifacts or records cross-mode provenance |
| C5. Hiding detection targeting the Toolan & Humphries (FSI:DI 58:302198, 2026) + Schwietert & Hilgert technique lists, evaluated against fishy-generated images | G5 | Papers propose hiding; nobody ships a detector for those techniques. SecurityRonin's `BACKUP-ROOT-DIVERGENCE` and CRC-mismatch findings are a tamper-detection slice → cited |
| C6. **Btrfs** orphaned/relocated-chunk forensics + historical chunk-map reconstruction; on remap-tree images, the stale remap tree as an explicit relocation log (experimental) | G6 | Our sandbox discovery (21/71 orphans outside chunk map); Beyond Carving future work. F2FS address-table rebuild (Oh & Hwang 2025) is the cited analog |
| C7. First public btrfs *image* corpus with per-file ground truth spanning checksum, compression, discard and block-group-tree axes + systematic tool benchmark | G8 | No such image corpus found (no btrfs at digitalcorpora/CFReDS). Prior datasets are cited, not claimed away: Wani & Bhat 2018 (*Data in Brief*; in-article tables, no images) and Schwietert & Hilgert 2025 (hiding corpus with ground truth; repository offline) (research.md §5.1) |

**Not building (exists elsewhere; reuse or benchmark instead):**
- compression algorithms (stdlib `zlib` and `compression.zstd`; only the
  small LZO1X decoder is ours, §3.5) and a second general-purpose btrfs
  reader (dissect.btrfs serves as a test oracle, not a dependency);
- old-root salvage (`btrfs restore`/find-root), deleted-file listing from
  historical roots found by scanning chunk-mapped tree regions (Beyond
  Carving) and backup-root deleted-file diffing (`SecurityRonin/btrfs-forensic`);
- unreferenced-subvolume restore (btrfscue v0.7 `recover`);
- carving (PhotoRec);
- chunk repair (chunk-recover, btrfs-rec);
- write-mode repair of any kind.

The benchmark set is §5 M7. The tool stays **strictly read-only** (forensic
soundness).

---

## 2. Architecture

Six layers; each independently testable.

```
┌──────────────────────────────────────────────────────────────┐
│ 6. Interfaces: CLI (argparse) · JSON/text reports ·          │
│    notebooks · local web UI over evidence.db (M9)            │
├──────────────────────────────────────────────────────────────┤
│ 5. Analysis: confidence & provenance · csum-tree verification│
│    · FST/overwrite-risk · hiding detection                   │
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
│ 1. Substrate (§3.5), all ours: read-only image/devices,      │
│    SB + mirrors, validation gate (csum dispatch, header      │
│    checks, incompat/compat_ro gate), `struct` tables, node   │
│    reader, chunk maps (current + historical), backup roots,  │
│    extent reads + decompression (stdlib zlib/zstd, own LZO1X)│
└──────────────────────────────────────────────────────────────┘
```

Design rules:

- **Scan once, query forever**: the image is read in one pass (plus targeted
  re-reads); everything else queries the catalog.
- **Validate before trusting**: no node, superblock or item enters the
  catalog without a recorded validation outcome (csum type + result, header
  checks, generation/owner consistency). Unvalidated bytes may be recorded,
  but only as such.
- **Provenance on every row**: how was this artifact discovered (anchored
  walk from which root / scan hit at which physical offset / slack region of
  which node), csum status, generation, owner.
- **Never collapse ambiguity**: contradictory metadata from different
  generations are all recorded; confidence tiers express uncertainty instead
  of guessing.
- **Refuse loudly, never mis-read silently**: an image with an unknown or
  unsupported incompat bit produces a report line and a non-zero exit, not
  best-effort output.
- Scan kernel has a frozen interface (`iter_candidate_nodes(image, regions)
  → NodeRecord`) so the numpy implementation can be swapped for Rust without
  touching layers 3–6.

## 3. Stack Decision

### 3.1 Decision

- **Language:** Python for everything except the scan kernel's fast path.
  `requires-python = ">=3.14"`, matching the existing `.python-version` pin
  and giving stdlib `compression.zstd` for zstd extents (verified on 3.14.6:
  libzstd 1.5.7, round-trip OK; no `backports.zstd`); `uv`/`uvx` provision
  the interpreter, so users need not
  have it installed. Revisit a lower floor before the first PyPI release.
  Rust (PyO3/maturin) scan core in M8; the numpy path remains as fallback.
  No Go/Zig/C++ (research.md §7).
- **Runtime deps:** `numpy` (scan kernel), `crc32c` (SSE4.2 CRC32c),
  `xxhash`; stdlib `hashlib` (sha256, blake2b), `zlib`, `compression.zstd`,
  `struct`, `sqlite3`, `argparse`. No btrfs library at runtime (§3.5).
  Licences are checked in §3.3.
- **Dev/test deps:** `pytest`, `ruff`; test oracles `dissect.btrfs==1.10.*`
  (AGPL-3.0-or-later) and `lzallright==0.2.*` (MIT), used only by
  differential tests (§3.5, §6.3). `uv`; CI via GitHub Actions.
- **Packaging:** `pyproject.toml` + uv lockfile, src layout, published to
  PyPI so reviewers run `uvx btrfska scan image.dd`.
- **Catalog:** SQLite, single-file `evidence.db` (hashable, chain-of-custody
  friendly). Build-phase tuning: batched transactions, indexes after load.
  Optional DuckDB/Parquet export for notebook analytics.
- **Rationale** (full analysis research.md §7): pure-stdlib Python is
  15–40 h/TB (non-viable); numpy+crc32c is I/O-bound (~20–75 min/TB);
  Python keeps research iteration and the DFIR/pip ecosystem; Rust core
  later gives bulk_extractor-class performance and a paper-citable
  memory-safety story. Dissect itself validates the hybrid pattern.

### 3.2 Two-track structure

- **Track R (research/paper):** M0–M7 in Python. The paper does not wait for
  Rust or the GUI.
- **Track P (product):** M8 Rust scan core + wheels; **M9 local web GUI**
  once the CLI's catalog schema and commands are stable.

### 3.3 License

**Decision: Apache-2.0** (revised 2026-09-15). The earlier AGPL-3.0
decision followed from importing dissect.btrfs at runtime, which §3.5 no
longer does.

Why Apache-2.0:
- DFIR and academic reuse: labs, vendors and other researchers can embed the
  parser or re-run the paper artifact without a copyleft review;
- an explicit patent grant (Apache-2.0 §3), which MIT and BSD lack;
- compatible with every remaining runtime dependency (table below), and
  combinable into a GPLv3/AGPLv3 work if the §3.5 fallback is ever taken;
- in line with the permissive Rust prior art (SecurityRonin, `btrfs-core`
  and rustutils are Apache-2.0 or MIT/Apache).

`legacy/` is the project owner's own prototype code and is released under
the same licence.

**Dependency licence check** (PyPI and GitHub metadata, 2026-09-15):

| Dependency | Scope | Licence | OK for an Apache-2.0 distribution? |
|---|---|---|---|
| CPython stdlib (`zlib`, `compression.zstd`, `hashlib`, `sqlite3`, `mmap`) | runtime | PSF-2.0 (bundled zlib: Zlib; libzstd: BSD) | yes |
| `numpy` 2.5.x | runtime (M2) | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 | yes |
| `xxhash` 4.0.x (python-xxhash) | runtime (M1) | BSD-2-Clause | yes |
| `crc32c` 2.9 (ICRAR) | runtime (M1) | LGPL-2.1-or-later | yes, as a separately installed, unmodified dependency (our wheel neither bundles nor modifies it). If a frozen single-file binary is ever shipped, swap in `google-crc32c` (Apache-2.0) behind `substrate/csum.py` instead of taking on LGPL relinking terms |
| PyO3, memmap2, rayon, zerocopy, crc-fast | runtime (M8, Rust) | Apache-2.0 (most dual MIT/Apache-2.0) | yes |
| `btrfs-diskformat` (layout seed) | reference (M8) | BSD-2-Clause | yes |
| Starlette, Jinja2 | runtime (M9) | BSD-3-Clause | yes |
| htmx (vendored static asset) | runtime (M9) | 0BSD | yes |
| `pytest`, `ruff` | dev | MIT | not distributed |
| `lzallright` 0.2.x | test oracle | MIT | not distributed |
| `dissect.btrfs` 1.10 (pulls `dissect.cstruct`, `dissect.util`: Apache-2.0) | test oracle | AGPL-3.0-or-later | not distributed (see below) |

**Test-only use of an AGPL library does not make the distributed package
AGPL.** The AGPL's conditions attach to conveying the AGPL program or a
work based on it (§§4–6), and to offering a *modified* version to users
over a network (§13). Here:
- `dissect.btrfs` is listed only in `[dependency-groups] dev`, and PEP 735
  dependency groups are not written into the published `Requires-Dist`
  metadata;
- no wheel or sdist contains dissect code; the oracle tests live in
  `tests/oracle/`, outside the `src/btrfska` package;
- an import-boundary test (M1) fails if anything under `src/` imports
  `dissect` or `lzallright`;
- running the unmodified library on our own machines and in CI is not
  conveying it.

So `btrfska` as published is Apache-2.0. This is the project's reading of
the licences, recorded for reviewers. Re-check it before the first PyPI
release, including the sdist file list (`tar tzf dist/*.tar.gz`).

**Fallback consequence.** If the §3.5 fallback re-adopts dissect.btrfs at
runtime, the combined tool becomes **AGPL-3.0-or-later** (Apache-2.0 code
can be combined into an AGPLv3 work, not the reverse). `LICENSE`,
`pyproject.toml` and README change in that PR, and the catalog records why.

Permissive Rust references (not dependencies):
- rustutils/btrfsutils — MIT/Apache, stalled since 2026-05-14;
- `btrfs-core` 0.1.5 — Apache-2.0, single/DUP only, crc32c only
  (research.md §10.6 item 9).

### 3.4 Naming

Repo stays `btrfs-forensics`. Package/CLI name: **`btrfska`**
("btrfs archaeology"). PyPI `btrfska` was unregistered on 2026-09-15 (HTTP
404) and §10 found no collision; re-check immediately before the first
release.

### 3.5 Substrate decision (revised 2026-09-15, amended after review)

**Finding (research.md §10.2).** dissect.btrfs 1.10 (latest stable,
2026-02-24; no functional commits since 2025-12):
- verifies no checksum of any type and no node-header field; a misaligned
  bytenr returned garbage items without error;
- ignores incompat flags (an injected unknown bit opened normally), so RST,
  remap-tree and encrypted images would be silently mis-read;
- maps only through the current chunk tree, never reads superblock mirrors,
  and exposes backup roots only as raw bytes.

It does correctly read file streams (inline, regular, sparse; zlib/lzo/zstd
— zstd verified 10/10 on `s01`), subvolumes, snapshots and backup-root
historical walks on `sandbox.img`.

**Review finding (2026-09-15).** Borrowing only dissect's file streams (the
first draft of this section) does not work as intended:
- dissect resolves every extent through *its own* chunk map, built from the
  current chunk tree. It has no API to route stream reads through our
  validated node reader or through a historical or reconstructed chunk map,
  so its streams cannot serve C6 or any orphan-derived extent;
- M1 already needs our own extent reads (backup-root and historical
  states), so dissect streams would duplicate them, not replace them;
- its only unique runtime contribution is therefore decompression. Zlib and
  zstd are in the Python 3.14 stdlib (`zlib`, `compression.zstd`; verified
  on 3.14.6 with libzstd 1.5.7), and btrfs LZO is a thin per-sector segment
  framing around LZO1X.

**Btrfs LZO framing** (kernel v7.0 `fs/btrfs/lzo.c`, header comment and
decompress path, which calls `lzo1x_decompress_safe`):
- a 4-byte LE total compressed length;
- then segments, each a 4-byte LE segment length followed by LZO1X data of
  at most `lzo1x_worst_compress(sectorsize)` bytes (4 421 for 4 KiB by the v7.0
  `include/linux/lzo.h:21` macro; the `lzo.c` header comment says 4 419) that
  decompresses to at most one sector;
- a segment header never straddles a sector boundary: if fewer than 4 bytes
  remain in the current sector, they are zero padding and the next header
  starts at the next sector;
- inline extents use the same header with a single segment.

**LZO1X decoder options** (evaluated 2026-09-15):

| Option | Licence / state | Behaviour on hostile input (test below) | Verdict |
|---|---|---|---|
| `python-lzo` 1.15 | GPL | — | Rejected: GPL, incompatible with the Apache-2.0 decision |
| `dissect.util` 3.24 `compression.lzo` (pure Python + Rust `_native`) | Apache-2.0, Fox-IT, maintained; the decoder dissect.btrfs uses | Pure Python: a back-reference before the start of output is silently accepted (the crafted stream returned 4 bytes, no error), and only `len == out_len` stops output. Native: **panics** (`pyo3_runtime.PanicException`, not an `Exception` subclass, so `except Exception` does not catch it) on the crafted stream and on 31–46 of 300 bit-flipped 4 KiB streams per seed (median 37; `tests/oracle/lzo_hostile.py`, seeds 1–5, M1c; the earlier single scratch run's 58/300 is superseded) | Rejected at runtime: a forensic reader must fail with a catchable, classified error on adversarial bytes. Its Apache-2.0 test vectors are reused, with attribution |
| `lzallright` 0.2.6 (Rust bindings of lzokay) | MIT; 2 stars, one maintainer; abi3 wheels | Raises `LZOError` cleanly on crafted, truncated and bit-flipped input | Not a runtime dependency (bus factor; a native wheel for a ~150-line function). **Adopted as an independent test oracle** and as fallback 1 |
| `lzokay` 2.1.0 (lzokay-rs) | MIT; 1 star, last push 2025-10 | not tested | Rejected: weaker upkeep than `lzallright` |
| **Own pure-Python LZO1X decoder** (`substrate/lzo.py`) | Ours (Apache-2.0) | Bounds-checked by design: input overrun, output overrun beyond the segment bound, lookbehind overrun, missing end marker; one `LzoError` class | **Chosen** |

Test run (seeded; `uv run --no-project --with dissect.util==3.24 --with
lzallright==0.2.6`, scratch only):
- 2 000 round-trip vectors (random, zero, low-entropy and repeated-text
  data, 1 B–70 KiB), compressed with lzallright, decoded identically by all
  three decoders;
- a crafted 10-byte stream `15 41 42 43 44 40 FF 11 00 00` (4 literals, then
  a match 2 041 bytes back);
- a truncated stream (all three raise a catchable error);
- 300 single-bit flips of one compressed 4 KiB sector.

**Also observed** (`tests/oracle/lzo_hostile.py`, seeds 1–5, M1c): per seed,
218–231 (median 227) of the 300 bit-flipped streams decoded "successfully" to
wrong bytes within the 4 KiB bound in btrfska, lzallright and dissect.util's
native decoder (258–277 in its pure-Python decoder). lzallright and both
dissect.util decoders returned more than 4 KiB for another 22–41, where
btrfska raises `output_overrun`. The earlier single scratch run (139–160) used
other data and flip positions and is superseded. LZO carries no integrity
check, so decode success is never evidence of correct content; only data
checksums (csum tree, M6) are.

**Beyond bit flips** (the same harness, seeds 1–5, 300 streams per corpus
per seed; added in the M1c review):
- truncation and random byte streams: every stream fails in btrfska and
  lzallright;
- one inserted byte: 9–14 per seed decode to wrong bytes within 4 KiB in
  btrfska and lzallright alike, and lzallright returns more than 4 KiB for
  57–71;
- one deleted byte: 32–71 wrong, identically; lzallright over 4 KiB for
  9–23;
- instruction-level random streams (every field of every instruction
  random, ending in a random `0001HLLL` terminator): 0–1 return bytes;
- dissect.util's native decoder panics on 119–176 insertions, 95–172
  deletions, 275–282 random byte streams and 272–277 instruction-level
  streams per seed.

btrfska and lzallright agree on all 300 streams of every corpus and seed,
counting an lzallright output over 4 KiB as a failure. Before the review
fix they did not: btrfska accepted the end-marker distance (16384) with
any copy length, where the v7.0 kernel (`lib/lzo/lzo1x_decompress_safe.c`
lines 208 and 274) and lzokay (`lzokay.cpp:284`) accept only length 3
(`11 00 00`). The instruction-level corpus disagreed on 6–11 of 300
streams per seed, all of them this case. The bit-flip, truncation,
insertion, deletion and random-byte corpora agreed on every stream even
then: no single-byte edit of `11 00 00` produces another length code
together with a zero distance.

Why our own decoder:
- decompression was the only thing left to borrow, and it sits on the
  hostile-input path (the kernel uses the "safe" decoder for the same
  reason);
- LZO1X decoding is small and fully specified (kernel
  `Documentation/staging/lzo.rst`). Output per segment is bounded by one
  sector, so pure-Python speed is adequate for Track R; M8 can move it to
  Rust;
- it is written from the bitstream description and dissect.util's
  Apache-2.0 code, not translated from GPL sources (kernel
  `lzo1x_decompress_safe.c`, python-lzo), which keeps the licence clean;
- correctness is cross-checked three ways: lzallright round-trip fuzz,
  dissect.btrfs stream bytes, and guest-printed SHA-256s on LZO corpus
  images (M1).

**Substrate options considered.**

| Option | For | Against |
|---|---|---|
| A. dissect.btrfs as the full substrate + thin extensions (the 2026-08-17 decision) | Least code | Its reader sits under every trust decision; validation retrofitted around `_read_node` means monkey-patching a private method; the current-chunk-map-only design blocks C6 |
| B. Own parsing/validation, borrow dissect streams + decompression (first 2026-09-15 draft) | Less stream code | Streams cannot go through our reader or historical maps (review finding), so they duplicate M1's extent reads; AGPL for what is in effect decompression only |
| **C. Own all runtime parsing, extent reads and decompression; dissect.btrfs as test oracle only** | Every byte behind a confidence tier or a recovered file passes through code we test; historical and reconstructed chunk maps work for content too; permissive licence (§3.3) | ~600–900 lines of superblock/node/chunk code plus ~300 lines of extent/decompression code (incl. ~150 for LZO1X), all typed, validated and fuzzed |
| D. Vendor/fork dissect's stream module | Proven stream code | Same chunk-map coupling; AGPL; a fork to maintain |

**Decision: C.** Everything lives in `src/btrfska/substrate/`:
- read-only image/device open;
- superblock parse + all mirrors + best-copy selection by csum, then
  generation;
- csum dispatch (crc32c/xxhash64/sha256/blake2b) for superblocks, tree
  blocks and data;
- node header validation (bytenr, fsid, chunk-tree uuid, generation ≤ SB
  generation, owner, level) and a node reader returning a `ValidatedNode`
  with a validation record;
- mirror policy (decided in M1b, 2026-09-15): every physical copy of a tree
  block (all DUP/RAID1 stripes) is read and validated on its own; the first
  valid copy in mirror order is used, and every copy's checks stay in the
  record, so a corrupt or divergent copy is always reported;
- the incompat/compat_ro gate;
- sys_chunk_array + chunk-tree map, keyed so historical maps can coexist
  (M5);
- backup roots (sorted by generation);
- `ondisk.py`: our own `struct` format tables for every on-disk structure
  and item we parse (item keys incl. 172, 230, 234–236), with values
  asserted against kernel v7.0 headers; no cstruct definitions;
- `extents.py`: EXTENT_DATA → bytes for inline, regular and prealloc
  extents and holes, through any `ChunkMap` (current, historical,
  reconstructed), with a per-extent read record;
- `compress.py`: zlib (`zlib.decompressobj`) and zstd
  (`compression.zstd.ZstdDecompressor`), both bounded by `ram_bytes`, plus
  the btrfs LZO framing over `lzo.py`; every failure is a recorded
  `DecodeError`, never truncated or padded output.

**dissect.btrfs's role:** a pinned dev/test dependency used only by
differential tests in `tests/oracle/` (§6.3). It is never imported under
`src/` (import-boundary test).

**Replacement boundary.** `extents.py` and `compress.py` are the only modules
that turn extent metadata into file content; everything above them consumes
their interface. If one proves unreliable, only that module is swapped.

**Fallback** (in order; each step recorded in the catalog):
1. our LZO1X decoder fails an oracle and cannot be fixed quickly → call
   `lzallright` (MIT) from `compress.py`; the licence stays Apache-2.0;
2. our extent/stream code proves unreliable → re-adopt dissect.btrfs at
   runtime behind the replacement boundary (current-tree reads only; C6
   content still needs our code). The distributed tool then becomes
   **AGPL-3.0-or-later** (§3.3).

**Guard:** the M1 task-8 oracle tests assert that, for every file in the
current tree and snapshots of `sandbox.img`, `m1_xxhash` (zstd), `m1_lzo`
and `m1_zlib`, our bytes equal dissect.btrfs's stream bytes and the
guest-printed SHA-256s, so a regression is caught in CI rather than in a
case.

---

## 4. Migration of the Current Prototype — What to Delete vs Keep

Principle: **most of the prototype is a re-implementation of things
maintained libraries and btrfs-progs already do — that code is dead weight
and goes.** Only the parts that encode *our novel logic* or *validated
empirical results* are worth carrying. Under §3.5 we own the whole substrate
(superblock, node, chunk, extent and decompression code), but the
prototype's versions are rewritten from
scratch against the spec (they carry defects #1–#8), not migrated. Nothing
is physically deleted until its replacement passes the same tests.

M0 moves `main.py utils/ tests/` → `legacy/` (a frozen reference kept
runnable for cross-checks, then dropped to a git tag once M4's parity gate
passes — see §4.3).

### 4.1 Verdict per file

Three verdicts: **DELETE** (redundant — the capability exists in a
maintained library/tool; keep nothing), **MIGRATE** (novel or hard-won
logic — port carefully with byte-identical behaviour, golden-tested),
**REWRITE** (the *concept* survives but the code is replaced).

| Current file | Lines | Verdict | Why / what replaces it |
|---|---|---|---|
| `utils/crc32c.py` | 33 | **DELETE** | Replaced by `crc32c` PyPI (SSE4.2) behind `substrate/csum.py` dispatch (all 4 types). Keep only the RFC-3720 test vectors as an oracle. |
| `utils/superblock.py` | 93 | **REWRITE** | `substrate/superblock.py`: all mirrors, csum-validated, best-copy selection, incompat/compat_ro gate, backup roots. The prototype reads only the primary and validates nothing. |
| `utils/constants.py` | 172 | **REWRITE** | `substrate/ondisk.py`: our own `struct` format tables plus offsets/keys, each asserted by a test against kernel `btrfs_tree.h` v7.0 values (the hand-kept table caused the DEV_ITEM defect). |
| `utils/inode_parser.py` | 132 | **DELETE** | A `struct` format table for `btrfs_inode_item` in `substrate/ondisk.py`; fixtures migrate as tests. |
| `utils/tree_walker.py` | 87 | **REWRITE** | `substrate/tree.py`: walker over `ValidatedNode`s from any bytenr, with per-hop validation records (dissect's `BTree` validates nothing). |
| `utils/chunk_parser.py` — chunk map + logical→physical | ~200 of 281 | **REWRITE** | `substrate/chunks.py`: all RAID stripe math for healthy reads, map objects keyed by source (current / historical) so M5 can add reconstructed maps. |
| `utils/chunk_parser.py` — `build_scan_regions()` (typed chunks + unmapped gaps) | ~80 of 281 | **MIGRATE** | Novel: the typed-region + relocated-chunk-gap logic behind the 21/71 finding. Port to `scan/regions.py`, add the MIXED_GROUPS fix and block-group-tree (tree 11) input. |
| `utils/btree.py` — raw sweep loop | ~200 of 968 | **REWRITE** | Concept (strided FSID+csum sweep) survives; replaced by the numpy/mmap kernel (`scan/kernel_numpy.py`). |
| `utils/btree.py` — orphan-item scan (beyond `nritems`), internal key-ptr scan, leaf/internal slack mining | ~400 of 968 | **MIGRATE** | Once called the crown jewels. EXP-005 (2026-09-21) showed the kernel zeroes this area on every write since v4.9: on `sandbox.img` the prototype finds 0 orphan items and 0 residuals, and its 4 saved leaf slacks are `mkfs.btrfs` leftovers. Still ported to `recover/orphans.py` + `recover/slack.py`, as the input of the C5 detector and for pre-4.9 filesystems; golden-tested against legacy output (which is those leftovers) and against a planted-slack image. |
| `utils/btree.py` — item parsing + inline/regular extract | ~350 of 968 | **REWRITE** | Parsing on our item tables; extraction via `substrate/extents.py` + `compress.py` (the prototype saved compressed extents raw). **Keep the ideas:** `(inode, generation)` keying, move/rename tagging, extent dedup. **Defect #8** (EXTENT_ITEM logical address is the key *objectid*; the key offset is the length) must be fixed in the rewrite and must **not** be frozen into golden tests. |
| `utils/orphan_scan.py` — live-metadata set via extent tree | 109 | **MIGRATE** | The "currently allocated" complement that defines orphan territory. Reparent onto `substrate/tree.py` in `scan/live_set.py`; also read tree 11. |
| `utils/recovery_report.py` | 230 | **REWRITE** | Flat counters → the SQLite evidence catalog + provenance/confidence report (M3/M6). |
| `main.py` | 201 | **REWRITE** | New CLI (subcommands: `info`/`scan`/`catalog`/`recover`/`timeline`/`detect-hiding`) over the new pipeline. |
| `tests/` (4 files) | 519 | **MIGRATE** | Port assertions as golden tests: 71/21 numbers, RFC-3720 CRC vectors, inode fixtures, targeted-scan parity — **plus** the gen 11–14 ground truth from `feature/m1-backup-roots` (§5 M1). |

**Tally:** of ~2,830 lines, roughly
- **~250 DELETE** (crc32c, inode_parser);
- **~590 MIGRATE** (orphan/slack archaeology, scan regions, live set,
  tests — the novel core);
- **~2,000 REWRITE** (substrate trust layer, sweep loop, item parsing,
  report, CLI).

The defensible ~590 lines are still what the paper is about. The rewrite
share grew because validation, extent reads and decompression are now ours
(§3.5).

### 4.2 Also delete / untrack (non-code)

- `recovery_output/` — tracked in git today (8 files); untrack in M0 and
  gitignore; regenerable with `legacy/main.py`.
- `commands.txt` — its `sudo mount` recipe is unusable on the dev host
  (research.md §10.4) and superseded by `corpus/vm/`; fold the two `uv run`
  lines into README in M0, then delete.
- `mnt_sandbox/` (empty, untracked) — mount points belong under
  `images/mnt/`; remove in M0.
- Prototype's "defrag hazard" heuristic — **do not migrate as-is**: it was
  mis-attributed to Wani 2020 (research.md §8.4). Re-derive or drop.
- `feature/m1-backup-roots` — leave unmerged. Its useful content is carried
  as spec/tests in M1 (research.md §10.5). **Done 2026-09-15:** annotated
  tag `m1-prototype` created and pushed to origin, pointing at the branch
  tip `26715ba`; the branch is kept.

### 4.3 Migration-done gate (end of M4)

New pipeline on `sandbox.img` reproduces the legacy report (same 71 orphans,
same 21 outside-map, same recovered files; backref addresses per the defect
#8 fix, not legacy's) **plus** compression, csum dispatch, superblock
mirrors, and backup-root walking. When that gate is green, tag
`legacy-final` and delete `legacy/`.

---

## 5. Milestones

Each milestone = one feature branch + PR + catalog.md entry (+ an
`experiments/EXP-NNN.md` record for every measured result, §7). Estimates
assume one focused developer. `corpus/vm/` is linted in CI from M0 and
generates images from M1 on (§6.2).

### M0 — Reset & scaffolding (~2 days)

**Goal:** new package skeleton, legacy frozen but runnable, CI green. No
forensic logic.

**Branch:** `feature/m0-scaffolding`.

**Tasks (in order).**

1. **Freeze legacy.** First run
   `uv run --python 3.14 python -m unittest discover -s tests` on the
   untouched tree and record the test count and result in the M0 catalog
   entry (the acceptance baseline). The integration and targeted-scan
   suites create their `test_output_*` dirs at the repo root and remove them
   again in `tearDownClass`; confirm with `git status` that none are left.
   Then
   `git mv main.py legacy/main.py && git mv utils legacy/utils && git mv tests legacy/tests`.
   Remove stray `legacy/utils/__pycache__`, `legacy/tests/__pycache__`
   (untracked).
2. **Keep legacy tests pointing at the real fixture.** The legacy tests
   compute `SANDBOX_IMG` and output dirs from the file's grandparent, which
   after the move is `legacy/`. They would then *silently skip*. Edit
   exactly these constants:
   - `legacy/tests/test_integration.py`: `SANDBOX_IMG` → repo root
     (`dirname` ×3); `TEST_OUTPUT` → `<repo>/images/scratch/legacy-tests/integration`.
   - `legacy/tests/test_targeted_scan.py`: `SANDBOX_IMG` → repo root;
     `TEST_OUT` → `<repo>/images/scratch/legacy-tests/targeted` (the suite
     appends `_legacy` / `_targeted` itself).

   These four constants are the only legacy edits. No `makedirs` change is
   needed: `test_integration.py` already calls
   `os.makedirs(TEST_OUTPUT, exist_ok=True)`, `test_targeted_scan.py`
   removes any old dir and then calls `os.makedirs(d)`, and `os.makedirs`
   creates the missing `images/scratch/legacy-tests/` parents. The
   `sys.path.insert(0, dirname(dirname(__file__)))` line in all four legacy
   test files stays as is: after the move it points at `legacy/`, which is
   what makes `import utils` resolve.
3. **Untrack non-code artifacts.**
   - `git rm -r --cached recovery_output`, keeping local files.
   - Add `recovery_output/`, `.pytest_cache/`, `.ruff_cache/` to
     `.gitignore`.
   - `rmdir mnt_sandbox`.

   (`commands.txt` is removed in task 8, once README has absorbed it.)
4. **Package skeleton** (src layout):
   - `src/btrfska/__init__.py` — `__version__ = "0.0.1"`.
   - `src/btrfska/__main__.py` — `from btrfska.cli import main; raise SystemExit(main())`.
   - `src/btrfska/cli.py` — argparse with `--version` and subcommand
     `info IMAGE`. `info` only opens the image read-only and prints size and
     sha256; the superblock comes in M1. `main(argv=None) -> int`.
   - `src/btrfska/substrate/__init__.py` — empty; M1 fills it.
   - `src/btrfska/substrate/image.py` — `open_image(path) -> ImageHandle`,
     the **single** place an evidence file is opened (`os.open(path,
     os.O_RDONLY)` + `mmap.ACCESS_READ`), `sha256()` helper.
5. **`pyproject.toml`** (replace):
   - `[project]` `name = "btrfska"`, `version = "0.0.1"`,
     `requires-python = ">=3.14"`,
     `license = "Apache-2.0"`, `license-files = ["LICENSE"]`,
     `dependencies = []` (`crc32c`/`xxhash` are added in M1 and `numpy` in
     M2; the dissect.btrfs and lzallright oracles join the `dev` group in
     M1).
   - `[project.scripts]` `btrfska = "btrfska.cli:main"`.
   - `[build-system]` `requires = ["uv_build>=0.11,<0.12"]`,
     `build-backend = "uv_build"`.
   - `[dependency-groups]` `dev = ["pytest>=8", "ruff>=0.13"]`.
   - `[tool.pytest.ini_options]`:
     - `testpaths = ["tests", "legacy/tests"]`
     - `markers = ["sandbox: needs sandbox.img", "vm: needs corpus/vm images"]`
     - `addopts = "-ra"`
   - `[tool.ruff]` `target-version = "py314"`, `line-length = 100`,
     `extend-exclude = ["legacy"]`.
   - `[tool.ruff.lint]` `select = ["E", "F", "W", "I", "B", "UP"]`.

   Then `uv lock`, which regenerates `uv.lock`.

   **Then format `corpus/` (formatting-only change, its own commit).** With
   the ruff config above in place, `corpus/vm/probe_stale_metadata.py` is
   the only tracked Python file outside `legacy/` that fails
   `ruff format --check` (ruff 0.16.7, checked 2026-09-15: a blank line after
   the docstring and inline-comment spacing). It already passes
   `ruff check`. Run `uv run ruff format corpus/`, confirm that
   `git diff --stat` touches only tracked `corpus/**/*.py`, and commit it
   alone as "Apply ruff formatting to corpus scripts (no functional
   change)". If `images/scenarios/s01_discard_none.img` exists locally,
   re-run the probe on it before and after and compare the four numbers.
   Shell scripts are not reformatted.
6. **LICENSE.** Add the verbatim Apache License 2.0 text as `LICENSE`,
   copied from `https://www.apache.org/licenses/LICENSE-2.0.txt` (§3.3).
7. **New tests** (`tests/`, plus a repo-root `conftest.py` so the hash guard
   also covers `legacy/tests`):
   - `conftest.py` (repo root):
     - `REPO_ROOT`;
     - a session fixture `sandbox_img` that skips with reason
       `"sandbox.img absent"` when the file is missing;
     - an autouse session fixture that, when `sandbox.img` exists,
       records its sha256 at start and asserts it unchanged at session end
       (expected `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`).
   - `tests/test_cli.py`: `--version` exits 0 and prints the version;
     `btrfska info sandbox.img` prints the expected sha256 (`@pytest.mark.sandbox`).
   - `tests/test_readonly.py`:
     - `open_image` on a temp file under `images/scratch/` opens `O_RDONLY`
       (the test creates `images/scratch/` with `mkdir(parents=True,
       exist_ok=True)`; it does not exist on a clean CI clone);
     - a write through the mmap raises `TypeError`;
     - no module under `src/` other than `substrate/image.py` calls `open(`
       with a write mode or `os.open` (AST scan).
8. **README rewrite** (short):
   - purpose (one paragraph);
   - status ("M0 scaffolding; prototype frozen under `legacy/`");
   - install/run (`uv sync`, `uv run btrfska --help`);
   - test commands (below), the test policy (§6.1) and the image rule;
   - pointers to `plan.md`, `research.md`, `catalog.md`, `corpus/vm/README.md`.

   Drop the prototype feature description (it lives in git history and
   `legacy/`). Also:
   - the licence line (Apache-2.0) and the `corpus/vm` smoke command
     (below, local only);
   - fold `commands.txt`'s two "running at once" `uv run` lines into a
     legacy subsection (paths updated to `legacy/`), drop its `sudo mount`
     recipe (research.md §10.4), then `git rm commands.txt`.
9. **CI fixture.** Add `tests/fixtures/sandbox.img.zst`, produced by
   `zstd -19 -c sandbox.img > tests/fixtures/sandbox.img.zst`. It is
   **~15 KB** (14 963 bytes), and the round-trip sha256 was verified
   byte-exact on 2026-09-15. Add `tests/fixtures/SHA256SUMS` with the
   sandbox hash. **Decided 2026-09-15: tracked.** `sandbox.img` itself stays
   gitignored; only this compressed copy is committed. The local pre-merge
   gate (§6.1) still runs too.
10. **CI** `.github/workflows/ci.yml` (outline):
    - triggers: `push` to `main`, `pull_request`;
    - one job `test` on `ubuntu-24.04`, `permissions: contents: read`;
    - steps:
      - `actions/checkout@v7` (current major; v7.0.1, 2026-07-20);
      - `astral-sh/setup-uv@v10.1.0` (pin a full tag: this action publishes no floating major tag, so `@v10` fails to resolve) with
        `enable-cache: true` (v10 only changed the `auto` default, which
        disables caching for `pull_request_target`, `workflow_run` and
        `release`);
      - `uv python install 3.14`;
      - `uv sync --locked`;
      - `uv run ruff check .`;
      - `uv run ruff format --check .` (covers `corpus/` Python);
      - `corpus/vm` shell syntax check:
        `for f in corpus/vm/*.sh corpus/vm/scenarios/*.sh corpus/vm/init; do sh -n "$f"; done`
        (passes today). `shellcheck` is not a gate yet: 0.9.0 reports style
        notes (SC2086, SC2015) and SC2148 on the sourced `*.guest.sh` files,
        and fixing those is a script change, not M0 work;
      - restore fixture:
        `zstd -dc tests/fixtures/sandbox.img.zst > sandbox.img && sha256sum -c tests/fixtures/SHA256SUMS`
        — decompresses to the gitignored repo-root path inside the checkout;
      - `uv run pytest`;
      - `uv run python -m unittest discover -s legacy/tests`;
      - `uv run btrfska --help`.
    - No image generation in CI: hosted runners are not assumed to expose
      `/dev/kvm` (the scheduled `vm` job arrives in M7).
11. **Catalog entry** for M0 with the acceptance outputs below.

**Commands (canonical, used in README and CI).**
```sh
uv sync                                                # create .venv from uv.lock
uv run ruff check . && uv run ruff format --check .   # lint (legacy/ excluded)
uv run pytest                                          # new tests + legacy tests (collected as unittest cases)
uv run pytest -m sandbox                               # sandbox-only subset
uv run python -m unittest discover -s legacy/tests     # legacy suite, original runner
uv run --python 3.14 python legacy/main.py sandbox.img -o images/scratch/legacy-out   # legacy CLI
uv run btrfska --help
uvx --from . btrfska --version
# corpus/vm smoke test: local only (needs /dev/kvm), not run in CI; output under images/
corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh && corpus/vm/make_image.sh smoke_s01
```

**Acceptance checks (all must pass, outputs pasted into the catalog entry).**
- `uv sync --locked` succeeds from a clean clone.
- `uv run ruff check .` and `uv run ruff format --check .` → no findings
  (the task-5 formatting commit changes only tracked `corpus/**/*.py`).
- The `corpus/vm` `sh -n` loop exits 0. If `/dev/kvm` is available locally,
  the smoke command prints `images/scenarios/smoke_s01.img`; record this in
  the catalog, but it is not a merge gate.
- `uv run pytest` → 0 failures. With `sandbox.img` present, the legacy
  integration and targeted-scan tests **run** (not skip). Confirm with
  `-ra`: the skip summary lists no `sandbox.img not found`.
- `uv run python -m unittest discover -s legacy/tests` → same test count as
  before the move, OK.
- `uvx --from . btrfska --version` prints `0.0.1`; `uv run btrfska info
  sandbox.img` prints the sha256 `07ca38d4…5876418`.
- `sha256sum sandbox.img` unchanged after the whole run.
- `git status` shows no files created or modified outside `src/ tests/
  legacy/ corpus/ .github/ conftest.py LICENSE README.md pyproject.toml
  uv.lock .gitignore catalog.md`, apart from the planned removals
  (`commands.txt`, untracked `recovery_output/`, the moved prototype files);
  test output only under `images/scratch/`.
- CI green on the PR.

**Status 2026-09-15: done** (catalog.md, M0 entry). One item recorded there as done was not:
`recovery_output/` stayed tracked until 2026-09-21 (catalog.md, "Repository layout and paper
library").

### M1 — Substrate trust layer + anchored walking (~1.5 weeks)

**Goal:** a validated read path we own (§3.5), with backup-root states walked
and proven against ground truth.

**Branch:** `feature/m1-substrate`.

**Tasks (in order).**

1. **Spec carry-over from `feature/m1-backup-roots`** (research.md §10.5) —
   as tests, not code:
   - add research.md §8.1 **defect #8** (EXTENT_ITEM objectid-vs-offset);
   - write the failing ground-truth tests first:
     - four backup slots hold gens {11, 12, 13, 14} in slot order
       13, 14, 11, 12;
     - all four share chunk-root gen 8;
     - `total_bytes` 268435456;
     - newest backup's tree root equals the SB root;
     - gen 11 fs tree: inode 257 `target_file.txt`, 31 B, inline;
     - gen 13: inode 257 `large_target.txt`, 5 242 880 B;
     - gen 14: root dir only;
     - gen 12 contents recorded from `btrfs inspect-internal dump-tree
       -t 5 -b <bytenr>` (not asserted on the old branch — capture it,
       don't guess).

   Record hardening-backlog items as later tasks: backup-root scan
   fallback, SB mirrors, richer second image, TREE_BLOCK_REF coverage.
2. **On-disk tables** `substrate/ondisk.py` (our own `struct` format
   strings; no cstruct definitions):
   - layouts for superblock, backup root, header, key, item, key pointer,
     inode item, inode ref/extref, dir item, root item/ref, file extent
     item, chunk + stripe, dev extent, block group, extent/metadata item and
     inline refs, with sizes asserted (e.g. inode item 160 B, item 25 B);
   - offsets, csum sizes, item keys incl. 172, 230, 234–236;
   - objectids 11, 12, 13;
   - incompat bits incl. RST `1<<14`, ETv2 `1<<13`, simple quota
     `1<<16`, REMAP `1<<17`;
   - compat_ro bits incl. BGT `1<<3`;
   - values asserted against kernel v7.0 `btrfs_tree.h` / `fs.h`
     (research.md §10.3).
3. **Csum dispatch** `substrate/csum.py` (adds the `crc32c` and `xxhash`
   runtime deps): crc32c / xxhash64 / sha256 /
   blake2b-256 over `[0x20:]` of superblock and tree blocks, and over data
   sectors. Test vectors: RFC-3720 CRC vectors, plus one known-good block
   per type from generated images.
4. **Superblock + mirrors + gate** `substrate/superblock.py`:
   - read the 64 KiB, 64 MiB and 256 GiB copies that fit the image;
   - validate magic, csum and bytenr;
   - select the best copy by csum-valid, then highest generation, and
     report the disagreement;
   - **incompat gate**:
     - known-stable bits → proceed;
     - RST / ETv2 / REMAP → refuse with report line
       `UNSUPPORTED_INCOMPAT <name>` (flag-only mode `--allow-unsupported`
       continues, marking every derived row `unsupported_format=1`);
     - **unknown bits → refuse**, same override.
   - compat_ro BGT → block groups are read from tree 11.
5. **Node reader** `substrate/node.py`: `read_node(logical|physical) →
   ValidatedNode` with checks for csum, bytenr, fsid (or metadata_uuid),
   chunk-tree uuid, generation ≤ SB gen, level ≤ 7, nritems bound, and
   owner. Each check is recorded individually — a failed node is returned
   *flagged*, never silently parsed. Plus the property test: random bytes
   and mutated valid nodes never crash. Every mirror copy is read and
   validated; the first valid one is used and all copies are reported
   (§3.5 mirror policy).
6. **Chunk maps** `substrate/chunks.py`: sys_chunk_array + chunk tree →
   `ChunkMap(source="current")`; healthy RAID stripe math; zero-stripe chunk
   items tolerated and flagged (remap-tree images).
7. **Tree walker + backup roots** `substrate/tree.py`, `substrate/roots.py`:
   - walk from any bytenr with per-hop validation;
   - backup roots parsed and **sorted by generation, never slot**;
   - enumerate subvolumes via ROOT_ITEM/ROOT_REF/ROOT_BACKREF.
8. **Extent reads + decompression** `substrate/extents.py`,
   `substrate/compress.py`, `substrate/lzo.py` (§3.5):
   - EXTENT_DATA → bytes for inline, regular and prealloc extents and holes
     (explicit and NO_HOLES-implicit), honouring `offset`, `num_bytes` and
     `ram_bytes`, through any `ChunkMap`; every read carries a record (map
     source, physical ranges, compression, decode outcome);
   - zlib via `zlib.decompressobj` and zstd via
     `compression.zstd.ZstdDecompressor`, both capped at `ram_bytes`; LZO
     via the btrfs segment framing (§3.5) over `lzo.py`; output length is
     checked against `ram_bytes`, and failures become `DecodeError(kind)`
     records, never truncated or padded content;
   - `lzo.py`: an LZO1X decoder written from the kernel's
     `Documentation/staging/lzo.rst` bitstream description, with
     input-overrun, output-overrun, lookbehind-overrun and
     missing-end-marker checks, raising only `LzoError`;
   - unit tests (`tests/test_lzo.py`, `tests/test_compress.py`):
     - dissect.util 3.24 LZO vectors (Apache-2.0, attributed);
     - the crafted lookbehind stream `15 41 42 43 44 40 FF 11 00 00` and a
       truncated stream raise `LzoError`;
     - property test: random and bit-flipped streams raise only
       `LzoError`/`DecodeError` and never exceed the output bound;
     - framing tests for the 1–3-byte sector-tail padding;
   - add `dissect.btrfs==1.10.*` and `lzallright==0.2.*` to the `dev`
     dependency group (test oracles only, §3.3);
   - oracle tests (`tests/oracle/`, skipped when the dev group is absent):
     - lzallright round-trip fuzz (seeded, ≥ 2 000 vectors, identical
       output);
     - every file in the current tree and snapshots of `sandbox.img`,
       `m1_xxhash` (zstd), `m1_lzo` and `m1_zlib`: our bytes == dissect.btrfs
       stream bytes, and == the guest-printed SHA-256 where the scenario
       printed one;
   - import-boundary test: nothing under `src/` imports `dissect` or
     `lzallright`.
9. **M1 corpus images via `corpus/vm/`** (all under `images/scenarios/`):
   - `m1_xxhash` (s01, `CSUM=xxhash`);
   - `m1_sha256_bgt` (`CSUM=sha256 MKFS_ARGS="-O block-group-tree"`);
   - `m1_blake2b`;
   - `m1_lzo` (s01 with `MOUNT_OPTS=compress-force=lzo,commit=5`) and
     `m1_zlib` (`compress-force=zlib,commit=5`), for task 8;
   - `m1_badnode`: copy of `m1_xxhash` with one leaf byte flipped by a
     committed script `corpus/mutate.py` that writes only to a new file under
     `images/`;
   - `m1_unknown_incompat`: bit 1<<40 set and superblock csum recomputed,
     same script;
   - `m1_mirror_damage`: primary SB zeroed.

   Each gets a manifest line in `corpus/manifest.tsv` (name, generator
   command, host mkfs version, guest kernel, sha256). Tests needing them
   are `@pytest.mark.vm` and skip when absent.
10. **CLI** `btrfska info IMAGE` (superblock copies, gate verdict, csum type,
    backup roots by generation) and `btrfska walk IMAGE --root
    {current,backup:GEN,bytenr:N}` (JSON lines with validation +
    provenance).
11. **EXP-001** (§7): csum-type coverage — legacy vs btrfska on the four
    csum-type images; the result goes to `experiments/EXP-001.md`.

**DoD.**
- Backup states gens 11–14 of `sandbox.img` walked with anchored provenance,
  and the task-1 ground-truth tests are green.
- `m1_xxhash`, `m1_sha256_bgt` and `m1_blake2b` are fully walked; the legacy
  tool finds nothing on non-crc32c images (defect #1 regression proof).
- `m1_unknown_incompat` is refused with exit ≠ 0 and an
  `UNSUPPORTED_INCOMPAT` line.
- `m1_badnode` reports a csum failure for that node instead of items.
- `m1_mirror_damage` selects mirror 1 and reports it.
- Task-8 oracle tests are green: every file on `sandbox.img`, `m1_xxhash`
  (zstd), `m1_lzo` and `m1_zlib` reads byte-identical to dissect.btrfs and
  to the guest SHA-256s; the LZO property tests pass.
- Import-boundary and read-only tests pass; `sandbox.img` hash unchanged.

**Status 2026-09-15: done.** Every DoD bullet is met across M1a, M1b and
M1c; the evidence per bullet is in the catalog.md M1c entry.

### M2 — Scan kernel v1 (~1 week)
- `scan/kernel_numpy.py`: mmap + `np.frombuffer` strided FSID compare +
  csum validation via `substrate/csum.py` + multiprocessing over image
  chunks; probe at sectorsize (4 KiB) alignment, not just nodesize.
- Port targeted regions (typed chunks + unmapped gaps) with the
  MIXED_GROUPS fix (parse incompat_flags) and tree-11 block-group input;
  `--full-sweep` fallback.
- Old-root discovery: from scan hits, group root-tree-owned blocks by
  (owner, level, generation) — find-root's algorithm feeding our catalog
  instead of stdout. Also record owner-13 (remap) and owner-12 (RST) blocks
  when present, unparsed.
- Discard axis first use: scan the three `s01_discard_{none,async,sync}`
  images (EXP-002).
  - On each image, our stale-block count must *equal*
    `probe_stale_metadata.py` run on that same image: this is a
    deterministic parse, so no tolerance applies.
  - Across regenerated images, counts are compared with EXP-000's per-column
    median and range from ≥ 5 runs. Any tolerance is that measured range,
    not a fixed number: the two cited runs already differ by 2 in columns
    1–3 and by 4 in column 4.
- **DoD:**
  - sandbox parity: 71 orphans, 21 outside map, identical offsets;
  - discard trio: exact per-image agreement with the probe; cross-run
    numbers reported as median and range next to EXP-000;
  - ≥200 MB/s single-core on a synthetic 10 GiB image generated under
    `images/`;
  - benchmark script committed.

**Status 2026-09-15: done.** M2a delivered the kernel, regions, classification and
EXP-003; M2b delivered old-root discovery, EXP-000 and EXP-002. Every DoD bullet is met
(catalog.md M2b entry, "M2 closeout"):
- sandbox parity: 71 legacy-compatible orphans, 21 outside the map, identical offsets
  (`test_sandbox_legacy_compatible_orphans_are_the_legacy_offsets`, M2a);
- discard trio: `btrfska scan --full-sweep`, counted under the probe's rules, equals
  `probe_stale_metadata.py` on 48 of 48 images (EXP-002). This is coverage agreement: the count
  reuses btrfska's scan plan and prefilter, so it verifies the offsets read, the fsid match and
  the generation field, not an independent re-implementation. Cross-run numbers are medians and
  ranges over N = 15 regenerations next to EXP-000's;
- ≥ 200 MB/s single-core on a synthetic 10 GiB image: 3 227.5 MB/s slowest run, 512 MB/s on a
  100 % metadata image (EXP-003, M2a);
- benchmark script committed: `experiments/bench_scan.py` (M2a).

Old-root discovery (`scan/roots.py`, `btrfska roots`) groups the valid blocks of every owner by
(owner, generation, level), not only root-tree blocks. It records owner-12 and owner-13 blocks
unparsed and groups log-tree blocks by generation. It rediscovers every superblock and backup root
on `sandbox.img` and the M1 images, and finds 31 candidate root-tree blocks (states) beyond the 4
backups on every s01 image without trims (EXP-002). That survival is partly an artefact of the
scenario's final balance and short life (EXP-002 §6.5).

**M2a** (catalog.md M2a entry).
- **Delivered:**
  - `scan/regions.py` with the MIXED_GROUPS fix, tree-11 block-group input
    and `--full-sweep`;
  - `scan/kernel_numpy.py`;
  - `scan/classify.py`, which holds the live set that §4.1 names
    `scan/live_set.py`;
  - `btrfska scan`;
  - EXP-003.
- **Sandbox parity** holds on the prototype's orphan definition (71 offsets,
  21 outside the map, identical). The reachability classes reconcile those
  71 as 8 live, 34 backup-reachable, 28 unreferenced and 1 invalid.
- **M2b** covers the rest: old-root discovery, the discard trio (EXP-002)
  and the EXP-000 backfill.
- **Review fixes** (catalog.md, M2a): log trees are walked and classified
  live (`m2_logtree`), the scan streams in bounded memory, skipped DATA bytes
  are reported, EXP-003 gained a density sweep. The foreign-FSID limitation
  is planned under M6.

### M3 — Evidence catalog (~1 week)

**Goal.** One pass over an image fills `evidence.db`; everything after it (M4 recovery, M5
timelines, M6 tiers, M9 GUI) queries the database, not the image. Design fixed on 2026-09-21,
before implementation.

**Decisions.**
1. **One database per image, written once.** `btrfska catalog build IMAGE --db PATH` refuses an
   existing `PATH`, refuses a path that is the image, and removes a partial file on failure. There
   is no in-place update: a rebuild is a new file. The single `scan_runs` row is the chain of
   custody: image path, size, SHA-256 before and after the pass, tool version, parameters, gate
   verdict, `schema_version`.
2. **One write site.** Databases are created only in `src/btrfska/catalog/db.py`. The read-only test
   bans `sqlite3.connect` everywhere else in `src/` and allowlists that module, next to
   `substrate/image.py`. Readers open with a `mode=ro` URI. No evidence image is ever written.
3. **The physical copy is the unit of evidence.** `nodes` has one row per scan candidate, valid or
   not, at its physical offset, with its classification; `node_checks` has one row per check, so a
   failed candidate stays queryable ("validate before trusting", §2). A logical block is the view
   `blocks` over valid nodes with equal (bytenr, generation, level, owner).
4. **Parsed content is stored once per distinct block content.** DUP and RAID1 copies are
   byte-identical, so `items` and `key_ptrs` hang off `contents` (SHA-256 of the block), and `nodes`
   point to it. A copy that differs gets its own content row, which keeps divergent mirrors visible.
5. **Integers.** SQLite integers are signed 64-bit. Every on-disk u64 is stored as its
   two's-complement signed value: objectids of 2^63 and above appear negative, which is how btrfs
   names them (−6 is the log tree). The schema document says so for every such column.
6. **Scan once.** The builder consumes one candidate stream and feeds classification, the block
   index for old-root discovery and the database from it. `scan` and `roots` each rescan today
   (catalog.md M2b, "Repeated work"); the catalog does not.
7. **No empty speculative tables.** `artifacts` and `provenance` are created by the milestone that
   first writes them (M4, M6), with a `schema_version` bump, not now.

**M3a: schema, build, custody** (first pull request).
- `catalog/schema.py` (DDL, `SCHEMA_VERSION = 1`), `catalog/db.py` (create, open read-only),
  `catalog/build.py`, CLI `btrfska catalog build` and `btrfska catalog info`.
- Tables: `scan_runs`, `superblocks`, `chunks`, `stripes`, `regions` (scanned and skipped ranges),
  `nodes`, `node_checks`, `known_roots` (superblock and backup slots, with rediscovery),
  `states`, `state_trees` (old-root discovery), `walk_failures`; view `blocks`.
- Schema documented in `docs/evidence-db.md`; a test fails when a table or column is undocumented.
- **DoD:** `catalog build sandbox.img` fills the database in one pass; its counts equal
  `scan_image(...).summary` and the `roots` discovery on the sandbox and on every corpus image; the
  image hash is unchanged; a second build to the same path is refused.

**M3b: content and reverse queries** (second pull request; details fixed 2026-09-21 before
implementation).
- `contents`: one row per distinct block content (SHA-256 of the nodesize bytes), with level,
  item count and the first and last key. `nodes.content_id` points to it; a block cut by the image
  end has none. Items are parsed when some node with that content is valid.
- `items` (key, offset, size and the raw item bytes, inline file data included) and `key_ptrs`.
  **Keys are stored twice:** as three readable integers, and as `key_sort`, the 17 bytes objectid
  (big-endian), type, offset (big-endian). Signed storage (decision 5) keeps values but not their
  order: objectid −6 sorts before 0. SQLite compares BLOBs bytewise, so `key_sort` orders keys as
  btrfs does, and range queries use it.
- View `tree_edges`: parent block to the child its pointer names, with whether a valid scanned
  block matches the pointer's bytenr, generation and level.
- Parsed tables: `inodes`, `inode_refs` (INODE_REF and INODE_EXTREF: the names and parents path
  reconstruction needs in M4), `dir_entries` (DIR_ITEM, DIR_INDEX, XATTR_ITEM), `file_extents`,
  `extents` (EXTENT_ITEM and METADATA_ITEM) and `extent_backrefs` (inline and standalone
  TREE_BLOCK_REF, SHARED_BLOCK_REF, EXTENT_DATA_REF, SHARED_DATA_REF, EXTENT_OWNER_REF 172). A
  payload that does not parse is kept in `items` and reported in `item_problems`; it never stops
  the build. The extent-item parser is new (`substrate/items.py`): the logical address is the key
  objectid and the key offset is the length, or the level for METADATA_ITEM (prototype defect #8).
- Reverse queries in `catalog/query.py`, each also `btrfska catalog query DB …`:
  parents-of (bytenr), owners-of (extent: file extents that point to it, and the extent tree's
  back-references to it), trees-covering (key), items-in-generation (g).
- **DoD:** the four reverse queries are answered from the database alone, with the image file
  deleted; results agree with `btrfska walk` on the current and backup roots of the sandbox; the
  extent parser agrees with `btrfs inspect-internal dump-tree` where btrfs-progs is installed.
  `schema_version` 2.

The schema is the contract M9's GUI reads; a change bumps `schema_version` and is described in
`docs/evidence-db.md`.

**Status 2026-09-21: done.** M3a delivered the schema, the single write site, the one-pass build
and the chain of custody; M3b the block contents, the parsed tables, the tree edges and the
reverse queries (catalog.md, M3a and M3b entries). Every DoD bullet is met, each by a test:
- one pass fills the database, and it equals independent `scan` and `roots` runs row for row on
  `sandbox.img` and 13 corpus images
  (`test_sandbox_database_equals_scan_and_roots_and_the_golden_numbers`,
  `test_corpus_database_equals_scan_and_roots`);
- the image hash is unchanged, a second build to the same path is refused and a failed build
  leaves no file (`test_a_second_build_is_refused_and_a_failed_build_leaves_no_file`);
- the four reverse queries are answered with the image file deleted and agree with anchored
  walks of the current and the four backup roots, on the sandbox and four corpus images
  (`test_sandbox_reverse_queries_agree_with_walks_with_the_image_deleted` and its corpus
  counterpart);
- the extent parser agrees with `btrfs inspect-internal dump-tree`
  (`test_extent_back_references_equal_btrfs_dump_tree`);
- every table and column is documented (`test_every_table_and_column_is_documented`);
  `schema_version` is 2.

What "all M1/M2 outputs flow through it" covers: everything `info`, `walk`, `scan` and `roots`
report. File *content* (`cat`) is not stored; extracting files is M4.

### M4 — Recovery engines (~1–2 weeks)
- Anchored recovery: extract files from any cataloged root via
  `substrate/extents.py` (compression handled), `-m`-style metadata, xattrs (0x18),
  INODE_EXTREF (0x0D); `FT_ENCRYPTED` 0x80 masked; encrypted extents
  refused with a report line.
- Streaming extent reads: M1c's `read_file` and `cat` hold a file fully in
  memory (peak about 2× its size); extraction reads and writes extent by
  extent.
- Archaeology port: beyond-`nritems` orphan items (leaf + internal),
  node-slack residual mining, kernel ORPHAN_ITEM (0x30) resurrection —
  golden-tested against legacy outputs (with defect #8 corrected).
- Cross-generation dedup of recovered content (by extent tuple + sha256).
- Settle whether copy-on-write zeroes node slack (research.md §10.13). **Done 2026-09-21,
  EXP-005:** copy-on-write copies the slack, and the write path zeroes it before every write
  (`prepare_eb_write`, v7.0 `extent_io.c:2215`, since v4.9), in leaves and in internal nodes. No
  kernel-written block of the corpus has a non-zero slack byte; `mkfs.btrfs` leaves stale items
  of its own in about a third of the blocks it writes. Consequences for this milestone: the
  beyond-`nritems` and slack parsers report *what is there and who can have written it* (mkfs
  remnant, or not explainable by any known writer), they are not expected to recover files, and
  they are tested on the mkfs remnants and on an image with planted slack.
- **DoD:**
  - migration-done criterion (§4.3) met;
  - deleted files recoverable from (a) anchored historical roots,
    (b) orphan nodes and (c) orphan items, each labeled with its source. After EXP-005, (c)
    means the kernel's ORPHAN_ITEM (0x30): an inode unlinked but not yet cleaned up;
  - on the beyond-4-generations image (§6.2) (b)/(c) recover a file that
    (a) cannot.

**M4b: anchored recovery, `btrfska recover`** (design fixed 2026-09-21, before implementation).

*What it is.* `btrfska recover IMAGE --db DB --out DIR [--root current|backup:GEN|state:ID]...
[--tree ID]` extracts the files of one tree as one cataloged root saw them. Every root the
catalog knows is a row of `states` (`known_as` names the current and backup roots; the rest were
discovered), and `state_trees` names each tree's root block, so one selector covers all three
kinds. Default: `--root current --tree 5`.

*Decisions.*
1. **Metadata comes from the database, file data from the image.** The tree is walked in the
   database: root block, `key_ptrs`, child blocks by (bytenr, generation, level), leaf `items`.
   That reaches blocks the current chunk map no longer places, which a walk through the image
   cannot, and it is the rule of §2 ("scan once, query forever"). A child that was not scanned as
   a valid block is a gap: recorded, and the files under it are simply absent. Item payloads are
   parsed with the `substrate/items.py` parsers, not read from the parsed tables, so recovery
   and `walk` share one parser. The image must be the one the database was built from: its
   SHA-256 is compared with `scan_runs.image_sha256_before` (skipped with `--no-rehash`, and
   recorded as not checked).
2. **Streaming.** `substrate/extents.py` gains `stream_extent`: the extent is mapped first (every
   piece, every copy, no data read), which is where `unmapped` and `unreadable` are decided; then
   an uncompressed extent is yielded in pieces of at most 1 MiB. A compressed extent is at most
   128 KiB in, 128 KiB out, and is decoded whole. `read_extent` is rebuilt on the same mapping
   step so there is one read path. The writer hashes as it writes; memory use does not depend on
   file size. Data extents are read through the current chunk map (historical maps: M5), so an
   old state's extent in a removed chunk fails as `unmapped`, and says so.
3. **A file that cannot be read completely is never passed off as complete.** Every extent
   failure leaves a hole of the extent's length, the file is written as `NAME.partial`, and the
   artifact row says which ranges are missing and why. An encrypted extent is refused: a report
   line on stderr (`refused: encrypted extent ...`), status `refused_encrypted`, no bytes written
   for that file. `FT_ENCRYPTED` (0x80) is masked out of directory-entry types and reported.
4. **Names.** Paths are built from INODE_REF and INODE_EXTREF (parent, name) up to the tree's root
   directory; every name of a hard-linked inode is recorded, the file is written once, under its
   first name in key order. An inode whose parent chain does not reach the root directory
   (a gap, or a cycle, which is bounded) goes under `_unattached/INODE`. Names are bytes from an
   untrusted image: `/`, NUL, `.` and `..` components are replaced and reported, and no path
   leaves `DIR`.
5. **The output writer is one module, `recover/output.py`, and it joins the read-only test's
   allowlist explicitly.** It creates `DIR` (which must not exist), creates directories and
   files relative to a directory descriptor with `O_CREAT | O_EXCL | O_NOFOLLOW`, never follows a
   symlink and never overwrites anything, so it cannot write to an image or to any existing
   file. It does not import the image layer; a test checks both. Symlinks, devices, FIFOs and
   sockets are **recorded, not created**: a symlink from a hostile image is a way out of `DIR`.
   Mode (permission bits only, never setuid, setgid or sticky) and mtime/atime are applied;
   ownership is recorded, not applied (no root). Extended attributes are recorded in the
   database and the manifest, not set (most need privileges the tool must not have).
6. **The database records every recovery** (schema version 3). `catalog/db.py` stays the only
   place a database is opened: `open_for_recovery` opens an existing version-3 database for
   appending, with an SQLite authorizer that allows INSERT and UPDATE on `recovery_runs`,
   `artifacts` and `provenance` and nothing else. The scan's rows cannot change after the build;
   M3's "written once" holds for them. A version-2 database is refused: rebuild it.
   - `recovery_runs`: one row per invocation (times, tool version, image hash check, output
     directory, options, counts).
   - `artifacts`: one row per inode recovered or refused: source, tree, root block, inode,
     kind, path and all names, size, mode, owner, times, xattrs, status, bytes written,
     SHA-256, the extent signature, `duplicate_of`, output path, symlink target, problems.
   - `provenance`: the evidence chain, one row per item an artifact was built from (role, leaf
     content and slot, leaf block, and for an extent its read record: kind, compression,
     address, the physical ranges and copies used, SHA-256, failure).
   `DIR/manifest.jsonl` repeats the artifact records, so the output directory explains itself
   without the database.
7. **Deduplication across roots.** Several `--root` give one subdirectory per root. An artifact
   whose extent signature (size plus every extent's address, offset, length, compression, or
   inline bytes) equals a complete artifact already written in this run is not read again: its
   row has `duplicate_of` and no output file. `--no-dedup` writes every copy.
8. `artifacts.in_current`: whether the current tree of the same id holds the same inode with
   the same creation generation. It is the label "deleted since", and M5's timelines replace it.

*Definition of done for M4b.*
- on `sandbox.img` and the corpus images, every regular file of the current fs tree comes out
  byte-identical to `btrfska cat` (and so to the oracle tests behind it), from `current` and
  from every backup root; on `m1_lzo` and `m1_zlib` that covers compressed extents;
- a file deleted before the last commit is recovered from a backup root and from a discovered
  state, with `in_current` 0 and a provenance chain that names the leaf and slot of every item;
- peak memory while recovering a file much larger than 1 MiB stays bounded (test with a
  synthetic large extent and `tracemalloc`);
- hostile input: names with `/`, `..`, NUL and 255+ bytes, parent cycles, an inode without
  INODE_ITEM, overlapping extents, a symlink, an encrypted extent, random item payloads: no
  crash, nothing written outside `DIR`;
- the image hash is unchanged; the authorizer refuses a write to a scan table; every new column
  is documented (`test_every_table_and_column_is_documented`); README documents the command and
  its records.

**M4b status 2026-09-21: done** (catalog.md, M4b entry). Each bullet of its definition of done
is a test in `tests/test_recover.py` or `tests/test_readonly.py`.

**M4c: the archaeology port, part 1: what lies beyond `nritems`** (design fixed 2026-09-21,
before implementation; part 2, M4d, is recovery from unreferenced leaves and ORPHAN_ITEMs).

*What EXP-005 changed.* On a filesystem the kernel has written since v4.9 this area is empty,
except in blocks `mkfs.btrfs` wrote and the kernel never rewrote. The port therefore does not
"recover deleted items"; it **describes** what a block's slack holds, so that (a) mkfs remnants
are recognised for what they are, (b) anything else stands out for the C5 detector, and (c) a
filesystem last written by an older kernel, where the prototype's technique does apply, is read
correctly. The parsers are ported to the spec, not line by line.

*Decisions.*
1. `substrate/slack.py` (a block parser belongs to the substrate, where the catalog may import it; §4.1 had pencilled in `recover/slack.py`), pure functions over one block's bytes:
   - `slack_range`: the two ranges `prepare_eb_write` zeroes (moved here from
     `experiments/exp005.py`, which imports it);
   - **stale items**: item headers on the leaf's 25-byte grid, from slot `nritems` to the end of
     the slack. A slot counts when it is not all-zero, its key type is a known item type and its
     data range lies inside the block. Each records where its data lies: `in_slack` (the payload
     is still there, and is kept), `overlaps_live` (live items now use that space), `empty`;
   - **stale key pointers**: the same on the 33-byte grid: block pointer non-zero and
     sector-aligned, generation non-zero and not above the block's own, known key type;
   - **both grids in both kinds of block.** A leaf reallocated as an internal node keeps leaf
     remnants, and the reverse (Bhat & Wani 2018). The prototype slid its 25-byte window from the
     *start of the node's slack*, which is off the leaf grid unless `33 × nritems` is a multiple
     of 25; grids here are anchored at the end of the header, where the items were;
   - `slack_class`: `zero`; `stale_structures` when the first grid slot of the slack is a valid
     stale entry (what mkfs and old kernels leave); `other` for non-zero content that does not
     begin with one (what a message hidden after Toolan & Humphries looks like). This is a
     description, not a verdict: forged stale headers would pass as `stale_structures`. Deciding
     is M6's job, with a measured false-positive rate.
2. **Stored at build time** (schema version 4), once per distinct content like every parsed table:
   `contents` gains `slack_start`, `slack_len`, `slack_nonzero`, `slack_class`; new tables
   `stale_items` and `stale_key_ptrs`. Only valid blocks are described.
3. **Prototype parity, without its defects.** On `sandbox.img` the prototype reports 0 orphan
   items, 0 internal pointers, 0 internal residuals and 4 saved leaf slacks. Golden test: our rows
   for those four physical copies have the prototype's slack length and non-zero count; no stale
   item of a file-tree type exists; and we also describe the extent-tree leaf the prototype skips
   (it routes owner-2 leaves to a parser that ignores slack). Defect #8 is asserted the right way
   round and relative to the image: every EXTENT_DATA_REF in `extent_backrefs` that names an
   inode and offset a `file_extents` row also names has that row's `disk_bytenr` as its extent
   address (the key objectid), never the key offset.
4. **A planted-slack image** for the case no honest image has: `corpus/mutate.py plant-slack`
   writes a message into the slack of one leaf and of one internal node of a copy of `m3_wide`
   and recomputes both checksums, as Toolan & Humphries did by hand. New manifest row
   `m4_planted_slack`. Expected: both blocks `other`, every other block as in `m3_wide`.
5. Hostile input: random blocks, `nritems` beyond capacity, headers pointing outside the block,
   data ranges that wrap: no exception, nothing read outside the block.

*Definition of done for M4c.* The golden test of decision 3; the claim of EXP-005 as a database
query on every corpus image (no kernel-written block has `slack_nonzero` > 0, relative to a
control formatted in the test); `m4_planted_slack` flags exactly the two planted blocks; synthetic
pre-4.9-style leaves give back a deleted file's name and inline content from stale items;
hostile-input tests; every new column documented; a fresh clone builds the new image with
`./setup.sh`.

**M4c status 2026-09-21: done** (catalog.md, M4c entry; tests in `tests/test_slack.py` and
`tests/test_mutate.py`).

**M4d: recovery without an anchor: unreferenced leaves and the kernel's ORPHAN_ITEM** (design
fixed 2026-09-21, before implementation).

*What it is.* `btrfska recover … --orphans` adds two sources to the anchored roots, and labels
every artifact with the one it came from (`artifacts.source_kind`):
- `orphan_node`: a valid leaf of a file tree (tree 5 or a subvolume) that **no cataloged state
  reaches**. "Reached" is computed from the database: the leaves of every file tree under every
  row of `states`. This is stricter than `nodes.status`, which knows only the current and the
  backup roots. Such leaves exist on every image looked at so far (26 on `m3_wide`, 4 on
  `sandbox.img`): mostly versions that were written out in the middle of a transaction and
  replaced before its commit, so no root tree ever named them, and leaves whose root tree is gone.
- `orphan_item`: an inode that a tree lists under ORPHAN_ITEM (objectid -5, type 48, offset =
  inode number): unlinked while still open, not yet cleaned up when that tree was written. Its
  INODE_ITEM and extents are intact and it has no name. It is found by the anchored walk of that
  tree; the label, and the search for the name it used to have, are what is new.

*Decisions.*
1. **One leaf at a time, no stitching.** An orphan leaf is read on its own: the inodes whose
   INODE_ITEM it holds, with the names, attributes and extents that are in the same leaf. A file
   whose extent items continue in another leaf comes out `partial` with the reason
   `continues_elsewhere`. Joining leaves of different generations into one file is reconstruction
   (M5, orphan graph), not recovery, and a wrong join would produce a file that never existed.
2. **Paths.** An orphan leaf rarely holds the parent directory, so its files land under
   `orphan_nodes/tree_ID/leaf_BYTENR_genG/.btrfska-unattached/PARENT/NAME`. The parent's objectid
   is kept; resolving it against other states is M5.
3. **What "only recoverable here" means, and how it is shown.** With deduplication on, an orphan
   artifact whose tree, inode, creation generation and extent signature equal an anchored artifact
   of the same run is a `duplicate`. `recover --root all --orphans` therefore leaves, as
   `orphan_node` artifacts that are `complete` and not duplicates, exactly the file versions no
   cataloged root can give. `--root all` (every state) is new for that.
4. **Former names for ORPHAN_ITEM inodes.** The database is searched for INODE_REF and
   INODE_EXTREF items of the same objectid in leaves of the same tree that also hold an INODE_ITEM
   of the same creation generation (an inode number alone proves nothing: `sandbox.img` reuses
   257). They are recorded in `names` with `"former": true` and the generation of the leaf they
   came from; the file is written as `.btrfska-orphan-items/INODE_NAME`.
5. No schema change: `source_kind`, `state_id` (NULL for an orphan leaf), `root_bytenr` and
   `root_generation` (the leaf itself for an orphan leaf) already exist. The document is updated.

*Changed during implementation (2026-09-21), because the first version fooled itself.* A trial
image had 85 root-tree candidates, and the catalog evaluated the newest 64 (`MAX_STATES`, a bound
meant for a terminal report). Six deleted files then looked "recoverable only from orphan
leaves", when root trees that had simply not been evaluated reached them. Two corrections:
- the catalog evaluates up to 4096 states (`catalog build --max-states`), and a bound that bites
  is recorded in `problems` (source `roots`) instead of passing silently;
- "orphan leaf" no longer depends on `states` at all: a file-tree leaf is an orphan when **no
  ROOT_ITEM in any valid root-tree leaf the scan found**, of any generation, names a tree that
  reaches it. That also covers root-tree leaves whose parent node is lost.
With that, the trial image had no file that only an orphan file-tree leaf could give, which is
the honest result for a sequential allocator: a victim's leaf and the root tree of its generation
are allocated side by side and die together. What no root tree ever names is something else:
**leaves of dropped log trees**. A file written, fsynced and deleted within one transaction
reaches the disk only through the log tree, which the next commit drops. Those leaves (owner -6,
not reached by the walk of the superblock's log root) are read as orphan leaves too.

*Definition of done for M4d.* On synthetic trees: an orphan leaf's file is recovered and
labelled; the same file reachable from a state is a duplicate, not a second copy; a file
continuing in another leaf is partial; an ORPHAN_ITEM inode is labelled, keeps its content and
gets its former name only from a leaf with the same creation generation. On `sandbox.img` and
`m3_wide`: every orphan leaf the database lists is processed, nothing crashes, the image is
unchanged, and every artifact has a provenance chain. The file that only an orphan source can
recover is shown on the beyond-4-generations image (next feature), where ground truth says
which file that must be.

**M4d status 2026-09-21: done** (catalog.md, M4d entry).

**M4e: the beyond-4-generations image, and M4's definition of done** (design fixed 2026-09-21,
before the image, its tests or the EXP-004 run were committed. The scenario was drafted during
M4d: its trial builds are what exposed the 64-state bound recorded there.)

*Image `m4_deep`* (scenario `deep`, `MOUNT_OPTS=commit=300`, no compression, no balance, 48
subvolumes so that the root tree has two levels):
- 24 rounds. Each creates one victim file, commits, prints its SHA-256, deletes it, commits,
  rewrites a seventh of 400 inline padding files and commits. A victim exists in exactly one
  committed generation; about 90 generations pass, so the four backup roots hold none but the
  last. Odd victims are inline; even ones are regular, grow from round to round and get a small
  separator file behind them before they are deleted, so that no later victim fits into the hole
  and the data survives.
- Every sixth round writes two **flash files**: written, fsynced and deleted within one
  transaction. They reach the disk only through the log tree, which the next commit drops.
- The last file is unlinked while open, and the guest powers off after the commit (sysrq `o`), so
  the last committed fs tree lists it under ORPHAN_ITEM.
The serial log is the ground truth (`=== VICTIM|FLASH|ORPHAN name sha256`).

*What the tests must show, relative to that image and its log, never as constants:*
- (a) anchored roots: the states beyond the current and backup roots recover victims that the
  current and the four backup roots cannot, byte-identical to the logged hashes;
- (b) orphan nodes: every flash file comes back, complete and hash-exact, as an `orphan_node`
  artifact from a dropped log leaf, and **no** anchored artifact of `--root all` has that hash;
- (c) orphan items: the open-unlinked file comes back as `orphan_item`, hash-exact, with the name
  it had;
- every artifact of the run carries one of the three source labels.
Trial builds (5 on the dev host) gave the same outcome each time; the numbers go into the
catalog with their range, and the tests assert the claims above, not the counts.

*EXP-004 on the new image.* `experiments/exp004.py`, unchanged, runs on `m4_deep`. EXP-004's
open case is a root-tree leaf whose parent node was lost. Trial builds contain none: every
root-tree leaf of a two-level generation still has its node. A natural image is unlikely to
produce one (the allocator places a generation's blocks side by side, and they are overwritten
together), so the case is made the way `m1_badnode_both` was: `corpus/mutate.py lose-root-node`
corrupts every physical copy of the oldest surviving root-tree node that still has leaves, giving
`m4_deep_lost_parent`. The prediction for it is registered in EXP-004 (§6.8) before the script
runs on it.

*M4's definition of done* is then checked bullet by bullet, including the migration gate of §4.3,
and recorded in the catalog. Tagging `legacy-final` and deleting `legacy/` is left to the
maintainer: EXP-001 and EXP-005 regenerate numbers by running the prototype.

**M4 status 2026-09-21: done.** Parts M4b (anchored recovery), M4c (slack describers), M4d
(orphan sources) and M4e (the deep image), with EXP-005 first and EXP-006 last. The definition
of done, bullet by bullet, each with the test or record that shows it:
- *migration-done criterion (§4.3).* On `sandbox.img` the new pipeline reproduces the prototype's
  report: the same 71 generation-defined orphans, 21 of them outside the chunk map
  (`test_sandbox_legacy_compatible_orphans_are_the_legacy_offsets`, summary `(71, 21)`); the same
  recovered files, byte for byte (`test_sandbox_recovery_gives_the_files_the_prototype_recovered`);
  the same leaf slacks, plus the block it skips
  (`test_sandbox_slack_equals_what_the_prototype_saved_and_adds_the_block_it_skips`); extent
  back-references with the address in the right key field, defect #8
  (`test_extent_back_references_carry_the_extent_address_not_the_length`). Compression, checksum
  dispatch, superblock mirrors and backup-root walking are M1's tests and EXP-001. Two things the
  prototype reports are deliberately **not** reproduced, because they are wrong: its "renamed
  inode 257" is two files with a reused number, and its slack finds are mkfs remnants, not
  deleted items (EXP-005).
  **The gate is green. Tagging `legacy-final` and deleting `legacy/` is left to the maintainer:**
  `experiments/exp001.py` and `experiments/exp005.py legacy` regenerate published numbers by
  running the prototype, so deleting it needs a decision on how those stay regenerable (run them
  from the tag, or keep `legacy/` until the paper is submitted).
- *deleted files recoverable from (a) anchored historical roots, (b) orphan nodes and (c) orphan
  items, each labeled with its source.* `artifacts.source_kind`; `tests/test_deep.py` on `m4_deep`
  for all three, against the hashes the scenario logged.
- *on the beyond-4-generations image (b)/(c) recover a file that (a) cannot.* On `m4_deep` every
  flash file comes back only as `orphan_node`, from a dropped log leaf, and appears under no root
  of `--root all` (`test_flash_files_come_back_from_orphan_nodes_and_from_no_anchored_root`);
  EXP-006 gives 8 of 8 in 5 of 5 builds. For committed files the honest answer is the opposite:
  orphan file-tree leaves add none (EXP-006 H2), and the plan no longer expects them to.
- *cross-generation dedup of recovered content.* By tree, inode, creation generation and extent
  signature, within one run (`test_an_unchanged_file_is_written_once_across_roots_unless_dedup_is_off`);
  the SHA-256 of every complete file is stored, so equal content across inodes is one query.
Not done in M4 and moved on: reading data extents through historical chunk maps (M5, C6); files
spanning several orphan leaves and parent paths of orphan files (M5, orphan graph); replaying the
live log tree (M5); data checksum verification and confidence tiers (M6).

### M5 — Reconstruction & timelines (~2 weeks; novelty core — start early)
- Orphan graph: reconcile scanned nodes + edges by owner/generation/
  key-range/csum into candidate historical subtrees; reattach fragments
  (cite btrfs-rec's rebuild-trees as prior art, ours is read-only evidence
  assembly).
- Multi-source per-inode lifecycle timelines (C3): full-state diff between
  any two cataloged states (backup roots, discovered old roots,
  reconstructed fragments) → create/modify/rename/move/delete, content delta
  via extent comparison. Sandbox gen 11→12→13→14 is the first test;
  SecurityRonin `recover_deleted` and Beyond Carving's objectid diff are the
  comparison points.
- Deleted-subvolume recovery (orphaned fs-tree roots without ROOT_ITEM);
  compare with btrfscue v0.7 unreferenced-subvolume recovery.
- Historical chunk-map reconstruction from orphaned CHUNK_ITEMs/DEV_EXTENTs
  (unlocks the 21 outside-map orphans → C6).
- **Integrity vs linkage checks in historical walks** (from the M1b review).
  - Today a copy that fails a linkage check (`parent_generation`,
    `first_key`, `owner`, level against the expected level) is invalid, just
    as a checksum failure is. This matches the kernel (disk-io.c:404-436,
    tree-checker.c:2247-2297) and is right for M1.
  - In a historical walk, though, it withholds a checksum-valid, well-formed
    block that was rewritten after the backup root was written.
  - Task:
    - split `node.check_block` into integrity checks (`csum`, `bytenr`,
      `fsid`, `chunk_tree_uuid`, `layout`, plus `nritems`, `written`, level <
      8 and generation ≤ superblock) and linkage checks;
    - expose items from integrity-valid nodes with a `linkage_mismatch` flag
      that names the failed linkage checks, and lower the confidence of every
      row derived from them (M6 tiers);
    - keep the kernel rule for current-state walks.
- Simple-quota attribution: stale EXTENT_OWNER_REF (172) names the creating
  subvolume of deleted data extents → timeline/confidence evidence.
- **DoD:**
  - `btrfska timeline <image>` renders the sandbox's known history;
  - `s01` (balance, 3/3 chunks relocated) yields a reconstructed historical
    chunk map and correctly-translated outside-map orphans.

**M5 is built as four features, in this order** (decided 2026-09-21): M5a historical chunk
maps, because a pre-balance state's file data cannot be read without them and everything later
wants file content; M5b integrity and linkage checks; M5c the orphan graph, deleted subvolumes
and log replay; M5d timelines. The prior-art watch was re-run first (research.md §11).

**M5a: historical chunk maps** (design fixed 2026-09-21, before implementation).

*What it is.* A balance gives every chunk a new logical address and removes the old chunks. The
blocks and the file data of an older state still lie where the old chunks were, but the current
chunk map no longer names those addresses, so today a pre-balance state's files come out
`partial`, every extent `unmapped` (catalog.md, M4b). The superseded chunk-tree blocks are still
on the disk. M5a reads them, stores one chunk map per surviving chunk-tree root, and lets
`btrfska recover` read a state's data through the map of its own time.

*Decisions.*
1. **One map per chunk-tree root that survives.** Old-root discovery already finds candidate
   chunk roots (owner 3, referenced by no block) and walks them through the block index, without
   a chunk map (M2b: `states.maps_historical` counts what such a map places). M5a keeps those
   maps instead of only counting: every candidate chunk root, and every chunk root a backup slot
   names, becomes a map `historical:GEN@BYTENR` with its chunks, its stripes, the chunk-tree
   blocks found and missing, and the sources naming it. The current map stays as it is, built
   by `open_filesystem` from the superblock; a historical map is never merged into it.
2. **DEV_EXTENTs are the second witness, and a fallback.** The dev tree records the same mapping
   from the other side: (devid, physical) to (chunk logical, length). For every stripe of every
   map, the catalog counts the scanned dev-tree leaves holding a DEV_EXTENT that agrees with it
   (`stripes.dev_extents`; 0 means the stripe rests on the CHUNK_ITEM alone). A last map,
   `dev_extents`, is assembled from DEV_EXTENTs only, for chunks whose CHUNK_ITEM did not
   survive. A DEV_EXTENT does not record the profile, so a chunk is accepted there only when
   it cannot matter: the BLOCK_GROUP_ITEM of that address names a mirrored or single profile
   whose length equals the extents', or there is no such item and the filesystem has one device
   (then every stripe is a full copy: SINGLE or DUP). A striped chunk, a chunk whose extents
   disagree, or one address with two different stripe sets (the address was reused) is recorded
   as rejected, with the reason. The pass never guesses a stripe order.
3. **Which map a read goes through.** A state's own map is the one of its chunk root
   (`states.chunk_root_*`, from the superblock or backup slot naming the state, else the newest
   surviving chunk root not newer than the state; `states.map_id`). A state whose chunk root is
   the current one is read exactly as today, through the current map and nothing else: the kernel
   rule for the current state. For any other state the order is: its own map; then, only for an
   address its own map does not hold, the maps newer than it, oldest first, ending with the
   current one; then `dev_extents`. A chunk never moves (relocation makes a new chunk at a new
   address), so a newer map that still holds the address is right unless the address was reused
   in between. An orphan leaf is read like a state of its header generation.
4. **Every read says which map it went through; no map overrides another silently.** An extent
   is mapped by one map as a whole, and `ExtentRead.chunk_map` (in `provenance.read_record`)
   names it. `artifacts.chunk_maps` lists the maps an artifact's content came through. A read
   that did not go through the state's own map says so in the artifact's problems. When the
   map used and a newer map place the same logical address at different physical offsets, the
   address was reused, and the problems say so. When the physical range read lies inside a
   chunk of a newer map, the space was given out again after the state, and the problems say
   that the bytes may have been overwritten. `complete` keeps its meaning (every byte was
   read); whether the bytes are the file's is settled by data checksums in M6, and until then by
   the scenario's logged hashes in tests and experiments.
5. **Outside-map blocks are checked against the maps, not assumed.** A tree block carries its own
   logical address and a checksum, so it is ground truth for a map: a map places the block
   correctly when it translates the header's `bytenr` to the offset the block was scanned at.
   `node_maps` stores, for every valid block the current map does not place where it lies, each
   historical map that does. This is the measurement behind "correctly translated outside-map
   orphans" in M5's definition of done, and it is how a wrong reconstruction would show.
6. **Schema version 5.** New table `chunk_maps`; `chunks.map_id` (and `chunks.map_source` keeps
   the map's name); `stripes.dev_extents`; `states.map_id`; `node_maps`; `artifacts.chunk_maps`.
   Every column documented in evidence-db.md; a version-4 database is refused.
7. `recover --maps current` keeps the M4 behaviour (current map only), so the effect of the
   historical maps can be measured with one tool. The default is `--maps own`.

*Bounds, stated so that no result rests on one silently.* At most 4096 chunk maps are built
(forged chunk roots must not flood the database); when the bound bites, `problems` says so. The
walk of a chunk root uses the existing bounds of old-root discovery.

*Not in M5a.* RAID5/6 parity reconstruction; multi-device images (the corpus has none before
M7, so the multi-device rules are tested on synthetic chunk items only); reading tree blocks
through a historical map in `walk`/`cat` (recovery takes metadata from the database, which
already reaches them); the stale remap tree as a relocation log (C6's experimental part, later).

*Definition of done for M5a.*
- on `s01_discard_none_r1` the catalog holds the pre-balance chunk maps, and every stripe of
  every historical chunk is confirmed by a DEV_EXTENT or reported as unconfirmed;
- the files of a pre-balance state that M4 wrote as `partial` come out `complete`, and their
  SHA-256 equals the one the scenario logged; with `--maps current` they are `partial` as before;
- every artifact read through a map other than the current one names that map, in the artifact
  and in the read record of each extent;
- `node_maps` explains the position of outside-map blocks, and the test asserts it relative to
  the image (each placement is recomputed from the stored chunks), never as a count;
- the `dev_extents` map, built without any CHUNK_ITEM, translates like the CHUNK_ITEM maps for
  every chunk both know (tested on the corpus, and with the CHUNK_ITEMs withheld);
- hostile input: DEV_EXTENTs that overlap, disagree in length, name a striped block group, claim
  an address twice with different stripes, or carry absurd lengths; forged chunk roots; a chunk
  item whose stripes point past the image: no crash, nothing accepted that the rules above
  reject, and the current map unchanged by any of it;
- EXP-007 registered before measuring, five builds, median and range;
- image hashes unchanged; every new column documented; README documents `--maps`.

**M5a status 2026-09-21: done** (catalog.md, M5a entry; EXP-007). Each bullet of its definition
of done is a test in `tests/test_chunkmaps.py` or a row of EXP-007 §6. On `sandbox.img` the 20
valid blocks outside the current map are all placed by the maps of generations 1 to 5: they are
blocks of the two temporary chunks `mkfs.btrfs` creates at 1 MiB and 5 MiB and removes again, not
traces of a balance (the 21st block of the prototype's count is an empty generation-1 fs-tree
leaf, which the kernel's checker rejects). That is the half of M5's definition of done that reads
"`s01` yields a reconstructed historical chunk map and correctly-translated outside-map orphans".

**M5b: integrity and linkage checks in historical walks** (design fixed 2026-09-21, before
implementation).

*What it is.* `node.check_block` answers two different questions with one verdict. *Is this a
well-formed block of this filesystem?* (integrity) and *is it the block the referrer meant?*
(linkage). The kernel needs both to hold, and so does every walk of the current state. A walk
from an old root meets a third case all the time: the address holds a sound block, but a newer
one than the old pointer names. Today that block is simply invalid, and what it holds is
withheld. M5b keeps the verdict and adds the distinction.

*Decisions.*
1. **The partition**, as the M1b review fixed it. Integrity: `csum`, `bytenr`, `fsid`,
   `chunk_tree_uuid`, `generation` (not above the superblock's, or the log rule), `nritems`,
   `written`, `layout`, and `level` below 8. Linkage: `owner`, `parent_generation`, `first_key`,
   and `level` against the level the referrer expects. The twelve check names, the scan records
   and the `node_checks` rows stay as they are: a failed `level` check is an integrity failure
   when the block's own level is 8 or above and a linkage failure otherwise, which is how
   `copy_failure` already reads it. `check_block` becomes `check_integrity` plus
   `check_linkage`, merged in `CHECK_NAMES` order.
2. **`read_node(..., linkage="enforce" | "report")`.** `enforce` is the default and is today's
   behaviour, unchanged: a copy is used only when every check holds. With `report`, when no copy
   passes everything, the first copy whose integrity checks all hold is used, and the node says
   which linkage checks failed (`ValidatedNode.linkage_mismatch`). `valid` keeps its meaning (the
   kernel's rule); the new `usable` is "has a copy whose items may be read". A copy that fails
   any integrity check is never used, in either mode.
3. **`walk(..., linkage=)`** descends usable nodes. A flagged node's pointers are followed like
   any other, with the expectations they imply, so a mismatch is reported where it occurs and not
   inherited silently: every node below it is checked against its own parent pointer.
4. **`btrfska walk --linkage report`** emits the items of flagged nodes with `linkage_mismatch`
   naming the failed checks (and `valid` false). It is **refused for the current root**: the
   current state is walked by the kernel's rule, always. `cat`, `tree`, `recover` and the catalog
   keep `enforce`.
5. **Recovery and timelines never follow a mismatched pointer.** What lies behind one is a
   different, usually newer, block: read as part of the old state it would produce a file
   version that never existed at that time. `recover` walks trees in the database by (bytenr,
   generation, level), so such a pointer is a gap there. M5b makes the gap say what it is: when
   the database holds a valid block of that address with another generation, level, owner or
   first key, the gap line names it and the linkage checks it fails. No row is derived from a
   mismatched block, so there is no confidence to lower yet; M6 gets the flag if a later
   feature starts using them.

*Definition of done for M5b.*
- for every block and expectation, `check_block` returns exactly what it returned before (the
  existing tests, unchanged, plus a property test over random blocks and expectations);
- forged blocks with a valid checksum that fail one linkage check each (owner, generation, first
  key, level) are unusable under `enforce`, usable under `report` with exactly that check named;
  a block failing any integrity check, or with level 8 and above, is never usable;
- random and bit-flipped blocks never raise and never become usable in `report` mode unless
  they pass every integrity check;
- on `sandbox.img` and the corpus: a walk from every backup root in `report` mode yields every
  item the `enforce` walk yields, every additional node is flagged, and the current root gives
  the same records in both modes;
- `walk --linkage report` is refused for the current root; README documents the option and the
  new key (the schema tests compare them);
- a recovery gap names the mismatched block when the database holds one.

**M5b status 2026-09-21: done** (catalog.md, M5b entry). Each bullet of its definition of done is
a test in `tests/test_linkage.py`; the first one was also checked once against the version on
`main`, 60 000 random blocks and expectations, identical checks and details. On the corpus only
`m2_logtree` has a backup slot whose blocks were rewritten: its oldest slot's root, extent and dev
tree addresses now hold blocks of other trees (`owner`, `parent_generation`).

**M5c: the orphan graph** (design fixed 2026-09-21, before implementation). Three pull requests:
M5c-1 joins (this design), M5c-2 log trees (which subvolume a dropped log leaf logged; replay of
the live log), M5c-3 deleted subvolumes (a scenario and its images). btrfs-rec's `rebuild-trees`
is the prior art for reattaching lost branches (research.md §2.5); it repairs a filesystem,
this assembles evidence read-only and says on what grounds.

*What M4 left open.* `recover --orphans` reads each leaf that no root tree leads to on its own:
a file whose items continue in the next leaf stays `partial`, a file whose directory is in
another leaf has no path, and nothing is ever joined. A wrong join makes a file that never
existed, so M4 refused all joins. M5c-1 allows the ones that can be justified, names the
justification on every artifact, and refuses the rest.

*What a survey of the corpus showed first* (2026-09-21, `m4_deep`, one build): of 345 orphan
leaves, 303 are named by the key pointer of a scanned internal node, and 110 internal nodes of
file trees are named by no pointer and no ROOT_ITEM. Most orphan leaves are therefore not alone:
they hang under tree versions whose root was written to disk and replaced before the commit.

*Decisions.*
1. **Three kinds of join, in order of strength.**
   - `pointer`: a scanned internal node names the child by address and generation, the child is
     one level down, its owner fits and its first key is the pointer's key. This is the evidence
     an anchored walk uses. A **fragment** is everything reached this way from a file-tree block
     that no pointer, no ROOT_ITEM and no superblock slot names; it is walked like a tree
     (`fragment:BYTENR@GEN`).
   - `sibling`: a lone leaf ends inside a file (M4's `continues_elsewhere`). Another leaf of the
     same tree continues it when its first key belongs to the same inode and lies above the
     head's last key, head and tail together cover the file exactly (no gap, no overlap, the
     last extent ends at `i_size`, rounded up to a sector for regular extents), no extent item is
     newer than the INODE_ITEM (`generation` ≤ `transid`), and the tail leaf was not written
     before the INODE_ITEM's last change (header generation ≥ `transid`). *The last condition
     was added during implementation, before any measurement:* the same leaf boundary exists in
     dozens of versions of a tree (33 candidate tails for one padding file of `m4_deep`), and an
     older tail of the right size would pass for the file's content when the right one is lost.
     A leaf written at or after the last change holds the file as it was then or later, and a
     later change of content shows as a newer extent or a different cover.
     A chain over several leaves is followed the same way. With NO_HOLES a gap could be a hole, so
     a file with holes is not joined: refused, and said so.
   - `parent_path`: the file's INODE_REF names its parent's inode number. The parent's name is
     taken from the scanned leaves of the same tree only when that number has exactly one name
     there (one creation generation, one (parent, name) pair); a DIR_INDEX of the parent that
     names this file under this name is recorded as confirmation. The chain is followed upward
     to the root directory.
2. **An ambiguous join is refused.** Two candidates that would give different results (two
   tails with different items, two names for the parent number, two creation generations of
   it) mean no join: the artifact stays what M4 made it, and its problems list the candidates.
   Candidates that are byte-identical for the file are one candidate.
3. **Every joined artifact says what was joined and on what evidence.** `source_kind` is
   `orphan_graph`; the new column `artifacts.joined` is a JSON list of joins, each with its kind,
   the blocks involved and the evidence in words; `provenance` names every item as before. A
   fragment's artifacts also say that no ROOT_ITEM names their tree: it is a version written
   within a transaction and replaced before the commit, or one whose root tree is lost, and its
   blocks were written at different moments of that transaction. It was never a committed state.
4. `recover --graph` does this; `--orphans` keeps M4's meaning (lone leaves, never joined), so
   EXP-006 regenerates unchanged. With `--graph`, fragments come after the roots and before the
   remaining lone leaves, and a leaf under a fragment is not read again on its own.
5. Timelines (M5d) use `orphan_graph` artifacts as a third source, marked as such.
6. **Schema version 6:** `artifacts.joined`; the `source_kind` value `orphan_graph`.

*Bounds.* At most 4096 fragments per recovery (newest first); a tail chain of at most 64 leaves;
a parent chain of at most 4096 (as `paths`). A bound that bites is reported in the run summary.

*Definition of done for M5c-1.*
- on `m4_deep` and `m3_wide`, files that `--orphans` leaves `partial` (`continues_elsewhere`) come
  out `complete` with `--graph` where a join is justified, and every such file that an anchored
  root also holds with the same inode, creation generation and `transid` has the same extent
  signature; every `complete` padding file of `m4_deep` has one of the contents the scenario can
  have produced for its name, and every logged file its logged hash;
- files that were unattached gain a path where the parent has one name, and none where it has two;
- forged input: two tails that differ, a tail newer than the head, a tail that overlaps or
  leaves a gap, a parent number with two names, a parent cycle, a fragment whose pointer names a
  block of another owner or first key: each refused or reported, no crash;
- every `orphan_graph` artifact has a non-empty `joined`, and its provenance names only leaves
  the joins list;
- EXP-008 registered before measuring, five builds; README and evidence-db.md document it.

**M5c-1 status 2026-09-21: done** (catalog.md, M5c-1 entry; EXP-008). Each bullet of its
definition of done is a test in `tests/test_graph.py` or a row of EXP-008 §6. Two rules came out
of the experiment's own checks and are now part of recovery for every orphan source: a file with
an extent newer than its INODE_ITEM, or (in a block that was never committed) with data past the
end of the file, is not `complete`. M5c-2 (log trees) and M5c-3 (deleted subvolumes) follow
M5d: timelines are M5's definition of done and need only the joins that exist now.

**M5d: timelines, `btrfska timeline`** (design fixed 2026-09-21, before implementation).

*What it is.* `btrfska timeline DB [--tree ID|all] [--inode N] [--uncommitted] [--json]` reads the
evidence database and says, for every inode of every file tree, what happened to it and when:
create, modify (with the ranges that changed), rename, move, link, unlink, attribute change,
delete. It is claim C3: a *full-state* diff over *every* cataloged state (the current root, the
backup roots, the roots only the scan found) and, on request, over what was never committed
(fragments, lone leaves, dropped log leaves). The comparison points diff sets of inode numbers
between one backup slot and the current tree (SecurityRonin) or over discovered root trees
(Beyond Carving); neither follows an inode through its versions.

*Decisions.*
1. **The database, not the image.** Everything a timeline needs is in the catalog (plan §2, "scan
   once, query forever"), so the command takes the database; M5's definition of done says
   `timeline <image>`, written before the catalog existed. Nothing is stored: a timeline is a
   pure function of the scan's tables, recomputed on demand. When the database also holds a
   recovery, a version carries the SHA-256 of the complete artifact with the same tree, inode,
   creation generation and extent signature.
2. **Identity is (tree, inode number, creation generation), never the number alone.** btrfs
   reuses inode numbers. On `sandbox.img` inode 257 is two files; the prototype reports them as
   one renamed file. A reused number is noted on the later file's `create`.
3. **Versions first, events from versions.** For every state, in generation order, every file
   tree it names is walked in the database (the walk recovery uses) and every inode gives an
   *observation*: names, size, mode, owner, link count, `transid`, times, extents. Consecutive
   equal observations of one identity collapse into a *version* with the states it was seen in.
   Events are the differences between consecutive versions: `create` for the first (its
   transaction is the INODE_ITEM's creation generation, exact); `rename`, `move`, `link`,
   `unlink`, `modify`, `attr` between two versions (transaction: the later version's `transid`;
   several changes between two surviving states show as their net effect, and the event says
   between which states it lies); `delete` when a later state of the same tree, walked without
   a gap, does not hold the identity (bounded by the two states; a walk with gaps gives
   `not_seen`, never `delete`). A subvolume whose ROOT_ITEM disappears gives one
   `subvolume_deleted`, not a delete per file.
4. **Content deltas come from extent comparison, not from reading data.** `modify` lists the byte
   ranges whose extent (address, offset, length, compression; for inline data its hash) differs
   between the two versions, as added, removed or replaced. Whether the bytes at an address are
   still those bytes is recovery's business.
5. **Time.** Generations order events and are trusted as far as the checksummed blocks are. Wall
   clock times are copied from the inode items (`otime` on create, `mtime`/`ctime` of the later
   version otherwise) and labelled as what the filesystem recorded: they are data a user can
   set.
6. **`--uncommitted`** adds observations from fragments, lone leaves and dropped log leaves
   (`recover --graph`'s sources, without sibling joins). They are ordered before the committed
   state of their generation, marked `uncommitted`, and never produce a `delete`: absence from a
   fragment proves nothing. A version with an inode item older than its extent (EXP-008) is
   marked `inconsistent`. An identity seen only there gets `never_committed` (a file written,
   fsynced and deleted within one transaction).
7. **`artifacts.in_current` goes** (schema version 7), as M4b announced: "deleted since" is a
   `delete` event now, with its bounds, instead of a flag computed against one tree.
8. **EXTENT_OWNER_REF (172) is not used.** Simple quotas need `btrfs quota enable --simple` or
   `mkfs.btrfs -O squota`, which arrived with btrfs-progs 6.7; the pinned guest tools are 6.6.3,
   so no corpus image can have them without changing the pin, and an attribution nobody can
   test is not added. The parser and the `extent_backrefs` rows exist (M3).

*Definition of done for M5d.*
- on `sandbox.img` the timeline shows inode 257 as two files (`target_file.txt`, created, then
  deleted; `large_target.txt`, created later under the same number, then deleted), each event
  with the states that bound it, and agrees with the image's known history of generations 11
  to 14; the text rendering is what M5's definition of done calls "renders the sandbox's known
  history";
- on `m4_deep` every logged victim has exactly one `create` and one `delete`, the delete bounded
  by the commit after its deletion, and with a recovery in the database its version carries the
  logged SHA-256; with `--uncommitted` the flash files appear as `never_committed`;
- synthetic trees: rename, move, link and unlink, modify with the changed ranges, attribute
  change, reuse of an inode number, a walk with a gap (`not_seen`), a deleted subvolume;
- hostile input: payloads that do not parse, cycles, hundreds of states: no crash, bounded (the
  catalog bounds the states at 4096);
- README documents the command and every key of its JSON records (the schema tests compare).

**M5d status 2026-09-21: done** (catalog.md, M5d entry). Each bullet of its definition of done is
a test in `tests/test_timeline.py`. One thing the plan did not foresee: two root trees of one
generation can survive (one written in the middle of the transaction, which no superblock ever
named), and generations cannot order them. They are taken by address, the superblock-named one
last, and every event that rests on that order says `order_assumed`.

**M5 status 2026-09-21: the definition of done holds; three items of its scope are open.**
Parts M5a (historical chunk maps, EXP-007), M5b (integrity and linkage), M5c-1 (the orphan graph,
EXP-008) and M5d (timelines), after the prior-art re-run (research.md §11). Bullet by bullet:
- *`btrfska timeline` renders the sandbox's known history.* Inode 257 as two files, each created
  and deleted between states the superblock names, generations 10 to 14
  (`test_sandbox_inode_257_is_two_files_each_created_and_deleted`,
  `test_the_command_renders_that_history_and_its_json_has_the_documented_keys`). The command
  takes the evidence database, not the image (M5d, decision 1). On `m4_deep`, 21 of 24 victims
  have one `create` and one `delete` and the logged SHA-256; the other three have no surviving
  state (EXP-006); all 8 flash files are `never_committed`.
- *`s01` yields a reconstructed historical chunk map and correctly-translated outside-map
  orphans.* Ten historical maps on `s01_discard_none_r1`; every valid block outside the current
  map is placed by the map of its own time; 81 of 81 file versions that the current map cannot
  read come out complete and hash-exact (EXP-007, N = 5 per discard mode;
  `tests/test_chunkmaps.py`).
- The other items of M5's list: orphan graph (M5c-1, with btrfs-rec cited as prior art in the
  plan and the code); full-state, multi-source timelines with content deltas (M5d); integrity and
  linkage (M5b); **simple-quota attribution: not done**, because the pinned guest tools
  (btrfs-progs 6.6.3) cannot make a filesystem with simple quotas, so nothing could test it
  (M5d, decision 8).
- **Open, and moved to a follow-up (M5e) instead of being claimed:**
  - *replay of the live log tree in recovery* (**done since: M5e-1, 2026-09-22**). The timeline reads log trees, live and dropped,
    and files each under the subvolume its log root names; `recover` still leaves the live log
    alone and reads dropped log leaves without saying which subvolume they logged. `m2_logtree`
    has the ground truth for it (two fsynced files and one appended file, hashes logged).
  - *deleted-subvolume recovery as a tested feature.* A subvolume tree that no ROOT_ITEM names is
    a fragment for `recover --graph`, and a subvolume that a later state no longer names gives
    `subvolume_deleted` in the timeline, but no corpus image deletes a subvolume, so neither was
    exercised on a real one. It needs a scenario and, as for `m4_deep_lost_parent`, a mutated
    variant whose root-tree leaves are gone.
  - *the comparison with btrfscue v0.7.* Its release ships one binary, for arm64, and the source;
    the hosts are x86-64. Pinning it means pinning a Go toolchain and its module downloads, which
    belongs with the baseline builds of M7.

**M5e-1: log trees in recovery** (design fixed 2026-09-21, before implementation; the first of
the items M5's status left open).

*What it is.* `recover --logs` reads every log tree the scan found, live or dropped, through the
log root tree that names it, and replays it over the state it was written against.
1. **Which subvolume.** A log root tree (owner -6) holds one ROOT_ITEM per logged subvolume: key
   objectid -6, key offset = the subvolume's id, naming that subvolume's log tree. That is a
   `pointer` join like any other, and it answers M4d's "a log leaf does not say which subvolume it
   logged". Artifacts get `source` `log:BYTENR@GEN`, `source_kind` `log_tree`, the subvolume as
   `tree_id`, and the join (`log_root`) in `joined`. Output goes to
   `DIR/log_trees/subvol_ID/log_BYTENR_genG/`.
2. **Replay, read-only, as the kernel would at mount** (tree-log.c `replay_one_extent`,
   `replay_one_buffer`): a logged extent replaces whatever the base tree holds in its range (a
   base extent that is only partly covered keeps its other part, with offset and length
   adjusted); the logged INODE_ITEM gives the size; nothing past the sector of the new end is
   kept. The base is the subvolume tree of the newest cataloged state older than the log, and
   only an inode with the same creation generation is a base. The join (`log_replay`) names the
   base state. An INODE_ITEM logged with generation 0 (the kernel's "exists only" mode) carries
   no content and is recorded, not written.
3. **In a log tree a range without an extent item is not a hole.** A fast fsync logs only what
   changed. Without a base, such a range is `not_logged` and the file is `partial`; M4d's lone log
   leaves get the same rule (they were read with NO_HOLES semantics, which would have passed an
   appended file off as complete with zeros in front).

*Definition of done.* On `m2_logtree`: `sv1/fsynced.txt` (new, fsynced, never committed) and
`sv1/committed.txt` (committed, then appended and fsynced) come out complete with the SHA-256 the
guest logged, the second through a replay over the current state; without its base the second
is `partial` with `not_logged`. On `m4_deep` the flash files come out under the subvolume their
log root names, hash-exact. Synthetic: overlay at the front, in the middle and at the end of a
base extent, over an inline base, a log that shrinks the file, a reused inode number (no base),
generation 0. README and evidence-db.md document it.

**M5e-1 status 2026-09-22: done** (catalog.md, M5e-1 entry; `tests/test_logs.py`). Of the three
items M5's status left open, two remain: deleted-subvolume recovery on a real image, and the
btrfscue comparison.

**M5e-2: a deleted subvolume on a real image** (design fixed 2026-09-22, before implementation;
the second item M5's status left open).

*What it is.* No new recovery code is expected: a subvolume whose ROOT_ITEM an older root tree
still holds is recovered from that state (`recover --root all --tree all`, M4b); one that no
ROOT_ITEM names any more is a fragment or a lone leaf for `recover --graph` (M5c-1); the timeline
reports `subvolume_deleted` (M5d). None of it was ever run on a deleted subvolume, because the
corpus has none. This adds the images and the tests, and fixes what they find.
- **Scenario `delsubvol`** (`m5_delsubvol`): two subvolumes; the doomed one gets a directory,
  one regular and one inline file whose SHA-256 the guest logs, and 300 small files so that its
  tree has a second level; commit; `btrfs subvolume delete`, `btrfs subvolume sync` (the cleaner
  drops the tree and removes the ROOT_ITEM); three more commits of small writes in the other
  subvolume; unmount.
- **`m5_delsubvol_lost_items`**, made by `corpus/mutate.py lose-root-items TREE`: every physical
  copy of every root-tree leaf that holds a ROOT_ITEM of that tree is broken, as
  `m4_deep_lost_parent` loses a node. Then no root tree names the subvolume, in any generation,
  and only its own blocks can give it back. A natural history is unlikely to produce this (a
  tree's blocks and its root-tree leaf are allocated side by side, EXP-006), so it is made.
- Both rows go into `corpus/manifest.tsv`; the corpus scripts change, so a fresh clone runs
  `./setup.sh`.

*Definition of done.* On `m5_delsubvol`: the current state does not name the doomed tree, an
older state does, the two logged files come back hash-exact from such a state, and the timeline
has one `subvolume_deleted` for that tree, bounded by two states, and no per-file `delete` in
it. On `m5_delsubvol_lost_items`: no scanned ROOT_ITEM names the tree; `recover --root all --tree
all` gives none of its files; `recover --graph` gives both logged files hash-exact, as
`orphan_graph`, with the doomed tree's id and their paths. Tests assert this relative to the
images and their log. Whatever does not hold is reported as a finding, not tuned away.

### M6 — Confidence, validation, hiding detection (~1–2 weeks)
- EXTENT_CSUM (0x80) verification of recovered content where the csum tree
  (current or historical) survives.
- FST forensics: parse FREE_SPACE_INFO/EXTENT/BITMAP (item keys 198–200,
  0xC6–0xC8; kernel v7.0 `include/uapi/linux/btrfs_tree.h:266,272,280`); classify
  every recovered extent as free/allocated-now; overwrite-risk score that
  includes the image's discard mode as observed (§6.2 discard axis).
- Confidence tiers (Confirmed/Probable/Unattached) computed from explicit,
  documented evidence rules:
  - validation record (M1);
  - anchored path;
  - csum-tree match;
  - gen/owner consistency;
  - backref agreement.

  Every reported artifact carries its provenance chain.
- Hiding detection: the research.md §8.3 target list (reserved regions,
  SB/chunk-array slack, STRING_ITEM 0xFD, ns-timestamp anomalies, inode
  reserved bytes) with correct reserved-range definitions (fixes defect #3
  into a feature). **The reserved ranges are derived from the feature flags,
  not taken as constants** (research.md §10.13): the published superblock
  range, 0xF0 bytes at 0x23B, is a pre-5.0 layout; at v7.0 only 0x264–0x32A is
  reserved, and `metadata_uuid`, `nr_global_roots` and the `remap_root` fields
  are anomalies only when non-zero without their feature flag. Also detect
  backup-root divergence (cite SecurityRonin). Target list per Toolan &
  Humphries FSI:DI 58:302198. Validate against images generated with
  **fishy**'s btrfs module.
- Foreign-FSID discovery (optional scan mode, from the M2a review). The M2
  prefilter matches only the current fsid or metadata_uuid, so tree blocks of
  a previous filesystem on the device, or written before `btrfstune -m`/`-u`,
  are never candidates. The mode counts header fsids across the scanned
  regions, validates blocks of every recurring foreign fsid with that fsid's
  own context, and feeds the result to the foreign-superblock finding (M1's
  `foreign` superblock copies), so a reformat or an fsid change is reported
  with its surviving metadata.
- **DoD:**
  - every artifact in the report has tier + provenance;
  - the detector finds ≥ the fishy-plantable techniques on generated images;
  - false-positive rate measured on clean corpus images (EXP record).

### M7 — Evaluation & corpus (~2 weeks, overlaps paper writing)
- Corpus generator = `corpus/vm/` scaled up (already in use since M1):
  scenario scripts × matrix below, per-image manifest (per-file SHA-256,
  operation log, guest kernel, host mkfs version, mkfs args, mount options,
  discard mode), before/after pairs.
- **Matrix axes:**
  - sizes {512 MiB, 8 GiB, 100 GiB (scheduled job)};
  - operations {simple delete, overwrite, create/delete stress,
    snapshot+delete, balance, defrag, beyond-4-generations};
  - compression {none, zstd, lzo, zlib};
  - csum {crc32c, xxhash, sha256, blake2b};
  - **block-group tree {off (`-O ^block-group-tree`), on}**, required
    because host mkfs 6.6.3 defaults off and progs ≥ 6.19 default on;
  - **discard {none: no virtio unmap; async quick-unmount: `DISCARD=1`;
    async idle: `DISCARD=1` + ≥ 130 s idle before unmount; sync:
    `discard=sync`}** plus a `nodiscard` mount-option control row;
  - **reclaim {off: kernel default, `bg_reclaim_threshold` 0 and dynamic/
    periodic reclaim off; on: enabled inside the guest through the per-fs
    `allocation/data/` sysfs knobs before the churn phase}** (research.md
    §10.3, §10.6 item 3). Exact knob names are confirmed against v7.0
    `fs/btrfs/sysfs.c` when the scenario is written. Reclaim is automatic
    relocation, so it is the unattended counterpart of the explicit
    `balance` operation;
  - MIXED_GROUPS small fs;
  - multi-device RAID1.

  Use a full factorial only where the axis interacts with recovery
  (discard × operation; BGT × balance; reclaim × discard, because a
  reclaimed, now-unused block group becomes async-discard-eligible after
  10 s); otherwise one-factor-at-a-time from
  a base configuration.
- **btrfs-specific recoverability axes** (Bhat & Wani 2018, research.md
  §4.6):
  - file-size bands **<1 KiB / 1–2 KiB / 2–4 KiB / >4 KiB**;
  - **merge- vs redistribution-forcing** deletion patterns;
  - **filesystem aging** (fresh vs aged);
  - inline vs regular vs multi-extent layout.

  Report recovery rate per band to validate/refute their heuristics on
  kernel 7.0.
- **Beyond-4-generations test** (redesigned 2026-09-15; research.md §10.12):
  delete a file, then force > 4 commits so its last state falls outside the 4
  backup roots. Variants separate two cases, and every recovered file is
  labelled by source (backup root, discovered state inside the current map,
  state outside it, unreferenced node, orphan item):
  - **(a) reachable by scanning the current chunk map.** No balance or
    reclaim after the deletion, so the old root-tree block and the trees it
    names lie in ranges the current chunk map places. A Beyond Carving-style
    scan (Algorithm 3, reimplemented and labelled as such) and
    `btrfs-find-root` + `restore` can find it; backup-root-bounded tools
    (SecurityRonin `recover_deleted`, `btrfs restore` without find-root)
    should miss it. Expected result for us: parity, not novelty.
  - **(b) only outside the current chunk map, or only from unreferenced
    blocks.** A balance or reclaim relocates the chunks after the deletion,
    or the old root-tree block is overwritten while the leaves naming the
    file survive unreferenced. Only unmapped-gap (and full-sweep DATA)
    scanning with historical chunk maps, or orphan-node and orphan-item
    recovery, reaches it. This is the differentiator.
- **Baseline harness** (scripted; each tool run read-only on a copy under
  `images/`, pinned version recorded):
  - `btrfs restore` (+find-root) from btrfs-progs ≥ 7.1, built rootless
    into `images/tools/`;
  - undelete-btrfs v1.0;
  - PhotoRec;
  - btrfscue v0.7 `recover`;
  - **`SecurityRonin/btrfs-forensic` `recover_deleted`** (pinned crate
    version);
  - **TSK `develop` build** (experimental btrfs, pinned commit);
  - FKIE-TSK `tsk_recover -e`;
  - btrForensics;
  - commercial (UFS Explorer/R-Studio) if licensed.
- Metrics: recovery rate, SHA-256 exact-match accuracy, metadata recovery
  rate (name/times/mode), runtime; per scenario, with repetition count and
  spread (§7). Per tool, report three counts, as ExtSFR does: files produced,
  hash-exact, name recovered (a carver can produce more files than were
  deleted). For timelines, also report the share of all file *states* in the
  ground truth that are recovered, as Plum & Dewald 2018 do; this needs the
  scenario log to record every state, not only the final one (research.md
  §10.13).
- Publish corpus (Zenodo DOI) — contribution C7.
- **DoD:** one command regenerates corpus + all baseline numbers + our
  numbers into the paper's tables.

### M8 — Rust scan core + product polish (Track P, after paper submission)
- `rust/scan-core`: memmap2 + rayon + crc32c/crc-fast + zerocopy structs
  (seed layouts from `btrfs-diskformat`); PyO3 module via maturin; numpy
  path stays as fallback; abi3 wheels in CI.
- Perf table (Python fallback vs Rust) — goes into the tool paper/README.
- Later/optional: standalone Rust CLI, degraded-RAID reads, log-tree (G9).

### M9 — Local web GUI (Track P, after the CLI is solid)

**Entry criteria:**
- M6 done;
- catalog `schema_version` unchanged for ≥ 4 weeks;
- CLI JSON outputs documented.

**Recommendation: a read-only local web UI served by the CLI** (`btrfska
serve evidence.db`, bound to 127.0.0.1, random port, token in URL), built
with **Starlette + Jinja2 templates + htmx**:
- Python only, a few small deps;
- no JS build step;
- reads `evidence.db` via `sqlite3` `mode=ro` URIs;
- never touches the image except through the same read-only substrate for
  on-demand hex views.

Views:
- **Overview:** scan run, chain-of-custody hashes, gate verdict.
- **Artifacts:** a filterable table (tier, source, generation, path)
  → artifact detail with provenance chain and csum status.
- **Timeline:** per-inode lifecycle.
- **Node inspector:** hex + parsed items, beyond-`nritems` highlighted.
- **Findings:** hiding findings.
- **Export:** buttons that call the same report code as the CLI.

**Alternatives rejected:**
- Datasette — a generic table browser, fine for ad-hoc SQL (keep as a
  documented dev tip), but no provenance-chain or timeline views;
- Qt/PySide desktop app — packaging weight and a second UI toolkit for one
  maintainer;
- Tauri/Electron — a JS/Rust build chain and no reuse of the Python
  analysis code.

**DoD:**
- every CLI report view is reachable in the UI with identical numbers
  (snapshot test comparing UI JSON endpoints to CLI JSON);
- the UI never opens the image or DB writable (test);
- works offline, with no external assets.

### Later research items (not scheduled; revisit after M5)
- **Remap tree** (kernel 7.0, experimental, incompat `1<<17`, tree 13, keys
  234–236; research.md §10.3): parse REMAP/REMAP_BACKREF/IDENTITY_REMAP and
  zero-stripe chunk items; treat stale owner-13 leaves as a relocation log
  (C6, presented as experimental). Until then the M1 gate refuses such
  images.
- **RAID stripe tree** (6.7, experimental, incompat `1<<14`, tree 12, key
  230): stale RST leaves as physical-placement evidence. Gate-refused until
  then.
- **Experimental guest kernel** (`CONFIG_BTRFS_EXPERIMENTAL=y`, self-built,
  rootless, output under `images/`) needed to generate remap-tree/RST
  images: **deferred**. Decide when one of the two items above is picked up.
  It is not needed for paper 1.
- Log-tree (G9) forensics.

---

## 6. Testing Strategy

### 6.1 Test policy

- **Primary regression image:** the repo-root `sandbox.img` (268 435 456
  bytes, crc32c, generation 14, compat_ro 0xb incl. block-group tree,
  sha256 `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`).
  It is **read-only and never mutated**:
  - opened only via `substrate/image.py` (`O_RDONLY`, `ACCESS_READ`);
  - a session-level test asserts its sha256 before and after every run;
  - no tool, test or experiment ever writes, mounts, repairs or `touch`es
    it.

  Golden numbers: 71 orphans / 21 outside map / backup gens 11–14.
- **Extra images are generated only inside the repo under the gitignored
  `images/` tree, via `corpus/vm/`:**
  - `images/scenarios/` — images and logs;
  - `images/vm/` — QEMU, kernel, initramfs;
  - `images/tools/` — baseline tool builds;
  - `images/scratch/` — test outputs, mutated copies;
  - `images/mnt/` — reserved, unused rootless.

  Mutated images (corrupt node, injected flags) are produced by committed
  scripts from generated images, into new files under `images/`.
- **Nothing is created outside the repo folder:** no `/tmp`, no `$HOME`
  caches for images, no system mounts. Tests use `images/scratch/` instead
  of `tmp_path` whenever they write image-like data, and `tmp_path` only for
  tiny non-image files.
- CI may reconstruct `sandbox.img` at the repo-root path from the tracked
  `tests/fixtures/sandbox.img.zst` (hash-checked); that is a restored copy
  of the primary image, not an extra image.
- Markers: `sandbox` (needs `sandbox.img`), `vm` (needs the images of
  `corpus/manifest.tsv`, built by `corpus/build.py`). Since 2026-09-21 the CI
  job `corpus` builds them with `./setup.sh` on a clean runner and runs the
  `vm` tests; the full M7 matrix stays a scheduled job.
- **Local pre-merge gate** (every PR, recorded in the catalog): `uv run
  pytest` with `sandbox.img` present and the `vm` images of the milestone
  regenerated, + `sha256sum sandbox.img`.

### 6.2 Corpus from M0/M1 onward

- `corpus/vm/` (rootless QEMU/KVM, stock 7.0.0-31 guest; research.md §10.4)
  is the only image generator. M0 lints it in CI (`ruff` for its Python,
  `sh -n` for its shell scripts) and documents a local smoke command; image
  generation starts in M1, which uses it for csum-type, BGT, compression,
  corrupted and mirror-damage images; M2 uses the discard trio; M4 the beyond-4-generations
  image; M5 the balance image; M7 scales it to the full matrix.
- Every generated image gets a `corpus/manifest.tsv` row (name, command,
  mkfs version, guest kernel, note); tests reference images by name and skip
  when absent. The manifest is a recipe and holds no image hash (revised
  2026-09-21): every mkfs draws a new filesystem UUID, so no build of a row
  can be repeated byte for byte. `corpus/build.py` builds every row in one
  command and records the hashes of what it built in the gitignored
  `images/scenarios/SHA256SUMS`; the `vm` tests compare the local images with
  that record. An EXP record still cites the sha256 of the instances it
  measured, as evidence of what was measured, not as something to rebuild.
- **Reproducibility target:** a fresh clone reaches a complete, tested
  checkout with `./setup.sh` in a few minutes, on any Linux distribution
  with KVM and QEMU. Every new scenario, baseline tool or guest package must
  keep that true: pinned by hash, fetched by URL, no root, nothing outside
  `images/`.
- **Discard axis** (none/async/sync) and **block-group-tree axis** (off/on)
  are in the matrix from their first use (M2 and M1 respectively), not only
  in M7.
- `mkfs --rootdir` images: parser fixtures only (fresh fs, host `st_ino`
  objectids), never deletion scenarios.

### 6.3 Other test layers

- **Differential testing** (oracles are dev-only, never runtime):
  - our anchored listings vs `btrfs inspect-internal dump-tree` on healthy
    images;
  - our file bytes vs dissect.btrfs streams and guest-printed SHA-256s;
  - our LZO1X decoder vs `lzallright` (M1 task 8).

  Oracle tests live in `tests/oracle/` and skip when the dev group is not
  installed.
- **Property tests** on parsers: random valid+corrupt nodes must never
  crash (adversarial-input safety, also a paper claim).
- CI runs the full suite on small images; 100 GiB and full-matrix scenarios
  run in a scheduled/manual job.

## 7. Research Method (experiment protocol)

Every measured result is an **experiment** with a paper-ready record.

**Record location.** `experiments/EXP-NNN.md` (three-digit, never reused).
Commit the regeneration script alongside it as `experiments/EXP-NNN.sh` or
`.py`; raw outputs go to `images/scratch/exp/EXP-NNN/` (gitignored). The
catalog.md entry for the work that ran the experiment links to the EXP id
and copies its headline numbers.

**Template** (sections in this order):
1. **Hypothesis** — one falsifiable sentence, e.g. "`discard=sync` removes
   ≥ 80 % of stale metadata blocks after scenario s01".
2. **Method** — procedure, metric definitions, what counts as success.
3. **Image / scenario** — `corpus/manifest.tsv` row(s): generator command,
   guest kernel, host mkfs version, csum, features, mount/discard options,
   image sha256.
4. **Environment record**, pasted verbatim from a committed
   `experiments/env.sh` (added with EXP-000):
   - host CPU model/cores, RAM, and the storage device and filesystem
     backing `images/`;
   - host kernel (`uname -r`);
   - QEMU version;
   - guest kernel;
   - btrfs-progs version (host mkfs and guest `btrfs --version`);
   - Python version and `uv.lock` sha256;
   - tool git commit, with a dirty-tree flag;
   - image sha256 before and after.
5. **Exact command** — copy-pasteable, from repo root.
6. **Result numbers** — a table with N repetitions giving, for each reported
   column, the median and the range (min–max). State N.
7. **Threats to validity** — internal (timing jitter, host caching,
   single-image effects), external (stock kernel, virtio vs real SSD/HDD,
   image size), construct (does the metric measure recoverability?).
8. **Status** — supports / refutes / inconclusive; follow-ups.

**Reproducibility rule.** A number may enter the paper **only if a committed
script regenerates it** from a committed or generated image. Guest-driven
scenarios are not bit-stable. Two runs of the research.md §10.4 "no discard" row gave
367/355/18/832 and 365/353/16/828: a difference of 2 in columns 1–3 and of 4
in column 4. The spread differs per column, so no single "± N blocks" figure
is used. Rules:
- run every guest-driven measurement ≥ 5 times;
- report, per column, the median and the range (min–max);
- set any DoD or test tolerance from the measured per-column range of those
  runs (recorded in the EXP record), never from a fixed number;
- claim effects at the resolution the spread supports;
- never quote a single run as a constant.

Pure-parse results on a fixed image (e.g. sandbox 71/21) are deterministic
and need one run plus the image hash.

**Backfill.** EXP-000 = the research.md §10.4 discard table: re-run
`corpus/vm/discard_table.sh` ×5 and record it under this template during M2. **Done 2026-09-15**
(`experiments/EXP-000.md`, N = 15): the medians equal the §10.4 table; the "none" row varied in
one run of 15 (365/353/18/828), the async and sync rows never.

## 8. Paper Plan

- **Primary target:** DFRWS EU/USA (FSI:DI) — the natural venue for this
  literature (deadline check needed); fallback IEEE Access (where Beyond
  Carving landed; fast OA). DFRWS APAC 2026 (19–22 Oct) accepted papers
  were checked on 2026-09-21: no file-system paper (research.md §11.1).
- **Paper 1 (tool + method):** "filesystem-state archaeology" — C1, C3, C4,
  C6 + evaluation vs the full baseline set on the released corpus (C7).
  - Structure maps to milestones: background/format (existing docs),
    method = layers 1–5 (validation layer included), evaluation = M7 +
    EXP records, related work = research.md §2/§4/§10.1–§10.2.
  - Positioning paragraph, three-way:
    - Beyond Carving answers *"what was deleted?"* from historical root trees
      it finds by scanning the regions the current chunk map places
      (research.md §10.12);
    - SecurityRonin audits a volume and diffs the FS tree of each of the four
      backup slots against the current one;
    - we answer *"what happened, from every surviving source, how
      confidently?"*. Our recovery source set strictly contains both.
  - CoW analogs (ReFS: Prade 2020, Bonnet/`forefst` 2026; F2FS: Oh & Hwang
    2025) cited as the same idea on other filesystems.
  - Remap-tree support presented as forward-looking/experimental.
- **Possible paper 2 (spin-off):** hiding detection + FST forensics
  (C2, C5) evaluated against fishy/ForTrace-generated anti-forensic images
  — cite Toolan & Humphries **FSI:DI 58:302198 (2026)** (not the SSRN
  preprint) and `fkie-cad/mind-the-slack`.
- **Artifact:** `uvx` installable tool + Zenodo corpus + EXP scripts that
  regenerate every table/figure.
- Re-run the prior-art watch (research.md §9) before M5 starts and before
  submission. **Done before M5 on 2026-09-21** (research.md §11): nothing found
  changes C3 or C6. Still to do before submission.
- **Deadline found by that re-run:** DFRWS EU is now the Digital Forensics
  Conference Europe 2027 (Edinburgh, 30 March to 2 April 2027); full papers are
  due **9 October 2026** (abstract 2 October; 10 pages, double-blind). Whether
  paper 1 aims for it is the maintainer's decision; the milestones do not
  assume it.

### Paper-readiness experiments (2026-09-15, from the paper-draft review)

- **E-findroot: done 2026-09-21 as EXP-004.** find-root enumerates the metadata
  block groups of the current chunk map, so it printed every state inside the
  map (229 of 229 on 13 images) and none outside it (0 of 133). Old-root
  discovery is claimed **outside the current chunk map only**. The plan as
  written: `btrfs-find-root -a` per
  generation against `btrfska roots --json --full-sweep` on the existing
  images (a copy of `sandbox.img`, the `m1_*` images, `m2_logtree`, the three
  `s01_discard_*_r1`). Split every generation by whether its root-tree block
  is placed by the current chunk map. It settles whether old-root discovery
  is new for any generation or only outside the current chunk map. Read
  find-root's scan range in the btrfs-progs source and register the
  prediction first (`paper-draft.md` §10).
- **Minimum experiment set for paper 1** (EXP records, ≥ 5 regenerations
  where a guest runs; details in `paper-draft.md` §10):
  - E-rec: file-level recovery per source, on no-balance, aged and ≥ 8 GiB
    images;
  - E-beyond4: the redesigned M7 test, cases (a) and (b);
  - E-baseline: every M7 baseline on the same images, with runtimes and peak
    memory;
  - E-discard: discard × operation with `nodiscard`, async-idle and a real SSD
    with discard passed through;
  - E-fp: discovery false-positive rate on forged images;
  - E-raid: RAID1, RAID1C3, RAID10 and RAID5/6 profiles;
  - E-csum; E-tiers (if C4 is claimed); E-perf; E-robust.
- **Corpus statement.** Every record and the paper state the corpus size
  (images per cell and in total, sizes, regenerations) and point to each
  image's operations log in the manifest.

## 9. Risks

| Risk | Mitigation |
|---|---|
| **Realised:** a Rust forensic library (`SecurityRonin/btrfs-forensic`) ships backup-root deletion diffing and graded findings | Claims C3/C4 re-worded (§1); move M5 early; benchmark it (M7); keep C1/C6 btrfs-specific |
| Beyond Carving team ships their future work first (code repo created, still empty) | M4/M5 prototyped; watch repo; publish corpus fast (C7: no comparable image corpus found, research.md §5.1) |
| Our own parsing, extent-read or LZO/stream code has bugs a mature library would not | Differential tests vs `dump-tree`, dissect.btrfs streams, `lzallright` and guest SHA-256s; property tests on hostile input; csum-type and compression images from M1; §3.5 fallback ladder (lzallright at runtime, then dissect.btrfs at runtime with an AGPL relicence) |
| dissect.btrfs (test oracle) drifts or is abandoned | Pinned `1.10.*` in the `dev` group; guest SHA-256s and `dump-tree` are independent oracles, so losing it costs one cross-check, not a runtime feature |
| Decoding "succeeds" on corrupted compressed data (LZO has no integrity check: 218–231 of 300 bit-flipped 4 KiB streams per seed decoded to wrong bytes in btrfska, lzallright and dissect.util native, §3.5) | Decode success never raises confidence; content is Confirmed only by a data-checksum match (M6); decoder errors are recorded, not hidden |
| Licence ambiguity from test-only AGPL use | Oracle confined to the `dev` group and `tests/oracle/`; import-boundary test on `src/`; sdist contents checked before release (§3.3) |
| New format features mis-read (remap tree, RST, fscrypt) | Incompat gate refuses unknown/unsupported bits (M1); later research items |
| Discard destroys evidence on real media (sync: ~91 % stale metadata gone) | Discard axis in corpus + observed-discard input to overwrite-risk score and report caveat |
| Scan performance disappoints on real HDD images | Kernel interface frozen — Rust core can be pulled forward |
| Ambiguity explosion in orphan graph on real-world images | Confidence tiers are the *product* of ambiguity; cap reconstruction depth, report Unattached honestly |
| Guest-scenario jitter undermines numbers | §7 repetition + spread rule; deterministic claims only from fixed images |
| Corpus not representative (stock 7.0 guest, virtio) | Mirror Kim et al. methodology + btrfs axes; state as threat to validity; DFRWS artifact review feedback |
| `sandbox.img` not tracked in git → CI blind to golden numbers | Resolved: the ~15 KB `.zst` fixture is tracked (M0 task 9) and hash-checked in CI, plus the local pre-merge gate |
| Single maintainer bandwidth | Track R before Track P; GUI only after CLI stabilises; every milestone independently shippable |

## 10. Working Conventions

The working rules moved to [`CONTRIBUTING.md`](../CONTRIBUTING.md) on
2026-09-21 and are maintained there: one feature per branch and pull request
with a catalog entry, plan then implement then test, the definition of done,
the read-only guarantee, the image rule, the reproducibility target
(`./setup.sh` from a fresh clone), the experiment protocol of §7, and cost.
