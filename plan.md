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
| C1. **Btrfs** orphan-item & slack archaeology as a recovery source (beyond-`nritems` items, node slack, kernel ORPHAN_ITEM 0x30 resurrection) | G1 | Beyond Carving scans whole valid blocks only — deep leaf scanning is *their stated future work*; SecurityRonin only *lists* kernel ORPHAN_ITEMs. Node-slack recovery exists for **ReFS** (`forefst`, Bonnet 2026; Prade et al. 2020) — cited as the CoW analog, not claimed |
| C2. Free-space-tree forensics: prove blocks were freed; overwrite-risk scoring | G2 | Zero tools, zero papers (re-swept 2026-09-15) |
| C3. **Full-state, multi-source, per-inode lifecycle timelines**: diffs across backup roots *and* scan-discovered old roots *and* reconstructed orphan fragments → create/modify/rename/move/delete with content deltas | G3 | Beyond Carving diffs objectid *sets* over backup roots; SecurityRonin `recover_deleted()` diffs one backup FS_TREE against the current one. Both are existence-only and backup-root-bounded (≤ 4 generations); "diffing generations" per se is **not** claimed |
| C4. **Evidence-rule-derived confidence tiers** (Confirmed/Probable/Unattached) with a per-artifact provenance chain spanning anchored *and* unanchored artifacts, csum-tree-verified content | G4 | SecurityRonin has severity grades (no provenance, no evidence rules); Beyond Carving has an extent-resolvability taxonomy for anchored recoveries only; `forefst` has ReFS recoverability verdicts; X-Ways has a binary flag. None scores unanchored orphan/slack artifacts or records cross-mode provenance |
| C5. Hiding detection targeting the Toolan & Humphries (FSI:DI 58:302198, 2026) + Schwietert & Hilgert technique lists, evaluated against fishy-generated images | G5 | Papers propose hiding; nobody ships a detector for those techniques. SecurityRonin's `BACKUP-ROOT-DIVERGENCE` and CRC-mismatch findings are a tamper-detection slice → cited |
| C6. **Btrfs** orphaned/relocated-chunk forensics + historical chunk-map reconstruction; on remap-tree images, the stale remap tree as an explicit relocation log (experimental) | G6 | Our sandbox discovery (21/71 orphans outside chunk map); Beyond Carving future work. F2FS address-table rebuild (Oh & Hwang 2025) is the cited analog |
| C7. First public btrfs deleted-file benchmark corpus (incl. discard and block-group-tree axes) + systematic tool benchmark | G8 | None exists (no btrfs at digitalcorpora/CFReDS; hide-and-seek dataset still offline) |

**Not building (exists elsewhere; reuse or benchmark instead):**
- compression algorithms (stdlib `zlib` and `compression.zstd`; only the
  small LZO1X decoder is ours, §3.5) and a second general-purpose btrfs
  reader (dissect.btrfs serves as a test oracle, not a dependency);
- old-root salvage (`btrfs restore`/find-root) and backup-root deleted-file
  diffing (Beyond Carving, `SecurityRonin/btrfs-forensic`);
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
  at most `lzo1x_worst_compress(sectorsize)` bytes (4 419 for 4 KiB) that
  decompresses to at most one sector;
- a segment header never straddles a sector boundary: if fewer than 4 bytes
  remain in the current sector, they are zero padding and the next header
  starts at the next sector;
- inline extents use the same header with a single segment.

**LZO1X decoder options** (evaluated 2026-09-15):

| Option | Licence / state | Behaviour on hostile input (test below) | Verdict |
|---|---|---|---|
| `python-lzo` 1.15 | GPL | — | Rejected: GPL, incompatible with the Apache-2.0 decision |
| `dissect.util` 3.24 `compression.lzo` (pure Python + Rust `_native`) | Apache-2.0, Fox-IT, maintained; the decoder dissect.btrfs uses | Pure Python: a back-reference before the start of output is silently accepted (the crafted stream returned 4 bytes, no error), and only `len == out_len` stops output. Native: **panics** (`pyo3_runtime.PanicException`, not an `Exception` subclass, so `except Exception` does not catch it) on the crafted stream and on 58/300 bit-flipped streams (single seeded run; counts are seed-dependent — the harness is committed in M1 as `tests/oracle/lzo_hostile.py` before any number is cited) | Rejected at runtime: a forensic reader must fail with a catchable, classified error on adversarial bytes. Its Apache-2.0 test vectors are reused, with attribution |
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

**Also observed** (single seeded run, see above): 139–160 of the 300 bit-flipped streams decoded
"successfully" to wrong bytes in *every* decoder. LZO carries no integrity
check, so decode success is never evidence of correct content; only data
checksums (csum tree, M6) are.

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
| `utils/btree.py` — orphan-item scan (beyond `nritems`), internal key-ptr scan, leaf/internal slack mining | ~400 of 968 | **MIGRATE** | **The crown jewels** — the capability Beyond Carving dismisses as an "edge case" and SecurityRonin lacks. Port to `recover/orphans.py` + `recover/slack.py`, golden-tested against legacy output. |
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
  tip `1e9984e`; the branch is kept.

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

### M3 — Evidence catalog (~1 week)
- SQLite schema (versioned, documented in-repo):
  - `nodes(bytenr, phys, dev, gen, owner, level, nritems, csum_type,
    csum_ok, header_checks, discovery, …)`
  - `tree_edges(parent, slot, child, key…)`
  - `items(node, slot, key, raw, parsed_kind, beyond_nritems)`
  - `roots`
  - `chunks(map_id, source=current|historical|remap, …)`
  - `extent_backrefs` (incl. EXTENT_OWNER_REF 172)
  - `inodes`, `dir_entries`, `file_extents`
  - `artifacts(path, sha256, source, confidence…)`
  - `provenance(subject, evidence, method)`
  - `scan_runs` (image sha256, tool version, params, gate verdict — chain
    of custody)
- Reverse queries: parents-of(bytenr), owners-of(extent), trees-covering
  (key), items-in-generation(g).
- The schema is the contract M9's GUI reads; changes bump `schema_version`.
- **DoD:** one scan of sandbox populates `evidence.db`; all M1/M2 outputs
  flow through it; reverse queries answered without re-reading the image.

### M4 — Recovery engines (~1–2 weeks)
- Anchored recovery: extract files from any cataloged root via
  `substrate/extents.py` (compression handled), `-m`-style metadata, xattrs (0x18),
  INODE_EXTREF (0x0D); `FT_ENCRYPTED` 0x80 masked; encrypted extents
  refused with a report line.
- Archaeology port: beyond-`nritems` orphan items (leaf + internal),
  node-slack residual mining, kernel ORPHAN_ITEM (0x30) resurrection —
  golden-tested against legacy outputs (with defect #8 corrected).
- Cross-generation dedup of recovered content (by extent tuple + sha256).
- **DoD:**
  - migration-done criterion (§4.3) met;
  - deleted files recoverable from (a) anchored historical roots,
    (b) orphan nodes and (c) orphan items, each labeled with its source;
  - on the beyond-4-generations image (§6.2) (b)/(c) recover a file that
    (a) cannot.

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

### M6 — Confidence, validation, hiding detection (~1–2 weeks)
- EXTENT_CSUM (0x80) verification of recovered content where the csum tree
  (current or historical) survives.
- FST forensics: parse FREE_SPACE_INFO/EXTENT/BITMAP (0xDD–0xDF); classify
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
  into a feature), plus backup-root divergence (cite SecurityRonin). Target
  list per Toolan & Humphries FSI:DI 58:302198. Validate against images
  generated with **fishy**'s btrfs module.
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
- **Beyond-4-generations test:** delete a file, then force >4 commits so it
  falls outside the 4 backup roots; confirm anchored methods (Beyond
  Carving's approach, `btrfs restore`, SecurityRonin `recover_deleted`) miss
  it while our orphan-node scan recovers it (headline differentiator).
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
  spread (§7).
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
- Markers: `sandbox` (needs `sandbox.img`), `vm` (needs `corpus/vm` output;
  skipped in default CI, run locally and in the scheduled M7 job).
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
  host mkfs version, guest kernel, sha256); tests reference images by name
  and skip when absent.
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
`corpus/vm/discard_table.sh` ×5 and record it under this template during M2.

## 8. Paper Plan

- **Primary target:** DFRWS EU/USA (FSI:DI) — the natural venue for this
  literature (deadline check needed); fallback IEEE Access (where Beyond
  Carving landed; fast OA). Re-check DFRWS APAC 2026 (19–22 Oct) accepted
  papers in October.
- **Paper 1 (tool + method):** "filesystem-state archaeology" — C1, C3, C4,
  C6 + evaluation vs the full baseline set on the released corpus (C7).
  - Structure maps to milestones: background/format (existing docs),
    method = layers 1–5 (validation layer included), evaluation = M7 +
    EXP records, related work = research.md §2/§4/§10.1–§10.2.
  - Positioning paragraph, three-way:
    - Beyond Carving answers *"what was deleted?"* from ≤ 4 backup roots;
    - SecurityRonin audits a volume and diffs one backup root;
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
  submission.

## 9. Risks

| Risk | Mitigation |
|---|---|
| **Realised:** a Rust forensic library (`SecurityRonin/btrfs-forensic`) ships backup-root deletion diffing and graded findings | Claims C3/C4 re-worded (§1); move M5 early; benchmark it (M7); keep C1/C6 btrfs-specific |
| Beyond Carving team ships their future work first (code repo created, still empty) | M4/M5 prototyped; watch repo; publish corpus fast (C7 uncontested) |
| Our own parsing, extent-read or LZO/stream code has bugs a mature library would not | Differential tests vs `dump-tree`, dissect.btrfs streams, `lzallright` and guest SHA-256s; property tests on hostile input; csum-type and compression images from M1; §3.5 fallback ladder (lzallright at runtime, then dissect.btrfs at runtime with an AGPL relicence) |
| dissect.btrfs (test oracle) drifts or is abandoned | Pinned `1.10.*` in the `dev` group; guest SHA-256s and `dump-tree` are independent oracles, so losing it costs one cross-check, not a runtime feature |
| Decoding "succeeds" on corrupted compressed data (LZO has no integrity check: 139–160 of 300 bit-flipped streams decoded to wrong bytes in all three decoders tested, §3.5) | Decode success never raises confidence; content is Confirmed only by a data-checksum match (M6); decoder errors are recorded, not hidden |
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

- One branch per feature (`feature/<name>`), PR to `main`, catalog.md entry
  with every merge (numbers + verification + EXP ids).
- Read-only guarantee: no code path may ever write to an evidence image. It
  is enforced by:
  - opening images `O_RDONLY` in exactly one place
    (`substrate/image.py`);
  - an AST test banning other open sites;
  - a session test asserting the `sandbox.img` hash before and after.
- Image rule: all images, mount points, VM tooling, tool builds and scratch
  outputs live under the gitignored `images/`; nothing is created outside
  the repo.
- Every empirical claim destined for the paper follows §7 (EXP record +
  committed regeneration script).
