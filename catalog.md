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

## 2026-09-15 — M1c: extent reads, decompression, oracle parity, EXP-001

- **Branch:** `feature/m1c-extent-reads` (from `main` at `16e7c77`). This is
  the last of three M1 PRs. It covers plan.md §5 M1 task 8 (extent reads,
  decompression, `cat`, oracles) and task 11 (EXP-001), and closes the M1
  DoD.
- **Commits:**
  - `c245e79` Add a bounds-checked LZO1X decoder with the dissect.util vectors and hostile-stream tests
  - `13ef276` Split chunk-map ranges at chunk ends and 64 KiB stripe boundaries
  - `33eea78` Decompress zlib, zstd and btrfs-framed LZO extents within the kernel's bounds
  - `4295ef0` Read extents and assemble file content with a provenance record per extent
  - `68f0c7d` Add btrfska cat: file bytes to stdout, extent records to stderr
  - `d20b138` Add the dissect.btrfs and lzallright oracles and the LZO hostile-input harness
  - `327fa72` Add EXP-001: checksum-type coverage of the legacy prototype and btrfska, with an environment record script
  - `a1ac866` Cite the LZO harness counts and the 4 421-byte worst case in the plan, and mark M1 done
  - `f7368fa` Record M1c extent-read, oracle and legacy findings
  - `7365cfd` Report i_size clipping only when an extent reaches past the sector holding EOF
  - `75ee852` Update the README status for M1 and document the cat records
  - `c4c9790` Record EXP-001: legacy accepts no tree block on non-crc32c images
  - this catalog entry (the commit after `c4c9790`)

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
`f7368fa` with a clean tree):

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
  `327fa72` (amended) before the recorded run.

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
- **A clipping-report change came after EXP-001 ran** (`7365cfd`). It changes
  only `problems` strings, none of EXP-001's metrics.

**Verification** (local, branch `feature/m1c-extent-reads` at `c4c9790`, all
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
lines trimmed with `…`; taken before `7365cfd`, whose clip message would now
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
`feature/m1c-extent-reads`, on top of `350a217`:
- `dac57ec` Reject LZO end markers whose copy length is not 3
- `8a19d34` Extend the LZO harness with truncation, insertion, deletion and random-stream corpora
- `45c72cc` Bound uncompressed extent lengths by the image size and map read pieces lazily
- `12a39ae` Note in-memory file reads and qualify the EXP-001 block counts
- `47387bc` Cite the extended LZO harness results
- this subsection (the commit after `47387bc`)

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
     loads `350a217`'s `lzo.py`). No single-byte edit of `11 00 00` yields
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

**Verification** (local, at `47387bc`; logs in
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

- **Branch:** `feature/m1b-validated-tree-walking` (from `main` at `a3c0e31`).
  This is the second of three M1 PRs. It covers plan.md §5 M1 tasks 5–7, the
  `walk` half of task 10 and the `m1_badnode` image of task 9.
- **Commits:**
  - `a41f583` Add chunk maps with stripe math for every profile and chunk item checks
  - `566d249` Add the node reader: every copy validated, each check recorded
  - `32fad0e` Add item payload parsers with never-raising JSON summaries
  - `c22432c` Walk trees from any root with per-hop checks; resolve backup roots and subvolumes
  - `d086270` Add btrfska walk: JSON lines per item with root and copy provenance
  - `c5561f7` Explain why superblock selection passes a wiped primary that btrfs-progs stops at
  - `de42668` Add a flip-byte operation to corpus/mutate.py for corrupt tree-block copies
  - `f3edc42` Add the m1_badnode images and vm tests for chunk maps, full walks and sv1 history
  - `3939c74` Record M1b tree-walking notes, the mirror policy and the README status
  - this catalog entry (the commit after `3939c74`)

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

- **Branch:** `feature/m1a-trust-foundations` (from `main` at `85cbc07`).
  This is the first of three M1 PRs. It covers plan.md §5 M1 tasks 1–4, the
  task-9 images these need (plus `m1_lzo` and `m1_zlib`), and the `info`
  half of task 10.
- **Commits:**
  - `d393c1e` Record defect #8 and the sandbox.img ground truth
  - `5efc964` Add on-disk struct tables checked against kernel v7.0 headers
  - `4a1317a` Add checksum dispatch for crc32c, xxhash64, sha256 and blake2b-256
  - `e34ae6e` Add superblock mirrors, best-copy selection and the incompat gate
  - `fda8316` Show superblock copies, gate verdict and backup roots in btrfska info
  - `00c93ea` Add the M1a corpus images, corpus/mutate.py and the image manifest
  - `d8140fa` Add an import-boundary test keeping test oracles out of src/
  - `5d61695` Record M1a format notes and update the README status
  - this catalog entry (the commit after `5d61695`)

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
  - `a018b41` Check superblock geometry against the kernel's validate_super rules
  - `52d11a9` Anchor superblock selection on the first valid copy's fsid
  - `527e976` Validate mutate.py patches before creating the output
  - `3cd7199` Tighten the ground-truth xfails to ImportError and zip copies strictly
  - `ef94dd2` Add the m1_foreign_mirror image and note foreign superblock residue
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
| Scope | `git diff --stat 8632164..HEAD` | 14 files, +712/−64: `src/btrfska/{cli.py,substrate/{ondisk,superblock}.py}`, `corpus/{mutate.py,manifest.tsv,vm/README.md}`, `research.md`, `tests/…` (+ this catalog) |
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
  (`checkout@v7`, `setup-uv@v10`) were taken from the plan. On the first PR run, CI failed at job setup because `astral-sh/setup-uv` has no floating `v10` tag; the workflow now pins `setup-uv@v10.1.0` and CI passes (run 34904950286, 17 s). These pins were not otherwise
  re-checked here.

**Review fixes** (commits `1d402c2`, `e275410`, `631f904`; each test
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
