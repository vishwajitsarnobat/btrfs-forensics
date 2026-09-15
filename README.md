# btrfs-forensics (`btrfska`)

`btrfska` ("btrfs archaeology") is a strictly read-only, open-source forensic
engine for raw Btrfs images. Btrfs's copy-on-write design leaves behind
historical metadata: orphaned nodes, item remnants beyond `nritems`, backup
and superseded roots, free-space-tree state and relocated-chunk residue. The
goal is to catalog all of it, with provenance and confidence, and answer what
existed, when, what changed, what can be recovered, and whether anything was
hidden.

**Status:** M1 done (substrate trust layer). Scanning for unreferenced
metadata (M2) comes next. The earlier prototype is frozen, still runnable,
under `legacy/`.
- `btrfska info IMAGE` validates every superblock copy (all four checksum
  types), selects the best one, and reports disagreements and the backup
  roots by generation. It refuses unsupported or unknown incompat features
  (exit 2, `UNSUPPORTED_INCOMPAT <name>`; override with
  `--allow-unsupported`).
- `btrfska walk IMAGE --root {current,backup:GEN,bytenr:N}
  [--tree fs|root|chunk|extent|dev|csum|ID]` walks one tree through the chunk
  map and prints one JSON line per item. Each line carries the root it was
  reached from and the validation record of every physical copy (DUP mirrors
  included); invalid nodes are reported instead of items.
- `btrfska cat IMAGE --inode N [--root …] [--tree fs|ID]` reads one file of
  the current state, a backup root, a subvolume or a snapshot. It handles
  inline, regular and prealloc extents and holes, and zlib, zstd and LZO
  compression (LZO through btrfska's own bounds-checked decoder). The bytes
  go to stdout only when every extent reads, with a provenance record per
  extent on stderr. Data checksums are not verified yet (M6).

**Licence:** Apache-2.0 (see `LICENSE`).

## Install and run

Requires [uv](https://docs.astral.sh/uv/); uv provisions Python 3.14.

```sh
uv sync                     # create .venv from uv.lock
uv run btrfska --help
uv run btrfska info sandbox.img
uv run btrfska walk sandbox.img --root backup:11 --tree fs
```

### `btrfska walk` output

`walk` writes one JSON object per line to stdout. A one-line summary, the
chunk-map problems (rejected chunks included) and any gate refusal go to
stderr. Every key below is always present; `null` means unknown or not
applicable.

Every record has these keys:
- `record`: `item`, `invalid_node` or `walk_problem`.
- `root`: where the walk started.
  - `source`: `current`, `backup:GEN` or `bytenr:N`.
  - `tree`: the `--tree` argument.
  - `tree_id`.
  - `bytenr`, `level` and `generation` of the start block, as the referrer
    records them.
  - `via`: how the start block was resolved (`superblock`, `backup slot N`,
    `ROOT_ITEM (…) in root tree … leaf … slot …` or `bytenr`).
- `chunk_map`: the source of the chunk map used (`current`).
- `unsupported_format`: `true` when `--allow-unsupported` overrode the gate.
- `node`: the tree block the record comes from.
  - `bytenr`: the block's logical address.
  - `level`, `generation` and `owner`: from the header of the copy used,
    else of the first readable copy (`null` when no copy was read).
  - `valid`: `true` when some copy passed every check.
  - `copies`: one object per physical copy, in mirror order.
  - `problems`: every failed check, as `mirror N: check: detail`, plus
    node-level findings such as a valid mirror that differs from the one
    used, or a mapping failure (then `copies` is empty).

Each entry of `copies` has these keys:
- `mirror`: 1-based, in stripe order.
- `devid`, `physical`: where the copy lives.
- `readable`: `false` when the bytes could not be read, because the device
  is missing or the copy lies beyond the image end.
- `used`: `true` for the copy whose items are reported.
- `valid`: `true` when no check failed.
- `checks`: every check, always in this order: `csum`, `bytenr`, `fsid`,
  `chunk_tree_uuid`, `generation`, `level`, `nritems`, `written`, `layout`,
  `owner`, `parent_generation`, `first_key`. Each value is `true`, `false`,
  or `null` when not checked (no reference value, or the copy is not
  readable).
- `problems`: `check: detail` for each failed check, or
  `readable: detail`.

Keys added by each record type:
- `item`: one leaf item of a valid leaf.
  - `slot`.
  - `key`: `objectid`, `type`, `type_name` and `offset`.
  - `size`: the item's data size.
  - `summary`: a cheap per-type decode.
- `invalid_node`: a block without any valid copy. It is reported in place of
  its items or children.
  - `parent`: the parent's logical address (`null` for the start block).
  - `parent_slot`: the pointer's slot in the parent.
- `walk_problem`: hop findings for a valid node, emitted before its items.
  - `parent`, `parent_slot`: as for `invalid_node`.
  - `problems`: for example, a last key not below the parent's next key, or
    a pointer to a block already reached, which is not followed.

### `btrfska cat` output

`btrfska cat IMAGE --inode N [--root current|backup:GEN|bytenr:N] [--tree fs|ID]`
writes the inode's bytes to stdout, and nothing else. They are written only
when every extent reads; otherwise stdout stays empty and the exit status is
1. The command opens no file other than the image. stderr carries one JSON
object per line: an `extent` record per extent in file order (implicit holes
included), then one `file` record, then a one-line summary or the error.

Both record types have:
- `record`: `extent` or `file`.
- `root`: as in `walk` (`source`, `tree`, `tree_id`, `bytenr`, `level`,
  `generation`, `via`).
- `inode`: the inode number read.
- `unsupported_format`: `true` when `--allow-unsupported` overrode the gate.

An `extent` record adds:
- `kind`: `inline`, `regular`, `prealloc`, `hole` (an explicit hole:
  `disk_bytenr` 0), `implicit_hole` (no item covers the range) or `invalid`.
- `file_offset`, `length`: the file range this extent supplies, clipped to
  the inode size.
- `leaf`, `slot`: where the EXTENT_DATA item was read (`null` for implicit
  holes).
- `generation`, `ram_bytes`, `disk_bytenr`, `disk_num_bytes`, `offset`,
  `num_bytes`: the item's fields (`null` when the kind has none).
- `compression`: `none`, `zlib`, `lzo`, `zstd` or `type N`.
- `chunk_map`: the source of the chunk map the data was read through.
- `ranges`: the logical ranges read, split at chunk ends and 64 KiB stripe
  boundaries. Each has `logical`, `length` and `copies`; each copy has
  `mirror`, `devid`, `physical`, `readable`, `used` (the copy whose bytes
  were used, the first readable one) and `matches` (whether it equals the
  used copy; `null` for the used copy and unreadable copies).
- `decoded_bytes`: the decompressor's output length. A compressed inline
  extent decodes a whole sector, more than `ram_bytes`.
- `sha256`: of the bytes supplied (`null` for zeros and failures).
- `error_kind`, `error_detail`: why the extent could not be read (`null` and
  `""` when it was): `unmapped`, `unreadable`, `malformed_item`,
  `invalid_extent`, `unsupported_encoding`, `unsupported_compression`,
  `corrupt_stream`, `truncated_stream`, `output_overrun`, `short_output`,
  `lzo_framing` or `lzo_<decoder error>`.
- `problems`: findings that do not change the bytes, such as a divergent
  mirror, non-zero bytes after a compressed stream or past `ram_bytes`, or
  an extent reaching past the sector that holds the end of the file (it is
  clipped to the inode size).

The `file` record adds `size` (the inode size, `null` without an
INODE_ITEM), `complete`, `extents` (the number of extent records), `errors`
(file-level failures: an unreadable tree, a missing inode, a directory,
overlapping extents) and `problems` (such as gaps on a filesystem without
NO_HOLES). Decoding success is not evidence of correct content: LZO has no
checksum and data checksums are verified from M6 on.

`cat` currently holds the whole file in memory before writing it, with a
peak of about twice the file size (explicit and implicit holes excepted).
Streaming reads arrive with the recovery engine (plan.md M4).

## Tests and lint

```sh
uv run ruff check . && uv run ruff format --check .   # lint (legacy/ excluded)
uv run pytest                                          # new tests + legacy tests (collected as unittest cases)
uv run pytest -m sandbox                               # sandbox-only subset
uv run python -m unittest discover -s legacy/tests     # legacy suite, original runner
uvx --from . btrfska --version
```

CI (`.github/workflows/ci.yml`) runs the same lint and tests, plus a `sh -n`
syntax check of the `corpus/vm` scripts. It restores `sandbox.img` from the
tracked `tests/fixtures/sandbox.img.zst` and checks it against
`tests/fixtures/SHA256SUMS`.

### Test policy

- `sandbox.img` at the repo root is the primary regression image (sha256
  `07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418`). It is
  read-only and never mutated. `btrfska` opens images only through
  `src/btrfska/substrate/image.py` (`O_RDONLY`, read-only mmap), and the test
  session asserts the image's sha256 before and after every run.
- Markers: `sandbox` (needs `sandbox.img`, skipped when absent) and `vm`
  (needs the `corpus/vm` images listed in `corpus/manifest.tsv`, skipped when
  absent; run them with `uv run pytest -m vm`).
- Full policy: `plan.md` §6.1.

### Image rule

All images, mount points, VM tooling, tool builds and scratch outputs live
under the gitignored `images/` folder (`images/scenarios/`, `images/vm/`,
`images/tools/`, `images/scratch/`, `images/mnt/`). Nothing is created
outside the repo.

The `corpus/vm` smoke test is local only (needs `/dev/kvm`) and is not run in
CI; its output goes under `images/`:

```sh
corpus/vm/fetch_vm.sh && corpus/vm/build_initramfs.sh && corpus/vm/make_image.sh smoke_s01
```

## Legacy prototype

The prototype CLI and its tests live under `legacy/` as a reference until the
new pipeline reaches parity (`plan.md` §4.3). Run both at once:

```sh
uv run --python 3.14 python legacy/main.py sandbox.img -o images/scratch/legacy-out
uv run --python 3.14 python -m unittest discover -s legacy/tests -v
```

## Documentation

- [`plan.md`](plan.md): build plan (architecture, stack, migration,
  milestones, test policy, experiment protocol).
- [`research.md`](research.md): verified prior-art and gap analysis.
- [`catalog.md`](catalog.md): chronological development record.
- [`corpus/vm/README.md`](corpus/vm/README.md): rootless QEMU scenario images.
