# btrfs-forensics (`btrfska`)

`btrfska` ("btrfs archaeology") is a strictly read-only, open-source forensic
engine for raw Btrfs images. Btrfs's copy-on-write design leaves behind
historical metadata: orphaned nodes, item remnants beyond `nritems`, backup
and superseded roots, free-space-tree state and relocated-chunk residue. The
goal is to catalog all of it, with provenance and confidence, and answer what
existed, when, what changed, what can be recovered, and whether anything was
hidden.

**Status:** M1b (validated tree walking). `btrfska info IMAGE` validates every
superblock copy (all four checksum types), selects the best one, reports
disagreements, backup roots by generation, and refuses unsupported or unknown
incompat features (exit 2, `UNSUPPORTED_INCOMPAT <name>`; override with
`--allow-unsupported`). `btrfska walk IMAGE --root {current,backup:GEN,bytenr:N}
[--tree fs|root|chunk|extent|dev|csum|ID]` walks one tree through the chunk
map and prints one JSON line per item. Each line carries the root it was
reached from and the validation record of every physical copy (DUP mirrors
included); invalid nodes are reported instead of items. File content
recovery comes next. The earlier prototype is frozen, still runnable, under
`legacy/`.

**Licence:** Apache-2.0 (see `LICENSE`).

## Install and run

Requires [uv](https://docs.astral.sh/uv/); uv provisions Python 3.14.

```sh
uv sync                     # create .venv from uv.lock
uv run btrfska --help
uv run btrfska info sandbox.img
```

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
