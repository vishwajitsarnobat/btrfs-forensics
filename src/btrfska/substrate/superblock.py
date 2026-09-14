"""Superblock copies, best-copy selection, backup roots and the feature gate.

Kernel v7.0 references:
- copies live at btrfs_sb_offset(0..2) = 64 KiB, 64 MiB, 256 GiB (disk-io.h:37-43); a copy is
  used only if it ends before the device end (volumes.c:1356, `bytenr + 4096 >= size` rejects);
- a copy is accepted when magic and bytenr match (volumes.c:1378-1379) and the csum over
  bytes [32:4096] matches (disk-io.c:153-169 btrfs_check_super_csum);
- the kernel mounts only incompat bits in BTRFS_FEATURE_INCOMPAT_SUPP (fs.h:299-330); unknown
  compat_ro bits only prevent writing, so a read-only reader may proceed.

Geometry sanity mirrors part of btrfs_validate_super (disk-io.c:2360-2580). The kernel rejects on
every one of these checks. A copy is marked invalid when the check guards values that later
readers slice or recurse by, so trusting them would be unsafe or meaningless:
- sectorsize a power of two in [4096, 65536] (l.2404-2408);
- nodesize a power of two in [sectorsize, 65536] (l.2417-2421);
- root_level, chunk_root_level, log_root_level < BTRFS_MAX_LEVEL 8 (l.2384-2398);
- sys_chunk_array_size in [97, 2048] (l.2548-2561): the bootstrap chunk map is read from it;
- a known csum_type (open_ctree, l.3345-3351): no csum means no trust at all.
Other checks only warn. They are recorded in `problems`, but the copy stays valid, because its
identity, backup roots and sys_chunk_array remain usable evidence, and a node reader bounds-checks
each address anyway:
- root, chunk_root and log_root aligned to sectorsize (l.2429-2443);
- num_devices != 0 (l.2527-2530) and <= 2^31 (l.2524-2526, a kernel warning too).
Not mirrored: super flags (l.2372), leafsize == nodesize (l.2422), the page-size limit on
sectorsize (l.2410, a host limit), fsid vs the mounted device set (l.2445-2467), feature
dependencies (l.2473-2508), bytes_used and stripesize (l.2514-2523), and
validate_sys_chunk_array (l.2542, M1b parses the array).
"""

from dataclasses import dataclass

from btrfska.substrate import csum, ondisk
from btrfska.substrate.image import ImageHandle

# Fields that legitimately differ between otherwise identical copies.
_PER_COPY_FIELDS = frozenset({"csum", "bytenr"})


@dataclass(frozen=True)
class SuperblockCopy:
    mirror: int
    offset: int
    fields: dict | None = None  # None: the copy does not fit in the image
    magic_ok: bool = False
    bytenr_ok: bool = False
    csum_ok: bool = False
    geometry_ok: bool = False
    # Every failed check. On a valid copy these are warnings only (see the module docstring).
    problems: tuple[str, ...] = ()

    @property
    def present(self) -> bool:
        return self.fields is not None

    @property
    def valid(self) -> bool:
        return self.magic_ok and self.bytenr_ok and self.csum_ok and self.geometry_ok


def _is_pow2(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def geometry_problems(fields: dict) -> tuple[list[str], list[str]]:
    """(invalidating, warning) problems from the btrfs_validate_super checks we mirror.

    Kernel v7.0 fs/btrfs/disk-io.c line numbers are given per check.
    """
    invalid, warn = [], []
    for name in ("root_level", "chunk_root_level", "log_root_level"):  # l.2384-2398
        if fields[name] >= ondisk.MAX_LEVEL:
            invalid.append(f"{name} {fields[name]} >= {ondisk.MAX_LEVEL}")

    sectorsize, nodesize = fields["sectorsize"], fields["nodesize"]
    sectorsize_ok = (
        _is_pow2(sectorsize) and ondisk.MIN_BLOCKSIZE <= sectorsize <= ondisk.MAX_METADATA_BLOCKSIZE
    )  # l.2404-2408
    if not sectorsize_ok:
        invalid.append(f"invalid sectorsize {sectorsize}")
    if not (
        _is_pow2(nodesize) and sectorsize <= nodesize <= ondisk.MAX_METADATA_BLOCKSIZE
    ):  # l.2417-2421
        invalid.append(f"invalid nodesize {nodesize}")

    size = fields["sys_chunk_array_size"]  # l.2548-2561
    if size > ondisk.SYSTEM_CHUNK_ARRAY_SIZE:
        invalid.append(f"sys_chunk_array_size {size} > {ondisk.SYSTEM_CHUNK_ARRAY_SIZE}")
    elif size < ondisk.MIN_SYS_CHUNK_ARRAY_SIZE:
        invalid.append(f"sys_chunk_array_size {size} < {ondisk.MIN_SYS_CHUNK_ARRAY_SIZE}")

    if sectorsize_ok:  # alignment against a garbage sectorsize says nothing; l.2429-2443
        for name in ("root", "chunk_root", "log_root"):
            if fields[name] % sectorsize:
                warn.append(f"{name} {fields[name]} not aligned to sectorsize {sectorsize}")

    if fields["num_devices"] == 0:  # l.2527-2530 (kernel: error)
        warn.append("num_devices is 0")
    elif fields["num_devices"] > 1 << 31:  # l.2524-2526 (kernel: warning)
        warn.append(f"suspicious num_devices {fields['num_devices']}")
    return invalid, warn


def parse_copy(block, mirror: int) -> SuperblockCopy:
    """Parse and validate one 4096-byte superblock copy read from sb_offset(mirror)."""
    fields = ondisk.SUPERBLOCK.unpack_from(block)
    expected = ondisk.sb_offset(mirror)
    problems = []

    magic_ok = fields["magic"] == ondisk.MAGIC
    if not magic_ok:
        problems.append("magic mismatch")
    # Without the magic the remaining fields are noise, so only report bytenr for real copies.
    bytenr_ok = magic_ok and fields["bytenr"] == expected
    if magic_ok and not bytenr_ok:
        problems.append(f"bytenr {fields['bytenr']} != expected {expected}")
    try:
        csum_ok = csum.block_csum_ok(fields["csum_type"], block)
    except csum.UnknownCsumType as exc:
        csum_ok = False
        problems.append(str(exc))
    else:
        if not csum_ok:
            problems.append("csum mismatch")
    geometry_ok = False
    if magic_ok:  # same reason as bytenr: judge geometry only on real copies
        invalid, warn = geometry_problems(fields)
        geometry_ok = not invalid
        problems += invalid + warn

    return SuperblockCopy(
        mirror,
        expected,
        fields,
        magic_ok=magic_ok,
        bytenr_ok=bytenr_ok,
        csum_ok=csum_ok,
        geometry_ok=geometry_ok,
        problems=tuple(problems),
    )


def read_copies(img: ImageHandle) -> list[SuperblockCopy]:
    """Every superblock mirror slot, in mirror order; slots beyond the image are not present."""
    copies = []
    for mirror in range(ondisk.SUPER_MIRROR_MAX):
        offset = ondisk.sb_offset(mirror)
        if offset + ondisk.SUPER_INFO_SIZE >= img.size:
            copies.append(SuperblockCopy(mirror, offset))
        else:
            block = img.mmap[offset : offset + ondisk.SUPER_INFO_SIZE]
            copies.append(parse_copy(block, mirror))
    return copies


@dataclass(frozen=True)
class Selection:
    copies: list[SuperblockCopy]
    selected: SuperblockCopy | None
    disagreements: list[str]


def select(copies: list[SuperblockCopy]) -> Selection:
    """Pick the csum-valid copy with the highest generation (lowest mirror on a tie).

    Every present copy that is invalid, older, or different from the selected one is
    reported as a disagreement.
    """
    valid = [c for c in copies if c.valid]
    selected = max(valid, key=lambda c: (c.fields["generation"], -c.mirror), default=None)
    disagreements = []
    for copy in copies:
        if not copy.present or copy is selected:
            continue
        if not copy.valid:
            disagreements.append(f"mirror {copy.mirror} invalid: {', '.join(copy.problems)}")
            continue
        gen, selected_gen = copy.fields["generation"], selected.fields["generation"]
        if gen != selected_gen:
            disagreements.append(
                f"mirror {copy.mirror} generation {gen} != selected generation {selected_gen}"
            )
            continue
        differing = [
            name
            for name, value in copy.fields.items()
            if name not in _PER_COPY_FIELDS and value != selected.fields[name]
        ]
        if differing:
            disagreements.append(
                f"mirror {copy.mirror} differs from mirror {selected.mirror} in: "
                + ", ".join(differing)
            )
    return Selection(copies, selected, disagreements)


def read_superblock(img: ImageHandle) -> Selection:
    return select(read_copies(img))


def backup_roots(fields: dict) -> list[dict]:
    """The four btrfs_root_backup slots, sorted by generation (never by slot).

    The slots form a ring whose start depends on mount history (disk-io.c:1596-1607), so slot
    order says nothing about age. Each entry keeps its `slot`.
    """
    raw = fields["super_roots"]
    roots = [
        {"slot": slot, **ondisk.ROOT_BACKUP.unpack_from(raw, slot * ondisk.ROOT_BACKUP.size)}
        for slot in range(ondisk.NUM_BACKUP_ROOTS)
    ]
    return sorted(roots, key=lambda r: (r["tree_root_gen"], r["slot"]))


@dataclass(frozen=True)
class GateVerdict:
    """Whether btrfska may interpret this filesystem.

    `unsupported` lists incompat features we refuse: the experimental ones (extent-tree-v2,
    RAID stripe tree, remap tree) and any bit unknown to kernel v7.0. `allow_unsupported`
    continues anyway; everything derived must then be marked unsupported_format=1.
    """

    unsupported: tuple[str, ...]
    unknown_compat_ro: tuple[str, ...]
    block_group_tree: bool
    allow_unsupported: bool = False

    @property
    def refused(self) -> bool:
        return bool(self.unsupported) and not self.allow_unsupported

    @property
    def status(self) -> str:
        if not self.unsupported:
            return "OK"
        return "OVERRIDDEN" if self.allow_unsupported else "REFUSED"

    def report_lines(self) -> list[str]:
        return [f"UNSUPPORTED_INCOMPAT {name}" for name in self.unsupported]


def gate(fields: dict, allow_unsupported: bool = False) -> GateVerdict:
    incompat = ondisk.flag_names(fields["incompat_flags"], ondisk.INCOMPAT)
    unsupported = tuple(
        name
        for name in incompat
        if name in ondisk.EXPERIMENTAL_INCOMPAT or name.startswith("UNKNOWN_BIT_")
    )
    compat_ro = ondisk.flag_names(fields["compat_ro_flags"], ondisk.COMPAT_RO)
    return GateVerdict(
        unsupported=unsupported,
        unknown_compat_ro=tuple(n for n in compat_ro if n.startswith("UNKNOWN_BIT_")),
        block_group_tree="BLOCK_GROUP_TREE" in compat_ro,
        allow_unsupported=allow_unsupported,
    )
