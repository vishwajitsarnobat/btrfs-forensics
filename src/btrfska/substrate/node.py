"""Tree block reader: every physical copy is read and validated, each check recorded on its own.

`read_node` maps a logical address through a `ChunkMap`, reads *every* copy (all DUP/RAID1
stripes), and validates each one independently. The first valid copy in mirror order is used;
every copy's checks are kept as provenance, so a corrupt copy is never hidden behind a good one.
A node without any valid copy is returned flagged: its header is reported, its items are not.

Checks, in `CHECK_NAMES` order (kernel v7.0 references):
- csum: over [32:nodesize] with the superblock csum type (disk-io.c:388-402);
- bytenr: header bytenr equals the logical address read (disk-io.c:369-374);
- fsid: header fsid equals the tree fsid, i.e. metadata_uuid when set (disk-io.c:328-352,
  volumes.c:734-740);
- chunk_tree_uuid: equals the chunk root header's, which the kernel records at mount
  (disk-io.c:3487-3489);
- generation: not newer than the superblock generation. In a log context (`Expect.log`, set only
  for trees reached from the superblock's log_root) exactly superblock generation + 1: the log is
  written in the running transaction (transaction.c:392-393, extent-tree.c:5306), whose previous
  transaction's superblock is on disk before the log's (tree-log.c:3554-3580,
  transaction.c:2535-2581), and the kernel reads the log root with transid generation + 1
  (disk-io.c:2017-2019);
- level: below BTRFS_MAX_LEVEL (disk-io.c:381-386) and equal to the expected level (l.404-409);
- nritems: leaf items fit in the block; an internal node holds 1..ptrs-per-block
  (tree-checker.c:2199-2205); leaves of trees that are never empty hold items (l.2047-2080);
- written: BTRFS_HEADER_FLAG_WRITTEN set (tree-checker.c:2033-2036, 2186-2189);
- layout: leaf keys strictly ascending, item data contiguous from the block end and clear of the
  item headers (tree-checker.c:2094-2150); node keys ascending, block pointers non-zero and
  sector-aligned (l.2209-2231);
- owner: btrfs_check_eb_owner (tree-checker.c:2247-2297): exact for non-subvolume trees, any
  subvolume owner for subvolume trees (shared snapshot blocks). The kernel skips log and reloc
  trees (l.2270); btrfska checks log trees exactly, since every log block is allocated with owner
  BTRFS_TREE_LOG_OBJECTID, -6 (btrfs_tree.h:92; disk-io.c:861-867, 887; ctree.c:520);
- parent_generation: equal to the parent pointer's generation (disk-io.c:410-417, "parent transid
  verify failed"). A newer block means the address was rewritten after the parent was written;
- first_key: the first key equals the parent pointer's key (disk-io.c:418-436).
A check whose reference is unknown (no parent, no chunk tree uuid yet) is recorded with ok=None.

Why a referenced block cannot be used (`node_failure`, one class per node):
- `reused`: a copy passes every integrity check (csum, fsid, chunk_tree_uuid, nritems, written,
  layout, level below 8) but fails a linkage check (bytenr, level, owner, parent_generation,
  first_key) and is newer than the referrer expects. The address now holds a newer tree's block,
  committed or not (an uncommitted log or transaction is newer than the superblock). This is the
  normal fate of an old backup root's blocks, not damage;
- `mismatch`: integrity holds, linkage fails, and the block is not newer (a forged or inconsistent
  referrer, or a rolled-back block);
- `corrupt`: this filesystem's header (fsid) but an integrity check fails;
- `overwritten`: no tree block of this filesystem there (data, another filesystem);
- `zeroed`: the copy reads as zeros (trimmed by discard, or never written);
- `unreadable`: the copy lies beyond the image end or on a missing device;
- `unmapped`: the chunk map places the address nowhere.
Across copies the most informative class wins, in that order.
"""

from dataclasses import dataclass, field
from typing import NamedTuple

from btrfska.substrate import csum, ondisk, superblock
from btrfska.substrate.chunks import ChunkMap, MappingError
from btrfska.substrate.image import ImageHandle

CHECK_NAMES = (
    "csum",
    "bytenr",
    "fsid",
    "chunk_tree_uuid",
    "generation",
    "level",
    "nritems",
    "written",
    "layout",
    "owner",
    "parent_generation",
    "first_key",
)
_HEADER = ondisk.HEADER.size
# Trees whose leaves may never be empty (tree-checker.c:2052-2078; the extent tree unless
# extent-tree-v2, which the feature gate refuses). Owner 0 is undefined.
_NEVER_EMPTY = frozenset(
    {
        0,
        ondisk.ROOT_TREE_OBJECTID,
        ondisk.EXTENT_TREE_OBJECTID,
        ondisk.CHUNK_TREE_OBJECTID,
        ondisk.DEV_TREE_OBJECTID,
        ondisk.FS_TREE_OBJECTID,
        ondisk.DATA_RELOC_TREE_OBJECTID,
    }
)


class InvalidNode(Exception):
    """Items or key pointers were requested from a node that has no valid copy."""


class Key(NamedTuple):
    """A btrfs key; tuple order is btrfs_comp_cpu_keys order."""

    objectid: int
    type: int
    offset: int

    def __str__(self) -> str:
        return f"({self.objectid} {self.type} {self.offset})"


@dataclass(frozen=True)
class Item:
    slot: int
    key: Key
    offset: int  # relative to the end of the header, as on disk
    size: int
    data: bytes


@dataclass(frozen=True)
class KeyPtr:
    slot: int
    key: Key
    blockptr: int
    generation: int


@dataclass(frozen=True)
class Expect:
    """What the referrer (superblock, root item or parent node) says the block must be."""

    level: int | None = None
    owner: int | None = None
    generation: int | None = None
    first_key: Key | None = None
    log: bool = False  # the block belongs to a log tree anchored at the superblock's log_root


NO_EXPECTATIONS = Expect()


@dataclass(frozen=True)
class NodeContext:
    nodesize: int
    sectorsize: int
    csum_type: int
    fsid: bytes  # the tree fsid (metadata_uuid when set)
    generation: int  # superblock generation
    chunk_tree_uuid: bytes | None = None

    @classmethod
    def from_superblock(cls, fields: dict, chunk_tree_uuid: bytes | None = None) -> NodeContext:
        return cls(
            nodesize=fields["nodesize"],
            sectorsize=fields["sectorsize"],
            csum_type=fields["csum_type"],
            fsid=superblock.tree_fsid(fields),
            generation=fields["generation"],
            chunk_tree_uuid=chunk_tree_uuid,
        )


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool | None  # None: not checked, the reference value is unknown
    detail: str = ""


def _key(fields: dict) -> Key:
    return Key(fields["key_objectid"], fields["key_type"], fields["key_offset"])


def _capacity(nodesize: int, level: int) -> int:
    return (nodesize - _HEADER) // (ondisk.ITEM.size if level == 0 else ondisk.KEY_PTR.size)


def _require_size(block, nodesize: int) -> None:
    if len(block) != nodesize:
        raise ValueError(f"block is {len(block)} bytes, nodesize is {nodesize}")


def parse_items(block, nodesize: int) -> tuple[tuple[Item, ...], tuple[str, ...]]:
    """Leaf items whose data lies inside the block, and one problem per item that does not.

    Never raises on content: nritems is clamped to what fits, and no slice escapes the block.
    Raises ValueError only when `block` is not `nodesize` bytes long.
    """
    _require_size(block, nodesize)
    count, problems = ondisk.HEADER.unpack_from(block)["nritems"], []
    if count > (limit := _capacity(nodesize, 0)):
        problems.append(f"nritems {count} > {limit} items fit in a leaf")
        count = limit
    items = []
    for slot in range(count):
        fields = ondisk.ITEM.unpack_from(block, _HEADER + slot * ondisk.ITEM.size)
        start = _HEADER + fields["offset"]
        end = start + fields["size"]
        if end > nodesize:
            problems.append(
                f"slot {slot}: data at {fields['offset']} size {fields['size']} ends past the block"
            )
            continue
        items.append(
            Item(slot, _key(fields), fields["offset"], fields["size"], bytes(block[start:end]))
        )
    return tuple(items), tuple(problems)


def parse_key_ptrs(block, nodesize: int) -> tuple[tuple[KeyPtr, ...], tuple[str, ...]]:
    """Key pointers of an internal node; nritems is clamped to what fits in the block."""
    _require_size(block, nodesize)
    count, problems = ondisk.HEADER.unpack_from(block)["nritems"], []
    if count > (limit := _capacity(nodesize, 1)):
        problems.append(f"nritems {count} > {limit} pointers fit in a node")
        count = limit
    ptrs = []
    for slot in range(count):
        fields = ondisk.KEY_PTR.unpack_from(block, _HEADER + slot * ondisk.KEY_PTR.size)
        ptrs.append(KeyPtr(slot, _key(fields), fields["blockptr"], fields["generation"]))
    return tuple(ptrs), tuple(problems)


def is_subvolume_tree(objectid: int) -> bool:
    """ctree.h:731-743 btrfs_is_fstree: tree 5, or 256 <= id as s64 with qgroup level 0."""
    return objectid == ondisk.FS_TREE_OBJECTID or ondisk.FIRST_FREE_OBJECTID <= objectid < 1 << 48


def owner_ok(expected: int | None, owner: int) -> bool | None:
    """The owner check: None when the kernel cannot check it either, else whether it holds."""
    skipped = (None, 0, ondisk.TREE_RELOC_OBJECTID)
    if expected in skipped:  # the kernel cannot check these either
        return None
    if is_subvolume_tree(expected):
        return is_subvolume_tree(owner)
    return owner == expected


def _layout(block, ctx: NodeContext, level: int, count: int) -> tuple[bool, str]:
    base = _HEADER
    if level == 0:
        previous, expected_end = Key(0, 0, 0), ctx.nodesize - _HEADER
        for slot in range(count):
            fields = ondisk.ITEM.unpack_from(block, base + slot * ondisk.ITEM.size)
            key, end = _key(fields), fields["offset"] + fields["size"]
            if key <= previous:
                return False, f"slot {slot}: key {key} is not above {previous}"
            if end != expected_end:
                return False, f"slot {slot}: data ends at {end}, expected {expected_end}"
            if fields["offset"] < (slot + 1) * ondisk.ITEM.size:
                return False, f"slot {slot}: data at {fields['offset']} overlaps the item headers"
            previous, expected_end = key, fields["offset"]
        return True, ""
    previous = None
    for slot in range(count):
        fields = ondisk.KEY_PTR.unpack_from(block, base + slot * ondisk.KEY_PTR.size)
        key, blockptr = _key(fields), fields["blockptr"]
        if previous is not None and key <= previous:
            return False, f"slot {slot}: key {key} is not above {previous}"
        if blockptr == 0 or blockptr % ctx.sectorsize:
            return False, f"slot {slot}: block pointer {blockptr} is null or not sector-aligned"
        previous = key
    return True, ""


def check_block(block, ctx: NodeContext, logical: int | None, expect: Expect) -> tuple[Check, ...]:
    """Validate one physical copy of a tree block; one `Check` per entry of `CHECK_NAMES`.

    `logical` is the address the block was read for (None when scanning physical blocks).
    Never raises on content; raises ValueError only when `block` is not nodesize bytes long.
    """
    _require_size(block, ctx.nodesize)
    header = ondisk.HEADER.unpack_from(block)
    checks = []

    def record(name: str, ok: bool | None, detail: str) -> None:
        checks.append(Check(name, ok, detail if ok is False else ""))

    stored = bytes(block[: csum.csum_size(ctx.csum_type)])
    computed = csum.compute(ctx.csum_type, memoryview(block)[ondisk.CSUM_SIZE :])
    record("csum", stored == computed, f"stored {stored.hex()} computed {computed.hex()}")
    record(
        "bytenr",
        None if logical is None else header["bytenr"] == logical,
        f"header bytenr {header['bytenr']} != logical {logical}",
    )
    record("fsid", header["fsid"] == ctx.fsid, f"fsid {header['fsid'].hex()} != {ctx.fsid.hex()}")
    ctu = ctx.chunk_tree_uuid
    record(
        "chunk_tree_uuid",
        None if ctu is None else header["chunk_tree_uuid"] == ctu,
        f"chunk_tree_uuid {header['chunk_tree_uuid'].hex()} != {ctu and ctu.hex()}",
    )
    generation = header["generation"]
    if expect.log:
        record(
            "generation",
            generation == ctx.generation + 1,
            f"generation {generation} != superblock generation + 1 ({ctx.generation + 1}), "
            "required for a log tree block",
        )
    else:
        record(
            "generation",
            generation <= ctx.generation,
            f"generation {generation} > superblock generation {ctx.generation}",
        )

    level = header["level"]
    if level >= ondisk.MAX_LEVEL:
        record("level", False, f"level {level} >= {ondisk.MAX_LEVEL}")
    else:
        record(
            "level",
            expect.level is None or level == expect.level,
            f"level {level} != expected {expect.level}",
        )

    count, owner = header["nritems"], header["owner"]
    limit = _capacity(ctx.nodesize, level)
    if level == 0:
        empty_forbidden = (
            count == 0 and not header["flags"] & ondisk.HEADER_FLAG_RELOC and owner in _NEVER_EMPTY
        )
        nritems_ok = count <= limit and not empty_forbidden
        detail = (
            f"nritems {count} > {limit} items fit in a leaf"
            if count > limit
            else f"leaf of tree {owner} must never be empty"
        )
    else:
        nritems_ok = 1 <= count <= limit
        detail = f"nritems {count} outside [1, {limit}] for a node"
    record("nritems", nritems_ok, detail)
    record(
        "written",
        bool(header["flags"] & ondisk.HEADER_FLAG_WRITTEN),
        f"WRITTEN flag not set (flags {header['flags']:#x})",
    )
    if nritems_ok:
        record("layout", *_layout(block, ctx, level, count))
    else:
        record("layout", None, "")

    record("owner", owner_ok(expect.owner, owner), f"owner {owner} != expected {expect.owner}")
    parent_gen = expect.generation
    relation = "newer: rewritten after the parent" if generation > (parent_gen or 0) else "older"
    record(
        "parent_generation",
        None if parent_gen is None else generation == parent_gen,
        f"generation {generation} != parent pointer generation {parent_gen} ({relation})",
    )
    if expect.first_key is None:
        record("first_key", None, "")
    elif not (nritems_ok and count):
        record("first_key", False, f"no first key to compare with {expect.first_key}")
    else:
        first = _key(ondisk.ITEM.unpack_from(block, _HEADER))  # keys lead items and pointers
        record(
            "first_key",
            first == expect.first_key,
            f"first key {first} != parent key {expect.first_key}",
        )
    return tuple(checks)


@dataclass(frozen=True)
class NodeCopy:
    """One physical copy of a tree block and its validation record."""

    mirror: int  # 1-based, in stripe order (the kernel's mirror_num)
    devid: int
    physical: int
    checks: tuple[Check, ...]
    # Header fields of this copy's bytes (None when unreadable), and whether they are all zero.
    generation: int | None = None
    owner: int | None = None
    level: int | None = None
    zero: bool = False

    @property
    def ok(self) -> bool:
        return all(check.ok is not False for check in self.checks)

    @property
    def readable(self) -> bool:
        """False when the copy's bytes could not be read (missing device, beyond the image end):
        its only check is then `readable`, and none of `CHECK_NAMES` ran."""
        return not any(check.name == "readable" for check in self.checks)

    @property
    def problems(self) -> tuple[str, ...]:
        return tuple(f"{c.name}: {c.detail}" for c in self.checks if c.ok is False)


@dataclass(frozen=True)
class ValidatedNode:
    logical: int
    copies: tuple[NodeCopy, ...]
    chosen: int | None  # index into `copies` of the copy used; None when no copy is valid
    header: dict | None  # the chosen copy's header, else the first readable copy's (report only)
    problems: tuple[str, ...]  # every failed check of every copy, plus node-level findings
    _items: tuple[Item, ...] = field(default=(), repr=False)
    _key_ptrs: tuple[KeyPtr, ...] = field(default=(), repr=False)

    @property
    def valid(self) -> bool:
        return self.chosen is not None

    @property
    def level(self) -> int | None:
        return None if self.header is None else self.header["level"]

    @property
    def generation(self) -> int | None:
        return None if self.header is None else self.header["generation"]

    @property
    def owner(self) -> int | None:
        return None if self.header is None else self.header["owner"]

    def _require_valid(self) -> None:
        if not self.valid:
            raise InvalidNode(f"node {self.logical} has no valid copy: {'; '.join(self.problems)}")

    @property
    def items(self) -> tuple[Item, ...]:
        """Leaf items of the chosen copy; InvalidNode when no copy is valid."""
        self._require_valid()
        return self._items

    @property
    def key_ptrs(self) -> tuple[KeyPtr, ...]:
        """Key pointers of the chosen copy; InvalidNode when no copy is valid."""
        self._require_valid()
        return self._key_ptrs


def read_node(
    img: ImageHandle,
    chunk_map: ChunkMap,
    logical: int,
    ctx: NodeContext,
    expect: Expect = NO_EXPECTATIONS,
) -> ValidatedNode:
    """Read and validate every copy of the tree block at `logical`. Never raises on content."""
    try:
        physical_copies = chunk_map.copies(logical, ctx.nodesize)
    except MappingError as exc:
        return ValidatedNode(logical, (), None, None, (str(exc),))

    copies, blocks = [], []
    for pc in physical_copies:
        block = None
        if pc.missing_device:
            checks = (Check("readable", False, f"devid {pc.devid} is not available"),)
        elif pc.physical + ctx.nodesize > img.size:
            detail = f"physical {pc.physical} + {ctx.nodesize} is beyond the image end ({img.size})"
            checks = (Check("readable", False, detail),)
        else:
            block = bytes(img.mmap[pc.physical : pc.physical + ctx.nodesize])
            checks = check_block(block, ctx, logical, expect)
        if block is None:
            copies.append(NodeCopy(pc.mirror, pc.devid, pc.physical, checks))
        else:
            fields = ondisk.HEADER.unpack_from(block)
            copies.append(
                NodeCopy(
                    pc.mirror, pc.devid, pc.physical, checks,
                    fields["generation"], fields["owner"], fields["level"], not any(block),
                )
            )  # fmt: skip
        blocks.append(block)

    chosen = next((i for i, copy in enumerate(copies) if copy.ok), None)
    problems = [f"mirror {c.mirror}: {p}" for c in copies for p in c.problems]
    items, ptrs = (), ()
    if chosen is None:
        block = next((b for b in blocks if b is not None), None)
    else:
        block = blocks[chosen]
        for i, copy in enumerate(copies):
            if i != chosen and copy.ok and blocks[i] != block:
                problems.append(
                    f"mirror {copy.mirror} is valid but differs from mirror {copies[chosen].mirror}"
                )
    header = None if block is None else ondisk.HEADER.unpack_from(block)
    if chosen is not None:
        if header["level"] == 0:
            items, _ = parse_items(block, ctx.nodesize)
        else:
            ptrs, _ = parse_key_ptrs(block, ctx.nodesize)
    return ValidatedNode(logical, tuple(copies), chosen, header, tuple(problems), items, ptrs)


FAILURE_CLASSES = (
    "reused", "mismatch", "corrupt", "overwritten", "zeroed", "unreadable", "unmapped",
)  # fmt: skip
INTEGRITY_CHECKS = frozenset({"csum", "fsid", "chunk_tree_uuid", "nritems", "written", "layout"})


def copy_failure(copy: NodeCopy, expect: Expect) -> str | None:
    """Why this copy cannot serve the referrer (module docstring), or None when it can."""
    if copy.ok:
        return None
    if not copy.readable:
        return "unreadable"
    if copy.zero:
        return "zeroed"
    failed = {check.name for check in copy.checks if check.ok is False}
    if "fsid" in failed:
        return "overwritten"
    if failed & INTEGRITY_CHECKS or (copy.level is not None and copy.level >= ondisk.MAX_LEVEL):
        return "corrupt"
    newer = expect.generation is not None and (copy.generation or 0) > expect.generation
    # Only a generation beyond the superblock's (a newer, uncommitted block) or linkage failed.
    return "reused" if newer else "mismatch"


def node_failure(node: ValidatedNode, expect: Expect) -> str | None:
    """The class of a node without a valid copy (module docstring); None for a valid node.

    `expect` is what the node was read with. A copy newer than the superblock fails only the
    generation check, which is not an integrity check: it can only be a newer, uncommitted block.
    """
    if node.valid:
        return None
    if not node.copies:
        return "unmapped"
    classes = {copy_failure(copy, expect) for copy in node.copies}
    return next(name for name in FAILURE_CLASSES if name in classes)


@dataclass(frozen=True)
class NodeReader:
    """An image, the chunk map to read it through and the validation context, bundled."""

    img: ImageHandle
    chunk_map: ChunkMap
    ctx: NodeContext

    def read(self, logical: int, expect: Expect = NO_EXPECTATIONS) -> ValidatedNode:
        return read_node(self.img, self.chunk_map, logical, self.ctx, expect)
