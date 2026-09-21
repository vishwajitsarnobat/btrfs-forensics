"""What lies beyond `nritems`: a block's slack, and the stale items and key pointers in it.

The slack of a tree block is what no current item or key pointer uses:
- internal node: from the end of key pointer `nritems` to the end of the block;
- leaf: from the end of item `nritems` to the lowest item data offset (the whole block after the
  header when it is empty).
These are the two ranges the kernel zeroes before every tree-block write (v7.0
fs/btrfs/extent_io.c:2215 prepare_eb_write, since v4.9). EXP-005 measured the consequence: on a
filesystem a current kernel wrote, only blocks that `mkfs.btrfs` wrote and the kernel never
rewrote hold anything here. So this module describes; it does not promise deleted files. What it
finds is one of: remnants of a non-kernel writer (mkfs), remnants on a filesystem last written by
a kernel older than 4.9 (where Bhat & Wani 2018's orphan items live), or bytes somebody put there.

Stale entries are looked for on both grids in both kinds of block, anchored at the end of the
header, because a leaf can be reallocated as an internal node and the reverse:
- stale items: 25-byte item headers; one counts when it is not all-zero, its key type is a known
  item type, and its data range lies inside the block and behind the header itself (size 0 only
  for the few item types that have no payload);
- stale key pointers: 33-byte pointers; one counts when its key type is known, its block pointer
  is non-zero and sector-aligned, and its generation is non-zero and not above the block's own.
Nothing here trusts a length it has not bounded, and nothing reads outside the block.
"""

from dataclasses import dataclass

from btrfska.substrate import ondisk
from btrfska.substrate.items import KEY_TYPE_NAMES
from btrfska.substrate.node import Key

HEADER = ondisk.HEADER.size
ITEM = ondisk.ITEM.size
KEY_PTR = ondisk.KEY_PTR.size

ZERO, STALE, OTHER = "zero", "stale_structures", "other"
# Key types whose items carry no payload; any other item of size 0 is not an item.
_MAY_BE_EMPTY = frozenset(
    ondisk.ITEM_KEYS[name]
    for name in ("ORPHAN_ITEM", "TREE_BLOCK_REF", "SHARED_BLOCK_REF", "FREE_SPACE_EXTENT")
)


@dataclass(frozen=True)
class StaleItem:
    position: int  # byte offset of the header in the block
    slot: int  # its index on the item grid; at least nritems in a leaf
    key: Key
    data_offset: int  # relative to the end of the block header, as on disk
    data_size: int
    data_state: str  # in_slack, overlaps_live or empty
    data: bytes | None  # the payload when it still lies wholly in the slack


@dataclass(frozen=True)
class StaleKeyPtr:
    position: int
    slot: int  # its index on the key-pointer grid
    key: Key
    blockptr: int
    generation: int


@dataclass(frozen=True)
class SlackReport:
    start: int
    length: int
    nonzero: int
    slack_class: str  # ZERO, STALE or OTHER
    items: tuple[StaleItem, ...]
    key_ptrs: tuple[StaleKeyPtr, ...]


def slack_range(block, nodesize: int) -> tuple[int, int]:
    """[start, end) of the slack, clamped to the block; empty when start >= end.

    On a block that does not validate the range means little; callers describe valid blocks.
    """
    header = ondisk.HEADER.unpack_from(block)
    count = header["nritems"]
    if header["level"] > 0:
        return min(HEADER + count * KEY_PTR, nodesize), nodesize
    start = min(HEADER + count * ITEM, nodesize)
    if count == 0:
        return start, nodesize
    offsets = (
        ondisk.ITEM.unpack_from(block, HEADER + slot * ITEM)["offset"]
        for slot in range(min(count, (nodesize - HEADER) // ITEM))
    )
    return start, min(HEADER + min(offsets), nodesize)


def _grid(start: int, end: int, size: int):
    """(slot, position) of every whole grid cell of `size` inside [start, end)."""
    first = -(-(start - HEADER) // size)
    for slot in range(first, (end - HEADER) // size):
        yield slot, HEADER + slot * size


def stale_items(block, nodesize: int, start: int, end: int) -> list[StaleItem]:
    found = []
    for slot, position in _grid(start, end, ITEM):
        if not any(block[position : position + ITEM]):
            continue
        fields = ondisk.ITEM.unpack_from(block, position)
        if fields["key_type"] not in KEY_TYPE_NAMES:
            continue
        data_start = HEADER + fields["offset"]
        data_end = data_start + fields["size"]
        # An item's data lies behind the item array, so behind its own header, and in the block.
        if data_start < position + ITEM or data_end > nodesize:
            continue
        if fields["size"] == 0:
            if fields["key_type"] not in _MAY_BE_EMPTY:
                continue
            state, data = "empty", None
        elif data_end <= end:
            state, data = "in_slack", bytes(block[data_start:data_end])
        else:
            state, data = "overlaps_live", None
        key = Key(fields["key_objectid"], fields["key_type"], fields["key_offset"])
        found.append(StaleItem(position, slot, key, fields["offset"], fields["size"], state, data))
    return found


def stale_key_ptrs(
    block, sectorsize: int, generation: int, start: int, end: int
) -> list[StaleKeyPtr]:
    found = []
    for slot, position in _grid(start, end, KEY_PTR):
        if not any(block[position : position + KEY_PTR]):
            continue
        fields = ondisk.KEY_PTR.unpack_from(block, position)
        pointer, pointed = fields["blockptr"], fields["generation"]
        if fields["key_type"] not in KEY_TYPE_NAMES:
            continue
        if pointer == 0 or pointer % sectorsize or not 0 < pointed <= generation:
            continue
        key = Key(fields["key_objectid"], fields["key_type"], fields["key_offset"])
        found.append(StaleKeyPtr(position, slot, key, pointer, pointed))
    return found


def describe(block, nodesize: int, sectorsize: int) -> SlackReport:
    """The slack of one block. Raises ValueError only when `block` is not `nodesize` long."""
    if len(block) != nodesize:
        raise ValueError(f"block of {len(block)} bytes; nodesize is {nodesize}")
    start, end = slack_range(block, nodesize)
    if end <= start:
        return SlackReport(start, 0, 0, ZERO, (), ())
    slack = bytes(block[start:end])
    nonzero = len(slack) - slack.count(0)
    if nonzero == 0:
        return SlackReport(start, len(slack), 0, ZERO, (), ())
    header = ondisk.HEADER.unpack_from(block)
    items = stale_items(block, nodesize, start, end)
    ptrs = stale_key_ptrs(block, sectorsize, header["generation"], start, end)
    # The first cell of the block's own grid is where its last removed entry was.
    own, size = (ptrs, KEY_PTR) if header["level"] > 0 else (items, ITEM)
    first = next(_grid(start, end, size), None)
    begins_stale = first is not None and any(entry.slot == first[0] for entry in own)
    return SlackReport(
        start, len(slack), nonzero, STALE if begins_stale else OTHER, tuple(items), tuple(ptrs)
    )
