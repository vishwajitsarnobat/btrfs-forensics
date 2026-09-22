"""Historical chunk maps: what superseded chunk-tree and dev-tree blocks say (plan.md M5a).

A balance gives every chunk a new logical address and removes the old chunks; the blocks and the
file data of older states stay where the old chunks were, and the current chunk map no longer
names them. The chunk-tree blocks that did are still on the disk. Old-root discovery
(scan/roots.py) walks every surviving chunk-tree root through its block index; this module holds
what is done with the items it finds, as pure functions of parsed items, so it can be tested on
forged input:

- `HistoricalMap`: the map of one chunk-tree root, named `historical:GEN@BYTENR`;
- `parse_dev_extents`: the dev tree's record of the same mapping from the other side, (devid,
  physical) to (chunk logical, length) (btrfs_tree.h btrfs_dev_extent; the kernel writes one per
  stripe in btrfs_alloc_dev_extent, volumes.c);
- `witnesses`: for every stripe of a map, how many scanned dev-tree leaves hold a DEV_EXTENT that
  agrees with it;
- `from_dev_extents`: a map assembled from DEV_EXTENTs alone, for chunks whose CHUNK_ITEM did not
  survive.

A DEV_EXTENT does not record the chunk's profile. `from_dev_extents` accepts a chunk only when
that cannot matter: a BLOCK_GROUP_ITEM of the same address names a single or mirrored profile and
the same length, or there is none and the filesystem has one device, where every stripe is a full
copy (SINGLE or DUP). Everything else is kept as a rejected chunk with the reason. A stripe order
is never guessed. No map made here is merged into another or into the current map.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from btrfska.substrate import ondisk
from btrfska.substrate.chunks import (
    BG,
    PROFILE_MASK,
    PROFILES,
    Chunk,
    ChunkMap,
    Stripe,
    stripe_size,
)
from btrfska.substrate.node import Item

K = ondisk.ITEM_KEYS
DEV_EXTENTS = "dev_extents"  # the name of the map `from_dev_extents` builds
_MIRRORED = BG["DUP"] | BG["RAID1"] | BG["RAID1C3"] | BG["RAID1C4"]
_NO_UUID = bytes(16)


def map_name(generation: int, bytenr: int) -> str:
    return f"historical:{generation}@{bytenr}"


@dataclass(frozen=True)
class DevExtent:
    devid: int
    physical: int
    chunk_offset: int  # the chunk's logical address
    length: int
    leaf: int  # logical address and generation of the dev-tree leaf holding the item
    generation: int


@dataclass(frozen=True)
class BlockGroup:
    logical: int
    length: int
    flags: int
    generation: int  # of the leaf holding the item


@dataclass(frozen=True)
class HistoricalMap:
    name: str
    kind: str  # historical (a chunk-tree root) or dev_extents
    chunk_map: ChunkMap
    root: tuple[int, int, int] | None = None  # (bytenr, generation, level) of the chunk root
    known_as: tuple[str, ...] = ()  # backup:GEN sources naming that root
    blocks: int = 0  # distinct chunk-tree blocks found under the root
    missing: int = 0  # referenced but not found: the map may lack chunks
    witnesses: dict = field(default_factory=dict)  # (chunk logical, stripe index) -> leaves

    @property
    def generation(self) -> int | None:
        return None if self.root is None else self.root[1]


def parse_dev_extents(items: Iterable[Item], leaf: int, generation: int) -> list[DevExtent]:
    """The DEV_EXTENT items of one dev-tree leaf. A payload of another size is skipped."""
    found = []
    for item in items:
        if item.key.type != K["DEV_EXTENT"] or len(item.data) != ondisk.DEV_EXTENT.size:
            continue
        fields = ondisk.DEV_EXTENT.unpack_from(item.data)
        found.append(
            DevExtent(item.key.objectid, item.key.offset, fields["chunk_offset"],
                      fields["length"], leaf, generation)
        )  # fmt: skip
    return found


def parse_block_groups(items: Iterable[Item], generation: int) -> list[BlockGroup]:
    found = []
    for item in items:
        if item.key.type != K["BLOCK_GROUP_ITEM"] or len(item.data) != ondisk.BLOCK_GROUP_ITEM.size:
            continue
        flags = ondisk.BLOCK_GROUP_ITEM.unpack_from(item.data)["flags"]
        found.append(BlockGroup(item.key.objectid, item.key.offset, flags, generation))
    return found


def witnesses(chunk_map: ChunkMap, dev_extents: Sequence[DevExtent]) -> dict[tuple[int, int], int]:
    """(chunk logical, stripe index) -> the number of dev-tree leaves with an agreeing DEV_EXTENT.

    Agreeing: the same device and physical offset, naming this chunk's logical address, with the
    length one stripe of the chunk takes. Rejected chunks are counted too: what a second witness
    says about a chunk item that failed a check is evidence as well.
    """
    leaves: dict[tuple[int, int, int, int], set[int]] = {}
    for extent in dev_extents:
        key = (extent.devid, extent.physical, extent.chunk_offset, extent.length)
        leaves.setdefault(key, set()).add(extent.leaf)
    return {
        (chunk.logical, index): len(
            leaves.get((stripe.devid, stripe.offset, chunk.logical, stripe_size(chunk)), ())
        )
        for chunk in (*chunk_map.chunks, *chunk_map.rejected)
        for index, stripe in enumerate(chunk.stripes)
    }


def _overlap(extents: list[tuple[int, int, int]]) -> bool:
    by_device = sorted(extents)
    return any(
        a[0] == b[0] and b[1] < a[1] + a[2] for a, b in zip(by_device, by_device[1:], strict=False)
    )


def _from_group(
    logical: int,
    extents: list[tuple[int, int, int]],
    group: BlockGroup | None,
    *,
    num_devices: int,
    devices: dict[int, bytes],
    sectorsize: int,
    together: bool = True,
) -> Chunk:
    """One chunk from the distinct (devid, physical, length) DEV_EXTENTs naming `logical`.

    `together`: some one dev-tree leaf holds every one of them. Two extents that never appear
    in the same leaf may be two chunks that had this address at different times, not two copies
    of one; such a pair is never presented as mirrors."""
    lengths = {length for _, _, length in extents}
    stripes = tuple(
        Stripe(devid, physical, devices.get(devid, _NO_UUID)) for devid, physical, _ in extents
    )
    origin = f"{len(extents)} DEV_EXTENT(s)"
    length = min(lengths)
    problems = []
    if len(lengths) > 1:
        problems.append(f"device extents of different lengths {sorted(lengths)}")
    if not length or length % sectorsize or logical % sectorsize:
        problems.append(f"logical {logical} or length {length} not aligned to {sectorsize}")
    if logical + length >= 1 << 64 or length >= 1 << 63:
        problems.append(f"logical {logical} + length {length} overflows")
    if _overlap(extents):
        problems.append("device extents overlap each other")
    if len(extents) > 1 and not together:
        problems.append(
            "no dev-tree leaf holds these device extents together: they may be two chunks that "
            "had this address at different times, not the copies of one"
        )
    if group is not None:
        origin += f" and BLOCK_GROUP_ITEM of generation {group.generation}"
        type_, profile = group.flags, group.flags & PROFILE_MASK
        if profile not in PROFILES:
            problems.append(f"block group profile flags {profile:#x} are not one profile")
        elif profile and not profile & _MIRRORED and (profile != BG["RAID0"] or len(extents) > 1):
            problems.append(
                f"{PROFILES[profile][0]} block group: a DEV_EXTENT does not record the stripe order"
            )
        elif len(extents) > PROFILES[profile][1]:
            problems.append(
                f"{len(extents)} device extents for a {PROFILES[profile][0]} block group: the "
                "address was reused, or the extents belong to different chunks"
            )
        if group.length != length and not problems:
            problems.append(f"block group length {group.length} != device extent length {length}")
    elif num_devices != 1:
        type_ = 0
        problems.append("no BLOCK_GROUP_ITEM and more than one device: the profile is unknown")
    else:
        type_ = BG["DUP"] if len(extents) == 2 else 0
        if len(extents) > 2:
            problems.append(
                f"{len(extents)} device extents on a one-device filesystem: the address was "
                "reused, or the extents belong to different chunks"
            )
    return Chunk(logical, length, type_, stripes, 1, origin, tuple(problems))


def from_dev_extents(
    dev_extents: Sequence[DevExtent],
    block_groups: Sequence[BlockGroup],
    *,
    num_devices: int,
    devices: dict[int, bytes],
    sectorsize: int,
) -> ChunkMap:
    """The `dev_extents` map. Never raises on content; what it cannot use is a rejected chunk."""
    groups: dict[int, set[tuple[int, int, int]]] = {}
    by_leaf: dict[int, dict[int, set]] = {}  # chunk -> leaf -> the extents that leaf holds
    for extent in dev_extents:
        placement = (extent.devid, extent.physical, extent.length)
        groups.setdefault(extent.chunk_offset, set()).add(placement)
        by_leaf.setdefault(extent.chunk_offset, {}).setdefault(extent.leaf, set()).add(placement)
    newest: dict[int, BlockGroup] = {}
    for group in block_groups:
        if group.logical not in newest or group.generation > newest[group.logical].generation:
            newest[group.logical] = group
    chunks = [
        _from_group(logical, sorted(extents), newest.get(logical), num_devices=num_devices,
                    devices=devices, sectorsize=sectorsize,
                    together=any(held == extents for held in by_leaf[logical].values()))
        for logical, extents in sorted(groups.items())
    ]  # fmt: skip
    return ChunkMap(DEV_EXTENTS, chunks, devices)


def order_for(
    generation: int, own: str | None, maps: Sequence[tuple[str, int | None, ChunkMap]]
) -> list[ChunkMap]:
    """The maps a read of a state consults, in order (plan.md M5a, decision 3).

    `maps` holds (name, generation, map) of every map of the image; the current map has the
    highest generation and the `dev_extents` map none. `own` names the state's map; without one,
    the newest map not newer than `generation` takes its place. Then the maps newer than it,
    oldest first. The caller appends the `dev_extents` map.
    """
    dated = sorted((m for m in maps if m[1] is not None), key=lambda m: (m[1], m[0]))
    first = next((m for m in dated if m[0] == own), None)
    if first is None:
        older = [m for m in dated if m[1] <= generation]
        first = older[-1] if older else (dated[0] if dated else None)
    if first is None:
        return []
    return [first[2]] + [m[2] for m in dated if m[1] > first[1]]
