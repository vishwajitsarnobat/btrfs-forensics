"""Open a Btrfs image for reading: superblock, feature gate, chunk map and node reader.

The steps follow the kernel's open_ctree, read-only:
1. select the superblock (superblock.select) and apply the incompat gate;
2. build the bootstrap map from the sys_chunk_array;
3. read the chunk root through it and take its chunk_tree_uuid, which every later tree block
   must carry (the kernel records it the same way, disk-io.c:3487-3489);
4. walk the chunk tree into the "current" chunk map, cross-checked against the sys_chunk_array.
Every later read goes through that map. Only this image's device is readable (the superblock's
dev_item); stripes on other devices are flagged missing.
"""

from dataclasses import dataclass, replace

from btrfska.substrate import chunks, ondisk, superblock
from btrfska.substrate.chunks import ChunkMap
from btrfska.substrate.image import ImageHandle
from btrfska.substrate.node import Expect, NodeContext, NodeReader, ValidatedNode
from btrfska.substrate.tree import walk


class NoValidSuperblock(Exception):
    """No superblock copy validates."""


class UnsupportedFormat(Exception):
    """The feature gate refused the filesystem."""

    def __init__(self, verdict: superblock.GateVerdict) -> None:
        super().__init__("unsupported incompat features: " + ", ".join(verdict.unsupported))
        self.verdict = verdict


@dataclass(frozen=True)
class Filesystem:
    selection: superblock.Selection
    verdict: superblock.GateVerdict
    chunk_root: ValidatedNode  # as read through the sys_chunk_array
    reader: NodeReader

    @property
    def fields(self) -> dict:
        return self.selection.selected.fields

    @property
    def chunk_map(self) -> ChunkMap:
        return self.reader.chunk_map

    @property
    def unsupported_format(self) -> bool:
        """True when the gate was overridden: everything derived must be flagged."""
        return self.verdict.status == "OVERRIDDEN"


def chunk_root_expect(fields: dict) -> Expect:
    return Expect(
        level=fields["chunk_root_level"],
        owner=ondisk.CHUNK_TREE_OBJECTID,
        generation=fields["chunk_root_generation"],
    )


def read_chunk_tree(reader: NodeReader, fields: dict, sys_chunks, sys_problems) -> ChunkMap:
    """The "current" chunk map: CHUNK_ITEMs of the chunk tree, plus any sys_chunk_array chunk
    the tree lacks (flagged). A sys_chunk_array chunk that differs from the tree's is reported."""
    problems = [f"sys_chunk_array: {p}" for p in sys_problems]
    found = []
    for visit in walk(reader, fields["chunk_root"], chunk_root_expect(fields)):
        node = visit.node
        problems += [
            f"chunk tree node {node.logical}: {p}" for p in (*node.problems, *visit.problems)
        ]
        if not node.valid or node.level:
            continue
        for item in node.items:
            if item.key.type == ondisk.ITEM_KEYS["CHUNK_ITEM"]:
                chunk = chunks.parse_chunk(
                    item.key.offset,
                    item.data,
                    sectorsize=fields["sectorsize"],
                    incompat=fields["incompat_flags"],
                    origin=f"chunk tree leaf {node.logical} slot {item.slot}",
                )
                found.append(chunk)
    in_tree = {chunk.logical: chunk for chunk in found}
    for chunk in sys_chunks:
        tree_chunk = in_tree.get(chunk.logical)
        if tree_chunk is None:
            problems.append(f"sys_chunk_array chunk {chunk.logical} is not in the chunk tree; kept")
            found.append(chunk)
        elif (tree_chunk.length, tree_chunk.type, tree_chunk.stripes, tree_chunk.sub_stripes) != (
            chunk.length,
            chunk.type,
            chunk.stripes,
            chunk.sub_stripes,
        ):
            problems.append(
                f"sys_chunk_array chunk {chunk.logical} differs from the chunk tree's; "
                "the chunk tree's is used"
            )
    return ChunkMap("current", found, reader.chunk_map.devices, problems)


def open_filesystem(img: ImageHandle, allow_unsupported: bool = False) -> Filesystem:
    """Raises NoValidSuperblock or UnsupportedFormat; damaged metadata is reported, not raised."""
    selection = superblock.read_superblock(img)
    if selection.selected is None:
        raise NoValidSuperblock("no valid superblock copy")
    fields = selection.selected.fields
    verdict = superblock.gate(fields, allow_unsupported=allow_unsupported)
    if verdict.refused:
        raise UnsupportedFormat(verdict)

    device = ondisk.DEV_ITEM.unpack_from(fields["dev_item"])
    sys_chunks, sys_problems = chunks.parse_sys_chunk_array(fields)
    bootstrap = ChunkMap("sys_chunk_array", sys_chunks, {device["devid"]: device["uuid"]})
    ctx = NodeContext.from_superblock(fields)
    chunk_root = NodeReader(img, bootstrap, ctx).read(
        fields["chunk_root"], chunk_root_expect(fields)
    )
    if chunk_root.valid:
        ctx = replace(ctx, chunk_tree_uuid=chunk_root.header["chunk_tree_uuid"])
    chunk_map = read_chunk_tree(NodeReader(img, bootstrap, ctx), fields, sys_chunks, sys_problems)
    return Filesystem(selection, verdict, chunk_root, NodeReader(img, chunk_map, ctx))
