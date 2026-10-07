"""Derive a damaged test image from a generated one (plan.md M1 task 9).

The source image is only read. The result is always a NEW file under the repo's images/
directory: an existing path (or symlink), a path outside images/, or any file named
sandbox.img is refused. Every patch is computed and validated before the output is created, so
a refused run leaves no file behind. Unchanged all-zero regions stay sparse.

  uv run python corpus/mutate.py SRC DST set-incompat-bit BIT
      set incompat bit 1<<BIT in every superblock copy and recompute each copy's csum
  uv run python corpus/mutate.py SRC DST zero-primary-sb
      zero the 4096-byte primary superblock at 64 KiB
  uv run python corpus/mutate.py SRC DST transplant-sb DONOR MIRROR GENERATION
      copy DONOR's superblock copy MIRROR into the same mirror slot of the output, with its
      generation set to GENERATION and its csum recomputed with the donor's csum type
      (a leftover copy of an earlier, different filesystem)
  uv run python corpus/mutate.py SRC DST flip-byte OFFSET [OFFSET ...]
      invert (XOR 0xFF) the byte at each physical OFFSET, checksums left stale
      (a corrupt tree-block copy; see corpus/manifest.tsv for which copies m1_badnode* hit)
  uv run python corpus/mutate.py SRC DST plant-slack [--message TEXT]
      hide TEXT in the slack of the current fs tree's root node and of its first leaf, in every
      physical copy, and recompute the tree-block checksums: data hidden in node slack as in
      Toolan & Humphries 2026, which no honest image contains (EXP-005). The source needs an fs
      tree with an internal node (m3_wide).
  uv run python corpus/mutate.py SRC DST lose-root-node
      invert one byte in every physical copy of the oldest root-tree node (level 1 or above) that
      still has a leaf on the image and is not the current root: that generation's root-tree
      leaves lose their parent, as if it had been overwritten (EXP-004 §6.8). Checksums are left
      stale, so the node no longer validates. The source needs a two-level root tree (m4_deep).
  uv run python corpus/mutate.py SRC DST lose-root-items TREE
      invert one byte in every physical copy of every superseded root-tree leaf that holds a
      ROOT_ITEM of tree TREE: afterwards no root tree of any generation names that tree, and
      only its own blocks can give it back (plan.md M5e-2). The source needs a deleted
      subvolume whose tree blocks survive (m5_delsubvol, tree 257).
  uv run python corpus/mutate.py SRC DST flip-data NAME MIRROR [NAME MIRROR ...]
      invert the first byte of the first data sector of the file NAME in the top directory of the
      current fs tree (its first uncompressed regular extent), in mirror MIRROR (1-based) or in
      `all` mirrors; the data checksum is left stale (plan.md M6a: one mirror is a sector the
      checksum repairs from the other copy, all mirrors a mismatch). The source needs those files
      in a data chunk with copies (m6_datacsum, data DUP).

Hiding techniques (plan.md M6d), each with the checksums recomputed in the source's csum type:
  uv run python corpus/mutate.py SRC DST plant-sb-reserved [--field FIELD] [--message TEXT]
      TEXT in the superblock's reserved[199] (0x264), or in a feature-gated FIELD
      (metadata_uuid, nr_global_roots, remap_root) whose incompat flag is clear, or in the
      padding of a backup root slot (backupN_unused_64, backupN_unused_8), every copy
  uv run python corpus/mutate.py SRC DST plant-sb-padding [--message TEXT]
      TEXT in the superblock's padding (0xDCB), every copy
  uv run python corpus/mutate.py SRC DST plant-chunk-array-slack [--message TEXT]
      TEXT at the end of the sys_chunk_array, behind its stale tail, every copy
  uv run python corpus/mutate.py SRC DST plant-backup-roots
      the oldest backup root slot copied over the slot of the superblock's generation
  uv run python corpus/mutate.py SRC DST plant-pre-sb [--message TEXT] [--offset N]
      TEXT at offset N of the first 64 KiB, or of the rest of the first MiB (no checksum)
  uv run python corpus/mutate.py SRC DST plant-inode-reserved [--message TEXT]
      TEXT (32 bytes) in the reserved bytes of the first regular file's INODE_ITEM
  uv run python corpus/mutate.py SRC DST plant-nsec
      16 bytes in that inode's four nanosecond fields, each value 10^9 or more (Göbel et al.)
  uv run python corpus/mutate.py SRC DST plant-string-item [--message TEXT]
      a STRING_ITEM (253) holding TEXT appended to the fs tree's last leaf (Toolan & Humphries)
  uv run python corpus/mutate.py SRC DST plant-file-slack NAME [--message TEXT] [--keep-csum]
      TEXT past the end of file NAME (top directory) in its last sector, every data copy, and
      its EXTENT_CSUM entry rewritten unless --keep-csum
  uv run python corpus/mutate.py SRC DST plant-device-slack [--message TEXT]
      TEXT past the last device extent, where no historical chunk was (Wani et al. 2020)

The planting functions also take where to plant, and how much, as keyword arguments whose
defaults are what the subcommands do (byte `at` of a field, the slack's `margin`, ...): EXP-021
plants every technique at its first and last byte and at its full capacity through them.
"""

import argparse
import os
import struct
import sys
from pathlib import Path

from btrfska.hiding.areas import intervals_minus, removed_stripes
from btrfska.scan.roots import discover_image
from btrfska.substrate import csum, items, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import parse_items, parse_key_ptrs
from btrfska.substrate.roots import find_root_set, resolve_tree, subvolumes
from btrfska.substrate.slack import slack_range
from btrfska.substrate.tree import walk

IMAGES = Path(__file__).resolve().parents[1] / "images"
CHUNK = 1 << 20
MESSAGE = "hidden in node slack, after Toolan & Humphries 2026"
MARGIN = 64  # bytes of slack left zero before the message: it does not start on an entry


def read_valid_copy(f, size: int, mirror: int, what: str) -> bytearray:
    offset = ondisk.sb_offset(mirror)
    if offset + ondisk.SUPER_INFO_SIZE >= size:
        sys.exit(f"mirror {mirror} of the {what} is not a valid superblock (beyond its end)")
    block = bytearray(os.pread(f.fileno(), ondisk.SUPER_INFO_SIZE, offset))
    if not sb.parse_copy(bytes(block), mirror).valid:
        sys.exit(f"mirror {mirror} of the {what} is not a valid superblock")
    return block


def put_u64(block: bytearray, name: str, value: int) -> None:
    struct.pack_into("<Q", block, ondisk.SUPERBLOCK.offset(name), value)


def recompute_csum(block: bytearray) -> bytes:
    """Rewrite the csum field with the block's own csum type."""
    csum_type = struct.unpack_from("<H", block, ondisk.SUPERBLOCK.offset("csum_type"))[0]
    block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
    block[: csum.csum_size(csum_type)] = csum.compute(csum_type, block[ondisk.CSUM_SIZE :])
    return bytes(block)


def set_incompat_bit(src, size: int, bit: int) -> dict[int, bytes]:
    patches = {}
    for mirror in range(ondisk.SUPER_MIRROR_MAX):
        offset = ondisk.sb_offset(mirror)
        if offset + ondisk.SUPER_INFO_SIZE >= size:
            continue
        block = read_valid_copy(src, size, mirror, "source")
        (flags,) = struct.unpack_from("<Q", block, ondisk.SUPERBLOCK.offset("incompat_flags"))
        put_u64(block, "incompat_flags", flags | 1 << bit)
        patches[offset] = recompute_csum(block)
    return patches


def zero_primary_sb(src, size: int) -> dict[int, bytes]:
    return {ondisk.SUPER_INFO_OFFSET: bytes(ondisk.SUPER_INFO_SIZE)}


def transplant_sb(src, size: int, donor: Path, mirror: int, generation: int) -> dict[int, bytes]:
    offset = ondisk.sb_offset(mirror)
    if offset + ondisk.SUPER_INFO_SIZE >= size:
        sys.exit(f"mirror {mirror} does not fit in the source")
    with open(donor, "rb") as f:
        block = read_valid_copy(f, os.fstat(f.fileno()).st_size, mirror, "donor")
    put_u64(block, "generation", generation)
    patched = recompute_csum(block)
    if not sb.parse_copy(patched, mirror).valid:
        sys.exit("the transplanted copy does not validate")
    return {offset: patched}


def flip_bytes(src, size: int, offsets: list[int]) -> dict[int, bytes]:
    patches = {}
    for offset in offsets:
        if not 0 <= offset < size:
            sys.exit(f"offset {offset} is outside the image (size {size})")
        (value,) = os.pread(src.fileno(), 1, offset)
        patches[offset] = bytes([value ^ 0xFF])
    return patches


def slack_targets(fs, leaf_only: bool = False) -> dict:
    """{"node": the current fs tree's root node, "leaf": its first leaf} (the leaf alone with
    `leaf_only`), the blocks plant-slack writes into."""
    root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), "fs")
    targets = {}
    for visit in walk(fs.reader, root.bytenr, root.expect()):
        kind = "node" if visit.node.level else "leaf"
        if visit.node.valid and kind not in targets and not (leaf_only and kind == "node"):
            targets[kind] = visit.node
    return targets


def plant_slack(
    path: Path, message: bytes, margin: int = MARGIN, from_end: bool = False,
    leaf_only: bool = False,
) -> dict[int, bytes]:  # fmt: skip
    """Patches that put `message` into the slack of the fs tree's root node and first leaf (the
    leaf alone with `leaf_only`), `margin` bytes after the slack's start, or before its end
    with `from_end`."""
    patches = {}
    with open_image(path) as img:
        fs = open_filesystem(img)
        ctx = fs.reader.ctx
        targets = slack_targets(fs, leaf_only)
        if set(targets) != ({"leaf"} if leaf_only else {"node", "leaf"}):
            sys.exit(f"{path}: the current fs tree has no internal node and leaf to plant in")
        for node in targets.values():
            for copy in node.copies:
                block = bytearray(img.mmap[copy.physical : copy.physical + ctx.nodesize])
                start, end = slack_range(block, ctx.nodesize)
                if end - start < margin + len(message) or margin < 0:
                    sys.exit(f"block {node.logical}: {end - start} bytes of slack is too little")
                first = end - margin - len(message) if from_end else start + margin
                block[first : first + len(message)] = message
                block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
                digest = csum.compute(ctx.csum_type, block[ondisk.CSUM_SIZE :])
                block[: len(digest)] = digest
                patches[copy.physical] = bytes(block)
    return patches


def lose_root_node(path: Path) -> tuple[dict[int, bytes], str]:
    """Patches that break every copy of the oldest root-tree node whose loss orphans a leaf.

    Root-tree leaves are shared between generations, so losing a node orphans only the children
    that no other root-tree node on the image points to. The node chosen is the oldest one that
    has such a child and is not the current root.
    """
    with open_image(path) as img:
        fs = open_filesystem(img)
        nodesize = fs.reader.ctx.nodesize
        index = discover_image(img, fs, full_sweep=True).index
        nodes = {}
        for i in range(index.nodes):
            bytenr, generation, level, owner = index.node(i)
            if owner == ondisk.ROOT_TREE_OBJECTID and level > 0:
                copies = index.copies(i)
                block = bytes(img.mmap[copies[0] : copies[0] + nodesize])
                children = {
                    (ptr.blockptr, ptr.generation)
                    for ptr in parse_key_ptrs(block, nodesize)[0]
                    if index.find(ptr.blockptr, ptr.generation, level - 1)
                }
                nodes[generation, bytenr] = (level, copies, children)
        for (generation, bytenr), (level, copies, children) in sorted(nodes.items()):
            elsewhere = set().union(*(c for key, (_, _, c) in nodes.items()
                                      if key != (generation, bytenr)))  # fmt: skip
            only_here = children - elsewhere
            if only_here and bytenr != fs.fields["root"]:
                where = ondisk.HEADER.size + 8  # inside the first key pointer
                patches = {p + where: bytes([img.mmap[p + where] ^ 0xFF]) for p in copies}
                lost = ", ".join(f"{child} generation {gen}" for child, gen in sorted(only_here))
                note = (f"root-tree node {bytenr} generation {generation} level {level}; "
                        f"children that no other node points to: {lost}")  # fmt: skip
                return patches, note
    sys.exit(f"{path}: no superseded root-tree node whose loss would orphan a child")


def lose_root_items(path: Path, tree_id: int) -> tuple[dict[int, bytes], str]:
    """Patches that break every copy of every root-tree leaf holding a ROOT_ITEM of `tree_id`.

    Afterwards no root tree of any generation names that tree: only its own blocks can give it
    back. A leaf is broken by one flipped byte inside its first item header, which fails its
    checksum; the ROOT_ITEMs of other trees in those leaves are lost with it.
    """
    with open_image(path) as img:
        fs = open_filesystem(img)
        nodesize = fs.reader.ctx.nodesize
        index = discover_image(img, fs, full_sweep=True).index
        patches, leaves = {}, []
        for i in range(index.nodes):
            bytenr, generation, level, owner = index.node(i)
            if owner != ondisk.ROOT_TREE_OBJECTID or level:
                continue
            copies = index.copies(i)
            block = bytes(img.mmap[copies[0] : copies[0] + nodesize])
            named = any(
                item.key.objectid == tree_id and item.key.type == ondisk.ITEM_KEYS["ROOT_ITEM"]
                for item in parse_items(block, nodesize)[0]
            )
            if named and bytenr != fs.fields["root"]:
                where = ondisk.HEADER.size + 8
                patches |= {p + where: bytes([img.mmap[p + where] ^ 0xFF]) for p in copies}
                leaves.append(f"{bytenr} generation {generation}")
    if not patches:
        sys.exit(f"{path}: no superseded root-tree leaf holds a ROOT_ITEM of tree {tree_id}")
    return patches, f"root-tree leaves that named tree {tree_id}: {', '.join(leaves)}"


def flip_data(path: Path, targets: list[tuple[str, str]]) -> tuple[dict[int, bytes], str]:
    """Patches that invert the first byte of each named file's first data sector, in the mirrors
    asked for. The file must be in the top directory of the current fs tree."""
    key = ondisk.ITEM_KEYS
    with open_image(path) as img:
        fs = open_filesystem(img)
        root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), "fs")
        names, extents = {}, {}
        for visit in walk(fs.reader, root.bytenr, root.expect()):
            for item in visit.node.items if visit.node.valid and visit.node.level == 0 else ():
                if item.key.type == key["INODE_REF"] and item.key.offset == 256:
                    for ref in items.inode_refs(item.data):
                        names[ref["name"]] = item.key.objectid
                elif item.key.type == key["EXTENT_DATA"] and item.key.objectid not in extents:
                    extent = items.file_extent(item.data)
                    if (extent["type"] == ondisk.FILE_EXTENT_REG and extent["disk_bytenr"]
                            and not extent["compression"]):  # fmt: skip
                        extents[item.key.objectid] = extent["disk_bytenr"] + extent["offset"]
        patches, done = {}, []
        for name, mirror in targets:
            if name not in names or names[name] not in extents:
                sys.exit(f"{path}: no file {name!r} with an uncompressed extent at the top")
            logical = extents[names[name]]
            copies = fs.chunk_map.copies(logical, 1)
            chosen = copies if mirror == "all" else [c for c in copies if str(c.mirror) == mirror]
            if not chosen:
                sys.exit(f"{path}: {name!r} at logical {logical} has no mirror {mirror}")
            for copy in chosen:
                patches[copy.physical] = bytes([img.mmap[copy.physical] ^ 0xFF])
            mirrors = ", ".join(str(c.mirror) for c in chosen)
            done.append(f"{name} at logical {logical}, mirror {mirrors} of {len(copies)}")
    return patches, "data bytes inverted: " + "; ".join(done)


# ---------------------------------------------------------------------------
# Hiding techniques (plan.md M6d): one subcommand each, checksums recomputed with the image's
# own csum type, so the hidden bytes sit in a block or superblock that still validates.
# ---------------------------------------------------------------------------
HIDDEN = b"hidden by corpus/mutate.py, plan.md M6d"
SB_FIELDS = {  # superblock byte ranges a hider writes to; the gated ones need their flag clear
    "reserved": (0x264, 0x32B, None),
    "metadata_uuid": (0x23B, 0x24B, "METADATA_UUID"),
    "nr_global_roots": (0x24B, 0x253, "EXTENT_TREE_V2"),
    "remap_root": (0x253, 0x264, "REMAP_TREE"),
    "padding": (0xDCB, 0x1000, None),
}
_ROOTS, _BACKUP = ondisk.SUPERBLOCK.offset("super_roots"), ondisk.ROOT_BACKUP
for _slot in range(ondisk.NUM_BACKUP_ROOTS):  # unused_64[4] and unused_8[10] of each backup slot
    _at = _ROOTS + _slot * _BACKUP.size
    SB_FIELDS[f"backup{_slot}_unused_64"] = (
        _at + _BACKUP.offset("num_devices") + 8,
        _at + _BACKUP.offset("tree_root_level"),
        None,
    )
    SB_FIELDS[f"backup{_slot}_unused_8"] = (
        _at + _BACKUP.offset("csum_root_level") + 1,
        _at + _BACKUP.size,
        None,
    )
PRE_SB_AREAS = (  # where plant-pre-sb writes: below 1 MiB, but not sector 0 or the superblock
    (512, ondisk.SUPER_INFO_OFFSET),
    (ondisk.SUPER_INFO_OFFSET + ondisk.SUPER_INFO_SIZE, 1 << 20),
)
NOTED = ("plant-inode-reserved", "plant-nsec", "plant-string-item", "plant-file-slack",
         "plant-device-slack")  # fmt: skip
NSEC_MESSAGE = b"\xa5hid\xa5den\xa5 in\xa5 ns"  # four distinct values, each >= 10^9


def each_superblock(src, size: int, edit) -> dict[int, bytes]:
    """Patches that apply `edit(block, fields)` to every valid superblock copy in the image and
    recompute each copy's checksum."""
    patches = {}
    for mirror in range(ondisk.SUPER_MIRROR_MAX):
        offset = ondisk.sb_offset(mirror)
        if offset + ondisk.SUPER_INFO_SIZE >= size:
            continue
        block = read_valid_copy(src, size, mirror, "source")
        edit(block, ondisk.SUPERBLOCK.unpack_from(block))
        patches[offset] = recompute_csum(block)
    return patches


def plant_sb_field(src, size: int, field: str, message: bytes, at: int = 0) -> dict[int, bytes]:
    """`message` from byte `at` of FIELD on, cut at the field's end, in every copy."""
    start, end, flag = SB_FIELDS[field]
    if not 0 <= at < end - start:
        sys.exit(f"byte {at} is outside {field} ({end - start} bytes)")

    def edit(block, fields):
        if flag and fields["incompat_flags"] & ondisk.INCOMPAT[flag]:
            sys.exit(f"incompat flag {flag} is set: {field} is in use, not spare")
        piece = message[: end - start - at]
        block[start + at : start + at + len(piece)] = piece

    return each_superblock(src, size, edit)


def chunk_array_free(block) -> int:
    """The first byte of the sys_chunk_array that neither the live array nor its stale tail
    uses (relative to the array's start)."""
    array = ondisk.SUPERBLOCK.offset("sys_chunk_array")
    used = ondisk.SUPERBLOCK.unpack_from(block)["sys_chunk_array_size"]
    tail = bytes(block[array + used : array + ondisk.SYSTEM_CHUNK_ARRAY_SIZE])
    return used + len(tail.rstrip(b"\0"))


def plant_chunk_array_slack(src, size: int, message: bytes, at: int | None = None):
    """`message` at the end of the 2048-byte array, behind whatever the array's tail holds; or
    from byte `at` of the array on, which must lie behind the tail."""
    array = ondisk.SUPERBLOCK.offset("sys_chunk_array")

    def edit(block, fields):
        if at is None:
            used = fields["sys_chunk_array_size"]
            stop = array + ondisk.SYSTEM_CHUNK_ARRAY_SIZE - MARGIN
            start = stop - len(message)
            if start < array + 2 * used:  # leave the live array and its stale tail alone
                sys.exit("the message does not fit behind the sys_chunk_array's tail")
        else:
            free = chunk_array_free(block)
            last = ondisk.SYSTEM_CHUNK_ARRAY_SIZE - 1
            if at < free or at + len(message) > last + 1:
                sys.exit(f"bytes {at}-{at + len(message) - 1} of the sys_chunk_array are not all "
                         f"free (free from {free} to {last})")  # fmt: skip
            start, stop = array + at, array + at + len(message)
        block[start:stop] = message

    return each_superblock(src, size, edit)


def plant_backup_roots(src, size: int, source: int | None = None) -> dict[int, bytes]:
    """Copy the oldest backup root slot (or slot `source`) over the one of the superblock's
    generation, as an edit that rolls the array back would."""
    base, length = ondisk.SUPERBLOCK.offset("super_roots"), ondisk.ROOT_BACKUP.size

    def edit(block, fields):
        roots = sb.backup_roots(fields)
        newest = [r for r in roots if r["tree_root_gen"] == fields["generation"]]
        if not newest or roots[0] is newest[0]:
            sys.exit("no older backup root slot to copy over the newest one")
        slot = roots[0]["slot"] if source is None else source
        if slot == newest[0]["slot"] or not 0 <= slot < ondisk.NUM_BACKUP_ROOTS:
            sys.exit(f"slot {slot} is not an older backup root slot")
        old, new = base + slot * length, base + newest[0]["slot"] * length
        block[new : new + length] = block[old : old + length]

    return each_superblock(src, size, edit)


def plant_pre_sb(src, size: int, message: bytes, offset: int) -> dict[int, bytes]:
    if not any(lo <= offset and offset + len(message) <= hi for lo, hi in PRE_SB_AREAS):
        sys.exit(f"offset {offset} is not inside the first 64 KiB after sector 0, nor in the "
                 "rest of the first MiB after the primary superblock")  # fmt: skip
    return {offset: message}


def rewrite_block(img, node, ctx, edit) -> dict[int, bytes]:
    """Patches that apply `edit(block)` to every physical copy of a tree block and recompute its
    checksum with the image's csum type."""
    patches = {}
    for copy in node.copies:
        block = bytearray(img.mmap[copy.physical : copy.physical + ctx.nodesize])
        edit(block)
        block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
        digest = csum.compute(ctx.csum_type, block[ondisk.CSUM_SIZE :])
        block[: len(digest)] = digest
        patches[copy.physical] = bytes(block)
    return patches


def fs_leaves(fs, tree: str | int = "fs"):
    root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), tree)
    for visit in walk(fs.reader, root.bytenr, root.expect()):
        if visit.node.valid and visit.node.level == 0:
            yield visit.node


def first_file_inode(fs):
    """The first leaf holding an INODE_ITEM of a regular file, and that item: in the top-level
    fs tree, else in the subvolumes in id order."""
    subvols, _ = subvolumes(fs.reader, find_root_set(fs.fields, "current"))
    for tree in ["fs", *(sv.id for sv in subvols if sv.id != ondisk.FS_TREE_OBJECTID and sv.root)]:
        for node in fs_leaves(fs, tree):
            for item in node.items:
                if item.key.type == ondisk.ITEM_KEYS["INODE_ITEM"] and item.key.objectid > 256:
                    if items.inode_item(item.data)["mode"] & 0o170000 == 0o100000:
                        return node, item
    sys.exit("no subvolume of the current state has a regular file")


def plant_inode_reserved(path: Path, message: bytes, at: int = 0) -> tuple[dict[int, bytes], str]:
    """`message` from byte `at` of the 32 reserved bytes on, cut at their end."""
    if not 0 <= at < 32:
        sys.exit(f"byte {at} is outside the 32 reserved bytes")
    start = ondisk.INODE_ITEM.offset("sequence") + 8
    piece = message[: 32 - at]
    with open_image(path) as img:
        fs = open_filesystem(img)
        node, item = first_file_inode(fs)
        first = ondisk.HEADER.size + item.offset + start + at

        def edit(block):
            block[first : first + len(piece)] = piece

        note = f"inode {item.key.objectid} in leaf {node.logical} slot {item.slot}"
        return rewrite_block(img, node, fs.reader.ctx, edit), note


def plant_nsec(path: Path, message: bytes, at: int = 0) -> tuple[dict[int, bytes], str]:
    """`message` into the four nanosecond fields, read as 16 bytes (4 per field, atime, ctime,
    mtime, otime), from byte `at` on; the other bytes of the fields are kept."""
    if not message or not 0 <= at <= 16 - len(message):
        sys.exit("the nanosecond message must fit the 16 bytes of the four fields, 4 per field")
    names = ("atime_nsec", "ctime_nsec", "mtime_nsec", "otime_nsec")
    with open_image(path) as img:
        fs = open_filesystem(img)
        node, item = first_file_inode(fs)
        base = ondisk.HEADER.size + item.offset

        def edit(block):
            for i, byte in enumerate(message, at):
                block[base + ondisk.INODE_ITEM.offset(names[i // 4]) + i % 4] = byte

        note = f"inode {item.key.objectid} in leaf {node.logical} slot {item.slot}"
        return rewrite_block(img, node, fs.reader.ctx, edit), note


def plant_string_item(path: Path, message: bytes) -> tuple[dict[int, bytes], str]:
    """A STRING_ITEM appended to the last leaf of the fs tree, as Toolan & Humphries 2026 §3.6
    describe: nritems + 1, a 25-byte item header after the last one, the payload just below the
    lowest item data offset. Its key sorts after the leaf's last key, so the leaf stays ordered
    and no parent key changes."""
    header, item_size = ondisk.HEADER.size, ondisk.ITEM.size
    with open_image(path) as img:
        fs = open_filesystem(img)
        leaves = list(fs_leaves(fs))
        if not leaves:
            sys.exit("the current fs tree has no leaf")
        node = leaves[-1]
        last = node.items[-1]
        free = min(i.offset for i in node.items) - (len(node.items) + 1) * item_size
        if free < len(message):
            sys.exit(f"leaf {node.logical} has {free} free bytes; the message needs {len(message)}")
        offset = min(i.offset for i in node.items) - len(message)
        key_offset = last.key.offset + 1 if last.key.type == 253 else 0
        nritems = ondisk.HEADER.offset("nritems")

        def edit(block):
            slot = len(node.items)
            struct.pack_into("<I", block, nritems, slot + 1)
            struct.pack_into("<QBQII", block, header + slot * item_size, last.key.objectid,
                             253, key_offset, offset, len(message))  # fmt: skip
            block[header + offset : header + offset + len(message)] = message

        new_key = f"({last.key.objectid} 253 {key_offset})"
        note = f"leaf {node.logical} slot {len(node.items)}, key {new_key}"
        return rewrite_block(img, node, fs.reader.ctx, edit), note


def plant_file_slack(path: Path, name: str, message: bytes, keep_csum: bool, at: int = 0):
    """`message` past the end of file NAME (top directory of the current fs tree) in its last
    sector, `at` bytes after the end, in every copy; unless `keep_csum`, the sector's
    EXTENT_CSUM entry is recomputed and the csum-tree leaf rewritten (Göbel et al. 2024 §3.2)."""
    key = ondisk.ITEM_KEYS
    with open_image(path) as img:
        fs = open_filesystem(img)
        ctx = fs.reader.ctx
        ss = ctx.sectorsize
        names, sizes, logical = {}, {}, None
        for node in fs_leaves(fs):
            for item in node.items:
                if item.key.type == key["INODE_REF"] and item.key.offset == 256:
                    for ref in items.inode_refs(item.data):
                        names[ref["name"]] = item.key.objectid
                elif item.key.type == key["INODE_ITEM"]:
                    sizes[item.key.objectid] = items.inode_item(item.data)["size"]
        if name not in names:
            sys.exit(f"{path}: no file {name!r} in the top directory")
        objectid = names[name]
        size = sizes[objectid]
        if not size % ss or at < 0 or at + len(message) > ss - size % ss:
            sys.exit(f"{name!r}: {ss - size % ss if size % ss else 0} bytes past the end; "
                     f"the message needs {at + len(message)}")  # fmt: skip
        sector = (size - 1) // ss * ss
        for node in fs_leaves(fs):
            for item in node.items:
                if (item.key.objectid, item.key.type) != (objectid, key["EXTENT_DATA"]):
                    continue
                extent = items.file_extent(item.data)
                covers = item.key.offset <= sector < item.key.offset + extent["num_bytes"]
                if (extent["type"] == ondisk.FILE_EXTENT_REG and not extent["compression"]
                        and extent["disk_bytenr"] and covers):  # fmt: skip
                    logical = extent["disk_bytenr"] + extent["offset"] + sector - item.key.offset
        if logical is None:
            sys.exit(f"{name!r}: its last sector is not in an uncompressed regular extent")
        tail = size % ss
        patches, data = {}, None
        for copy in fs.chunk_map.copies(logical, ss):
            data = bytearray(img.mmap[copy.physical : copy.physical + ss])
            data[tail + at : tail + at + len(message)] = message
            patches[copy.physical] = bytes(data)
        note = f"{name} (inode {objectid}, size {size}): sector at logical {logical}"
        if keep_csum:
            return patches, note + ", data checksum left as it was"
        size_ = csum.csum_size(ctx.csum_type)
        root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), "csum")
        for visit in walk(fs.reader, root.bytenr, root.expect()):
            node = visit.node
            if not node.valid or node.level:
                continue
            for item in node.items:
                if item.key.type != key["EXTENT_CSUM"]:
                    continue
                start, count = item.key.offset, item.size // size_
                if start <= logical < start + count * ss:
                    at = ondisk.HEADER.size + item.offset + (logical - start) // ss * size_
                    digest = csum.compute(ctx.csum_type, bytes(data))[:size_]

                    def edit(block, at=at, digest=digest):
                        block[at : at + size_] = digest

                    patches |= rewrite_block(img, node, ctx, edit)
                    return patches, note + f", EXTENT_CSUM in csum-tree leaf {node.logical}"
        sys.exit(f"{name!r}: no EXTENT_CSUM covers logical {logical}")


def device_free(img, fs) -> tuple[list[tuple[int, int]], int, int]:
    """([start, end) pieces past this device's last device extent that no historical chunk and
    no superblock slot explains, the last extent's end, the device's end)."""
    device = ondisk.DEV_ITEM.unpack_from(fs.fields["dev_item"])
    root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), "dev")
    last = 1 << 20
    for visit in walk(fs.reader, root.bytenr, root.expect()):
        for item in visit.node.items if visit.node.valid and not visit.node.level else ():
            if (item.key.type, item.key.objectid) == (
                ondisk.ITEM_KEYS["DEV_EXTENT"],
                device["devid"],
            ):
                length = ondisk.DEV_EXTENT.unpack_from(item.data)["length"]
                last = max(last, item.key.offset + length)
    end = min(device["total_bytes"], img.size)
    # Not where a removed chunk was, nor in a superblock slot: the bytes must be unexplained.
    maps = [entry.chunk_map for entry in discover_image(img, fs).discovery.chunk_maps]
    cut = removed_stripes(maps, device["devid"]) + [
        (slot, slot + ondisk.SUPER_INFO_SIZE)
        for slot in map(ondisk.sb_offset, range(ondisk.SUPER_MIRROR_MAX))
    ]
    free, _ = intervals_minus([(last, end)], cut)
    return free, last, end


def plant_device_slack(path: Path, message: bytes, at: int | None = None):
    """`message` halfway between this device's last device extent and its end (Wani et al. 2020,
    volume slack), or at image offset `at`, which must lie wholly in what device_free gives."""
    with open_image(path) as img:
        fs = open_filesystem(img)
        devid = ondisk.DEV_ITEM.unpack_from(fs.fields["dev_item"])["devid"]
        free, last, end = device_free(img, fs)
        note = f"devid {devid}: last device extent ends at {last}, device at {end}"
        if at is not None:
            if not any(lo <= at and at + len(message) <= hi for lo, hi in free):
                sys.exit(f"bytes {at}-{at + len(message) - 1} are not all past the last device "
                         "extent, outside superblock slots and historical chunks")  # fmt: skip
            return {at: message}, note
        lo, hi = max(free, key=lambda piece: piece[1] - piece[0], default=(0, 0))
        offset = (lo + (hi - lo) // 2) // 4096 * 4096
        if hi - lo < 2 * 4096 + len(message):
            sys.exit(f"no room past the last device extent (ends at {last}, device {end})")
        return {offset: message}, note


def check_patches(size: int, patches: dict[int, bytes]) -> None:
    for offset, block in patches.items():
        if offset < 0 or offset + len(block) > size:
            sys.exit(f"patch at {offset} (+{len(block)}) extends beyond the image end ({size})")


def write_patched(src, out, size: int, patches: dict[int, bytes], chunk: int = CHUNK) -> None:
    """Copy src to out chunk by chunk, applying each patch to the part inside each chunk.

    A patch may straddle chunk boundaries; each chunk keeps its exact length.
    """
    src.seek(0)
    position = 0
    while data := bytearray(src.read(chunk)):
        end = position + len(data)
        for offset, block in patches.items():
            lo, hi = max(offset, position), min(offset + len(block), end)
            if lo < hi:
                data[lo - position : hi - position] = block[lo - offset : hi - offset]
        assert len(data) == end - position
        if data.count(0) != len(data):  # any(data), without a Python loop over every byte
            out.write(data)
        else:
            out.seek(len(data), os.SEEK_CUR)
        position = end
    out.truncate(size)


def checked_output(src: Path, dst: Path) -> Path:
    if dst.name == "sandbox.img":
        sys.exit("refusing to write a file named sandbox.img")
    resolved = dst.parent.resolve() / dst.name
    if not resolved.is_relative_to(IMAGES.resolve()):  # images/ may be a symlink
        sys.exit(f"output must be under images/ ({IMAGES})")
    if resolved == src.resolve():
        sys.exit("output must differ from the source")
    return resolved


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("src", type=Path)
    parser.add_argument("dst", type=Path)
    ops = parser.add_subparsers(dest="op", required=True)
    ops.add_parser("zero-primary-sb")
    bit = ops.add_parser("set-incompat-bit")
    bit.add_argument("bit", type=int, choices=range(64), metavar="BIT")
    transplant = ops.add_parser("transplant-sb")
    transplant.add_argument("donor", type=Path)
    transplant.add_argument("mirror", type=int, choices=range(ondisk.SUPER_MIRROR_MAX))
    transplant.add_argument("generation", type=int)
    flip = ops.add_parser("flip-byte")
    flip.add_argument("offsets", type=int, nargs="+", metavar="OFFSET")
    ops.add_parser("lose-root-node")
    items = ops.add_parser("lose-root-items")
    items.add_argument("tree", type=int, metavar="TREE")
    data = ops.add_parser("flip-data")
    data.add_argument("targets", nargs="+", metavar="NAME MIRROR")
    plant = ops.add_parser("plant-slack")
    plant.add_argument("--message", default=MESSAGE)
    field = ops.add_parser("plant-sb-reserved")
    field.add_argument("--field", choices=[f for f in SB_FIELDS if f != "padding"],
                       default="reserved")  # fmt: skip
    for name in ("plant-sb-reserved", "plant-sb-padding", "plant-chunk-array-slack",
                 "plant-pre-sb", "plant-inode-reserved", "plant-string-item",
                 "plant-file-slack", "plant-device-slack"):  # fmt: skip
        sub = field if name == "plant-sb-reserved" else ops.add_parser(name)
        sub.add_argument("--message", default=HIDDEN.decode())
        if name == "plant-pre-sb":
            sub.add_argument("--offset", type=int, default=0x8000)
        if name == "plant-file-slack":
            sub.add_argument("name", metavar="NAME")
            sub.add_argument("--keep-csum", action="store_true")
    ops.add_parser("plant-nsec")
    ops.add_parser("plant-backup-roots")
    args = parser.parse_args(argv)

    dst = checked_output(args.src, args.dst)
    with open(args.src, "rb") as src:
        size = os.fstat(src.fileno()).st_size
        if args.op == "zero-primary-sb":
            patches = zero_primary_sb(src, size)
        elif args.op == "set-incompat-bit":
            patches = set_incompat_bit(src, size, args.bit)
        elif args.op == "transplant-sb":
            patches = transplant_sb(src, size, args.donor, args.mirror, args.generation)
        elif args.op == "plant-slack":
            patches = plant_slack(args.src, args.message.encode())
        elif args.op == "lose-root-node":
            patches, note = lose_root_node(args.src)
        elif args.op == "lose-root-items":
            patches, note = lose_root_items(args.src, args.tree)
        elif args.op == "flip-data":
            if len(args.targets) % 2:
                sys.exit("flip-data takes pairs of NAME MIRROR")
            pairs = list(zip(args.targets[::2], args.targets[1::2], strict=True))
            patches, note = flip_data(args.src, pairs)
        elif args.op == "plant-sb-reserved":
            patches = plant_sb_field(src, size, args.field, args.message.encode())
        elif args.op == "plant-sb-padding":
            patches = plant_sb_field(src, size, "padding", args.message.encode())
        elif args.op == "plant-chunk-array-slack":
            patches = plant_chunk_array_slack(src, size, args.message.encode())
        elif args.op == "plant-backup-roots":
            patches = plant_backup_roots(src, size)
        elif args.op == "plant-pre-sb":
            patches = plant_pre_sb(src, size, args.message.encode(), args.offset)
        elif args.op == "plant-inode-reserved":
            patches, note = plant_inode_reserved(args.src, args.message.encode())
        elif args.op == "plant-nsec":
            patches, note = plant_nsec(args.src, NSEC_MESSAGE)
        elif args.op == "plant-string-item":
            patches, note = plant_string_item(args.src, args.message.encode())
        elif args.op == "plant-file-slack":
            patches, note = plant_file_slack(
                args.src, args.name, args.message.encode(), args.keep_csum
            )
        elif args.op == "plant-device-slack":
            patches, note = plant_device_slack(args.src, args.message.encode())
        else:
            patches = flip_bytes(src, size, args.offsets)
        check_patches(size, patches)
        # "xb" is O_CREAT|O_EXCL: it fails on any existing path, including a dangling symlink.
        with open(dst, "xb") as out:
            write_patched(src, out, size, patches)
    print(f"{dst}: {args.op} {' '.join(str(o) for o in patches)}")
    if args.op in ("lose-root-node", "lose-root-items", "flip-data", *NOTED):
        print(note)


if __name__ == "__main__":
    main()
