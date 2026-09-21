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
"""

import argparse
import os
import struct
import sys
from pathlib import Path

from btrfska.scan.roots import discover_image
from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import parse_key_ptrs
from btrfska.substrate.roots import find_root_set, resolve_tree
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


def plant_slack(path: Path, message: bytes) -> dict[int, bytes]:
    """Patches that put `message` into the slack of the fs tree's root node and first leaf."""
    patches = {}
    with open_image(path) as img:
        fs = open_filesystem(img)
        ctx = fs.reader.ctx
        root = resolve_tree(fs.reader, find_root_set(fs.fields, "current"), "fs")
        targets = {}
        for visit in walk(fs.reader, root.bytenr, root.expect()):
            kind = "node" if visit.node.level else "leaf"
            if visit.node.valid and kind not in targets:
                targets[kind] = visit.node
        if set(targets) != {"node", "leaf"}:
            sys.exit(f"{path}: the current fs tree has no internal node and leaf to plant in")
        for node in targets.values():
            for copy in node.copies:
                block = bytearray(img.mmap[copy.physical : copy.physical + ctx.nodesize])
                start, end = slack_range(block, ctx.nodesize)
                if end - start < MARGIN + len(message):
                    sys.exit(f"block {node.logical}: {end - start} bytes of slack is too little")
                block[start + MARGIN : start + MARGIN + len(message)] = message
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
        if any(data):
            out.write(data)
        else:
            out.seek(len(data), os.SEEK_CUR)
        position = end
    out.truncate(size)


def checked_output(src: Path, dst: Path) -> Path:
    if dst.name == "sandbox.img":
        sys.exit("refusing to write a file named sandbox.img")
    resolved = dst.parent.resolve() / dst.name
    if not resolved.is_relative_to(IMAGES):
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
    plant = ops.add_parser("plant-slack")
    plant.add_argument("--message", default=MESSAGE)
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
        else:
            patches = flip_bytes(src, size, args.offsets)
        check_patches(size, patches)
        # "xb" is O_CREAT|O_EXCL: it fails on any existing path, including a dangling symlink.
        with open(dst, "xb") as out:
            write_patched(src, out, size, patches)
    print(f"{dst}: {args.op} {' '.join(str(o) for o in patches)}")
    if args.op == "lose-root-node":
        print(note)


if __name__ == "__main__":
    main()
