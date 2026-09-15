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
"""

import argparse
import os
import struct
import sys
from pathlib import Path

from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb

IMAGES = Path(__file__).resolve().parents[1] / "images"
CHUNK = 1 << 20


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
        else:
            patches = flip_bytes(src, size, args.offsets)
        check_patches(size, patches)
        # "xb" is O_CREAT|O_EXCL: it fails on any existing path, including a dangling symlink.
        with open(dst, "xb") as out:
            write_patched(src, out, size, patches)
    print(f"{dst}: {args.op} {' '.join(str(o) for o in patches)}")


if __name__ == "__main__":
    main()
