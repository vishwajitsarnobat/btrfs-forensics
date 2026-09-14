"""Derive a damaged test image from a generated one (plan.md M1 task 9).

The source image is only read. The result is always a NEW file under the repo's images/
directory: an existing path (or symlink), a path outside images/, or any file named
sandbox.img is refused. Unchanged all-zero regions stay sparse.

  uv run python corpus/mutate.py SRC DST set-incompat-bit BIT
      set incompat bit 1<<BIT in every superblock copy and recompute each copy's csum
  uv run python corpus/mutate.py SRC DST zero-primary-sb
      zero the 4096-byte primary superblock at 64 KiB
"""

import argparse
import os
import struct
import sys
from pathlib import Path

from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb

IMAGES = Path(__file__).resolve().parents[1] / "images"
CHUNK = 1 << 20  # superblock offsets (64 KiB, 64 MiB) sit inside single chunks


def set_incompat_bit(src, size: int, bit: int) -> dict[int, bytes]:
    patches = {}
    for mirror in range(ondisk.SUPER_MIRROR_MAX):
        offset = ondisk.sb_offset(mirror)
        if offset + ondisk.SUPER_INFO_SIZE >= size:
            continue
        block = bytearray(os.pread(src.fileno(), ondisk.SUPER_INFO_SIZE, offset))
        if not sb.parse_copy(bytes(block), mirror).valid:
            sys.exit(f"mirror {mirror} of the source is not a valid superblock")
        field = ondisk.SUPERBLOCK.offset("incompat_flags")
        (flags,) = struct.unpack_from("<Q", block, field)
        struct.pack_into("<Q", block, field, flags | 1 << bit)
        csum_type = struct.unpack_from("<H", block, ondisk.SUPERBLOCK.offset("csum_type"))[0]
        block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
        block[: csum.csum_size(csum_type)] = csum.compute(csum_type, block[ondisk.CSUM_SIZE :])
        patches[offset] = bytes(block)
    return patches


def zero_primary_sb(src, size: int) -> dict[int, bytes]:
    return {ondisk.SUPER_INFO_OFFSET: bytes(ondisk.SUPER_INFO_SIZE)}


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
    args = parser.parse_args(argv)

    dst = checked_output(args.src, args.dst)
    # "xb" is O_CREAT|O_EXCL: it fails on any existing path, including a dangling symlink.
    with open(args.src, "rb") as src, open(dst, "xb") as out:
        size = os.fstat(src.fileno()).st_size
        if args.op == "zero-primary-sb":
            patches = zero_primary_sb(src, size)
        else:
            patches = set_incompat_bit(src, size, args.bit)
        position = 0
        while chunk := src.read(CHUNK):
            data = bytearray(chunk)
            for offset, block in patches.items():
                if position <= offset < position + len(data):
                    data[offset - position : offset - position + len(block)] = block
            if any(data):
                out.write(data)
            else:
                out.seek(len(data), os.SEEK_CUR)
            position += len(data)
        out.truncate(size)
    print(f"{dst}: {args.op} {' '.join(str(o) for o in patches)}")


if __name__ == "__main__":
    main()
