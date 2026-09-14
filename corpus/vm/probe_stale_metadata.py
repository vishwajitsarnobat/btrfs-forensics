#!/usr/bin/env python3
"""Count surviving (stale) Btrfs metadata in a raw image.

Reads the image strictly read-only and prints ONE line with four integers,
separated by single spaces, in this order (the columns of research.md §10.4):

  1. fsid_blocks    4 KiB-aligned blocks whose tree-block header carries this
                    filesystem's FSID at header offset +0x20. Blocks holding a
                    superblock copy (0x10000, 64 MiB, 256 GiB) are skipped,
                    because the superblock also has the FSID at +0x20.
  2. stale_blocks   The subset of (1) whose header generation (u64 LE at
                    +0x50) is LOWER than the primary superblock generation,
                    i.e. tree blocks from an older transaction that are no
                    longer part of the current trees (history / evidence).
  3. needle_copies  Byte-exact occurrences of NEEDLE anywhere in the image
                    (default b"small secret", the content of the deleted
                    inline file in the discard scenarios).
  4. nonzero_blocks 4 KiB-aligned blocks containing at least one non-zero
                    byte (whole image, superblocks included). A coarse
                    measure of how much was trimmed back to zeros.

Usage: probe_stale_metadata.py IMAGE [NEEDLE]

Only the Python standard library is used. The probe is 4 KiB-aligned
(sectorsize), so it also finds 16 KiB nodes, whose headers always start on
a 4 KiB boundary.
"""
import struct
import sys

BLOCK = 4096
SB_OFFSETS = (0x10000, 0x4000000, 0x4000000000)   # primary + two mirrors
CHUNK = 1024 * BLOCK                               # read 4 MiB at a time


def main():
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    path = sys.argv[1]
    needle = sys.argv[2].encode() if len(sys.argv) == 3 else b"small secret"

    fsid_blocks = stale_blocks = needle_copies = nonzero_blocks = 0
    zero = bytes(BLOCK)
    skip = set(off // BLOCK for off in SB_OFFSETS)

    with open(path, "rb") as f:                     # read-only open
        f.seek(SB_OFFSETS[0])
        sb = f.read(BLOCK)
        if sb[0x40:0x48] != b"_BHRfS_M":
            sys.exit(f"{path}: no btrfs superblock magic at 0x10000")
        fsid = sb[0x20:0x30]
        sb_gen = struct.unpack_from("<Q", sb, 0x48)[0]

        f.seek(0)
        blockno = 0
        tail = b""                  # carry-over so needles spanning reads count
        while True:
            buf = f.read(CHUNK)
            if not buf:
                break
            # needle search over tail+buf; the tail is shorter than the needle,
            # so no occurrence is counted twice
            data = tail + buf
            needle_copies += data.count(needle)
            tail = data[-(len(needle) - 1):] if len(needle) > 1 else b""

            for off in range(0, len(buf) - BLOCK + 1, BLOCK):
                blk = buf[off:off + BLOCK]
                if blk != zero:
                    nonzero_blocks += 1
                if blockno not in skip and blk[0x20:0x30] == fsid:
                    fsid_blocks += 1
                    if struct.unpack_from("<Q", blk, 0x50)[0] < sb_gen:
                        stale_blocks += 1
                blockno += 1

    print(fsid_blocks, stale_blocks, needle_copies, nonzero_blocks)


if __name__ == "__main__":
    main()
