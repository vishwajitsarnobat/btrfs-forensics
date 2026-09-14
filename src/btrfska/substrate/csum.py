"""Checksum dispatch for superblocks, tree blocks and data sectors.

Mirrors kernel v7.0 fs/btrfs/fs.c:44-62 btrfs_csum():
- crc32c:   ~crc32c(~0, data) stored as little-endian u32 (the standard CRC-32C value);
- xxhash64: XXH64 with seed 0, stored as little-endian u64;
- sha256:   the 32-byte digest;
- blake2b:  unkeyed BLAKE2b with a 32-byte digest (BLAKE2b-256, not a truncated BLAKE2b-512).
"""

import hashlib

import crc32c
import xxhash

from btrfska.substrate.ondisk import CSUM_SIZE, CSUM_TYPES

CRC32C = 0
XXHASH = 1
SHA256 = 2
BLAKE2 = 3


class UnknownCsumType(ValueError):
    """The csum_type is not one of the four the kernel defines."""

    def __init__(self, csum_type: int) -> None:
        super().__init__(f"unknown csum_type {csum_type}")
        self.csum_type = csum_type


def _entry(csum_type: int) -> tuple[str, int]:
    try:
        return CSUM_TYPES[csum_type]
    except KeyError:
        raise UnknownCsumType(csum_type) from None


def csum_name(csum_type: int) -> str:
    return _entry(csum_type)[0]


def csum_size(csum_type: int) -> int:
    return _entry(csum_type)[1]


def compute(csum_type: int, data) -> bytes:
    """The checksum of `data` (any bytes-like object) as stored on disk."""
    match csum_type:
        case 0:
            return crc32c.crc32c(data).to_bytes(4, "little")
        case 1:
            return xxhash.xxh64_intdigest(data).to_bytes(8, "little")
        case 2:
            return hashlib.sha256(data).digest()
        case 3:
            return hashlib.blake2b(data, digest_size=32).digest()
    raise UnknownCsumType(csum_type)


def block_csum_ok(csum_type: int, block) -> bool:
    """True if the csum stored at the start of a superblock or tree block matches its contents.

    The checksum covers everything after the 32-byte csum field; like the kernel, only the
    first csum_size bytes of that field are compared.
    """
    view = memoryview(block)
    return compute(csum_type, view[CSUM_SIZE:]) == bytes(view[: csum_size(csum_type)])
