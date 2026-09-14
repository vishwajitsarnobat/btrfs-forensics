"""Checksum dispatch: published vectors, sandbox.img superblocks, and the generated images."""

import hashlib
import json
import random
from pathlib import Path

import pytest

from btrfska.substrate import csum, ondisk
from btrfska.substrate.image import open_image

GROUND_TRUTH = json.loads((Path(__file__).parent / "ground_truth" / "sandbox.json").read_text())

# RFC 3720 appendix B.4 CRC32c examples, plus the canonical "123456789" check value.
PDU = bytes.fromhex(
    "01c00000000000000000000000000000"
    "14000000000004000000001400000018"
    "28000000000000000200000000000000"
)
CRC32C_VECTORS = [
    (b"\x00" * 32, 0x8A9136AA),
    (b"\xff" * 32, 0x62A8AB43),
    (bytes(range(32)), 0x46DD794E),
    (bytes(range(31, -1, -1)), 0x113FDB5C),
    (PDU, 0xD9963A56),
    (b"123456789", 0xE3069283),
]


@pytest.mark.parametrize(("data", "crc"), CRC32C_VECTORS)
def test_crc32c_rfc3720_vectors(data, crc):
    # The kernel stores ~crc32c(~0, data) as little-endian u32 (fs/btrfs/fs.c:48).
    assert csum.compute(csum.CRC32C, data) == crc.to_bytes(4, "little")


def test_xxhash64_vectors():
    # xxHash reference sanity values, seed 0; stored as little-endian u64 (fs.c:51).
    assert csum.compute(csum.XXHASH, b"") == (0xEF46DB3751D8E999).to_bytes(8, "little")
    assert csum.compute(csum.XXHASH, b"abc") == (0x44BC2CF5AD770999).to_bytes(8, "little")


def test_sha256_vector():
    # FIPS 180-2 appendix B.1
    assert csum.compute(csum.SHA256, b"abc").hex() == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_blake2b_is_blake2b_256_not_truncated_512():
    # fs.c:57 blake2b(NULL, 0, data, len, out, 32): unkeyed BLAKE2b with a 32-byte digest.
    # Value as printed by coreutils `printf abc | b2sum -l 256`.
    digest = csum.compute(csum.BLAKE2, b"abc")
    assert digest.hex() == "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    assert digest != hashlib.blake2b(b"abc").digest()[:32]


def test_sizes_and_names_follow_ondisk_table():
    for csum_type, (name, size) in ondisk.CSUM_TYPES.items():
        assert csum.csum_name(csum_type) == name
        assert csum.csum_size(csum_type) == size
        assert len(csum.compute(csum_type, b"x")) == size


@pytest.mark.parametrize("csum_type", [4, 255, 0xFFFF, -1])
def test_unknown_type_raises(csum_type):
    with pytest.raises(csum.UnknownCsumType):
        csum.compute(csum_type, b"")
    with pytest.raises(csum.UnknownCsumType):
        csum.csum_size(csum_type)
    assert issubclass(csum.UnknownCsumType, ValueError)


def test_accepts_memoryview():
    data = bytes(range(256)) * 4
    for csum_type in ondisk.CSUM_TYPES:
        assert csum.compute(csum_type, memoryview(data)[7:]) == csum.compute(csum_type, data[7:])


def test_block_csum_ok_detects_every_single_bit_flip_in_a_sample():
    rng = random.Random(1)
    block = bytearray(rng.randbytes(4096))
    for csum_type in ondisk.CSUM_TYPES:
        block[: ondisk.CSUM_SIZE] = bytes(32)
        block[: csum.csum_size(csum_type)] = csum.compute(csum_type, block[ondisk.CSUM_SIZE :])
        assert csum.block_csum_ok(csum_type, block)
        for _ in range(50):
            bit = rng.randrange(len(block) * 8)
            flipped = bytearray(block)
            flipped[bit // 8] ^= 1 << (bit % 8)
            # A flip in the unused tail of the 32-byte csum field is not covered, as in the kernel.
            covered = bit // 8 < csum.csum_size(csum_type) or bit // 8 >= ondisk.CSUM_SIZE
            assert csum.block_csum_ok(csum_type, flipped) is not covered


@pytest.mark.sandbox
def test_sandbox_superblocks_are_known_good_crc32c_blocks(sandbox_img):
    with open_image(sandbox_img) as img:
        for copy in GROUND_TRUTH["superblock"]["copies"]:
            block = img.mmap[copy["bytenr"] : copy["bytenr"] + ondisk.SUPER_INFO_SIZE]
            assert csum.block_csum_ok(csum.CRC32C, block)
            # dump-super prints the stored csum bytes in on-disk order.
            assert block[:4] == bytes.fromhex(copy["csum"])
            assert not csum.block_csum_ok(csum.XXHASH, block)
