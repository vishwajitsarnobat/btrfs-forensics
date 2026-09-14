"""Shared test helpers: synthetic superblocks and scratch images under images/scratch/."""

import shutil
import struct
import tempfile
from contextlib import contextmanager
from pathlib import Path

from btrfska.substrate import csum, ondisk

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRATCH = REPO_ROOT / "images" / "scratch"
SCENARIOS = REPO_ROOT / "images" / "scenarios"
# MIXED_BACKREF | BIG_METADATA | EXTENDED_IREF | SKINNY_METADATA | NO_HOLES
SANDBOX_INCOMPAT = 0x361


# Superblock fields narrower than u64 (the rest of the integers are "<Q").
_NARROW = {
    "sectorsize": "<I",
    "nodesize": "<I",
    "leafsize": "<I",
    "stripesize": "<I",
    "sys_chunk_array_size": "<I",
    "csum_type": "<H",
    "root_level": "<B",
    "chunk_root_level": "<B",
    "log_root_level": "<B",
}


def make_block(
    mirror: int = 0,
    generation: int = 7,
    csum_type: int = csum.CRC32C,
    incompat: int = SANDBOX_INCOMPAT,
    compat_ro: int = 0,
    backups: list[tuple[int, int]] = (),
    **overrides,
) -> bytes:
    """A minimal superblock with sane geometry and a correct checksum.

    `backups` holds (slot, generation) pairs. `overrides` sets any other superblock field by
    name: integers are packed with the field's width, bytes are copied in place.
    """
    block = bytearray(ondisk.SUPER_INFO_SIZE)

    def put(offset, value, fmt="<Q"):
        struct.pack_into(fmt, block, offset, value)

    field = ondisk.SUPERBLOCK.offset
    values = {
        "bytenr": ondisk.sb_offset(mirror),
        "magic": ondisk.MAGIC,
        "generation": generation,
        "root": 0x100000 + generation * 0x1000,
        "total_bytes": 1 << 30,
        "bytes_used": 1 << 20,
        "num_devices": 1,
        "sectorsize": 4096,
        "nodesize": 16384,
        "leafsize": 16384,
        "stripesize": 4096,
        "sys_chunk_array_size": ondisk.MIN_SYS_CHUNK_ARRAY_SIZE,
        "compat_ro_flags": compat_ro,
        "incompat_flags": incompat,
        "csum_type": csum_type,
        **overrides,
    }
    for name, value in values.items():
        if isinstance(value, bytes):
            block[field(name) : field(name) + len(value)] = value
        else:
            put(field(name), value, _NARROW.get(name, "<Q"))
    for slot, gen in backups:
        base = field("super_roots") + slot * ondisk.ROOT_BACKUP.size
        put(base + ondisk.ROOT_BACKUP.offset("tree_root"), 0x200000 + gen)
        put(base + ondisk.ROOT_BACKUP.offset("tree_root_gen"), gen)
    if csum_type in ondisk.CSUM_TYPES:
        block[: csum.csum_size(csum_type)] = csum.compute(csum_type, block[ondisk.CSUM_SIZE :])
    return bytes(block)


def write_sparse_image(path: Path, size: int, blocks: dict[int, bytes]) -> Path:
    """A sparse test image of `size` bytes with `blocks` written at their offsets."""
    with open(path, "wb") as f:
        f.truncate(size)
        for offset, block in blocks.items():
            f.seek(offset)
            f.write(block)
    return path


@contextmanager
def scratch_dir(prefix: str):
    """A fresh directory under the gitignored images/scratch/, removed afterwards."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=SCRATCH))
    try:
        yield path
    finally:
        shutil.rmtree(path)
