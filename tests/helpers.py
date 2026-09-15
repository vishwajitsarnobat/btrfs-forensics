"""Shared test helpers: synthetic superblocks and tree nodes, scratch images under images/."""

import shutil
import struct
import tempfile
from contextlib import contextmanager
from pathlib import Path

from btrfska.substrate import csum, ondisk
from btrfska.substrate.node import NodeContext

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


LZO_END = b"\x11\x00\x00"  # 0001HLLL with distance 16384: end of stream (lzo.rst)


def lzo_literal_stream(data: bytes) -> bytes:
    """A valid LZO1X stream storing `data` as literals, built from kernel lzo.rst encodings.

    1..238 bytes: first byte 17 + n. Longer: first byte 0 (state 0, long literal), whose length is
    3 + 15 + 255 per zero byte + the first non-zero byte.
    """
    n = len(data)
    if n == 0:
        return LZO_END
    if n <= 238:
        return bytes([17 + n]) + data + LZO_END
    zeros, last = divmod(n - 18, 255)
    if last == 0:
        zeros, last = zeros - 1, 255
    return b"\x00" + bytes(zeros) + bytes([last]) + data + LZO_END


def sector_pad(data: bytes, sectorsize: int = 4096) -> bytes:
    return data + bytes(-len(data) % sectorsize)


def lzo_extent(payloads: list[bytes], sectorsize: int = 4096) -> bytes:
    """Frame LZO segments as fs/btrfs/lzo.c writes them: a LE32 total length, then per segment a
    LE32 length and the payload, padding with zeros when fewer than 4 bytes are left in a sector.
    The total includes that padding; on disk the extent is padded to whole sectors."""
    buf = bytearray(4)
    for payload in payloads:
        buf += len(payload).to_bytes(4, "little") + payload
        left = -len(buf) % sectorsize
        if left < 4:
            buf += bytes(left)
    buf[:4] = len(buf).to_bytes(4, "little")
    return bytes(buf)


@contextmanager
def scratch_dir(prefix: str):
    """A fresh directory under the gitignored images/scratch/, removed afterwards."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=SCRATCH))
    try:
        yield path
    finally:
        shutil.rmtree(path)


# ---------------------------------------------------------------------------
# Synthetic tree nodes
# ---------------------------------------------------------------------------
FSID = bytes(range(16))
CHUNK_TREE_UUID = bytes(range(16, 32))
DEV_UUID = bytes(range(32, 48))
NODESIZE = 4096
_HEADER_FORMATS = {
    "fsid": "16s",
    "bytenr": "<Q",
    "flags": "<Q",
    "chunk_tree_uuid": "16s",
    "generation": "<Q",
    "owner": "<Q",
    "nritems": "<I",
    "level": "<B",
}


def node_ctx(**overrides) -> NodeContext:
    """The node context matching make_node's defaults (superblock generation 100)."""
    values = {
        "nodesize": NODESIZE,
        "sectorsize": 4096,
        "csum_type": csum.XXHASH,
        "fsid": FSID,
        "generation": 100,
        "chunk_tree_uuid": CHUNK_TREE_UUID,
        **overrides,
    }
    return NodeContext(**values)


def recsum(block, csum_type: int = csum.XXHASH) -> bytes:
    """`block` with its tree-block checksum recomputed."""
    block = bytearray(block)
    block[: ondisk.CSUM_SIZE] = bytes(ondisk.CSUM_SIZE)
    block[: csum.csum_size(csum_type)] = csum.compute(csum_type, block[ondisk.CSUM_SIZE :])
    return bytes(block)


def set_header(block, csum_type: int = csum.XXHASH, **fields) -> bytes:
    """`block` with header fields replaced and the checksum recomputed."""
    block = bytearray(block)
    for name, value in fields.items():
        struct.pack_into(_HEADER_FORMATS[name], block, ondisk.HEADER.offset(name), value)
    return recsum(block, csum_type)


def flip(block, offset: int) -> bytes:
    """`block` with the byte at `offset` inverted and the checksum left stale."""
    block = bytearray(block)
    block[offset] ^= 0xFF
    return bytes(block)


def make_node(
    bytenr: int,
    *,
    level: int = 0,
    items=(),
    ptrs=(),
    owner: int = ondisk.FS_TREE_OBJECTID,
    generation: int = 7,
    nodesize: int = NODESIZE,
    csum_type: int = csum.XXHASH,
    fsid: bytes = FSID,
    chunk_tree_uuid: bytes = CHUNK_TREE_UUID,
    flags: int = ondisk.HEADER_FLAG_WRITTEN,
    nritems: int | None = None,
) -> bytes:
    """A tree block laid out as the kernel writes it, with a correct checksum.

    Leaves take `items` as ((objectid, type, offset), data) pairs, packed from the end of the
    block. Internal nodes take `ptrs` as ((objectid, type, offset), blockptr, generation).
    """
    block = bytearray(nodesize)
    count = len(items) if level == 0 else len(ptrs)
    struct.pack_into(
        ondisk.HEADER.format,
        block,
        0,
        bytes(ondisk.CSUM_SIZE),
        fsid,
        bytenr,
        flags,
        chunk_tree_uuid,
        generation,
        owner,
        count if nritems is None else nritems,
        level,
    )
    base = ondisk.HEADER.size
    if level == 0:
        end = nodesize - base
        for slot, (key, data) in enumerate(items):
            end -= len(data)
            struct.pack_into(
                ondisk.ITEM.format, block, base + slot * ondisk.ITEM.size, *key, end, len(data)
            )
            block[base + end : base + end + len(data)] = data
    else:
        for slot, (key, blockptr, gen) in enumerate(ptrs):
            struct.pack_into(
                ondisk.KEY_PTR.format, block, base + slot * ondisk.KEY_PTR.size, *key, blockptr, gen
            )
    return recsum(block, csum_type)
