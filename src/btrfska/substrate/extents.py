"""Extent reads and file assembly: EXTENT_DATA items to file bytes, with a record per extent.

`read_extent(reader, item, leaf)` turns one EXTENT_DATA item into its file bytes and an
`ExtentRead` record. Physical reads go through `reader.chunk_map`, whichever map that is (current
now; historical or reconstructed in M5). `read_file(reader, root, inode, no_holes=)` walks an fs
tree for the inode and assembles its content in file order.

Extent kinds (btrfs_tree.h btrfs_file_extent_item; kernel read path inode.c:7129-7196 and
btrfs_get_extent):
- inline: the data follows the item's 21-byte head. The kernel reads min(ram_bytes, sectorsize)
  bytes; a compressed inline extent decodes up to one sector (compress.py);
- regular: uncompressed, [disk_bytenr + offset, + num_bytes); compressed, the whole
  [disk_bytenr, + disk_num_bytes) decodes to ram_bytes and the file takes [offset, + num_bytes);
- regular with disk_bytenr 0: an explicit hole of num_bytes zeros;
- prealloc: num_bytes zeros, the disk bytes are not read;
- implicit_hole: a range no item covers, zeros. Normal with the NO_HOLES feature; without it the
  gap is reported as a problem.
Content is clipped to i_size; clipping is reported only when an extent reaches past the sector
holding the end of the file. Data checksums are not verified here (M6).

Hostile lengths are bounded before any read or allocation:
- compressed extents: ram_bytes and disk_num_bytes in (0, 128 KiB] (BTRFS_MAX_UNCOMPRESSED and
  BTRFS_MAX_COMPRESSED, compression.h:35 and :40);
- uncompressed regular extents: disk_num_bytes and num_bytes at most the image size. Every byte
  of a readable copy comes from this one image, so a longer extent cannot be read without
  aliasing. btrfska does not assume the kernel allocator's 128 MiB limit (BTRFS_MAX_EXTENT_SIZE,
  fs.h:66): the tree checker does not enforce it (tree-checker.c:306-321 checks only alignment
  and end overflow), so an image may hold a longer extent that the kernel still accepts.
Ranges are mapped and read one piece at a time, stopping at the first unmapped or unreadable one.

Every physical range records all copies (DUP, RAID1*): the first readable copy is used and every
other readable copy is compared with it, a divergent copy being reported. Failures are records,
never truncated or padded content: `ExtentRead.error_kind` is one of unmapped, unreadable,
malformed_item, invalid_extent, unsupported_encoding, or a compress.DecodeError kind. A
`FileRead` with any error is incomplete, and its `chunks()` raises IncompleteRead.
"""

import hashlib
import stat
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field, replace

from btrfska.substrate import compress, items, ondisk
from btrfska.substrate.chunks import MappingError
from btrfska.substrate.node import Item, NodeReader
from btrfska.substrate.roots import TreeRoot
from btrfska.substrate.tree import walk

K = ondisk.ITEM_KEYS
_ZEROS = 1 << 20  # zero runs are yielded in pieces of at most this size


class IncompleteRead(Exception):
    """File content was requested from a read that has errors."""


@dataclass(frozen=True)
class DataCopy:
    mirror: int  # 1-based, in stripe order
    devid: int
    physical: int
    readable: bool  # False: device missing or the range is beyond the image end
    used: bool  # the copy whose bytes were used
    matches: bool | None  # equal to the used copy; None for the used copy or an unreadable one


@dataclass(frozen=True)
class DataRange:
    logical: int
    length: int
    copies: tuple[DataCopy, ...]


@dataclass(frozen=True)
class ExtentRead:
    """Where one extent's bytes came from and how they were decoded. JSON-ready via asdict."""

    kind: str  # inline, regular, prealloc, hole, implicit_hole, invalid
    file_offset: int
    length: int  # bytes of file content supplied, after clipping to i_size
    leaf: int | None = None  # logical address of the leaf holding the item
    slot: int | None = None
    generation: int | None = None  # the item's generation field
    compression: str | None = None  # none, zlib, lzo, zstd or "type N"
    ram_bytes: int | None = None
    disk_bytenr: int | None = None
    disk_num_bytes: int | None = None
    offset: int | None = None
    num_bytes: int | None = None
    chunk_map: str | None = None  # source of the chunk map the ranges were read through
    ranges: tuple[DataRange, ...] = ()
    decoded_bytes: int | None = None  # decompressor output length
    sha256: str | None = None  # of the supplied bytes; None for zeros and failures
    error_kind: str | None = None
    error_detail: str = ""
    problems: tuple[str, ...] = ()  # findings that do not make the content wrong


def _read(reader: NodeReader, logical: int, length: int):
    """(bytes or None, ranges, problems, (error kind, detail) or None) for a logical range."""
    chunk_map, img = reader.chunk_map, reader.img
    out, ranges, problems = bytearray(), [], []
    pieces = chunk_map.pieces(logical, length)
    while True:  # one piece at a time: stop at the first unmapped or unreadable one
        try:
            piece = next(pieces, None)
            if piece is None:
                break
            start, size = piece
            copies = chunk_map.copies(start, size)
        except MappingError as exc:
            return None, tuple(ranges), tuple(problems), ("unmapped", str(exc))
        blocks = [
            None
            if copy.missing_device or copy.physical + size > img.size
            else bytes(img.mmap[copy.physical : copy.physical + size])
            for copy in copies
        ]
        used = next((i for i, block in enumerate(blocks) if block is not None), None)
        records = []
        for i, copy in enumerate(copies):
            compared = used is not None and i != used and blocks[i] is not None
            matches = blocks[i] == blocks[used] if compared else None
            if matches is False:
                problems.append(
                    f"logical {start}+{size}: mirror {copy.mirror} differs from mirror "
                    f"{copies[used].mirror}"
                )
            records.append(
                DataCopy(copy.mirror, copy.devid, copy.physical, blocks[i] is not None, i == used,
                         matches)
            )  # fmt: skip
        ranges.append(DataRange(start, size, tuple(records)))
        if used is None:
            return None, tuple(ranges), tuple(problems), (
                "unreadable", f"no readable copy of logical {start}+{size}",
            )  # fmt: skip
        out += blocks[used]
    return bytes(out), tuple(ranges), tuple(problems), None


def _nonzero(data: bytes) -> int:
    return len(data) - data.count(0)


def read_extent(reader: NodeReader, item: Item, leaf: int) -> tuple[ExtentRead, bytes | None]:
    """One EXTENT_DATA item: its record and its bytes (None for zeros or on error)."""
    sectorsize = reader.ctx.sectorsize
    where = {"file_offset": item.key.offset, "leaf": leaf, "slot": item.slot}
    try:
        fe = items.file_extent(item.data)
    except items.ItemError as exc:
        return ExtentRead("invalid", length=0, error_kind="malformed_item",
                          error_detail=str(exc), **where), None  # fmt: skip
    code = fe["compression"]
    info = where | {
        "generation": fe["generation"],
        "compression": compress.NAMES.get(code, f"type {code}"),
        "ram_bytes": fe["ram_bytes"],
    }
    kind = items.EXTENT_TYPE_NAMES.get(fe["type"], "invalid")
    if fe["type"] != ondisk.FILE_EXTENT_INLINE and kind != "invalid":
        info |= {
            name: fe[name] for name in ("disk_bytenr", "disk_num_bytes", "offset", "num_bytes")
        }
    length = fe.get("num_bytes", 0) if kind != "inline" else min(fe["ram_bytes"], sectorsize)

    def failed(error: str, detail: str, **extra) -> tuple[ExtentRead, None]:
        record_kind = "hole" if kind == "regular" and fe.get("disk_bytenr") == 0 else kind
        return ExtentRead(record_kind, length=length if kind != "invalid" else 0,
                          error_kind=error, error_detail=detail, **info, **extra), None  # fmt: skip

    if kind == "invalid":
        return failed("invalid_extent", f"extent type {fe['type']}")
    if fe["encryption"] or fe["other_encoding"]:
        return failed(
            "unsupported_encoding",
            f"encryption {fe['encryption']}, other_encoding {fe['other_encoding']}",
        )
    if code not in compress.NAMES:
        return failed("unsupported_compression", f"compression type {code}")

    if kind == "inline":
        return _inline(item, fe, info, length, sectorsize, failed)
    if kind == "prealloc":
        return ExtentRead("prealloc", length=length, **info), None
    if fe["disk_bytenr"] == 0:
        return ExtentRead("hole", length=length, **info), None

    info["chunk_map"] = reader.chunk_map.source
    offset, ram, disk_bytes = fe["offset"], fe["ram_bytes"], fe["disk_num_bytes"]
    if code == compress.NONE:
        image_size = reader.img.size
        for name, value in (("disk_num_bytes", disk_bytes), ("num_bytes", length)):
            if value > image_size:
                return failed("invalid_extent", f"{name} {value} exceeds the image size "
                              f"{image_size}")  # fmt: skip
        if offset + length > disk_bytes:
            return failed("invalid_extent", f"offset {offset} + num_bytes {length} > "
                          f"disk_num_bytes {disk_bytes}")  # fmt: skip
        data, ranges, problems, error = _read(reader, fe["disk_bytenr"] + offset, length)
        if error:
            return failed(*error, ranges=ranges, problems=problems)
        return ExtentRead("regular", length=length, ranges=ranges, problems=problems, **info), data

    if not 0 < ram <= compress.BTRFS_MAX_UNCOMPRESSED:
        return failed("invalid_extent", f"compressed ram_bytes {ram} outside (0, 128 KiB]")
    if not 0 < disk_bytes <= compress.BTRFS_MAX_COMPRESSED:
        return failed(
            "invalid_extent", f"compressed disk_num_bytes {disk_bytes} outside (0, 128 KiB]"
        )
    if offset + length > ram:
        return failed("invalid_extent", f"offset {offset} + num_bytes {length} > ram_bytes {ram}")
    raw, ranges, problems, error = _read(reader, fe["disk_bytenr"], disk_bytes)
    if error:
        return failed(*error, ranges=ranges, problems=problems)
    try:
        decoded = compress.decompress(code, raw, min_out=ram, max_out=ram, sectorsize=sectorsize)
    except compress.DecodeError as exc:
        return failed(exc.kind, exc.detail, ranges=ranges, problems=problems)
    if count := _nonzero(decoded.slack):
        problems += (f"{count} non-zero bytes after the end of the compressed stream",)
    record = ExtentRead("regular", length=length, ranges=ranges, decoded_bytes=len(decoded.data),
                        problems=problems, **info)  # fmt: skip
    return record, decoded.data[offset : offset + length]


def _inline(item: Item, fe: dict, info: dict, length: int, sectorsize: int, failed):
    data = item.data[ondisk.FILE_EXTENT_INLINE_DATA_START :]
    problems = []
    if item.key.offset != 0:
        return failed("invalid_extent", f"inline extent at file offset {item.key.offset}, not 0")
    if fe["ram_bytes"] > sectorsize:
        problems.append(f"ram_bytes {fe['ram_bytes']} > sectorsize: the kernel reads one sector")
    if fe["compression"] == compress.NONE:
        if len(data) < length:
            return failed("invalid_extent", f"inline data of {len(data)} bytes < {length}")
        if len(data) != fe["ram_bytes"]:
            problems.append(f"inline item holds {len(data)} bytes, ram_bytes {fe['ram_bytes']}")
        return ExtentRead("inline", length=length, problems=tuple(problems), **info), data[:length]
    try:
        decoded = compress.decompress(fe["compression"], data, min_out=length, max_out=sectorsize,
                                      sectorsize=sectorsize, inline=True)  # fmt: skip
    except compress.DecodeError as exc:
        return failed(exc.kind, exc.detail)
    if count := _nonzero(decoded.data[length:]):
        problems.append(f"{count} non-zero bytes past ram_bytes in the decoded sector")
    if count := _nonzero(decoded.slack):
        problems.append(f"{count} non-zero bytes after the end of the compressed stream")
    record = ExtentRead("inline", length=length, decoded_bytes=len(decoded.data),
                        problems=tuple(problems), **info)  # fmt: skip
    return record, decoded.data[:length]


@dataclass(frozen=True)
class FileRead:
    root: TreeRoot  # the fs tree root the inode was read from
    inode: int
    size: int | None  # i_size; None without an INODE_ITEM
    extents: tuple[ExtentRead, ...]  # in file order, implicit holes included
    errors: tuple[str, ...]  # file-level failures (walk, missing inode, overlaps)
    problems: tuple[str, ...]  # file-level findings that do not make the content wrong
    _data: tuple[bytes | None, ...] = field(default=(), repr=False)

    @property
    def complete(self) -> bool:
        return not self.errors and all(e.error_kind is None for e in self.extents)

    @property
    def failures(self) -> tuple[str, ...]:
        """Why the read is incomplete: file errors, then extent errors."""
        return (*self.errors, *(
            f"extent at file offset {e.file_offset}: {e.error_kind}: {e.error_detail}"
            for e in self.extents
            if e.error_kind
        ))  # fmt: skip

    def chunks(self) -> Iterator[bytes]:
        """The file content in order. Raises IncompleteRead before yielding anything."""
        if not self.complete:
            raise IncompleteRead(f"inode {self.inode}: {'; '.join(self.failures)}")
        for extent, data in zip(self.extents, self._data, strict=True):
            if data is not None:
                yield data
                continue
            remaining = extent.length
            while remaining:
                step = min(remaining, _ZEROS)
                yield bytes(step)
                remaining -= step

    def record(self) -> dict:
        return {
            "root": asdict(self.root),
            "inode": self.inode,
            "size": self.size,
            "complete": self.complete,
            "extents": len(self.extents),
            "errors": list(self.errors),
            "problems": list(self.problems),
        }


def read_file(reader: NodeReader, root: TreeRoot, inode: int, *, no_holes: bool) -> FileRead:
    """Read `inode` from the fs tree at `root`; `no_holes` is the superblock's NO_HOLES bit.

    The content is held fully in memory: every non-zero extent's bytes are kept in the `FileRead`,
    and each is built from a read buffer first, so the peak is about twice the file size (zero
    runs excepted). Streaming reads arrive with the recovery engine (plan.md M4)."""
    errors, problems, inode_fields, found = [], [], None, []
    for visit in walk(reader, root.bytenr, root.expect()):
        node = visit.node
        if not node.valid:
            errors.append(f"tree node {node.logical} is invalid: {'; '.join(node.problems)}")
            continue
        errors += [f"tree node {node.logical}: {p}" for p in visit.problems]
        for item in node.items if node.level == 0 else ():
            if item.key.objectid != inode:
                continue
            if item.key.type == K["INODE_ITEM"]:
                try:
                    inode_fields = items.inode_item(item.data)
                except items.ItemError as exc:
                    errors.append(f"INODE_ITEM in leaf {node.logical}: {exc}")
            elif item.key.type == K["EXTENT_DATA"]:
                found.append((item, node.logical))

    size = None if inode_fields is None else inode_fields["size"]
    if inode_fields is None:
        errors.append(f"no INODE_ITEM for inode {inode} in the tree at {root.bytenr}")
    elif stat.S_ISDIR(inode_fields["mode"]):
        errors.append(f"inode {inode} is a directory")

    extents, data, pos = [], [], 0
    sectorsize = reader.ctx.sectorsize

    def hole(start: int, end: int) -> None:
        extents.append(ExtentRead("implicit_hole", file_offset=start, length=end - start))
        data.append(None)
        if not no_holes:
            problems.append(f"no extent item covers [{start}, {end}) and NO_HOLES is not set")

    for item, leaf in found:
        record, content = read_extent(reader, item, leaf)
        start, end = record.file_offset, record.file_offset + record.length
        if start < pos:
            errors.append(f"extent at file offset {start} overlaps the extent ending at {pos}")
        elif start > pos and (size is None or pos < size):
            hole(pos, start if size is None else min(start, size))
        if size is not None and end > size:
            kept = max(0, size - start)
            found = record.problems
            if end > -(-size // sectorsize) * sectorsize:  # reaches past the sector holding EOF
                found = (*found, f"clipped from {record.length} to {kept} bytes by i_size {size}")
            record = replace(record, length=kept, problems=found)
            content = None if content is None else content[:kept]
        if content is not None:
            record = replace(record, sha256=hashlib.sha256(content).hexdigest())
        extents.append(record)
        data.append(content)
        pos = max(pos, end)
    if size is not None and pos < size:
        hole(pos, size)
    return FileRead(root, inode, size, tuple(extents), tuple(errors), tuple(problems), tuple(data))
