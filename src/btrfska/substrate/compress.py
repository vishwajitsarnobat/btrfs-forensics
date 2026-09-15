"""Extent decompression: zlib, zstd and the btrfs LZO segment framing, bounded and classified.

`decompress(compression, data, min_out=, max_out=, inline=)` returns a `Decoded` whose data is
between `min_out` and `max_out` bytes long, or raises `DecodeError(kind, detail)`. Output is never
truncated or padded to fit. Callers pass the kernel's bounds (tag v7.0):
- regular extents decode to exactly ram_bytes (min_out == max_out == ram_bytes);
- inline extents decode up to one sector and must cover min(ram_bytes, sectorsize)
  (inode.c:7129-7168 uncompress_inline). The kernel compresses an inline extent's whole sector,
  so the output is often a full sector whose bytes past ram_bytes are not file content.

Kinds: unsupported_compression, invalid_bounds, corrupt_stream, truncated_stream (the stream ended
before its end marker), output_overrun, short_output, lzo_framing, and lzo_<LzoError kind>.

Per compression:
- zlib: like zlib_decompress_bio (zlib.c:344-445), a stream with a valid zlib header and no preset
  dictionary is inflated as raw deflate, so its adler32 trailer is not checked;
- zstd: one frame (compression.zstd.ZstdDecompressor);
- lzo (lzo.c:24-59, 429-545, 547-590): a LE32 total length that includes itself, then segments of
  a LE32 length and at most lzo1x_worst_compress(sectorsize) bytes of LZO1X data. A segment header
  never straddles a sector: when fewer than 4 bytes remain, they are padding. A regular extent's
  total may not exceed min(128 KiB, the extent) nor leave a whole sector unused; each segment
  decodes to at most one sector, and reading stops once `min_out` bytes are decoded, as the kernel
  stops when the read is filled. An inline extent holds exactly one segment filling the item.
`Decoded.slack` holds the bytes after the end of the stream (zlib, zstd) or after the LZO total:
normally zero padding to the sector boundary, so non-zero slack is worth reporting.
"""

import zlib
from compression import zstd
from dataclasses import dataclass

from btrfska.substrate import lzo

NONE, ZLIB, LZO, ZSTD = 0, 1, 2, 3
NAMES = {NONE: "none", ZLIB: "zlib", LZO: "lzo", ZSTD: "zstd"}
BTRFS_MAX_COMPRESSED = 128 * 1024  # compression.h:35
BTRFS_MAX_UNCOMPRESSED = 128 * 1024  # compression.h:40
_LZO_LEN = 4


class DecodeError(Exception):
    """An extent could not be decoded within its bounds."""

    def __init__(self, kind: str, detail: str = "") -> None:
        super().__init__(f"{kind}: {detail}" if detail else kind)
        self.kind = kind
        self.detail = detail


@dataclass(frozen=True)
class Decoded:
    data: bytes
    slack: bytes  # input bytes after the end of the stream


def lzo_worst_compress(size: int) -> int:
    """include/linux/lzo.h:21."""
    return size + size // 16 + 64 + 3 + 2


def _check_length(out_len: int, min_out: int, max_out: int) -> None:
    if out_len > max_out:
        raise DecodeError("output_overrun", f"more than {max_out} bytes decoded")
    if out_len < min_out:
        raise DecodeError("short_output", f"{out_len} bytes decoded, {min_out} expected")


def _zlib(data: bytes, min_out: int, max_out: int) -> Decoded:
    wbits, view, raw = zlib.MAX_WBITS, data, False
    if (
        len(data) > 2
        and not data[1] & 0x20  # PRESET_DICT
        and data[0] & 0x0F == 8  # Z_DEFLATED
        and ((data[0] << 8) + data[1]) % 31 == 0
    ):
        wbits, view, raw = -((data[0] >> 4) + 8), data[2:], True
    try:
        inflater = zlib.decompressobj(wbits)
        out = inflater.decompress(view, max_out)
        tail = inflater.unconsumed_tail
        if not inflater.eof and tail and inflater.decompress(tail, 1):
            raise DecodeError("output_overrun", f"more than {max_out} bytes decoded")
    except (zlib.error, ValueError) as exc:
        raise DecodeError("corrupt_stream", str(exc)) from None
    if not inflater.eof:
        raise DecodeError("truncated_stream", f"no end of stream after {len(out)} bytes")
    _check_length(len(out), min_out, max_out)
    slack = inflater.unused_data[4:] if raw else inflater.unused_data  # raw: skip the adler32
    return Decoded(out, slack)


def _zstd(data: bytes, min_out: int, max_out: int) -> Decoded:
    try:
        decompressor = zstd.ZstdDecompressor()
        out = decompressor.decompress(data, max_length=max_out)
        if (
            not decompressor.eof
            and not decompressor.needs_input
            and decompressor.decompress(b"", max_length=1)
        ):
            raise DecodeError("output_overrun", f"more than {max_out} bytes decoded")
    except zstd.ZstdError as exc:
        raise DecodeError("corrupt_stream", str(exc)) from None
    if not decompressor.eof:
        raise DecodeError("truncated_stream", f"no end of frame after {len(out)} bytes")
    _check_length(len(out), min_out, max_out)
    return Decoded(out, decompressor.unused_data)


def _le32(data: bytes, pos: int) -> int:
    return int.from_bytes(data[pos : pos + _LZO_LEN], "little")


def _lzo_segment(payload: bytes, bound: int) -> bytes:
    try:
        return lzo.decompress(payload, bound)
    except lzo.LzoError as exc:
        raise DecodeError(f"lzo_{exc.kind}", exc.detail) from None


def _lzo(data: bytes, min_out: int, max_out: int, sectorsize: int, inline: bool) -> Decoded:
    worst = lzo_worst_compress(sectorsize)
    size = len(data)
    if size < 2 * _LZO_LEN:
        raise DecodeError("lzo_framing", f"{size} bytes cannot hold the two LZO headers")
    total = _le32(data, 0)
    if inline:
        # lzo_decompress (lzo.c:547-590): one segment filling the item.
        segment = _le32(data, _LZO_LEN)
        if size > worst + 2 * _LZO_LEN or total != size or segment != size - 2 * _LZO_LEN:
            raise DecodeError(
                "lzo_framing",
                f"inline item of {size} bytes: total {total}, segment {segment}",
            )
        out = _lzo_segment(data[2 * _LZO_LEN :], min(sectorsize, max_out))
        _check_length(len(out), min_out, max_out)
        return Decoded(out, b"")

    if total > min(BTRFS_MAX_COMPRESSED, size) or -(-total // sectorsize) * sectorsize < size:
        raise DecodeError("lzo_framing", f"total length {total} for a {size}-byte extent")
    out = bytearray()
    pos = _LZO_LEN
    while pos < total and len(out) < min_out:
        segment = _le32(data, pos)
        pos += _LZO_LEN
        if segment > worst or pos + segment > total:
            raise DecodeError(
                "lzo_framing",
                f"segment of {segment} bytes at offset {pos - _LZO_LEN} (total {total}, "
                f"worst case {worst})",
            )
        out += _lzo_segment(data[pos : pos + segment], min(sectorsize, max_out - len(out)))
        pos += segment
        if sectorsize - pos % sectorsize < _LZO_LEN:
            pos += sectorsize - pos % sectorsize  # padding before the next sector
    _check_length(len(out), min_out, max_out)
    return Decoded(bytes(out), data[total:])


def decompress(
    compression: int,
    data: bytes,
    *,
    min_out: int,
    max_out: int,
    sectorsize: int = 4096,
    inline: bool = False,
) -> Decoded:
    """Decode one extent's compressed bytes; see the module docstring. Raises only DecodeError."""
    if not 0 <= min_out <= max_out or max_out < 1:
        raise DecodeError("invalid_bounds", f"min_out {min_out}, max_out {max_out}")
    data = bytes(data)
    if compression == ZLIB:
        return _zlib(data, min_out, max_out)
    if compression == ZSTD:
        return _zstd(data, min_out, max_out)
    if compression == LZO:
        return _lzo(data, min_out, max_out, sectorsize, inline)
    raise DecodeError("unsupported_compression", f"compression type {compression}")
