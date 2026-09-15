"""Extent decompression (substrate/compress.py): zlib, zstd and the btrfs LZO framing.

Bounds follow the kernel read paths (tag v7.0): regular extents decode to exactly ram_bytes;
inline extents decode up to one sector and must cover min(ram_bytes, sectorsize).
"""

import random
import zlib
from compression import zstd

import pytest

from btrfska.substrate import compress
from btrfska.substrate.compress import LZO, ZLIB, ZSTD, DecodeError, decompress
from tests.helpers import lzo_extent, lzo_literal_stream, sector_pad

SECTOR = 4096


def literal_payload(size: int, seed: int) -> tuple[bytes, bytes]:
    """(data, LZO stream) whose stream is exactly `size` bytes, for data of at most one sector."""
    for n in range(SECTOR, 0, -1):
        if len(lzo_literal_stream(bytes(n))) == size:
            data = random.Random(seed).randbytes(n)
            return data, lzo_literal_stream(data)
    raise ValueError(size)


def text(size: int) -> bytes:
    return b"".join(b"%d\n" % i for i in range(size))[:size]


# ---------------------------------------------------------------------------
# zlib
# ---------------------------------------------------------------------------
def test_zlib_regular_extent_round_trip_with_sector_padding():
    data = text(110592)
    decoded = decompress(ZLIB, sector_pad(zlib.compress(data)), min_out=110592, max_out=110592)
    assert decoded.data == data
    assert not any(decoded.slack)


def test_zlib_adler32_is_not_checked_like_the_kernel():
    """zlib_decompress_bio inflates raw deflate after a valid header (zlib.c:373-382)."""
    stream = bytearray(zlib.compress(text(5000)))
    stream[-1] ^= 0xFF
    assert decompress(ZLIB, bytes(stream), min_out=5000, max_out=5000).data == text(5000)


def test_zlib_more_output_than_ram_bytes_is_an_overrun():
    with pytest.raises(DecodeError) as exc:
        decompress(ZLIB, zlib.compress(text(8192)), min_out=4096, max_out=4096)
    assert exc.value.kind == "output_overrun"


def test_zlib_less_output_than_ram_bytes_is_short():
    with pytest.raises(DecodeError) as exc:
        decompress(ZLIB, zlib.compress(text(4000)), min_out=4096, max_out=4096)
    assert exc.value.kind == "short_output"


def test_zlib_truncated_stream():
    stream = zlib.compress(random.Random(1).randbytes(20000))
    with pytest.raises(DecodeError) as exc:
        decompress(ZLIB, stream[: len(stream) // 2], min_out=20000, max_out=20000)
    assert exc.value.kind == "truncated_stream"


def test_zlib_garbage_is_corrupt():
    with pytest.raises(DecodeError) as exc:
        decompress(ZLIB, b"\x78\x9c" + b"\xff" * 64, min_out=10, max_out=10)
    assert exc.value.kind == "corrupt_stream"


def test_zlib_output_that_ends_exactly_at_the_bound_is_accepted():
    data = bytes(65536)
    assert decompress(ZLIB, zlib.compress(data), min_out=65536, max_out=65536).data == data


# ---------------------------------------------------------------------------
# zstd
# ---------------------------------------------------------------------------
def test_zstd_regular_extent_round_trip_with_sector_padding():
    data = text(131072)
    decoded = decompress(ZSTD, sector_pad(zstd.compress(data)), min_out=131072, max_out=131072)
    assert decoded.data == data
    assert not any(decoded.slack)


def test_zstd_inline_extent_may_decode_a_whole_sector():
    """The kernel compresses an inline extent's whole sector: ram_bytes 5, a 4096-byte stream."""
    sector = b"gen1\n" + bytes(SECTOR - 5)
    decoded = decompress(ZSTD, zstd.compress(sector), min_out=5, max_out=SECTOR)
    assert decoded.data == sector


def test_zstd_overrun_short_truncated_and_corrupt():
    stream = zstd.compress(text(8192))
    for kwargs, kind in [
        ({"min_out": 4096, "max_out": 4096}, "output_overrun"),
        ({"min_out": 9000, "max_out": 9000}, "short_output"),
    ]:
        with pytest.raises(DecodeError) as exc:
            decompress(ZSTD, stream, **kwargs)
        assert exc.value.kind == kind
    with pytest.raises(DecodeError) as exc:
        decompress(ZSTD, stream[:-4], min_out=8192, max_out=8192)
    assert exc.value.kind == "truncated_stream"
    with pytest.raises(DecodeError) as exc:
        decompress(ZSTD, b"\x28\xb5\x2f\xfd" + b"\xff" * 32, min_out=10, max_out=10)
    assert exc.value.kind == "corrupt_stream"


def test_non_zero_bytes_after_the_stream_are_returned_as_slack():
    stream = zstd.compress(text(100)) + b"\0\0hidden"
    decoded = decompress(ZSTD, stream, min_out=100, max_out=100)
    assert decoded.slack == b"\0\0hidden"


# ---------------------------------------------------------------------------
# btrfs LZO framing (fs/btrfs/lzo.c header comment, lzo_decompress_bio, lzo_decompress)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("left", [0, 1, 2, 3, 4, 5])
def test_lzo_segment_headers_skip_a_sector_tail_shorter_than_four_bytes(left):
    first, first_stream = literal_payload(SECTOR - 8 - left, seed=left)
    second, second_stream = literal_payload(300, seed=100 + left)
    extent = lzo_extent([first_stream, second_stream])
    padded = left in (1, 2, 3)
    if padded:
        assert extent[SECTOR - left : SECTOR] == bytes(left)
    header_at = SECTOR if padded else SECTOR - left
    assert int.from_bytes(extent[header_at : header_at + 4], "little") == len(second_stream)
    size = len(first) + len(second)
    decoded = decompress(LZO, sector_pad(extent), min_out=size, max_out=size)
    assert decoded.data == first + second


def test_lzo_header_straddling_a_sector_is_misread():
    """Without the padding, the reader skips the tail and misreads the next segment header."""
    first, first_stream = literal_payload(SECTOR - 8 - 2, seed=1)
    second, second_stream = literal_payload(300, seed=2)
    buf = bytearray(4)
    for payload in (first_stream, second_stream):
        buf += len(payload).to_bytes(4, "little") + payload
    buf[:4] = len(buf).to_bytes(4, "little")
    size = len(first) + len(second)
    with pytest.raises(DecodeError):
        decompress(LZO, sector_pad(bytes(buf)), min_out=size, max_out=size)


def test_lzo_multi_sector_extent_round_trip():
    chunks = [random.Random(i).randbytes(SECTOR) for i in range(5)]
    extent = lzo_extent([lzo_literal_stream(c) for c in chunks])
    decoded = decompress(LZO, sector_pad(extent), min_out=5 * SECTOR, max_out=5 * SECTOR)
    assert decoded.data == b"".join(chunks)


def test_lzo_inline_extent_has_one_segment_covering_the_item():
    data = b"small secret\n" + bytes(SECTOR - 13)
    extent = lzo_extent([lzo_literal_stream(data)])
    assert decompress(LZO, extent, min_out=13, max_out=SECTOR, inline=True).data == data


@pytest.mark.parametrize(
    ("mutate", "inline"),
    [
        (lambda e: (len(e) + 1).to_bytes(4, "little") + e[4:], True),  # total != item size
        (lambda e: e + b"\0", True),  # a byte after the single segment
        (lambda e: e[:6], True),  # shorter than both headers
        (lambda e: (1 << 20).to_bytes(4, "little") + e[4:], False),  # total > extent size
        (lambda e: (4).to_bytes(4, "little") + e[4:], False),  # total leaves whole sectors unused
    ],
)
def test_lzo_invalid_totals_are_framing_errors(mutate, inline):
    extent = lzo_extent([lzo_literal_stream(b"abc" * 100)])
    data = mutate(extent) if inline else mutate(sector_pad(extent) + bytes(SECTOR))
    with pytest.raises(DecodeError) as exc:
        decompress(LZO, data, min_out=300, max_out=SECTOR if inline else 300, inline=inline)
    assert exc.value.kind == "lzo_framing"


def test_lzo_segment_longer_than_the_worst_case_is_a_framing_error():
    """lzo1x_worst_compress(4096) is 4421 bytes (include/linux/lzo.h:21, v7.0); the "4419" in
    fs/btrfs/lzo.c's header comment predates the macro's "+ 2"."""
    assert compress.lzo_worst_compress(SECTOR) == 4421
    payload = lzo_literal_stream(bytes(200))
    extent = bytearray(lzo_extent([payload]))
    extent[4:8] = (4422).to_bytes(4, "little")
    with pytest.raises(DecodeError) as exc:
        decompress(LZO, sector_pad(bytes(extent)) + bytes(2 * SECTOR), min_out=200, max_out=200)
    assert exc.value.kind == "lzo_framing"


def test_lzo_segment_running_past_the_total_is_a_framing_error():
    extent = bytearray(lzo_extent([lzo_literal_stream(bytes(200))]))
    extent[4:8] = (3000).to_bytes(4, "little")
    with pytest.raises(DecodeError) as exc:
        decompress(LZO, sector_pad(bytes(extent)), min_out=200, max_out=200)
    assert exc.value.kind == "lzo_framing"


def test_lzo_decoder_errors_keep_their_kind():
    crafted = bytes.fromhex("154142434440ff110000")  # 4 literals, match 2 041 bytes back
    with pytest.raises(DecodeError) as exc:
        decompress(LZO, sector_pad(lzo_extent([crafted])), min_out=4096, max_out=4096)
    assert exc.value.kind == "lzo_lookbehind_overrun"


def test_lzo_segment_output_is_bounded_by_one_sector():
    extent = lzo_extent([lzo_literal_stream(bytes(SECTOR + 1))])
    with pytest.raises(DecodeError) as exc:
        decompress(LZO, sector_pad(extent), min_out=SECTOR + 1, max_out=2 * SECTOR)
    assert exc.value.kind == "lzo_output_overrun"


def test_lzo_short_output():
    extent = lzo_extent([lzo_literal_stream(bytes(100))])
    with pytest.raises(DecodeError) as exc:
        decompress(LZO, sector_pad(extent), min_out=SECTOR, max_out=SECTOR)
    assert exc.value.kind == "short_output"


# ---------------------------------------------------------------------------
# Common
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("compression", [0, 4, 255])
def test_other_compression_values_are_refused(compression):
    with pytest.raises(DecodeError) as exc:
        decompress(compression, b"x", min_out=1, max_out=1)
    assert exc.value.kind == "unsupported_compression"


@pytest.mark.parametrize(("min_out", "max_out"), [(0, 0), (5, 4), (-1, 10)])
def test_invalid_bounds_are_refused(min_out, max_out):
    with pytest.raises(DecodeError) as exc:
        decompress(ZSTD, zstd.compress(b"x"), min_out=min_out, max_out=max_out)
    assert exc.value.kind == "invalid_bounds"


def test_decode_error_is_an_exception_with_kind_and_detail():
    error = DecodeError("short_output", "3 < 5")
    assert isinstance(error, Exception) and (error.kind, error.detail) == ("short_output", "3 < 5")
    assert compress.NAMES == {0: "none", 1: "zlib", 2: "lzo", 3: "zstd"}


def _streams():
    data = text(3 * SECTOR)
    lzo = sector_pad(
        lzo_extent([lzo_literal_stream(data[i : i + SECTOR]) for i in (0, 4096, 8192)])
    )
    return {ZLIB: sector_pad(zlib.compress(data)), ZSTD: sector_pad(zstd.compress(data)), LZO: lzo}


@pytest.mark.parametrize("compression", [ZLIB, ZSTD, LZO])
def test_bit_flips_and_random_input_raise_only_decode_error_within_bounds(compression):
    stream = _streams()[compression]
    rng = random.Random(compression)
    size = 3 * SECTOR
    candidates = [rng.randbytes(rng.randrange(0, 2 * SECTOR)) for _ in range(200)]
    for _ in range(400):
        flipped = bytearray(stream)
        bit = rng.randrange(len(flipped) * 8)
        flipped[bit // 8] ^= 1 << (bit % 8)
        candidates.append(bytes(flipped))
    for candidate in candidates:
        for inline, bounds in ((False, (size, size)), (True, (1, SECTOR))):
            try:
                decoded = decompress(
                    compression, candidate, min_out=bounds[0], max_out=bounds[1], inline=inline
                )
            except DecodeError:
                continue
            assert bounds[0] <= len(decoded.data) <= bounds[1]
