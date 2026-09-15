"""LZO1X decoder against lzallright (MIT, lzokay bindings), plus the hostile-input harness.

Skipped when the dev dependency group (lzallright) is not installed.
"""

import random

import pytest

from btrfska.substrate.lzo import LzoError, decompress

lzallright = pytest.importorskip("lzallright")

from tests.oracle import lzo_hostile  # noqa: E402


def test_round_trip_fuzz_is_identical_to_lzallright():
    """2 000 seeded vectors (random, zero, low-entropy, text; 1 B to 70 KiB)."""
    rng = random.Random(20260915)
    compressor = lzallright.LZOCompressor()
    mismatches = []
    for index in range(2000):
        data = lzo_hostile.vector(rng)
        stream = compressor.compress(data)
        ours = decompress(stream, len(data))
        theirs = compressor.decompress(stream, output_size_hint=len(data))
        if not ours == theirs == data:
            mismatches.append((index, len(data)))
    assert mismatches == []


def test_bit_flipped_sectors_agree_with_lzallright_and_raise_only_lzo_error():
    """Both decoders fail, or both return the same bytes, on every flipped stream."""
    rng = random.Random(7)
    compressor = lzallright.LZOCompressor()
    sector = bytes(rng.choice(b"abcdefgh\n ") for _ in range(4096))
    stream = compressor.compress(sector)
    for _ in range(1000):
        flipped = bytearray(stream)
        bit = rng.randrange(len(flipped) * 8)
        flipped[bit // 8] ^= 1 << (bit % 8)
        flipped = bytes(flipped)
        try:
            ours = decompress(flipped, 4096)
        except LzoError:
            ours = None
        try:
            theirs = compressor.decompress(flipped, output_size_hint=4096)
        except lzallright.LZOError:
            theirs = None
        if theirs is not None and len(theirs) > 4096:
            theirs = None  # lzallright has no hard output bound; ours raises output_overrun
        assert ours == theirs, flipped.hex()


def test_harness_runs_and_btrfska_fails_cleanly():
    result = lzo_hostile.run(seed=1, vectors=50, flips=100)
    ours = result["decoders"]["btrfska"]
    assert ours["round_trip_identical"] == 50
    assert ours["crafted"] == ("exception", "LzoError")
    assert ours["truncated"] == ("exception", "LzoError")
    assert ours["bit_flips"]["non_exception"] == 0
    assert set(ours["bit_flip_exception_types"]) <= {"LzoError"}
