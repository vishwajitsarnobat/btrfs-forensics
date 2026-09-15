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


@pytest.mark.parametrize("seed", [11, 12])
def test_every_hostile_corpus_agrees_with_lzallright(seed):
    """Truncated, byte-inserted, byte-deleted, bit-flipped and random streams: both decoders fail
    or both return the same bytes (an lzallright output over 4 KiB counting as a failure)."""
    result = lzo_hostile.run(seed=seed, vectors=0, mutations=400)
    assert result["disagreements"] == []
    assert result["agreement"] == dict.fromkeys(lzo_hostile.CORPORA, 400)


def test_harness_runs_and_btrfska_fails_cleanly():
    result = lzo_hostile.run(seed=1, vectors=50, mutations=100)
    ours = result["decoders"]["btrfska"]
    assert ours["round_trip_identical"] == 50
    assert ours["crafted"] == ("exception", "LzoError")
    assert ours["truncated"] == ("exception", "LzoError")
    for corpus in lzo_hostile.CORPORA:
        assert ours[corpus]["non_exception"] == ours[corpus]["over_bound"] == 0
        assert set(ours[f"{corpus}_failure_types"]) <= {"LzoError"}
