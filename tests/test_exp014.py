"""experiments/exp014.py: the bit-flip corpus is the harness's, and the decoders' claims hold.

Claims are checked relative to what the decoders return on the drawn streams, not against the
counts in experiments/EXP-014.md.
"""

import pytest

pytest.importorskip("lzallright")

from experiments import exp014  # noqa: E402
from tests.oracle import lzo_hostile  # noqa: E402


def test_the_streams_are_drawn_as_the_harness_draws_them():
    # lzo_hostile.run draws 2000 vectors, then the sector, then the corpora, bit flips first.
    ours = exp014.run(2, mutations=40)
    theirs = lzo_hostile.run(2, vectors=exp014.VECTORS, mutations=40)
    for name, entry in ours["decoders"].items():
        counts = theirs["decoders"][name]["bit_flips"]
        assert {k: entry[k] for k in exp014.KINDS} == {k: counts[k] for k in exp014.KINDS}


def test_each_stream_differs_from_the_original_by_one_bit():
    _, stream, flips = exp014.bit_flip_streams(1, mutations=50)
    for flipped in flips:
        assert len(flipped) == len(stream)
        assert sum(bin(a ^ b).count("1") for a, b in zip(flipped, stream, strict=True)) == 1


def test_btrfska_fails_only_with_its_own_error_and_never_beyond_one_sector():
    result = exp014.run(1, mutations=60)
    ours = result["decoders"]["btrfska"]
    assert ours["unflipped_correct"]
    assert ours["over_bound"] == ours["non_exception"] == 0
    assert set(ours["failure_types"]) <= {"LzoError"}
    assert sum(ours[k] for k in exp014.KINDS) == 60


def test_btrfska_and_lzallright_return_the_same_wrong_bytes():
    result = exp014.run(3, mutations=60)
    ours, theirs = result["decoders"]["btrfska"], result["decoders"]["lzallright"]
    assert ours["wrong"] == theirs["wrong"] > 0
    if "wrong_in_all_three" in result:  # dissect.util native installed
        assert result["wrong_identical_in_all_three"] == result["wrong_in_all_three"]
