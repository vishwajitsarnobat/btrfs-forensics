"""experiments/exp010.py: the merged newest-wins chunk map it emulates (EXP-010 §2.3).

No image needed; the measurement itself is in experiments/EXP-010.md.
"""

import pytest

from btrfska.substrate.chunks import BG, Chunk, Stripe, UnmappedAddress
from experiments import exp010

MIB = 1 << 20
UUID = bytes(16)
DEVICES = {1: UUID}


def data(logical: int, physical: int, length: int = 64 * MIB) -> Chunk:
    return Chunk(logical, length, BG["DATA"], (Stripe(1, physical, UUID),))


def test_the_newest_record_per_chunk_start_wins():
    maps = [
        ("historical:16@1", 16, [data(100 * MIB, 400 * MIB), data(200 * MIB, 500 * MIB)]),
        ("current", 1 << 64, [data(100 * MIB, 150 * MIB)]),
    ]
    merged = exp010.MergedMap(maps, DEVICES)
    # the reused start goes to the newest record, the removed chunk stays as it was
    assert merged.copies(100 * MIB + 4096, 4096)[0].physical == 150 * MIB + 4096
    assert merged.copies(200 * MIB, 4096)[0].physical == 500 * MIB
    assert merged.source == exp010.MERGED


def test_a_lookup_bisects_on_chunk_start_even_where_chunks_of_other_starts_overlap():
    maps = [
        ("historical:5@1", 5, [data(100 * MIB, 400 * MIB)]),
        ("current", 1 << 64, [data(132 * MIB, 600 * MIB)]),
    ]
    merged = exp010.MergedMap(maps, DEVICES)
    assert len(merged.chunks) == 2  # ChunkMap alone would drop the overlapping later one
    assert merged.copies(140 * MIB, 4096)[0].physical == 608 * MIB
    assert merged.copies(120 * MIB, 4096)[0].physical == 420 * MIB
    with pytest.raises(UnmappedAddress):
        merged.copies(300 * MIB, 4096)


def test_maps_are_applied_oldest_first_whatever_order_they_arrive_in():
    maps = sorted(
        [("current", 1 << 64, [data(0, 300 * MIB)]), ("historical:3@1", 3, [data(0, 100 * MIB)])],
        key=lambda m: (m[1], m[0]),
    )
    assert exp010.MergedMap(maps, DEVICES).copies(0, 4096)[0].physical == 300 * MIB
