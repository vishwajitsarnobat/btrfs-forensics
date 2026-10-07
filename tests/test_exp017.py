"""experiments/exp017.py: generation alone against btrfska's anchored superblock selection."""

import pytest

from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from experiments import exp017
from tests.helpers import SCENARIOS, make_block

FSID_A, FSID_B = bytes.fromhex("aa" * 16), bytes.fromhex("bb" * 16)


def test_generation_alone_picks_a_higher_generation_foreign_copy():
    copies = [
        sb.parse_copy(make_block(0, generation=5, fsid=FSID_A), 0),
        sb.parse_copy(make_block(1, generation=900, fsid=FSID_B, csum_type=csum.SHA256), 1),
    ]
    assert exp017.by_generation(copies) is copies[1]
    assert sb.select(copies).selected is copies[0]


def test_generation_alone_ignores_invalid_copies():
    copies = [sb.parse_copy(make_block(0, generation=5), 0), sb.parse_copy(bytes(4096), 1)]
    assert exp017.by_generation(copies) is copies[0]
    assert exp017.by_generation([sb.parse_copy(bytes(4096), 0)]) is None


@pytest.mark.vm
def test_the_foreign_mirror_would_win_on_generation_and_its_chunk_root_fails_here():
    path = SCENARIOS / "m1_foreign_mirror.img"
    if not path.exists():
        pytest.skip("m1_foreign_mirror.img absent")
    result = exp017.measure(path)
    assert result["unchanged"] and not result["rules_agree"]
    assert result["selected"]["mirror"] == result["kernel"]["mirror"] == 0
    assert result["foreign"] == [result["generation_only"]]
    assert result["generation_only"]["generation"] > result["selected"]["generation"]
    replay = result["generation_only_chunk_root"]
    assert not replay["valid"] and any("fsid" in p for p in replay["problems"])
    assert result["selected_chunk_root"]["valid"]


@pytest.mark.vm
def test_the_rules_agree_on_the_image_the_foreign_copy_was_planted_in():
    path = SCENARIOS / "m1_xxhash.img"
    if not path.exists():
        pytest.skip("m1_xxhash.img absent")
    result = exp017.measure(path)
    assert result["rules_agree"] and result["foreign"] == []
    assert ondisk.sb_offset(result["selected"]["mirror"]) == result["selected"]["offset"]
