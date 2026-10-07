"""experiments/exp016.py: classifying reads, choosing ground truth, and one image end to end."""

import pytest

pytest.importorskip("dissect.btrfs")

from experiments import exp016  # noqa: E402
from tests.helpers import SCENARIOS  # noqa: E402


def row(**kw):
    return {"complete": True, "btrfska": "a", "dissect": "a"} | kw


def test_a_read_is_equal_only_when_complete_and_both_hashes_match():
    assert exp016.classify(row()) == "equal"
    assert exp016.classify(row(dissect="b")) == "differ"
    assert exp016.classify(row(dissect=None)) == "dissect_failed"
    assert exp016.classify(row(complete=False, btrfska=None)) == "btrfska_incomplete"


def test_ground_truth_is_taken_only_from_s01_built_images():
    assert exp016.s01_built("m1_lzo") and exp016.s01_built("s01_discard_sync_r1")
    for name in ("m2_logtree", "m3_wide", "m1_badnode", "m4_deep", "sandbox"):
        assert not exp016.s01_built(name)


@pytest.mark.vm
def test_m1_lzo_reads_equal_dissect_and_the_guest_hashes():
    path = SCENARIOS / "m1_lzo.img"
    if not path.exists():
        pytest.skip("m1_lzo.img absent")
    line = exp016.measure(path)
    assert line["reads"] and line["problems"] == []
    assert {exp016.classify(r) for r in line["reads"]} == {"equal"}
    assert {r["codec"] for r in line["reads"]} == {"lzo"}
    assert all(r["expected"] in (None, r["btrfska"]) for r in line["reads"])
    assert any(r["expected"] for r in line["reads"])
    assert all(not x["btrfska_only"] and not x["dissect_only"] for x in line["listing"])
