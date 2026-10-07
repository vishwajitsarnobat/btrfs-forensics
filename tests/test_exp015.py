"""experiments/exp015.py: the two orphan definitions, cross-tabulated on the image it reads."""

import pytest

from experiments import exp015
from tests.helpers import REPO_ROOT


def test_a_block_disagrees_when_exactly_one_definition_calls_it_an_orphan():
    assert exp015.disagrees(True, "live") and exp015.disagrees(True, "invalid")
    assert exp015.disagrees(False, "unreferenced") and exp015.disagrees(False, "backup_reachable")
    assert not exp015.disagrees(True, "backup_reachable")
    assert not exp015.disagrees(False, "live")


def test_objectids_above_two_to_the_63_are_negative():
    assert exp015.signed((1 << 64) - 9) == -9 and exp015.signed(5) == 5


@pytest.mark.sandbox
def test_sandbox_cross_table_accounts_for_every_candidate_and_every_disagreement():
    path = REPO_ROOT / "sandbox.img"
    if not path.exists():
        pytest.skip("sandbox.img absent")
    result = exp015.measure(path)
    cells = result["cells"]
    assert sum(c["blocks"] for c in cells) == result["candidates"]
    disagreeing = sum(
        c["blocks"] for c in cells if exp015.disagrees(c["legacy_orphan"], c["status"])
    )
    assert disagreeing == len(result["disagreements"]) > 0
    generation = result["superblock_generation"]
    for block in result["disagreements"]:
        if block["legacy_orphan"]:
            # Old but still named by the current state, or failing a check the prototype skips.
            assert block["status"] in ("live", "invalid") and block["generation"] < generation
            assert (block["status"] == "invalid") == bool(block["failed"])
        else:
            # An orphan the generation rule cannot see: written in the current generation.
            assert block["generation"] == generation
    assert exp015.measure(path, full_sweep=True)["cells"] == cells
