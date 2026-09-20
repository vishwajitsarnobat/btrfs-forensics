"""experiments/exp004.py: parsing btrfs-find-root's output and the registered prediction P1.

No image and no btrfs-progs needed; the measurement itself is in experiments/EXP-004.md.
"""

from experiments import exp004

# Verbatim shape of `btrfs-find-root -a` output (btrfs-progs 6.6.3 and 7.1).
OUTPUT = """\
Superblock thinks the generation is 38
Superblock thinks the level is 0
Well block 65437696(gen: 38 level: 0) seems good, and it matches superblock
Well block 65323008(gen: 37 level: 0) seems good, but generation/level doesn't match, want gen: 38 level: 0
Well block 30474240(gen: 7 level: 1) seems good, but we are unsure about the correct generation/level
"""  # noqa: E501


def block(bytenr, generation, level, inside=True, aligned=True):
    return {
        "bytenr": bytenr,
        "generation": generation,
        "level": level,
        "inside_map": inside,
        "aligned": aligned,
    }


def test_well_block_lines_are_parsed_into_bytenr_generation_level():
    found = {tuple(map(int, m.groups())) for m in exp004.WELL.finditer(OUTPUT)}
    assert found == {(65437696, 38, 0), (65323008, 37, 0), (30474240, 7, 1)}


def test_the_found_tree_root_line_of_a_run_without_a_is_parsed_too():
    line = "Found tree root at 65437696 gen 38 level 0\n"
    assert [tuple(map(int, m.groups())) for m in exp004.FOUND.finditer(line)] == [(65437696, 38, 0)]


def test_prediction_keeps_only_blocks_inside_the_current_chunk_map():
    rows = [block(100, 5, 0), block(200, 4, 0, inside=False)]
    assert exp004.predicted_find_root(rows) == {(100, 5, 0)}


def test_prediction_drops_blocks_off_the_nodesize_grid_of_their_chunk():
    rows = [block(100, 5, 0), block(104, 6, 0, aligned=False)]
    assert exp004.predicted_find_root(rows) == {(100, 5, 0)}


def test_prediction_keeps_only_the_highest_level_of_each_generation():
    rows = [block(100, 5, 1), block(200, 5, 0), block(300, 5, 0), block(400, 6, 0)]
    assert exp004.predicted_find_root(rows) == {(100, 5, 1), (400, 6, 0)}


def test_the_highest_level_is_taken_over_visible_blocks_only():
    """A higher block outside the map is invisible to find-root, so it hides nothing."""
    rows = [block(100, 5, 1, inside=False), block(200, 5, 0)]
    assert exp004.predicted_find_root(rows) == {(200, 5, 0)}


def test_several_blocks_of_one_generation_at_the_top_level_are_all_predicted():
    rows = [block(100, 7, 0), block(200, 7, 0)]
    assert exp004.predicted_find_root(rows) == {(100, 7, 0), (200, 7, 0)}
