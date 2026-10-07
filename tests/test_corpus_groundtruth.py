"""corpus/groundtruth.py: the scenario log parser and its consistency check. No image needed."""

import importlib.util
import random

import pytest

from tests.helpers import REPO_ROOT

spec = importlib.util.spec_from_file_location("corpus_gt", REPO_ROOT / "corpus" / "groundtruth.py")
gt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gt)

H1, H2 = "a" * 64, "b" * 64
LOG = f"""\
=== HOST-MKFS mkfs.btrfs, part of btrfs-progs v6.6.3
=== HOST-MKFS-ARGS -q -f --csum crc32c -O ^block-group-tree
=== HOST-SIZE 512M
=== HOST-DEVICES 1
=== HOST-DISCARD unmap
SeaBIOS (version 1.17.0)
\x1b[2J=== GUEST Linux version 7.0.0-31-generic (buildd@x) #31 SMP
=== SCENARIO matrix MOUNTOPTS commit=300,discard=sync
=== MOUNTED /dev/vda /mnt btrfs rw,relatime,discard,space_cache=v2,commit=300 0 0
=== MATRIX op=delete size=512M compress=none csum=crc32c bgt=off discard=sync layout=single
=== RECLAIM space=data bg_reclaim_threshold=0 reclaim_count=0
=== COMMIT 7 6
=== EVENT create 256 7 data
=== EVENT create 257 7 data/a.txt sha256={H1}
=== PHASE settled-after-population 7
=== COMMIT 8 7
=== EVENT overwrite 257 8 data/a.txt sha256={H2}
=== COMMIT 9 8
=== EVENT rename 257 9 data/a.txt data/b.txt
=== EVENT create 258 9 data/c.txt sha256={H1}
=== COMMIT 12 9
=== EVENT delete 258 12 data/c.txt
=== SCENARIO-DONE
"""


def test_a_matrix_log_parses_into_every_field():
    truth = gt.parse(LOG)
    assert truth.host == {
        "mkfs": "mkfs.btrfs, part of btrfs-progs v6.6.3",
        "mkfs_args": "-q -f --csum crc32c -O ^block-group-tree",
        "size": "512M",
        "devices": "1",
        "discard": "unmap",
    }
    assert truth.guest_kernel == "7.0.0-31-generic"
    assert truth.mount_options_asked == "commit=300,discard=sync"
    assert "discard" in truth.mount_options and "commit=300" in truth.mount_options
    assert truth.matrix["discard"] == "sync" and truth.matrix["layout"] == "single"
    assert truth.reclaim == [{"space": "data", "bg_reclaim_threshold": "0", "reclaim_count": "0"}]
    assert truth.phases == [("settled-after-population", 7)]
    assert truth.done
    assert truth.events[1] == gt.Event("create", 257, 7, "data/a.txt", None, H1, 6)
    assert truth.events[3] == gt.Event("rename", 257, 9, "data/a.txt", "data/b.txt", None, 8)
    assert truth.commits == [(7, 6), (8, 7), (9, 8), (12, 9)]
    # the kernel committed twice on its own before the last sync: only a window is claimed
    assert [e.exact for e in truth.events] == [True] * 5 + [False]
    assert gt.check(truth) == []
    final = gt.final_states(truth)
    assert set(final) == {"data", "data/b.txt"}
    assert final["data/b.txt"].sha256 == H2 and final["data/b.txt"].generation == 8


def test_a_deep_log_without_hashes_parses():
    log = "=== EVENT create 300 12 victims/v_1.txt\n=== EVENT unlink 300 13 victims/v_1.txt\n"
    truth = gt.parse(log)
    assert [e.kind for e in truth.events] == ["create", "unlink"]
    assert truth.events[0].after is None and not truth.events[0].exact
    assert gt.check(truth) == [] and gt.final_states(truth) == {}


@pytest.mark.parametrize(
    "lines, problem",
    [
        (["create 1 5 a", "create 2 4 b"], "generation goes back"),
        (["create 1 5 a", "create 1 5 a"], "exists already"),
        (["delete 1 5 a"], "no live path"),
        (["create 1 5 a", "delete 2 5 a"], "no live path with inode 2"),
        (["create 1 5 a", "create 2 5 b", "rename 1 6 a b"], "b exists already"),
        (["create 1 5 a", "modify 1 6 a"], "no content hash"),
    ],
)
def test_check_names_each_inconsistency(lines, problem):
    truth = gt.parse("".join(f"=== EVENT {line}\n" for line in lines))
    problems = gt.check(truth)
    assert problems and any(problem in p for p in problems), problems


@pytest.mark.parametrize(
    "line",
    [
        "=== EVENT create x 5 a",
        "=== EVENT create 1 five a",
        "=== EVENT explode 1 5 a",
        "=== EVENT create 1 5",
        "=== EVENT create 1 5 a b",
        "=== EVENT rename 1 5 a",
        f"=== EVENT delete 1 5 a sha256={H1}",
        "=== EVENT create 1 5 a=b",
        "=== PHASE settled",
        "=== PHASE settled x",
        "=== MOUNTED /dev/vda",
        "=== MATRIX nothing here",
        "=== COMMIT 7",
        "=== COMMIT 7 six",
    ],
)
def test_a_malformed_line_raises_log_error_with_its_number(line):
    with pytest.raises(gt.LogError, match="line 2"):
        gt.parse(f"boot noise\n{line}\n")


def test_an_event_not_after_its_commit_window_is_an_inconsistency():
    truth = gt.parse("=== COMMIT 5 5\n=== EVENT create 1 5 a\n")
    assert any("not after generation 5" in p for p in gt.check(truth))


def test_hostile_logs_raise_log_error_or_parse():
    """Random bytes, random marker soup and truncations: LogError or a result, nothing else."""
    rng = random.Random(58)
    words = ["===", "EVENT", "COMMIT", "PHASE", "MATRIX", "RECLAIM", "MOUNTED", "HOST-X", "GUEST",
             "create", "rename", "delete", "1", "18446744073709551616", "-3", "sha256=" + H1,
             "a/b", "=", "\x00", " ", "x=y", "SCENARIO", "MOUNTOPTS"]  # fmt: skip
    samples = [LOG[:cut] for cut in range(0, len(LOG), 7)]
    samples += [bytes(rng.randrange(256) for _ in range(400)).decode("latin-1") for _ in range(50)]
    samples += [
        "\n".join(
            " ".join(rng.choice(words) for _ in range(rng.randrange(1, 9))) for _ in range(30)
        )
        for _ in range(300)
    ]
    for sample in samples:
        try:
            truth = gt.parse(sample)
        except gt.LogError:
            continue
        gt.check(truth)
        gt.final_states(truth)


def test_main_prints_json_and_refuses_bad_usage(capsys):
    assert gt.main([]) == 2
    path = REPO_ROOT / "pyproject.toml"  # any readable file without markers: an empty truth
    assert gt.main([str(path)]) == 0
    assert '"events": []' in capsys.readouterr().out
