"""The discard trio (EXP-000, EXP-002): btrfska's full sweep counted under the probe's rules gives
the same counts as corpus/vm/probe_stale_metadata.py (coverage agreement: the count reuses
btrfska's scan plan and prefilter, so it is not an independent re-implementation), and old-root
discovery per discard mode. Tests skip when an image is absent.

The images are rebuilt by corpus/build.py, and a guest run is not bit-stable (plan.md §7): the
number of transaction commits depends on timing, so block counts and the final generation differ
slightly between builds and hosts (EXP-000 saw 365-367 blocks in 15 runs; a slower CI runner gave
363 and one more generation). The tests therefore assert what EXP-000 and EXP-002 claim, relative
to each image's own superblock generation and its own probe output. The measured numbers are in
experiments/EXP-000.md and EXP-002.md, not here."""

import pytest

from btrfska.cli import main
from btrfska.scan.classify import scan_image
from btrfska.scan.roots import discover_image
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from experiments.exp002 import probe_columns, probe_compat
from tests.helpers import SCENARIOS
from tests.test_vm_images import assert_unchanged_since_built, manifest_rows

pytestmark = pytest.mark.vm

TRIO = {
    "none": "s01_discard_none_r1",
    "async": "s01_discard_async_r1",
    "sync": "s01_discard_sync_r1",
}
CLASSES = ("candidates", "valid", "live", "backup_reachable", "unreferenced")
BACKUP_TREES = ("root", "extent", "chunk", "dev")


def image(mode: str):
    path = SCENARIOS / f"{TRIO[mode]}.img"
    if not path.exists():
        pytest.skip(f"{path.name} absent: regenerate it with the corpus/manifest.tsv command")
    return path


def test_manifest_lists_the_discard_trio():
    rows = manifest_rows()
    for mode, name in TRIO.items():
        assert f"discard_{mode}.sh" in rows[name]["command"]


@pytest.mark.parametrize("mode", TRIO)
def test_trio_image_is_unchanged_since_it_was_built(mode):
    assert_unchanged_since_built(image(mode))


@pytest.mark.parametrize("mode", TRIO)
def test_full_sweep_candidates_cover_the_blocks_the_probe_counts(mode):
    path = image(mode)
    probe = probe_columns(path)
    compat = probe_compat(path)
    # probe columns: fsid_blocks stale_blocks needle_copies nonzero_blocks
    assert len(probe) == 4 and probe[0] >= probe[1] > 0
    assert [compat["fsid_blocks"], compat["stale_blocks"]] == probe[:2]
    # Blocks 0-15 (the first 64 KiB) are read by the probe only, and hold no fsid; btrfska probes
    # no block the probe skips. Both use the same fsid and superblock generation.
    assert (compat["probe_only_blocks"], compat["probe_only_hits"]) == ([[0, 15]], 0)
    assert (compat["btrfska_only_blocks"], compat["btrfska_only_hits"]) == ([], 0)
    assert compat["fsid_equal"] and compat["generation_equal"] and compat["sectorsize"] == 4096


def test_sync_discard_removes_most_stale_metadata():
    """EXP-000's hypothesis: under discard=sync fewer than 20 % of the stale blocks survive."""
    stale = {mode: probe_columns(image(mode))[1] for mode in ("none", "sync")}
    assert stale["sync"] < 0.2 * stale["none"]


@pytest.fixture(scope="module")
def trio():
    result = {}
    for mode in TRIO:
        with open_image(image(mode)) as img:
            fs = open_filesystem(img)
            scan = scan_image(img, fs, full_sweep=True)
            for _ in scan.classified:
                pass
            found = discover_image(img, fs, full_sweep=True).discovery
            result[mode] = (scan.summary, found, fs.fields["generation"])
    return result


@pytest.mark.parametrize("mode", ["none", "async"])
def test_without_trims_every_backup_state_and_dozens_of_older_states_survive(trio, mode):
    summary, found, generation = trio[mode]
    candidates, valid, live, backup_reachable, unreferenced = (summary[name] for name in CLASSES)
    assert candidates == probe_columns(image(mode))[0]
    assert live + backup_reachable + unreferenced == valid <= candidates
    assert live > 0 and backup_reachable > 0
    assert unreferenced > live + backup_reachable  # most surviving history is reached by no root
    assert summary["walk_failures"] == {"current": {}, "backup": {}}
    assert all(r.indexed and r.candidate for r in found.rediscovered)
    backups = [s for s in found.states if s.known_as]
    assert [s.generation for s in backups] == [generation - back for back in range(4)]
    assert all(s.completeness == 1.0 for s in backups)
    beyond = [s for s in found.states if not s.known_as]
    assert found.root_tree_candidates == len(backups) + len(beyond)
    assert len(beyond) >= 20  # EXP-002 measured 31
    assert all(s.generation < generation - 3 for s in beyond)
    # The generation-3 csum root is the mkfs leaf at 1130496 without the WRITTEN flag: present in
    # the state's own chunk, so corrupt, not unmapped. Every other older state is complete.
    assert [(s.generation, s.missing) for s in beyond if s.completeness < 1] == [
        (3, {"corrupt": 1})
    ]


def test_sync_discard_zeroes_the_older_backup_states(trio):
    summary, found, generation = trio["sync"]
    candidates, valid, live, backup_reachable, unreferenced = (summary[name] for name in CLASSES)
    assert candidates == probe_columns(image("sync"))[0]
    assert live + backup_reachable + unreferenced == valid <= candidates
    assert live > 0 and backup_reachable == 0  # nothing is reached from an older backup only
    assert candidates < 0.2 * trio["none"][0]["candidates"]
    # 3 older backups x 4 roots each were trimmed; the walks meet zeros, not damage.
    assert summary["walk_failures"] == {"current": {}, "backup": {"zeroed": 12}}
    lost = [(r.root.source, r.root.tree) for r in found.rediscovered if not r.indexed]
    assert lost == [
        (f"backup:{older}", tree)
        for older in range(generation - 3, generation)
        for tree in BACKUP_TREES
    ]
    # The fs and csum roots of the three older backups are shared with the live state and survive.
    assert all(r.candidate for r in found.rediscovered if r.indexed)
    assert found.root_tree_candidates == 2
    assert [(s.generation, s.known_as, s.missing) for s in found.states] == [
        (generation, (f"backup:{generation}", "current"), {}),
        (3, (), {"corrupt": 1}),
    ]


def test_the_sync_summary_counts_surviving_slot_references_and_distinct_blocks(capsys):
    """26 superblock and backup slot references name 14 distinct blocks. Under sync discard 14
    references survive, but only 6 of the 14 blocks: the lost references are the root, extent,
    chunk and dev roots of the three older backups, which share one chunk and one dev root."""
    assert main(["roots", str(image("sync")), "--full-sweep"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert (
        "rediscovered: 14/26 superblock and backup root slot references are candidate roots "
        "(14 indexed), naming 14 distinct blocks: 6/14 candidate roots (6 indexed)"
    ) in lines
