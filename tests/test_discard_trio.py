"""The discard trio (EXP-000, EXP-002): btrfska's full sweep counted under the probe's rules gives
the same counts as corpus/vm/probe_stale_metadata.py (coverage agreement: the count reuses
btrfska's scan plan and prefilter, so it is not an independent re-implementation), and old-root
discovery per discard mode. Each image is the
representative run of its mode (corpus/manifest.tsv); tests skip when it is absent."""

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
# probe_stale_metadata.py on each image: fsid_blocks stale_blocks needle_copies nonzero_blocks
PROBE = {"none": [367, 355, 18, 832], "async": [367, 355, 18, 832], "sync": [43, 31, 2, 107]}


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
    assert probe == PROBE[mode]
    assert [compat["fsid_blocks"], compat["stale_blocks"]] == probe[:2]
    # Blocks 0-15 (the first 64 KiB) are read by the probe only, and hold no fsid; btrfska probes
    # no block the probe skips. Both use the same fsid and superblock generation.
    assert (compat["probe_only_blocks"], compat["probe_only_hits"]) == ([[0, 15]], 0)
    assert (compat["btrfska_only_blocks"], compat["btrfska_only_hits"]) == ([], 0)
    assert compat["fsid_equal"] and compat["generation_equal"] and compat["sectorsize"] == 4096


@pytest.fixture(scope="module")
def trio():
    result = {}
    for mode in TRIO:
        with open_image(image(mode)) as img:
            fs = open_filesystem(img)
            scan = scan_image(img, fs, full_sweep=True)
            for _ in scan.classified:
                pass
            result[mode] = (scan.summary, discover_image(img, fs, full_sweep=True).discovery)
    return result


@pytest.mark.parametrize("mode", ["none", "async"])
def test_without_trims_every_backup_state_and_31_older_states_survive(trio, mode):
    summary, found = trio[mode]
    classes = ("candidates", "valid", "live", "backup_reachable", "unreferenced")
    assert [summary[name] for name in classes] == [367, 362, 22, 24, 316]
    assert summary["walk_failures"] == {"current": {}, "backup": {}}
    assert found.root_tree_candidates == 35
    assert all(r.indexed and r.candidate for r in found.rediscovered)
    backups = [s for s in found.states if s.known_as]
    assert [s.generation for s in backups] == [38, 37, 36, 35]
    assert all(s.completeness == 1.0 for s in backups)
    beyond = [s for s in found.states if not s.known_as]
    assert len(beyond) == 31 and sum(s.completeness == 1.0 for s in beyond) == 30
    # The generation-3 csum root is the mkfs leaf at 1130496 without the WRITTEN flag: present in
    # the state's own chunk, so corrupt, not unmapped.
    assert [(s.generation, s.missing) for s in beyond if s.completeness < 1] == [
        (3, {"corrupt": 1})
    ]


def test_sync_discard_zeroes_the_older_backup_states(trio):
    summary, found = trio["sync"]
    classes = ("candidates", "valid", "live", "backup_reachable", "unreferenced")
    assert [summary[name] for name in classes] == [43, 38, 22, 0, 16]
    assert summary["walk_failures"] == {"current": {}, "backup": {"zeroed": 12}}
    assert found.root_tree_candidates == 2
    lost = [(r.root.source, r.root.tree) for r in found.rediscovered if not r.indexed]
    assert lost == [
        (f"backup:{generation}", tree)
        for generation in (35, 36, 37)
        for tree in ("root", "extent", "chunk", "dev")
    ]
    # The fs and csum roots of backups 35-37 are shared with the live state and survive.
    assert all(r.candidate for r in found.rediscovered if r.indexed)
    assert [(s.generation, s.known_as, s.missing) for s in found.states] == [
        (38, ("backup:38", "current"), {}),
        (3, (), {"corrupt": 1}),
    ]


def test_the_sync_summary_counts_surviving_slot_references_and_distinct_blocks(capsys):
    """26 superblock and backup slot references name 14 distinct blocks. Under sync discard 14
    references survive, but only 6 of the 14 blocks: the lost references are the root, extent,
    chunk and dev roots of backups 35-37, and backups 35-37 share one chunk and one dev root."""
    assert main(["roots", str(image("sync")), "--full-sweep"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert (
        "rediscovered: 14/26 superblock and backup root slot references are candidate roots "
        "(14 indexed), naming 14 distinct blocks: 6/14 candidate roots (6 indexed)"
    ) in lines
