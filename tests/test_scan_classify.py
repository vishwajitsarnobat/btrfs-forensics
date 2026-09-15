"""Orphan classification: live and backup reachability, chunk-map coverage, legacy parity."""

import collections
import contextlib
import io
import json
import os
import sys
from pathlib import Path

import pytest

from btrfska.scan.classify import Reachability, classify, scan_image, summarize
from btrfska.scan.kernel_numpy import NodeRecord
from btrfska.scan.regions import Region
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from btrfska.substrate.node import CHECK_NAMES, Check
from tests.helpers import REPO_ROOT, SCENARIOS, node_ctx, scratch_dir

LEGACY = json.loads(
    (Path(__file__).parent / "ground_truth" / "sandbox_legacy_scan.json").read_text()
)
CTX = node_ctx(nodesize=16384, generation=14)
MAPPED = [Region(8 << 20, 24 << 20, "METADATA|single", 1 << 30, 0)]
GAP = Region(0, 8 << 20, "unmapped_gap")


def record(physical, bytenr=None, generation=10, csum=True, valid=True, region=GAP):
    checks = tuple(Check(name, csum if name == "csum" else True) for name in CHECK_NAMES)
    return NodeRecord(
        physical=physical,
        bytenr=physical if bytenr is None else bytenr,
        generation=generation,
        owner=5,
        level=0,
        nritems=1,
        checks=checks,
        valid=valid,
        bytenr_mapped=True,
        maps_here=True,
        region=region,
        problems=(),
    )


def test_status_follows_reachability_and_never_counts_backups_as_live():
    reach = Reachability(
        live=frozenset({(9 << 20, 9 << 20)}),
        backup=frozenset({(9 << 20, 9 << 20), (10 << 20, 10 << 20)}),
        live_logical=frozenset({9 << 20}),
        extent_tree=frozenset({9 << 20}),
        problems=(),
    )
    records = [
        record(9 << 20),
        record(10 << 20),
        record(11 << 20),
        record(12 << 20, valid=False, csum=False),
        record(13 << 20, bytenr=9 << 20),  # a stale copy claiming a live address
    ]
    result = classify(records, reach, MAPPED, CTX)
    assert [(c.status, c.orphan) for c in result] == [
        ("live", False),
        ("backup_reachable", True),
        ("unreferenced", True),
        ("invalid", False),
        ("unreferenced", True),
    ]


def test_outside_map_and_the_legacy_compatible_definition():
    records = [
        record(1 << 20),  # in a gap, nodesize-aligned, older than the superblock
        record((8 << 20) + 4096),  # not nodesize-aligned
        record(9 << 20, generation=14),  # current generation
        record(10 << 20, csum=False, valid=False),
        record(11 << 20, csum=True, valid=False),  # csum ok, another check failed
    ]
    result = classify(records, Reachability.empty(), MAPPED, CTX)
    assert [c.outside_map for c in result] == [True, False, False, False, False]
    assert [c.legacy_orphan for c in result] == [True, False, False, False, True]


def test_summary_counts_per_class_and_region():
    reach = Reachability(
        live=frozenset({(9 << 20, 9 << 20)}),
        backup=frozenset({(10 << 20, 10 << 20)}),
        live_logical=frozenset({9 << 20}),
        extent_tree=frozenset({9 << 20, 42}),
        problems=(),
    )
    meta = MAPPED[0]
    records = [
        record(1 << 20),
        record(9 << 20, region=meta),
        record(10 << 20, region=meta),
        record(11 << 20, region=meta, valid=False, csum=False),
    ]
    summary = summarize(classify(records, reach, MAPPED, CTX), [GAP, meta], reach)
    assert summary["candidates"] == 4 and summary["valid"] == 3 and summary["invalid"] == 1
    assert (summary["live"], summary["orphans"]) == (1, 2)
    assert (summary["backup_reachable"], summary["unreferenced"]) == (1, 1)
    assert (summary["outside_map"], summary["outside_map_orphans"]) == (1, 1)
    assert summary["extent_tree_only"] == 1 and summary["walk_only"] == 0
    assert summary["regions"] == [
        {"region": GAP, "candidates": 1, "valid": 1, "live": 0, "orphans": 1},
        {"region": meta, "candidates": 3, "valid": 2, "live": 1, "orphans": 1},
    ]


@pytest.fixture(scope="module")
def sandbox_scans():
    path = REPO_ROOT / "sandbox.img"
    if not path.exists():
        pytest.skip("sandbox.img absent")
    with open_image(path) as img:
        fs = open_filesystem(img)
        return {
            mode: scan_image(img, fs, full_sweep=mode == "full") for mode in ("targeted", "full")
        }


@pytest.mark.sandbox
def test_sandbox_legacy_compatible_orphans_are_the_legacy_offsets(sandbox_scans):
    scan = sandbox_scans["targeted"]
    legacy = [c.record for c in scan.classified if c.legacy_orphan]
    assert [
        {"physical": r.physical, "bytenr": r.bytenr, "generation": r.generation,
         "owner": r.owner, "level": r.level}
        for r in legacy
    ] == LEGACY["orphans"]  # fmt: skip
    outside = [c.record for c in scan.classified if c.legacy_orphan and c.outside_map]
    # Block starts 0x100000..0x12c000 and 0x500000..0x520000; each header claims its own offset.
    assert len(outside) == 21
    assert all(
        0x100000 <= r.physical <= 0x12C000 or 0x500000 <= r.physical <= 0x520000 for r in outside
    )
    assert all(r.bytenr == r.physical and not r.bytenr_mapped for r in outside)


@pytest.mark.sandbox
def test_sandbox_reconciliation_of_the_legacy_orphans(sandbox_scans):
    scan = sandbox_scans["targeted"]
    legacy = [c for c in scan.classified if c.legacy_orphan]
    assert collections.Counter(c.status for c in legacy) == {
        "live": 8,
        "backup_reachable": 34,
        "unreferenced": 28,
        "invalid": 1,
    }
    assert collections.Counter(c.outside_map for c in legacy if c.status == "unreferenced") == {
        True: 20,
        False: 8,
    }
    # The invalid one: an empty generation-1 fs-tree leaf in a removed mkfs chunk. The csum is
    # good, but the kernel rejects an empty leaf of tree 5 (tree-checker.c:2047-2080).
    (invalid,) = [c for c in legacy if c.status == "invalid"]
    assert (invalid.record.physical, invalid.record.owner, invalid.record.nritems) == (
        1114112,
        5,
        0,
    )
    assert [c.name for c in invalid.record.checks if c.ok is False] == ["nritems"]
    assert invalid.outside_map


@pytest.mark.sandbox
def test_sandbox_scan_classes(sandbox_scans):
    summary = sandbox_scans["targeted"].summary
    assert {k: summary[k] for k in ("candidates", "valid", "invalid")} == {
        "candidates": 85,
        "valid": 84,
        "invalid": 1,
    }
    assert (summary["live"], summary["backup_reachable"], summary["unreferenced"]) == (20, 34, 30)
    assert (summary["outside_map"], summary["outside_map_orphans"]) == (20, 20)
    assert summary["bytenr_elsewhere"] == 20
    assert (summary["legacy_orphans"], summary["legacy_orphans_outside_map"]) == (71, 21)
    assert (summary["extent_tree_only"], summary["walk_only"]) == (0, 0)


@pytest.mark.sandbox
def test_sandbox_targeted_scan_equals_the_full_sweep(sandbox_scans):
    def key(scan):
        return [(c.record.physical, c.status, c.outside_map) for c in scan.classified]

    targeted, full = sandbox_scans["targeted"], sandbox_scans["full"]
    assert key(targeted) == key(full)
    regions = targeted.plan.regions
    outside = [
        c for c in full.classified
        if c.orphan and not any(r.start <= c.record.physical < r.end for r in regions)
    ]  # fmt: skip
    assert outside == []


@pytest.mark.sandbox
def test_sandbox_every_live_copy_is_found_by_the_scan(sandbox_scans):
    scan = sandbox_scans["targeted"]
    live = {(c.record.bytenr, c.record.physical) for c in scan.classified if c.status == "live"}
    assert live == scan.reach.live and len(live) == 20
    assert scan.reach.extent_tree == scan.reach.live_logical
    assert scan.reach.problems == ()


@pytest.mark.sandbox
def test_golden_legacy_offsets_match_a_live_legacy_run(sandbox_img):
    legacy_dir = str(REPO_ROOT / "legacy")
    if not os.path.isdir(legacy_dir):
        pytest.skip("legacy/ removed")
    sys.path.insert(0, legacy_dir)
    try:
        from utils.btree import sweep_for_orphans
        from utils.chunk_parser import build_scan_regions
        from utils.recovery_report import RecoveryReport
        from utils.superblock import parse_superblock

        with scratch_dir("test_scan_legacy_") as out, contextlib.redirect_stdout(io.StringIO()):
            sb = parse_superblock(str(sandbox_img))
            regions = build_scan_regions(
                sb["chunk_map"], sb["nodesize"], sandbox_img.stat().st_size
            )
            report = RecoveryReport(str(out))
            sweep_for_orphans(str(sandbox_img), sb, report, str(out), scan_regions=regions)
    finally:
        sys.path.remove(legacy_dir)
    assert [list(r) for r in regions] == LEGACY["regions"]
    assert report.orphan_offsets == [o["physical"] for o in LEGACY["orphans"]]


@pytest.mark.vm
@pytest.mark.parametrize("name", ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m1_lzo", "m1_zlib"])
def test_generated_images_scan_finds_every_live_copy_and_the_full_sweep_agrees(name):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent")
    with open_image(path) as img:
        fs = open_filesystem(img)
        targeted = scan_image(img, fs)
        full = scan_image(img, fs, full_sweep=True)
    live = {(c.record.bytenr, c.record.physical) for c in targeted.classified if c.status == "live"}
    assert live == targeted.reach.live
    assert targeted.reach.problems == ()
    assert targeted.reach.extent_tree == targeted.reach.live_logical
    valid_full = [(c.record.physical, c.status) for c in full.classified if c.record.valid]
    valid_targeted = [(c.record.physical, c.status) for c in targeted.classified if c.record.valid]
    assert valid_full == valid_targeted
