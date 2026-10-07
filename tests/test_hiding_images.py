"""The hiding detector on images (plan.md M6d): every planted corpus row is found with the right
technique at the planted place and nothing else is reported; the clean corpus is quiet; the four
btrfs images of fkie-cad/hide-and-seek-dataset, an independent planter, are found too. Planted
places are recomputed by running the same corpus/mutate.py function on the row's source image,
so every claim is relative to the images read, not to one build's numbers."""

import importlib.util
import json
import os
import re
from collections import Counter

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.schema import SCHEMA_VERSION
from btrfska.hiding.detect import detect
from btrfska.scan.roots import discover_image
from btrfska.substrate import csum, ondisk
from btrfska.substrate import superblock as sb
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from tests.helpers import REPO_ROOT, SCENARIOS, scratch_dir

pytestmark = pytest.mark.vm

HIDE_AND_SEEK = REPO_ROOT / "images" / "hide-and-seek"
MIRROR1 = ondisk.sb_offset(1)


def load_mutate():
    spec = importlib.util.spec_from_file_location("mutate", REPO_ROOT / "corpus" / "mutate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MUTATE = load_mutate()


def image(name: str, where=SCENARIOS):
    path = where / f"{name}.img"
    if not path.exists():
        hint = "corpus/hide_and_seek.py" if where == HIDE_AND_SEEK else "corpus/build.py"
        pytest.skip(f"{name}.img absent: fetch or build it with {hint}")
    return path


def run(path):
    with open_image(path) as img:
        fs = open_filesystem(img, allow_unsupported=True)  # m1_unknown_incompat is gated

        def history():
            return [entry.chunk_map for entry in discover_image(img, fs).discovery.chunk_maps]

        return detect(img, fs, history)


def planted(base: str, plant) -> list[tuple[int, int]]:
    """[start, end) of every patch the mutate function writes into the row's source image."""
    path = image(base)
    with open(path, "rb") as src:
        result = plant(src, os.fstat(src.fileno()).st_size, path)
    patches = result[0] if isinstance(result, tuple) else result
    return [(offset, offset + len(data)) for offset, data in patches.items()]


# row: (source image, the mutate call, the techniques expected, at most this many per technique)
M = MUTATE
PLANTED = {
    "m6_hide_sb_reserved": ("m1_sha256_bgt",
                            lambda f, s, p: M.plant_sb_field(f, s, "reserved", M.HIDDEN),
                            {"superblock_reserved": 2}),
    "m6_hide_sb_gated": ("m1_blake2b",
                         lambda f, s, p: M.plant_sb_field(f, s, "nr_global_roots", M.HIDDEN),
                         {"superblock_reserved": 2}),
    "m6_hide_sb_padding": ("m1_xxhash", lambda f, s, p: M.plant_sb_field(f, s, "padding", M.HIDDEN),
                           {"superblock_padding": 2}),
    "m6_hide_chunk_array": ("m6_datacsum",
                            lambda f, s, p: M.plant_chunk_array_slack(f, s, M.HIDDEN),
                            {"sys_chunk_array_slack": 2}),
    "m6_hide_backup_roots": ("m1_blake2b", lambda f, s, p: M.plant_backup_roots(f, s),
                             {"backup_root_divergence": 1}),
    "m6_hide_pre_sb": ("m1_sha256_bgt", lambda f, s, p: M.plant_pre_sb(f, s, M.HIDDEN, 0x8000),
                       {"pre_superblock": 1}),
    "m6_hide_inode_reserved": ("m1_blake2b", lambda f, s, p: M.plant_inode_reserved(p, M.HIDDEN),
                               {"inode_reserved": 1}),
    "m6_hide_nsec": ("m1_xxhash", lambda f, s, p: M.plant_nsec(p, M.NSEC_MESSAGE),
                     {"timestamp_nsec": 1}),
    "m6_hide_string_item": ("m6_datacsum", lambda f, s, p: M.plant_string_item(p, M.HIDDEN),
                            {"string_item": 1}),
    "m6_hide_file_slack": ("m6_datacsum",
                           lambda f, s, p: M.plant_file_slack(p, "plain.txt", M.HIDDEN, False),
                           {"file_slack": 1}),
    "m6_hide_device_slack": ("m1_sha256_bgt", lambda f, s, p: M.plant_device_slack(p, M.HIDDEN),
                             {"device_slack": 1}),
    "m4_planted_slack": ("m3_wide", lambda f, s, p: M.plant_slack(p, M.MESSAGE.encode()),
                         {"node_slack": 4}),
}  # fmt: skip


def where(finding) -> int:
    """The first byte a finding points at."""
    if finding.technique == "device_slack":
        return finding.detail["runs"][0][0]
    return finding.detail.get("first_nonzero", finding.physical)


@pytest.mark.parametrize("name", sorted(PLANTED))
def test_each_planted_technique_is_found_where_it_was_planted_and_nothing_else(name):
    base, plant, expected = PLANTED[name]
    found, summary = run(image(name))
    assert Counter(f.technique for f in found) == Counter(expected)
    assert summary["findings"] == sum(expected.values())
    ranges = planted(base, plant)
    for finding in found:
        if finding.technique == "backup_root_divergence":
            # The slot of the superblock's generation was overwritten, in every copy.
            assert any(lo <= finding.physical < hi for lo, hi in ranges)
            assert "no slot holds the superblock's generation" in finding.evidence
            continue
        assert any(lo <= where(finding) < hi for lo, hi in ranges), (finding, ranges)


def test_planted_messages_read_back():
    found, _ = run(image("m6_hide_sb_reserved"))
    assert all(f.text.startswith("hidden by corpus/mutate.py") for f in found)
    found, _ = run(image("m6_hide_file_slack"))
    assert found[0].detail["csum"] == "covers_hidden" and found[0].text.startswith("hidden by")
    found, _ = run(image("m6_hide_nsec"))
    assert all(value >= 10**9 for value in found[0].detail["nsec"].values())
    found, _ = run(image("m6_hide_sb_gated"))
    assert {f.detail["field"] for f in found} == {"nr_global_roots"}


def log_value(name: str, marker: str) -> str:
    image(name)
    match = re.search(rf"=== {marker} (\S+)", (SCENARIOS / f"{name}.log").read_text())
    assert match, f"{marker} not in {name}.log"
    return match[1]


def test_the_hidden_snapshot_is_found_and_the_normally_named_one_is_not():
    found, _ = run(image("m6_hidden_snapshot"))
    hidden = int(log_value("m6_hidden_snapshot", "HIDDEN-ID"))
    assert {f.technique for f in found} == {"hidden_name"}
    assert all(f.detail["subvolume"] == hidden and f.detail["name_hex"] == "efbbbf" for f in found)
    top = [f for f in found if f.detail["tree"] == ondisk.FS_TREE_OBJECTID]
    assert [f.detail["path"] for f in top] == ["/.lib32/\\ufeff"]
    assert ".lib32" in top[0].evidence
    # The normal snapshot was taken while the hidden one sat at the top, so it holds the hidden
    # name as a stub entry; its own name is never reported.
    assert not any(f.detail["path"].endswith("snapshot-weekly") for f in found)


# The clean corpus: no finding, except the documented ones (plan.md M6d).
EXPLAINED = {
    # mkfs --mixed -b 60M over an older, larger filesystem: past the new last device extent and
    # past the new device size lie the old filesystem's bytes (M6f finds its blocks).
    "m6_reformat_geometry": {"device_slack": 2},
}
CLEAN = sorted(
    {path.stem for path in SCENARIOS.glob("*.img")}
    - set(PLANTED) - {"m6_hidden_snapshot"}
)  # fmt: skip


@pytest.mark.parametrize("name", CLEAN)
def test_clean_corpus_images_are_quiet(name):
    found, summary = run(image(name))
    assert Counter(f.technique for f in found) == Counter(EXPLAINED.get(name, {}))
    assert summary["trees"]["blocks"] > 0


@pytest.mark.sandbox
def test_sandbox_is_quiet(sandbox_img):
    found, _ = run(sandbox_img)
    assert found == []


@pytest.mark.parametrize("base", ["m1_xxhash", "m1_sha256_bgt", "m1_blake2b", "m6_datacsum"])
def test_every_planting_subcommand_recomputes_checksums_for_every_csum_type(base):
    """The patches leave every superblock copy and tree block they rewrite valid, in all four
    csum types (crc32c, xxhash64, sha256, blake2b)."""
    path = image(base)
    with open_image(path) as img:
        csum_type = sb.read_superblock(img).selected.fields["csum_type"]
        nodesize = sb.read_superblock(img).selected.fields["nodesize"]
    calls = [plant for name, (_, plant, _) in PLANTED.items()
             if name not in ("m6_hide_file_slack", "m4_planted_slack")]  # fmt: skip
    if base == "m6_datacsum":
        calls.append(PLANTED["m6_hide_file_slack"][1])
    checked = 0
    for plant in calls:
        with open(path, "rb") as src:
            result = plant(src, os.fstat(src.fileno()).st_size, path)
        patches = result[0] if isinstance(result, tuple) else result
        for offset, data in patches.items():
            if len(data) == ondisk.SUPER_INFO_SIZE and offset in map(ondisk.sb_offset, range(3)):
                mirror = [ondisk.sb_offset(m) for m in range(3)].index(offset)
                assert sb.parse_copy(data, mirror).valid
                checked += 1
            elif len(data) == nodesize:
                assert csum.block_csum_ok(csum_type, data)
                checked += 1
    assert checked >= 8


# ---------------------------------------------------------------------------
# fkie-cad/hide-and-seek-dataset (corpus/hide_and_seek.py; no licence, never committed)
# ---------------------------------------------------------------------------
def test_hide_and_seek_superblock_image_shows_an_overwritten_mirror():
    """The metadata says reserved and slack bytes of both copies; what the image holds is
    mirror 1 overwritten from its first byte (docs/research/fishy-btrfs.md §4.2)."""
    found, _ = run(image("btrfs_superblock", HIDE_AND_SEEK))
    assert [(f.technique, f.physical) for f in found] == [("superblock_slot", MIRROR1)]
    assert found[0].text.startswith("HIDDEN DATA")


def test_hide_and_seek_inode_reserved_image():
    found, _ = run(image("btrfs_inode_reserved", HIDE_AND_SEEK))
    reserved = sorted((f.detail["inode"], f.physical) for f in found
                      if f.technique == "inode_reserved")  # fmt: skip
    # metadata.json: absolute_start_offset_bytes of each 32-byte run, by inode.
    assert reserved == [(256, 39583664), (257, 39583424), (260, 39583012), (263, 39581079),
                        (266, 39580858)]  # fmt: skip
    divergence = [f for f in found if f.technique == "copy_divergence"]
    assert len(divergence) == 1 and len(found) == 6  # the other DUP copy was left as it was


def test_hide_and_seek_hidden_snapshot_image():
    found, _ = run(image("btrfs_hidden_snapshot", HIDE_AND_SEEK))
    assert [(f.technique, f.detail["path"], f.detail["kind"]) for f in found] == [
        ("hidden_name", "/.lib32/\\ufeff", "directory")
    ]


def test_hide_and_seek_raid1_slack_images():
    found, _ = run(image("btrfs_raid1_slack_dev2", HIDE_AND_SEEK))
    assert [(f.technique, f.detail["area"], f.detail["devid"]) for f in found] == [
        ("device_slack", "past_last_extent", 2)
    ]
    lo, hi = found[0].detail["runs"][0]
    assert lo <= 734003200 < hi  # metadata.json offset_start
    assert run(image("btrfs_raid1_slack_dev1", HIDE_AND_SEEK))[0] == []


def test_catalog_build_stores_the_findings_without_a_schema_change():
    with scratch_dir("test_hiding_db_") as d:
        built = build_catalog(image("m6_hide_string_item"), d / "h.db", hiding=True)
        conn = db.open_readonly(d / "h.db")
        with conn:
            version, summary = conn.execute(
                "SELECT schema_version, scan_summary FROM scan_runs"
            ).fetchone()
            problems = [row[0] for row in conn.execute(
                "SELECT detail FROM problems WHERE source = 'hiding'")]  # fmt: skip
        conn.close()
        plain = build_catalog(image("m6_hide_string_item"), d / "plain.db")
    hidden = json.loads(summary)["hiding"]
    assert version == SCHEMA_VERSION and built.image_unchanged
    assert hidden["by_technique"]["string_item"] == 1 and hidden["findings"] == 1
    assert [r["technique"] for r in hidden["records"]] == ["string_item"]
    assert any(line.startswith("finding string_item:") for line in problems)
    assert "hiding" not in plain.scan_summary
