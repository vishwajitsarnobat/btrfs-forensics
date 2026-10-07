"""Foreign-FSID discovery on the M6f images (plan.md M6f): two reformats and two fsid changes,
built in the guest by corpus/vm/scenarios/reformat.sh and fsid_change.sh. Every claim is
relative to the image and to its own log: the `=== FS` line of each life names its fsid, device
uuid, nodesize and csum type as dump-super read them."""

import json
import re

import pytest

from btrfska.catalog import db
from btrfska.catalog.build import build_catalog
from btrfska.catalog.schema import SCHEMA_VERSION
from btrfska.cli import main
from btrfska.scan.classify import scan_image
from btrfska.scan.foreign import foreign_scan
from btrfska.substrate import csum
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from tests.helpers import SCENARIOS, scratch_dir

pytestmark = pytest.mark.vm

LIFE = re.compile(
    r"=== FS fsid (\S+) metadata_uuid (\S+) dev_uuid (\S+) nodesize (\d+) csum_type (\d+)"
)


def image(name: str):
    path = SCENARIOS / f"{name}.img"
    if not path.exists():
        pytest.skip(f"{name}.img absent: build it with corpus/build.py")
    return path


def lives(name: str) -> list[dict]:
    """The `=== FS` line of every life in the image's log, in order."""
    log = (SCENARIOS / f"{name}.log").read_text()
    keys = ("fsid", "metadata_uuid", "dev_uuid", "nodesize", "csum_type")
    found = [dict(zip(keys, match, strict=True)) for match in LIFE.findall(log)]
    return [life | {"nodesize": int(life["nodesize"]), "csum_type": int(life["csum_type"])}
            for life in found]  # fmt: skip


_cache: dict[str, tuple] = {}


def foreign(name: str) -> tuple[dict, list, frozenset[int]]:
    """(summary, valid foreign physical offsets, live physical offsets of the current scan)."""
    if name not in _cache:
        records = []
        with open_image(image(name)) as img:
            fs = open_filesystem(img)
            scan = scan_image(img, fs)
            live = frozenset(c.record.physical for c in scan.classified if c.status == "live")
            summary = foreign_scan(img, fs, scan.plan.regions, records.append)
        _cache[name] = summary, [r.physical for r in records if r.valid], live
    return _cache[name]


@pytest.mark.parametrize("name", ["m6_reformat", "m6_reformat_geometry"])
def test_a_reformat_is_found_in_the_old_geometry(name):
    old, *_ = lives(name)
    summary, valid, live = foreign(name)
    (found,) = summary["filesystems"]
    assert found["fsid"] == old["fsid"]
    assert found["kind"] == "reformat"
    assert found["valid"] > 0 and valid and not set(valid) & live
    context = found["context"]
    assert (context["nodesize"], context["csum_type"]) == (old["nodesize"], old["csum_type"])
    assert summary["metadata_uuid_change"] is None


def test_the_same_geometry_reformat_is_inferred_and_dated_by_generation():
    old, *_ = lives("m6_reformat")
    (found,) = foreign("m6_reformat")[0]["filesystems"]
    assert found["context"]["source"] == "inferred" and found["superblocks"] == []
    # No old chunk-tree leaf survives the new mkfs at the same place; the generations decide.
    assert found["device_uuids"] == {}
    with open_image(image("m6_reformat")) as img:
        generation = open_filesystem(img).fields["generation"]
    assert found["generations"][1] > generation


def test_the_other_geometry_reformat_reads_its_context_from_the_surviving_superblock():
    old, new = lives("m6_reformat_geometry")
    assert (old["nodesize"], old["csum_type"]) == (32768, csum.CRC32C)  # the scenario's options
    assert (new["nodesize"], new["csum_type"]) == (4096, csum.XXHASH)
    (found,) = foreign("m6_reformat_geometry")[0]["filesystems"]
    assert found["context"]["source"] == "superblock" and found["context"]["mirror"] == 1
    assert [copy["fsid"] for copy in found["superblocks"]] == [old["fsid"]]
    assert old["dev_uuid"] in found["device_uuids"]
    assert new["dev_uuid"] not in found["device_uuids"]
    assert found["invalid"] == 0


def test_btrfstune_u_leaves_the_old_fsid_on_unlisted_blocks_and_keeps_the_device():
    before, after = lives("m6_fsid_u")
    assert before["fsid"] != after["fsid"] and before["dev_uuid"] == after["dev_uuid"]
    summary, valid, live = foreign("m6_fsid_u")
    (found,) = summary["filesystems"]
    assert found["fsid"] == before["fsid"] and found["kind"] == "fsid_change"
    assert after["dev_uuid"] in found["device_uuids"]
    assert valid and not set(valid) & live
    with open_image(image("m6_fsid_u")) as img:
        generation = open_filesystem(img).fields["generation"]
    assert found["generations"][1] <= generation


def test_btrfstune_m_leaves_no_foreign_header_and_is_read_from_the_superblock():
    before, after = lives("m6_fsid_m")
    summary, valid, _ = foreign("m6_fsid_m")
    assert summary["filesystems"] == [] and valid == []
    assert summary["metadata_uuid_change"] == {
        "fsid": after["fsid"],
        "metadata_uuid": before["fsid"],
    }
    assert after["metadata_uuid"] == before["fsid"]


@pytest.mark.parametrize("name", ["m1_xxhash", "m3_wide", "m4_deep", "m5_reuse", "m6_datacsum"])
def test_clean_images_have_no_foreign_filesystem(name):
    summary = foreign(name)[0]
    assert summary["filesystems"] == [] and summary["metadata_uuid_change"] is None


def test_the_transplanted_mirror_is_a_foreign_filesystem_without_blocks():
    (found,) = foreign("m1_foreign_mirror")[0]["filesystems"]
    assert (found["candidates"], found["context"]["source"]) == (0, "superblock")
    assert found["kind"] == "reformat"


def test_scan_json_carries_foreign_records(capsys):
    path = image("m6_fsid_u")
    assert main(["scan", str(path), "--foreign", "--json"]) == 0
    captured = capsys.readouterr()
    records = [json.loads(line) for line in captured.out.splitlines()]
    nodes = [r for r in records if r["record"] == "foreign_node"]
    (filesystem,) = [r for r in records if r["record"] == "foreign_filesystem"]
    assert len(nodes) == filesystem["candidates"]
    assert sum(r["valid"] for r in nodes) == filesystem["valid"]
    assert {r["fsid"] for r in nodes} == {filesystem["fsid"]}
    assert any(line.startswith("foreign filesystem ") for line in captured.err.splitlines())


def test_catalog_build_foreign_keeps_the_schema_and_records_the_findings():
    path = image("m6_reformat_geometry")
    old, _ = lives("m6_reformat_geometry")
    with scratch_dir("test_foreign_catalog_") as d:
        build_catalog(path, d / "evidence.db", foreign=True)
        conn = db.open_readonly(d / "evidence.db")
        with conn:
            run = conn.execute("SELECT schema_version, scan_summary FROM scan_runs").fetchone()
            details = [row[0] for row in conn.execute(
                "SELECT detail FROM problems WHERE source = 'foreign'")]  # fmt: skip
        conn.close()
    assert run[0] == SCHEMA_VERSION
    (found,) = json.loads(run[1])["foreign"]["filesystems"]
    assert found["fsid"] == old["fsid"] and found["kind"] == "reformat"
    assert any(line.startswith(f"foreign filesystem {old['fsid']}: reformat") for line in details)
