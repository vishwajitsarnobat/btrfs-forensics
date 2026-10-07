"""experiments/exp021.py: the planted-image harness of EXP-021 (plan.md M6e).

The claims are relative to the images read: on a kept base, a sample of every technique's plants
is found where it was planted, the payloads the rules cannot see by design are not, and nothing
else is reported."""

import pytest

from btrfska.hiding.findings import Finding
from experiments import exp021
from tests.helpers import SCENARIOS, scratch_dir


@pytest.mark.parametrize(
    ("values", "reported"),
    [
        ([10**9, 0, 0, 0], True),
        ([10**9 - 1, 5, 5, 5], False),
        ([0x3A414141, 0x3A424242, 0x3A434343, 0x3A444444], True),  # four printable, below 10^9
        ([0x3A414141, 0x3A414141, 0x3A434343, 0x3A444444], False),  # two equal
        ([0x3A414141, 0x3A424242, 0x3A434343, 0x01444444], False),  # one not printable
    ],
)
def test_the_nanosecond_rule_as_the_harness_predicts_it(values, reported):
    assert exp021.nsec_rule(values) == reported


def area(technique, physical, length, first, nonzero):
    return Finding(technique, physical, length, nonzero, "", "", detail={"first_nonzero": first})


def test_a_finding_is_exact_only_when_it_points_at_the_planted_bytes_alone():
    plant = exp021.Plant("superblock_reserved", "x", spans=[(1010, 1013)])
    assert exp021.covers(area("superblock_reserved", 1000, 100, 1010, 3), plant)
    assert exp021.exact(area("superblock_reserved", 1000, 100, 1010, 3), plant)
    # A stale tail before the payload: the area covers it, but does not point at it alone.
    assert not exp021.exact(area("superblock_reserved", 1000, 100, 1001, 50), plant)
    assert not exp021.covers(area("superblock_reserved", 1013, 100, 1013, 3), plant)
    device = Finding("device_slack", 0, 1 << 20, 3, "", "", detail={"runs": [[4096, 8192]]})
    assert exp021.covers(device, exp021.Plant("device_slack", "x", spans=[(5000, 5003)]))
    assert exp021.exact(device, exp021.Plant("device_slack", "x", spans=[(5000, 5003)]))
    assert not exp021.covers(device, exp021.Plant("device_slack", "x", spans=[(9000, 9003)]))


def test_the_guest_log_is_read_for_mount_scrub_errors_and_kernel_messages():
    log = "\n".join([
        "=== MOUNTED /dev/vda /mnt btrfs rw 0 0",
        "=== SCRUB Status:          finished",
        "=== SCRUB Error summary:    csum=2",
        "=== SCRUB Duration:        0:00:00",
        "=== READ-ERROR /mnt/plain.txt",
        "=== BALANCE Done, had to relocate 4 out of 4 chunks",
        "=== DMESG [    1.6] BTRFS info (device vda): using crc32c checksum algorithm",
        "=== DMESG [    1.7] BTRFS warning (device vda): csum failed root 5 ino 257",
        "=== SCENARIO-DONE",
    ])  # fmt: skip
    found = exp021.guest_log(log)
    assert found["mounted"] and found["done"] and not found["mount_fail"]
    assert found["scrub"] == ["Status:          finished", "Error summary:    csum=2"]
    assert found["read_errors"] == ["/mnt/plain.txt"]
    assert found["dmesg_problems"] == [log.splitlines()[7].removeprefix("=== DMESG ")]
    assert exp021.scrub_errors({"guest": found})
    assert found["balance"] == ["Done, had to relocate 4 out of 4 chunks"]


@pytest.mark.vm
@pytest.mark.parametrize("base", ["m6_datacsum", "m3_wide"])
def test_a_sample_of_every_technique_is_found_where_it_was_planted(base):
    path = SCENARIOS / f"{base}.img"
    if not path.exists():
        pytest.skip(f"{base}.img absent: build it with corpus/build.py")
    plants = [p for p in exp021.plants_for(base, path) if not p.na]
    # Per technique its first plant and its largest one; every plant out of the rules' scope.
    largest = {}
    for plant in plants:
        size = sum(b - a for a, b in plant.spans)
        if size > largest.get(plant.technique, (0, None))[0]:
            largest[plant.technique] = (size, plant)
    sample, seen = [], set()
    for plant in plants:
        if plant.technique not in seen or largest[plant.technique][1] is plant or not (
                plant.in_scope):  # fmt: skip
            sample.append(plant)
            seen.add(plant.technique)
    assert {p.technique for p in sample} >= set(exp021.TECHNIQUES) - {"hidden_name",
                                                                       "file_slack"}  # fmt: skip
    with scratch_dir("test_exp021_") as d:
        for plant in sample:
            copy = exp021.planted_copy(path, plant.patches, d)
            found, _, _ = exp021.run_detector(copy)
            copy.unlink()
            verdict = exp021.judge(plant, found)
            assert verdict["detected"] == plant.in_scope, (plant.label, verdict)
            assert verdict["covers"] == plant.in_scope, (plant.label, verdict)
            allowed = {"inode_reserved"} if plant.technique == "copy_divergence" else set()
            assert set(verdict["others"]) <= allowed, (plant.label, verdict)
            if plant.in_scope and plant.technique in ("superblock_reserved", "superblock_padding",
                                                      "pre_superblock", "node_slack",
                                                      "inode_reserved", "string_item",
                                                      "file_slack", "device_slack"):  # fmt: skip
                assert verdict["exact"], (plant.label, verdict)
            if plant.technique == "sys_chunk_array_slack":
                assert verdict["exact"] is False  # the stale tail is part of the area
            if plant.technique == "file_slack":
                assert verdict["csum"] == plant.expect["csum"]
