"""btrfska scan on hostile copies of sandbox.img: bounded memory on a candidate flood, identical
output for any worker count, and metadata planted inside a skipped DATA chunk."""

import contextlib
import hashlib
import io
import json
import shutil
import tracemalloc

import pytest

from btrfska.cli import main
from btrfska.scan.classify import scan_image
from btrfska.substrate.fs import open_filesystem
from btrfska.substrate.image import open_image
from tests.helpers import scratch_dir

pytestmark = pytest.mark.sandbox

SECTOR = 4096
# The sandbox's trailing unmapped gap, after the last METADATA|DUP stripe: 39 680 sectors.
TRAILING_GAP = (105906176, 268435456)
DATA_CHUNK = (13631488, 22020096)  # DATA|single, skipped by the targeted plan
PLANTED = DATA_CHUNK[0] + (1 << 20)
DONOR = 38797312  # a valid unreferenced fs-tree leaf copy (logical 30408704, generation 13)
FLOOD_CANDIDATES = 85 + (TRAILING_GAP[1] - TRAILING_GAP[0]) // SECTOR
# Peak Python heap (tracemalloc) of a whole `scan --json` run. Before streaming, the flood took
# about 80 MB here (about 2 KB per candidate); the budget does not depend on the image.
BUDGET = 16 << 20


class HashingSink(io.TextIOBase):
    """A text stream that keeps only the SHA-256 and line count of what was written."""

    def __init__(self):
        self.digest, self.lines = hashlib.sha256(), 0

    def write(self, text):
        self.digest.update(text.encode())
        self.lines += text.count("\n")
        return len(text)


def derived(sandbox_img, directory, name, patches):
    path = directory / name
    shutil.copyfile(sandbox_img, path)
    with open(path, "r+b") as f:
        for offset, data in patches:
            f.seek(offset)
            f.write(data)
    return path


@pytest.fixture(scope="module")
def flood(sandbox_img):
    """sandbox.img with every sector of the trailing gap an fsid-matching garbage candidate."""
    with open_image(sandbox_img) as img:
        fsid = open_filesystem(img).reader.ctx.fsid
    sector = bytearray(SECTOR)
    sector[0x20:0x30] = fsid
    start, end = TRAILING_GAP
    megabyte = bytes(sector) * 256
    with scratch_dir("test_scan_flood_") as directory:
        patches = ((offset, megabyte) for offset in range(start, end, len(megabyte)))
        yield derived(sandbox_img, directory, "flood.img", patches)


@pytest.fixture(scope="module")
def planted(sandbox_img):
    """sandbox.img with a valid tree block copied into the DATA chunk, as after reallocation."""
    with open_image(sandbox_img) as img:
        block = bytes(img.mmap[DONOR : DONOR + 16384])
    with scratch_dir("test_scan_planted_") as directory:
        yield derived(sandbox_img, directory, "planted.img", [(PLANTED, block)])


def scan_json(path, *args):
    out, err = HashingSink(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(["scan", str(path), "--json", *args])
    return code, out, err.getvalue().splitlines()


def test_scan_memory_is_bounded_on_a_candidate_flood_for_any_worker_count(flood):
    runs = {}
    for workers in ("1", "4"):
        tracemalloc.start()
        try:
            runs[workers] = scan_json(flood, "--workers", workers)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        code, out, err = runs[workers]
        assert code == 0 and out.lines == FLOOD_CANDIDATES
        assert f"candidates: {FLOOD_CANDIDATES} (valid 84, invalid 39681)" in err
        assert peak < BUDGET, f"--workers {workers}: peak {peak} bytes"
    one, four = runs["1"], runs["4"]
    assert one[1].digest.hexdigest() == four[1].digest.hexdigest()
    assert one[2] == four[2]


def test_metadata_in_a_skipped_data_chunk_is_found_only_by_the_full_sweep(planted, capsys):
    assert main(["scan", str(planted)]) == 0
    targeted = capsys.readouterr().out.splitlines()
    assert "skipped as DATA: 8388608 bytes (use --full-sweep to include reallocated ranges)" in (
        targeted
    )
    assert "candidates: 85 (valid 84, invalid 1)" in targeted

    assert main(["scan", str(planted), "--full-sweep", "--json"]) == 0
    captured = capsys.readouterr()
    lines = captured.err.splitlines()
    assert "skipped as DATA: 0 bytes (full sweep)" in lines
    assert "candidates: 86 (valid 85, invalid 1)" in lines
    (node,) = [r for r in map(json.loads, captured.out.splitlines()) if r["physical"] == PLANTED]
    assert (node["status"], node["valid"], node["region"]["kind"]) == (
        "unreferenced",
        True,
        "DATA|single",
    )


def test_the_summary_counts_the_bytes_skipped_as_data(planted):
    with open_image(planted) as img:
        fs = open_filesystem(img)
        for full_sweep, expected in ((False, 8388608), (True, 0)):
            scan = scan_image(img, fs, full_sweep=full_sweep)
            for _ in scan.classified:
                pass
            assert scan.summary["skipped_data_bytes"] == expected
