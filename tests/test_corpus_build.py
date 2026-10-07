"""corpus/build.py and corpus/manifest.tsv: the one-command corpus build. No image or VM needed."""

import importlib.util
import re
import shlex

import pytest

from tests.helpers import REPO_ROOT, scratch_dir

BUILD = REPO_ROOT / "corpus" / "build.py"


def load_build():
    spec = importlib.util.spec_from_file_location("corpus_build", BUILD)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build = load_build()


def test_manifest_is_a_recipe_without_image_hashes():
    rows = build.manifest_rows()
    assert rows
    for row in rows:
        assert list(row) == ["name", "command", "mkfs", "guest_kernel", "note"]
        assert re.fullmatch(r"[a-z0-9_]+", row["name"])
        assert row["command"] and row["mkfs"] and row["guest_kernel"]
        assert not re.search(r"\b[0-9a-f]{64}\b", "\t".join(row.values()))
    names = [row["name"] for row in rows]
    assert len(names) == len(set(names))


def test_every_command_runs_a_tracked_script_and_names_its_own_image():
    for row in build.manifest_rows():
        words = shlex.split(row["command"])
        scripts = [word for word in words if word.startswith("corpus/")]
        assert scripts, row["command"]
        for script in scripts:
            assert (REPO_ROOT / script).is_file(), script
        # the command must produce images/scenarios/<name>.img: by destination path, by NAME=, or
        # as the make_image.sh argument
        name = row["name"]
        assert (
            f"images/scenarios/{name}.img" in words or f"NAME={name}" in words or words[-1] == name
        ), row["command"]


def test_an_image_derived_from_another_comes_after_it():
    seen = set()
    for row in build.manifest_rows():
        sources = re.findall(r"images/scenarios/([a-z0-9_]+)\.img", row["command"])
        for source in sources:
            assert source == row["name"] or source in seen, f"{row['name']} needs {source} first"
        seen.add(row["name"])


def test_build_record_round_trips_in_sha256sum_format(monkeypatch):
    with scratch_dir("build-record-") as directory:
        monkeypatch.setattr(build, "RECORD", directory / "SHA256SUMS")
        assert build.read_record() == {}
        record = {"b.img": "1" * 64, "a.img": "0" * 64}
        build.write_record(record)
        assert build.read_record() == record
        lines = (directory / "SHA256SUMS").read_text().splitlines()
        assert lines == [f"{'0' * 64}  a.img", f"{'1' * 64}  b.img"]  # what `sha256sum -c` reads


def test_sha256_matches_hashlib(monkeypatch):
    import hashlib

    with scratch_dir("build-sha-") as directory:
        path = directory / "blob"
        path.write_bytes(b"btrfska" * 300_000)
        assert build.sha256(path) == hashlib.sha256(path.read_bytes()).hexdigest()


def test_host_check_names_the_missing_tool_and_a_package(monkeypatch):
    monkeypatch.setattr(build.shutil, "which", lambda tool: None if tool == "cpio" else "/bin/x")
    problems = build.host_problems()
    assert any("`cpio` not found; install cpio" in problem for problem in problems)
    assert not any("curl" in problem for problem in problems)


def test_unknown_image_name_is_refused_before_anything_runs(monkeypatch, capsys):
    monkeypatch.setattr(build, "host_problems", lambda: [])
    monkeypatch.setattr(build, "run", lambda command: (_ for _ in ()).throw(AssertionError))
    assert build.main(["no_such_image"]) == 2
    assert "no_such_image" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# M7a: the matrix tiers (corpus/matrix.py writes corpus/matrix.tsv and corpus/large.tsv)
# ---------------------------------------------------------------------------
spec = importlib.util.spec_from_file_location("corpus_matrix", REPO_ROOT / "corpus" / "matrix.py")
matrix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(matrix)
BLOCKS = [("OP", "DISCARD_MODE"), ("BGT", "OP"), ("RECLAIM", "DISCARD_MODE")]


def test_the_tier_manifests_are_what_the_generator_writes():
    for tier, (file, rows) in matrix.TIERS.items():
        assert (REPO_ROOT / "corpus" / file).read_text() == matrix.tsv(rows())
        assert build.TIERS[tier] == REPO_ROOT / "corpus" / file


def test_every_tier_is_a_recipe_and_no_name_repeats_across_tiers():
    names = []
    for tier in build.TIERS:
        for row in build.manifest_rows(tier):
            assert list(row) == ["name", "command", "mkfs", "guest_kernel", "note"]
            assert re.fullmatch(r"[a-z0-9_]+", row["name"])
            assert not re.search(r"\b[0-9a-f]{64}\b", "\t".join(row.values()))
            words = shlex.split(row["command"])
            assert tier == "default" or words[-2:] == [matrix.SCRIPT, row["name"]]
            assert all((REPO_ROOT / w).is_file() for w in words if w.startswith("corpus/"))
            names.append(row["name"])
    assert len(names) == len(set(names))


def test_the_matrix_has_its_factorial_blocks_and_every_axis_value():
    rows = build.manifest_rows("matrix") + build.manifest_rows("large")
    configs = {row["name"]: matrix.configuration(row) for row in rows}
    base = matrix.BASE

    def block(*axes):
        """The cells of `axes` among the rows whose other axes are all at the base value."""
        return {
            tuple(c[a] for a in axes)
            for c in configs.values()
            if all(c[a] == base[a] for a in base if a not in axes)
        }

    discards = matrix.AXES["DISCARD_MODE"]
    assert block("OP", "DISCARD_MODE") == {(o, d) for o in matrix.AXES["OP"] for d in discards}
    assert block("BGT", "OP") >= {(b, o) for b in ("off", "on") for o in ("delete", "balance")}
    assert block("RECLAIM", "DISCARD_MODE") == {(r, d) for r in ("off", "on") for d in discards}
    for axis, values in matrix.AXES.items():
        assert set(values) <= {c[axis] for c in configs.values()}, axis
    # outside the blocks a row changes one axis (the mixed layout comes with its small size)
    for name, c in configs.items():
        changed = {a for a in base if c[a] != base[a]}
        if c["LAYOUT"] == "mixed":
            changed.discard("SIZE")
        assert len(changed) <= 1 or any(changed <= set(b) for b in BLOCKS), (name, changed)
    assert len(configs) == 47
    assert [row["name"] for row in build.manifest_rows("large")] == ["mx_100g"]


def test_a_name_from_another_tier_is_refused(monkeypatch, capsys):
    monkeypatch.setattr(build, "host_problems", lambda: [])
    monkeypatch.setattr(build, "run", lambda command: (_ for _ in ()).throw(AssertionError))
    assert build.main(["--tier", "matrix", "m1_xxhash"]) == 2
    assert "corpus/matrix.tsv" in capsys.readouterr().err


def test_a_multi_device_row_records_every_device():
    with scratch_dir("build-devices-") as directory:
        for name in ("mx_raid1.img", "mx_raid1.dev2.img", "mx_raid10.img"):
            (directory / name).write_bytes(b"x")
        found = [p.name for p in build.row_images(directory / "mx_raid1.img")]
        assert found == ["mx_raid1.img", "mx_raid1.dev2.img"]


def test_an_axis_value_off_the_matrix_is_refused():
    with pytest.raises(ValueError, match="COMPRESS=lz4"):
        matrix.row("mx_x", "note", COMPRESS="lz4")
