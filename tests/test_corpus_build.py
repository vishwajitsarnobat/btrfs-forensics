"""corpus/build.py and corpus/manifest.tsv: the one-command corpus build. No image or VM needed."""

import importlib.util
import re
import shlex

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
