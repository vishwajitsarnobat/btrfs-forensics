"""The baseline harness of plan.md M7d: the lock, the toolchain resolver and the scorer. No VM,
image or download is needed; the guest builds and runs are proved by hand (catalog.md, M7d).
"""

import importlib.util
import os
import re
import shutil
import subprocess

from tests.helpers import REPO_ROOT, scratch_dir

BASELINES = REPO_ROOT / "corpus" / "baselines"
LOCK = BASELINES / "baselines.lock"


def load(name: str):
    spec = importlib.util.spec_from_file_location(f"baselines_{name}", BASELINES / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


score = load("score")
resolve = load("resolve")

S01_LOG = """\x1b[2J=== GUEST Linux version 7.0.0-31-generic
=== MOUNTED /dev/vda /mnt btrfs rw 0 0
44969d026ed4164dbe77d48d4d359e98ac4057008cafd61723be72bff83e5fd4  /mnt/sv1/deleted_big.txt
df6ff35ab08001a736c9112350fe1251fde92360b63f07a1a97c43c54def5db2  /mnt/sv1/deleted_inline.txt\r
f6351f5ead9a700e34275480b3856ea738122a7c57bdeb744a631251c069587a  /mnt/sv1/keep.txt
=== SCENARIO-DONE
"""
DEEP_LOG = """=== EVENT create 260 7 victims/victim_1.txt
=== VICTIM victim_1.txt 9858806432057460e1ec885e32bbc79ce2fbdd60a1a6d77e7bc6a02732551e46  -
=== EVENT delete 260 8 victims/victim_1.txt
=== FLASH flash_inline_6.txt f6953e92646551e7cd33d002e212da3f41b14d4e271b162921a1234ce417d15e  -
=== FILE docs/kept.txt 1111111111111111111111111111111111111111111111111111111111111111  -
=== FILE gone.txt 2222222222222222222222222222222222222222222222222222222222222222  -
=== EVENT delete 300 9 gone.txt
=== ORPHAN open_unlinked.txt 23f90f8b2c3a4b5f3b5e156339994afd5c2718b378aca6f0e17111f80a70d4ec  -
"""
BIG = "44969d026ed4164dbe77d48d4d359e98ac4057008cafd61723be72bff83e5fd4"
KEEP = "f6351f5ead9a700e34275480b3856ea738122a7c57bdeb744a631251c069587a"
VICTIM = "9858806432057460e1ec885e32bbc79ce2fbdd60a1a6d77e7bc6a02732551e46"
HEADER = "path\tname\tsize\tsha256\n"


def test_truth_reads_sha256sum_lines_and_kind_lines_once_each():
    truth = {(t.kind, t.path): t for t in score.read_truth(S01_LOG + S01_LOG)}
    assert set(truth) == {
        ("sha256sum", "sv1/deleted_big.txt"),
        ("sha256sum", "sv1/deleted_inline.txt"),
        ("sha256sum", "sv1/keep.txt"),
    }
    assert truth[("sha256sum", "sv1/keep.txt")].name == "keep.txt"
    # no EVENT line says what s01 deleted, so deletion is unknown, not guessed from a name
    assert all(t.deleted is None for t in truth.values())


def test_victims_flashes_orphans_are_deleted_and_events_mark_the_rest():
    truth = {t.path: t for t in score.read_truth(DEEP_LOG)}
    assert truth["victim_1.txt"].kind == "victim" and truth["victim_1.txt"].deleted
    assert truth["flash_inline_6.txt"].deleted and truth["open_unlinked.txt"].deleted
    assert truth["gone.txt"].deleted is True
    assert truth["docs/kept.txt"].deleted is None


def test_escaped_paths_and_names_read_back():
    text = HEADER + f"a\\tb/c\\nd\\\\e\tc\\nd\\\\e\t12\t{BIG}\n"
    rows, malformed = score.read_outputs(text)
    assert malformed == 0
    assert rows == [score.Output("a\tb/c\nd\\e", "c\nd\\e", 12, BIG)]
    assert score.unescape("x\\qy") == "x\\qy"  # an unknown escape is left alone


def test_malformed_rows_are_counted_and_skipped():
    text = HEADER + "\n".join(
        [
            f"ok\tok\t1\t{BIG}",
            "too\tfew\t1",
            f"bad size\tx\t-1\t{BIG}",
            "bad hash\tx\t1\tXYZ",
            f"upper\tx\t1\t{BIG.upper()}",
            f"extra\tx\t1\t{BIG}\tmore",
            "",
        ]
    )
    rows, malformed = score.read_outputs(text)
    assert [r.path for r in rows] == ["ok"] and malformed == 5


def test_a_files_tsv_without_its_header_scores_nothing():
    rows, malformed = score.read_outputs(f"x\tx\t1\t{BIG}\n")
    assert rows == [] and malformed == 1
    assert score.read_outputs("") == ([], 0)


def test_counts_hash_exact_and_names_overall_and_for_deleted_files():
    truth = score.read_truth(S01_LOG + DEEP_LOG)
    outputs = [
        score.Output("live/sv1/keep.txt", "keep.txt", 5, KEEP),
        score.Output("root-1/sv1/keep.txt", "keep.txt", 5, KEEP),  # a second copy
        score.Output("recup_dir.1/f0000001.txt", "", 9, BIG),  # carved: no name
        score.Output("inode_260_gen_7", "victim_1.txt", 3, VICTIM),
        score.Output("noise", "noise", 1, "0" * 64),
    ]
    r = score.score(truth, outputs)
    assert r["files_produced"] == 5
    assert r["produced_matching_a_logged_file"] == 4
    assert r["all"] == {"logged": 8, "hash_exact": 3, "name_recovered": 2}
    assert r["deleted"] == {"logged": 4, "hash_exact": 1, "name_recovered": 1}
    assert r["by_kind"]["sha256sum"] == {"logged": 3, "hash_exact": 2, "name_recovered": 1}
    assert r["recovered"] == ["victim:victim_1.txt"]


def test_a_derived_image_is_scored_against_the_log_of_its_source():
    assert score.log_for("m1_badnode").name == "m1_xxhash.log"
    assert score.log_for("m4_deep_lost_parent").name == "m4_deep.log"
    assert score.log_for("no_such_image").name == "no_such_image.log"


def test_hostile_run_directories_never_crash_the_scorer():
    with scratch_dir("test_baselines_") as d:
        (d / "run.tsv").write_bytes(b"tool\tx\nno tab here\n\xff\xfe\timage\n")
        (d / "files.tsv").write_bytes(
            HEADER.encode() + os.urandom(4096) + b"\n" + b"\t" * 5000 + b"\n"
        )
        log = d / "scenario.log"
        log.write_bytes(os.urandom(2048) + S01_LOG.encode() + os.urandom(2048))
        r = score.score_run(d, log)
        assert r["tool"] == "x" and r["files_produced"] == 0 and r["malformed_rows"] >= 2
        assert r["all"]["logged"] == 3


def test_every_lock_line_has_a_group_a_hash_a_safe_file_name_and_a_source():
    groups = set()
    for line in LOCK.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        group, sha, file, source = line.split("\t")
        assert re.fullmatch(r"[0-9a-f]{64}", sha), line
        assert not file.startswith("/") and ".." not in file.split("/"), line
        assert source.startswith(("https://", "pool/")), line
        groups.add(group)
    tools = {p.name for p in (BASELINES / "tools").iterdir()}
    assert "toolchain" in groups
    assert groups - {"toolchain"} <= tools | {f"{t}-deps" for t in tools}
    # every tool has its own pinned source
    assert tools <= groups


def test_every_tool_has_both_recipes_and_its_needs_build_before_it():
    order = re.search(r'^ALL="([^"]+)"', (BASELINES / "build.sh").read_text(), re.M)[1].split()
    assert sorted(order) == sorted(p.name for p in (BASELINES / "tools").iterdir())
    for i, tool in enumerate(order):
        assert (BASELINES / "tools" / tool / "build.sh").exists()
        assert (BASELINES / "tools" / tool / "run.sh").exists()
        needs = BASELINES / "tools" / tool / "needs"
        if needs.exists():
            assert set(needs.read_text().split()) <= set(order[:i])


def test_setup_does_not_build_the_baselines():
    assert "baselines" not in (REPO_ROOT / "setup.sh").read_text()


def test_debian_versions_sort_as_dpkg_sorts_them():
    cmp = resolve.compare_versions
    assert cmp("2.39-0ubuntu8.9", "2.39-0ubuntu8.10") < 0
    assert cmp("1.0~rc1", "1.0") < 0
    assert cmp("1:0.1", "2.0") > 0
    assert cmp("13.3.0-6ubuntu2~24.04.1", "13.3.0-6ubuntu2") < 0
    assert cmp("1.89.0+dfsg~24.04-0ubuntu0.24.04.2", "1.89.0+dfsg~24.04-0ubuntu0.24.04.2") == 0
    assert cmp("5.6.1+really5.4.5-1", "5.6.1-1") > 0


def test_the_closure_takes_the_first_real_alternative_and_resolves_virtual_names():
    def pkg(name, depends="", provides="", pre=""):
        return {"Package": name, "Version": "1", "Depends": depends, "Provides": provides,
                "Pre-Depends": pre}  # fmt: skip

    index = {
        "tool": pkg("tool", "libfoo (>= 1) | libbar, awk, base:any", pre="pre"),
        "libbar": pkg("libbar"),
        "mawk": pkg("mawk", provides="awk"),
        "gawk": pkg("gawk", provides="awk"),
        "base": pkg("base"),
        "pre": pkg("pre"),
        "unused": pkg("unused"),
    }
    provides = {"awk": ["mawk", "gawk"]}
    names = [s["Package"] for s in resolve.closure(["tool"], index, provides)]
    assert names == ["base", "gawk", "libbar", "pre", "tool"]


def test_fls_listings_become_paths():
    awk = shutil.which("awk")
    assert awk, "awk is needed to check guest/fls-tree.awk"
    listing = (
        "Root directory content:\n\n"
        "d/d 257:      pad\n"
        "+ r/r 260:      p1\n"
        "+ d/d 261:      sub\n"
        "++ r/r 262:      deep name.txt\n"
        "r/r 263:      top.txt\n"
        "Error: something\n"
    )
    done = subprocess.run(
        [awk, "-f", str(BASELINES / "guest" / "fls-tree.awk")],
        input=listing, capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert done.stdout.splitlines() == [
        "d\t257\tpad",
        "r\t260\tpad/p1",
        "d\t261\tpad/sub",
        "r\t262\tpad/sub/deep name.txt",
        "r\t263\ttop.txt",
    ]
