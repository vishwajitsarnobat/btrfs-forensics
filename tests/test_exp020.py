"""experiments/exp020.py: the ground truth is read as the record says, and the tier checks hold
on `sandbox.img`, relative to what the recovery of that image gives."""

from experiments import exp020
from tests.helpers import REPO_ROOT, scratch_dir


def test_names_logged_twice_keep_every_hash(tmp_path, monkeypatch):
    log = tmp_path / "x.log"
    log.write_text(
        "=== FILE a.txt " + "1" * 64 + "\n" + "2" * 64 + "  /mnt/dir/a.txt\n"
        + "3" * 64 + "  /mnt/b.bin\nnoise " + "4" * 64 + "\n"
    )  # fmt: skip
    monkeypatch.setattr(exp020, "SCENARIOS", tmp_path)
    assert exp020.truth(tmp_path / "x.img") == {"a.txt": {"1" * 64, "2" * 64}, "b.bin": {"3" * 64}}
    assert exp020.truth(tmp_path / "missing.img") == {}


def test_the_sandbox_has_no_wrong_confirmation_and_the_image_is_unchanged(monkeypatch):
    with scratch_dir("test_exp020_") as d:
        monkeypatch.setattr(exp020, "OUT", d)
        result = exp020.measure(REPO_ROOT / "sandbox.img")
    assert result["sha256_before"] == result["sha256_after"]
    assert result["files"] == sum(result["by_source"].values())
    assert result["h1"]["wrong"] == [] and result["h2"]["not_confirmed"] == []
    assert result["h2"]["backref_disagrees"] == 0
    assert all(tier in exp020.TIERS for tier in result["artifacts"])
