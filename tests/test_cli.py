import subprocess
import sys

import pytest

from btrfska import __version__
from btrfska.cli import main

SANDBOX_SHA256 = "07ca38d42b11062f5461f97a572134a1b56cbf94e1138183d6e74502f5876418"


def test_version_exits_zero_and_prints_version():
    result = subprocess.run(
        [sys.executable, "-m", "btrfska", "--version"], capture_output=True, text=True
    )
    assert result.returncode == 0
    assert result.stdout.strip() == __version__ == "0.0.1"


@pytest.mark.sandbox
def test_info_prints_sandbox_sha256(sandbox_img, capsys):
    assert main(["info", str(sandbox_img)]) == 0
    out = capsys.readouterr().out
    assert f"sha256: {SANDBOX_SHA256}" in out
    assert "size:   268435456 bytes" in out


def test_info_missing_image_fails_cleanly(capsys):
    assert main(["info", "does-not-exist.img"]) == 1
    assert "error" in capsys.readouterr().err
