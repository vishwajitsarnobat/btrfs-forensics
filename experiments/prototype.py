"""The frozen prototype, checked out from the git tag `legacy-final` for the experiments that
still run it (EXP-001, EXP-005). It was deleted from the tree on 2026-09-22 (plan.md section 4.3,
catalog.md); the tag keeps every number that was measured with it regenerable.

The checkout goes under the gitignored images/scratch/ and is made once per session.
"""

import subprocess
import tarfile
from io import BytesIO
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TAG = "legacy-final"
WHERE = REPO / "images" / "scratch" / "prototype" / TAG


def checkout() -> Path:
    """The directory holding the prototype's `main.py`, `utils/` and `tests/`."""
    if not (WHERE / "legacy" / "main.py").exists():
        WHERE.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(
            ["git", "archive", "--format=tar", TAG, "legacy"],
            cwd=REPO, capture_output=True, check=True,
        ).stdout  # fmt: skip
        with tarfile.open(fileobj=BytesIO(archive)) as tar:
            tar.extractall(WHERE, filter="data")
    return WHERE / "legacy"
