"""Repo-wide pytest fixtures."""

from pathlib import Path

import pytest

from btrfska.substrate.image import open_image

REPO_ROOT = Path(__file__).resolve().parent
SANDBOX_IMG = REPO_ROOT / "sandbox.img"
SHA256SUMS = REPO_ROOT / "tests" / "fixtures" / "SHA256SUMS"


def _expected_sha256(name: str) -> str:
    """The pinned hash for `name` in SHA256SUMS, the single source shared with CI."""
    for line in SHA256SUMS.read_text().splitlines():
        digest, _, filename = line.partition("  ")
        if filename == name:
            return digest
    raise LookupError(f"{name} not listed in {SHA256SUMS}")


SANDBOX_SHA256 = _expected_sha256("sandbox.img")


def _sha256(path: Path) -> str:
    with open_image(path) as img:
        return img.sha256()


@pytest.fixture(scope="session")
def sandbox_img() -> Path:
    if not SANDBOX_IMG.exists():
        pytest.skip("sandbox.img absent")
    return SANDBOX_IMG


@pytest.fixture(scope="session", autouse=True)
def sandbox_hash_guard():
    """Fail the session if sandbox.img is not the expected image or changes during it."""
    if not SANDBOX_IMG.exists():
        yield
        return
    before = _sha256(SANDBOX_IMG)
    assert before == SANDBOX_SHA256, f"sandbox.img sha256 is {before}, expected {SANDBOX_SHA256}"
    yield
    after = _sha256(SANDBOX_IMG)
    assert after == before, f"sandbox.img changed during the test session: {after}"
