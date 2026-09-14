"""Read-only guarantees: one open site, O_RDONLY, and an unwritable map."""

import ast
import fcntl
import hashlib
import os
from pathlib import Path

import pytest

from btrfska.substrate.image import open_image

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
OPEN_SITE = SRC / "btrfska" / "substrate" / "image.py"
SCRATCH = REPO_ROOT / "images" / "scratch"


@pytest.fixture
def scratch_image():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / f"test_readonly_{os.getpid()}.img"
    data = bytes(range(256)) * 16
    path.write_bytes(data)
    yield path, data
    path.unlink()


def test_open_image_is_o_rdonly(scratch_image):
    path, _ = scratch_image
    with open_image(path) as img:
        assert fcntl.fcntl(img.fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY


def test_write_through_mmap_raises_type_error(scratch_image):
    path, data = scratch_image
    with open_image(path) as img:
        with pytest.raises(TypeError):
            img.mmap[0] = 0xFF
    assert path.read_bytes() == data


def test_sha256_and_size(scratch_image):
    path, data = scratch_image
    with open_image(path) as img:
        assert img.size == len(data)
        assert img.sha256() == hashlib.sha256(data).hexdigest()


def _is_write_mode(call: ast.Call) -> bool:
    """True unless the mode argument is a constant string with no w/a/x/+ in it."""
    args = call.args
    # open(file, mode) and io.open(file, mode) take mode second; Path.open(mode) takes it first.
    first_is_mode = (
        isinstance(call.func, ast.Attribute)
        and args
        and isinstance(args[0], ast.Constant)
        and isinstance(args[0].value, str)
    )
    if first_is_mode:
        mode = args[0]
    else:
        mode = args[1] if len(args) > 1 else None
    for kw in call.keywords:
        if kw.arg == "mode":
            mode = kw.value
    if mode is None:
        return False
    if not (isinstance(mode, ast.Constant) and isinstance(mode.value, str)):
        return True
    return any(c in mode.value for c in "wax+")


def open_violations(source: str) -> list[int]:
    """Line numbers of `os.open(...)` calls and `open(...)`/`x.open(...)` calls in a write mode."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "open"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            lines.append(node.lineno)
        elif (
            isinstance(func, ast.Name | ast.Attribute)
            and (func.id if isinstance(func, ast.Name) else func.attr) == "open"
            and _is_write_mode(node)
        ):
            lines.append(node.lineno)
    return lines


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("os.open(p, os.O_RDONLY)", True),
        ("open(p, 'wb')", True),
        ("open(p, mode='r+b')", True),
        ("Path(p).open('a')", True),
        ("io.open(p, 'w')", True),
        ("open(p, mode)", True),
        ("open(p)", False),
        ("open(p, 'rb')", False),
        ("Path(p).open('rb')", False),
        ("io.open(p, 'rb')", False),
    ],
)
def test_open_scanner_detects_write_opens(source, flagged):
    assert bool(open_violations(source)) is flagged


def test_only_image_module_opens_files():
    offenders = {}
    for path in sorted(SRC.rglob("*.py")):
        if path == OPEN_SITE:
            continue
        lines = open_violations(path.read_text())
        if lines:
            offenders[str(path.relative_to(REPO_ROOT))] = lines
    assert offenders == {}
