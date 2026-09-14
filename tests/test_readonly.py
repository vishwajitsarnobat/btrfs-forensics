"""Read-only guarantees: one open site, O_RDONLY, and an unwritable map."""

import ast
import fcntl
import hashlib
import os
import shutil
import signal
import tempfile
from pathlib import Path

import pytest

from btrfska.substrate.image import open_image

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
IMAGE_MODULE = SRC / "btrfska" / "substrate" / "image.py"
# The only modules allowed to open, create or writably map files. The M4 `recover`
# output writers will join this allowlist explicitly; nothing else should.
WRITE_ALLOWLIST = frozenset({IMAGE_MODULE})
SCRATCH = REPO_ROOT / "images" / "scratch"


@pytest.fixture
def scratch_image():
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = SCRATCH / f"test_readonly_{os.getpid()}.img"
    data = bytes(range(256)) * 16
    path.write_bytes(data)
    yield path, data
    path.unlink()


@pytest.fixture
def scratch_dir():
    """A fresh directory under the gitignored images/scratch/ (pytest's tmp_path is in /tmp)."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="test_readonly_", dir=SCRATCH))
    yield path
    shutil.rmtree(path)


def test_directory_is_rejected(scratch_dir):
    with pytest.raises(ValueError, match="not a regular file or block device"):
        open_image(scratch_dir)


def test_fifo_is_rejected_without_blocking(scratch_dir):
    fifo = scratch_dir / "fifo"
    os.mkfifo(fifo)

    def blocked(signum, frame):
        raise TimeoutError("open_image blocked on a FIFO")

    previous = signal.signal(signal.SIGALRM, blocked)
    signal.alarm(5)
    try:
        with pytest.raises(ValueError, match="not a regular file or block device"):
            open_image(fifo)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def test_empty_file_is_rejected(scratch_dir):
    empty = scratch_dir / "empty.img"
    empty.touch()
    with pytest.raises(ValueError, match="empty image"):
        open_image(empty)


def test_symlink_to_regular_file_opens(scratch_image, scratch_dir):
    path, data = scratch_image
    link = scratch_dir / "link.img"
    link.symlink_to(path)
    with open_image(link) as img:
        assert img.size == len(data)
        assert img.sha256() == hashlib.sha256(data).hexdigest()


def test_close_is_idempotent(scratch_image):
    path, _ = scratch_image
    img = open_image(path)
    img.close()
    img.close()
    with img:
        pass


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


# Import-resolved calls that open, create, replace or resize files.
WRITE_CALLS = frozenset(
    {
        "os.open",
        "os.fdopen",
        "os.truncate",
        "os.ftruncate",
        "io.FileIO",
        "shutil.copyfile",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copytree",
        "shutil.move",
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryFile",
        "tempfile.SpooledTemporaryFile",
        "tempfile.mkstemp",
    }
)
# Write-only method names, flagged on any receiver (`Path(p).write_bytes()`, `x.fdopen()`).
# `copy` and `move` are left to WRITE_CALLS because `dict.copy()` is everywhere.
WRITE_ATTRS = frozenset(
    {
        "write_bytes",
        "write_text",
        "fdopen",
        "truncate",
        "ftruncate",
        "copyfile",
        "copy2",
        "copytree",
        "FileIO",
        "NamedTemporaryFile",
        "TemporaryFile",
        "SpooledTemporaryFile",
        "mkstemp",
    }
)
READ_ONLY_MMAP_ACCESS = frozenset({"mmap.ACCESS_READ", "ACCESS_READ"})


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    """Local name -> dotted origin, so `import os as x` and `from os import open as o` resolve."""
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def _qualname(node: ast.expr, aliases: dict[str, str]) -> str | None:
    """Dotted name of a Name/Attribute chain with imports resolved; None for anything else."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _qualname(node.value, aliases)
        return f"{base}.{node.attr}" if base else None
    return None


def write_violations(source: str) -> list[int]:
    """Line numbers of calls that could open, create, modify or writably map a file."""
    tree = ast.parse(source)
    aliases = _import_aliases(tree)
    lines = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _qualname(node.func, aliases)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else None
        if name in WRITE_CALLS or attr in WRITE_ATTRS:
            flagged = True
        elif name in {"mmap.mmap", "mmap"}:
            access = next((kw.value for kw in node.keywords if kw.arg == "access"), None)
            flagged = access is None or _qualname(access, aliases) not in READ_ONLY_MMAP_ACCESS
        elif name in {"open", "io.open"} or attr == "open":
            flagged = _is_write_mode(node)
        else:
            flagged = False
        if flagged:
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
        # Bypasses of the original scan: aliases, other write APIs, writable maps.
        ("from os import open as oopen\noopen(p, 1)", True),
        ("import os as x\nx.open(p, 0)", True),
        ("os.fdopen(fd, 'wb')", True),
        ("Path(p).write_bytes(b'')", True),
        ("Path(p).write_text('')", True),
        ("io.FileIO(p, 'w')", True),
        ("from io import FileIO\nFileIO(p, 'w')", True),
        ("shutil.copyfile(a, b)", True),
        ("shutil.copy(a, b)", True),
        ("shutil.copy2(a, b)", True),
        ("shutil.move(a, b)", True),
        ("from shutil import copy\ncopy(a, b)", True),
        ("import shutil as s\ns.move(a, b)", True),
        ("os.truncate(p, 0)", True),
        ("os.ftruncate(fd, 0)", True),
        ("mmap.mmap(fd, 0, access=mmap.ACCESS_WRITE)", True),
        ("mmap.mmap(fd, 0)", True),
        ("from mmap import mmap\nmmap(fd, 0)", True),
        ("mmap.mmap(fd, 0, access=mode)", True),
        ("tempfile.NamedTemporaryFile()", True),
        # Legitimate patterns stay allowed.
        ("mmap.mmap(fd, size, access=mmap.ACCESS_READ)", False),
        ("from mmap import ACCESS_READ, mmap\nmmap(fd, 0, access=ACCESS_READ)", False),
        ("d.copy()", False),
        ("shutil.which('btrfs')", False),
    ],
)
def test_write_scanner_flags_write_capable_calls(source, flagged):
    assert bool(write_violations(source)) is flagged


def test_image_module_needs_the_allowlist_only_for_os_open():
    """Its read-only mmap passes the scan; the lone flagged call is the O_RDONLY os.open."""
    source = IMAGE_MODULE.read_text()
    flagged = [source.splitlines()[n - 1] for n in write_violations(source)]
    assert len(flagged) == 1
    assert "os.open(" in flagged[0]


def test_only_allowlisted_modules_write():
    offenders = {}
    for path in sorted(SRC.rglob("*.py")):
        if path in WRITE_ALLOWLIST:
            continue
        lines = write_violations(path.read_text())
        if lines:
            offenders[str(path.relative_to(REPO_ROOT))] = lines
    assert offenders == {}
