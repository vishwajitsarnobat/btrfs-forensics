"""Import boundary: test oracles never reach the distributed package (plan.md §3.3, §3.5)."""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
FORBIDDEN = ("dissect", "lzallright")


def forbidden_imports(source: str) -> list[str]:
    """Top-level names of forbidden modules imported by `source`, statically or by string."""
    found = []
    for node in ast.walk(ast.parse(source)):
        names = []
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            func = node.func
            callee = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if callee in {"import_module", "__import__"} and isinstance(node.args[0].value, str):
                names = [node.args[0].value]
        found += [n for n in names if n.split(".")[0] in FORBIDDEN]
    return found


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("import dissect.btrfs", True),
        ("from dissect.btrfs import Btrfs", True),
        ("import lzallright", True),
        ("from lzallright import LZOCompressor as C", True),
        ("importlib.import_module('dissect.util')", True),
        ("__import__('lzallright')", True),
        ("import dissection", False),
        ("from btrfska.substrate import csum", False),
    ],
)
def test_scanner(source, flagged):
    assert bool(forbidden_imports(source)) is flagged


def test_src_never_imports_test_oracles():
    offenders = {
        str(path.relative_to(SRC)): hits
        for path in sorted(SRC.rglob("*.py"))
        if (hits := forbidden_imports(path.read_text()))
    }
    assert offenders == {}
