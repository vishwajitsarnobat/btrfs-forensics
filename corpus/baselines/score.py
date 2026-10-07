"""Score baseline runs against the ground truth of their image (docs/plan.md M7d, M7 metrics).

A run directory (corpus/baselines/run.sh) holds `files.tsv`, one row per file the tool produced
(path, recovered name, size, SHA-256; tab, newline and backslash escaped as \\t, \\n and \\\\),
and `run.tsv` (tool, version, exit status, wall time, peak memory, image, ...). The ground truth
is the scenario's serial log, images/scenarios/<image>.log, or for a derived image the log of the
image it was made from (corpus/manifest.tsv, "via NAME"). A logged file is
  * a `HASH  /mnt/PATH` line (sha256sum output in the scenario), or
  * a `=== KIND NAME HASH` line, KIND one of FILE, DOOMED, VICTIM, FLASH, ORPHAN;
and `=== EVENT delete INODE GENERATION PATH` lines name deleted paths. VICTIM, FLASH, ORPHAN and
DOOMED files are deleted by definition (the scenario deletes, unlinks or drops them); a
`/mnt/PATH` or FILE line is deleted when an EVENT deletes that path, and unknown otherwise.

Per run, as ExtSFR reports (plan M7 metrics):
  files produced   rows of files.tsv
  hash-exact       logged files whose SHA-256 some produced file has
  name recovered   logged files that a hash-exact produced file also names (its recovered name
                   equals the logged file's name)
each overall and for the logged files known to be deleted. Malformed rows are counted, never
fatal: files.tsv comes from a tool run on possibly hostile images.

Usage, from the repo root:
  uv run python corpus/baselines/score.py RUN_DIR [RUN_DIR ...] [--log LOG] [--json]
"""

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SCENARIOS = REPO / "images" / "scenarios"
MANIFEST = REPO / "corpus" / "manifest.tsv"
HEX64 = re.compile(r"[0-9a-f]{64}")
SUMLINE = re.compile(r"^([0-9a-f]{64})  /mnt/(.+?)\r?$", re.M)
KINDLINE = re.compile(r"^=== (FILE|DOOMED|VICTIM|FLASH|ORPHAN) (\S+) ([0-9a-f]{64})\b", re.M)
DELETE = re.compile(r"^=== EVENT delete \d+ \d+ (\S+)", re.M)
DELETED_KINDS = {"victim", "flash", "orphan", "doomed"}


@dataclass(frozen=True)
class Truth:
    kind: str  # sha256sum (a /mnt/PATH line), or the lower-case KIND of a === line
    path: str  # the logged path or name, relative to the mount point
    sha256: str
    deleted: bool | None  # None: the log does not say

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass(frozen=True)
class Output:
    path: str
    name: str
    size: int
    sha256: str


def unescape(field: str) -> str:
    """Undo guest/job.sh's escaping: \\t, \\n and \\\\; any other backslash stays as it is."""
    return re.sub(r"\\([tn\\])", lambda m: {"t": "\t", "n": "\n", "\\": "\\"}[m[1]], field)


def read_outputs(text: str) -> tuple[list[Output], int]:
    """(rows of a files.tsv, number of malformed lines). The header line is required."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if not lines or lines[0] != "path\tname\tsize\tsha256":
        return [], len(lines)
    rows, malformed = [], 0
    for line in lines[1:]:
        fields = line.split("\t")
        if len(fields) != 4 or not HEX64.fullmatch(fields[3]) or not fields[2].isdigit():
            malformed += 1
            continue
        rows.append(Output(unescape(fields[0]), unescape(fields[1]), int(fields[2]), fields[3]))
    return rows, malformed


def read_run(text: str) -> dict[str, str]:
    """run.tsv as a dict; lines without a tab are ignored, a repeated key keeps its last value."""
    info = {}
    for line in text.splitlines():
        key, sep, value = line.partition("\t")
        if sep:
            info[key] = value
    return info


def read_truth(text: str) -> list[Truth]:
    """Every logged file of a scenario log, once per (path, hash)."""
    deleted_paths = set(DELETE.findall(text))
    deleted_names = {path.rsplit("/", 1)[-1] for path in deleted_paths}
    found: dict[tuple[str, str], Truth] = {}
    for match in SUMLINE.finditer(text):
        path = match[2]
        deleted = True if path in deleted_paths else None
        found.setdefault((path, match[1]), Truth("sha256sum", path, match[1], deleted))
    for match in KINDLINE.finditer(text):
        kind, path, sha = match[1].lower(), match[2], match[3]
        if kind in DELETED_KINDS:
            deleted = True
        else:
            deleted = True if path in deleted_paths or path in deleted_names else None
        found.setdefault((path, sha), Truth(kind, path, sha, deleted))
    return list(found.values())


def score(truth: list[Truth], outputs: list[Output]) -> dict:
    hashes = {o.sha256 for o in outputs}
    names_by_hash: dict[str, set[str]] = {}
    for o in outputs:
        names_by_hash.setdefault(o.sha256, set()).add(o.name)

    def counts(subset: list[Truth]) -> dict[str, int]:
        exact = [t for t in subset if t.sha256 in hashes]
        named = [t for t in exact if t.name in names_by_hash[t.sha256]]
        return {"logged": len(subset), "hash_exact": len(exact), "name_recovered": len(named)}

    truth_hashes = {t.sha256 for t in truth}
    by_kind = {}
    for kind in sorted({t.kind for t in truth}):
        by_kind[kind] = counts([t for t in truth if t.kind == kind])
    return {
        "files_produced": len(outputs),
        "produced_matching_a_logged_file": sum(o.sha256 in truth_hashes for o in outputs),
        "all": counts(truth),
        "deleted": counts([t for t in truth if t.deleted]),
        "by_kind": by_kind,
        "recovered": sorted(
            {f"{t.kind}:{t.path}" for t in truth if t.sha256 in hashes and t.deleted}
        ),
    }


def log_for(image: str) -> Path:
    """The scenario log of an image: its own, or that of the first image it was derived from."""
    own = SCENARIOS / f"{image}.log"
    if own.exists() or not MANIFEST.exists():
        return own
    with MANIFEST.open(newline="") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            if row["name"] == image and (via := re.search(r"\(via ([a-z0-9_]+)", row["mkfs"])):
                return SCENARIOS / f"{via[1]}.log"
    return own


def score_run(run_dir: Path, log: Path | None = None) -> dict:
    info = read_run((run_dir / "run.tsv").read_text(errors="replace"))
    outputs, malformed = read_outputs(
        (run_dir / "files.tsv").read_bytes().decode("utf-8", "surrogateescape")
    )
    log = log or log_for(info.get("image", ""))
    truth = read_truth(log.read_text(errors="replace")) if log.exists() else []
    result = {
        "tool": info.get("tool", "?"),
        "image": info.get("image", "?"),
        "version": info.get("version", "?"),
        "exit": info.get("exit", "?"),
        "wall_s": info.get("wall_s", "?"),
        "max_rss_kib": info.get("max_rss_kib", "?"),
        "log": str(log) if log.exists() else None,
        "malformed_rows": malformed,
    }
    result.update(score(truth, outputs))
    return result


def run_dirs(paths: list[Path]) -> list[Path]:
    """The run directories named, or found below a named directory (images/baselines/runs)."""
    found = []
    for path in paths:
        if (path / "run.tsv").exists() and (path / "files.tsv").exists():
            found.append(path)
            continue
        below = sorted(p.parent for p in path.rglob("run.tsv") if (p.parent / "files.tsv").exists())
        if not below:
            print(f"score.py: no run.tsv and files.tsv in or below {path}", file=sys.stderr)
            sys.exit(1)
        found += below
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("runs", nargs="+", type=Path, help="run directories of run.sh")
    parser.add_argument("--log", type=Path, help="scenario log (default: the image's own)")
    parser.add_argument("--json", action="store_true", help="one JSON object per run")
    args = parser.parse_args()
    for run_dir in run_dirs(args.runs):
        r = score_run(run_dir, args.log)
        if args.json:
            print(json.dumps(r))
            continue
        a, d = r["all"], r["deleted"]
        print(f"{r['tool']} on {r['image']}: {r['version']}")
        print(
            f"  exit {r['exit']}, {r['wall_s']} s, peak RSS {r['max_rss_kib']} KiB; "
            f"{r['files_produced']} files produced ({r['malformed_rows']} malformed rows), "
            f"{r['produced_matching_a_logged_file']} with a logged hash"
        )
        print(
            f"  logged files: {a['hash_exact']}/{a['logged']} hash-exact, "
            f"{a['name_recovered']} with the name; deleted: {d['hash_exact']}/{d['logged']} "
            f"hash-exact, {d['name_recovered']} with the name"
        )
        if r["log"] is None:
            print("  (no scenario log found: nothing to score against)")


if __name__ == "__main__":
    main()
