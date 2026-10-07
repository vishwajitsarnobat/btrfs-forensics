"""Regenerate the computed groups of corpus/baselines/baselines.lock.

The lock pins every input of the baseline harness by SHA-256. Most groups are written by hand
(one source tarball per tool, from docs/research/baselines.md). Four are computed, and this script
computes them, so the lists are reproducible rather than typed:

  toolchain   the dependency closure (Depends and Pre-Depends, no Recommends) of TOOLCHAIN below,
              from the Packages indices of the same Ubuntu snapshot as corpus/vm/guest.lock; for a
              package in several suites the highest version wins (noble-updates over noble)
  btrfscue    the Go modules btrfscue's go.sum names, fetched from proxy.golang.org (.info, .mod
              and, for modules whose code is in the build, .zip)
  securityronin  the registry crates of the btrfs-forensic workspace's Cargo.lock at the pinned
              tag, with crates.io's checksums from that lock
  mbkn        the cp314 x86-64 manylinux (or pure-Python) wheels that mbkn-btrfs-rescue's uv.lock
              pins for its runtime dependencies, with uv.lock's SHA-256

The hand-written groups are kept as they are. Source tarballs are read from images/baselines/dl/
(run corpus/baselines/fetch.sh first for the hand-written groups). Only the Go files are hashed
here, because nothing upstream publishes a SHA-256 for them; everything else takes the hash the
publisher's own index gives, and fetch.sh checks every download against the lock.

Usage, from the repo root:  uv run python corpus/baselines/resolve.py [GROUP ...]
Environment: UBUNTU_MIRROR (default: the snapshot below).
"""

import hashlib
import lzma
import os
import re
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LOCK = HERE / "baselines.lock"
WORK = REPO / "images" / "baselines"
DL = WORK / "dl"
INDEX = WORK / "index"
MIRROR = os.environ.get("UBUNTU_MIRROR", "https://snapshot.ubuntu.com/ubuntu/20260919T000000Z")
SUITES = ["noble", "noble-updates", "noble-security"]
COMPONENTS = ["main", "universe"]
GOPROXY = "https://proxy.golang.org"
CRATES = "https://static.crates.io/crates"

# What the build guest needs (docs/research/baselines.md §4.1). The closure adds the rest.
TOOLCHAIN = [
    # compilers, linkers and build tools
    "gcc", "g++", "cpp", "binutils", "make", "libc6-dev", "pkgconf", "autoconf", "automake",
    "libtool", "m4", "cmake", "patch", "rustc-1.89", "cargo-1.89", "golang-1.24-go",
    "golang-1.24-src",
    # libraries btrfs-progs 7.1 and TSK link against
    "uuid-dev", "libblkid-dev", "zlib1g-dev", "liblzo2-dev", "libzstd-dev",
    # a shell and the tools the recipes and undelete-btrfs call
    "bash", "dash", "coreutils", "findutils", "grep", "sed", "gawk", "mawk", "tar", "gzip", "bzip2",
    "xz-utils", "zstd", "diffutils", "ncurses-bin", "ncurses-base", "util-linux", "procps",
    # wall time and peak memory of each run
    "time",
]  # fmt: skip
COMPUTED = ("toolchain", "btrfscue-deps", "securityronin-deps", "mbkn-deps")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


# --- Debian version comparison (deb-version(7)), enough to pick the newest of a few candidates


def _order(c: str) -> int:
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _compare_part(a: str, b: str) -> int:
    while a or b:
        a_text = re.match(r"[^\d]*", a)[0]
        b_text = re.match(r"[^\d]*", b)[0]
        for i in range(max(len(a_text), len(b_text))):
            x = _order(a_text[i]) if i < len(a_text) else 0
            y = _order(b_text[i]) if i < len(b_text) else 0
            if x != y:
                return -1 if x < y else 1
        a, b = a[len(a_text) :], b[len(b_text) :]
        a_num = re.match(r"\d*", a)[0]
        b_num = re.match(r"\d*", b)[0]
        if int(a_num or 0) != int(b_num or 0):
            return -1 if int(a_num or 0) < int(b_num or 0) else 1
        a, b = a[len(a_num) :], b[len(b_num) :]
    return 0


def compare_versions(a: str, b: str) -> int:
    """-1, 0 or 1 as Debian version a sorts before, with or after b."""

    def split(v: str) -> tuple[int, str, str]:
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        upstream, _, revision = rest.rpartition("-") if "-" in rest else (rest, "", "0")
        return int(epoch or 0), upstream, revision

    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _compare_part(ua, ub) or _compare_part(ra, rb)


# --- toolchain: the dependency closure from the Packages indices


def parse_packages(text: str) -> list[dict[str, str]]:
    stanzas = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        key = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and key:
                fields[key] += "\n" + line
            elif ":" in line:
                key, _, value = line.partition(":")
                fields[key] = value.strip()
        if "Package" in fields:
            stanzas.append(fields)
    return stanzas


def load_index() -> tuple[dict[str, dict[str, str]], dict[str, list[str]]]:
    """({package: newest stanza}, {virtual name: [providing packages]})."""
    INDEX.mkdir(parents=True, exist_ok=True)
    newest: dict[str, dict[str, str]] = {}
    for suite in SUITES:
        for component in COMPONENTS:
            path = INDEX / f"{suite}-{component}.Packages.xz"
            if not path.exists():
                url = f"{MIRROR}/dists/{suite}/{component}/binary-amd64/Packages.xz"
                print(f"fetch {url}", file=sys.stderr)
                path.write_bytes(fetch(url))
            for stanza in parse_packages(lzma.decompress(path.read_bytes()).decode()):
                if stanza.get("Architecture") not in ("amd64", "all"):
                    continue
                name = stanza["Package"]
                old = newest.get(name)
                if old is None or compare_versions(stanza["Version"], old["Version"]) > 0:
                    newest[name] = stanza
    provides: dict[str, list[str]] = {}
    for name, stanza in newest.items():
        for item in stanza.get("Provides", "").split(","):
            virtual = item.strip().split(" ")[0]
            if virtual:
                provides.setdefault(virtual, []).append(name)
    return newest, provides


def closure(roots: list[str], newest: dict, provides: dict) -> list[dict[str, str]]:
    """Every package the roots need, through Depends and Pre-Depends; the first alternative that
    exists as a real package wins, else the first provider in name order."""
    chosen: dict[str, dict[str, str]] = {}
    todo = list(roots)
    while todo:
        name = todo.pop()
        if name in chosen:
            continue
        if name not in newest:
            raise SystemExit(f"resolve.py: no package {name} in the snapshot")
        stanza = chosen[name] = newest[name]
        for field in ("Pre-Depends", "Depends"):
            for clause in stanza.get(field, "").split(","):
                clause = clause.strip()
                if not clause:
                    continue
                options = [alt.strip().split(" ")[0].split(":")[0] for alt in clause.split("|")]
                pick = next((o for o in options if o in chosen), None)
                pick = pick or next((o for o in options if o in newest), None)
                if pick is None:
                    providers = sorted(p for o in options for p in provides.get(o, []))
                    if not providers:
                        raise SystemExit(f"resolve.py: {name} needs {clause}: nothing provides it")
                    pick = next((p for p in providers if p in chosen), providers[0])
                todo.append(pick)
    return [chosen[name] for name in sorted(chosen)]


def resolve_toolchain() -> list[str]:
    newest, provides = load_index()
    lines = []
    for stanza in closure(TOOLCHAIN, newest, provides):
        path = stanza["Filename"]
        lines.append(f"toolchain\t{stanza['SHA256']}\t{Path(path).name}\t{path}")
    return lines


# --- per-tool offline dependencies, read from the pinned sources


def lock_entries() -> list[tuple[str, str, str, str]]:
    entries = []
    for line in LOCK.read_text().splitlines():
        if line and not line.startswith("#"):
            entries.append(tuple(line.split("\t")))
    return entries


def source(group: str) -> Path:
    """The downloaded source archive of a hand-written group (its first entry)."""
    for g, _, name, _ in lock_entries():
        if g == group:
            path = DL / group / name
            if not path.exists():
                raise SystemExit(f"resolve.py: {path} missing; run corpus/baselines/fetch.sh")
            return path
    raise SystemExit(f"resolve.py: no group {group} in {LOCK}")


def member(archive: Path, suffix: str) -> bytes:
    with tarfile.open(archive) as tar:
        for info in tar.getmembers():
            if info.isfile() and info.name.endswith(suffix) and info.name.count("/") == 1:
                return tar.extractfile(info).read()
    raise SystemExit(f"resolve.py: no {suffix} at the top of {archive}")


def escape_module(path: str) -> str:
    """Module path as the Go proxy protocol spells it: capitals as '!' + lower case."""
    return re.sub(r"[A-Z]", lambda m: "!" + m[0].lower(), path)


def resolve_btrfscue() -> list[str]:
    lines = []
    seen = set()
    for row in member(source("btrfscue"), "/go.sum").decode().splitlines():
        module, version, _ = row.split()
        files = ["mod"] if version.endswith("/go.mod") else ["info", "mod", "zip"]
        version = version.removesuffix("/go.mod")
        for kind in files:
            rel = f"{escape_module(module)}/@v/{escape_module(version)}.{kind}"
            if rel in seen:
                continue
            seen.add(rel)
            url = f"{GOPROXY}/{rel}"
            print(f"fetch {url}", file=sys.stderr)
            sha = hashlib.sha256(fetch(url)).hexdigest()
            lines.append(f"btrfscue-deps\t{sha}\tgoproxy/{rel}\t{url}")
    return lines


def resolve_securityronin() -> list[str]:
    lock = tomllib.loads(member(source("securityronin"), "/Cargo.lock").decode())
    lines = []
    for package in lock["package"]:
        if package.get("source", "").startswith("registry+"):
            name, version = package["name"], package["version"]
            crate = f"{name}-{version}.crate"
            lines.append(
                f"securityronin-deps\t{package['checksum']}\tcrates/{crate}\t{CRATES}/{name}/{crate}"
            )
    return lines


def resolve_mbkn() -> list[str]:
    lock = tomllib.loads(member(source("mbkn"), "/uv.lock").decode())
    packages = {p["name"]: p for p in lock["package"]}
    root = next(p for p in lock["package"] if p.get("source", {}).get("editable") == ".")
    todo = [d["name"] for d in root.get("dependencies", [])]
    names = set()
    while todo:
        name = todo.pop()
        if name not in names:
            names.add(name)
            todo += [d["name"] for d in packages[name].get("dependencies", [])]
    lines = []
    for name in sorted(names):
        wheel = pick_wheel(packages[name].get("wheels", []))
        if wheel is None:
            raise SystemExit(f"resolve.py: no cp314 x86-64 wheel for {name} in mbkn's uv.lock")
        file = wheel["url"].rsplit("/", 1)[1]
        sha = wheel["hash"].removeprefix("sha256:")
        lines.append(f"mbkn-deps\t{sha}\twheels/{file}\t{wheel['url']}")
    return lines


def pick_wheel(wheels: list[dict]) -> dict | None:
    """A wheel CPython 3.14 on glibc x86-64 installs: compiled cp314 manylinux, else pure Python."""

    def tags(w: dict) -> tuple[str, str, str]:
        python, abi, platform = w["url"].rsplit("/", 1)[1].removesuffix(".whl").split("-")[-3:]
        return python, abi, platform

    for w in wheels:
        python, abi, platform = tags(w)
        if "cp314" in python.split(".") and abi == "cp314" and "manylinux" in platform:
            if "x86_64" in platform:
                return w
    for w in wheels:
        python, abi, platform = tags(w)
        if abi == "none" and platform == "any":
            return w
    return None


RESOLVERS = {
    "toolchain": resolve_toolchain,
    "btrfscue-deps": resolve_btrfscue,
    "securityronin-deps": resolve_securityronin,
    "mbkn-deps": resolve_mbkn,
}


def main() -> None:
    groups = sys.argv[1:] or list(COMPUTED)
    for group in groups:
        if group not in RESOLVERS:
            raise SystemExit(f"resolve.py: {group} is not a computed group ({', '.join(COMPUTED)})")
    text = LOCK.read_text()
    kept = [line for line in text.splitlines() if line.split("\t")[0] not in groups]
    fresh = []
    for group in groups:
        found = RESOLVERS[group]()
        print(f"{group}: {len(found)} entries", file=sys.stderr)
        fresh += found
    LOCK.write_text("\n".join(kept + fresh) + "\n")


if __name__ == "__main__":
    main()
