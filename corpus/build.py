"""Build the test-image corpus of corpus/manifest.tsv, from a fresh clone, in one command.

    uv run python corpus/build.py              # everything that is not built yet
    uv run python corpus/build.py --force      # rebuild every image
    uv run python corpus/build.py m1_lzo ...   # only these images (and nothing they depend on)
    uv run python corpus/build.py --check      # only check the host, build nothing

Steps: check the host, fetch the pinned guest bundle (corpus/vm/fetch_vm.sh, about 190 MB, once),
build the guest initramfs, then run the `command` of every manifest row in file order, so an image
derived from another comes after it. Everything is written under the gitignored images/ folder.
No root is needed and nothing is installed.

The manifest is the recipe and holds no image hash: every mkfs draws a new filesystem UUID, so two
builds of one row never have the same bytes. What was built here is recorded in
images/scenarios/SHA256SUMS (`sha256sum -c` format). The vm tests compare the local images with
that record, which catches an image that was modified after it was built.
"""

import argparse
import csv
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
MANIFEST = REPO / "corpus" / "manifest.tsv"
SCENARIOS = REPO / "images" / "scenarios"
RECORD = SCENARIOS / "SHA256SUMS"
VM = REPO / "corpus" / "vm"

# Host commands the build needs, and the package that provides each on common distributions.
REQUIRED = {
    "qemu-system-x86_64": "qemu-system-x86 (Debian/Ubuntu), qemu-system-x86-core (Fedora), "
    "qemu-system-x86_64 (Arch), qemu-x86 (openSUSE)",
    "curl": "curl",
    "sha256sum": "coreutils",
    "ar": "binutils",
    "tar": "tar",
    "zstd": "zstd",
    "cpio": "cpio",
    "gzip": "gzip",
}


def host_problems() -> list[str]:
    problems = [
        f"`{tool}` not found; install {package}"
        for tool, package in REQUIRED.items()
        if shutil.which(tool) is None
    ]
    kvm = Path("/dev/kvm")
    if not kvm.exists():
        problems.append("/dev/kvm does not exist: enable virtualisation (VT-x/AMD-V) and KVM")
    elif not os.access(kvm, os.R_OK | os.W_OK):
        problems.append(
            "/dev/kvm is not readable and writable for this user: add the user to the `kvm` group "
            "(`sudo usermod -aG kvm $USER`, then log in again)"
        )
    return problems


def manifest_rows() -> list[dict]:
    with MANIFEST.open(newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def read_record() -> dict[str, str]:
    if not RECORD.exists():
        return {}
    lines = (line.split(maxsplit=1) for line in RECORD.read_text().splitlines() if line.strip())
    return {name.strip().removeprefix("*"): digest for digest, name in lines}


def write_record(record: dict[str, str]) -> None:
    RECORD.write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(record.items())))


def run(command: str | list[str]) -> None:
    subprocess.run(command, shell=isinstance(command, str), cwd=REPO, check=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", help="manifest rows to build (default: all)")
    parser.add_argument("--force", action="store_true", help="rebuild images that already exist")
    parser.add_argument("--check", action="store_true", help="check the host and stop")
    args = parser.parse_args(argv)

    if problems := host_problems():
        print("This host cannot build the corpus yet:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    if args.check:
        print("host ok: every tool is present and /dev/kvm is usable")
        return 0

    rows = manifest_rows()
    known = {row["name"] for row in rows}
    if unknown := [name for name in args.names if name not in known]:
        print(f"not in {MANIFEST.relative_to(REPO)}: {', '.join(unknown)}", file=sys.stderr)
        return 2
    wanted = [row for row in rows if not args.names or row["name"] in args.names]

    run([str(VM / "fetch_vm.sh")])
    run([str(VM / "build_initramfs.sh")])
    SCENARIOS.mkdir(parents=True, exist_ok=True)

    record = read_record()
    built = 0
    for row in wanted:
        path = SCENARIOS / f"{row['name']}.img"
        if path.exists() and not args.force:
            print(f"have   {row['name']}", flush=True)
        else:
            path.unlink(missing_ok=True)  # corpus/mutate.py refuses an existing destination
            started = time.monotonic()
            run(row["command"])
            if not path.exists():
                print(f"{row['name']}: the command did not write {path}", file=sys.stderr)
                return 1
            built += 1
            print(f"built  {row['name']} ({time.monotonic() - started:.1f} s)", flush=True)
            record.pop(path.name, None)
        if path.name not in record:
            record[path.name] = sha256(path)
        write_record(record)

    print(f"{built} built, {len(wanted) - built} already present; hashes in {RECORD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
