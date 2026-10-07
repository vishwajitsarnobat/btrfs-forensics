"""Unpack the pinned toolchain packages into a root tree for the baseline guest.

Every .deb of the lock group `toolchain` (fetched by fetch.sh) is unpacked the way `dpkg-deb -x`
would, with nothing installed and no maintainer script run: the data member is extracted into
images/baselines/toolchain/root. Noble is only partly usr-merged, so members under /bin, /sbin,
/lib and /lib64 are put under /usr and the top-level names are symlinks, as on an installed
system. What the maintainer scripts would have done and the jobs need is done here: the
`/etc/mtab` link undelete-btrfs reads, and the empty directories the guest mounts onto.

build.sh then formats the tree into images/baselines/toolchain.img with the bundle's own
`mkfs.btrfs --rootdir` (corpus/vm/pinned.sh).

Usage, from the repo root:  uv run python corpus/baselines/toolchain.py
"""

import io
import shutil
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
LOCK = HERE / "baselines.lock"
WORK = REPO / "images" / "baselines"
ROOT = WORK / "toolchain" / "root"
MERGED = ("bin", "sbin", "lib", "lib64")
# Mount points of the guest's /init (corpus/baselines/guest/init) and the job's directories.
MOUNT_POINTS = ("proc", "sys", "dev", "tmp", "work", "root")
# The links dpkg's alternatives and diversions would make (maintainer scripts of dash, gawk,
# automake, gcc, g++, rustc-1.89, cargo-1.89 and golang-1.24-go), so recipes call the usual names.
ALTERNATIVES = {
    "usr/bin/sh": "dash",
    "usr/bin/awk": "gawk",
    "usr/bin/cc": "gcc",
    "usr/bin/c++": "g++",
    "usr/bin/aclocal": "aclocal-1.16",
    "usr/bin/automake": "automake-1.16",
    "usr/bin/rustc": "../lib/rust-1.89/bin/rustc",
    "usr/bin/cargo": "../lib/rust-1.89/bin/cargo",
    "usr/bin/go": "../lib/go-1.24/bin/go",
    "usr/bin/gofmt": "../lib/go-1.24/bin/gofmt",
}


def ar_members(path: Path) -> dict[str, bytes]:
    """The members of a Debian ar archive (deb(5)): name -> bytes."""
    data = path.read_bytes()
    if not data.startswith(b"!<arch>\n"):
        raise SystemExit(f"toolchain.py: {path} is not an ar archive")
    members = {}
    at = 8
    while at + 60 <= len(data):
        header = data[at : at + 60]
        name = header[:16].decode().strip().rstrip("/")
        size = int(header[48:58].decode().strip())
        members[name] = data[at + 60 : at + 60 + size]
        at += 60 + size + (size & 1)
    return members


def merged(name: str) -> str:
    """A member path with /bin, /sbin, /lib, /lib64 moved under /usr."""
    parts = name.removeprefix("./").split("/", 1)
    if parts[0] in MERGED:
        return "./usr/" + "/".join(parts)
    return name


def unpack(deb: Path) -> None:
    members = ar_members(deb)
    data = next(name for name in members if name.startswith("data.tar"))
    with tarfile.open(fileobj=io.BytesIO(members[data])) as tar:
        for info in tar.getmembers():
            info.name = merged(info.name)
            if info.islnk():
                info.linkname = merged(info.linkname)
            if info.isdir() and info.name.rstrip("/") in ("./usr", "."):
                continue
            # the 'tar' filter refuses absolute and escaping member paths; symlink targets are
            # left alone because they are resolved inside the guest's chroot
            tar.extract(info, ROOT, filter="tar")


def main() -> None:
    debs = []
    for line in LOCK.read_text().splitlines():
        if line.startswith("toolchain\t"):
            _, _, file, _ = line.split("\t")
            debs.append(WORK / "dl" / "toolchain" / file)
    missing = [deb for deb in debs if not deb.exists()]
    if missing:
        raise SystemExit(f"toolchain.py: {missing[0]} missing; run corpus/baselines/fetch.sh")
    shutil.rmtree(ROOT, ignore_errors=True)
    (ROOT / "usr").mkdir(parents=True)
    for top in MERGED:
        (ROOT / "usr" / top).mkdir()
        (ROOT / top).symlink_to(f"usr/{top}")
    for deb in debs:
        unpack(deb)
    for point in MOUNT_POINTS:
        (ROOT / point).mkdir(exist_ok=True)
    for link, target in ALTERNATIVES.items():
        if not (ROOT / link).parent.joinpath(target).exists():
            raise SystemExit(f"toolchain.py: {link} -> {target}: no such file in the tree")
        (ROOT / link).unlink(missing_ok=True)
        (ROOT / link).symlink_to(target)
    (ROOT / "etc").mkdir(exist_ok=True)
    mtab = ROOT / "etc" / "mtab"
    mtab.unlink(missing_ok=True)
    mtab.symlink_to("/proc/mounts")
    print(f"unpacked {len(debs)} packages into {ROOT}", file=sys.stderr)


if __name__ == "__main__":
    main()
