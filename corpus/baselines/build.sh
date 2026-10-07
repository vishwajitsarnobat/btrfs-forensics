#!/bin/sh
# Build the baseline tools inside the pinned guest (docs/plan.md M7d). Not part of setup.sh: the
# first run downloads about 550 MB and compiles for a while.
#
# Usage: corpus/baselines/build.sh [TOOL ...]     (default: every tool, in the order below)
#
# 1. fetch.sh             every input of baselines.lock, checked against its SHA-256
# 2. toolchain.py + mkfs  images/baselines/toolchain.img, the build and run root, from the lock's
#                         toolchain group (remade when the lock or toolchain.py is newer)
# 3. one guest job per tool: tools/TOOL/build.sh, chroot'ed into the toolchain disk, with no
#    network; the install tree lands in images/baselines/built/TOOL/tool
#
# A tool that fails to build is reported and the others still build; the exit status is then 1.
# Environment: MEM (default 3072), SMP (default 4), TIMEOUT (default 5400), plus vm.sh's.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${BASELINES_DIR:-$REPO/images/baselines}
ALL="btrfs-progs undelete-btrfs photorec btrfscue securityronin tsk fkie-tsk btrforensics mbkn"
TOOLS=${*:-$ALL}
for tool in $TOOLS; do
    [ -d "$HERE/tools/$tool" ] || { echo "build.sh: unknown tool $tool (known: $ALL)" >&2; exit 2; }
done

"$HERE/fetch.sh"
"$REPO/corpus/vm/fetch_vm.sh" > /dev/null
[ -r "$REPO/images/vm/initramfs.cpio.gz" ] || "$REPO/corpus/vm/build_initramfs.sh"

IMG=$WORK/toolchain.img
if [ ! -e "$IMG" ] || [ "$HERE/baselines.lock" -nt "$IMG" ] || [ "$HERE/toolchain.py" -nt "$IMG" ]
then
    echo "== toolchain disk"
    (cd "$REPO" && uv run python corpus/baselines/toolchain.py)
    rm -f "$IMG"
    truncate -s 4G "$IMG.part"
    "$REPO/corpus/vm/pinned.sh" mkfs.btrfs -q -f --rootdir "$WORK/toolchain/root" "$IMG.part"
    mv "$IMG.part" "$IMG"
fi

# job TOOL MODE DIR: a job directory for vm.sh (guest/job.sh documents its layout)
job() {
    rm -rf "$3"
    mkdir -p "$3/dl" "$3/deps"
    cp "$HERE/guest/job.sh" "$HERE/guest/fls-tree.awk" "$3/"
    printf 'MODE=%s\nTOOL=%s\n' "$2" "$1" > "$3/job.env"
    cp -R "$HERE/tools/$1" "$3/recipe"
    for group in "$1" "$1-deps"; do
        [ -d "$WORK/dl/$group" ] && ln -s "$WORK/dl/$group" "$3/dl/$group"
    done
    if [ -r "$HERE/tools/$1/needs" ]; then
        for dep in $(cat "$HERE/tools/$1/needs"); do
            [ -d "$WORK/built/$dep/tool" ] || {
                echo "build.sh: $1 needs $dep built first" >&2; return 1; }
            ln -s "$WORK/built/$dep/tool" "$3/deps/$dep"
        done
    fi
}

failed=
mkdir -p "$WORK/built" "$WORK/jobs"
for tool in $TOOLS; do
    echo "== build $tool"
    out=$WORK/built/$tool
    rm -rf "$out" "$out.failed"
    if job "$tool" build "$WORK/jobs/build-$tool" &&
        MEM=${MEM:-3072} SMP=${SMP:-4} TIMEOUT=${TIMEOUT:-5400} \
            "$HERE/vm.sh" "$WORK/jobs/build-$tool" "$out" > /dev/null; then
        grep -v '^#' "$HERE/baselines.lock" | awk -F '\t' -v t="$tool" \
            '$1 == t || $1 == t "-deps"' > "$out/pins.tsv"
        echo "built $tool: $(head -n 1 "$out/tool/VERSION")"
    else
        [ -d "$out" ] && mv "$out" "$out.failed"
        echo "FAILED $tool: see $out.failed/logs/build.log" >&2
        failed="$failed $tool"
    fi
    rm -rf "$WORK/jobs/build-$tool"
done
[ -z "$failed" ] || { echo "build.sh: not built:$failed" >&2; exit 1; }
