#!/bin/bash
# One baseline job inside the guest (chroot'ed into the toolchain disk; see guest/init). The host
# side (corpus/baselines/build.sh or run.sh) puts into /work/in:
#
#   job.env    MODE (build or run) and TOOL
#   recipe/    corpus/baselines/tools/$TOOL: build.sh, run.sh and anything they need
#   dl/        the tool's pinned inputs (lock groups $TOOL and $TOOL-deps)
#   deps/NAME  for a build, the install tree of a tool this one builds against
#   tool/      for a run, the tool's install tree from its build job
#
# A build runs recipe/build.sh, which installs into /work/tool (its prefix) and writes
# /work/tool/VERSION; /work/tool is then copied to /work/out/tool. A run links /work/tool to the
# install tree, runs recipe/run.sh under GNU time with the evidence at /dev/vdb, and normalises
# what it wrote into /work/out/files.tsv and /work/out/run.tsv (corpus/baselines/README.md).
set -u
. /work/in/job.env
export TOOL MODE
export IN=/work/in DL=/work/in/dl DEPS=/work/in/deps RECIPE=/work/in/recipe
export PREFIX=/work/tool SRC=/work/src
export EVIDENCE=/dev/vdb
export OUT=/work/out/files LOGS=/work/out/logs SCRATCH=/work/scratch
export MAKEFLAGS=-j$(nproc)
mkdir -p "$HOME" "$SRC" "$LOGS" "$SCRATCH"

if [ "$MODE" = build ]; then
    mkdir -p "$PREFIX"
    {
        echo "gcc	$(gcc --version | head -n 1)"
        echo "rustc	$(rustc --version)"
        echo "go	$(go version)"
        echo "kernel	$(uname -r)"
    } > /work/out/toolchain.tsv
    bash -e "$RECIPE/build.sh" > "$LOGS/build.log" 2>&1
    status=$?
    tail -n 40 "$LOGS/build.log"
    if [ $status -eq 0 ]; then
        cp -a "$PREFIX" /work/out/tool
        echo "=== BUILT $TOOL $(head -n 1 "$PREFIX/VERSION")"
    else
        echo "=== BUILD-FAILED $TOOL status $status"
    fi
    exit $status
fi

# run: the evidence must be read-only all the way down, whatever the tool does
[ "$(cat /sys/block/vdb/ro)" = 1 ] || { echo "=== EVIDENCE-WRITABLE"; exit 90; }
ln -s /work/in/tool "$PREFIX"
mkdir -p "$OUT"
# NAMES (from the recipe): `path` when the tool restores names and paths (the name of a file is
# then its basename unless names.tsv says otherwise), `none` for a carver
NAMES=path
[ -r "$RECIPE/names" ] && NAMES=$(cat "$RECIPE/names")
/usr/bin/time -f '%e	%M' -o /work/out/time.tsv bash "$RECIPE/run.sh" > "$LOGS/run.log" 2>&1
status=$?
tail -n 20 "$LOGS/run.log"

# files.tsv: one row per regular file the tool produced, with tab, newline and backslash
# escaped as \t, \n and \\ (score.py reads it back)
esc() {
    local s=${1//\\/\\\\}
    s=${s//$'\t'/\\t}
    printf '%s' "${s//$'\n'/\\n}"
}
declare -A named=()
if [ -r /work/out/names.tsv ]; then
    while IFS=$'\t' read -r path name; do named[$path]=$name; done < /work/out/names.tsv
fi
{
    printf 'path\tname\tsize\tsha256\n'
    cd "$OUT"
    find . -type f -print0 | sort -z | while IFS= read -r -d '' f; do
        f=${f#./}
        case $NAMES in
            none) name= ;;
            *) name=${named[$(esc "$f")]-${f##*/}} ;;
        esac
        sha=$(sha256sum < "$f")
        printf '%s\t%s\t%s\t%s\n' "$(esc "$f")" "$(esc "$name")" "$(stat -c %s "$f")" "${sha%% *}"
    done
} > /work/out/files.tsv
IFS=$'\t' read -r wall rss < <(tail -n 1 /work/out/time.tsv)
{
    printf 'tool\t%s\n' "$TOOL"
    printf 'version\t%s\n' "$(head -n 1 "$PREFIX/VERSION")"
    printf 'recipe_sha256\t%s\n' "$(sha256sum < "$RECIPE/run.sh" | cut -d' ' -f1)"
    printf 'exit\t%s\n' "$status"
    printf 'wall_s\t%s\n' "$wall"
    printf 'max_rss_kib\t%s\n' "$rss"
    printf 'files\t%s\n' "$(($(wc -l < /work/out/files.tsv) - 1))"
    printf 'guest_kernel\t%s\n' "$(uname -r)"
} > /work/out/run.tsv
echo "=== RAN $TOOL exit $status files $(($(wc -l < /work/out/files.tsv) - 1))"
exit 0
