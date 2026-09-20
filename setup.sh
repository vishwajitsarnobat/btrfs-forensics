#!/bin/sh
# From a fresh clone to a fully working checkout, in one command and a few minutes:
#
#   ./setup.sh            # environment, sandbox.img, test-image corpus, full test suite
#   ./setup.sh --no-corpus   # skip the corpus (no KVM/QEMU needed; its tests are then skipped)
#
# 1. uv sync --locked          the Python environment, exactly as uv.lock pins it
# 2. sandbox.img               the primary regression image, restored from the tracked fixture
#                              and checked against tests/fixtures/SHA256SUMS
# 3. corpus/build.py           the generated test images (downloads about 190 MB once)
# 4. ruff + pytest             lint and every test
#
# Needs uv (https://docs.astral.sh/uv/) and zstd; step 3 also needs KVM, QEMU and a few common
# tools, and says exactly what is missing. No root; nothing is written outside this folder.
set -eu

cd "$(dirname "$0")"
CORPUS=yes
case ${1:-} in
    --no-corpus) CORPUS=no ;;
    '') ;;
    *) echo "usage: ./setup.sh [--no-corpus]" >&2; exit 2 ;;
esac

command -v uv >/dev/null || {
    echo "uv is not installed: see https://docs.astral.sh/uv/getting-started/installation/" >&2
    exit 1; }
command -v zstd >/dev/null || { echo "zstd is not installed" >&2; exit 1; }

echo "== 1/4 Python environment"
uv sync --locked

echo "== 2/4 sandbox.img"
if ! sha256sum -c --quiet tests/fixtures/SHA256SUMS 2>/dev/null; then
    zstd -dc tests/fixtures/sandbox.img.zst > sandbox.img
    sha256sum -c tests/fixtures/SHA256SUMS
fi

if [ "$CORPUS" = yes ]; then
    echo "== 3/4 test-image corpus"
    uv run python corpus/build.py
else
    echo "== 3/4 test-image corpus: skipped (--no-corpus)"
fi

echo "== 4/4 lint and tests"
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
echo "setup complete"
