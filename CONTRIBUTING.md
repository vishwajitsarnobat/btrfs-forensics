# Working on btrfs-forensics

The rules everyone working on this repository follows. They are short on
purpose and they are not optional. If a rule is wrong, change it here in a
pull request; do not work around it. Background and reasons live in
[`docs/plan.md`](docs/plan.md) (the build plan), [`docs/catalog.md`](docs/catalog.md)
(what was done and why) and [`docs/research.md`](docs/research.md) (prior art).

## 1. One feature, one branch, one pull request

1. **Plan first.** Before writing code, know what the feature is, what "done"
   means (the milestone's definition of done in `docs/plan.md` §5, or write
   one), which files change and how it will be tested. For anything larger
   than a fix, write the plan into the pull request description or the plan.
2. **Branch** from an up-to-date `main`: `feature/<name>`, `fix/<name>`,
   `docs/<name>` or `chore/<name>`. One feature per branch. Never commit to
   `main` directly.
3. **Implement in small commits.** A commit subject is one plain sentence
   that says what changed: "Add the numpy scan kernel: strided fsid prefilter,
   every candidate validated and kept".
4. **Test** (§3) before opening the pull request, not after.
5. **Record it:** every pull request adds an entry at the top of
   `docs/catalog.md`: branch, why, what changed, the numbers, how it was
   verified. A measured result also gets an `experiments/EXP-NNN.md` record
   (§5).
6. **Open the pull request** into `main`. Describe it for a reader who was not
   there: `## Summary` (what and why, in plain language), `## Key results`
   when there are numbers, `## Verification`, `## Must know` (limits, caveats,
   anything surprising).
7. **Review it** before merging, even when you wrote it: read the whole diff
   on GitHub, check that nothing unrelated slipped in, and wait for CI to
   pass. GitHub can take a few minutes to start a run: "no checks reported"
   means wait, not merge, unless the change touches only `docs/` (which starts
   no run). A failing check is fixed on the branch, never merged over.
8. **Merge** with a merge commit and delete the branch.

Ask the maintainer when a decision is really theirs to make: a change of
scope or of a claim in the paper, anything that costs money, anything that
cannot be undone, or a choice between designs with different long-term
costs. Otherwise pick the sensible default, say so in the pull request, and
carry on.

## 2. How things are written

- Commits, pull requests, comments and documents are written by and for
  people: plain language, complete sentences, no filler.
- **No tool or assistant attribution anywhere:** no "generated with" lines, no
  `Co-authored-by` trailers for tools, in no commit, pull request, comment or
  document. The authors of this project are the people listed on it.
- Code reads like the code around it: same naming, same comment density, same
  idiom. Kernel behaviour is cited by file and line at tag v7.0.
- A document never states more than the evidence supports. Unverified facts
  are marked UNVERIFIED until someone checks them.

## 3. Definition of done for a pull request

```sh
uv run ruff check . && uv run ruff format --check .
uv run pytest                      # with sandbox.img and the corpus present: nothing skipped
sha256sum -c tests/fixtures/SHA256SUMS
```

- New behaviour has tests. A bug fix has a test that failed before it.
- Parsers never crash on hostile input; a new parser gets a hostile-input
  test.
- When a script under `corpus/`, `setup.sh` or the CI workflow changes, prove
  it from scratch: clone the branch into `images/scratch/`, run `./setup.sh`
  there, and delete the clone.
- Python runs through `uv` only (`uv sync --locked`, `uv run …`). A new
  dependency is a decision for the maintainer.

## 4. Anyone can rebuild everything

**A fresh clone reaches a complete, tested checkout with `./setup.sh` in a
few minutes, on any Linux distribution.** Every change keeps that true.

- No dependence on the host: not on its distribution, its package manager,
  its btrfs-progs or its libraries. What decides the bytes on disk (guest
  kernel, `mkfs.btrfs`, guest tools) is pinned by SHA-256 in
  `corpus/vm/guest.lock` and fetched by URL. A new baseline tool or guest
  package is pinned the same way.
- No root. Nothing is installed. Nothing is written outside the repository
  folder; images, VM tooling, tool builds and scratch output go under the
  gitignored `images/`.
- `corpus/manifest.tsv` is a recipe. A new test image is a new row whose
  `command` builds it; `corpus/build.py` builds every row.

## 5. Evidence and numbers

- **Read-only, always.** No code path may write to an evidence image. Images
  are opened in exactly one place (`src/btrfska/substrate/image.py`,
  `O_RDONLY`); a test bans other open sites; the test session checks the
  `sandbox.img` hash before and after. `sandbox.img` is never mounted,
  repaired or modified.
- A number may enter the paper only if a committed script regenerates it, and
  it is written up as `experiments/EXP-NNN.md` with the template of
  `docs/plan.md` §7 (hypothesis, method, environment record, exact command,
  results, threats to validity).
- A run inside the guest is not bit-stable: counts and generation numbers
  vary with timing and with the class of host. Run it at least 5 times, report
  median and range, name the host, and never quote one run as a constant.
  **Tests assert claims relative to the image they read, never one run's
  numbers.**
- Register a prediction before running an experiment that could embarrass a
  claim, and report the result either way.

## 6. The repository

- `main` is never force-pushed and published history is never rewritten.
  Commit hashes are cited throughout `docs/` and the experiment records. (It
  was done once, on 2026-09-21; `docs/commit-hash-map-2026-09-21.tsv` maps the
  old hashes.)
- Project documents live in `docs/`; `README.md` stays at the root and
  documents the command-line interface exactly (tests compare them).
- Papers live in `docs/papers/`, tracked, named
  `firstauthor[_secondauthor]_short_topic_year.pdf`, each with a row in
  `docs/papers/README.md`. Get them from the publisher, an open-access
  repository or the authors. A paper is cited for what it says only after
  someone has read it; until then its notes say so.
- `major-project.jpg` (the signed project proposal) stays where it is.
- `legacy/` is the frozen prototype. It is changed only to keep it running,
  and deleted only when the parity gate of `docs/plan.md` §4.3 is met.

## 7. Cost

The project spends nothing. The repository is public, so GitHub Actions is
free on the standard runners the workflow uses. Keep usage small anyway:
collect fixes into one push instead of many, do not re-run workflows without
a reason, and keep the guards in `.github/workflows/ci.yml` (time limits,
cancelled superseded runs, no run for changes under `docs/` only). Nothing
that needs a paid plan, a paid runner or a payment method is added.
