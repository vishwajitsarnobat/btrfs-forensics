"""EXP-014: single-bit flips of a compressed LZO sector decode to wrong bytes without an error.

The hypothesis is in experiments/EXP-014.md §1. The streams are the bit-flip corpus of
tests/oracle/lzo_hostile.py, drawn from the same seed in the same order, so the counts here are the
harness's bit_flips counts (plan.md §3.5, catalog.md M1c review fixes): per seed, a 4 KiB sector
of low-entropy text (bytes from "abcdefgh\\n "), compressed once with lzallright, and 300 copies of
that stream with one bit flipped at a uniformly random position. Each copy is decoded with a
4 KiB bound by every installed decoder: btrfska.substrate.lzo, lzallright (lzokay), and
dissect.util's pure-Python and native decoders.

Per seed and decoder a stream is counted as `correct` (the original sector), `wrong` (other bytes,
at most 4 KiB, no error), `over_bound` (more than 4 KiB returned), `exception` (a catchable
`Exception`) or `non_exception` (a `BaseException` that is not an `Exception`, such as pyo3's
PanicException). Across decoders, per seed: the streams every one of btrfska, lzallright and
dissect.util native decodes to wrong bytes, and on how many of those the three return the same
bytes; and how many of btrfska's wrong outputs are exactly one sector long.

Everything is a deterministic function of the seed and the decoder versions (uv.lock).

Usage, from the repo root:
  uv run python experiments/exp014.py [--seeds 1 2 3 4 5] [--json OUT]
"""

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))  # tests/oracle/lzo_hostile.py, whether run as a script or imported

from tests.oracle import lzo_hostile  # noqa: E402

KINDS = ("correct", "wrong", "over_bound", "exception", "non_exception")
# The decoders whose wrong outputs the paper compares (plan.md §3.5).
SAME = ("btrfska", "lzallright", "dissect.util-native")
VECTORS = 2000  # lzo_hostile.run draws these before the sector; they fix the random state


def bit_flip_streams(seed: int, mutations: int = 300) -> tuple[bytes, bytes, list[bytes]]:
    """(sector, its compressed stream, the flipped streams), drawn as lzo_hostile.run draws them."""
    rng = random.Random(seed)
    for _ in range(VECTORS):
        lzo_hostile.vector(rng)
    sector = bytes(rng.choice(b"abcdefgh\n ") for _ in range(lzo_hostile.SECTOR))
    stream = lzo_hostile.compressor().compress(sector)
    return sector, stream, lzo_hostile.corpora(rng, stream, mutations)["bit_flips"]


def decode(function, data: bytes) -> tuple[str, bytes | str | None]:
    """(kind, output bytes or failure type) under the harness's one-sector bound."""
    bound = lzo_hostile.SECTOR
    try:
        out = function(data, bound)
    except Exception as exc:  # noqa: BLE001 - classifying every decoder's failures is the point
        return "exception", type(exc).__name__
    except BaseException as exc:  # noqa: BLE001 - e.g. pyo3 PanicException
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        return "non_exception", type(exc).__name__
    return ("over_bound" if len(out) > bound else "returned"), bytes(out)


def run(seed: int, mutations: int = 300) -> dict:
    sector, stream, flips = bit_flip_streams(seed, mutations)
    found = lzo_hostile.decoders()
    result = {"seed": seed, "mutations": mutations, "stream_bytes": len(stream), "decoders": {}}
    outputs = {}
    for name, function in found.items():
        kind, out = decode(function, stream)
        counts = dict.fromkeys(KINDS, 0)
        failures, one_sector, per_stream = set(), 0, []
        for flipped in flips:
            kind_i, out_i = decode(function, flipped)
            if kind_i == "returned":
                kind_i = "correct" if out_i == sector else "wrong"
                one_sector += kind_i == "wrong" and len(out_i) == len(sector)
            elif kind_i != "over_bound":
                failures.add(out_i)
            counts[kind_i] += 1
            per_stream.append((kind_i, out_i if kind_i == "wrong" else None))
        outputs[name] = per_stream
        result["decoders"][name] = {
            "unflipped_correct": kind == "returned" and out == sector,
            **counts,
            "wrong_one_sector_long": one_sector,
            "failure_types": sorted(failures),
        }
    if all(name in outputs for name in SAME):
        wrong_in_all = [
            i for i in range(len(flips)) if all(outputs[n][i][0] == "wrong" for n in SAME)
        ]
        result["wrong_in_all_three"] = len(wrong_in_all)
        result["wrong_identical_in_all_three"] = sum(
            len({outputs[n][i][1] for n in SAME}) == 1 for i in wrong_in_all
        )
        result["same_wrong_set"] = all(
            [k == "wrong" for k, _ in outputs[n]] == [k == "wrong" for k, _ in outputs[SAME[0]]]
            for n in SAME
        )
    return result


def _cell(values: list[int]) -> str:
    return f"{statistics.median(values):g} ({min(values)}–{max(values)})"


def report(results: list[dict]) -> str:
    seeds = [r["seed"] for r in results]
    names = list(results[0]["decoders"])
    lines = [f"seeds {seeds}, {results[0]['mutations']} flipped streams per seed; "
             f"compressed sector {[r['stream_bytes'] for r in results]} bytes", "",
             "Per seed (wrong bytes within 4 KiB, no error):", "",
             "| Decoder | " + " | ".join(f"seed {s}" for s in seeds) + " | Median (range) |",
             "|---|" + "---|" * (len(seeds) + 1)]  # fmt: skip
    for name in names:
        values = [r["decoders"][name]["wrong"] for r in results]
        lines.append(f"| {name} | " + " | ".join(map(str, values)) + f" | {_cell(values)} |")
    lines += ["", "Median (range) over the seeds:", "",
              "| Decoder | Unflipped stream correct | Correct | Wrong ≤ 4 KiB | > 4 KiB "
              "| `Exception` | non-`Exception` | Wrong and one sector long | Failure types |",
              "|---|---|---|---|---|---|---|---|---|"]  # fmt: skip
    for name in names:
        entries = [r["decoders"][name] for r in results]
        cells = [_cell([e[k] for e in entries]) for k in (*KINDS, "wrong_one_sector_long")]
        unflipped = sum(e["unflipped_correct"] for e in entries)
        types = sorted({t for e in entries for t in e["failure_types"]})
        lines.append(f"| {name} | {unflipped}/{len(entries)} | " + " | ".join(cells)
                     + f" | {', '.join(types) or '-'} |")  # fmt: skip
    if "wrong_in_all_three" in results[0]:
        lines += [
            "",
            f"wrong in all of {', '.join(SAME)}: "
            f"{[r['wrong_in_all_three'] for r in results]}; of those, identical bytes in all "
            f"three: {[r['wrong_identical_in_all_three'] for r in results]}; the same streams "
            f"are wrong in all three: {[r['same_wrong_set'] for r in results]}",
        ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    parser.add_argument("--mutations", type=int, default=300, help="flipped streams per seed")
    parser.add_argument("--json", type=Path, help="also write the results as JSON (under images/)")
    args = parser.parse_args(argv)
    results = [run(seed, args.mutations) for seed in args.seeds]
    print(report(results))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
