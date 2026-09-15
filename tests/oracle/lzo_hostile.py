"""LZO1X hostile-input harness (plan.md §3.5): btrfska's decoder beside the rejected options.

Run from the repo root with the dev group installed:

    uv run python tests/oracle/lzo_hostile.py --seeds 1 2 3 4 5 [--json OUT]

Per seed and decoder it reports:
- round trip: `--vectors` inputs (random, zero, low-entropy and repeated-text data, 1 B to 70 KiB,
  log-uniform sizes) compressed with lzallright, and whether each decoder returns them exactly;
- crafted: `15 41 42 43 44 40 FF 11 00 00` (4 literals, then a match 2 041 bytes back);
- truncated: a compressed 4 KiB sector cut in half;
- bit flips: `--flips` single-bit flips of one compressed 4 KiB sector, counted as correct bytes,
  wrong bytes within the 4 KiB bound, more bytes than the bound (`over_bound`: a decoder whose
  bound is only a size hint), a catchable `Exception`, or a `BaseException` that is not an
  `Exception` (a Rust panic surfacing as `pyo3_runtime.PanicException`);
- agreement: flipped streams on which btrfska and lzallright both fail (an over-bound output
  counting as a failure) or return the same bytes.
Every count is a deterministic function of the seed and the decoder versions. The decoders are
btrfska.substrate.lzo, lzallright (lzokay) and dissect.util's pure-Python and native decoders;
unavailable ones are skipped.
"""

import argparse
import json
import random
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from btrfska.substrate import lzo  # noqa: E402

CRAFTED = bytes.fromhex("154142434440ff110000")
SECTOR = 4096


def decoders() -> dict:
    """name -> function(stream, bound) -> bytes, for every decoder that is installed."""
    found = {"btrfska": lzo.decompress}
    try:
        import lzallright

        compressor = lzallright.LZOCompressor()
        found["lzallright"] = lambda data, bound: compressor.decompress(
            data, output_size_hint=max(bound, 1)
        )
    except ImportError:
        pass
    try:
        from dissect.util.compression import lzo_native, lzo_python

        found["dissect.util-python"] = lambda data, bound: lzo_python.decompress(data, False, bound)
        if lzo_native is not None:
            found["dissect.util-native"] = lambda data, bound: lzo_native.decompress(
                data, False, bound
            )
    except ImportError:
        pass
    return found


def compressor():
    import lzallright

    return lzallright.LZOCompressor()


def vector(rng: random.Random) -> bytes:
    size = int(round(2 ** rng.uniform(0, 16.1)))  # 1 B .. ~70 KiB
    size = max(1, min(size, 70 * 1024))
    kind = rng.choice(["random", "zero", "low-entropy", "text"])
    if kind == "random":
        return rng.randbytes(size)
    if kind == "zero":
        return bytes(size)
    if kind == "low-entropy":
        return bytes(rng.choice(b"abcdefgh\n ") for _ in range(size))
    line = b"%d the quick brown fox\n" % rng.randrange(1000)
    return (line * (size // len(line) + 1))[:size]


def outcome(decode, data: bytes, bound: int, expected: bytes | None):
    try:
        out = decode(data, bound)
    except Exception as exc:  # noqa: BLE001 - classifying every decoder's failures is the point
        return "exception", type(exc).__name__
    except BaseException as exc:  # noqa: BLE001 - e.g. pyo3 PanicException
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        return "non_exception", type(exc).__name__
    if expected is None:
        return "returned", len(out)
    if out == expected:
        return "correct", len(out)
    return ("over_bound" if len(out) > bound else "wrong"), len(out)


def run(seed: int, vectors: int = 2000, flips: int = 300) -> dict:
    rng = random.Random(seed)
    comp = compressor()
    found = decoders()
    result = {"seed": seed, "vectors": vectors, "flips": flips, "decoders": {}}
    inputs = [vector(rng) for _ in range(vectors)]
    streams = [comp.compress(data) for data in inputs]
    sector = bytes(rng.choice(b"abcdefgh\n ") for _ in range(SECTOR))
    sector_stream = comp.compress(sector)
    flipped = []
    for _ in range(flips):
        stream = bytearray(sector_stream)
        bit = rng.randrange(len(stream) * 8)
        stream[bit // 8] ^= 1 << (bit % 8)
        flipped.append(bytes(stream))

    for name, decode in found.items():
        entry = {}
        entry["round_trip_identical"] = sum(
            outcome(decode, s, len(d), d)[0] == "correct"
            for s, d in zip(streams, inputs, strict=True)
        )
        entry["crafted"] = outcome(decode, CRAFTED, SECTOR, None)
        entry["truncated"] = outcome(decode, sector_stream[: len(sector_stream) // 2], SECTOR, None)
        counts = dict.fromkeys(("correct", "wrong", "over_bound", "exception", "non_exception"), 0)
        classes = set()
        for stream in flipped:
            kind, detail = outcome(decode, stream, SECTOR, sector)
            counts[kind] += 1
            if kind in ("exception", "non_exception"):
                classes.add(detail)
        entry["bit_flips"] = counts
        entry["bit_flip_exception_types"] = sorted(classes)
        result["decoders"][name] = entry

    # Agreement between btrfska and lzallright on the flipped streams: both fail (more output than
    # the bound counts as a failure), or both return the same bytes.
    if "lzallright" in found:
        agree = 0
        for stream in flipped:
            ours = _bytes_or_error(found["btrfska"], stream)
            theirs = _bytes_or_error(found["lzallright"], stream)
            agree += ours == theirs
        result["btrfska_lzallright_bit_flip_agreement"] = agree
    return result


def _bytes_or_error(decode, stream: bytes):
    try:
        out = decode(stream, SECTOR)
    except BaseException as exc:  # noqa: BLE001
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        return "error"
    return "error" if len(out) > SECTOR else out


def summary(results: list[dict]) -> str:
    lines = [f"seeds: {[r['seed'] for r in results]}"]
    names = results[0]["decoders"]
    for name in names:
        lines.append(f"{name}:")
        entries = [r["decoders"][name] for r in results]
        rt = [e["round_trip_identical"] for e in entries]
        lines.append(f"  round trip identical: {rt} of {results[0]['vectors']}")
        lines.append(f"  crafted: {sorted({tuple(e['crafted']) for e in entries})}")
        lines.append(f"  truncated: {sorted({tuple(e['truncated']) for e in entries})}")
        for kind in ("correct", "wrong", "over_bound", "exception", "non_exception"):
            values = [e["bit_flips"][kind] for e in entries]
            lines.append(
                f"  bit flips {kind}: {values} (median {statistics.median(values)}, "
                f"range {min(values)}-{max(values)})"
            )
        types = sorted({t for e in entries for t in e["bit_flip_exception_types"]})
        lines.append(f"  bit flip failure types: {types}")
    if "btrfska_lzallright_bit_flip_agreement" in results[0]:
        values = [r["btrfska_lzallright_bit_flip_agreement"] for r in results]
        lines.append(
            f"btrfska/lzallright agreement on bit flips: {values} of {results[0]['flips']}"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    parser.add_argument("--vectors", type=int, default=2000)
    parser.add_argument("--flips", type=int, default=300)
    parser.add_argument("--json", type=Path, help="also write the results as JSON (under images/)")
    args = parser.parse_args(argv)
    results = [run(seed, args.vectors, args.flips) for seed in args.seeds]
    print(summary(results))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
