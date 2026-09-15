"""LZO1X hostile-input harness (plan.md §3.5): btrfska's decoder beside the rejected options.

Run from the repo root with the dev group installed:

    uv run python tests/oracle/lzo_hostile.py --seeds 1 2 3 4 5 [--json OUT]

Per seed and decoder it reports:
- round trip: `--vectors` inputs (random, zero, low-entropy and repeated-text data, 1 B to 70 KiB,
  log-uniform sizes) compressed with lzallright, and whether each decoder returns them exactly;
- crafted: `15 41 42 43 44 40 FF 11 00 00` (4 literals, then a match 2 041 bytes back);
- truncated: a compressed 4 KiB sector cut in half;
- six hostile corpora of `--mutations` streams each, decoded with a 4 KiB bound:
  - bit_flips: one compressed 4 KiB sector with one bit flipped anywhere;
  - truncation: the same stream cut to a random length below its own;
  - insertion: one random byte inserted at a random position;
  - deletion: one byte deleted at a random position;
  - random_bytes: a valid literal run (first byte 18..32, 1..16 random literals) followed by
    1..16 bytes, each drawn half the time below 32 and otherwise from 0..255;
  - random_instructions: a literal run, 0..6 instructions of random class with every field random
    (lengths, zero-run extensions, distances, trailing-literal counts), then a 0001HLLL
    terminator with random H, length, distance and trailing count.
  In truncation, insertion and deletion every second position is drawn from the last TAIL (8)
  positions instead of the whole stream, the end-marker region. No single byte insertion,
  deletion or truncation turns `11 00 00` into another length code, and byte-level random
  streams almost never form `0001HLLL 00 00` at an instruction boundary: with the decoder that
  accepted any length there, the first five corpora agreed with lzallright on every stream for
  seeds 1-5, and only random_instructions exposed the difference.
  Each stream is counted as correct bytes (the original sector; never for the random corpora),
  other bytes within the bound (`wrong`, or `returned` for the random corpora), more bytes than
  the bound (`over_bound`:
  a decoder whose bound is only a size hint), a catchable `Exception`, or a `BaseException` that
  is not an `Exception` (a Rust panic surfacing as `pyo3_runtime.PanicException`);
- agreement per corpus: streams on which btrfska and lzallright both fail or return the same
  bytes, where an lzallright output over the bound counts as a failure (btrfska's one-sector
  bound is stricter by design). Every other stream is listed under `disagreements` with its hex.
Every count is a deterministic function of the seed and the decoder versions. The decoders are
btrfska.substrate.lzo, lzallright (lzokay) and dissect.util's pure-Python and native decoders;
unavailable ones are skipped. The bit-flip corpus draws from the seed exactly as the first,
bit-flip-only version of this harness did, so its counts are comparable across versions.
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
CORPORA = (
    "bit_flips",
    "truncation",
    "insertion",
    "deletion",
    "random_bytes",
    "random_instructions",
)
RANDOM = ("random_bytes", "random_instructions")
KINDS = ("correct", "wrong", "returned", "over_bound", "exception", "non_exception")
TAIL = 8


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
    if len(out) > bound:
        return "over_bound", len(out)
    if expected is None:
        return "returned", len(out)
    return ("correct" if out == expected else "wrong"), len(out)


def _position(rng: random.Random, index: int, limit: int) -> int:
    """Even indices: uniform in [0, limit); odd: within the last TAIL positions."""
    return rng.randrange(limit) if index % 2 == 0 else rng.randrange(max(0, limit - TAIL), limit)


def _random_stream(rng: random.Random) -> bytes:
    literals = rng.randrange(1, 17)
    body = bytes(
        rng.randrange(32) if rng.random() < 0.5 else rng.randrange(256)
        for _ in range(rng.randrange(1, 17))
    )
    return bytes([17 + literals]) + rng.randbytes(literals) + body


def _run_length(rng: random.Random) -> bytes:
    """The operand bytes of a zero length field: 0..2 zero bytes, then a non-zero byte."""
    return bytes(rng.randrange(3)) + bytes([rng.randrange(1, 256)])


def _small(rng: random.Random) -> int:
    return rng.randrange(4) if rng.random() < 0.5 else rng.randrange(256)


def _random_instructions(rng: random.Random) -> bytes:
    """A literal run, 0..6 instructions with every field random, then a 0001HLLL terminator with
    random H, L, D and S. Byte-level randomness almost never places a well-formed terminator."""
    literals = rng.randrange(1, 16)
    out = bytearray([17 + literals]) + rng.randbytes(literals)
    for _ in range(rng.randrange(7)):
        kind = rng.randrange(4)
        if kind == 0:  # 0000DDSS H
            op = rng.randrange(16)
            out += bytes([op, _small(rng)])
        elif kind == 1:  # 01LDDDSS H or 1LLDDDSS H
            op = rng.randrange(64, 256)
            out += bytes([op, _small(rng)])
        else:  # 001LLLLL LE16 or 0001HLLL LE16
            op = rng.randrange(32, 64) if kind == 2 else rng.randrange(16, 32)
            out.append(op)
            if op & (31 if kind == 2 else 7) == 0:
                out += _run_length(rng)
            out += bytes([_small(rng), _small(rng) if rng.random() < 0.5 else 0])
            op = out[-2]
        out += rng.randbytes(op & 3)  # the S trailing literals
    length = rng.randrange(8)
    out.append(16 | rng.randrange(2) << 3 | length)
    if length == 0:
        out += _run_length(rng)
    distance = 0 if rng.random() < 0.5 else rng.randrange(1, 64)
    trailing = rng.randrange(4)
    out += (distance << 2 | trailing).to_bytes(2, "little")
    if rng.random() < 0.5:
        out += rng.randbytes(trailing)
    return bytes(out)


def corpora(rng: random.Random, stream: bytes, count: int) -> dict[str, list[bytes]]:
    """The five hostile corpora, drawn in a fixed order from `rng`."""
    found = {name: [] for name in CORPORA}
    for _ in range(count):
        flipped = bytearray(stream)
        bit = rng.randrange(len(flipped) * 8)
        flipped[bit // 8] ^= 1 << (bit % 8)
        found["bit_flips"].append(bytes(flipped))
    for i in range(count):
        found["truncation"].append(stream[: _position(rng, i, len(stream))])
    for i in range(count):
        at = _position(rng, i, len(stream) + 1)
        found["insertion"].append(stream[:at] + bytes([rng.randrange(256)]) + stream[at:])
    for i in range(count):
        at = _position(rng, i, len(stream))
        found["deletion"].append(stream[:at] + stream[at + 1 :])
    for _ in range(count):
        found["random_bytes"].append(_random_stream(rng))
    for _ in range(count):
        found["random_instructions"].append(_random_instructions(rng))
    return found


def run(seed: int, vectors: int = 2000, mutations: int = 300) -> dict:
    rng = random.Random(seed)
    comp = compressor()
    found = decoders()
    result = {"seed": seed, "vectors": vectors, "mutations": mutations, "decoders": {}}
    inputs = [vector(rng) for _ in range(vectors)]
    streams = [comp.compress(data) for data in inputs]
    sector = bytes(rng.choice(b"abcdefgh\n ") for _ in range(SECTOR))
    sector_stream = comp.compress(sector)
    hostile = corpora(rng, sector_stream, mutations)

    for name, decode in found.items():
        entry = {}
        entry["round_trip_identical"] = sum(
            outcome(decode, s, len(d), d)[0] == "correct"
            for s, d in zip(streams, inputs, strict=True)
        )
        entry["crafted"] = outcome(decode, CRAFTED, SECTOR, None)
        entry["truncated"] = outcome(decode, sector_stream[: len(sector_stream) // 2], SECTOR, None)
        for corpus, cases in hostile.items():
            counts = dict.fromkeys(KINDS, 0)
            classes = set()
            expected = None if corpus in RANDOM else sector
            for stream in cases:
                kind, detail = outcome(decode, stream, SECTOR, expected)
                counts[kind] += 1
                if kind in ("exception", "non_exception"):
                    classes.add(detail)
            entry[corpus] = counts
            entry[f"{corpus}_failure_types"] = sorted(classes)
        result["decoders"][name] = entry

    if "lzallright" in found:
        result["agreement"], result["disagreements"] = {}, []
        for corpus, cases in hostile.items():
            agree = 0
            for stream in cases:
                ours = _bytes_or_error(found["btrfska"], stream)
                theirs = _bytes_or_error(found["lzallright"], stream)
                if ours == theirs:
                    agree += 1
                else:
                    result["disagreements"].append(
                        {"corpus": corpus, "stream": stream.hex(), "btrfska": _describe(ours),
                         "lzallright": _describe(theirs)}
                    )  # fmt: skip
            result["agreement"][corpus] = agree
    return result


def _bytes_or_error(decode, stream: bytes):
    """The output bytes, or ("error", type and message); output over the bound is an error."""
    try:
        out = decode(stream, SECTOR)
    except BaseException as exc:  # noqa: BLE001
        if isinstance(exc, KeyboardInterrupt | SystemExit):
            raise
        return ("error",)
    return ("error",) if len(out) > SECTOR else out


def _describe(value) -> str:
    return "error" if isinstance(value, tuple) else f"{len(value)} bytes"


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
        for corpus in CORPORA:
            for kind in KINDS:
                values = [e[corpus][kind] for e in entries]
                if not any(values):
                    continue
                lines.append(
                    f"  {corpus} {kind}: {values} (median {statistics.median(values)}, "
                    f"range {min(values)}-{max(values)})"
                )
            types = sorted({t for e in entries for t in e[f"{corpus}_failure_types"]})
            lines.append(f"  {corpus} failure types: {types}")
    if "agreement" in results[0]:
        for corpus in CORPORA:
            values = [r["agreement"][corpus] for r in results]
            lines.append(
                f"btrfska/lzallright agreement on {corpus}: {values} of {results[0]['mutations']}"
            )
        for r in results:
            for case in r["disagreements"]:
                lines.append(
                    f"disagreement seed {r['seed']} {case['corpus']}: {case['stream']} "
                    f"btrfska {case['btrfska']}, lzallright {case['lzallright']}"
                )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3, 4, 5])
    parser.add_argument("--vectors", type=int, default=2000)
    parser.add_argument("--mutations", type=int, default=300, help="streams per hostile corpus")
    parser.add_argument("--json", type=Path, help="also write the results as JSON (under images/)")
    args = parser.parse_args(argv)
    results = [run(seed, args.vectors, args.mutations) for seed in args.seeds]
    print(summary(results))
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
