"""EXP-003: single-core throughput of the numpy scan kernel on a synthetic 10 GiB image.

Regenerates every number in experiments/EXP-003.md. From the repo root, with sandbox.img present:

    uv run python experiments/bench_scan.py generate            # writes the image and image.json
    uv run python experiments/bench_scan.py generate --verify   # recompute the hash only
    uv run python experiments/bench_scan.py run --runs 5        # results.json and a table on stdout
    uv run python experiments/bench_scan.py profile --mode full # cProfile of one warm run
    uv run python experiments/bench_scan.py clean               # drops its page cache, deletes it

Everything goes to images/scratch/exp/EXP-003/ (gitignored); nothing else is written.

The image is sparse and a deterministic function of the parameters (recorded in image.json with
its SHA-256). It is cut into 64 MiB tiles and a seeded shuffle assigns each tile a kind:
- metadata: 16 KiB slots, each holding, with a per-tile probability drawn from --density, a copy
  of a valid tree block of sandbox.img (crc32c; copies stay valid, since a tree block's checksum
  does not cover its location). A --corrupt fraction of the copies gets one byte flipped after the
  fsid, so they stay candidates and fail csum. Other slots are zero;
- data: random bytes;
- hole: never written (sparse, reads as zeros).

Measurement (plan.md §7). The whole image is one region; the kernel runs in this process
(workers=1), with an empty chunk map, so every header bytenr lookup misses. Modes:
- prefilter: iter_prefilter_hits only;
- full: iter_candidate_nodes, i.e. prefilter + check_block on every hit + chunk-map lookup.
Page cache states:
- cold: posix_fadvise(POSIX_FADV_DONTNEED) on the image before the run (no root needed);
- warm: run right after a pass that read every page.
Each round runs cold prefilter, warm prefilter, cold full, warm full, so every warm run follows a
cold run that has just read the image. Before each run, mincore() records the fraction of the
image's pages in the page cache, so the cache state is measured, not assumed. Throughput is image
bytes / wall-clock seconds, in MB/s (10^6 bytes) and MiB/s; CPU seconds are recorded too.
"""

import argparse
import cProfile
import ctypes
import hashlib
import io
import json
import os
import pstats
import random
import statistics
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

import numpy as np  # noqa: E402

from btrfska.scan.classify import scan_image  # noqa: E402
from btrfska.scan.kernel_numpy import iter_candidate_nodes, iter_prefilter_hits  # noqa: E402
from btrfska.scan.regions import Region  # noqa: E402
from btrfska.substrate.chunks import ChunkMap  # noqa: E402
from btrfska.substrate.fs import open_filesystem  # noqa: E402
from btrfska.substrate.image import open_image  # noqa: E402

OUT = REPO / "images" / "scratch" / "exp" / "EXP-003"
IMAGE = OUT / "synthetic.img"
SANDBOX = REPO / "sandbox.img"
MIB, GIB = 1 << 20, 1 << 30
PAGE = os.sysconf("SC_PAGE_SIZE")
EMPTY_MAP = ChunkMap("bench", [], {})


def node_pool():
    """Valid tree blocks of sandbox.img (targeted scan order), and the context to scan with."""
    with open_image(SANDBOX) as img:
        fs = open_filesystem(img)
        result = scan_image(img, fs)
        nodesize = fs.reader.ctx.nodesize
        pool = [
            bytes(img.mmap[c.record.physical : c.record.physical + nodesize])
            for c in result.classified
            if c.record.valid
        ]
    return pool, fs.reader.ctx


def tiles(params: dict, pool: list[bytes]):
    """(tile index, kind, bytes or None for a hole, stats) for every tile, deterministically."""
    rng = random.Random(params["seed"])
    count = params["size"] // params["tile"]
    order = list(range(count))
    rng.shuffle(order)
    kinds = ["hole"] * count
    metadata, data = params["metadata_tiles"], params["data_tiles"]
    for index in order[:metadata]:
        kinds[index] = "metadata"
    for index in order[metadata : metadata + data]:
        kinds[index] = "data"
    nodesize = len(pool[0])
    for index, kind in enumerate(kinds):
        if kind == "hole":
            yield index, kind, None, {}
        elif kind == "data":
            yield index, kind, rng.randbytes(params["tile"]), {}
        else:
            density = rng.uniform(*params["density"])
            buffer, nodes, corrupt = bytearray(params["tile"]), 0, 0
            for slot in range(0, params["tile"], nodesize):
                if rng.random() >= density:
                    continue
                node = bytearray(pool[rng.randrange(len(pool))])
                if rng.random() < params["corrupt"]:
                    node[rng.randrange(0x30, nodesize)] ^= 0xFF  # after the fsid: still a candidate
                    corrupt += 1
                buffer[slot : slot + nodesize] = node
                nodes += 1
            yield (
                index,
                kind,
                bytes(buffer),
                {"density": density, "nodes": nodes, "corrupt": corrupt},
            )


def generate(params: dict, verify: bool) -> dict:
    pool, _ = node_pool()
    digest, zero = hashlib.sha256(), bytes(params["tile"])
    summary = {"tiles": {"metadata": 0, "data": 0, "hole": 0}, "nodes": 0, "corrupt": 0}
    started = time.perf_counter()
    target = None if verify else open(IMAGE, "wb")  # noqa: SIM115
    try:
        if target is not None:
            target.truncate(params["size"])
        for index, kind, data, stats in tiles(params, pool):
            summary["tiles"][kind] += 1
            summary["nodes"] += stats.get("nodes", 0)
            summary["corrupt"] += stats.get("corrupt", 0)
            if data is not None and target is not None:
                os.pwrite(target.fileno(), data, index * params["tile"])
            digest.update(zero if data is None else data)
        digest.update(bytes(params["size"] % params["tile"]))
    finally:
        if target is not None:
            target.close()
    pool_digest = hashlib.sha256(b"".join(pool)).hexdigest()
    record = {
        "params": params,
        "node_pool": {"source": "sandbox.img valid scan candidates", "count": len(pool),
                      "sha256": pool_digest},
        **summary,
        "sha256": digest.hexdigest(),
        "seconds": round(time.perf_counter() - started, 1),
    }  # fmt: skip
    if not verify:
        stat = IMAGE.stat()
        record["allocated_bytes"] = stat.st_blocks * 512
        (OUT / "image.json").write_text(json.dumps(record, indent=1) + "\n")
    return record


def residency(img) -> float:
    """Fraction of the image's pages in the page cache (mincore on its read-only map)."""
    view = np.frombuffer(img.mmap, dtype=np.uint8)
    address = view.ctypes.data
    del view
    pages = -(-img.size // PAGE)
    vector = (ctypes.c_ubyte * pages)()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mincore.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p)
    if libc.mincore(address, img.size, vector):
        raise OSError(ctypes.get_errno(), "mincore failed")
    return float((np.frombuffer(vector, dtype=np.uint8) & 1).mean())


def one_run(mode: str, cache: str, ctx) -> dict:
    region = None
    with open_image(IMAGE) as img:
        region = Region(0, img.size, "bench")
        if cache == "cold":
            os.posix_fadvise(img.fd, 0, 0, os.POSIX_FADV_DONTNEED)
        resident = residency(img)
        wall, cpu = time.perf_counter(), time.process_time()
        hits = valid = 0
        if mode == "prefilter":
            hits = sum(1 for _ in iter_prefilter_hits(img, [region], ctx.fsid, ctx.sectorsize))
            valid = None
        else:
            for record in iter_candidate_nodes(img, [region], ctx, EMPTY_MAP):
                hits += 1
                valid += record.valid
        wall, cpu = time.perf_counter() - wall, time.process_time() - cpu
        size = img.size
    return {
        "mode": mode,
        "cache": cache,
        "resident_before": round(resident, 4),
        "wall_s": round(wall, 3),
        "cpu_s": round(cpu, 3),
        "mb_per_s": round(size / 1e6 / wall, 1),
        "mib_per_s": round(size / MIB / wall, 1),
        "hits": hits,
        "valid": valid,
    }


def spread(values) -> dict:
    return {"median": statistics.median(values), "min": min(values), "max": max(values)}


def run(runs: int) -> dict:
    image = json.loads((OUT / "image.json").read_text())
    _, ctx = node_pool()
    combos = [("prefilter", "cold"), ("prefilter", "warm"), ("full", "cold"), ("full", "warm")]
    rows = []
    for number in range(1, runs + 1):
        for mode, cache in combos:
            row = {"run": number, **one_run(mode, cache, ctx)}
            rows.append(row)
            print(json.dumps(row), flush=True)
    summary = []
    for mode, cache in combos:
        selected = [r for r in rows if (r["mode"], r["cache"]) == (mode, cache)]
        summary.append(
            {
                "mode": mode,
                "cache": cache,
                "n": len(selected),
                **{key: spread([r[key] for r in selected])
                   for key in ("mb_per_s", "mib_per_s", "wall_s", "cpu_s", "resident_before")},
                "hits": sorted({r["hits"] for r in selected}),
                "valid": sorted({r["valid"] for r in selected}, key=str),
            }
        )  # fmt: skip
    result = {"image": image, "affinity": sorted(os.sched_getaffinity(0)), "rows": rows,
              "summary": summary}  # fmt: skip
    (OUT / "results.json").write_text(json.dumps(result, indent=1) + "\n")
    return result


def _cell(values: dict, digits: int = 1) -> str:
    return f"{values['median']:.{digits}f} ({values['min']:.{digits}f}–{values['max']:.{digits}f})"


def table(result: dict) -> str:
    lines = [
        "| Mode | Cache | N | MB/s median (range) | MiB/s median (range) | Wall s median (range) "
        "| CPU s median (range) | Pages cached before run | Hits | Valid |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in result["summary"]:
        lines.append(
            f"| {s['mode']} | {s['cache']} | {s['n']} | {_cell(s['mb_per_s'])} "
            f"| {_cell(s['mib_per_s'])} | {_cell(s['wall_s'], 2)} | {_cell(s['cpu_s'], 2)} "
            f"| {_cell(s['resident_before'], 4)} | {', '.join(map(str, s['hits']))} "
            f"| {', '.join(map(str, s['valid']))} |"
        )
    return "\n".join(lines)


def profile(mode: str) -> str:
    _, ctx = node_pool()
    one_run("prefilter", "warm", ctx)  # read every page first
    profiler = cProfile.Profile()
    profiler.enable()
    row = one_run(mode, "warm", ctx)
    profiler.disable()
    stream = io.StringIO()
    pstats.Stats(profiler, stream=stream).sort_stats("tottime").print_stats(15)
    text = json.dumps(row) + "\n" + stream.getvalue()
    (OUT / f"profile_{mode}.txt").write_text(text)
    return text


def clean() -> None:
    if IMAGE.exists():
        with open_image(IMAGE) as img:
            os.posix_fadvise(img.fd, 0, 0, os.POSIX_FADV_DONTNEED)
        IMAGE.unlink()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate")
    gen.add_argument("--seed", type=int, default=3)
    gen.add_argument("--size-gib", type=int, default=10)
    gen.add_argument("--metadata-tiles", type=int, default=6)
    gen.add_argument("--data-tiles", type=int, default=80)
    gen.add_argument("--density", type=float, nargs=2, default=(0.2, 0.9))
    gen.add_argument("--corrupt", type=float, default=0.01)
    gen.add_argument("--verify", action="store_true", help="recompute the hash; write nothing")
    bench = sub.add_parser("run")
    bench.add_argument("--runs", type=int, default=5)
    bench.add_argument("--cpu", type=int, help="pin this process to one logical CPU")
    prof = sub.add_parser("profile")
    prof.add_argument("--mode", choices=("prefilter", "full"), default="full")
    sub.add_parser("clean")
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)
    if args.command == "generate":
        params = {
            "seed": args.seed,
            "size": args.size_gib * GIB,
            "tile": 64 * MIB,
            "metadata_tiles": args.metadata_tiles,
            "data_tiles": args.data_tiles,
            "density": list(args.density),
            "corrupt": args.corrupt,
        }
        record = generate(params, args.verify)
        print(json.dumps(record, indent=1))
        if args.verify:
            stored = json.loads((OUT / "image.json").read_text())
            if (stored["params"], stored["sha256"]) != (params, record["sha256"]):
                print("verify: MISMATCH with image.json", file=sys.stderr)
                return 1
            print("verify: identical to image.json")
    elif args.command == "run":
        if args.cpu is not None:
            os.sched_setaffinity(0, {args.cpu})
        print(table(run(args.runs)))
    elif args.command == "profile":
        print(profile(args.mode))
    else:
        clean()
    return 0


if __name__ == "__main__":
    sys.exit(main())
