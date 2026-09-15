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


def read_bytes() -> int:
    """Bytes this process caused to be fetched from storage (/proc/self/io read_bytes)."""
    for line in Path("/proc/self/io").read_text().splitlines():
        if line.startswith("read_bytes:"):
            return int(line.split()[1])
    raise OSError("read_bytes missing from /proc/self/io")


def one_run(mode: str, cache: str, ctx, path: Path = IMAGE) -> dict:
    region = None
    allocated = path.stat().st_blocks * 512
    with open_image(path) as img:
        region = Region(0, img.size, "bench")
        if cache == "cold":
            os.posix_fadvise(img.fd, 0, 0, os.POSIX_FADV_DONTNEED)
        resident = residency(img)
        io_before = read_bytes()
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
        device_read = read_bytes() - io_before
        size = img.size
    return {
        "mode": mode,
        "cache": cache,
        "resident_before": round(resident, 4),
        "wall_s": round(wall, 3),
        "cpu_s": round(cpu, 3),
        "mb_per_s": round(size / 1e6 / wall, 1),
        "mib_per_s": round(size / MIB / wall, 1),
        # Non-hole bytes per second: holes read as zeros without device I/O.
        "allocated_mb_per_s": round(allocated / 1e6 / wall, 1),
        "device_read_mb": round(device_read / 1e6, 1),
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


def allocated_table() -> str:
    """The headline cells again as non-hole bytes per second, from results.json and image.json."""
    result = json.loads((OUT / "results.json").read_text())
    allocated = result["image"]["allocated_bytes"]
    lines = [
        "| Mode | Cache | N | image MB/s median (range) | allocated MB/s median (range) |",
        "|---|---|---|---|---|",
    ]
    for s in result["summary"]:
        rows = [r for r in result["rows"] if (r["mode"], r["cache"]) == (s["mode"], s["cache"])]
        alloc = spread([allocated / 1e6 / r["wall_s"] for r in rows])
        cells = f"{_cell(s['mb_per_s'])} | {_cell(alloc)}"
        lines.append(f"| {s['mode']} | {s['cache']} | {len(rows)} | {cells} |")
    return f"allocated bytes: {allocated} of {result['image']['params']['size']}\n" + "\n".join(
        lines
    )


# ---------------------------------------------------------------------------
# Density sweep: 1 GiB images at 0 %, 10 % and 100 % tree-block density
# ---------------------------------------------------------------------------
SWEEP_SIZE = GIB
SWEEP_DENSITIES = (0, 10, 100)  # percent of 16 KiB slots holding a tree block
SWEEP_CORRUPT = 0.01


def sweep_image(density: int) -> Path:
    return OUT / f"sweep_{density}.img"


def sweep_generate(verify: bool) -> dict:
    """Dense (non-sparse) images: each 16 KiB slot holds a pool tree block with probability
    density %, else random bytes. Seeded per density (1000 + density)."""
    pool, _ = node_pool()
    nodesize = len(pool[0])
    records = {}
    for density in SWEEP_DENSITIES:
        rng, digest = random.Random(1000 + density), hashlib.sha256()
        nodes = corrupt = 0
        started = time.perf_counter()
        target = None if verify else open(sweep_image(density), "wb")  # noqa: SIM115
        try:
            for _ in range(SWEEP_SIZE // nodesize):
                if rng.random() * 100 < density:
                    block = bytearray(pool[rng.randrange(len(pool))])
                    if rng.random() < SWEEP_CORRUPT:
                        block[rng.randrange(0x30, nodesize)] ^= 0xFF
                        corrupt += 1
                    block, nodes = bytes(block), nodes + 1
                else:
                    block = rng.randbytes(nodesize)
                digest.update(block)
                if target is not None:
                    target.write(block)
        finally:
            if target is not None:
                target.close()
        records[str(density)] = {
            "density_percent": density,
            "size": SWEEP_SIZE,
            "seed": 1000 + density,
            "corrupt": corrupt,
            "nodes": nodes,
            "sha256": digest.hexdigest(),
            "seconds": round(time.perf_counter() - started, 1),
        }
        if not verify:
            records[str(density)]["allocated_bytes"] = sweep_image(density).stat().st_blocks * 512
    if not verify:
        (OUT / "sweep_images.json").write_text(json.dumps(records, indent=1) + "\n")
    return records


def sweep_run(runs: int) -> dict:
    """N rounds; each round runs cold then warm full validation on 0 %, 10 %, 100 %, in order."""
    images = json.loads((OUT / "sweep_images.json").read_text())
    _, ctx = node_pool()
    rows = []
    for number in range(1, runs + 1):
        for density in SWEEP_DENSITIES:
            expected = images[str(density)]
            for cache in ("cold", "warm"):
                row = {"run": number, "density": density,
                       **one_run("full", cache, ctx, sweep_image(density))}  # fmt: skip
                if (row["hits"], row["valid"]) != (
                    expected["nodes"],
                    expected["nodes"] - expected["corrupt"],
                ):
                    raise AssertionError(f"counts differ from the generator: {row}")
                rows.append(row)
                print(json.dumps(row), flush=True)
    summary = []
    for density in SWEEP_DENSITIES:
        for cache in ("cold", "warm"):
            selected = [r for r in rows if (r["density"], r["cache"]) == (density, cache)]
            keys = ("mb_per_s", "allocated_mb_per_s", "wall_s", "cpu_s", "resident_before",
                    "device_read_mb")  # fmt: skip
            summary.append(
                {"density": density, "cache": cache, "n": len(selected),
                 **{key: spread([r[key] for r in selected]) for key in keys},
                 "hits": sorted({r["hits"] for r in selected}),
                 "valid": sorted({r["valid"] for r in selected})}
            )  # fmt: skip
    result = {"images": images, "affinity": sorted(os.sched_getaffinity(0)), "rows": rows,
              "summary": summary}  # fmt: skip
    (OUT / "sweep_results.json").write_text(json.dumps(result, indent=1) + "\n")
    return result


def sweep_table(result: dict) -> str:
    lines = [
        "| Density | Cache | N | MB/s median (range) | Wall s | CPU s | Pages cached before run "
        "| Device read MB | Hits | Valid |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for s in result["summary"]:
        lines.append(
            f"| {s['density']} % | {s['cache']} | {s['n']} | {_cell(s['mb_per_s'])} "
            f"| {_cell(s['wall_s'], 2)} | {_cell(s['cpu_s'], 2)} "
            f"| {_cell(s['resident_before'], 4)} | {_cell(s['device_read_mb'])} "
            f"| {', '.join(map(str, s['hits']))} | {', '.join(map(str, s['valid']))} |"
        )
    return "\n".join(lines)


def clean() -> None:
    for path in (IMAGE, *(sweep_image(density) for density in SWEEP_DENSITIES)):
        if path.exists():
            with open_image(path) as img:
                os.posix_fadvise(img.fd, 0, 0, os.POSIX_FADV_DONTNEED)
            path.unlink()


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
    sub.add_parser("allocated", help="headline cells as non-hole bytes per second")
    sweep_gen = sub.add_parser("sweep-generate", help="1 GiB images at 0, 10 and 100 %% density")
    sweep_gen.add_argument("--verify", action="store_true", help="recompute hashes; write nothing")
    sweep_bench = sub.add_parser("sweep-run", help="cold and warm full scans of the sweep images")
    sweep_bench.add_argument("--runs", type=int, default=5)
    sub.add_parser("clean", help="delete the 10 GiB image and the sweep images")
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
    elif args.command == "allocated":
        print(allocated_table())
    elif args.command == "sweep-generate":
        records = sweep_generate(args.verify)
        print(json.dumps(records, indent=1))
        if args.verify:
            stored = json.loads((OUT / "sweep_images.json").read_text())
            if any(stored[k]["sha256"] != records[k]["sha256"] for k in records):
                print("verify: MISMATCH with sweep_images.json", file=sys.stderr)
                return 1
            print("verify: identical to sweep_images.json")
    elif args.command == "sweep-run":
        print(sweep_table(sweep_run(args.runs)))
    else:
        clean()
    return 0


if __name__ == "__main__":
    sys.exit(main())
