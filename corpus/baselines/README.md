# corpus/baselines — the baseline tools, built and run in the pinned guest

Builds every baseline of `docs/plan.md` M7 ("Baseline harness") inside the same rootless
QEMU/KVM guest as `corpus/vm/`, runs each one read-only on a copy of an image, and scores what it
produced against the image's scenario log. Nothing is built on the host, nothing is installed,
no root; everything lands under the gitignored `images/baselines/`. Design and definition of
done: `docs/plan.md` M7d; where each tool comes from and why it is pinned as it is:
`docs/research/baselines.md`.

`setup.sh` does not build the baselines: the first build downloads about 550 MB and compiles
for a while. Requirements are those of `corpus/vm/` (KVM, host QEMU, curl, sha256sum, tar,
cpio, gzip) plus `uv`.

```sh
corpus/baselines/build.sh [TOOL ...]              # fetch, toolchain disk, build in the guest
corpus/baselines/run.sh TOOL IMAGE [OUT_DIR]      # one run, read-only, normalised output
uv run python corpus/baselines/score.py RUN_DIR   # files produced, hash-exact, names recovered
```

Tools, in build order: `btrfs-progs` (`btrfs restore` + `btrfs-find-root` 7.1),
`undelete-btrfs` (v1.0, on the btrfs-progs build), `photorec` (TestDisk 7.2 static binary),
`btrfscue` (v0.7), `securityronin` (btrfs-forensic 0.1.3 `recover_deleted` through
`tools/securityronin/harness/`), `tsk` (Sleuth Kit `develop` at 424ee3c), `fkie-tsk` (pool
tools), `btrforensics` (on the TSK build), `mbkn` (mbkn-btrfs-rescue v0.4.0). Commercial tools
are out (they cost money).

## How it works

1. **Pins.** [`baselines.lock`](baselines.lock) lists every input, `group sha256 file source`,
   like `corpus/vm/guest.lock`. One group per tool holds its source; `toolchain`,
   `btrfscue-deps`, `securityronin-deps` and `mbkn-deps` are computed by
   [`resolve.py`](resolve.py) (the dependency closure of a short package list from the Ubuntu
   snapshot's Packages indices; the Go modules of btrfscue's go.sum; the crates of SecurityRonin's
   Cargo.lock; the cp314 wheels of mbkn's uv.lock). [`fetch.sh`](fetch.sh) downloads them into
   `images/baselines/dl/` and checks every SHA-256.
2. **Toolchain disk.** [`toolchain.py`](toolchain.py) unpacks the `toolchain` packages (no
   maintainer scripts; `/bin`, `/sbin`, `/lib`, `/lib64` merged into `/usr`; the alternatives
   links `sh`, `awk`, `cc`, `c++`, `rustc`, `cargo`, `go` made by hand), and the bundle's
   `mkfs.btrfs --rootdir` formats the tree into `images/baselines/toolchain.img`.
3. **Jobs.** [`vm.sh`](vm.sh) boots the corpus kernel and initramfs with a second init,
   [`guest/init`](guest/init), and five disks: the toolchain disk (`/dev/vda`, read-only; the job
   runs chroot'ed into it), the evidence copy (`/dev/vdb`, QEMU `readonly=on`), the job's input
   as a tar (`/dev/vdc`), a fresh btrfs work disk (`/dev/vdd`) and the output tar (`/dev/vde`),
   which the host unpacks. No network. [`guest/job.sh`](guest/job.sh) runs the tool's recipe.
4. **Recipes.** `tools/TOOL/build.sh` installs into the job's prefix and writes `VERSION`;
   `tools/TOOL/run.sh` runs the tool on `/dev/vdb` and writes what it recovers under `files/`.
   `needs` names a tool built first (its install tree is in `deps/`); `names` is `none` for a
   carver.

## Output of a run

`images/baselines/runs/TOOL/IMAGE/`:

| File | Content |
|---|---|
| `files.tsv` | `path name size sha256`, one row per regular file under `files/`; `name` is the recovered name (the basename, or what the tool reports, empty for a carver); tab, newline and backslash escaped as `\t`, `\n`, `\\` |
| `run.tsv` | `key value`: tool, version, recipe_sha256, exit, wall_s, max_rss_kib (peak resident set of the largest process, GNU time), files, guest_kernel, image, image_sha256 (the copy, before and after: equal or the run fails), source_sha256, guest_mem_mib, guest_cpus, host_cpu, qemu |
| `files/` | what the tool wrote |
| `logs/` | the tool's own output and logs |
| `console.log`, `vm-console.log` | the job's console and the whole serial log |

The guest refuses to start a tool unless the kernel reports `/dev/vdb` read-only, and
`run.sh` compares the copy's SHA-256 before and after. The original image is never attached.

Guest memory: builds `MEM=3072` MiB and 4 CPUs, runs 2048 MiB and 2 CPUs (QEMU `-m`, `-smp`);
SecurityRonin's `recover_deleted` reads the whole image into memory, so a run on an image larger
than about 1.5 GiB needs more.

Wall times and peak memory of a guest run vary with the host and with timing; report them over
repetitions (CONTRIBUTING.md §5), never from one run.
