# Demo: what btrfska does, in ten steps

A walk through the tool for someone seeing it for the first time, in about two minutes. Run it
from the repository root after `./setup.sh`:

```sh
docs/demo/demo.sh
```

The script runs the steps below in order and writes its output under `images/scratch/demo/`.
Every step reads an image and none writes to one. Counts depend on the build of the corpus images
(guest runs are not bit-stable), so the script prints them and this page does not.

| Step | What it shows | Image |
|---|---|---|
| 1. Trust gate | Every superblock copy is validated, a damaged mirror is reported, and an unknown incompat feature is refused | `sandbox.img`, `m1_mirror_damage`, `m1_unknown_incompat` |
| 2. Every physical copy checked | One DUP copy of a leaf has a single flipped byte; it is reported with the check that failed, and the good copy is used | `m1_badnode` |
| 3. Compressed read with provenance | An LZO file read through our own bounds-checked decoder, with a provenance record per extent | `m1_lzo` |
| 4. Scan | Every tree block on the device, including blocks in chunks that no longer exist | `m4_deep` |
| 5. Old-root discovery | Far more filesystem states than the superblock and its four backup roots name | `m4_deep` |
| 6. Evidence database | One pass builds the catalog, with the image hash as chain of custody | `m4_deep` |
| 7. Recovery | Every state, every orphan leaf and every log tree | `m4_deep` |
| 8. Ground truth | Recovered files compared with the SHA-256 the guest logged when it wrote each one | `m4_deep` |
| 9. Timeline | The lifecycle of one deleted file (claim C3) | `m4_deep` |
| 10. Read-only | The image hash after the session | `m4_deep` |

`m4_deep` has about 90 generations: 24 files deleted one per generation, 8 "flash" files that
only ever lived in log trees, and one file unlinked while it was open.

`check_truth.py` is the step-8 checker: it reads a recovery manifest and the scenario log and
prints, per ground-truth file, whether some complete artifact matches its logged hash and from
which source.
