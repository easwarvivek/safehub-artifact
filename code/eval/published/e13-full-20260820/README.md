# E13 sweep 1 — push, clone and storage across six arms

Collected 2026-08-20. **204 of 204 cells, seven experiments, zero failed cells.**

## Scope, stated plainly

This sweep times **three operations**: `arm_update` (stage, commit, push), its zero-payload floor,
and `arm_clone`. It does **not** cover pull, fetch, merge, rebase, force-push, rotate or
consolidation — those are sweep 2 (`code/eval/SWEEP2-PLAN.md`). Three of the nine operations
originally scoped are measured here.

## Provenance

| | |
|---|---|
| architecture | clients and remotes on **separate machines**; every arm over HTTP, no arm on `file://` |
| server | bench-1 (`c8g.8xlarge`): `git-http-backend`, plus a SafeHub server and control service per lane |
| clients | bench-2 (lanes 1–2), bench-3 (lanes 3–4) |
| concurrency | two lanes per client box, validated by a contention control at ≤9.9% worst-arm deviation |
| source parity | all four hosts byte-identical at digest `0cb98382` |
| reps | 5 per cell, gcrypt 3, recorded per cell and never averaged across |
| wall clock | ~61 min against ~197 min sequential |

Arms: `git`, `git-crypt`, `git-remote-gcrypt`, `SafeHub`, `SGitChar`, `SGitLine`. The last two are
our reimplementation — no artifact was published for that system — built as a real Git add-on.

## Contents

| file | experiment | points | cells |
|---|---|---|---|
| `e13-A1-delta.json` | update vs size of new content | 5 KiB … 3 MiB | 36 |
| `e13-A2-filesz.json` | update vs file size, fixed 1 KiB edit | 10 KiB … 8 MiB | 30 |
| `e13-A3-nfiles.json` | update vs number of files touched | 1 … 50 | 36 |
| `e13-B-size.json` | push, clone, storage vs repository size | 5 … 200 MB | 24 |
| `e13-C-depth.json` | clone vs history depth | 10 … 1000 heads | 24 |
| `e13-D-updates.json` | storage vs number of versions | 10 … 100 | 24 |
| `e13-E-revs.json` | push, clone, storage vs revisions of one file | 1 … 200 | 30 |

`*-rows.jsonl` holds the raw per-cell rows. B ran split across two lanes (its 200 MB point alone)
and `B-size-rows-merged.jsonl` is the concatenation the artifact was published from.

## Reading the byte columns

Three distinct quantities, not interchangeable:

- **`wire_bytes_per_update`** — the thin pack a push put on the wire, computed against the remote tip
  *before* the push. Defined only where the transport is an ordinary Git push; `null` for gcrypt and
  SafeHub, which expose no readable ref map. Never read `null` as zero.
- **`remote_growth_per_update`** / **`stored_growth_bytes`** — storage the remote gained, packed at
  both ends. Defined for every arm.
- **`bytes_changed`** — the plaintext the edit actually altered.

Byte columns reproduced between Apple silicon and Graviton4 to under 0.05%; timings are
hardware-dependent and bytes are not.

## Caveats

**A3 stops at 50 files, deliberately.** The 100-file point measures a Git packing cliff, not any
design's cost: past roughly 50–60 changed objects, `pack-objects --thin` stops using the remote's
copy as a delta base and sends the marginal files essentially whole — 314 B/file at 50, 1,834 at 60,
4,888 at 100, reproduced with plain git and no SafeHub or sgit involved. Ruled out by direct test:
repository size, `pack.window` at 250, `pack.depth` at 500, and corpus self-similarity. It penalised
exactly the two arms that delta-compress and spared the two that send whole files, so publishing it
would have charged SGitChar a 12x penalty belonging to Git.

**Cells do not share an n.** gcrypt runs at 3 repetitions, the rest at 5; each cell records its own,
so any ratio spans two.

**git-crypt's push column in B is non-monotone** (126, 293, 107, 117 ms at 5/25/100/200 MB) and is
not yet explained. Treat it as unexplained rather than as a finding.

**SGitChar's storage is large by construction.** Per-file base64 ciphertext defeats Git's
compression, so it stores ~71 MB where git stores 6 MB at depth 1000. That is a property of the
design, not an artifact.
